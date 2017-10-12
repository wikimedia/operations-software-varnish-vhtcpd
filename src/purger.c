/* Copyright © 2013 Brandon L Black <bblack@wikimedia.org>
 *
 * This file is part of vhtcpd.
 *
 * vhtcpd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * vhtcpd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with vhtcpd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "purger.h"

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ev.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "stats.h"
#include "strq.h"
#include "libdmn/dmn.h"
#include "http-parser/http_parser.h"

// XXX some of the below could be configurable as well

// this buffer holds the complete HTTP response we get, and can grow at runtime
#define INBUF_INITSIZE 4096U

// initial and maximum wait betwen connect() attempts when connects are failing
//  and/or timing out.  The wait doubles after every failure (but limited to the
//  max), and is reset to initial value on connection success.
#define CONN_WAIT_INIT 1U
#define CONN_WAIT_MAX 8U

// Limit uptime of each purging socket.  It seems that Varnish imposes no limit
//   here other than inter-purge idle time, so it's a good idea that we close()
//   occasionally to avoid pushing corner-case bug buttons.  At ~53 minutes,
//   we're still getting the vast majority of the benefit, so this is basically
//   a free safety valve.
#define PERSIST_TIME 3181.0

// These are the 5 possible states of the purger object.
// * Note that usually in the case where a valid purger connection is open
// and we have data to send (e.g. after completing a purger response, or
// from the connected+idle state), we attempt to send it immediately
// without falling back out to the eventloop.  This is because that is
// almost always immediately successful without network delay (goes to
// outbound tcp buffer, which always has room due to serial, small
// transactions).  The code does exist to fall back to stalling on
// writeability in the eventloop, but it's mostly there for correctness.
// * In other states, we prefer to re-enter the eventloop even in cases
// where that's locally-inefficient, because it gets us back to handling
// the UDP receives in receiver.c quicker, where there's a real risk of
// input falling off the socket buffer if it overfills in a spike.
// * Note that all states use the timeout watcher, so we use it
// ev_timer_again() mode for efficiency (method 2 in the libev docs)

typedef enum {
    // In this state we're in the process of trying to establish the
    //   outbound connection (waiting on nonblock connect() success).
    // Possible next states: PST_CONN_IDLE, PST_NOTCONN_WAIT
    // Active watchers: write, timeout
    PST_CONNECTING,

    // While disconnects that occur from other states (send, recv, idle)
    //   result in an immediate reconnect attempt (connecting, above), a
    //   failure during connecting itself results in exponential backoff
    //   delays between reconnection attempts, and they wait out their
    //   timers in this state.
    // Possible next states: PST_CONNECTING
    // Active watchers: timeout
    PST_NOTCONN_WAIT,

    // SENDWAIT means we're waiting to send request bytes to the purger.
    // Possible next states: PST_RECVWAIT, PST_CONN_IDLE, PST_CONNECTING
    // Active watchers: read, write?, timeout
    PST_SENDWAIT,

    // Possible next states: PST_SENDWAIT, PST_CONN_IDLE, PST_CONNECTING
    // Active watchers: read, timeout
    PST_RECVWAIT,

    // In this state, outbuf is empty, the queue is empty, but we still
    //   have a live HTTP connection to the server from a previous
    //   message,  and we're ready to send another message if one arrives
    //   via the queue.
    // Possible next states: PST_SENDWAIT, PST_CONNECTING
    // Active watchers: read, timeout
    PST_CONN_IDLE,
} purger_state_t;

// for debug logging
#ifndef NDEBUG
static const char* state_strs[] = {
    "CONNECTING",
    "NOTCONN_WAIT",
    "SENDWAIT",
    "RECVWAIT",
    "CONN_IDLE",
};
#endif

struct purger {
    purger_state_t state;
    int fd;
    unsigned outbuf_bytes;   // total size of current buffered message
    unsigned outbuf_written; // bytes of the message sent so far...
    unsigned inbuf_size;     // dynamic resize of inbuf
    unsigned inbuf_parsed;   // consumed by parser so far
    unsigned io_timeout;     // set via config
    unsigned conn_wait_timeout; // dynamic, rises until success...
    ev_tstamp fd_expire;
    dmn_anysin_t daddr;
    char* outbuf;
    char* inbuf;
    strq_t* queue;
    purger_t* next_purger;
    purger_stats_t* pstats;
    struct ev_loop* loop;
    ev_io* write_watcher;
    ev_io* read_watcher;
    ev_timer* timeout_watcher;
    http_parser* parser;
};

typedef struct {
    bool cb_called; // whether msg_complete was issued
    bool need_to_close; // iff cb_called, indicates server connection: close
    bool status_ok; // iff cb_called, was status acceptable?
} parse_res_t;

static int msg_complete_cb(http_parser* p) {
    dmn_assert(p);

    parse_res_t* pr = p->data;
    dmn_assert(pr);

    pr->cb_called = true;
    pr->need_to_close = !http_should_keep_alive(p);
    pr->status_ok = p->status_code < 400;

    return 0;
}

http_parser_settings psettings = {
    .on_message_begin = NULL,
    .on_url = NULL,
    .on_status = NULL,
    .on_header_field = NULL,
    .on_header_value = NULL,
    .on_headers_complete = NULL,
    .on_body = NULL,
    .on_message_complete = msg_complete_cb,
    .on_chunk_header = NULL,
    .on_chunk_complete = NULL
};

#ifdef NDEBUG

#define purger_assert_sanity(x) ((void)(0))

#else

// Obviously, these assertions aren't always true mid-function
//   while transitioning from one state to another.  They're the
//   states we should be in when we return to the eventloop, and
//   should be checked on entry from an eventloop callback or
//   poke().
static void purger_assert_sanity(purger_t* p) {
    dmn_assert(p);
    dmn_assert(p->outbuf);
    dmn_assert(p->inbuf);
    dmn_assert(p->inbuf_size);
    dmn_assert(p->queue);
    dmn_assert(p->loop);
    dmn_assert(p->write_watcher);
    dmn_assert(p->read_watcher);
    dmn_assert(p->timeout_watcher);
    dmn_assert(ev_is_active(p->timeout_watcher));

    switch(p->state) {
        case PST_CONNECTING:
            dmn_assert(p->fd != -1);
            dmn_assert(ev_is_active(p->write_watcher));
            dmn_assert(!ev_is_active(p->read_watcher));
            break;
        case PST_NOTCONN_WAIT:
            dmn_assert(p->fd == -1);
            dmn_assert(!ev_is_active(p->write_watcher));
            dmn_assert(!ev_is_active(p->read_watcher));
            break;
        case PST_SENDWAIT:
            dmn_assert(p->fd != -1);
            dmn_assert(p->outbuf_bytes);
            dmn_assert(p->outbuf_written < p->outbuf_bytes);
            dmn_assert(!p->inbuf_parsed);
            dmn_assert(ev_is_active(p->read_watcher));
            break;
        case PST_RECVWAIT:
            dmn_assert(p->fd != -1);
            dmn_assert(p->outbuf_bytes);
            dmn_assert(p->outbuf_written == p->outbuf_bytes);
            dmn_assert(!ev_is_active(p->write_watcher));
            dmn_assert(ev_is_active(p->read_watcher));
            break;
        case PST_CONN_IDLE:
            dmn_assert(p->fd != -1);
            dmn_assert(!p->outbuf_bytes);
            dmn_assert(!p->outbuf_written);
            dmn_assert(!p->inbuf_parsed);
            dmn_assert(!ev_is_active(p->write_watcher));
            dmn_assert(ev_is_active(p->read_watcher));
            break;
        default:
            dmn_assert(0);
    }
}

#endif

static void close_socket(purger_t* p) {
    ev_io_stop(p->loop, p->write_watcher);
    ev_io_stop(p->loop, p->read_watcher);
    if(p->fd != -1) {
        shutdown(p->fd, SHUT_RDWR);
        close(p->fd);
    }
    p->fd = -1;
    p->fd_expire = 0.;
}

static void purger_connect(purger_t* p);

static void do_reconnect_socket(purger_t* p) {
    close_socket(p);
    purger_connect(p);
}

// rv "idle": false -> outbuf has a purge to send
//            true -> queue empty, nothing in outbuf (idle-time!)
// This should work for all outbuf/queue states.
static bool _txn_prep_buffers(purger_t* p, const bool clear_current) {
    dmn_assert(p);
    dmn_assert(p->outbuf);
    dmn_assert(p->inbuf);

    bool idle = true;

    p->inbuf_parsed = 0;
    p->outbuf_written = 0;
    if(clear_current)
        p->outbuf_bytes = 0;

    if(p->outbuf_bytes) {
        idle = false;
    } else {
        unsigned req_len;
        const char* req;
        req = strq_dequeue(p->queue, &req_len);
        if(req) {
            memcpy(p->outbuf, req, req_len);
            p->outbuf_bytes = req_len;
            idle = false;
        }
    }

    return idle;
}

static void purger_write_req(purger_t* p, const bool via_watcher);

// Called at any txn/connection boundary (purge success/fail, connection success).
// Not called while cycling within reconnect attempt callbacks.
// If the "reconnect" argument is present, this causes a disconnect->reconnect cycle,
// otherwise it ensures the buffer has a live request if possible and moves to
// either the idle state or the sending state.  "clear_current" wipes the
// currently-buffered request in the case it's suspected of being malformed.
static void on_txn_boundary(purger_t* p, const bool clear_current, const bool reconnect) {
    dmn_assert(p);

    const bool idle = _txn_prep_buffers(p, clear_current);
    ev_tstamp now = ev_now(p->loop);

    // force reconnect here if we pass our persistence limits
    if(reconnect || p->fd_expire <= now) {
        do_reconnect_socket(p);
    } else if(idle) {
        p->state = PST_CONN_IDLE;
        ev_io_stop(p->loop, p->write_watcher);
        p->timeout_watcher->repeat = p->fd_expire - now;
        ev_timer_again(p->loop, p->timeout_watcher);
    } else {
        p->state = PST_SENDWAIT;
        p->timeout_watcher->repeat = p->io_timeout;
        ev_timer_again(p->loop, p->timeout_watcher);
        purger_write_req(p, true);
    }
}

static void on_connect_success(purger_t* p) {
    dmn_assert(p);
    dmn_assert(p->state == PST_CONNECTING);

    dmn_log_info("TCP connection established to %s", dmn_logf_anysin(&p->daddr));
    p->fd_expire = ev_now(p->loop) + PERSIST_TIME;
    p->conn_wait_timeout = CONN_WAIT_INIT;
    ev_io_stop(p->loop, p->write_watcher);
    ev_io_set(p->read_watcher, p->fd, EV_READ);
    ev_io_start(p->loop, p->read_watcher);
    on_txn_boundary(p, false, false);
}

static void on_connect_fail(purger_t* p, const char* reason, const int so_error) {
    dmn_assert(p);
    dmn_assert(p->state == PST_CONNECTING);

    dmn_log_err(
        "TCP connect to %s failed (%s): %s",
        dmn_logf_anysin(&p->daddr), reason,
        so_error ? dmn_logf_errnum(so_error) : dmn_logf_errno()
    );
    close_socket(p);
    p->state = PST_NOTCONN_WAIT;
    if(p->conn_wait_timeout < CONN_WAIT_MAX)
        p->conn_wait_timeout <<= 1;
    p->timeout_watcher->repeat = p->conn_wait_timeout;
    ev_timer_again(p->loop, p->timeout_watcher);
}

static void purger_connect(purger_t* p) {
    dmn_assert(p);

    dmn_log_debug("purger: %s/%s -> purger_connect()", dmn_logf_anysin(&p->daddr), state_strs[p->state]);

    // we arrive in this function from several states/callbacks, but in
    // all cases they should put us in this intermediate state first (no
    // half-processed in or out buffers, no active i/o watchers, no
    // socket fd)
    dmn_assert(p->fd == -1);
    dmn_assert(!ev_is_active(p->read_watcher));
    dmn_assert(!ev_is_active(p->write_watcher));

    // set our proper state during connection attempts
    p->state = PST_CONNECTING;

    // cache the protoent, because in many cases this blocks reading a database...
    static struct protoent* pe = NULL;
    if(!pe) {
         pe = getprotobyname("tcp");
         if(!pe)
             dmn_log_fatal("getprotobyname('tcp') failed");
    }

    // These failures aren't likely to be transient...
    p->fd = socket(PF_INET, SOCK_STREAM, pe->p_proto);
    if(p->fd == -1)
        dmn_log_fatal("Failed to create TCP socket: %s", dmn_logf_errno());
    if(fcntl(p->fd, F_SETFL, (fcntl(p->fd, F_GETFL, 0)) | O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to set O_NONBLOCK on TCP socket: %s", dmn_logf_errno());

    // Atypical with no intent to bind(), but may help with racing other threads for
    //  ephemeral port allocation in Linux leading to random socket errors, supposedly?
    int opt_one = 1;
    if(setsockopt(p->fd, SOL_SOCKET, SO_REUSEADDR, &opt_one, sizeof(int)))
        dmn_log_warn("Failed to set SO_REUSEADDR on TCP socket: %s", dmn_logf_errno());

    // Initiate a connect() attempt.  In theory this always returns -1/EINPROGRESS for
    //   a nonblocking socket, but it's possible it succeeds immediately for localhost...
    if(connect(p->fd, &p->daddr.sa, p->daddr.len) == -1) {
        if(errno != EINPROGRESS) {
            on_connect_fail(p, "immediate", 0);
        }
        else {
            // return to libev until connection is ready
            ev_io_set(p->write_watcher, p->fd, EV_WRITE);
            ev_io_start(p->loop, p->write_watcher);
            p->timeout_watcher->repeat = p->io_timeout;
            ev_timer_again(p->loop, p->timeout_watcher);
        }
    }
    else { // immediately-successful connect!
        on_connect_success(p);
    }
}

static void purger_write_req(purger_t* p, const bool via_watcher) {
    dmn_assert(p);
    dmn_assert(p->state == PST_SENDWAIT);

    const unsigned to_send = p->outbuf_bytes - p->outbuf_written;
    int writerv = send(p->fd, &p->outbuf[p->outbuf_written], to_send, 0);
    if(writerv == -1) {
        switch(errno) {
            case EAGAIN:
            case EINTR:
                // no real problem, but must return to eventloop and wait more
                return;
            case ENOTCONN:
            case ECONNRESET:
            case ETIMEDOUT:
            case EHOSTUNREACH:
            case ENETUNREACH:
            case EPIPE:
                // "normal" problems, no need to log about it
                break;
            default:
                // abormal problems, mention it in the log
                dmn_log_err("TCP conn to %s failed while writing: %s", dmn_logf_anysin(&p->daddr), dmn_logf_errno());
        }

        // close up connection and reconnect, do not clear current output buffer
        on_txn_boundary(p, false, true);
    }
    else {
        if(writerv < (int)to_send) {
            // maintain same state, have to send more next iteration
            p->outbuf_written += writerv;
            if (!via_watcher)
                ev_io_start(p->loop, p->write_watcher);
        }
        else {
            dmn_assert(writerv == (int)to_send);
            p->outbuf_written += writerv;
            dmn_assert(p->outbuf_written == p->outbuf_bytes);
            p->state = PST_RECVWAIT;
            if (via_watcher)
                ev_io_stop(p->loop, p->write_watcher);
        }
    }
}

static void purger_write_cb(struct ev_loop* loop, ev_io* w, int revents) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_WRITE);

    purger_t* p = w->data;
    dmn_log_debug("purger: %s/%s -> purger_write_cb()", dmn_logf_anysin(&p->daddr), state_strs[p->state]);
    purger_assert_sanity(p);

    // This callback only happens in two states: CONNECTING and SENDWAIT...

    if(p->state == PST_CONNECTING) { // CONNECTING state, called back after EINPROGRESS wait
        int so_error = 0;
        unsigned int so_error_len = sizeof(so_error);
        getsockopt(p->fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len);
        if(so_error)
            on_connect_fail(p, "nonblock", so_error);
        else
            on_connect_success(p);
    } else {
        purger_write_req(p, true);
    }
}

static void purger_read_cb(struct ev_loop* loop, ev_io* w, int revents) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_READ);

    purger_t* p = w->data;
    purger_assert_sanity(p);
    dmn_log_debug("purger: %s/%s -> purger_read_cb()", dmn_logf_anysin(&p->daddr), state_strs[p->state]);

    const unsigned to_recv = p->inbuf_size - p->inbuf_parsed;
    int recvrv = recv(p->fd, &p->inbuf[p->inbuf_parsed], to_recv, 0);
    if(recvrv < 0) {
        switch(errno) {
            case EAGAIN:
            case EINTR:
                // no real problem, but must return to eventloop and wait more
                dmn_log_debug("purger: %s/%s -> purger_read_cb silent result: EAGAIN/EINTR", dmn_logf_anysin(&p->daddr), state_strs[p->state]);
                return;
            case ENOTCONN:
            case ECONNRESET:
            case ETIMEDOUT:
            case EPIPE:
                // "normal" problems, no need to log about it
                dmn_log_debug("purger: %s/%s -> purger_read_cb silent result: closing due to '%s'", dmn_logf_anysin(&p->daddr), state_strs[p->state], dmn_logf_errno());
                break;
            default:
                // abormal problems, mention it in the log
                dmn_log_err("TCP conn to %s failed while reading: %s", dmn_logf_anysin(&p->daddr), dmn_logf_errno());
        }
        on_txn_boundary(p, false, true);
        return;
    }

    // From here we actually got some data...

    if(p->state != PST_RECVWAIT) {
        if(recvrv == 0)
            dmn_log_debug("purger: %s/%s -> purger_read_cb silent result: server closed", dmn_logf_anysin(&p->daddr), state_strs[p->state]);
        else
            dmn_log_err("TCP conn to %s: received unexpected data from server during request-send or idle phases...", dmn_logf_anysin(&p->daddr));
        on_txn_boundary(p, false, true);
        return;
    }
    else if(recvrv == 0) {
        dmn_log_err("TCP conn to %s: connection closed while waiting on response", dmn_logf_anysin(&p->daddr));
        on_txn_boundary(p, false, true);
        return;
    }

    if(recvrv == (int)to_recv) {
        // TCP might want to give us more data than the buffer can hold, expand it the buffer
        //  and feed what we have to the parser.  It's exceedingly likely the parse won't yet
        //  complete and we'll get another recv callback to finish up.
        p->inbuf_size <<= 1;
        p->inbuf = realloc(p->inbuf, p->inbuf_size);
        dmn_log_err("TCP recv buffer for %s grew to %u", dmn_logf_anysin(&p->daddr), p->inbuf_size);
    }

    if(!p->inbuf_parsed) // first read
        http_parser_init(p->parser, HTTP_RESPONSE);

    parse_res_t pr = { false, false, false };
    p->parser->data = &pr;
    int hpe_parsed = http_parser_execute(p->parser, &psettings, &p->inbuf[p->inbuf_parsed], recvrv);
    p->inbuf_parsed += hpe_parsed;
    if(p->parser->http_errno != HPE_OK || hpe_parsed != recvrv) { // not parseable, could be more trailing garbage, close it all down
        dmn_log_err("TCP conn to %s: response unparseable (parser error %s), dropping request", dmn_logf_anysin(&p->daddr), http_errno_description(p->parser->http_errno));
        on_txn_boundary(p, true, true);
        return;
    }
    else if(pr.cb_called) { // parsed a full response
        dmn_log_debug("purger: %s/%s -> purger_read_cb silent result: successful response parsed", dmn_logf_anysin(&p->daddr), state_strs[p->state]);

        // Only forward to next purger and mark sent in stats if status was reasonable
        if(pr.status_ok) {
            if(p->next_purger) {
                purger_enqueue(p->next_purger, p->outbuf, p->outbuf_bytes);
                purger_ping(p->next_purger);
            }
            p->pstats->inpkts_sent++;
        }
        else {
            dmn_log_warn("PURGE response code was was >= 400");
        }

        on_txn_boundary(p, true, pr.need_to_close);
    }
    else {
        // If neither of the above, parser consumed all available data and didn't complete the message,
        //  so just return to the loop and maintain this state to get more data.
        dmn_log_debug("purger: %s/%s -> purger_read_cb silent result: apparent partial parse (%u new, %u total), still waiting for data...", dmn_logf_anysin(&p->daddr), state_strs[p->state], recvrv, p->inbuf_parsed);
    }
}

static void purger_timeout_cb(struct ev_loop* loop, ev_timer* w, int revents) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_TIMER);

    purger_t* p = w->data;
    dmn_log_debug("purger: %s/%s -> purger_timeout_cb()", dmn_logf_anysin(&p->daddr), state_strs[p->state]);
    purger_assert_sanity(p);

    // this is potentially invoked in every state
    switch(p->state) {
        case PST_CONN_IDLE:
            // reached fd persistence timeout during idle state
            do_reconnect_socket(p);
            break;
        case PST_CONNECTING:
            // reached io timeout while waiting for connect() success
            dmn_log_warn("connect() to %s timed out", dmn_logf_anysin(&p->daddr));
            on_connect_fail(p, "timeout", 0);
            break;
        case PST_SENDWAIT:
            // reached io timeout while waiting for send [buffer] readiness...
            dmn_log_warn("send to %s timed out", dmn_logf_anysin(&p->daddr));
            on_txn_boundary(p, false, true);
            break;
        case PST_RECVWAIT:
            // reached io timeout while waiting for a full (or any?) response
            dmn_log_warn("recv from %s timed out after receiving %u bytes", dmn_logf_anysin(&p->daddr), p->inbuf_parsed);
            on_txn_boundary(p, false, true);
            break;
        case PST_NOTCONN_WAIT:
            // end of short timeout between successive connectfail->reconnect attempts
            purger_connect(p);
            break;
        default:
            dmn_assert(0);
    }
}

purger_t* purger_new(struct ev_loop* loop, const dmn_anysin_t* daddr, purger_t* next_purger, purger_stats_t* pstats, unsigned max_mb, unsigned io_timeout) {
    purger_t* p = calloc(1, sizeof(purger_t));
    p->pstats = pstats;
    p->fd = -1;
    p->inbuf_size = INBUF_INITSIZE;
    p->outbuf = malloc(OUTBUF_SIZE);
    p->inbuf = malloc(p->inbuf_size);
    p->parser = malloc(sizeof(http_parser));
    p->queue = strq_new(loop, pstats, max_mb);
    p->next_purger = next_purger;
    p->loop = loop;
    p->io_timeout = io_timeout;
    p->conn_wait_timeout = CONN_WAIT_INIT;

    memcpy(&p->daddr, daddr, sizeof(dmn_anysin_t));

    p->write_watcher = malloc(sizeof(ev_io));
    ev_io_init(p->write_watcher, purger_write_cb, -1, EV_WRITE);
    ev_set_priority(p->write_watcher, 1);
    p->write_watcher->data = p;

    p->read_watcher = malloc(sizeof(ev_io));
    ev_io_init(p->read_watcher, purger_read_cb, -1, EV_READ);
    ev_set_priority(p->read_watcher, 1);
    p->read_watcher->data = p;

    p->timeout_watcher = malloc(sizeof(ev_timer));
    ev_timer_init(p->timeout_watcher, purger_timeout_cb, 0., 0.);
    ev_set_priority(p->timeout_watcher, 0);
    p->timeout_watcher->data = p;

    // Initiate the first connection
    purger_connect(p);

    return p;
}

void purger_enqueue(purger_t* p, const char* req, const unsigned req_len) {
    dmn_assert(p); dmn_assert(req); dmn_assert(req_len);
    dmn_log_debug("purger: %s/%s -> purger_enqueue()", dmn_logf_anysin(&p->daddr), state_strs[p->state]);
    purger_assert_sanity(p);

    strq_enqueue(p->queue, req, req_len);
    p->pstats->inpkts_enqueued++;
}

void purger_ping(purger_t* p) {
    dmn_assert(p);
    dmn_log_debug("purger: %s/%s -> purger_ping()", dmn_logf_anysin(&p->daddr), state_strs[p->state]);
    // In all other states we'll check the queue later on our own...
    if(p->state == PST_CONN_IDLE)
        on_txn_boundary(p, false, false);
}

void purger_destroy(purger_t* p) {
    ev_timer_stop(p->loop, p->timeout_watcher);
    close_socket(p);
    free(p->write_watcher);
    free(p->read_watcher);
    free(p->timeout_watcher);
    free(p->inbuf);
    free(p->outbuf);
    free(p->parser);
    strq_destroy(p->queue);
    free(p);
}
