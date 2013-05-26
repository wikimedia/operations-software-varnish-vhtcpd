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

#include "strq.h"
#include "libdmn/dmn.h"
#include "http-parser/http_parser.h"

// XXX some of the below could be configurable as well
// XXX note that while this is set up to try to take advantage
//   of keep-alive, apparently varnish closes after every
//   response to a PURGE, currently.

// this buffer holds a fully-formed HTTP request to purge a single URL.
#define OUTBUF_SIZE 4096U

// this buffer holds the complete HTTP response we get
#define INBUF_SIZE 4096U

// initial and maximum wait betwen connect() attempts when connects are failing
//  and/or timing out.  The wait doubles after every failure (but limited to the
//  max), and is reset to initial value on connection success.
#define CONN_WAIT_INIT 1U
#define CONN_WAIT_MAX 32U

// These are the 6 possible states of the purger object.
// Note in the state transition code that we often *could* skip
//   straight through multiple states without returning to libev
//   (at least try and see if the next call doesn't EAGAIN),
//   but we'd rather return to the loop early and often
//   because dequeuing the UDP listener with minimum latency is
//   more important.
// We do attempt fall-through in the "obvious"  places like
//   connect_success->send and read_success->send_next,
//   but we still fully update the ev watcher states during these
//   to keep the code simpler to follow, even when it's likely
//   to be pointless churn.

typedef enum {
    // In this state, no message is pending in outbuf or the queue,
    //   and we have no active connection and no active libev watchers.
    // The only way out of NOTCONN_IDLE is a new purger_enqueue() call
    //   from the receiver code.
    PST_NOTCONN_IDLE = 0,

    // In this state, there's a message pending in outbuf, and there
    //   may or may not be more in the queue, and we're in the process
    //   of trying to establish the outbound connection (waiting on
    //   nonblock connect() success).
    PST_CONNECTING,

    // This is an exception state that occurs when the connect()
    //   attempt above fails.  We wait a short timeout before moving
    //   back to CONNECTING and trying again.  Note that in other
    //   connection failure cases (during read/write), we immediately
    //   retry the connection first, and don't wait until that
    //   connect() attempt fails.
    PST_NOTCONN_WAIT,

    // In these two states, outbuf has a complete message pending,
    //   and we have a live connection to use.
    // In the SENDWAIT state we've written less than all bytes.
    // In the RECVWAIT state we've written all bytes and haven't
    //   yet read a complete response.
    // If we eventually succeed in both sending the complete message
    //   and receiving an acceptable response code, the transaction
    //   will finish and outbuf will be cleared.  Whether we immediately
    //   shift back to SENDWAIT or CONN_IDLE depends on the queue.
    // Various failure scenarios lead to other outcomes.  Some bad
    //   status returns from the server should lead to dropping the
    //   current outbuf and moving on (possible bad URL).  Some
    //   should result in terminating the connection but trying
    //   the same URL again on the next connection.
    PST_SENDWAIT,
    PST_RECVWAIT,

    // In this state, outbuf is empty, the queue is empty, but we still
    //   have a live HTTP connection to the server from a previous
    //   message,  and we're ready to send another message if one arrives
    //   via the queue.
    // If the server disconnects us or we hit our own idle timeout
    //   and disconnect from it, we'll move back to _NOTCONN and
    //   wait there until another message needs to be sent.  If
    //   a new URL comes in via purger_enqueue() before that, we'll
    //   move straight back to _SENDWAIT (and then possibly right
    //   back through to _RECVWAIT as well).
    PST_CONN_IDLE,
} purger_state_t;

// for debug logging
#ifndef NDEBUG
static const char* state_strs[] = {
    "NOTCONN_IDLE",
    "CONNECTING",
    "NOTCONN_WAIT",
    "SENDWAIT",
    "RECVWAIT",
    "CONN_IDLE",
};
#endif

struct purger {
    purger_state_t state;
    bool purge_full_url;
    unsigned vhead;          // queue vhead index
    int fd;
    unsigned outbuf_size;    // total size of current buffered message
    unsigned outbuf_written; // bytes of the message sent so far...
    unsigned inbuf_parsed;
    unsigned io_timeout;     // these two are fixed via config
    unsigned idle_timeout;   // these two are fixed via config
    unsigned conn_wait_timeout; // dynamic, rises until success...
    dmn_anysin_t daddr;
    char* outbuf;
    char* inbuf;
    strq_t* queue;
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
    pr->status_ok = true; // XXX actually set this...

    return 0;
}

http_parser_settings psettings = {
    .on_message_begin = NULL,
    .on_url = NULL,
    .on_status_complete = NULL,
    .on_header_field = NULL,
    .on_header_value = NULL,
    .on_headers_complete = NULL,
    .on_body = NULL,
    .on_message_complete = msg_complete_cb
};

// Obviously, these assertions aren't always true mid-function
//   while transitioning from one state to another.  They're the
//   states we should be in when we return to the eventloop, and
//   should be checked on entry from an eventloop callback or
//   poke().
static void purger_assert_sanity(purger_t* s) {
    dmn_assert(s);
    dmn_assert(s->outbuf);
    dmn_assert(s->queue);
    dmn_assert(s->loop);
    dmn_assert(s->write_watcher);
    dmn_assert(s->read_watcher);
    dmn_assert(s->timeout_watcher);

    switch(s->state) {
        case PST_NOTCONN_IDLE:
            dmn_assert(s->fd == -1);
            dmn_assert(!s->outbuf_size);
            dmn_assert(!s->outbuf_written);
            dmn_assert(!s->inbuf_parsed);
            dmn_assert(!ev_is_active(s->write_watcher));
            dmn_assert(!ev_is_active(s->read_watcher));
            dmn_assert(!ev_is_active(s->timeout_watcher));
            break;
        case PST_CONNECTING:
            dmn_assert(s->fd != -1);
            dmn_assert(s->outbuf_size);
            dmn_assert(!s->outbuf_written);
            dmn_assert(!s->inbuf_parsed);
            dmn_assert(ev_is_active(s->write_watcher));
            dmn_assert(!ev_is_active(s->read_watcher));
            break;
        case PST_NOTCONN_WAIT:
            dmn_assert(s->fd == -1);
            dmn_assert(s->outbuf_size);
            dmn_assert(!s->outbuf_written);
            dmn_assert(!s->inbuf_parsed);
            dmn_assert(!ev_is_active(s->write_watcher));
            dmn_assert(!ev_is_active(s->read_watcher));
            break;
        case PST_SENDWAIT:
            dmn_assert(s->fd != -1);
            dmn_assert(s->outbuf_size);
            dmn_assert(s->outbuf_written < s->outbuf_size);
            dmn_assert(!s->inbuf_parsed);
            dmn_assert(ev_is_active(s->write_watcher));
            dmn_assert(ev_is_active(s->read_watcher));
            break;
        case PST_RECVWAIT:
            dmn_assert(s->fd != -1);
            dmn_assert(s->outbuf_size);
            dmn_assert(s->outbuf_written == s->outbuf_size);
            dmn_assert(!ev_is_active(s->write_watcher));
            dmn_assert(ev_is_active(s->read_watcher));
            break;
        case PST_CONN_IDLE:
            dmn_assert(s->fd != -1);
            dmn_assert(!s->outbuf_size);
            dmn_assert(!s->outbuf_written);
            dmn_assert(!s->inbuf_parsed);
            dmn_assert(!ev_is_active(s->write_watcher));
            dmn_assert(ev_is_active(s->read_watcher));
            break;
        default:
            dmn_assert(0);
    }
}

// The fixed parts of the request string.
// The two holes are for the URL and the hostname.
static const char out_prefix[] = "PURGE ";
static const unsigned out_prefix_len = sizeof(out_prefix) - 1;
static const char out_middle[] = " HTTP/1.1\r\nHost: ";
static const unsigned out_middle_len = sizeof(out_middle) - 1;
static const char out_suffix[] = "\r\nUser-Agent: vhtcpd\r\n\r\n";
static const unsigned out_suffix_len = sizeof(out_suffix) - 1;

// bits for url parser object with at least host + path defined
static const unsigned uf_hostpath = (1 << UF_HOST) | (1 << UF_PATH);

// true retval => reject for parse failure
static bool encode_to_outbuf(purger_t* s, const char* url, unsigned url_len) {
    dmn_assert(s); dmn_assert(url); dmn_assert(url_len);
    dmn_assert(!s->outbuf_size); // no other packet currently buffered
    dmn_assert(!s->outbuf_written); // no other packet currently buffered

    bool rv = true;

    struct http_parser_url up;
    memset(&up, 0, sizeof(struct http_parser_url));
    if(http_parser_parse_url(url, url_len, 0, &up) || ((up.field_set & uf_hostpath) != uf_hostpath)) {
        dmn_log_warn("Rejecting enqueued URL, cannot parse host + path: %s", url);
    }
    else {
        const char* path_etc;
        unsigned path_etc_len;
        if(s->purge_full_url) {
            path_etc = url;
            path_etc_len = url_len;
        }
        else {
            path_etc = &url[up.field_data[UF_PATH].off];
            path_etc_len = url_len - up.field_data[UF_PATH].off;
        }

        const char* hn = &url[up.field_data[UF_HOST].off];
        const unsigned hn_len = up.field_data[UF_HOST].len;

        const unsigned total_len = out_prefix_len + path_etc_len + out_middle_len + hn_len + out_suffix_len;
        if(total_len > OUTBUF_SIZE) {
            dmn_log_warn("Rejecting enqueued URL for excessive size: %s", url);
        }
        else {
            char* writeptr = s->outbuf;
            memcpy(writeptr, out_prefix, out_prefix_len); writeptr += out_prefix_len;
            memcpy(writeptr,   path_etc,   path_etc_len); writeptr +=   path_etc_len;
            memcpy(writeptr, out_middle, out_middle_len); writeptr += out_middle_len;
            memcpy(writeptr,         hn,         hn_len); writeptr +=         hn_len;
            memcpy(writeptr, out_suffix, out_suffix_len); writeptr += out_suffix_len;
            s->outbuf_size = total_len;
            rv = false;
        }
    }

    return rv;
}

// rv: false -> placed something in outbuf
//     true -> queue (effectively) empty, nothing placed in outbuf
static bool dequeue_to_outbuf(purger_t* s) {
    dmn_assert(s);

    unsigned url_len;
    const char* url;
    while((url = strq_dequeue(s->queue, &url_len, s->vhead))) {
        if(!encode_to_outbuf(s, url, url_len))
            return false;
    }

    return true;
}

static void purger_connect(purger_t* s) {
    dmn_assert(s);

    dmn_log_debug("purger: %s/%s -> hit purger_connect()", dmn_logf_anysin(&s->daddr), state_strs[s->state]);

    // we arrive in this function from several states/callbacks, but
    //   in all cases they should put us in this intermediate state first:
    dmn_assert(s->fd == -1);
    dmn_assert(s->outbuf_size);
    dmn_assert(!s->outbuf_written);
    dmn_assert(!s->inbuf_parsed);
    dmn_assert(!ev_is_active(s->timeout_watcher));
    dmn_assert(!ev_is_active(s->read_watcher));
    dmn_assert(!ev_is_active(s->write_watcher));

    // cache the protoent, because in many cases this blocks reading a database...
    static struct protoent* pe = NULL;
    if(!pe) {
         pe = getprotobyname("tcp");
         if(!pe)
             dmn_log_fatal("getprotobyname('tcp') failed");
    }

    // These failures aren't likely to be transient...
    s->fd = socket(PF_INET, SOCK_STREAM, pe->p_proto);
    if(s->fd == -1)
        dmn_log_fatal("Failed to create TCP socket: %s", dmn_logf_errno());
    if(fcntl(s->fd, F_SETFL, (fcntl(s->fd, F_GETFL, 0)) | O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to set O_NONBLOCK on TCP socket: %s", dmn_logf_errno());

    // Initiate a connect() attempt.  In theory this always returns -1/EINPROGRESS for
    //   a nonblocking socket, but it's possible it succeeds immediately for localhost...
    if(connect(s->fd, &s->daddr.sa, s->daddr.len) == -1) {
        if(errno != EINPROGRESS) {
            // hard/fast failure
            dmn_log_err("TCP connect to %s failed: %s", dmn_logf_anysin(&s->daddr), dmn_logf_errno());
            s->state = PST_NOTCONN_WAIT;
            shutdown(s->fd, SHUT_RDWR);
            close(s->fd);
            s->fd = -1;
            if(s->conn_wait_timeout < CONN_WAIT_MAX)
                s->conn_wait_timeout <<= 1;
            ev_timer_set(s->timeout_watcher, s->conn_wait_timeout, 0.);
            ev_timer_start(s->loop, s->timeout_watcher);
        }
        else {
            // return to libev until connection is ready
            s->state = PST_CONNECTING;
            ev_io_set(s->write_watcher, s->fd, EV_WRITE);
            ev_io_start(s->loop, s->write_watcher);
            ev_timer_set(s->timeout_watcher, s->io_timeout, 0.);
            ev_timer_start(s->loop, s->timeout_watcher);
        }
    }
    else {
        // immediate success, straight to send attempt
        s->state = PST_SENDWAIT;
        s->conn_wait_timeout = CONN_WAIT_INIT;
        ev_io_set(s->write_watcher, s->fd, EV_WRITE);
        ev_io_start(s->loop, s->write_watcher);
        ev_io_set(s->read_watcher, s->fd, EV_READ);
        ev_io_start(s->loop, s->read_watcher);
        ev_timer_set(s->timeout_watcher, s->io_timeout, 0.);
        ev_timer_start(s->loop, s->timeout_watcher);
        ev_invoke(s->loop, s->write_watcher, EV_WRITE);
    }
}

static void purger_write_cb(struct ev_loop* loop, ev_io* w, int revents) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_WRITE);

    purger_t* s = w->data;
    dmn_log_debug("purger: %s/%s -> hit purger_write_cb()", dmn_logf_anysin(&s->daddr), state_strs[s->state]);
    purger_assert_sanity(s);

    // This callback only happens in two states: CONNECTING and SENDWAIT...

    if(s->state == PST_CONNECTING) { // CONNECTING state, called back after EINPROGRESS wait
        int so_error = 0;
        unsigned int so_error_len = sizeof(so_error);
        getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len);
        if(so_error) {
            dmn_log_err("TCP connect() failed: %s", dmn_logf_errnum(so_error));
            s->state = PST_NOTCONN_WAIT;
            shutdown(s->fd, SHUT_RDWR);
            close(s->fd);
            s->fd = -1;
            if(s->conn_wait_timeout < CONN_WAIT_MAX)
                s->conn_wait_timeout <<= 1;
            ev_io_stop(s->loop, s->write_watcher);
            ev_timer_stop(s->loop, s->timeout_watcher);
            ev_timer_set(s->timeout_watcher, s->conn_wait_timeout, 0.);
            ev_timer_start(s->loop, s->timeout_watcher);
            return;
        }
        else { // successful connect(), alter state and fall through to the first send attempt
            s->state = PST_SENDWAIT;
            s->conn_wait_timeout = CONN_WAIT_INIT;
            ev_io_set(s->read_watcher, s->fd, EV_READ);
            ev_io_start(s->loop, s->read_watcher);
        }
    }

    dmn_assert(s->state == PST_SENDWAIT);
    const unsigned to_send = s->outbuf_size - s->outbuf_written;
    int writerv = send(s->fd, &s->outbuf[s->outbuf_written], to_send, 0);
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
                dmn_log_err("TCP conn to %s failed while writing: %s", dmn_logf_anysin(&s->daddr), dmn_logf_errno());
        }

        // reset state to try this send from the top on a fresh connection...
        s->outbuf_written = 0;
        shutdown(s->fd, SHUT_RDWR);
        close(s->fd);
        s->fd = -1;
        ev_io_stop(s->loop, s->write_watcher);
        ev_io_stop(s->loop, s->read_watcher);
        ev_timer_stop(s->loop, s->timeout_watcher);
        purger_connect(s);
    }
    else {
        if(writerv < (int)to_send) {
            // maintain same state, have to send more next iteration
            s->outbuf_written += writerv;
        }
        else {
            dmn_assert(writerv == (int)to_send);
            s->outbuf_written += writerv;
            dmn_assert(s->outbuf_written == s->outbuf_size);
            s->state = PST_RECVWAIT;
            ev_io_stop(s->loop, s->write_watcher);
        }
    }
}

// Common "clean up connection" code for multiple points in the read_cb below
// If clear_current is true, wipe the current request and decide next state
//   based on presence of another queued request, otherwise reconnect to
//   re-send the current request.
static void close_from_read_cb(purger_t* s, const bool clear_current) {
    shutdown(s->fd, SHUT_RDWR);
    close(s->fd);
    s->fd = -1;
    ev_timer_stop(s->loop, s->timeout_watcher);
    ev_io_stop(s->loop, s->read_watcher);

    if(s->state == PST_CONN_IDLE) {
        dmn_assert(!clear_current); // there was no "current" buffer output
        s->state = PST_NOTCONN_IDLE;
    }
    else { // SENDWAIT or RECVWAIT
        if(s->state == PST_SENDWAIT)
            ev_io_stop(s->loop, s->write_watcher);
        else
            s->inbuf_parsed = 0;
        s->outbuf_written = 0;

        if(clear_current) {
            s->outbuf_size = 0;
            dequeue_to_outbuf(s);
        }

        if(s->outbuf_size) // existing, or clear_current -> next queue entry
            purger_connect(s);
        else
            s->state = PST_NOTCONN_IDLE;
    }
}

static void purger_read_cb(struct ev_loop* loop, ev_io* w, int revents) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_READ);

    purger_t* s = w->data;
    purger_assert_sanity(s);
    dmn_log_debug("purger: %s/%s -> hit purger_read_cb()", dmn_logf_anysin(&s->daddr), state_strs[s->state]);

    const unsigned to_recv = INBUF_SIZE - s->inbuf_parsed;
    int recvrv = recv(s->fd, &s->inbuf[s->inbuf_parsed], to_recv, 0);
    if(recvrv < 1) {
        if(recvrv == -1) {
            switch(errno) {
                case EAGAIN:
                case EINTR:
                    // no real problem, but must return to eventloop and wait more
                    dmn_log_debug("purger: %s/%s -> purger_read_cb silent result: EAGAIN/EINTR", dmn_logf_anysin(&s->daddr), state_strs[s->state]);
                    return;
                case ENOTCONN:
                case ECONNRESET:
                case ETIMEDOUT:
                case EPIPE:
                    // "normal" problems, no need to log about it
                    dmn_log_debug("purger: %s/%s -> purger_read_cb silent result: closing due to '%s'", dmn_logf_anysin(&s->daddr), state_strs[s->state], dmn_logf_errno());
                    break;
                default:
                    // abormal problems, mention it in the log
                    dmn_log_err("TCP conn to %s failed while reading: %s", dmn_logf_anysin(&s->daddr), dmn_logf_errno());
            }
        }

        if(recvrv == 0)
            dmn_log_debug("purger: %s/%s -> purger_read_cb silent result: server closed", dmn_logf_anysin(&s->daddr), state_strs[s->state]);

        close_from_read_cb(s, false);
        return;
    }

    // From here we actually got some data...

    if(s->state != PST_RECVWAIT) {
        dmn_log_err("TCP conn to %s: received unexpected data from server during request-send or idle phases...", dmn_logf_anysin(&s->daddr));
        close_from_read_cb(s, false);
        return;
    }

    if(recvrv == (int)to_recv) {
        dmn_log_err("TCP conn to %s: response too large, dropping request", dmn_logf_anysin(&s->daddr));
        close_from_read_cb(s, true);
        return;
    }
    else { // reasonably-sized data, attempt parse
        if(!s->inbuf_parsed) // first read
            http_parser_init(s->parser, HTTP_RESPONSE);

        parse_res_t pr = { false, false, false };
        s->parser->data = &pr;
        int hpe_parsed = http_parser_execute(s->parser, &psettings, &s->inbuf[s->inbuf_parsed], recvrv);
        s->inbuf_parsed += hpe_parsed;
        if(hpe_parsed != recvrv) { // not parseable, could be more trailing garbage, close it all down
            dmn_log_err("TCP conn to %s: response unparseable, dropping request", dmn_logf_anysin(&s->daddr));
            close_from_read_cb(s, true);
            return;
        }
        else if(pr.cb_called) { // parsed a full response
            // XXX pr.status_ok will just be for stats?
            dmn_log_debug("purger: %s/%s -> purger_read_cb silent result: successful response parsed", dmn_logf_anysin(&s->daddr), state_strs[s->state]);

            // reset i/o progress
            s->outbuf_size = s->outbuf_written = s->inbuf_parsed = 0;

            // no matter which path, current timer needs to go
            ev_timer_stop(s->loop, s->timeout_watcher);

            if(pr.need_to_close) {
                shutdown(s->fd, SHUT_RDWR);
                close(s->fd);
                s->fd = -1;
                ev_io_stop(s->loop, s->read_watcher);
                if(!dequeue_to_outbuf(s))
                    purger_connect(s);
                else
                    s->state = PST_NOTCONN_IDLE;
            }
            else { // maintain connection
                if(!dequeue_to_outbuf(s)) {
                    ev_timer_set(s->timeout_watcher, s->io_timeout, 0.);
                    ev_timer_start(s->loop, s->timeout_watcher);
                    ev_io_start(s->loop, s->write_watcher);
                    s->state = PST_SENDWAIT;
                    ev_invoke(s->loop, s->write_watcher, EV_WRITE); // predictive, EAGAIN if not
                }
                else {
                    ev_timer_set(s->timeout_watcher, s->idle_timeout, 0.);
                    ev_timer_start(s->loop, s->timeout_watcher);
                    s->state = PST_CONN_IDLE;
                }
            }
        }
        else {
            dmn_log_debug("purger: %s/%s -> purger_read_cb silent result: apparent partial parse, still waiting for data...", dmn_logf_anysin(&s->daddr), state_strs[s->state]);
        }

        // If neither of the above, parser consumed all available data and didn't complete the message,
        //  so just return to the loop and maintain this state to get more data.
        return;
    }
}

static void purger_timeout_cb(struct ev_loop* loop, ev_timer* w, int revents) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_TIMER);

    purger_t* s = w->data;
    dmn_log_debug("purger: %s/%s -> hit purger_timeout_cb()", dmn_logf_anysin(&s->daddr), state_strs[s->state]);
    purger_assert_sanity(s);

    // this is potentially invoked in every state except NOTCONN_IDLE...
    switch(s->state) {
        case PST_CONN_IDLE:
            s->state = PST_NOTCONN_IDLE;
            ev_io_stop(s->loop, s->read_watcher);
            shutdown(s->fd, SHUT_RDWR);
            close(s->fd);
            s->fd = -1;
            break;
        case PST_CONNECTING:
            dmn_log_warn("connect() to %s timed out", dmn_logf_anysin(&s->daddr));
            s->state = PST_NOTCONN_WAIT;
            ev_io_stop(s->loop, s->write_watcher);
            shutdown(s->fd, SHUT_RDWR);
            close(s->fd);
            s->fd = -1;
            if(s->conn_wait_timeout < CONN_WAIT_MAX)
                s->conn_wait_timeout <<= 1;
            ev_timer_set(s->timeout_watcher, s->conn_wait_timeout, 0.);
            ev_timer_start(s->loop, s->timeout_watcher);
            break;
        case PST_SENDWAIT:
            dmn_log_warn("send to %s timed out", dmn_logf_anysin(&s->daddr));
            s->outbuf_written = 0;
            ev_io_stop(s->loop, s->write_watcher);
            ev_io_stop(s->loop, s->read_watcher);
            shutdown(s->fd, SHUT_RDWR);
            close(s->fd);
            s->fd = -1;
            purger_connect(s);
            break;
        case PST_RECVWAIT:
            dmn_log_warn("recv from %s timed out", dmn_logf_anysin(&s->daddr));
            s->outbuf_written = 0;
            s->inbuf_parsed = 0;
            ev_io_stop(s->loop, s->read_watcher);
            shutdown(s->fd, SHUT_RDWR);
            close(s->fd);
            s->fd = -1;
            purger_connect(s);
            break;
        case PST_NOTCONN_WAIT:
            purger_connect(s);
            break;
        default:
            dmn_assert(0);
    }
}

purger_t* purger_new(struct ev_loop* loop, const dmn_anysin_t* daddr, strq_t* queue, unsigned vhead, bool purge_full_url, unsigned io_timeout, unsigned idle_timeout) {
    purger_t* s = calloc(1, sizeof(purger_t));
    s->fd = -1;
    s->purge_full_url = purge_full_url;
    s->outbuf = malloc(OUTBUF_SIZE);
    s->inbuf = malloc(INBUF_SIZE);
    s->parser = malloc(sizeof(http_parser));
    s->queue = queue;
    s->vhead = vhead;
    s->loop = loop;
    s->io_timeout = io_timeout;
    s->idle_timeout = idle_timeout;
    s->conn_wait_timeout = CONN_WAIT_INIT;

    memcpy(&s->daddr, daddr, sizeof(dmn_anysin_t));

    s->write_watcher = malloc(sizeof(ev_io));
    ev_io_init(s->write_watcher, purger_write_cb, -1, EV_WRITE);
    ev_set_priority(s->write_watcher, 1);
    s->write_watcher->data = s;

    s->read_watcher = malloc(sizeof(ev_io));
    ev_io_init(s->read_watcher, purger_read_cb, -1, EV_READ);
    ev_set_priority(s->read_watcher, 1);
    s->read_watcher->data = s;

    s->timeout_watcher = malloc(sizeof(ev_timer));
    ev_timer_init(s->timeout_watcher, purger_timeout_cb, 0., 0.);
    ev_set_priority(s->timeout_watcher, 0);
    s->timeout_watcher->data = s;

    return s;
}

void purger_ping(purger_t* s) {
    dmn_assert(s);
    dmn_log_debug("purger: %s/%s -> hit purger_ping()", dmn_logf_anysin(&s->daddr), state_strs[s->state]);
    purger_assert_sanity(s);

    // ping is called immediately after an enqueue...
    dmn_assert(strq_get_size(s->queue));

    // enqueue can happen in any state, but actions differ:
    switch(s->state) {
        // when in either idle state, the queue is empty and the outbuf
        //   is empty, so encode directly to the outbuf and start up
        //   I/O action...
        case PST_NOTCONN_IDLE:
            if(!dequeue_to_outbuf(s))
                purger_connect(s); // state transition is conditional within
            break;
        case PST_CONN_IDLE:
            if(!dequeue_to_outbuf(s)) {
                ev_io_start(s->loop, s->write_watcher);
                ev_timer_stop(s->loop, s->timeout_watcher);
                ev_timer_set(s->timeout_watcher, s->io_timeout, 0.);
                ev_timer_start(s->loop, s->timeout_watcher);
                s->state = PST_SENDWAIT;
            }
            break;

        // When in non-idle states, there's nothing to do here.
        //   the queue will be checked when current actions are completed later
        case PST_CONNECTING:
        case PST_NOTCONN_WAIT:
        case PST_SENDWAIT:
        case PST_RECVWAIT:
            break;

        default:
            dmn_assert(0);
            break;
    }
}

void purger_destroy(purger_t* s) {
    ev_io_stop(s->loop, s->write_watcher);
    ev_io_stop(s->loop, s->read_watcher);
    ev_timer_stop(s->loop, s->timeout_watcher);
    if(s->fd != -1) {
        shutdown(s->fd, SHUT_RDWR);
        close(s->fd);
    }
    free(s->write_watcher);
    free(s->read_watcher);
    free(s->timeout_watcher);
    free(s->inbuf);
    free(s->outbuf);
    free(s->parser);
    free(s);
}
