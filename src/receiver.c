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

#include "receiver.h"
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <inttypes.h>

#include "stats.h"
#include "libdmn/dmn.h"
#include "http-parser/http_parser.h"

// input buffer size for single message, we discard messages
//   longer than this.  Given practical URLs on the internet
//   are limited to 2K and there's not much else in the packet,
//   and nobody wants multicast packets that fragment on
//   common networks, this should be plenty.
#define INBUF_SIZE 4096

// How many pending packets we'll dequeue from the kernel
//   (and potentially regex-filter to /dev/null)
//   in a tight loop before giving control back to libev
//   for purge operations, to help absorb bursts before
//   the kernel buffer runs out.
#define MAX_TIGHT_RECV 64U

// As above, but a limit on queueing URLs to purge which
//   survived any regex filter
#define MAX_TIGHT_QUEUE 8U

// how big we try to set the kernel buffer via setsockopt().
// Note: if this fails, we'll halve it until it succeeds
#define DESIRED_KBUF 16777216
#define MIN_KBUF 65536

struct receiver {
    int fd;
    bool purge_full_url;
    char* inbuf;
    struct ev_loop* loop;
    ev_io* read_watcher;
    purger_t* purger;
    const pcre* matcher;
    const pcre_extra* matcher_extra;
};

// GCC-ish unaligned access for 16-bit numbers
struct _una16 { uint16_t x; } __attribute__((__packed__));
#define get_una16(_p) (((const struct _una16*)(_p))->x)

int receiver_create_lsock(const dmn_anysin_t* iface, const dmn_anysin_t* mcasts, unsigned num_mcasts) {
    dmn_assert(iface); dmn_assert(mcasts); dmn_assert(num_mcasts);

    // Create a non-blocking UDP socket with a large receive buffer
    struct protoent* pe;
    pe = getprotobyname("udp");
    if(!pe)
        dmn_log_fatal("getprotobyname('udp') failed");
    const int sock = socket(PF_INET, SOCK_DGRAM, pe->p_proto);
    if(sock == -1)
        dmn_log_fatal("Cannot create UDP socket: %s", dmn_strerror(errno));
    if(fcntl(sock, F_SETFL, (fcntl(sock, F_GETFL, 0)) | O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to set O_NONBLOCK on UDP socket: %s", dmn_strerror(errno));
    int desired_kbuf = DESIRED_KBUF;
    while(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &desired_kbuf, sizeof(desired_kbuf)) == -1) {
        desired_kbuf >>= 1;
        if(desired_kbuf < MIN_KBUF)
            dmn_log_fatal("Cannot set UDP receive buffer to a decently large size: %s", dmn_strerror(errno));
    }
    dmn_log_debug("receiver: UDP RCVBUF final accepted size: %u", desired_kbuf);

    // Bind to the specified port number, on 0.0.0.0
    dmn_anysin_t binder;
    memcpy(&binder, iface, sizeof(dmn_anysin_t));
    binder.sin.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(sock, &binder.sa, binder.len))
        dmn_log_fatal("Cannot bind() UDP listening socket to %s: %s", dmn_logf_anysin(&binder), dmn_strerror(errno));

    // Set up multicast memberships (interface addr + mcast addr)
    for(unsigned i = 0; i < num_mcasts; i++) {
        struct ip_mreq mreq;
        memset(&mreq, 0, sizeof(struct ip_mreq));
        mreq.imr_multiaddr.s_addr = mcasts[i].sin.sin_addr.s_addr;
        mreq.imr_interface.s_addr = iface->sin.sin_addr.s_addr;
        if(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(struct ip_mreq)) == -1)
            dmn_log_fatal("Multicast IP_ADD_MEMBERSHIP failure for multicast addr '%s' + interface addr '%s': %s",
                dmn_logf_anysin_noport(&mcasts[i]),
                dmn_logf_anysin_noport(iface),
                dmn_logf_errno()
            );
    }

    return sock;
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

static void receiver_read_cb(struct ev_loop* loop, ev_io* w, int revents) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_READ);

    receiver_t* r = w->data;
    dmn_assert(r->fd == w->fd);
    dmn_assert(r->read_watcher == w);

    dmn_log_debug("receiver: recv()ing packets...");
    unsigned recv_ctr = MAX_TIGHT_RECV;
    unsigned queued_ctr = MAX_TIGHT_QUEUE;
    while(recv_ctr-- && queued_ctr) {
        int recvrv = recv(r->fd, r->inbuf, INBUF_SIZE, 0);
        if(recvrv < 0) {
           if(errno == EAGAIN || errno == EINTR)
               break; // back to libev
           dmn_log_fatal("UDP socket error: %s", dmn_strerror(errno));
        }
        // dmn_log_debug("receiver: processing packet %u ...", MAX_TIGHT_RECV - recv_ctr);
        stats.inpkts_recvd++;

        if(recvrv > INBUF_SIZE) {
            dmn_log_warn("Rejecting HTCP packet, size larger than %d", INBUF_SIZE);
            continue; // too big, drop the request but keep looping
        }

        if(recvrv < 20) {
            dmn_log_warn("Rejecting HTCP packet, size smaller than 20");
            continue; // too small to have a valid request in it
        }

        // Parse the URL from the message, filtering for CLR op.
        // Note this is supposed to be RFC2756, but (a) the RFC itself has clear logical
        //   errors in its description of the wire format, and (b) that aside, apparently
        //   Squid and Mediawiki speak a whole different dialect that differs even where
        //   the RFC is clear.  So we're adapting to the Squid/Mediawiki way and being
        //   very very minimalistic about validating the data.
        if(r->inbuf[6] != 4U) { // CLR opcode
            dmn_log_warn("Rejecting HTCP packet, no CLR opcode");
            continue;
        }

        unsigned offs = 14; // start offset for data section
        const unsigned method_len = ntohs(get_una16(&r->inbuf[offs])); offs += 2;
        offs += method_len; // skip method
        if((offs + 2U) >= (unsigned)recvrv) {
            dmn_log_warn("Rejecting HTCP packet, URL len field runs off end of packet");
            continue;
        }
        unsigned url_len = ntohs(get_una16(&r->inbuf[offs])); offs += 2;
        if(!url_len) {
            dmn_log_warn("Rejecting HTCP packet, URL len is zero");
            continue;
        }
        if((offs + url_len) > (unsigned)recvrv) {
            dmn_log_warn("Rejecting HTCP packet, URL runs off end of packet");
            continue;
        }
        r->inbuf[offs + url_len] = '\0'; // inject NUL-terminator in the buffer
        const char* url = &r->inbuf[offs];

        // Parse the URL itself into host+path parts with http_parser
        struct http_parser_url up;
        memset(&up, 0, sizeof(struct http_parser_url));
        if(http_parser_parse_url(url, url_len, 0, &up) || ((up.field_set & uf_hostpath) != uf_hostpath)) {
            dmn_log_warn("Rejecting enqueued URL, cannot parse host + path: %s", url);
            continue;
        }

        // Figure out the request encoding and see if it's too big for OUTBUF_SIZE
        const char* path_etc;
        unsigned path_etc_len;
        if(r->purge_full_url) {
            path_etc = url;
            path_etc_len = url_len;
        }
        else {
            path_etc = &url[up.field_data[UF_PATH].off];
            path_etc_len = url_len - up.field_data[UF_PATH].off;
        }

        const char* hn = &url[up.field_data[UF_HOST].off];
        const unsigned hn_len = up.field_data[UF_HOST].len;

        const unsigned buf_len = out_prefix_len + path_etc_len + out_middle_len + hn_len + out_suffix_len;
        if(buf_len > OUTBUF_SIZE) {
            dmn_log_warn("Rejecting URL for excessive size: %s", url);
            continue;
        }

        stats.inpkts_sane++;

        // dmn_log_debug("receiver: packet %u passed sanity filters...", MAX_TIGHT_RECV - recv_ctr);

        // optionally regex-filter the hostname in the URL
        if(r->matcher) {
            int pcre_rv = pcre_exec(r->matcher, r->matcher_extra,
                hn, hn_len, 0, 0, NULL, 0);
            if(pcre_rv < 0) { // match failed, or an error occured
                if(pcre_rv != PCRE_ERROR_NOMATCH)
                    dmn_log_err("Error executing regex matcher: PCRE error code: %d", pcre_rv);
                continue;
            }
        }

        dmn_log_debug("receiver: packet %u passed regex filter...", MAX_TIGHT_RECV - recv_ctr);

        // encode an output buffer, purger->strq will copy, so use local mem
        char buf[buf_len];
        char* writeptr = &buf[0];
        memcpy(writeptr, out_prefix, out_prefix_len); writeptr += out_prefix_len;
        memcpy(writeptr,   path_etc,   path_etc_len); writeptr +=   path_etc_len;
        memcpy(writeptr, out_middle, out_middle_len); writeptr += out_middle_len;
        memcpy(writeptr,         hn,         hn_len); writeptr +=         hn_len;
        memcpy(writeptr, out_suffix, out_suffix_len); // writeptr += out_suffix_len;

        // send to purger's input queue
        purger_enqueue(r->purger, buf, buf_len);
        queued_ctr--;
    }

    dmn_log_debug("receiver: done recv()ing, enqueued: %u", MAX_TIGHT_QUEUE - queued_ctr);
    purger_ping(r->purger);
}

receiver_t* receiver_new(struct ev_loop* loop, const pcre* matcher, const pcre_extra* matcher_extra, purger_t* purger, int lsock, bool purge_full_url) {
    dmn_assert(loop); dmn_assert(purger);

    receiver_t* r = malloc(sizeof(receiver_t));
    r->purge_full_url = purge_full_url;
    r->inbuf = malloc(INBUF_SIZE);
    r->read_watcher = malloc(sizeof(ev_io));
    r->matcher = matcher;
    r->matcher_extra = matcher_extra;
    r->loop = loop;
    r->purger = purger;
    r->fd = lsock;
    ev_io_init(r->read_watcher, receiver_read_cb, r->fd, EV_READ);
    ev_set_priority(r->read_watcher, 2);
    r->read_watcher->data = r;
    ev_io_start(loop, r->read_watcher);

    return r;
}

void receiver_destroy(receiver_t* r) {
    dmn_assert(r);
    ev_io_stop(r->loop, r->read_watcher);
    close(r->fd);
    free(r->read_watcher);
    free(r->inbuf);
    free(r);
}
