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

#include "strq.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ev.h>

#include "stats.h"
#include "libdmn/dmn.h"

// MUST be powers of two, and don't make them any
//   smaller than these values, please.  There may
//   be assumptions that these values can be right-
//   shifted N bits and still have a non-zero value...
#define INIT_QSIZE 64U
#define INIT_STRSIZE 4096U

// Attempt excess space reclamation every ~5 minutes
//  (faster in debug build)
#ifdef NDEBUG
#define RECLAIM_SECS 293U
#else
#define RECLAIM_SECS 17U
#endif

typedef struct {
    unsigned idx;
    unsigned len;
} qentry_t;

struct strq {
    qentry_t* queue; // the queue itself
    char* strings;   // all strings for the queue

    // The queue itself wraps around.  head == tail
    //  could mean empty or full, depends on size.
    unsigned q_head;    // always mod q_alloc
    unsigned q_tail;    // always mod q_alloc
    unsigned q_alloc;   // allocation size of "queue" above
    unsigned q_size;    // used from allocation, always < q_alloc
    unsigned q_maxsize; // peak value of the above over time...

    // Virtual heads for multiple dequeuers operating in parallel
    // Note that at least one head always matches the true head, and
    //   one or more others could be ahead of the true head
    unsigned num_vheads;
    unsigned* vheads;

    // The string storage doesn't wrap.  New space is consumed
    //   at the end and released from the front, until it becomes
    //   necessary to memmove() whatever remains to the bottom
    //   and possibly expand the storage.
    unsigned str_head;  // always mod str_alloc
    unsigned str_tail;  // in some corner cases, this can point
                        //  one byte off the end (== str_alloc), if
                        //  a large new string exactly occupied the
                        //  remaining free bytes in the tail.
    unsigned str_alloc; // allocation size of "strings" above

    unsigned max_mem;   // total memory limit for queue+strings

    // watchers for reclamation and stats(?)
    struct ev_loop* loop;
    ev_timer* reclaim_timer;
};

static void assert_queue_sane(strq_t* q) {
    dmn_assert(q);
    dmn_assert(q->q_size < q->q_alloc);
    dmn_assert(q->q_head < q->q_alloc);
    dmn_assert(q->q_tail < q->q_alloc);
    for(unsigned i = 0; i < q->num_vheads; i++)
        dmn_assert(q->vheads[i] < q->q_alloc);
    dmn_assert(q->str_head < q->str_alloc);
    dmn_assert(q->str_tail <= q->str_alloc);
    if(q->q_size) {
        dmn_assert(q->q_head != q->q_tail);
        const unsigned itermask = q->q_alloc - 1;
        unsigned i = q->q_head;
        do {
            qentry_t* qe = &q->queue[i];
            dmn_assert(qe->idx < q->str_alloc);
            dmn_assert(qe->len > 1);
            dmn_assert(qe->idx + qe->len <= q->str_alloc);
            i++;
            i &= itermask;
        } while(i != q->q_tail);
    }

    // at least one vhead is at the real head...
    bool one_vhead_is_head = false;
    for(unsigned i = 0; i < q->num_vheads; i++)
        if(q->vheads[i] == q->q_head)
            one_vhead_is_head = true;
    dmn_assert(one_vhead_is_head);
}

static void reclaim_cb(struct ev_loop* loop, ev_timer* w, int revents);

strq_t* strq_new(struct ev_loop* loop, unsigned max_mb, unsigned num_vheads) {
    dmn_assert(loop); dmn_assert(max_mb); dmn_assert(num_vheads);

    const unsigned max_mem = max_mb * 1024 * 1024;
    dmn_assert(max_mem > ((INIT_QSIZE * sizeof(qentry_t)) + INIT_STRSIZE));
    strq_t* q = calloc(1, sizeof(strq_t));
    q->max_mem = max_mem;
    q->num_vheads = num_vheads;
    q->vheads = calloc(num_vheads, sizeof(unsigned));
    q->q_alloc = INIT_QSIZE;
    q->str_alloc = INIT_STRSIZE;
    q->queue = malloc(q->q_alloc * sizeof(qentry_t));
    q->strings = malloc(q->str_alloc);
    q->loop = loop;
    q->reclaim_timer = malloc(sizeof(ev_timer));
    ev_timer_init(q->reclaim_timer, reclaim_cb, RECLAIM_SECS, RECLAIM_SECS);
    ev_set_priority(q->reclaim_timer, -1);
    q->reclaim_timer->data = q;
    ev_timer_start(q->loop, q->reclaim_timer);
    return q;
}

unsigned strq_is_empty(const strq_t* q, unsigned vhead) {
    dmn_assert(q); dmn_assert(vhead < q->num_vheads);
    return (q->vheads[vhead] == q->q_tail);
}

const char* strq_dequeue(strq_t* q, unsigned* len_outptr, unsigned vhead) {
    dmn_assert(q); dmn_assert(len_outptr); dmn_assert(vhead < q->num_vheads);

    const char* rv = NULL;
    const unsigned this_vhead = q->vheads[vhead];
    if(this_vhead != q->q_tail) {
        qentry_t* qe = &q->queue[this_vhead];
        dmn_assert(qe->len > 1);
        dmn_assert(qe->idx < q->str_alloc);
        rv = &q->strings[qe->idx];
        *len_outptr = qe->len - 1; // convert back from storage size to strlen size

        bool advance_head = false;
        if(this_vhead == q->q_head) { // we pulled from the real head
            advance_head = true;
            // a different vhead is also pointing at the real head...
            for(unsigned i = 0; i < q->num_vheads; i++)
                if(i != vhead && q->vheads[i] == this_vhead)
                    advance_head = false;
        }

        // advance the current vhead
        q->vheads[vhead]++;
        q->vheads[vhead] &= (q->q_alloc - 1U); // mod po2 to wrap

        if(advance_head) {
            stats.inpkts_dequeued++;
            q->q_head++;
            q->q_head &= (q->q_alloc - 1U); // mod po2 to wrap
            q->q_size--;
            if(!q->q_size) {
                // if this was the last entry remaining, it's an easy optimization
                //   to go ahead and reset the string head/tails back to zero to
                //   avoid unnecc move/shift later.
                dmn_assert((q->str_head + qe->len) == q->str_tail);
                q->str_head = q->str_tail = 0;
            }
            else {
                q->str_head += qe->len;
            }
        }
        assert_queue_sane(q);
    }
    return rv;
}

/* q->strings and growth/move stuff:
 *
 * New strings always go on the tail, and head strings are dequeued
 *   from the head.  If at enqueue time there's no room at the tail:
 *     1) If the total free space (head+tail ends) is less than double
 *        the string length, go ahead and realloc() to larger storage.
 *     2) Move the string head to the bottom via memmove().
 */

// shift all strings down such that str_head == 0
static void strings_shift(strq_t* q) {
    dmn_assert(q);
    dmn_assert(q->str_head);
    dmn_assert(q->q_size);

    const unsigned move_by = q->str_head;

    // adjust the strings stuff itself
    const unsigned move_total = q->str_tail - q->str_head;
    memmove(q->strings, &q->strings[move_by], move_total);
    q->str_tail -= move_by;
    q->str_head = 0;

    // adjust the queue entries to reflect the above
    const unsigned itermask = q->q_alloc - 1;
    unsigned i = q->q_head;
    do {
        q->queue[i].idx -= move_by;
        i++;
        i &= itermask;
    } while(i != q->q_tail);
}

// retval below if we hit the allocation limit and need to reset the queue...
#define SS_MAXALLOC_RV 0xFFFFFFFF

static unsigned store_string(strq_t* q, const char* new_string, unsigned len) {
    dmn_assert(q); dmn_assert(new_string); dmn_assert(len > 1);

    const unsigned tail_space = q->str_alloc - q->str_tail;
    if(len > tail_space) { // no easy room at end
        // if the string takes up half (or more) of the total
        //   free space at the head+tail ends, go ahead and expand
        //   the storage pool by doubling (possibly more than once,
        //   if the string is also larger than the whole current pool size)
        if(len > ((tail_space + q->str_head) >> 1U)) {
            unsigned new_str_alloc = q->str_alloc;
            while(len > new_str_alloc)
                new_str_alloc <<= 1;
            new_str_alloc <<= 1;
            if(new_str_alloc + (q->q_alloc * sizeof(qentry_t)) > q->max_mem)
                return SS_MAXALLOC_RV;
            q->str_alloc = new_str_alloc;
            dmn_log_debug("strq: realloc strings to %u bytes", q->str_alloc);
            q->strings = realloc(q->strings, q->str_alloc);
        }

        // shift all free space to the end if necc
        if(q->str_head)
            strings_shift(q);
   }

    const unsigned new_str_idx = q->str_tail;
    memcpy(&q->strings[new_str_idx], new_string, len);
    q->str_tail += len;

    assert_queue_sane(q);
    return new_str_idx;
}

static void wipe_queue(strq_t* q) {
    dmn_assert(q);
    dmn_log_err("Queue growth excessive! Wiping out backlog to prevent runaway memory growth");
    stats.queue_overflows++;
    q->q_size = q->q_head = q->q_tail = 0;
    q->str_head = q->str_tail = 0;
    memset(q->vheads, 0, q->num_vheads * sizeof(unsigned));
    assert_queue_sane(q);
}

void strq_enqueue(strq_t* q, const char* new_string, unsigned len) {
    dmn_assert(q); dmn_assert(new_string); dmn_assert(len);

    len++; // store the NUL, too

    // store string into q->strings and get its index
    const unsigned new_str_idx = store_string(q, new_string, len);

    if(new_str_idx == SS_MAXALLOC_RV)
        return wipe_queue(q);

    // handle queue re-allocation if this bump fills us.
    //   note this "wastes" the final slot by reallocating early,
    //   but the upside is q_head != q_tail unless the queue is empty,
    //   which makes other logic simpler with the virtual heads...
    q->q_size++;
    if(q->q_size == q->q_alloc) {
        if(q->str_alloc + ((q->q_alloc << 1) * sizeof(qentry_t)) > q->max_mem)
            return wipe_queue(q);
        // first, double the raw space
        const unsigned old_alloc = q->q_alloc;
        q->q_alloc <<= 1;
        dmn_log_debug("strq: realloc queue to %u entries", q->q_alloc);
        q->queue = realloc(q->queue, q->q_alloc * sizeof(qentry_t));
        // then, move the wrapped tail end to the physical end of
        //   the original allocation
        if(q->q_head) {
            dmn_assert(q->q_tail < old_alloc); // memcpy doesn't overlap
            memcpy(&q->queue[old_alloc], q->queue, q->q_tail * sizeof(qentry_t));
            q->q_tail += old_alloc;
        }
        dmn_assert(q->q_tail < q->q_alloc); // new tail within new storage
        // handle vhead moves if they were memcpy'd from the wrapped area
        for(unsigned i = 0; i < q->num_vheads; i++)
            if(q->vheads[i] < q->q_head)
                q->vheads[i] += old_alloc;
    }

    // queue sizing and peak-tracking
    if(q->q_size > q->q_maxsize)
        q->q_maxsize = q->q_size;

    // update tail pointer
    qentry_t* qe = &q->queue[q->q_tail];
    qe->idx = new_str_idx;
    qe->len = len;
    q->q_tail++;
    q->q_tail &= (q->q_alloc - 1); // mod po2 to wrap

    assert_queue_sane(q);
}

// Reclaim excessive allocation from the queue.  Invoked
//   periodically to reduce memory waste from queue spikes,
//   because the queue auto-grows on enqueue, but does not
//   auto-shrink on dequeue.  The implementation avoids
//   ping-pong cycles of reallocation (doesn't reclaim as
//   aggressively as it grows).
static void reclaim_cb(struct ev_loop* loop, ev_timer* w, int revents) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_TIMER);

    strq_t* q = w->data;
    dmn_assert(q);

    dmn_log_debug("strq: periodic reclaim hit: qa: %u qs: %u qh: %u qt: %u stra: %u strh: %u strt: %u",
            q->q_alloc, q->q_size, q->q_head, q->q_tail,
            q->str_alloc, q->str_head, q->str_tail);

    // Reclaim queue itself.  We cut the queue allocation in half
    //   iff the current queue size is less than 1/8 of the allocation,
    //   and is also larger than the initial size.
    if(q->q_alloc > (q->q_size << 3) && q->q_alloc > INIT_QSIZE) {
        if(q->q_size) {
            if(q->q_head <= q->q_tail) {
                memmove(q->queue, &q->queue[q->q_head], q->q_size * sizeof(qentry_t));
                for(unsigned i = 0; i < q->num_vheads; i++)
                    q->vheads[i] -= q->q_head;
                q->q_tail -= q->q_head;
                q->q_head = 0;
            }
            else {
                const unsigned end_len = q->q_alloc - q->q_head;
                const unsigned start_len = q->q_size - end_len;
                memmove(&q->queue[end_len], q->queue, start_len * sizeof(qentry_t));
                memcpy(q->queue, &q->queue[q->q_head], end_len * sizeof(qentry_t));
                for(unsigned i = 0; i < q->num_vheads; i++)
                    if(q->vheads[i] > q->q_tail)
                        q->vheads[i] -= q->q_head;
                    else
                        q->vheads[i] += end_len;
                q->q_tail += end_len;
                q->q_head = 0;
            }
        }
        else { // empty queue
            memset(q->vheads, 0, q->num_vheads * sizeof(unsigned));
            q->q_head = q->q_tail = 0;
        }

        q->q_alloc >>= 1;
        dmn_log_debug("strq: downsizing queue to %u entries", q->q_alloc);
        q->queue = realloc(q->queue, q->q_alloc * sizeof(qentry_t));
    }

    // Reclaim string storage.  Same basic rules as above.
    if(q->str_alloc > ((q->str_tail - q->str_head) << 3)
       && q->str_alloc > INIT_STRSIZE) {
        if(q->str_head)
            strings_shift(q);
        q->str_alloc >>= 1;
        dmn_log_debug("strq: downsizing strings to %u bytes", q->str_alloc);
        q->strings = realloc(q->strings, q->str_alloc);
    }

    assert_queue_sane(q);
}

void strq_destroy(strq_t* q) {
    ev_timer_stop(q->loop, q->reclaim_timer);
    free(q->vheads);
    free(q->reclaim_timer);
    free(q->strings);
    free(q->queue);
    free(q);
}
