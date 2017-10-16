/* Copyright © 2013-2017 Brandon L Black <bblack@wikimedia.org>
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

// MUST be a power of 2
#define INIT_QSIZE 1024U

// head==tail means empty queue
struct strq {
    qentry_t* queue; // the queue itself
    size_t    head;  // always mod q_alloc
    size_t    tail;  // always mod q_alloc
    size_t    alloc; // allocated slots of "queue" above
    size_t    size;  // used from allocation, always < q_alloc
    size_t    mem;   // total memory used by queue+strs
    size_t    shrink_limit; // will not shrink "alloc" below this...
    purger_stats_t* pstats;
};

#ifdef NDEBUG

#define assert_queue_sane(x) ((void)(0))

#else

static void assert_queue_sane(strq_t* q) {
    dmn_assert(q);
    dmn_assert(q->alloc);
    dmn_assert(q->size < q->alloc);
    dmn_assert(q->head < q->alloc);
    dmn_assert(q->tail < q->alloc);
    if(q->size) {
        // q_mem assert only assumes bare min 1 byte strings
        dmn_assert(q->mem >= (q->alloc * sizeof(qentry_t)) + q->size);
        dmn_assert(q->head != q->tail);
        const size_t itermask = q->alloc - 1;
        size_t i = q->head;
        do {
            qentry_t* qe = &q->queue[i];
            dmn_assert(qe->str);
            dmn_assert(qe->len);
            i++;
            i &= itermask;
        } while(i != q->tail);
    }
    else {
       // when queue is empty, q_mem should reflect allocated structures
       dmn_assert(q->mem == (q->alloc * sizeof(qentry_t)));
    }
}

#endif

strq_t* strq_new(purger_stats_t* pstats) {
    dmn_assert(pstats);

    strq_t* q = calloc(1, sizeof(*q));
    q->pstats = pstats;
    q->alloc = INIT_QSIZE;
    q->shrink_limit = INIT_QSIZE;
    q->mem = q->alloc * sizeof(*q->queue);
    q->queue = malloc(q->mem);
    return q;
}

static void strq_grow(strq_t* q) {
    dmn_assert(q);

    // first, double the raw space
    const size_t old_alloc = q->alloc;
    q->alloc <<= 1;
    dmn_log_debug("strq: realloc queue to %zu entries", q->alloc);
    q->queue = realloc(q->queue, q->alloc * sizeof(*q->queue));
    q->mem += (old_alloc * sizeof(*q->queue));
    // if there's a wrapped tail, unwrap it
    if(q->head) {
        dmn_assert(q->tail < old_alloc); // memcpy doesn't overlap
        memcpy(&q->queue[old_alloc], q->queue, q->tail * sizeof(qentry_t));
    }
    q->tail += old_alloc;
    dmn_assert(q->tail < q->alloc); // new tail within new storage
}

static void strq_shrink(strq_t* q) {
    dmn_assert(q);

    // If the current queue contents wrap over the end of the space,
    // we'll need to first un-wrap them by shifting the tail portion at
    // the bottom forward and then copying the head portion down to the
    // start.  We know there's more than enough space to do this because
    // we only trigger on < 1/8 total allocation fill.
    if(q->tail < q->head) {
        const size_t head_end_bytes = q->alloc - q->head;
        memmove(&q->queue[head_end_bytes], q->queue, q->tail * sizeof(*q->queue));
        memcpy(q->queue, &q->queue[q->head], head_end_bytes * sizeof(*q->queue));
        q->tail = q->size;
        q->head = 0;
    }

    // Otherwise if we have a normal non-wrapped queue whose contents
    // intrude on the upper half about to be freed, copy it down:
    else if(q->tail >= (q->alloc >> 1)) {
        memcpy(q->queue, &q->queue[q->head], q->size * sizeof(*q->queue));
        q->tail = q->size;
        q->head = 0;
    }

    // Now that the above has ensured the queue contents are non-wrapped
    // and fit within the first half of the buffer, do the shrink:
    q->alloc >>= 1;
    const size_t new_size = q->alloc * sizeof(*q->queue);
    q->mem -= new_size;
    dmn_log_debug("strq: realloc queue to %zu entries", q->alloc);
    q->queue = realloc(q->queue, new_size);
}

const qentry_t* strq_dequeue(strq_t* q) {
    dmn_assert(q);

    const qentry_t* qe = NULL;
    if(q->size) {
        // shrink by half if above shrink_limit && qsize <= alloc/8
        if(q->alloc > q->shrink_limit && q->size <= (q->alloc >> 3))
            strq_shrink(q);
        qe = &q->queue[q->head];
        dmn_assert(qe->str);
        dmn_assert(qe->len);
        q->head++;
        q->head &= (q->alloc - 1U); // mod po2 to wrap
        q->size--;
        q->pstats->q_size = q->size;
        q->mem -= qe->len;
        q->pstats->q_mem = q->mem;

        if(!q->size)
            q->head = q->tail = 0;

        assert_queue_sane(q);
    }
    return qe;
}

void strq_enqueue(strq_t* q, char* new_string, const size_t len, const ev_tstamp stamp) {
    dmn_assert(q); dmn_assert(new_string); dmn_assert(len);

    // account for new string in all stats and qsize
    q->size++;
    q->pstats->q_size = q->size;
    if(q->size > q->pstats->q_max_size) {
        q->pstats->q_max_size = q->size;
	// shrink_limit starts at INIT_QSIZE, then grows to a
	// non-power-of-two size of max_size/4 over time as max_size
	// rises.  The actual power-of-two we halve to on shrinking will
	// therefore be somewhere in the range of 1/8 to 1/4 of the
	// max_size at any given time.
	const size_t max_size_quarter = q->size >> 2;
        if(max_size_quarter > q->shrink_limit)
            q->shrink_limit = max_size_quarter;
    }

    // update tail pointer
    qentry_t* qe = &q->queue[q->tail];
    qe->str = new_string;
    qe->len = len;
    qe->stamp = stamp;
    q->tail++;
    q->tail &= (q->alloc - 1); // mod po2 to wrap
    q->mem += len;

    // Grow queue by doubling if completely full
    if(q->size == q->alloc) {
        dmn_assert(q->tail == q->head);
        strq_grow(q); // will grow q->mem too
        dmn_assert(q->tail != q->head);
    }

    q->pstats->q_mem = q->mem;
    if(q->mem > q->pstats->q_max_mem)
        q->pstats->q_max_mem = q->mem;

    assert_queue_sane(q);
}

void strq_destroy(strq_t* q) {
    /* This could free all the storage on shutdown, but seems wasteful
       unless we need it later for valgrind clarity
    size_t q_idx = q->head;
    while(q_idx != q->tail) {
        qentry_t* qe = q->queue[q_idx];
        free(qe->str);
        q_idx++;
        q->idx &= (q->alloc - 1U); // mod po2 to wrap
    }
    */
    free(q->queue);
    free(q);
}
