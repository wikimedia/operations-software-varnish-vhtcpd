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

// MUST be a power of 2
#define INIT_QSIZE 1024U

struct strq {
    qentry_t* queue; // the queue itself

    // The queue itself wraps around.  head == tail
    //  could mean empty or full, depends on size.
    size_t q_head;    // always mod q_alloc
    size_t q_tail;    // always mod q_alloc
    size_t q_alloc;   // allocated slots of "queue" above
    size_t q_size;    // used from allocation, always < q_alloc

    purger_stats_t* pstats;
};

#ifdef NDEBUG

#define assert_queue_sane(x) ((void)(0))

#else

static void assert_queue_sane(strq_t* q) {
    dmn_assert(q);
    dmn_assert(q->q_alloc);
    dmn_assert(q->q_size < q->q_alloc);
    dmn_assert(q->q_head < q->q_alloc);
    dmn_assert(q->q_tail < q->q_alloc);
    if(q->q_size) {
        // queue_mem assert only assumes bare min 1 byte strings
        dmn_assert(q->pstats->queue_mem >= (q->q_alloc * sizeof(qentry_t)) + q->q_size);
        dmn_assert(q->q_head != q->q_tail);
        const size_t itermask = q->q_alloc - 1;
        size_t i = q->q_head;
        do {
            qentry_t* qe = &q->queue[i];
            dmn_assert(qe->str);
            dmn_assert(qe->len);
            i++;
            i &= itermask;
        } while(i != q->q_tail);
    }
    else {
       // when queue is empty, queue_mem should reflect allocated structures
       dmn_assert(q->pstats->queue_mem == (q->q_alloc * sizeof(qentry_t)));
    }
}

#endif

strq_t* strq_new(purger_stats_t* pstats) {
    dmn_assert(pstats);

    strq_t* q = calloc(1, sizeof(*q));
    q->pstats = pstats;
    q->q_alloc = INIT_QSIZE;
    q->pstats->queue_mem = q->q_alloc * sizeof(*q->queue);
    q->queue = malloc(q->pstats->queue_mem);
    return q;
}

const qentry_t* strq_dequeue(strq_t* q) {
    dmn_assert(q);

    const qentry_t* qe = NULL;
    if(q->q_size) {
        qe = &q->queue[q->q_head];
        dmn_assert(qe->str);
        dmn_assert(qe->len);
        q->pstats->queue_mem -= qe->len;
        q->pstats->inpkts_dequeued++;
        q->q_head++;
        q->q_head &= (q->q_alloc - 1U); // mod po2 to wrap
        q->q_size--;
        q->pstats->queue_size--;

        if(!q->q_size)
            q->q_head = q->q_tail = 0;

        assert_queue_sane(q);
    }
    return qe;
}

void strq_enqueue(strq_t* q, char* new_string, const size_t len, const ev_tstamp stamp) {
    dmn_assert(q); dmn_assert(new_string); dmn_assert(len);

    // account for new string in all stats and qsize
    q->pstats->queue_mem += len;
    q->pstats->queue_size++;
    q->pstats->inpkts_enqueued++;
    q->q_size++;
    if(q->q_size > q->pstats->queue_max_size)
        q->pstats->queue_max_size = q->q_size;

    // handle queue re-allocation if this bump fills us.
    //   note this "wastes" the final slot by reallocating early,
    //   but the upside is q_head != q_tail unless the queue is empty,
    //   which makes other logic simpler
    if(q->q_size == q->q_alloc) {
        // first, double the raw space
        const size_t old_alloc = q->q_alloc;
        q->q_alloc <<= 1;
        dmn_log_debug("strq: realloc queue to %zu entries", q->q_alloc);
        q->queue = realloc(q->queue, q->q_alloc * sizeof(*q->queue));
        q->pstats->queue_mem += (old_alloc * sizeof(*q->queue));
        // then, move the wrapped tail end to the physical end of
        //   the original allocation
        if(q->q_head) {
            dmn_assert(q->q_tail < old_alloc); // memcpy doesn't overlap
            memcpy(&q->queue[old_alloc], q->queue, q->q_tail * sizeof(qentry_t));
            q->q_tail += old_alloc;
        }
        dmn_assert(q->q_tail < q->q_alloc); // new tail within new storage
    }

    // update tail pointer
    qentry_t* qe = &q->queue[q->q_tail];
    qe->str = new_string;
    qe->len = len;
    qe->stamp = stamp;
    q->q_tail++;
    q->q_tail &= (q->q_alloc - 1); // mod po2 to wrap

    assert_queue_sane(q);
}

void strq_destroy(strq_t* q) {
    /* This could free all the storage on shutdown, but seems wasteful
       unless we need it later for valgrind clarity
    size_t q_idx = q->q_head;
    while(q_idx != q->q_tail) {
        qentry_t* qe = q->queue[q_idx];
        free(qe->str);
        q_idx++;
        q->q_idx &= (q->q_alloc - 1U); // mod po2 to wrap
    }
    */
    free(q->queue);
    free(q);
}
