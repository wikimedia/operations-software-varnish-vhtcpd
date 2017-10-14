
#ifndef VHTCPD_STRQ_H
#define VHTCPD_STRQ_H

#include <ev.h>
#include "stats.h"

/*
 * This is a single-threaded queue of strings with
 *  its own storage for the string data.  Sizes are
 *  unlimited, and storage will auto-grow if necc
 *  during enqueue.
 */

typedef struct {
    char* str;
    size_t len;
    ev_tstamp stamp;
} qentry_t;

struct strq;
typedef struct strq strq_t;

// Create a new queue for strings
strq_t* strq_new(purger_stats_t* pstats);

// Add a new string onto the tail of the queue.  len cannot be zero.
// strq takes ownership of the string allocation at enqueue time.
void strq_enqueue(strq_t* q, char* new_string, const size_t len, const ev_tstamp stamp);

// Remove a string from the queue.  NULL retval if queue is empty.
// The queue owns the qentry_t storage, which is only valid until the
// next strq operation (in other words, consume it and forget it
// immediately after this call).  The actual string in qentry_t->str,
// however, is owned by the caller from dequeue onwards, and it is up to
// the caller to free it.
const qentry_t* strq_dequeue(strq_t* q);

// Destroy the whole queue, rendering the passed pointer invalid
void strq_destroy(strq_t* q);

#endif // VHTCPD_STRQ_H
