
#ifndef VHTCPD_STRQ_H
#define VHTCPD_STRQ_H

#include <ev.h>

/*
 * This is a single-threaded queue of strings with
 *  its own storage for the string data.  Sizes are
 *  unlimited, and storage will auto-grow if necc
 *  during enqueue.  Storage is downsized if excess
 *  space is very excessive, once in a while on a low
 *  priority libev callback.
 */

struct strq;
typedef struct strq strq_t;

// Create a new queue for strings
strq_t* strq_new(struct ev_loop* loop, unsigned max_mb);

// Anything pending
unsigned strq_is_empty(const strq_t* q);

// Remove a string from the queue.  NULL retval
//   if queue is empty.  Note that the returned string
//   storage is owned by the queue, and is considered
//   invalid as soon as any other write operation on
//   the queue occurs.  *len_outptr is set to the same
//   value strlen() would calculate on the returned
//   string (which we already had cached), and is not
//   set at all if the retval is NULL.
// Basically any return to libev or any call other than _get_size()
//   is going to invalidate the string.
const char* strq_dequeue(strq_t* q, unsigned* len_outptr);

// Copy a new string onto the tail of the queue.  Must be
//   NUL-terminated, and "len" should be the strlen() length of it.
void strq_enqueue(strq_t* q, const char* new_string, unsigned len);

// Destroy the whole queue, rendering the passed pointer invalid
void strq_destroy(strq_t* q);

#endif // VHTCPD_STRQ_H
