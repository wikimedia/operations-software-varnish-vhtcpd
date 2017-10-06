
#ifndef VHTCPD_PURGER_H
#define VHTCPD_PURGER_H

#include <ev.h>
#include "stats.h"
#include "libdmn/dmn.h"

// this buffer holds a fully-formed HTTP request to purge a single URL,
// and is used by both the receiver and purger code
#define OUTBUF_SIZE 4096U

struct purger;
typedef struct purger purger_t;

// Sender does not own the loop, the caller does.
purger_t* purger_new(struct ev_loop* loop, const dmn_anysin_t* daddr, purger_t* next_purger, purger_stats_t* pstats, unsigned max_mb, unsigned io_timeout, unsigned idle_timeout);
void purger_enqueue(purger_t* s, const char* req, const unsigned req_len);
void purger_destroy(purger_t* s);

#endif // VHTCPD_PURGER_H
