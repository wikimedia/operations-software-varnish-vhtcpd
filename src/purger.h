
#ifndef VHTCPD_PURGER_H
#define VHTCPD_PURGER_H

#include <ev.h>
#include "stats.h"
#include "libdmn/dmn.h"

struct purger;
typedef struct purger purger_t;

// Purger does not own the loop, the caller does.
purger_t* purger_new(struct ev_loop* loop, const dmn_anysin_t* daddr, purger_t* next_purger, purger_stats_t* pstats, unsigned io_timeout, double delay);
void purger_enqueue(purger_t* p, char* req, const size_t req_len);
void purger_destroy(purger_t* p);

#endif // VHTCPD_PURGER_H
