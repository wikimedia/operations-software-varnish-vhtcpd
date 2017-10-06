
#ifndef VHTCPD_PURGER_H
#define VHTCPD_PURGER_H

#include <ev.h>
#include "libdmn/dmn.h"

struct purger;
typedef struct purger purger_t;

// Sender does not own the loop, the caller does.
purger_t* purger_new(struct ev_loop* loop, const dmn_anysin_t* daddr, unsigned max_mb, bool purge_full_url, unsigned io_timeout, unsigned idle_timeout);
void purger_enqueue(purger_t* s, const char* url, const unsigned url_len);
void purger_destroy(purger_t* s);

#endif // VHTCPD_PURGER_H
