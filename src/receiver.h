
#ifndef VHTCPD_RECEIVER_H
#define VHTCPD_RECEIVER_H

#include <sys/types.h>
#include <regex.h>
#include <ev.h>
#include "libdmn/dmn.h"
#include "strq.h"
#include "purger.h"

struct receiver;
typedef struct receiver receiver_t;

// create listening socket separately, because it can fail hard/early
//   and could potentially need privs depending on the port
int receiver_create_lsock(const dmn_anysin_t* iface, const dmn_anysin_t* mcasts, unsigned num_mcasts);

// Receiver does not own the loop, the regex, or the purger, the caller does.
// However, they must be valid for the life of the receiver.
receiver_t* receiver_new(
    struct ev_loop* loop,
    const regex_t* matcher,
    strq_t* queue,
    purger_t** purgers,
    unsigned num_purgers,
    int lsock
);
void receiver_destroy(receiver_t* r);

#endif // VHTCPD_RECEIVER_H
