
#ifndef VHTCPD_STATS_H
#define VHTCPD_STATS_H

#include <inttypes.h>
#include <ev.h>

typedef struct {
    uint64_t inpkts_recvd;
    uint64_t inpkts_sane;
    uint64_t inpkts_enqueued;
    uint64_t inpkts_dequeued;
    uint64_t queue_overflows;
} stats_t;

extern stats_t stats;

void stats_init(struct ev_loop* loop, const char* statsfile);

#endif // VHTCPD_STATS_H
