
#ifndef VHTCPD_STATS_H
#define VHTCPD_STATS_H

#include <inttypes.h>
#include <ev.h>

typedef struct {
    uint64_t inpkts_enqueued;
    uint64_t inpkts_dequeued;
    uint64_t inpkts_sent;
    uint64_t queue_size;
    uint64_t queue_max_size;
    uint64_t queue_mem;
} purger_stats_t;

typedef struct {
    uint64_t inpkts_recvd;
    uint64_t inpkts_sane;
    purger_stats_t* purgers;
} stats_t;

extern stats_t stats;

void stats_init(struct ev_loop* loop, const char* statsfile, const unsigned num_purgers_in);

#endif // VHTCPD_STATS_H
