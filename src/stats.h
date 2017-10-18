
#ifndef VHTCPD_STATS_H
#define VHTCPD_STATS_H

#include <inttypes.h>
#include <ev.h>

typedef struct {
    uint64_t input;
    uint64_t failed;
    uint64_t q_size;
    uint64_t q_mem;
    uint64_t q_max_size;
    uint64_t q_max_mem;
} purger_stats_t;

typedef struct {
    uint64_t recvd;
    uint64_t bad;
    uint64_t filtered;
    purger_stats_t* purgers;
} stats_t;

extern stats_t stats;

void stats_init(struct ev_loop* loop, const char* statsfile, const unsigned num_purgers_in);

#endif // VHTCPD_STATS_H
