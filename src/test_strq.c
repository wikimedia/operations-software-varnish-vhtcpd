
#include <string.h>
#include <ev.h>
#include "strq.h"
#include "stats.h"
#include "libdmn/dmn.h"

static char test_str_1[] = "Test string #1";
static char test_str_2[] = " - Test string #2, which happens to be a bit larger";
static const size_t test_len_1 = sizeof(test_str_1) - 1;
static const size_t test_len_2 = sizeof(test_str_2) - 1;

#define TST(msg, ...) do { \
    if(!(__VA_ARGS__)) \
        dmn_log_fatal("Test failed: " msg); \
    } while(0)

int main(int argc, char* argv[]) {
    dmn_init_log("test_strq", true);
    dmn_log_info("%s", argv[argc - 1]);
    struct ev_loop* loop = ev_loop_new(0);
    stats_init(loop, "/tmp/testme", 1);
    strq_t* q = strq_new(&stats.purgers[0]);

    const qentry_t* qe = NULL;

    // Basic initial tests

    qe = strq_dequeue(q);
    TST("empty initial dequeue", !qe);

    strq_enqueue(q, test_str_1, test_len_1, 0);
    qe = strq_dequeue(q);
    TST("correct result dequeueing non-empty dequeue: exists", qe);
    TST("correct result dequeueing non-empty dequeue: len-match", qe->len == test_len_1);
    TST("correct result dequeueing non-empty dequeue: data-match", !memcmp(test_str_1, qe->str, test_len_1));
    TST("empty again after one cycle", !strq_dequeue(q));

    // Start 8K seq deq

    for(unsigned i = 0; i < 8000; i++) {
        strq_enqueue(q, test_str_1, test_len_1, 0);
        strq_enqueue(q, test_str_2, test_len_2, 0);
    }

    for(unsigned i = 0; i < 8000; i++) {
        qe = strq_dequeue(q);
        TST("correct result during 8k seq deq", qe && qe->str && qe->len == test_len_1 && !memcmp(test_str_1, qe->str, test_len_1));
        qe = strq_dequeue(q);
        TST("correct result during 8k seq deq", qe && qe->str && qe->len == test_len_2 && !memcmp(test_str_2, qe->str, test_len_2));
    }

    TST("empty queue post-8k", !strq_dequeue(q));

    strq_destroy(q);
    ev_loop_destroy(loop);

    return 0;
}
