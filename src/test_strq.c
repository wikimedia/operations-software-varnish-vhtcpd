
#include <string.h>
#include <ev.h>
#include "strq.h"
#include "libdmn/dmn.h"

static const char test_str_1[] = "Test string #1";
static const char test_str_2[] = " - Test string #2, which happens to be a bit larger";
static const unsigned test_len_1 = sizeof(test_str_1) - 1;
static const unsigned test_len_2 = sizeof(test_str_2) - 1;

#define TST(msg, ...) do { \
    if(!(__VA_ARGS__)) \
        dmn_log_fatal("Test failed: " msg); \
    } while(0)

int main(int argc, char* argv[]) {
    dmn_init_log("test_strq", true);
    dmn_log_info("%s", argv[argc - 1]);
    struct ev_loop* loop = ev_loop_new(0);
    strq_t* q = strq_new(loop, 2);


    const char* deq_str = NULL;
    unsigned deq_len = 0;

    // Basic initial tests

    TST("empty initial queue", strq_is_empty(q));
    deq_str = strq_dequeue(q, &deq_len);
    TST("empty initial dequeue", !deq_str && !deq_len);

    strq_enqueue(q, test_str_1, test_len_1);
    deq_len = 0;
    TST("not-empty after one insert", !strq_is_empty(q));
    deq_str = strq_dequeue(q, &deq_len);
    TST("correct result dequeueing non-empty dequeue", deq_str && deq_len && !strcmp(test_str_1, deq_str));
    TST("empty again after one cycle", strq_is_empty(q));

    // Start 8K seq deq

    for(unsigned i = 0; i < 8000; i++) {
        strq_enqueue(q, test_str_1, test_len_1);
        strq_enqueue(q, test_str_2, test_len_2);
    }

    for(unsigned i = 0; i < 8000; i++) {
        TST("not-empty during 8k seq deq", !strq_is_empty(q));
        deq_len = 0;
        deq_str = strq_dequeue(q, &deq_len);
        TST("correct result during 8k seq deq", deq_str && deq_len && !strcmp(test_str_1, deq_str));
        TST("not-empty during 8k seq deq", !strq_is_empty(q));
        deq_len = 0;
        deq_str = strq_dequeue(q, &deq_len);
        TST("correct result during 8k seq deq", deq_str && deq_len && !strcmp(test_str_2, deq_str));
    }

    TST("empty queue post-8k", strq_is_empty(q));
    deq_len = 0;
    deq_str = strq_dequeue(q, &deq_len);
    TST("empty dequeue post-8k", !deq_str && !deq_len);

    strq_destroy(q);
    ev_loop_destroy(loop);

    return 0;
}
