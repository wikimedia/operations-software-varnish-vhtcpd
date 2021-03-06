/* Copyright © 2013-2017 Brandon L Black <bblack@wikimedia.org>
 *
 * This file is part of vhtcpd.
 *
 * vhtcpd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * vhtcpd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with vhtcpd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <pcre.h>
#include <ev.h>
#include "purger.h"
#include "receiver.h"
#include "stats.h"
#include "libdmn/dmn.h"
#include "config.h"

// Tune jemalloc for our single-threaded usecase?
#include <jemalloc/jemalloc.h>
const char* malloc_conf = "narenas:1,tcache:false";

/* global libev priorities:
 *  2) receiver input
 *  1) purger i/o
 *  0) purger timeouts/timers
 * -1) <unused>
 * -2) stats/monitor stuff...
 */

static const char def_ifaddr[] = "0.0.0.0:4827";
#define DEF_USERNAME PACKAGE_NAME
#define DEF_PIDFILE VHTCPD_SYSRUNDIR "/" PACKAGE_NAME ".pid"
#define DEF_MCAST_PORT 4827U
#define DEF_STATS_FILE "/tmp/" PACKAGE_NAME ".stats"
#define DEF_IO_TIMEOUT 57U

static void usage(const char* argv0) {
    fprintf(stderr, PACKAGE_NAME " " PACKAGE_VERSION "\nUsage:\n"
        "%s "
#ifndef NDEBUG
        "[-d] "
#endif
        "[-v] [-F] [-u %s] [-p %s] [-a %s] [-r host_regex] [-s %s] [-t %u] -m mcast_addr -c cache_addr_port <action>\n"
#ifndef NDEBUG
        "  -d -- Extra debug logging for developer build\n"
#endif
        "  -v -- Verbose logging\n"
        "  -F -- Use full absolute URL in PURGE request\n"
        "  -u -- Username for privilege drop\n"
        "  -p -- Pidfile pathname\n"
        "  -a -- Multicast local listen IP[:Port] (port defaults to %u)\n"
        "  -r -- Regex filter for valid purge hostnames (PCRE case-insensitive, default unfiltered)\n"
        "  -s -- Stats output filename\n"
        "  -t -- I/O timeout for purgers\n"
        "  -m -- Multicast address (required, multiple allowed)\n"
        "  -c -- Cache IP:Port[,delay] or Hostname:Port[,delay]"
        "        ^ (required, multiple allowed, delay optional, def delay 0, min non-zero delay 0.1)\n"
        "<action> is one of:\n"
        "  startfg - Start " PACKAGE_NAME " in foreground w/ logs to stderr\n"
        "  start - Start " PACKAGE_NAME " as a regular daemon\n"
        "  stop - Stops a running daemon previously started by 'start'\n"
        "  restart - stop && start\n"
        "  reload - Aliases 'restart'\n"
        "  force-reload - Aliases 'restart'\n"
        "  condrestart - Does 'restart' action only if already running\n"
        "  try-restart - Aliases 'condrestart'\n"
        "  status - Checks the status of the running daemon\n\n",
    argv0, DEF_USERNAME, DEF_PIDFILE, def_ifaddr, DEF_STATS_FILE,
    DEF_IO_TIMEOUT, DEF_MCAST_PORT);
    exit(99);
}

typedef enum {
    ACT_STARTFG = 0,
    ACT_START,
    ACT_STOP,
    ACT_RESTART,
    ACT_CRESTART, // downgrades to ACT_RESTART after checking...
    ACT_STATUS,
    ACT_UNDEF
} action_t;

typedef struct {
    const char* cmdstring;
    action_t action;
} actmap_t;

static actmap_t actionmap[] = {
    { "startfg",      ACT_STARTFG },  // 1
    { "start",        ACT_START },    // 2
    { "stop",         ACT_STOP },     // 3
    { "reload",       ACT_RESTART },  // 4
    { "restart",      ACT_RESTART },  // 5
    { "force-reload", ACT_RESTART },  // 6
    { "condrestart",  ACT_CRESTART }, // 7
    { "try-restart",  ACT_CRESTART }, // 8
    { "status",       ACT_STATUS },   // 9
};
#define ACTIONMAP_COUNT 9

static action_t match_action(const char* arg) {
    dmn_assert(arg);

    unsigned i;
    for(i = 0; i < ACTIONMAP_COUNT; i++)
        if(!strcasecmp(actionmap[i].cmdstring, arg))
            return actionmap[i].action;
    return ACT_UNDEF;
}

typedef struct {
    action_t action;
    bool debug;
    bool verbose;
    bool purge_full_url;
    int lsock;
    unsigned num_purgers;
    unsigned io_timeout;
    char* username;
    char* pidfile;
    char* statsfile;
    pcre* matcher;
    pcre_extra* matcher_extra;
    dmn_anysin_t* purger_addrs;
    double* purger_delays;
} cfg_t;

static cfg_t* handle_args(int argc, char* argv[]) {
    cfg_t* cfg = calloc(1, sizeof(cfg_t));

    const char* match_str = NULL;
    const char* if_addr = NULL;
    unsigned num_purgers = 0;
    unsigned num_mcs = 0;
    const char** purger_addrs = NULL;
    const char** mc_addrs = NULL;

    // Basic cmdline parse
    int optch;
    while((optch = getopt(argc, argv, "a:c:dFl:m:p:r:s:T:t:u:v")) != -1) {
        switch(optch) {
            case 'a':
                if_addr = optarg;
                break;
            case 'c':
                num_purgers++;
                purger_addrs = realloc(purger_addrs, num_purgers * sizeof(char*));
                purger_addrs[num_purgers - 1] = optarg;
                break;
            case 'd':
                cfg->debug = true;
                break;
            case 'F':
                cfg->purge_full_url = true;
                break;
            case 'l':
                // ignore removed option for basic backcompat
                break;
            case 'm':
                num_mcs++;
                mc_addrs = realloc(mc_addrs, num_mcs * sizeof(char*));
                mc_addrs[num_mcs - 1] = optarg;
                break;
            case 'p':
                cfg->pidfile = strdup(optarg);
                break;
            case 'r':
                match_str = optarg;
                break;
            case 's':
                cfg->statsfile = strdup(optarg);
                break;
            case 'T':
                // ignore removed option for basic backcompat
                break;
            case 't':
                cfg->io_timeout = (unsigned)atoi(optarg);
                break;
            case 'u':
                cfg->username = strdup(optarg);
                break;
            case 'v':
                cfg->verbose = true;
                break;
            default:
                usage(argv[0]);
        }
    }

    // Defaulting
    if(!cfg->username)
        cfg->username = strdup(DEF_USERNAME);
    if(!cfg->pidfile)
        cfg->pidfile = strdup(DEF_PIDFILE);
    if(!if_addr)
        if_addr = def_ifaddr;
    if(!cfg->statsfile)
        cfg->statsfile = strdup(DEF_STATS_FILE);
    if(!cfg->io_timeout)
        cfg->io_timeout = DEF_IO_TIMEOUT;

    // require final non-option for action
    if(optind != (argc - 1)) {
        fprintf(stderr, "Missing <action>\n");
        usage(argv[0]);
    }

    cfg->action = match_action(argv[optind]);
    if(cfg->action == ACT_UNDEF) {
        fprintf(stderr, "Invalid <action>\n");
        usage(argv[0]);
    }

    // will we daemonize? startfg doesn't count...
    bool will_daemonize = false;
    switch(cfg->action) {
         case ACT_START:
         case ACT_RESTART:
         case ACT_CRESTART:
             will_daemonize = true;
             break;
         default:
             break;
    }

    dmn_init_log(PACKAGE_NAME, !will_daemonize);
    if(will_daemonize)
        dmn_start_syslog();

    // Handle debug stuff
    dmn_set_debug(cfg->debug);
    dmn_log_debug("Debug logging enabled!");

    // Take action for simple actions
    if(cfg->action == ACT_STATUS) {
        const pid_t oldpid = dmn_status(cfg->pidfile);
        if(!oldpid) {
            dmn_log_info("status: not running, based on pidfile '%s'", cfg->pidfile);
            exit(3);
        }
        dmn_log_info("status: running at pid %li in pidfile %s", (long)oldpid, cfg->pidfile);
        exit(0);
    }
    else if(cfg->action == ACT_STOP) {
        exit(dmn_stop(cfg->pidfile) ? 1 : 0);
    }

    if(cfg->action == ACT_CRESTART) {
        const pid_t oldpid = dmn_status(cfg->pidfile);
        if(!oldpid) {
            dmn_log_info("condrestart: not running, will not restart");
            exit(0);
        }
        cfg->action = ACT_RESTART;
    }

    // from here out, all actions are attempting startup...
    dmn_assert(cfg->action == ACT_STARTFG
            || cfg->action == ACT_START
            || cfg->action == ACT_RESTART
    );

    if(!geteuid())
        dmn_secure_setup(cfg->username, NULL);

    // Check basic things
    if(!num_mcs) {
        dmn_log_err("Argument -m mcast_addr required!");
        usage(argv[0]);
    }
    if(!num_purgers) {
        dmn_log_err("Argument -c cache_addr_port required!");
        usage(argv[0]);
    }

    // construct regex
    if(match_str) {
        const char* pcre_err = NULL;
        int pcre_err_offs = 0;
        cfg->matcher = pcre_compile(match_str, PCRE_CASELESS, &pcre_err, &pcre_err_offs, 0);
        if(!cfg->matcher)
            dmn_log_fatal("PCRE regex compilation error! %s at offset %d in >>> %s <<<", pcre_err, pcre_err_offs, match_str);
        cfg->matcher_extra = pcre_study(cfg->matcher, 0, &pcre_err);
        if(!cfg->matcher_extra && pcre_err) 
            dmn_log_fatal("Study of compiled regex '%s' failed: %s", match_str, pcre_err);
    }

    // Parse input IP/port strings...

    dmn_anysin_t iface;
    memset(&iface, 0, sizeof(dmn_anysin_t));
    int addr_err = dmn_anysin_fromstr(if_addr, DEF_MCAST_PORT, &iface, true);
    if(addr_err)
        dmn_log_fatal("Cannot parse interface address / port spec '%s': %s",
            if_addr, gai_strerror(addr_err));
    if(iface.sa.sa_family != AF_INET)
        dmn_log_fatal("Multicast listener config must be all IPv4");

    dmn_anysin_t mcasts[num_mcs];
    for(unsigned i = 0; i < num_mcs; i++) {
        addr_err = dmn_anysin_fromstr(mc_addrs[i], 0, &mcasts[i], true);
        if(addr_err)
            dmn_log_fatal("Cannot parse multicast address spec '%s': %s",
                mc_addrs[i], gai_strerror(addr_err));
        if(mcasts[i].sa.sa_family != AF_INET)
            dmn_log_fatal("Multicast listener config must be all IPv4");

    }
    free(mc_addrs);

    cfg->num_purgers = num_purgers;
    cfg->purger_addrs = calloc(num_purgers, sizeof(dmn_anysin_t));
    cfg->purger_delays = calloc(num_purgers, sizeof(double));
    for(unsigned i = 0; i < num_purgers; i++) {
        char* comma = strchr(purger_addrs[i], ',');
        if(comma) {
            *comma++ = '\0'; // inject NUL here to make addr parsing sane later
            char* endptr = NULL;
            errno = 0;
            double delay = strtod(comma, &endptr);
            if(endptr == comma || errno)
                dmn_log_fatal("Failed to parse a valid floating-point delay from '%s'", comma);
            if(delay < 0.1) {
                dmn_log_warn("delays '%s' increased to the minimum of 0.1s", comma);
                cfg->purger_delays[i] = 0.1;
            }
            else {
                cfg->purger_delays[i] = delay;
            }
        } else {
            cfg->purger_delays[i] = 0.0;
        }
        addr_err = dmn_anysin_fromstr(purger_addrs[i], 0, &cfg->purger_addrs[i], false);
        if(addr_err)
            dmn_log_fatal("Invalid cache address:port '%s': %s", purger_addrs[i], gai_strerror(addr_err));
    }
    free(purger_addrs);

    // Daemonize if applicable (before opening long-term sockets...)
    if(cfg->action != ACT_STARTFG)
        dmn_daemonize(cfg->pidfile, (cfg->action == ACT_RESTART));

    // Create the listening socket
    cfg->lsock = receiver_create_lsock(&iface, mcasts, num_mcs);

    // Drop privs
    if(!geteuid())
        dmn_secure_me(false);

    return cfg;
}

static void cfg_destroy(cfg_t* cfg) {
    free(cfg->username);
    free(cfg->pidfile);
    pcre_free(cfg->matcher_extra);
    pcre_free(cfg->matcher);
    free(cfg->purger_addrs);
    free(cfg->statsfile);
    free(cfg);
}

static purger_t** purgers = NULL;

static void syserr_for_ev(const char* msg) { dmn_assert(msg); dmn_log_fatal("%s: %s", msg, dmn_logf_errno()); }

static void terminal_signal(struct ev_loop* loop, struct ev_signal *w, const int revents) {
    dmn_assert(loop); dmn_assert(w);
    dmn_assert(revents == EV_SIGNAL);
    dmn_assert(w->signum == SIGTERM || w->signum == SIGINT);
    dmn_log_info("Received terminating signal %i, exiting", w->signum);
    ev_break(loop, EVBREAK_ALL);
}

static ev_signal* sig_int;
static ev_signal* sig_term;
static void setup_signals(struct ev_loop* loop) {
    dmn_assert(loop);

    sig_int = malloc(sizeof(ev_signal));
    sig_term = malloc(sizeof(ev_signal));

    ev_signal_init(sig_int, terminal_signal, SIGINT);
    ev_signal_start(loop, sig_int);
    ev_signal_init(sig_term, terminal_signal, SIGTERM);
    ev_signal_start(loop, sig_term);
}

#ifndef NDEBUG
static void debug_prep_cb(struct ev_loop *loop, ev_prepare *w, int revents) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_PREPARE);
    dmn_log_debug("------------------------------ Re-entered eventloop for waiting");
}
#endif

int main(int argc, char* argv[]) {
    // Parse args, do config/setup/daemonization tasks
    cfg_t* cfg = handle_args(argc, argv);

    // Basic libev setup
    ev_set_syserr_cb(syserr_for_ev);
    struct ev_loop* loop = ev_default_loop(EVBACKEND_SELECT);
    setup_signals(loop);

    // Determine minimum of the non-zero queue delays, and use 1/10th
    // this value as our timeout collect interval, with the maximum
    // clamped at ~0.1, and the implicit minimum at ~0.01 due to the
    // lower bound on the delay values.
    double io_interval = 0.1;
    for(unsigned i = 0; i < cfg->num_purgers; i++) {
        if(cfg->purger_delays[i] > 0.0 && cfg->purger_delays[i] < 1.0) {
            double one_tenth = cfg->purger_delays[i] / 10.0;
            if(one_tenth < io_interval)
                io_interval = one_tenth;
        }
    }
    dmn_log_info("libev timeout collection interval set to %.3f", io_interval);
    ev_set_timeout_collect_interval(loop, io_interval);

    // stats has a timeout callback for reporting
    stats_init(loop, cfg->statsfile, cfg->num_purgers);

    // print purger configs in ascending order to reduce user confusion
    for(unsigned i = 0; i < cfg->num_purgers; i++) {
        dmn_log_info("Configuring purger %u for %s with delay %.3f", i, dmn_logf_anysin(&cfg->purger_addrs[i]), cfg->purger_delays[i]);
    }

    // set up an array of purger objects, and initialize them in reverse
    // order so we can set up the purger->purger queueing chain
    purgers = malloc(cfg->num_purgers * sizeof(purger_t*));
    {
        purger_t* next_purger = NULL;
        unsigned i = cfg->num_purgers - 1;
        do {
            purger_stats_t* pstats = &stats.purgers[i];
            purgers[i] = purger_new(loop, &cfg->purger_addrs[i], next_purger, pstats, cfg->io_timeout, cfg->purger_delays[i], cfg->verbose);
            next_purger = purgers[i];
        } while(i--);
    }

    // set up the singular receiver, with purger[0] as the dequeur
    receiver_t* receiver = receiver_new(
        loop,
        cfg->matcher,
        cfg->matcher_extra,
        purgers[0],
        cfg->lsock,
        cfg->purge_full_url
    );

    // Finish daemonization (release initial process and stderr)
    if(cfg->action != ACT_STARTFG)
       dmn_daemonize_finish();

#ifndef NDEBUG
    ev_prepare* debug_prep = malloc(sizeof(ev_prepare));
    ev_prepare_init(debug_prep, debug_prep_cb);
    ev_prepare_start(loop, debug_prep);
#endif

    // All runtime executes here...
    ev_run(loop, 0);

    // cleanup
    receiver_destroy(receiver);
    for(unsigned i = 0; i < cfg->num_purgers; i++)
        purger_destroy(purgers[i]);
    ev_loop_destroy(loop);
    cfg_destroy(cfg);

    return 0;
}
