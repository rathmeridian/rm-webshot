/*
 * main.c - rm-webshot: scan hosts for web services and screenshot what you find.
 *
 * High level flow:
 *
 *   1. parse options and expand every positional argument into targets
 *   2. build one job per (target, port) pair
 *   3. hand the jobs to a thread pool; each job connects and probes
 *   4. print what was found
 *   5. if -s was given, walk the results and capture each web service
 *
 * The scan runs in parallel because it is I/O bound. The screenshot pass runs
 * one at a time on purpose: each capture starts a whole browser, and running
 * dozens at once will exhaust memory on a modest machine. If you want to
 * parallelise it, see the note above run_screenshot_pass().
 */

#include "scanner.h"
#include "screenshot.h"
#include "targets.h"
#include "threadpool.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ---------------------------------------------------------------- defaults */

/* Ports checked when the user does not pass -p. */
static const int DEFAULT_PORTS[] = { 80, 443, 8000, 8008, 8080, 8443, 8888 };
#define DEFAULT_PORT_COUNT ((int)(sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0])))

#define DEFAULT_THREADS       64
#define DEFAULT_TIMEOUT_MS    2000
#define DEFAULT_OUTPUT_DIR    "scan-output"
#define DEFAULT_SHOT_TIMEOUT  20
#define DEFAULT_WIDTH         1280
#define DEFAULT_HEIGHT        1024

/* Upper bound on -t, to stop a typo from spawning an absurd number of threads. */
#define MAX_THREADS 1024

/* ------------------------------------------------------------- job records */

/*
 * One unit of scanning work. Filled in before the pool starts and read back
 * after it finishes, so no locking is needed on these fields: each job is
 * touched by exactly one worker.
 */
typedef struct {
    const target_t *target; /* host being scanned                   */
    int port;               /* port being tested                    */
    int timeout_ms;         /* per-operation budget                 */
    int is_open;            /* result: 1 if something answered      */
    service_t service;      /* result: what it looked like          */
    int verbose;            /* echo closed ports too                */
} scan_job_t;

/* Serialises printing from worker threads so lines do not interleave. */
static pthread_mutex_t g_print_lock = PTHREAD_MUTEX_INITIALIZER;

/* -------------------------------------------------------------- utilities */

static void usage(const char *prog)
{
    printf(
"rm-webshot - scan hosts for HTTP/HTTPS services and screenshot them\n"
"\n"
"Usage: %s [options] <target> [target ...]\n"
"\n"
"Targets may be given as:\n"
"  an IPv4 or IPv6 address      192.0.2.10   or   ::1\n"
"  an IPv4 CIDR block           192.0.2.0/24\n"
"  a hostname                   example.com\n"
"\n"
"Options:\n"
"  -p, --ports <list>      Ports to scan. Comma separated, ranges allowed.\n"
"                          Example: -p 80,443,8000-8100\n"
"                          Default: 80,443,8000,8008,8080,8443,8888\n"
"  -t, --threads <n>       Concurrent scan workers (default %d, max %d)\n"
"  -T, --timeout <ms>      Per-connection timeout in milliseconds (default %d)\n"
"  -s, --screenshot        Capture screenshots of discovered web services.\n"
"                          Requires a Chromium-family browser on PATH.\n"
"  -o, --output <dir>      Root directory for results (default '%s')\n"
"      --shot-timeout <s>  Seconds to allow per screenshot (default %d)\n"
"      --window <WxH>      Browser viewport size (default %dx%d)\n"
"      --force-large-range Allow CIDR blocks wider than /24\n"
"  -v, --verbose           Report closed ports and browser output too\n"
"  -h, --help              Show this help\n"
"\n"
"Output layout:\n"
"  <output>/<host>/<ip>_<port>_screenshot<N>.png\n"
"\n"
"Only scan hosts you own or have explicit permission to test.\n",
        prog, DEFAULT_THREADS, MAX_THREADS, DEFAULT_TIMEOUT_MS,
        DEFAULT_OUTPUT_DIR, DEFAULT_SHOT_TIMEOUT, DEFAULT_WIDTH, DEFAULT_HEIGHT);
}

/*
 * Parse a port specification such as "80,443,8000-8100" into an array.
 *
 * On success returns a malloc'd array and writes its length to *out_count.
 * On failure returns NULL after printing why.
 */
static int *parse_ports(const char *spec, int *out_count)
{
    char *copy = strdup(spec);
    if (copy == NULL) {
        fprintf(stderr, "error: out of memory parsing ports\n");
        return NULL;
    }

    int capacity = 16;
    int count = 0;
    int *ports = malloc((size_t)capacity * sizeof(int));
    if (ports == NULL) {
        free(copy);
        fprintf(stderr, "error: out of memory parsing ports\n");
        return NULL;
    }

    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, ",", &saveptr);
         tok != NULL;
         tok = strtok_r(NULL, ",", &saveptr)) {

        int lo = 0;
        int hi = 0;

        /* Each token is either "N" or "A-B". */
        char *dash = strchr(tok, '-');
        if (dash != NULL) {
            *dash = '\0';
            lo = atoi(tok);
            hi = atoi(dash + 1);
        } else {
            lo = atoi(tok);
            hi = lo;
        }

        if (lo < 1 || lo > 65535 || hi < 1 || hi > 65535 || hi < lo) {
            fprintf(stderr, "error: invalid port specification '%s'\n", spec);
            free(ports);
            free(copy);
            return NULL;
        }

        for (int p = lo; p <= hi; p++) {
            if (count == capacity) {
                capacity *= 2;
                int *grown = realloc(ports, (size_t)capacity * sizeof(int));
                if (grown == NULL) {
                    fprintf(stderr, "error: out of memory parsing ports\n");
                    free(ports);
                    free(copy);
                    return NULL;
                }
                ports = grown;
            }
            ports[count++] = p;
        }
    }

    free(copy);

    if (count == 0) {
        fprintf(stderr, "error: no ports were given\n");
        free(ports);
        return NULL;
    }

    *out_count = count;
    return ports;
}

/*
 * Turn a host label into something safe to use as a directory name.
 *
 * This is a security boundary, not just cosmetics. A label can come from a
 * hostname the user typed, so without sanitising it a name containing '/' or
 * ".." could steer writes outside the output directory. Anything that is not
 * a plain letter, digit, dot, dash or underscore becomes an underscore, and
 * a leading dot is replaced so we cannot produce "." or "..".
 */
static void sanitize_name(const char *in, char *out, size_t outlen)
{
    size_t i = 0;
    for (; in[i] != '\0' && i < outlen - 1; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isalnum(c) || c == '.' || c == '-' || c == '_') {
            out[i] = (char)c;
        } else {
            out[i] = '_';
        }
    }
    out[i] = '\0';

    /* Never allow a name that begins with a dot. */
    if (out[0] == '.' || out[0] == '\0') {
        out[0] = '_';
    }
}

/*
 * Create a directory and any missing parents, like "mkdir -p".
 * Returns 0 on success or if it already exists.
 */
static int make_dir_p(const char *path)
{
    char tmp[PATH_MAX];
    size_t len = strlen(path);

    if (len == 0 || len >= sizeof(tmp)) {
        fprintf(stderr, "error: output path is empty or too long\n");
        return -1;
    }
    memcpy(tmp, path, len + 1);

    /* Drop a trailing slash so the loop does not try to mkdir "". */
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }

    /*
     * Walk the string, temporarily terminating at each separator so we can
     * create each ancestor in turn.
     */
    for (char *p = tmp + 1; *p != '\0'; p++) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "error: cannot create '%s': %s\n", tmp, strerror(errno));
            return -1;
        }
        *p = '/';
    }

    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "error: cannot create '%s': %s\n", tmp, strerror(errno));
        return -1;
    }
    return 0;
}

/* --------------------------------------------------------------- scanning */

/* Thread pool entry point: test one port and record the outcome. */
static void scan_job_run(void *arg)
{
    scan_job_t *job = (scan_job_t *)arg;

    service_t svc = SVC_CLOSED;
    int rc = scanner_check_port(job->target->ip, job->port, job->timeout_ms, &svc);

    job->is_open = (rc == 1);
    job->service = svc;

    /* Report findings as they happen so long scans show progress. */
    if (job->is_open || job->verbose) {
        pthread_mutex_lock(&g_print_lock);
        if (job->is_open) {
            printf("  [+] %s (%s) port %d -> %s\n",
                   job->target->label, job->target->ip, job->port,
                   scanner_service_name(svc));
        } else {
            printf("  [-] %s (%s) port %d closed\n",
                   job->target->label, job->target->ip, job->port);
        }
        fflush(stdout);
        pthread_mutex_unlock(&g_print_lock);
    }
}

/* ------------------------------------------------------------ screenshots */

/*
 * Per-host screenshot counter. The naming scheme requires a number that
 * increments per host, and a host can appear more than once (a name with
 * several A records), so we cannot simply use the port index.
 */
typedef struct {
    /*
     * Keyed by the full directory path rather than the bare label, so two
     * different labels that sanitise to the same name still get separate
     * counters. Sized to PATH_MAX to avoid truncating long output paths,
     * which would make two distinct hosts share a counter and overwrite
     * each other's files.
     */
    char dir[PATH_MAX];
    int count;
} host_counter_t;

/* Find or create the counter for a directory, returning the next number. */
static int next_screenshot_number(host_counter_t **counters, size_t *n,
                                  size_t *cap, const char *dir)
{
    for (size_t i = 0; i < *n; i++) {
        if (strcmp((*counters)[i].dir, dir) == 0) {
            return ++(*counters)[i].count;
        }
    }

    if (*n == *cap) {
        size_t new_cap = (*cap == 0) ? 16 : *cap * 2;
        host_counter_t *grown = realloc(*counters, new_cap * sizeof(**counters));
        if (grown == NULL) {
            return -1;
        }
        *counters = grown;
        *cap = new_cap;
    }

    strncpy((*counters)[*n].dir, dir, PATH_MAX - 1);
    (*counters)[*n].dir[PATH_MAX - 1] = '\0';
    (*counters)[*n].count = 1;
    (*n)++;
    return 1;
}

/*
 * Walk the finished jobs and capture every web service found.
 *
 * Deliberately sequential: one browser process at a time. To parallelise,
 * you could submit these to a second, much smaller thread pool (2-4 workers),
 * but the per-host counter would then need a mutex.
 */
static int run_screenshot_pass(scan_job_t *jobs, size_t job_count,
                               const char *output_dir,
                               const screenshot_config_t *shot_cfg)
{
    host_counter_t *counters = NULL;
    size_t counter_n = 0;
    size_t counter_cap = 0;
    int captured = 0;

    printf("\nCapturing screenshots with '%s'...\n", shot_cfg->browser);

    for (size_t i = 0; i < job_count; i++) {
        scan_job_t *job = &jobs[i];

        /* Only web services are worth pointing a browser at. */
        if (!job->is_open) {
            continue;
        }
        if (job->service != SVC_HTTP && job->service != SVC_HTTPS) {
            continue;
        }

        /* <output>/<sanitised host label>/ */
        char safe_label[TARGET_LABEL_LEN];
        sanitize_name(job->target->label, safe_label, sizeof(safe_label));

        char host_dir[PATH_MAX];
        if (snprintf(host_dir, sizeof(host_dir), "%s/%s", output_dir, safe_label)
                >= (int)sizeof(host_dir)) {
            fprintf(stderr, "warning: path too long for %s, skipping\n", safe_label);
            continue;
        }

        if (make_dir_p(host_dir) != 0) {
            continue;
        }

        int number = next_screenshot_number(&counters, &counter_n, &counter_cap, host_dir);
        if (number < 0) {
            fprintf(stderr, "error: out of memory tracking screenshot numbers\n");
            break;
        }

        /* <ip>_<port>_screenshot<N>.png, with the IP made filename-safe. */
        char safe_ip[TARGET_IP_LEN];
        sanitize_name(job->target->ip, safe_ip, sizeof(safe_ip));

        char out_path[PATH_MAX];
        if (snprintf(out_path, sizeof(out_path), "%s/%s_%d_screenshot%d.png",
                     host_dir, safe_ip, job->port, number) >= (int)sizeof(out_path)) {
            fprintf(stderr, "warning: path too long for %s, skipping\n", safe_ip);
            continue;
        }

        char url[2048];
        const char *scheme = (job->service == SVC_HTTPS) ? "https" : "http";
        if (screenshot_build_url(scheme, job->target->ip, job->port,
                                 url, sizeof(url)) != 0) {
            fprintf(stderr, "warning: could not build a URL for %s:%d\n",
                    job->target->ip, job->port);
            continue;
        }

        printf("  [*] %s -> %s\n", url, out_path);

        if (screenshot_capture(shot_cfg, url, out_path) == 0) {
            captured++;
        }
    }

    free(counters);
    return captured;
}

/* ------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    /* Option state, seeded with the defaults. */
    const char *port_spec = NULL;
    const char *output_dir = DEFAULT_OUTPUT_DIR;
    int thread_count = DEFAULT_THREADS;
    int timeout_ms = DEFAULT_TIMEOUT_MS;
    int want_screenshots = 0;
    int force_large_range = 0;
    int verbose = 0;
    int shot_timeout = DEFAULT_SHOT_TIMEOUT;
    int win_w = DEFAULT_WIDTH;
    int win_h = DEFAULT_HEIGHT;

    /* Long options without a short form get an id above the ASCII range. */
    enum {
        OPT_FORCE_LARGE = 1000,
        OPT_SHOT_TIMEOUT,
        OPT_WINDOW
    };

    static struct option long_opts[] = {
        { "ports",             required_argument, NULL, 'p' },
        { "threads",           required_argument, NULL, 't' },
        { "timeout",           required_argument, NULL, 'T' },
        { "screenshot",        no_argument,       NULL, 's' },
        { "output",            required_argument, NULL, 'o' },
        { "verbose",           no_argument,       NULL, 'v' },
        { "help",              no_argument,       NULL, 'h' },
        { "force-large-range", no_argument,       NULL, OPT_FORCE_LARGE },
        { "shot-timeout",      required_argument, NULL, OPT_SHOT_TIMEOUT },
        { "window",            required_argument, NULL, OPT_WINDOW },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:t:T:so:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            port_spec = optarg;
            break;
        case 't':
            thread_count = atoi(optarg);
            if (thread_count < 1 || thread_count > MAX_THREADS) {
                fprintf(stderr, "error: --threads must be between 1 and %d\n", MAX_THREADS);
                return 1;
            }
            break;
        case 'T':
            timeout_ms = atoi(optarg);
            if (timeout_ms < 50 || timeout_ms > 60000) {
                fprintf(stderr, "error: --timeout must be between 50 and 60000 ms\n");
                return 1;
            }
            break;
        case 's':
            want_screenshots = 1;
            break;
        case 'o':
            output_dir = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        case OPT_FORCE_LARGE:
            force_large_range = 1;
            break;
        case OPT_SHOT_TIMEOUT:
            shot_timeout = atoi(optarg);
            if (shot_timeout < 1 || shot_timeout > 600) {
                fprintf(stderr, "error: --shot-timeout must be between 1 and 600 seconds\n");
                return 1;
            }
            break;
        case OPT_WINDOW:
            if (sscanf(optarg, "%dx%d", &win_w, &win_h) != 2 ||
                win_w < 100 || win_h < 100 || win_w > 10000 || win_h > 10000) {
                fprintf(stderr, "error: --window expects WxH, for example 1280x1024\n");
                return 1;
            }
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "error: no targets given\n\n");
        usage(argv[0]);
        return 1;
    }

    /*
     * Check for a browser before doing any scanning. Failing here saves the
     * user from waiting through a long scan only to find nothing can be
     * captured at the end.
     */
    const char *browser = NULL;
    if (want_screenshots) {
        browser = screenshot_find_browser();
        if (browser == NULL) {
            fprintf(stderr, "error: -s was given but no supported browser was found.\n");
            fprintf(stderr, "       Looked for:");
            for (int i = 0; screenshot_browser_candidates[i] != NULL; i++) {
                fprintf(stderr, " %s", screenshot_browser_candidates[i]);
            }
            fprintf(stderr, "\n       Install one, for example: sudo apt install chromium\n");
            return 1;
        }
    }

    /* Work out which ports to scan. */
    int *ports = NULL;
    int port_count = 0;
    if (port_spec != NULL) {
        ports = parse_ports(port_spec, &port_count);
        if (ports == NULL) {
            return 1;
        }
    } else {
        port_count = DEFAULT_PORT_COUNT;
        ports = malloc((size_t)port_count * sizeof(int));
        if (ports == NULL) {
            fprintf(stderr, "error: out of memory\n");
            return 1;
        }
        memcpy(ports, DEFAULT_PORTS, sizeof(DEFAULT_PORTS));
    }

    /* Expand every positional argument into concrete targets. */
    target_list_t targets;
    target_list_init(&targets);

    for (int i = optind; i < argc; i++) {
        /*
         * A failure here is per-argument, not fatal: an unresolvable name
         * should not stop the other targets from being scanned.
         */
        targets_expand_arg(&targets, argv[i], force_large_range);
    }

    if (targets.count == 0) {
        fprintf(stderr, "error: no usable targets after expansion\n");
        free(ports);
        target_list_free(&targets);
        return 1;
    }

    /* One job per host/port combination. */
    size_t job_count = targets.count * (size_t)port_count;
    scan_job_t *jobs = calloc(job_count, sizeof(*jobs));
    if (jobs == NULL) {
        fprintf(stderr, "error: out of memory allocating %zu jobs\n", job_count);
        free(ports);
        target_list_free(&targets);
        return 1;
    }

    /*
     * Build jobs host-major so results come out grouped by host, which makes
     * the screenshot numbering read naturally.
     */
    size_t j = 0;
    for (size_t t = 0; t < targets.count; t++) {
        for (int p = 0; p < port_count; p++) {
            jobs[j].target = &targets.items[t];
            jobs[j].port = ports[p];
            jobs[j].timeout_ms = timeout_ms;
            jobs[j].verbose = verbose;
            j++;
        }
    }

    printf("Scanning %zu host(s) across %d port(s) = %zu checks, %d workers\n",
           targets.count, port_count, job_count, thread_count);

    /* Run the scan. */
    threadpool_t *pool = threadpool_create((size_t)thread_count);
    if (pool == NULL) {
        free(jobs);
        free(ports);
        target_list_free(&targets);
        return 1;
    }

    for (size_t i = 0; i < job_count; i++) {
        if (threadpool_submit(pool, scan_job_run, &jobs[i]) != 0) {
            fprintf(stderr, "warning: could not queue a scan job\n");
        }
    }

    threadpool_wait(pool);
    threadpool_destroy(pool);

    /* Summarise. */
    int open_count = 0;
    int web_count = 0;
    for (size_t i = 0; i < job_count; i++) {
        if (!jobs[i].is_open) {
            continue;
        }
        open_count++;
        if (jobs[i].service == SVC_HTTP || jobs[i].service == SVC_HTTPS) {
            web_count++;
        }
    }

    printf("\nScan complete: %d open port(s), %d look like web services\n",
           open_count, web_count);

    /* Optional capture pass. */
    if (want_screenshots) {
        if (web_count == 0) {
            printf("Nothing to screenshot.\n");
        } else if (make_dir_p(output_dir) != 0) {
            fprintf(stderr, "error: could not create output directory '%s'\n", output_dir);
        } else {
            screenshot_config_t shot_cfg;
            shot_cfg.browser = browser;
            shot_cfg.width = win_w;
            shot_cfg.height = win_h;
            shot_cfg.timeout_s = shot_timeout;
            shot_cfg.verbose = verbose;

            int captured = run_screenshot_pass(jobs, job_count, output_dir, &shot_cfg);
            printf("\nSaved %d screenshot(s) under '%s/'\n", captured, output_dir);
        }
    } else if (web_count > 0) {
        printf("Re-run with -s to capture screenshots.\n");
    }

    free(jobs);
    free(ports);
    target_list_free(&targets);
    return 0;
}
