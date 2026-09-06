/*
 * screenshot.c - Implementation of headless browser capture.
 *
 * The flow for one capture is:
 *   1. make a throwaway profile directory so parallel or repeat runs cannot
 *      fight over a shared Chromium profile lock
 *   2. fork and exec the browser with --screenshot
 *   3. wait, killing it if it exceeds the timeout
 *   4. delete the throwaway profile
 *   5. treat the capture as successful only if a non-empty file appeared
 */

#include "screenshot.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * Browsers we know how to drive, in order of preference. All are Chromium
 * derivatives and accept the same --headless --screenshot flags.
 * Firefox is deliberately absent: its --screenshot flag behaves differently
 * and does not accept an arbitrary output path in the same way.
 */
const char *const screenshot_browser_candidates[] = {
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "brave-browser",
    NULL
};

/* Poll interval while waiting for the browser to exit. */
#define WAIT_POLL_MS 100

/*
 * Is `name` runnable? We search PATH ourselves rather than calling `which`,
 * which avoids spawning a shell just to answer a simple question.
 */
static int is_executable_on_path(const char *name)
{
    const char *path = getenv("PATH");
    if (path == NULL) {
        return 0;
    }

    /* strtok modifies its input, so work on a copy. */
    char *copy = strdup(path);
    if (copy == NULL) {
        return 0;
    }

    int found = 0;
    char *saveptr = NULL;
    for (char *dir = strtok_r(copy, ":", &saveptr);
         dir != NULL;
         dir = strtok_r(NULL, ":", &saveptr)) {

        char candidate[4096];
        int n = snprintf(candidate, sizeof(candidate), "%s/%s", dir, name);
        if (n < 0 || (size_t)n >= sizeof(candidate)) {
            continue;
        }

        if (access(candidate, X_OK) == 0) {
            found = 1;
            break;
        }
    }

    free(copy);
    return found;
}

const char *screenshot_find_browser(void)
{
    for (int i = 0; screenshot_browser_candidates[i] != NULL; i++) {
        if (is_executable_on_path(screenshot_browser_candidates[i])) {
            return screenshot_browser_candidates[i];
        }
    }
    return NULL;
}

int screenshot_build_url(const char *scheme, const char *host, int port,
                         char *buf, size_t buflen)
{
    /* An IPv6 literal contains colons and must be wrapped in brackets. */
    int is_ipv6 = (strchr(host, ':') != NULL);

    /* Omit the port when it is the default for the scheme. */
    int default_port = (strcmp(scheme, "https") == 0) ? 443 : 80;

    int n;
    if (port == default_port) {
        n = snprintf(buf, buflen, "%s://%s%s%s/",
                     scheme,
                     is_ipv6 ? "[" : "", host, is_ipv6 ? "]" : "");
    } else {
        n = snprintf(buf, buflen, "%s://%s%s%s:%d/",
                     scheme,
                     is_ipv6 ? "[" : "", host, is_ipv6 ? "]" : "",
                     port);
    }

    if (n < 0 || (size_t)n >= buflen) {
        return -1;
    }
    return 0;
}

/* Callback for nftw: delete one entry. */
static int unlink_entry(const char *path, const struct stat *sb,
                        int typeflag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)typeflag;
    (void)ftwbuf;
    return remove(path);
}

/* Recursively delete a directory tree, ignoring errors. */
static void remove_tree(const char *path)
{
    /*
     * FTW_DEPTH visits children before their parent, which is what remove()
     * needs. FTW_PHYS stops us following symlinks out of the tree.
     */
    nftw(path, unlink_entry, 16, FTW_DEPTH | FTW_PHYS);
}

/* Sleep for a number of milliseconds, restarting if a signal interrupts. */
static void sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
        /* resume the remaining time */
    }
}

/*
 * Wait for `pid`, giving up after timeout_s seconds.
 * Returns the exit status, or -1 if the child had to be killed.
 */
static int wait_with_timeout(pid_t pid, int timeout_s)
{
    int waited_ms = 0;
    int limit_ms = timeout_s * 1000;

    for (;;) {
        int status = 0;
        pid_t r = waitpid(pid, &status, WNOHANG);

        if (r == pid) {
            /* Exited on its own. Report its code, or -1 if a signal got it. */
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            return -1;
        }

        if (r < 0) {
            return -1; /* waitpid failed outright */
        }

        if (waited_ms >= limit_ms) {
            /*
             * Out of time. Ask politely first, then insist. Chromium can
             * ignore SIGTERM while it is starting up.
             */
            kill(pid, SIGTERM);
            sleep_ms(500);
            if (waitpid(pid, &status, WNOHANG) != pid) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
            }
            return -1;
        }

        sleep_ms(WAIT_POLL_MS);
        waited_ms += WAIT_POLL_MS;
    }
}

/* True if the path exists and holds more than zero bytes. */
static int file_has_content(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return S_ISREG(st.st_mode) && st.st_size > 0;
}

/*
 * Run the browser once with a specific headless flag.
 * Split out because older Chromium builds only accept "--headless" while
 * newer ones want "--headless=new", and we want to try both.
 */
static int run_browser(const screenshot_config_t *cfg, const char *headless_flag,
                       const char *url, const char *out_path)
{
    /* Throwaway profile directory, unique per capture. */
    char profile_dir[] = "/tmp/rm-webshot-profile-XXXXXX";
    if (mkdtemp(profile_dir) == NULL) {
        fprintf(stderr, "error: could not create a temporary browser profile: %s\n",
                strerror(errno));
        return -1;
    }

    /* Flags that take a value have to be assembled into their own buffers. */
    char arg_profile[512];
    char arg_window[64];
    char arg_shot[4096];
    char arg_budget[64];

    snprintf(arg_profile, sizeof(arg_profile), "--user-data-dir=%s", profile_dir);
    snprintf(arg_window, sizeof(arg_window), "--window-size=%d,%d", cfg->width, cfg->height);
    snprintf(arg_shot, sizeof(arg_shot), "--screenshot=%s", out_path);

    /*
     * Virtual time budget lets the page run timers quickly and then forces the
     * screenshot, so a page with an endless animation still gets captured.
     * Two thirds of the hard timeout leaves room for browser startup.
     */
    snprintf(arg_budget, sizeof(arg_budget), "--virtual-time-budget=%d",
             (cfg->timeout_s * 1000 * 2) / 3);

    char *argv[] = {
        (char *)cfg->browser,
        (char *)headless_flag,
        "--disable-gpu",              /* no GPU in a headless context      */
        "--no-sandbox",               /* required when running as root     */
        "--disable-dev-shm-usage",    /* avoids /dev/shm limits in Docker  */
        "--disable-extensions",
        "--disable-background-networking",
        "--no-first-run",
        "--no-default-browser-check",
        "--hide-scrollbars",
        "--ignore-certificate-errors", /* self-signed certs are the norm here */
        arg_profile,
        arg_window,
        arg_budget,
        arg_shot,
        (char *)url,
        NULL
    };

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "error: fork failed: %s\n", strerror(errno));
        remove_tree(profile_dir);
        return -1;
    }

    if (pid == 0) {
        /* Child process. */
        if (!cfg->verbose) {
            /*
             * Chromium is extremely chatty on stderr even when it succeeds.
             * Send both streams to /dev/null unless the user asked to see them.
             */
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > STDERR_FILENO) {
                    close(devnull);
                }
            }
        }

        execvp(cfg->browser, argv);

        /* Only reached if exec failed. _exit avoids flushing the parent's buffers. */
        _exit(127);
    }

    /* Parent process. */
    int rc = wait_with_timeout(pid, cfg->timeout_s);
    remove_tree(profile_dir);

    /*
     * Chromium sometimes returns a non-zero status while still having written
     * a perfectly good screenshot, so the file is the real source of truth.
     */
    if (file_has_content(out_path)) {
        return 0;
    }

    return (rc == 127) ? 127 : -1;
}

int screenshot_capture(const screenshot_config_t *cfg, const char *url,
                       const char *out_path)
{
    if (cfg == NULL || cfg->browser == NULL) {
        return -1;
    }

    /* Newer Chromium wants --headless=new; try it first. */
    int rc = run_browser(cfg, "--headless=new", url, out_path);
    if (rc == 0) {
        return 0;
    }

    if (rc == 127) {
        fprintf(stderr, "error: could not execute browser '%s'\n", cfg->browser);
        return -1;
    }

    /* Fall back to the older flag before declaring failure. */
    rc = run_browser(cfg, "--headless", url, out_path);
    if (rc == 0) {
        return 0;
    }

    fprintf(stderr, "warning: screenshot of %s failed or timed out\n", url);
    return -1;
}
