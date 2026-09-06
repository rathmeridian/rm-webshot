/*
 * screenshot.h - Driving a headless browser to capture a page.
 *
 * Rendering a modern web page means running a browser engine, so rather than
 * embedding one we shell out to whichever Chromium-family browser is already
 * installed. That keeps the binary dependency-free at build time: the browser
 * is only needed at run time, and only when screenshots are requested.
 *
 * The child process is started with fork() and execvp() rather than system().
 * That matters for safety, because URLs are built from names supplied on the
 * command line and, in the case of DNS results, by remote servers. execvp
 * passes arguments as a vector directly to the new program, so there is no
 * shell to reinterpret quotes, semicolons or backticks.
 */

#ifndef SCREENSHOT_H
#define SCREENSHOT_H

#include <stddef.h>

/* Settings shared by every capture in a run. */
typedef struct {
    const char *browser;  /* path or name of the browser binary       */
    int width;            /* viewport width in pixels                 */
    int height;           /* viewport height in pixels                */
    int timeout_s;        /* kill the browser after this many seconds */
    int verbose;          /* non-zero: let browser output through     */
} screenshot_config_t;

/*
 * Look for a usable headless browser on PATH.
 *
 * Returns a static string naming the first one found, or NULL if none are
 * installed. The returned pointer must not be freed.
 */
const char *screenshot_find_browser(void);

/* The browser names we look for, NULL terminated. Useful for error messages. */
extern const char *const screenshot_browser_candidates[];

/*
 * Assemble a URL.
 *
 * Handles the two fiddly cases: IPv6 literals need square brackets, and the
 * default port for the scheme is left out so the URL looks natural.
 *
 * Returns 0 on success, -1 if the buffer was too small.
 */
int screenshot_build_url(const char *scheme, const char *host, int port,
                         char *buf, size_t buflen);

/*
 * Capture `url` into `out_path` as a PNG.
 *
 * Returns 0 on success, -1 on failure (a reason is printed to stderr).
 * Failure is common and not fatal: pages time out, refuse to load, or the
 * browser may not support a flag on an older release.
 */
int screenshot_capture(const screenshot_config_t *cfg, const char *url,
                       const char *out_path);

#endif /* SCREENSHOT_H */
