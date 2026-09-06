/*
 * targets.h - Turning command line arguments into concrete scan targets.
 *
 * A "target" is one resolved IP address plus the label the user originally
 * typed. Keeping the original label matters because output directories are
 * named after it: if you ask for "example.com" you want a directory called
 * example.com, not one named after whatever address it resolved to.
 *
 * Three kinds of argument are understood:
 *   - a literal IPv4 or IPv6 address   e.g. 192.0.2.10 or ::1
 *   - an IPv4 CIDR block               e.g. 192.0.2.0/24
 *   - a hostname                       e.g. example.com
 *
 * A hostname that resolves to several addresses produces several targets that
 * all share the same label, so their screenshots land in the same directory.
 */

#ifndef TARGETS_H
#define TARGETS_H

#include <stddef.h>

/* Longest text form of an address we store. INET6_ADDRSTRLEN is 46. */
#define TARGET_IP_LEN 46

/* Longest label we keep. DNS names max out at 253 characters. */
#define TARGET_LABEL_LEN 256

/* One host to scan. */
typedef struct {
    char label[TARGET_LABEL_LEN]; /* what the user typed; names the output dir */
    char ip[TARGET_IP_LEN];       /* numeric address we actually connect to    */
} target_t;

/* Growable array of targets. */
typedef struct {
    target_t *items;
    size_t count;
    size_t capacity;
} target_list_t;

/* Prepare an empty list. Must be called before any other list function. */
void target_list_init(target_list_t *list);

/* Release the memory held by the list and reset it to empty. */
void target_list_free(target_list_t *list);

/*
 * Append one target. Returns 0 on success, -1 if memory ran out.
 * Both strings are copied, so the caller keeps ownership of its buffers.
 */
int target_list_add(target_list_t *list, const char *label, const char *ip);

/*
 * Expand a single command line argument into zero or more targets, appending
 * them to `list`.
 *
 * allow_large_range: when 0, a CIDR block wider than /24 is rejected so that a
 * mistyped prefix cannot queue millions of hosts. Pass non-zero to permit it.
 *
 * Returns the number of targets added, or -1 on error (an explanatory message
 * is printed to stderr).
 */
int targets_expand_arg(target_list_t *list, const char *arg, int allow_large_range);

#endif /* TARGETS_H */
