/*
 * targets.c - Implementation of argument classification and expansion.
 *
 * See targets.h for the API contract. The interesting logic here is:
 *   1. deciding what kind of thing an argument is, and
 *   2. walking a CIDR block without accidentally generating a huge list.
 */

#include "targets.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

/*
 * Narrowest prefix we expand without an explicit override. /24 is 256
 * addresses, which is a reasonable "one subnet" default. Anything wider is
 * almost always a typo, and scanning it would take a very long time.
 */
#define CIDR_SAFE_PREFIX 24

void target_list_init(target_list_t *list)
{
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void target_list_free(target_list_t *list)
{
    free(list->items);
    target_list_init(list);
}

int target_list_add(target_list_t *list, const char *label, const char *ip)
{
    /* Grow geometrically so that adding N targets stays O(N) overall. */
    if (list->count == list->capacity) {
        size_t new_cap = (list->capacity == 0) ? 16 : list->capacity * 2;
        target_t *grown = realloc(list->items, new_cap * sizeof(*grown));
        if (grown == NULL) {
            fprintf(stderr, "error: out of memory while building target list\n");
            return -1;
        }
        list->items = grown;
        list->capacity = new_cap;
    }

    target_t *slot = &list->items[list->count];

    /*
     * strncpy leaves the buffer unterminated if the source is too long, so
     * terminate by hand. Over-long labels are truncated rather than rejected;
     * they only affect the directory name, not the scan itself.
     */
    strncpy(slot->label, label, TARGET_LABEL_LEN - 1);
    slot->label[TARGET_LABEL_LEN - 1] = '\0';
    strncpy(slot->ip, ip, TARGET_IP_LEN - 1);
    slot->ip[TARGET_IP_LEN - 1] = '\0';

    list->count++;
    return 0;
}

/*
 * Is this string a bare numeric address? Returns 1 for IPv4 or IPv6, else 0.
 * We test both families because inet_pton only checks the one it is told to.
 */
static int is_numeric_address(const char *s)
{
    struct in_addr v4;
    struct in6_addr v6;

    if (inet_pton(AF_INET, s, &v4) == 1) {
        return 1;
    }
    if (inet_pton(AF_INET6, s, &v6) == 1) {
        return 1;
    }
    return 0;
}

/*
 * Expand an IPv4 CIDR block such as 192.0.2.0/24.
 *
 * Each generated address becomes its own target, labelled with the address
 * itself, so every host in the block gets a separate output directory.
 *
 * For blocks of /30 or wider we skip the network and broadcast addresses,
 * since nothing listens on those. For /31 and /32 every address is usable
 * (see RFC 3021 for the /31 case), so we emit them all.
 */
static int expand_cidr(target_list_t *list, const char *arg, int allow_large_range)
{
    char base[TARGET_IP_LEN];
    const char *slash = strchr(arg, '/');
    size_t base_len = (size_t)(slash - arg);

    if (base_len == 0 || base_len >= sizeof(base)) {
        fprintf(stderr, "error: '%s' is not a valid CIDR block\n", arg);
        return -1;
    }
    memcpy(base, arg, base_len);
    base[base_len] = '\0';

    /* Only IPv4 CIDR is supported; an IPv6 block would be absurdly large. */
    struct in_addr addr;
    if (inet_pton(AF_INET, base, &addr) != 1) {
        fprintf(stderr, "error: '%s' has an invalid IPv4 address before the '/'\n", arg);
        return -1;
    }

    /* Parse the prefix length, rejecting junk like "/24abc" or "/33". */
    char *endptr = NULL;
    errno = 0;
    long prefix = strtol(slash + 1, &endptr, 10);
    if (errno != 0 || endptr == slash + 1 || *endptr != '\0' || prefix < 0 || prefix > 32) {
        fprintf(stderr, "error: '%s' has an invalid prefix length (expected /0 to /32)\n", arg);
        return -1;
    }

    if (prefix < CIDR_SAFE_PREFIX && !allow_large_range) {
        unsigned long long hosts = 1ULL << (32 - prefix);
        fprintf(stderr,
                "error: /%ld covers %llu addresses, which is above the /%d safety limit.\n"
                "       Re-run with --force-large-range if you really mean it.\n",
                prefix, hosts, CIDR_SAFE_PREFIX);
        return -1;
    }

    /*
     * Work in host byte order so arithmetic on the address is straightforward,
     * then convert back to text one address at a time.
     */
    uint32_t host_base = ntohl(addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    uint32_t network = host_base & mask;
    uint32_t count = (prefix == 32) ? 1u : (1u << (32 - prefix));

    uint32_t first = network;
    uint32_t last = network + count - 1;

    /* Trim network and broadcast for blocks that have them. */
    if (prefix <= 30) {
        first += 1;
        last -= 1;
    }

    int added = 0;
    for (uint32_t a = first; a <= last; a++) {
        struct in_addr cur;
        cur.s_addr = htonl(a);

        char text[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &cur, text, sizeof(text)) == NULL) {
            fprintf(stderr, "error: could not format an address in %s: %s\n",
                    arg, strerror(errno));
            return -1;
        }

        if (target_list_add(list, text, text) != 0) {
            return -1;
        }
        added++;

        /* Guard against wrapping around at the top of the address space. */
        if (a == 0xFFFFFFFFu) {
            break;
        }
    }

    return added;
}

/*
 * Resolve a hostname to one or more addresses. Every address becomes a target
 * sharing the hostname as its label.
 */
static int expand_hostname(target_list_t *list, const char *arg)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     /* accept both IPv4 and IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* we only ever open TCP connections */

    int rc = getaddrinfo(arg, NULL, &hints, &results);
    if (rc != 0) {
        fprintf(stderr, "warning: could not resolve '%s': %s\n", arg, gai_strerror(rc));
        return -1;
    }

    int added = 0;
    for (struct addrinfo *ai = results; ai != NULL; ai = ai->ai_next) {
        char text[TARGET_IP_LEN];

        /*
         * getnameinfo with NI_NUMERICHOST converts the sockaddr back to text
         * without doing a reverse lookup, which keeps this fast.
         */
        if (getnameinfo(ai->ai_addr, ai->ai_addrlen, text, sizeof(text),
                        NULL, 0, NI_NUMERICHOST) != 0) {
            continue; /* skip anything we cannot render */
        }

        /*
         * getaddrinfo often returns the same address once per socket type.
         * Drop duplicates so we do not scan the same host twice.
         */
        int duplicate = 0;
        for (size_t i = 0; i < list->count; i++) {
            if (strcmp(list->items[i].ip, text) == 0 &&
                strcmp(list->items[i].label, arg) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        if (target_list_add(list, arg, text) != 0) {
            freeaddrinfo(results);
            return -1;
        }
        added++;
    }

    freeaddrinfo(results);

    if (added == 0) {
        fprintf(stderr, "warning: '%s' resolved to no usable addresses\n", arg);
        return -1;
    }
    return added;
}

int targets_expand_arg(target_list_t *list, const char *arg, int allow_large_range)
{
    if (arg == NULL || *arg == '\0') {
        fprintf(stderr, "error: empty target argument\n");
        return -1;
    }

    /* A '/' means CIDR. Nothing else we accept contains one. */
    if (strchr(arg, '/') != NULL) {
        return expand_cidr(list, arg, allow_large_range);
    }

    /* A bare address needs no resolution; use it directly. */
    if (is_numeric_address(arg)) {
        if (target_list_add(list, arg, arg) != 0) {
            return -1;
        }
        return 1;
    }

    /* Anything else is treated as a name to resolve. */
    return expand_hostname(list, arg);
}
