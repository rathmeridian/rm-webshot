/*
 * scanner.h - TCP port checking and lightweight web service detection.
 *
 * An open TCP port is not necessarily a web server, and a web server is not
 * necessarily plaintext. Before we hand a URL to a browser we want to know
 * which scheme to use, so the scanner does two things per port:
 *
 *   1. a bounded-timeout TCP connect to see whether anything is listening
 *   2. a tiny plaintext HTTP request to see how the service replies
 *
 * The probe is intentionally cheap. It sends one small request and reads at
 * most a few hundred bytes.
 */

#ifndef SCANNER_H
#define SCANNER_H

/* What we concluded about an open port. */
typedef enum {
    SVC_CLOSED = 0, /* nothing listening, or the connection was refused */
    SVC_HTTP,       /* answered a plaintext HTTP request */
    SVC_HTTPS,      /* spoke TLS, or refused plaintext on a known TLS port */
    SVC_UNKNOWN     /* open, but it does not look like a web server */
} service_t;

/* Human readable name for a service_t, for printing results. */
const char *scanner_service_name(service_t svc);

/*
 * Test one port on one host.
 *
 * ip:         numeric address, IPv4 or IPv6
 * port:       TCP port to test
 * timeout_ms: budget for the connect, and separately for the probe read
 * out:        receives the classification
 *
 * Returns 1 if the port is open (check *out for what it looks like),
 * 0 if it is closed or unreachable, and -1 if the attempt could not be made
 * at all (for example the address failed to parse).
 */
int scanner_check_port(const char *ip, int port, int timeout_ms, service_t *out);

/*
 * Best guess at a scheme based on the port number alone, used when the probe
 * is inconclusive. Returns SVC_HTTPS for the usual TLS ports, SVC_HTTP for the
 * usual plaintext ones, and SVC_UNKNOWN for anything unrecognised.
 */
service_t scanner_guess_by_port(int port);

#endif /* SCANNER_H */
