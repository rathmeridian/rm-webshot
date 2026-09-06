/*
 * scanner.c - Implementation of the port check and service probe.
 *
 * Everything here uses non-blocking sockets with poll() so that a host that
 * silently drops packets costs us the timeout and nothing more. A blocking
 * connect() can hang for over a minute on such a host, which would make
 * scanning a whole subnet unbearably slow.
 */

#include "scanner.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* How much of the server's reply we read before deciding what it is. */
#define PROBE_BUFFER_SIZE 256

const char *scanner_service_name(service_t svc)
{
    switch (svc) {
    case SVC_HTTP:    return "http";
    case SVC_HTTPS:   return "https";
    case SVC_UNKNOWN: return "open (not web)";
    case SVC_CLOSED:
    default:          return "closed";
    }
}

service_t scanner_guess_by_port(int port)
{
    switch (port) {
    /* Ports conventionally used for TLS-wrapped HTTP. */
    case 443:
    case 8443:
    case 9443:
        return SVC_HTTPS;
    /* Ports conventionally used for plaintext HTTP. */
    case 80:
    case 8000:
    case 8008:
    case 8080:
    case 8081:
    case 8888:
        return SVC_HTTP;
    default:
        return SVC_UNKNOWN;
    }
}

/* Put a descriptor into non-blocking mode. Returns 0 on success. */
static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/*
 * Build a sockaddr for a numeric address and port.
 *
 * getaddrinfo with AI_NUMERICHOST does the parsing for both IPv4 and IPv6
 * without touching DNS, which saves us from writing two code paths.
 * Caller must freeaddrinfo() the result.
 */
static struct addrinfo *resolve_numeric(const char *ip, int port)
{
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    struct addrinfo *res = NULL;
    if (getaddrinfo(ip, port_text, &hints, &res) != 0) {
        return NULL;
    }
    return res;
}

/*
 * Attempt a TCP connection with a timeout.
 * Returns a connected socket on success, or -1 if the port is not open.
 */
static int connect_with_timeout(const struct addrinfo *ai, int timeout_ms)
{
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
        return -1;
    }

    if (set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc == 0) {
        /* Connected immediately, which happens for loopback targets. */
        return fd;
    }

    /*
     * Anything other than EINPROGRESS is a real failure: ECONNREFUSED means
     * the port is closed, EHOSTUNREACH means we cannot get there at all.
     */
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    /* Wait for the handshake to finish, or for the timeout to expire. */
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) {
        /* 0 means timed out, -1 means poll itself failed. Either way: give up. */
        close(fd);
        return -1;
    }

    /*
     * poll() reporting POLLOUT does not by itself mean success. The real
     * verdict is in SO_ERROR, which is 0 only if the connection completed.
     */
    int soerr = 0;
    socklen_t len = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0 || soerr != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * Send a minimal HTTP request and classify whatever comes back.
 *
 * A plaintext HTTP server replies with "HTTP/1.x ...".
 * A TLS server sees our plaintext as a malformed handshake and usually replies
 * with a TLS alert record, which starts with byte 0x15 (or 0x16 for a
 * handshake record). Some just close the connection instead.
 */
static service_t probe_service(int fd, const char *ip, int port, int timeout_ms)
{
    char request[512];

    /*
     * HTTP/1.0 keeps the reply short and avoids keep-alive. The Host header is
     * included anyway because some virtual-host setups reject requests without
     * one even on 1.0.
     */
    int n = snprintf(request, sizeof(request),
                     "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: rm-webshot\r\n\r\n", ip);
    if (n < 0 || (size_t)n >= sizeof(request)) {
        return scanner_guess_by_port(port);
    }

    /*
     * MSG_NOSIGNAL stops a SIGPIPE from killing the whole program if the peer
     * has already hung up. Ignoring the return value is fine: if the write
     * failed we will simply read nothing and fall through to the port guess.
     */
    ssize_t sent = send(fd, request, (size_t)n, MSG_NOSIGNAL);
    (void)sent;

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    if (poll(&pfd, 1, timeout_ms) <= 0) {
        /* Nothing said anything in time; fall back to what the port implies. */
        return scanner_guess_by_port(port);
    }

    unsigned char buf[PROBE_BUFFER_SIZE];
    ssize_t got = recv(fd, buf, sizeof(buf) - 1, 0);
    if (got <= 0) {
        /*
         * Connection closed or reset without a reply. A TLS server given
         * plaintext very often behaves exactly like this, so lean on the port.
         */
        return scanner_guess_by_port(port);
    }
    buf[got] = '\0';

    /* A plaintext HTTP response is unambiguous. */
    if (got >= 5 && memcmp(buf, "HTTP/", 5) == 0) {
        return SVC_HTTP;
    }

    /*
     * TLS record types: 0x15 is "alert", 0x16 is "handshake". Either means we
     * are talking to something that expects TLS.
     */
    if (buf[0] == 0x15 || buf[0] == 0x16) {
        return SVC_HTTPS;
    }

    /*
     * Something is listening and it talks, but not HTTP. Common on SSH, SMTP
     * and similar. Fall back to the port hint so an unusual web port still
     * gets a chance, otherwise report it as open-but-not-web.
     */
    return scanner_guess_by_port(port);
}

int scanner_check_port(const char *ip, int port, int timeout_ms, service_t *out)
{
    if (out != NULL) {
        *out = SVC_CLOSED;
    }

    struct addrinfo *ai = resolve_numeric(ip, port);
    if (ai == NULL) {
        return -1;
    }

    int fd = connect_with_timeout(ai, timeout_ms);
    freeaddrinfo(ai);

    if (fd < 0) {
        return 0; /* closed, filtered or unreachable */
    }

    service_t svc = probe_service(fd, ip, port, timeout_ms);
    close(fd);

    if (out != NULL) {
        *out = svc;
    }
    return 1;
}
