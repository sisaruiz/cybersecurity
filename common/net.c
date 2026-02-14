#include "net.h"

#include <errno.h>
#include <netdb.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int send_all(int fd, const void *buf, size_t len)
{
    const char *p;
    size_t sent;

    if (fd < 0 || (buf == NULL && len > 0)) {
        errno = EINVAL;
        return -1;
    }

    p = (const char *)buf;
    sent = 0;

    /* Loop until the entire buffer has been transmitted. */
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (n == 0) {
            errno = EIO;
            return -1;
        }

        sent += (size_t)n;
    }

    return 0;
}

int recv_all(int fd, void *buf, size_t len)
{
    char *p;
    size_t recvd;

    if (fd < 0 || (buf == NULL && len > 0)) {
        errno = EINVAL;
        return -1;
    }

    p = (char *)buf;
    recvd = 0;

    /* Loop until the caller's buffer is fully populated. */
    while (recvd < len) {
        ssize_t n = recv(fd, p + recvd, len - recvd, 0);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (n == 0) {
            errno = ECONNRESET;
            return -1;
        }

        recvd += (size_t)n;
    }

    return 0;
}

int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *rp;
    int fd;
    int gai_rc;
    int saved_errno;

    if (host == NULL || port == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    result = NULL;
    gai_rc = getaddrinfo(host, port, &hints, &result);
    if (gai_rc != 0) {
        errno = (gai_rc == EAI_SYSTEM) ? errno : EHOSTUNREACH;
        return -1;
    }

    saved_errno = EHOSTUNREACH;
    /* Try each resolved endpoint until one succeeds. */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            saved_errno = errno;
            continue;
        }

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            freeaddrinfo(result);
            return fd;
        }

        saved_errno = errno;
        close(fd);
    }

    freeaddrinfo(result);
    errno = saved_errno;
    return -1;
}

int tcp_listen(const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *rp;
    int fd;
    int yes;
    int gai_rc;
    int saved_errno;

    if (port == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    result = NULL;
    gai_rc = getaddrinfo(NULL, port, &hints, &result);
    if (gai_rc != 0) {
        errno = (gai_rc == EAI_SYSTEM) ? errno : EADDRNOTAVAIL;
        return -1;
    }

    saved_errno = EADDRNOTAVAIL;
    /* Try each resolved bind address until one succeeds. */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            saved_errno = errno;
            continue;
        }

        yes = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            saved_errno = errno;
            close(fd);
            continue;
        }

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) < 0) {
            saved_errno = errno;
            close(fd);
            continue;
        }

        if (listen(fd, SOMAXCONN) < 0) {
            saved_errno = errno;
            close(fd);
            continue;
        }

        freeaddrinfo(result);
        return fd;
    }

    freeaddrinfo(result);
    errno = saved_errno;
    return -1;
}

int tcp_accept(int listen_fd)
{
    int fd;

    if (listen_fd < 0) {
        errno = EINVAL;
        return -1;
    }

    /* Retry if accept is interrupted by a signal. */
    for (;;) {
        fd = accept(listen_fd, NULL, NULL);
        if (fd >= 0) {
            return fd;
        }
        if (errno != EINTR) {
            return -1;
        }
    }
}
