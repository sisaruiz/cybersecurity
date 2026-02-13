#ifndef COMMON_NET_H
#define COMMON_NET_H

#include <stddef.h>

/* Send exactly len bytes unless an error occurs. */
int send_all(int fd, const void *buf, size_t len);

/* Receive exactly len bytes unless an error occurs. */
int recv_all(int fd, void *buf, size_t len);

/* Open a TCP connection to host:port. */
int tcp_connect(const char *host, const char *port);

/* Create and bind a TCP listening socket for port. */
int tcp_listen(const char *port);

/* Accept one incoming TCP connection from a listening socket. */
int tcp_accept(int listen_fd);

#endif /* COMMON_NET_H */
