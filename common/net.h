#ifndef COMMON_NET_H
#define COMMON_NET_H

#include <stddef.h>
#include <sys/types.h>

ssize_t send_all(int fd, const void *buf, size_t len);
ssize_t recv_all(int fd, void *buf, size_t len);

#endif /* COMMON_NET_H */
