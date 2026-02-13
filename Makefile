CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -O2 -g -I.

COMMON_SRCS := common/net.c common/dsspacket.c common/replay.c
SERVER_SRCS := server/main.c $(COMMON_SRCS)
CLIENT_SRCS := client/main.c $(COMMON_SRCS)

.PHONY: all clean

all: server/dss_server client/dss_client

server/dss_server: $(SERVER_SRCS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRCS)

client/dss_client: $(CLIENT_SRCS)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRCS)

clean:
	rm -f server/dss_server client/dss_client
