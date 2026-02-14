CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -O2 -g -D_POSIX_C_SOURCE=200809L -I.
LDFLAGS := -lssl -lcrypto

COMMON_SRCS := common/net.c common/dsspacket.c common/replay.c common/securechan.c
SERVER_SRCS := server/main.c $(COMMON_SRCS)
CLIENT_SRCS := client/main.c $(COMMON_SRCS)

.PHONY: all clean

all: server/dss_server client/dss_client

server/dss_server: $(SERVER_SRCS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRCS) $(LDFLAGS)

client/dss_client: $(CLIENT_SRCS)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRCS) $(LDFLAGS)

clean:
	rm -f server/dss_server client/dss_client
