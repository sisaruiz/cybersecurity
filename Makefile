CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -O2 -g -D_POSIX_C_SOURCE=200809L -I.
LDFLAGS := -lssl -lcrypto

COMMON_SRCS := common/net.c common/dsspacket.c common/replay.c common/securechan.c common/handshake.c
SERVER_SRCS := server/main.c server/auth.c server/storage.c $(COMMON_SRCS)
CLIENT_SRCS := client/main.c $(COMMON_SRCS)
ACCOUNT_PROVISION_SRCS := tools/account_provision.c server/auth.c

.PHONY: all clean tools

all: server/dss_server client/dss_client

server/dss_server: $(SERVER_SRCS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRCS) $(LDFLAGS)

client/dss_client: $(CLIENT_SRCS)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRCS) $(LDFLAGS)

tools: tools/account_provision

tools/account_provision: $(ACCOUNT_PROVISION_SRCS)
	$(CC) $(CFLAGS) -o $@ $(ACCOUNT_PROVISION_SRCS) $(LDFLAGS)

clean:
	rm -f server/dss_server client/dss_client tools/account_provision
