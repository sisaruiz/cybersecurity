CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -O2 -g -D_POSIX_C_SOURCE=200809L -I.
LDFLAGS := -lssl -lcrypto

COMMON_SRCS := common/net.c common/dsspacket.c common/replay.c common/securechan.c common/handshake.c
SERVER_SRCS := server/main.c server/auth.c server/storage.c $(COMMON_SRCS)
CLIENT_SRCS := client/main.c $(COMMON_SRCS)
USER_BOOTSTRAP_SRCS := server/user_bootstrap.c server/auth.c
KS_TEST_SRCS := server/ks_test.c server/auth.c server/storage.c
ACCOUNT_PROVISION_SRCS := server/account_provision.c server/auth.c

.PHONY: all clean ks_test

all: server/dss_server client/dss_client user_bootstrap server/account_provision

server/dss_server: $(SERVER_SRCS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRCS) $(LDFLAGS)

client/dss_client: $(CLIENT_SRCS)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRCS) $(LDFLAGS)

user_bootstrap: $(USER_BOOTSTRAP_SRCS)
	$(CC) $(CFLAGS) -o server/user_bootstrap $(USER_BOOTSTRAP_SRCS) $(LDFLAGS)

server/account_provision: $(ACCOUNT_PROVISION_SRCS)
	$(CC) $(CFLAGS) -o $@ $(ACCOUNT_PROVISION_SRCS) $(LDFLAGS)

ks_test: $(KS_TEST_SRCS)
	$(CC) $(CFLAGS) -o server/ks_test $(KS_TEST_SRCS) $(LDFLAGS)

clean:
	rm -f server/dss_server client/dss_client server/user_bootstrap server/account_provision server/ks_test
