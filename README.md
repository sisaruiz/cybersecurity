## Build

Build the runtime deliverables only (default target):

```bash
make
```

This builds:
- `server/dss_server`
- `client/dss_client`

Build the optional offline provisioning tool separately:

```bash
make tools
```

This builds:
- `tools/account_provision`

Clean runtime and tool binaries:

```bash
make clean
```

## Generate test server keypair (PEM)

Use OpenSSL to create a server private/public keypair for local testing.

1. Generate a private key in `server/res/keys`:

```bash
openssl genpkey -algorithm RSA -out server/res/keys/server-private.pem -pkeyopt rsa_keygen_bits:2048
```

2. Extract the matching public key to `client/res`:

```bash
openssl rsa -pubout -in server/res/keys/server-private.pem -out client/res/server-public.pem
```

## Manual tests

Example interactive flow in the client:

```text
login <user>
changepw
createkeys
signdoc client/res/testdocs/doc1.txt
deletekeys
signdoc client/res/testdocs/doc1.txt
```

After `deletekeys`, the final `signdoc` must be refused with:

```text
Operation refused: keys deleted (tombstone). Re-registration required.
```

## Offline Account Provisioning

Use `tools/account_provision` to register accounts directly in `server/res/users.db` from the server machine itself (no network path is used).

```bash
./tools/account_provision register <username> <new_password>
```

This local tool is required to re-register a user after tombstone deletion (`deleted=1`), because active accounts are intentionally not overwritten.

## Deliverable scope

`ks_test` and bundled binary test artefacts were removed because they are development/test-only and are not part of the runtime deliverable.
