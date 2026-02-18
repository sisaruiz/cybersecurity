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

## Start-up

To start the server and client, run:

```bash
./server/dss_server 9000
./client/dss_client 127.0.0.1 9000
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

## Secure packet format (operations channel)

Application operation type is now encrypted inside the AES-GCM plaintext, not sent in clear in the outer header.

- Outer DSS header: `req_nonce[16] | payload_len[4]`.
- AES-GCM AAD: `req_nonce[16] | payload_len[4]`.
- Request plaintext: `u8 opcode | op_specific_bytes...`.
- Response plaintext: `u8 opcode | u16 status | u32 data_len | op_specific_bytes...`.
- Ciphertext wire layout is unchanged: `iv[12] | tag[16] | ciphertext[...]`.
- Replay protection is unchanged and still binds each frame to a unique request nonce.

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
