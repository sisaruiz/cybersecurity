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
