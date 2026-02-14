#include "../common/dsspacket.h"
#include "../common/handshake.h"
#include "../common/net.h"
#include "../common/securechan.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fill_random_nonce(uint8_t nonce[REQ_NONCE_LEN])
{
    int fd;
    size_t offset;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    offset = 0;
    while (offset < REQ_NONCE_LEN) {
        ssize_t n = read(fd, nonce + offset, REQ_NONCE_LEN - offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            errno = EIO;
            return -1;
        }
        offset += (size_t)n;
    }

    if (close(fd) != 0) {
        return -1;
    }

    return 0;
}

static int send_encrypted_ping(int fd,
                               const uint8_t key_out[32],
                               const uint8_t req_nonce[REQ_NONCE_LEN])
{
    dss_header_t hdr;
    const char *message;
    size_t pt_len;
    size_t payload_len;
    uint8_t aad[DSSPACKET_AAD_LEN];
    size_t aad_len;
    uint8_t *payload;
    uint8_t *iv;
    uint8_t *tag;
    uint8_t *ct;

    message = "hello";
    pt_len = strlen(message);
    payload_len = GCM_IV_LEN + GCM_TAG_LEN + pt_len;
    if (payload_len > UINT32_MAX) {
        return -1;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.opcode = OP_SIGN_DOC;
    memcpy(hdr.req_nonce, req_nonce, REQ_NONCE_LEN);
    hdr.payload_len = htonl((uint32_t)payload_len);

    if (dsspacket_build_aad(&hdr, aad, &aad_len) != 0) {
        return -1;
    }

    payload = malloc(payload_len);
    if (payload == NULL) {
        return -1;
    }

    iv = payload;
    tag = payload + GCM_IV_LEN;
    ct = payload + GCM_IV_LEN + GCM_TAG_LEN;

    /* Generate a fresh IV for each encrypted request frame. */
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) {
        free(payload);
        return -1;
    }

    if (sc_aead_encrypt(key_out, iv,
                        aad, aad_len,
                        (const uint8_t *)message, pt_len,
                        ct, tag) != 0) {
        free(payload);
        return -1;
    }

    if (dsspacket_send(fd, &hdr, payload) != 0) {
        free(payload);
        return -1;
    }

    free(payload);
    return 0;
}

static int recv_decrypt_and_print_pong(int fd, const uint8_t key_in[32])
{
    dss_header_t hdr;
    uint8_t aad[DSSPACKET_AAD_LEN];
    size_t aad_len;
    uint8_t *payload;
    uint32_t payload_len;
    const uint8_t *iv;
    const uint8_t *tag;
    const uint8_t *ct;
    size_t ct_len;
    uint8_t *pt;

    payload = NULL;
    pt = NULL;

    if (dsspacket_recv(fd, &hdr, &payload) != 0) {
        return -1;
    }

    payload_len = ntohl(hdr.payload_len);
    if (payload_len < (GCM_IV_LEN + GCM_TAG_LEN)) {
        dsspacket_free(payload);
        return -1;
    }

    if (dsspacket_build_aad(&hdr, aad, &aad_len) != 0) {
        dsspacket_free(payload);
        return -1;
    }

    iv = payload;
    tag = payload + GCM_IV_LEN;
    ct = payload + GCM_IV_LEN + GCM_TAG_LEN;
    ct_len = payload_len - GCM_IV_LEN - GCM_TAG_LEN;

    pt = (ct_len > 0) ? malloc(ct_len + 1u) : malloc(1u);
    if (pt == NULL) {
        dsspacket_free(payload);
        return -1;
    }

    if (sc_aead_decrypt(key_in, iv,
                        aad, aad_len,
                        ct, ct_len,
                        tag,
                        pt) != 0) {
        free(pt);
        dsspacket_free(payload);
        return -1;
    }

    pt[ct_len] = '\0';
    fputs((const char *)pt, stdout);
    fputc('\n', stdout);

    free(pt);
    dsspacket_free(payload);
    return 0;
}

int main(int argc, char **argv)
{
    const char *host;
    const char *port;
    int fd;
    uint8_t req_nonce[REQ_NONCE_LEN];
    uint8_t c2s_key[32];
    uint8_t s2c_key[32];
    uint8_t *client_pub;
    size_t client_pub_len;
    EVP_PKEY *client_ecdh_priv;
    uint8_t *server_pub;
    size_t server_pub_len;
    uint8_t *sig;
    size_t sig_len;
    uint8_t *transcript;
    size_t transcript_len;
    uint8_t *shared_secret;
    size_t shared_secret_len;

    host = (argc > 1) ? argv[1] : "127.0.0.1";
    port = (argc > 2) ? argv[2] : "9000";
    client_pub = NULL;
    client_pub_len = 0;
    client_ecdh_priv = NULL;
    server_pub = NULL;
    server_pub_len = 0;
    sig = NULL;
    sig_len = 0;
    transcript = NULL;
    transcript_len = 0;
    shared_secret = NULL;
    shared_secret_len = 0;

    if (fill_random_nonce(req_nonce) != 0) {
        perror("fill_random_nonce");
        return 1;
    }

    fd = tcp_connect(host, port);
    if (fd < 0) {
        perror("tcp_connect");
        return 1;
    }

    /* Perform ECDH handshake before any encrypted DSS traffic. */
    if (hs_gen_ecdh_keypair(&client_pub, &client_pub_len, &client_ecdh_priv) != 0) {
        fprintf(stderr, "hs_gen_ecdh_keypair failed\n");
        goto cleanup;
    }

    if (hs_send_chlo(fd, client_pub, client_pub_len) != 0) {
        fprintf(stderr, "hs_send_chlo failed\n");
        goto cleanup;
    }
    puts("Handshake: CHLO sent");

    if (hs_recv_shlo(fd, &server_pub, &server_pub_len, &sig, &sig_len) != 0) {
        fprintf(stderr, "hs_recv_shlo failed\n");
        goto cleanup;
    }
    puts("Handshake: SHLO received");

    if (client_pub_len > SIZE_MAX - server_pub_len) {
        fprintf(stderr, "transcript length overflow\n");
        goto cleanup;
    }

    transcript_len = client_pub_len + server_pub_len;
    transcript = malloc(transcript_len);
    if (transcript == NULL) {
        fprintf(stderr, "transcript allocation failed\n");
        goto cleanup;
    }

    memcpy(transcript, client_pub, client_pub_len);
    memcpy(transcript + client_pub_len, server_pub, server_pub_len);

    if (hs_verify_transcript("client/res/server_public.pem", transcript, transcript_len,
                             sig, sig_len) != 0) {
        fprintf(stderr, "Handshake error: signature verification failed\n");
        goto cleanup;
    }
    puts("Handshake: signature verified");

    if (hs_compute_shared(client_ecdh_priv, server_pub, server_pub_len,
                          &shared_secret, &shared_secret_len) != 0) {
        fprintf(stderr, "hs_compute_shared failed\n");
        goto cleanup;
    }

    if (hs_derive_keys(shared_secret, shared_secret_len,
                       transcript, transcript_len,
                       c2s_key, s2c_key) != 0) {
        fprintf(stderr, "hs_derive_keys failed\n");
        goto cleanup;
    }
    puts("Handshake: session keys derived");

    /* Send an initial encrypted PING with a fresh nonce. */
    /* key_out = c2s_key (encrypt client->server), key_in = s2c_key (decrypt server->client). */
    if (send_encrypted_ping(fd, c2s_key, req_nonce) != 0) {
        perror("send_encrypted_ping");
        goto cleanup;
    }

    if (recv_decrypt_and_print_pong(fd, s2c_key) != 0) {
        perror("recv_decrypt_and_print_pong");
        goto cleanup;
    }

    /* Send the same nonce again to trigger replay detection. */
    if (send_encrypted_ping(fd, c2s_key, req_nonce) != 0) {
        perror("send_encrypted_ping");
        goto cleanup;
    }

    if (recv_decrypt_and_print_pong(fd, s2c_key) != 0) {
        perror("recv_decrypt_and_print_pong");
        goto cleanup;
    }

    close(fd);
    free(shared_secret);
    free(transcript);
    free(sig);
    free(server_pub);
    EVP_PKEY_free(client_ecdh_priv);
    free(client_pub);
    return 0;

cleanup:
    close(fd);
    free(shared_secret);
    free(transcript);
    free(sig);
    free(server_pub);
    EVP_PKEY_free(client_ecdh_priv);
    free(client_pub);
    return 1;
}
