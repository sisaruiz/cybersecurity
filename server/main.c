#include "../common/dsspacket.h"
#include "../common/handshake.h"
#include "../common/net.h"
#include "../common/replay.h"
#include "../common/securechan.h"

#include "auth.h"
#include "storage.h"

#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct session_state {
    int is_authenticated;
    char username[256];
    int must_change;
    int deleted;
    uint8_t key[32];
    int has_key;
} session_state_t;

static void session_clear(session_state_t *s)
{
    if (s == NULL) {
        return;
    }
    OPENSSL_cleanse(s->key, sizeof(s->key));
    memset(s, 0, sizeof(*s));
}

static int send_encrypted_response(int fd,
                                   const uint8_t key_out[32],
                                   uint8_t opcode,
                                   const uint8_t req_nonce[REQ_NONCE_LEN],
                                   dss_status_t status,
                                   const uint8_t *data,
                                   size_t data_len)
{
    dss_header_t out_hdr;
    dss_response_header_t rsp_hdr;
    uint8_t aad[DSSPACKET_AAD_LEN];
    size_t aad_len;
    size_t pt_len;
    size_t payload_len;
    uint8_t *payload;
    uint8_t *iv;
    uint8_t *tag;
    uint8_t *ct;
    uint8_t *pt;

    if (data_len > UINT16_MAX) {
        return -1;
    }

    pt_len = sizeof(rsp_hdr) + data_len;
    payload_len = GCM_IV_LEN + GCM_TAG_LEN + pt_len;
    if (payload_len > UINT32_MAX) {
        return -1;
    }

    memset(&out_hdr, 0, sizeof(out_hdr));
    out_hdr.opcode = opcode;
    memcpy(out_hdr.req_nonce, req_nonce, REQ_NONCE_LEN);
    out_hdr.payload_len = htonl((uint32_t)payload_len);

    if (dsspacket_build_aad(&out_hdr, aad, &aad_len) != 0) {
        return -1;
    }

    payload = malloc(payload_len);
    pt = malloc(pt_len);
    if (payload == NULL || pt == NULL) {
        free(payload);
        free(pt);
        return -1;
    }

    rsp_hdr.status = htons((uint16_t)status);
    rsp_hdr.reserved = 0;
    rsp_hdr.data_len = htonl((uint32_t)data_len);

    memcpy(pt, &rsp_hdr, sizeof(rsp_hdr));
    if (data_len > 0) {
        memcpy(pt + sizeof(rsp_hdr), data, data_len);
    }

    iv = payload;
    tag = payload + GCM_IV_LEN;
    ct = payload + GCM_IV_LEN + GCM_TAG_LEN;

    /* Generate a fresh IV for each encrypted response frame. */
    if (RAND_bytes(iv, GCM_IV_LEN) != 1 ||
        sc_aead_encrypt(key_out, iv, aad, aad_len, pt, pt_len, ct, tag) != 0 ||
        dsspacket_send(fd, &out_hdr, payload) != 0) {
        free(payload);
        free(pt);
        return -1;
    }

    free(payload);
    free(pt);
    return 0;
}

static int require_authenticated(const session_state_t *sess)
{
    return (sess->is_authenticated == 1 && sess->deleted == 0 && sess->has_key == 1) ? 0 : -1;
}

int main(int argc, char **argv)
{
    const char *port;
    int listen_fd;
    int client_fd;
    ReplayCache cache;
    int rc;
    uint8_t c2s_key[32];
    uint8_t s2c_key[32];
    uint8_t key_in[32];
    uint8_t key_out[32];
    uint8_t *client_pub;
    size_t client_pub_len;
    uint8_t *server_pub;
    size_t server_pub_len;
    EVP_PKEY *server_ecdh_priv;
    uint8_t *shared_secret;
    size_t shared_secret_len;
    uint8_t *transcript;
    size_t transcript_len;
    uint8_t *sig;
    size_t sig_len;
    session_state_t session;

    port = (argc > 1) ? argv[1] : "9000";
    listen_fd = -1;
    client_fd = -1;
    memset(&cache, 0, sizeof(cache));
    memset(&session, 0, sizeof(session));
    client_pub = NULL;
    client_pub_len = 0;
    server_pub = NULL;
    server_pub_len = 0;
    server_ecdh_priv = NULL;
    shared_secret = NULL;
    shared_secret_len = 0;
    transcript = NULL;
    transcript_len = 0;
    sig = NULL;
    sig_len = 0;

    if (auth_bootstrap_from_seed_if_needed("server/res/users.db", "server/res/users.seed") != 0 ||
        auth_load_db("server/res/users.db") != 0) {
        fprintf(stderr, "auth db load failed\n");
        return 1;
    }

    listen_fd = tcp_listen(port);
    if (listen_fd < 0) {
        perror("tcp_listen");
        return 1;
    }

    client_fd = tcp_accept(listen_fd);
    if (client_fd < 0) {
        perror("tcp_accept");
        close(listen_fd);
        return 1;
    }

    /* Perform ECDH handshake and derive directional session keys. */
    if (hs_recv_chlo(client_fd, &client_pub, &client_pub_len) != 0) {
        fprintf(stderr, "hs_recv_chlo failed\n");
        goto cleanup;
    }

    if (hs_gen_ecdh_keypair(&server_pub, &server_pub_len, &server_ecdh_priv) != 0) {
        fprintf(stderr, "hs_gen_ecdh_keypair failed\n");
        goto cleanup;
    }

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

    if (hs_sign_transcript("server/res/keys/server_private.pem", transcript, transcript_len,
                           &sig, &sig_len) != 0 ||
        hs_send_shlo(client_fd, server_pub, server_pub_len, sig, sig_len) != 0 ||
        hs_compute_shared(server_ecdh_priv, client_pub, client_pub_len,
                          &shared_secret, &shared_secret_len) != 0 ||
        hs_derive_keys(shared_secret, shared_secret_len,
                       transcript, transcript_len,
                       c2s_key, s2c_key) != 0) {
        fprintf(stderr, "handshake failed\n");
        goto cleanup;
    }

    memcpy(key_in, c2s_key, sizeof(key_in));
    memcpy(key_out, s2c_key, sizeof(key_out));

    rc = replay_init(&cache, 0);
    if (rc != 0) {
        fprintf(stderr, "replay_init failed\n");
        goto cleanup;
    }

    for (;;) {
        dss_header_t in_hdr;
        uint8_t aad[DSSPACKET_AAD_LEN];
        size_t aad_len;
        uint8_t *payload;
        uint32_t payload_len;
        const uint8_t *iv;
        const uint8_t *tag;
        const uint8_t *ct;
        size_t ct_len;
        uint8_t *pt;
        dss_status_t status;
        uint8_t *resp_data;
        size_t resp_len;

        payload = NULL;
        pt = NULL;
        resp_data = NULL;
        resp_len = 0;
        status = ST_ERR_BAD_REQ;

        if (dsspacket_recv(client_fd, &in_hdr, &payload) != 0) {
            dsspacket_free(payload);
            break;
        }
        if (replay_check_and_add(&cache, in_hdr.req_nonce) < 0) {
            dsspacket_free(payload);
            break;
        }

        payload_len = ntohl(in_hdr.payload_len);
        if (payload_len < (GCM_IV_LEN + GCM_TAG_LEN) ||
            dsspacket_build_aad(&in_hdr, aad, &aad_len) != 0) {
            dsspacket_free(payload);
            break;
        }

        iv = payload;
        tag = payload + GCM_IV_LEN;
        ct = payload + GCM_IV_LEN + GCM_TAG_LEN;
        ct_len = payload_len - GCM_IV_LEN - GCM_TAG_LEN;

        pt = (ct_len > 0) ? malloc(ct_len) : NULL;
        if (ct_len > 0 && pt == NULL) {
            dsspacket_free(payload);
            break;
        }

        if (sc_aead_decrypt(key_in, iv, aad, aad_len, ct, ct_len, tag, pt) != 0) {
            free(pt);
            dsspacket_free(payload);
            break;
        }

        if (in_hdr.opcode != OP_AUTH && in_hdr.opcode != OP_GET_PUBLIC_KEY && session.is_authenticated == 0) {
            status = ST_ERR_AUTH;
        } else if (in_hdr.opcode == OP_AUTH) {
            uint8_t ulen;
            uint8_t plen;
            const char *user;
            const char *pw;
            int must_change;
            int deleted;

            if (ct_len < 2u) {
                status = ST_ERR_BAD_REQ;
            } else {
                ulen = pt[0];
                if (ct_len < (size_t)(1u + ulen + 1u)) {
                    status = ST_ERR_BAD_REQ;
                } else {
                    plen = pt[1u + ulen];
                    if (ct_len != (size_t)(2u + ulen + plen) || ulen == 0u || plen == 0u ) {
                        status = ST_ERR_BAD_REQ;
                    } else {
                        user = (const char *)(pt + 1u);
                        pw = (const char *)(pt + 2u + ulen);
                        char user_buf[256];
                        char pw_buf[256];
                        memcpy(user_buf, user, ulen);
                        user_buf[ulen] = '\0';
                        memcpy(pw_buf, pw, plen);
                        pw_buf[plen] = '\0';
                        if (auth_verify_password(user_buf, pw_buf, &must_change, &deleted) != 0) {
                                status = ST_ERR_AUTH;
                        } else {
                            uint8_t flags[2];
                                session_clear(&session);
                                session.is_authenticated = 1;
                                session.must_change = must_change;
                                session.deleted = deleted;
                                memcpy(session.username, user_buf, ulen + 1u);
                                if (ks_derive_session_key(session.username, pw_buf, session.key) == 0) {
                                    session.has_key = 1;
                                }
                            OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
                            flags[0] = (uint8_t)must_change;
                            flags[1] = (uint8_t)deleted;
                            resp_data = malloc(2u);
                            if (resp_data == NULL) {
                                status = ST_ERR_INTERNAL;
                            } else {
                                memcpy(resp_data, flags, 2u);
                                resp_len = 2u;
                                status = ST_OK;
                            }
                        }
                    }
                }
            }
        } else if (session.must_change == 1 && in_hdr.opcode != OP_CHANGE_PASSWORD && in_hdr.opcode != OP_LOGOUT) {
            status = ST_ERR_AUTH;
        } else {
            switch (in_hdr.opcode) {
            case OP_CHANGE_PASSWORD: {
                uint8_t nlen;
                char new_pw[256];
                uint8_t new_key[32];
                if (require_authenticated(&session) != 0 || ct_len < 1u) {
                    status = ST_ERR_AUTH;
                    break;
                }
                nlen = pt[0];
                if (ct_len != (size_t)(1u + nlen) || nlen == 0u ) {
                    status = ST_ERR_BAD_REQ;
                    break;
                }
                memcpy(new_pw, pt + 1u, nlen);
                new_pw[nlen] = '\0';
                if (ks_derive_session_key(session.username, new_pw, new_key) != 0 ||
                    ks_reencrypt_private_for_new_session_key(session.username, session.key, new_key) != 0 ||
                    auth_change_password_authenticated(session.username, new_pw) != 0) {
                    status = ST_ERR_INTERNAL;
                } else {
                    memcpy(session.key, new_key, sizeof(new_key));
                    session.must_change = 0;
                    status = ST_OK;
                }
                OPENSSL_cleanse(new_pw, sizeof(new_pw));
                OPENSSL_cleanse(new_key, sizeof(new_key));
                break;
            }
            case OP_CREATE_KEYS:
                if (session.is_authenticated != 1 || session.has_key != 1) {
                    status = ST_ERR_AUTH;
                } else if (session.deleted != 0) {
                    status = ST_ERR_DELETED;
                } else if (ks_create_keys_session(session.username, session.key) != 0) {
                    status = ST_ERR_INTERNAL;
                } else {
                    status = ST_OK;
                }
                break;
            case OP_SIGN_DOC: {
                uint8_t *sig_out;
                size_t sig_len;
                if (require_authenticated(&session) != 0) {
                    status = ST_ERR_AUTH;
                    break;
                }
                sig_out = NULL;
                sig_len = 0;
                if (ks_sign_doc_session(session.username, session.key, pt, ct_len, &sig_out, &sig_len) != 0) {
                    status = ST_ERR_INTERNAL;
                } else {
                    resp_data = sig_out;
                    resp_len = sig_len;
                    status = ST_OK;
                }
                break;
            }
            case OP_GET_PUBLIC_KEY: {
                const char *target_user;
                char temp_user[256];
                uint8_t *pub;
                size_t pub_len;
                pub = NULL;
                pub_len = 0;
                if (ct_len == 0u) {
                    if (session.is_authenticated == 0) {
                        status = ST_ERR_AUTH;
                        break;
                    }
                    target_user = session.username;
                } else {
                    uint8_t ulen = pt[0];
                    if (ct_len != (size_t)(1u + ulen) || ulen == 0u ) {
                        status = ST_ERR_BAD_REQ;
                        break;
                    }
                    memcpy(temp_user, pt + 1u, ulen);
                    temp_user[ulen] = '\0';
                    target_user = temp_user;
                }
                if (ks_get_public(target_user, &pub, &pub_len) != 0) {
                    status = ST_ERR_NOT_FOUND;
                } else {
                    resp_data = pub;
                    resp_len = pub_len;
                    status = ST_OK;
                }
                break;
            }
            case OP_DELETE_KEYS:
                if (require_authenticated(&session) != 0) {
                    status = ST_ERR_AUTH;
                } else if (ks_delete_keys(session.username) != 0) {
                    status = ST_ERR_INTERNAL;
                } else {
                    session.deleted = 1;
                    status = ST_OK;
                }
                break;
            case OP_LOGOUT:
                session_clear(&session);
                status = ST_OK;
                break;
            default:
                status = ST_ERR_BAD_REQ;
                break;
            }
        }

        if (send_encrypted_response(client_fd, key_out, in_hdr.opcode, in_hdr.req_nonce,
                                    status, resp_data, resp_len) != 0) {
            free(resp_data);
            free(pt);
            dsspacket_free(payload);
            break;
        }

        free(resp_data);
        free(pt);
        dsspacket_free(payload);
    }

cleanup:
    session_clear(&session);
    free(sig);
    free(transcript);
    free(shared_secret);
    free(server_pub);
    free(client_pub);
    EVP_PKEY_free(server_ecdh_priv);
    replay_free(&cache);
    close(client_fd);
    close(listen_fd);
    return 0;
}
