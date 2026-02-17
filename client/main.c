#include "../common/dsspacket.h"
#include "../common/handshake.h"
#include "../common/net.h"
#include "../common/securechan.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

typedef struct cli_state {
    int logged_in;
    int must_change;
    int deleted;
    char username[256];
} cli_state_t;

static const char *status_to_string(dss_status_t st)
{
    switch (st) {
    case ST_OK:
        return "ok";
    case ST_ERR:
        return "error";
    case ST_ERR_AUTH:
        return "authentication error";
    case ST_ERR_DELETED:
        return "keys deleted (tombstone)";
    case ST_ERR_NOT_FOUND:
        return "not found";
    case ST_ERR_BAD_REQ:
        return "bad request";
    case ST_ERR_INTERNAL:
        return "internal error";
    default:
        return "unknown status";
    }
}

static void print_command_failure(const char *command, dss_status_t st, const cli_state_t *state)
{
    if (st == ST_ERR_DELETED) {
        puts("Operation refused: keys deleted (tombstone). Re-registration required.");
        return;
    }

    printf("%s failed: %s\n", command, status_to_string(st));
    if (st == ST_ERR_AUTH && state != NULL && state->must_change == 1) {
        puts("Hint: run 'changepw' first.");
    }
}

static void trim_newline(char *s)
{
    size_t n;

    if (s == NULL) {
        return;
    }
    n = strlen(s);
    if (n > 0 && s[n - 1] == '\n') {
        s[n - 1] = '\0';
    }
}

static int read_line(const char *prompt, char *buf, size_t buf_len)
{
    if (buf == NULL || buf_len == 0u) {
        return -1;
    }

    if (prompt != NULL) {
        fputs(prompt, stdout);
        fflush(stdout);
    }

    if (fgets(buf, (int)buf_len, stdin) == NULL) {
        return -1;
    }

    trim_newline(buf);
    return 0;
}

static int read_password(const char *prompt, char *buf, size_t buf_len)
{
    struct termios old_term;
    struct termios new_term;
    int had_tty;

    if (buf == NULL || buf_len == 0u) {
        return -1;
    }

    had_tty = isatty(STDIN_FILENO);
    if (prompt != NULL) {
        fputs(prompt, stdout);
        fflush(stdout);
    }

    if (had_tty) {
        if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
            return -1;
        }
        new_term = old_term;
        new_term.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
            return -1;
        }
    }

    if (fgets(buf, (int)buf_len, stdin) == NULL) {
        if (had_tty) {
            (void)tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        }
        return -1;
    }

    if (had_tty) {
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        fputc('\n', stdout);
    }

    trim_newline(buf);
    return 0;
}

static int read_file_all(const char *path, uint8_t **buf_out, size_t *len_out)
{
    FILE *fp;
    long size;
    uint8_t *buf;
    size_t n;

    if (path == NULL || buf_out == NULL || len_out == NULL) {
        return -1;
    }
    *buf_out = NULL;
    *len_out = 0;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    buf = (size > 0) ? malloc((size_t)size) : malloc(1u);
    if (buf == NULL) {
        fclose(fp);
        return -1;
    }

    n = fread(buf, 1u, (size_t)size, fp);
    if (n != (size_t)size) {
        free(buf);
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        free(buf);
        return -1;
    }

    *buf_out = buf;
    *len_out = (size_t)size;
    return 0;
}

static int send_request_and_get_response(int fd,
                                         const uint8_t c2s_key[32],
                                         const uint8_t s2c_key[32],
                                         dss_opcode_t opcode,
                                         const uint8_t *pt,
                                         size_t pt_len,
                                         dss_status_t *status_out,
                                         uint8_t **resp_data_out,
                                         size_t *resp_len_out)
{
    dss_header_t req_hdr;
    dss_header_t resp_hdr;
    dss_response_header_t rsp_plain_hdr;
    uint8_t resp_opcode;
    uint8_t req_aad[DSSPACKET_AAD_LEN];
    size_t req_aad_len;
    uint8_t *req_payload;
    size_t req_payload_len;
    uint8_t *resp_payload;
    uint32_t resp_payload_len;
    uint8_t resp_aad[DSSPACKET_AAD_LEN];
    size_t resp_aad_len;
    const uint8_t *resp_iv;
    const uint8_t *resp_tag;
    const uint8_t *resp_ct;
    size_t resp_ct_len;
    uint8_t *resp_pt;
    uint32_t data_len_u32;
    uint8_t *data;

    if (status_out == NULL || resp_data_out == NULL || resp_len_out == NULL) {
        return -1;
    }

    *resp_data_out = NULL;
    *resp_len_out = 0;

    req_payload = NULL;
    resp_payload = NULL;
    resp_pt = NULL;
    data = NULL;

    req_payload_len = GCM_IV_LEN + GCM_TAG_LEN + 1u + pt_len;
    if (req_payload_len > UINT32_MAX) {
        return -1;
    }

    memset(&req_hdr, 0, sizeof(req_hdr));
    if (RAND_bytes(req_hdr.req_nonce, REQ_NONCE_LEN) != 1) {
        return -1;
    }
    req_hdr.payload_len = htonl((uint32_t)req_payload_len);

    if (dsspacket_build_aad(&req_hdr, req_aad, &req_aad_len) != 0) {
        return -1;
    }

    req_payload = malloc(req_payload_len);
    if (req_payload == NULL) {
        return -1;
    }

    {
        uint8_t *req_pt;
        size_t req_pt_len = 1u + pt_len;

        req_pt = malloc(req_pt_len);
        if (req_pt == NULL) {
            free(req_payload);
            return -1;
        }
        req_pt[0] = (uint8_t)opcode;
        if (pt_len > 0u) {
            memcpy(req_pt + 1u, pt, pt_len);
        }

        if (RAND_bytes(req_payload, GCM_IV_LEN) != 1 ||
            sc_aead_encrypt(c2s_key,
                            req_payload,
                            req_aad,
                            req_aad_len,
                            req_pt,
                            req_pt_len,
                            req_payload + GCM_IV_LEN + GCM_TAG_LEN,
                            req_payload + GCM_IV_LEN) != 0 ||
            dsspacket_send(fd, &req_hdr, req_payload) != 0) {
            free(req_pt);
            free(req_payload);
            return -1;
        }

        free(req_pt);
    }
    free(req_payload);

    if (dsspacket_recv(fd, &resp_hdr, &resp_payload) != 0) {
        return -1;
    }

    resp_payload_len = ntohl(resp_hdr.payload_len);
    if (resp_payload_len < (GCM_IV_LEN + GCM_TAG_LEN)) {
        dsspacket_free(resp_payload);
        return -1;
    }

    if (dsspacket_build_aad(&resp_hdr, resp_aad, &resp_aad_len) != 0) {
        dsspacket_free(resp_payload);
        return -1;
    }

    resp_iv = resp_payload;
    resp_tag = resp_payload + GCM_IV_LEN;
    resp_ct = resp_payload + GCM_IV_LEN + GCM_TAG_LEN;
    resp_ct_len = (size_t)resp_payload_len - GCM_IV_LEN - GCM_TAG_LEN;

    resp_pt = (resp_ct_len > 0) ? malloc(resp_ct_len) : malloc(1u);
    if (resp_pt == NULL) {
        dsspacket_free(resp_payload);
        return -1;
    }

    if (sc_aead_decrypt(s2c_key,
                        resp_iv,
                        resp_aad,
                        resp_aad_len,
                        resp_ct,
                        resp_ct_len,
                        resp_tag,
                        resp_pt) != 0) {
        free(resp_pt);
        dsspacket_free(resp_payload);
        return -1;
    }

    dsspacket_free(resp_payload);

    if (resp_ct_len < (1u + sizeof(rsp_plain_hdr))) {
        free(resp_pt);
        return -1;
    }

    resp_opcode = resp_pt[0];
    if (resp_opcode != (uint8_t)opcode) {
        free(resp_pt);
        return -1;
    }

    memcpy(&rsp_plain_hdr, resp_pt + 1u, sizeof(rsp_plain_hdr));
    *status_out = (dss_status_t)ntohs(rsp_plain_hdr.status);
    data_len_u32 = ntohl(rsp_plain_hdr.data_len);

    if (resp_ct_len != 1u + sizeof(rsp_plain_hdr) + (size_t)data_len_u32) {
        free(resp_pt);
        return -1;
    }

    if (data_len_u32 > 0u) {
        data = malloc(data_len_u32);
        if (data == NULL) {
            free(resp_pt);
            return -1;
        }
        memcpy(data, resp_pt + 1u + sizeof(rsp_plain_hdr), data_len_u32);
    }

    free(resp_pt);
    *resp_data_out = data;
    *resp_len_out = (size_t)data_len_u32;
    return 0;
}

static int run_handshake(int fd, uint8_t c2s_key[32], uint8_t s2c_key[32])
{
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
    int rc;

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
    rc = -1;

    if (hs_gen_ecdh_keypair(&client_pub, &client_pub_len, &client_ecdh_priv) != 0 ||
        hs_send_chlo(fd, client_pub, client_pub_len) != 0 ||
        hs_recv_shlo(fd, &server_pub, &server_pub_len, &sig, &sig_len) != 0) {
        goto cleanup;
    }

    if (client_pub_len > SIZE_MAX - server_pub_len) {
        goto cleanup;
    }

    transcript_len = client_pub_len + server_pub_len;
    transcript = malloc(transcript_len);
    if (transcript == NULL) {
        goto cleanup;
    }
    memcpy(transcript, client_pub, client_pub_len);
    memcpy(transcript + client_pub_len, server_pub, server_pub_len);

    if (hs_verify_transcript("client/res/server_public.pem", transcript, transcript_len, sig, sig_len) != 0 ||
        hs_compute_shared(client_ecdh_priv, server_pub, server_pub_len, &shared_secret, &shared_secret_len) != 0 ||
        hs_derive_keys(shared_secret, shared_secret_len, transcript, transcript_len, c2s_key, s2c_key) != 0) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    free(shared_secret);
    free(transcript);
    free(sig);
    free(server_pub);
    EVP_PKEY_free(client_ecdh_priv);
    free(client_pub);
    return rc;
}

int main(int argc, char **argv)
{
    const char *host;
    const char *port;
    int fd;
    uint8_t c2s_key[32];
    uint8_t s2c_key[32];
    cli_state_t state;
    char line[1024];

    host = (argc > 1) ? argv[1] : "127.0.0.1";
    port = (argc > 2) ? argv[2] : "9000";
    memset(&state, 0, sizeof(state));

    fd = tcp_connect(host, port);
    if (fd < 0) {
        perror("tcp_connect");
        return 1;
    }

    /* Run the authenticated handshake immediately after connecting. */
    if (run_handshake(fd, c2s_key, s2c_key) != 0) {
        fprintf(stderr, "handshake failed\n");
        close(fd);
        return 1;
    }
    puts("Connected and handshake complete.");

    for (;;) {
        char *cmd;
        char *arg;

        if (read_line("dss> ", line, sizeof(line)) != 0) {
            break;
        }

        cmd = strtok(line, " \t");
        if (cmd == NULL) {
            continue;
        }
        arg = strtok(NULL, "");
        while (arg != NULL && (*arg == ' ' || *arg == '\t')) {
            arg++;
        }

        if (strcmp(cmd, "quit") == 0) {
            break;
        } else if (strcmp(cmd, "login") == 0) {
            uint8_t payload[1u + 255u + 1u + 255u];
            size_t ulen;
            char pw[256];
            size_t plen;
            dss_status_t st;
            uint8_t *resp;
            size_t resp_len;

            if (arg == NULL || *arg == '\0') {
                puts("usage: login <user>");
                continue;
            }
            ulen = strlen(arg);
            if (ulen == 0u || ulen > 255u) {
                puts("username length must be 1..255");
                continue;
            }
            if (read_password("password: ", pw, sizeof(pw)) != 0) {
                puts("failed to read password");
                continue;
            }
            plen = strlen(pw);
            if (plen == 0u || plen > 255u) {
                puts("password length must be 1..255");
                OPENSSL_cleanse(pw, sizeof(pw));
                continue;
            }

            payload[0] = (uint8_t)ulen;
            memcpy(payload + 1u, arg, ulen);
            payload[1u + ulen] = (uint8_t)plen;
            memcpy(payload + 2u + ulen, pw, plen);

            resp = NULL;
            resp_len = 0;
            if (send_request_and_get_response(fd,
                                              c2s_key,
                                              s2c_key,
                                              OP_AUTH,
                                              payload,
                                              2u + ulen + plen,
                                              &st,
                                              &resp,
                                              &resp_len) != 0) {
                puts("request failed");
                OPENSSL_cleanse(pw, sizeof(pw));
                continue;
            }
            OPENSSL_cleanse(pw, sizeof(pw));

            if (st == ST_OK && resp_len == 2u) {
                state.logged_in = 1;
                state.must_change = (resp[0] != 0);
                state.deleted = (resp[1] != 0);
                snprintf(state.username, sizeof(state.username), "%s", arg);
                printf("logged in as %s (must_change=%d, deleted=%d)\n",
                       state.username,
                       state.must_change,
                       state.deleted);
                if (state.must_change == 1) {
                    puts("Password change required before using other operations.");
                }
            } else {
                printf("login failed: %s\n", status_to_string(st));
            }
            free(resp);
        } else if (strcmp(cmd, "changepw") == 0) {
            char new_pw[256];
            size_t nlen;
            uint8_t payload[1u + 255u];
            dss_status_t st;
            uint8_t *resp;
            size_t resp_len;

            if (state.logged_in == 0) {
                puts("not logged in");
                continue;
            }
            if (read_password("new password: ", new_pw, sizeof(new_pw)) != 0) {
                puts("failed to read password");
                continue;
            }
            nlen = strlen(new_pw);
            if (nlen == 0u || nlen > 255u) {
                puts("password length must be 1..255");
                OPENSSL_cleanse(new_pw, sizeof(new_pw));
                continue;
            }

            payload[0] = (uint8_t)nlen;
            memcpy(payload + 1u, new_pw, nlen);
            resp = NULL;
            resp_len = 0;

            if (send_request_and_get_response(fd,
                                              c2s_key,
                                              s2c_key,
                                              OP_CHANGE_PASSWORD,
                                              payload,
                                              1u + nlen,
                                              &st,
                                              &resp,
                                              &resp_len) != 0) {
                puts("request failed");
                OPENSSL_cleanse(new_pw, sizeof(new_pw));
                continue;
            }
            OPENSSL_cleanse(new_pw, sizeof(new_pw));

            if (st == ST_OK) {
                state.must_change = 0;
                puts("password changed");
            } else {
                print_command_failure("changepw", st, &state);
            }
            free(resp);
        } else if (strcmp(cmd, "createkeys") == 0) {
            dss_status_t st;
            uint8_t *resp;
            size_t resp_len;
            resp = NULL;
            resp_len = 0;

            if (send_request_and_get_response(fd,
                                              c2s_key,
                                              s2c_key,
                                              OP_CREATE_KEYS,
                                              NULL,
                                              0,
                                              &st,
                                              &resp,
                                              &resp_len) != 0) {
                puts("request failed");
                continue;
            }
            if (st == ST_OK) {
                puts("keys created");
            } else {
                print_command_failure("createkeys", st, &state);
            }
            free(resp);
        } else if (strcmp(cmd, "signdoc") == 0) {
            uint8_t *doc;
            size_t doc_len;
            dss_status_t st;
            uint8_t *resp;
            size_t resp_len;

            if (arg == NULL || *arg == '\0') {
                puts("usage: signdoc <file>");
                continue;
            }
            doc = NULL;
            doc_len = 0;
            if (read_file_all(arg, &doc, &doc_len) != 0) {
                puts("failed to read file");
                continue;
            }

            resp = NULL;
            resp_len = 0;
            if (send_request_and_get_response(fd,
                                              c2s_key,
                                              s2c_key,
                                              OP_SIGN_DOC,
                                              doc,
                                              doc_len,
                                              &st,
                                              &resp,
                                              &resp_len) != 0) {
                puts("request failed");
                free(doc);
                continue;
            }
            free(doc);

            if (st == ST_OK) {
                printf("signature (%zu bytes):\n", resp_len);
                for (size_t i = 0; i < resp_len; i++) {
                    printf("%02x", resp[i]);
                }
                fputc('\n', stdout);
            } else {
                print_command_failure("signdoc", st, &state);
            }
            free(resp);
        } else if (strcmp(cmd, "getpub") == 0) {
            uint8_t payload[1u + 255u];
            const uint8_t *payload_ptr;
            size_t payload_len;
            dss_status_t st;
            uint8_t *resp;
            size_t resp_len;

            if (arg == NULL || *arg == '\0') {
                payload_ptr = NULL;
                payload_len = 0;
            } else {
                size_t ulen = strlen(arg);
                if (ulen == 0u || ulen > 255u) {
                    puts("username length must be 1..255");
                    continue;
                }
                payload[0] = (uint8_t)ulen;
                memcpy(payload + 1u, arg, ulen);
                payload_ptr = payload;
                payload_len = 1u + ulen;
            }

            resp = NULL;
            resp_len = 0;
            if (send_request_and_get_response(fd,
                                              c2s_key,
                                              s2c_key,
                                              OP_GET_PUBLIC_KEY,
                                              payload_ptr,
                                              payload_len,
                                              &st,
                                              &resp,
                                              &resp_len) != 0) {
                puts("request failed");
                continue;
            }

            if (st == ST_OK) {
                fwrite(resp, 1u, resp_len, stdout);
                if (resp_len == 0u || resp[resp_len - 1] != '\n') {
                    fputc('\n', stdout);
                }
            } else {
                print_command_failure("getpub", st, &state);
            }
            free(resp);
        } else if (strcmp(cmd, "deletekeys") == 0) {
            dss_status_t st;
            uint8_t *resp;
            size_t resp_len;

            resp = NULL;
            resp_len = 0;
            if (send_request_and_get_response(fd,
                                              c2s_key,
                                              s2c_key,
                                              OP_DELETE_KEYS,
                                              NULL,
                                              0,
                                              &st,
                                              &resp,
                                              &resp_len) != 0) {
                puts("request failed");
                continue;
            }
            if (st == ST_OK) {
                state.deleted = 1;
                puts("keys deleted");
            } else {
                print_command_failure("deletekeys", st, &state);
            }
            free(resp);
        } else if (strcmp(cmd, "logout") == 0) {
            dss_status_t st;
            uint8_t *resp;
            size_t resp_len;

            resp = NULL;
            resp_len = 0;
            if (send_request_and_get_response(fd,
                                              c2s_key,
                                              s2c_key,
                                              OP_LOGOUT,
                                              NULL,
                                              0,
                                              &st,
                                              &resp,
                                              &resp_len) != 0) {
                puts("request failed");
                continue;
            }

            if (st == ST_OK) {
                memset(&state, 0, sizeof(state));
                puts("logged out");
            } else {
                print_command_failure("logout", st, &state);
            }
            free(resp);
        } else {
            puts("commands: login <user>, changepw, createkeys, signdoc <file>, getpub <user>, deletekeys, logout, quit");
        }
    }

    close(fd);
    return 0;
}
