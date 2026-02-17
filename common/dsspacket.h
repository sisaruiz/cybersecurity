#ifndef COMMON_DSSPACKET_H
#define COMMON_DSSPACKET_H

#include <stddef.h>
#include <stdint.h>

#define REQ_NONCE_LEN 16u
#define DSSPACKET_AAD_LEN 20u

typedef enum dss_opcode {
    OP_AUTH = 0,
    OP_CHANGE_PASSWORD = 1,
    OP_CREATE_KEYS = 2,
    OP_SIGN_DOC = 3,
    OP_GET_PUBLIC_KEY = 4,
    OP_DELETE_KEYS = 5,
    OP_LOGOUT = 6,
} dss_opcode_t;

/*
 * Encrypted request plaintext format:
 *   u8 opcode | operation-specific bytes
 *
 * OP_AUTH operation-specific request bytes:
 *   u8 username_len | username bytes | u8 password_len | password bytes
 *
 * Encrypted response plaintext format:
 *   u8 opcode | response header | operation-specific bytes
 *
 * OP_AUTH response operation-specific bytes:
 *   u8 must_change_flag | u8 deleted_flag
 *
 * The request nonce format remains unchanged.
 */

typedef enum dss_status {
    ST_OK = 0,
    ST_ERR = 1,
    ST_ERR_AUTH = 2,
    ST_ERR_DELETED = 3,
    ST_ERR_NOT_FOUND = 4,
    ST_ERR_BAD_REQ = 5,
    ST_ERR_INTERNAL = 6,
} dss_status_t;

#pragma pack(push, 1)
typedef struct dss_header {
    uint8_t req_nonce[REQ_NONCE_LEN];
    uint32_t payload_len; /* Network byte order. */
} dss_header_t;

typedef struct dss_response_header {
    uint16_t status;   /* Network byte order. */
    uint32_t data_len; /* Network byte order. */
} dss_response_header_t;
#pragma pack(pop)

int dsspacket_build_aad(const dss_header_t *hdr, uint8_t aad_out[DSSPACKET_AAD_LEN], size_t *aad_len);

int dsspacket_send(int fd, const dss_header_t *hdr, const uint8_t *payload);
int dsspacket_recv(int fd, dss_header_t *hdr, uint8_t **payload_out);
void dsspacket_free(uint8_t *payload);

#endif /* COMMON_DSSPACKET_H */
