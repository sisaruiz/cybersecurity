#ifndef COMMON_DSSPACKET_H
#define COMMON_DSSPACKET_H

#include <stdint.h>

#define REQ_NONCE_LEN 16u

typedef enum dss_opcode {
    PING = 1,
    PONG = 2,
} dss_opcode_t;

#pragma pack(push, 1)
typedef struct dss_header {
    uint8_t opcode;
    uint8_t reserved[3];
    uint8_t req_nonce[REQ_NONCE_LEN];
    uint32_t payload_len; /* Network byte order. */
} dss_header_t;
#pragma pack(pop)

int dsspacket_send(int fd, const dss_header_t *hdr, const uint8_t *payload);
int dsspacket_recv(int fd, dss_header_t *hdr, uint8_t **payload_out);
void dsspacket_free(uint8_t *payload);

#endif /* COMMON_DSSPACKET_H */
