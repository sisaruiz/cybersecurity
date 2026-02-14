#include "replay.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int replay_init(ReplayCache *c, size_t capacity)
{
    size_t total_bytes;

    if (c == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (capacity == 0) {
        capacity = REPLAY_DEFAULT_CAPACITY;
    }

    if (capacity > (SIZE_MAX / REPLAY_NONCE_LEN)) {
        errno = EOVERFLOW;
        return -1;
    }

    total_bytes = capacity * REPLAY_NONCE_LEN;
    c->entries = calloc(1, total_bytes);
    if (c->entries == NULL) {
        return -1;
    }

    c->capacity = capacity;
    c->count = 0;
    c->next_index = 0;
    return 0;
}

void replay_free(ReplayCache *c)
{
    if (c == NULL) {
        return;
    }

    free(c->entries);
    c->entries = NULL;
    c->capacity = 0;
    c->count = 0;
    c->next_index = 0;
}

int replay_check_and_add(ReplayCache *c, const uint8_t nonce[16])
{
    size_t i;
    uint8_t *slot;

    if (c == NULL || nonce == NULL || c->entries == NULL || c->capacity == 0) {
        errno = EINVAL;
        return -1;
    }

    /* Scan only entries currently in use during initial fill-up. */
    for (i = 0; i < c->count; i++) {
        const uint8_t *existing = c->entries + (i * REPLAY_NONCE_LEN);
        if (memcmp(existing, nonce, REPLAY_NONCE_LEN) == 0) {
            return 0;
        }
    }

    /* Insert at ring head, overwriting the oldest element once full. */
    slot = c->entries + (c->next_index * REPLAY_NONCE_LEN);
    memcpy(slot, nonce, REPLAY_NONCE_LEN);

    c->next_index = (c->next_index + 1) % c->capacity;
    if (c->count < c->capacity) {
        c->count++;
    }

    return 1;
}
