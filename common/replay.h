#ifndef COMMON_REPLAY_H
#define COMMON_REPLAY_H

#include <stddef.h>
#include <stdint.h>

#define REPLAY_NONCE_LEN 16u
#define REPLAY_DEFAULT_CAPACITY 1024u

typedef struct ReplayCache {
    uint8_t *entries;
    size_t capacity;
    size_t count;
    size_t next_index;
} ReplayCache;

/*
 * Initialise a replay cache.
 * If capacity is zero, a sensible default is used.
 */
int replay_init(ReplayCache *c, size_t capacity);

/* Release any resources held by the replay cache. */
void replay_free(ReplayCache *c);

/*
 * Check nonce presence and add if fresh.
 * Returns 1 if added, 0 if already seen, and -1 on error.
 */
int replay_check_and_add(ReplayCache *c, const uint8_t nonce[16]);

#endif /* COMMON_REPLAY_H */
