#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "tools.h"


void create_mem_pool(MEMORY_POOL *mp) {
    mp->mem = (uint8_t*)calloc(mp->max_size, 1);
    mp->usage = 0;
}

void del_mem_pool(MEMORY_POOL *mp) {
    free(mp->mem);
    memset(mp, 0, sizeof(MEMORY_POOL)); // heap assert
}

void* mem_pool_alloc(MEMORY_POOL *mp, size_t size) {
    assert(mp->max_size >= size + mp->usage);
    if (0 == size) {
        return NULL;
    }
    uint8_t *ret = &mp->mem[mp->usage];
    memset(ret, 0, size);
    mp->usage += size;
    return ret;
}

void mem_pool_free(MEMORY_POOL *mp, size_t size) {
    assert(mp->usage >= size);
    if (0 == size) {
        return;
    }
    // memset(&mp->mem[mp->usage - size], 0, size);
    mp->usage -= size;
    return;
}