#include "../../include/lz.h"

int lz_ring_init(lz_context_t *ctx, size_t size) {
    if (!ctx) return LZ_ERR;
    if (ctx->shm && ctx->shm->ring) return LZ_OK;

    if (size == 0) size = LZ_RING_SIZE;
    
    size = 1 << (32 - __builtin_clz(size - 1));

    if (!ctx->shm) return LZ_ERR;

    char path[LZ_PATH_MAX];
    snprintf(path, sizeof(path), "/dev/shm/%s_ring", 
             ctx->config.shm_name[0] ? ctx->config.shm_name : "lz_default");

    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return LZ_ERR_IO;
    
    fchmod(fd, 0600);

    size_t total_size = sizeof(lz_ring_t) + size;

    if (ftruncate(fd, total_size) < 0) {
        close(fd);
        return LZ_ERR_IO;
    }

    void *mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        close(fd);
        return LZ_ERR_MEM;
    }

    lz_ring_t *ring = (lz_ring_t *)mem;
    ring->capacity = (uint32_t)size;
    ring->mask = (uint32_t)(size - 1);
    ring->entry_size = sizeof(lz_event_t);
    
    atomic_store_explicit(&ring->write_idx, 0, memory_order_relaxed);
    atomic_store_explicit(&ring->read_idx, 0, memory_order_relaxed);
    atomic_store_explicit(&ring->dropped, 0, memory_order_relaxed);

    ctx->shm->ring = ring;
    ctx->shm->ring_size = size;
    ctx->shm->ring_phys = 0;
    close(fd);

    return LZ_OK;
}

void lz_ring_free(lz_context_t *ctx) {
    if (!ctx || !ctx->shm || !ctx->shm->ring) return;
    
    size_t total_size = sizeof(lz_ring_t) + ctx->shm->ring_size;
    munmap(ctx->shm->ring, total_size);
    
    ctx->shm->ring = NULL;
    ctx->shm->ring_size = 0;
}

int lz_ring_push(lz_context_t *ctx, const lz_event_t *ev) {
    if (!ctx || !ctx->shm || !ctx->shm->ring || !ev) return LZ_ERR;

    lz_ring_t *ring = ctx->shm->ring;
    uint32_t w = atomic_load_explicit(&ring->write_idx, memory_order_relaxed);
    uint32_t r = atomic_load_explicit(&ring->read_idx, memory_order_acquire);

    if ((w - r) >= ring->capacity) {
        atomic_fetch_add_explicit(&ring->dropped, 1, memory_order_relaxed);
        return LZ_ERR_RING;
    }

    size_t offset = sizeof(lz_ring_t) + (w & ring->mask) * ring->entry_size;
    uint8_t *dst = (uint8_t *)ring + offset;
    
    memcpy(dst, ev, sizeof(lz_event_t));

    atomic_store_explicit(&ring->write_idx, w + 1, memory_order_release);

    return LZ_OK;
}

int lz_ring_pop(lz_context_t *ctx, lz_event_t *ev) {
    if (!ctx || !ctx->shm || !ctx->shm->ring || !ev) return LZ_ERR;

    lz_ring_t *ring = ctx->shm->ring;
    uint32_t r = atomic_load_explicit(&ring->read_idx, memory_order_relaxed);
    uint32_t w = atomic_load_explicit(&ring->write_idx, memory_order_acquire);

    if (r == w) {
        return LZ_ERR_RING;
    }

    size_t offset = sizeof(lz_ring_t) + (r & ring->mask) * ring->entry_size;
    uint8_t *src = (uint8_t *)ring + offset;
    
    memcpy(ev, src, sizeof(lz_event_t));

    atomic_store_explicit(&ring->read_idx, r + 1, memory_order_release);

    return LZ_OK;
}

uint64_t lz_ring_count(lz_context_t *ctx) {
    if (!ctx || !ctx->shm || !ctx->shm->ring) return 0;
    lz_ring_t *ring = ctx->shm->ring;
    uint32_t w = atomic_load_explicit(&ring->write_idx, memory_order_acquire);
    uint32_t r = atomic_load_explicit(&ring->read_idx, memory_order_acquire);
    return (w >= r) ? (w - r) : (UINT32_MAX - r + w + 1);
}

uint64_t lz_ring_dropped(lz_context_t *ctx) {
    if (!ctx || !ctx->shm || !ctx->shm->ring) return 0;
    return atomic_load_explicit(&ctx->shm->ring->dropped, memory_order_relaxed);
}

int lz_ring_run(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    if (!ctx->shm || !ctx->shm->ring) {
        return lz_ring_init(ctx, ctx->config.ring_size);
    }
    return LZ_OK;
}

int lz_ring_stop(lz_context_t *ctx) {
    (void)ctx;
    return LZ_OK;
}