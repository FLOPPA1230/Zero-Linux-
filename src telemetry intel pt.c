#include "../../include/lz.h"

typedef struct {
    int fd;
    void *base;
    size_t base_size;
    void *aux;
    size_t aux_size;
    uint32_t cpu;
    pid_t pid;
} lz_pt_state_t;

static size_t lz_pt_page_size(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    return page ? page : 4096;
}

static uint32_t lz_pt_type_id(void) {
    uint32_t type = 8;
    int fd = open("/sys/bus/event_source/devices/intel_pt/type", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char buf[16] = {0};
        if (read(fd, buf, sizeof(buf) - 1) > 0) {
            uint32_t val = (uint32_t)strtoul(buf, NULL, 10);
            if (val > 0) type = val;
        }
        close(fd);
    }
    return type;
}

int lz_pt_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;

    lz_pt_state_t *state = calloc(1, sizeof(lz_pt_state_t));
    if (!state) return LZ_ERR_MEM;

    state->fd = -1;
    state->base = NULL;
    state->aux = NULL;
    state->aux_size = lz_pt_page_size() * 256;
    
    ctx->module_data[LZ_MOD_PT] = state;
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_PT, "Intel PT initialized (aux %zu bytes, type %u)", 
           state->aux_size, lz_pt_type_id());
    return LZ_OK;
}

int lz_pt_open(lz_context_t *ctx, pid_t pid, uint32_t cpu) {
    if (!ctx) return -1;
    lz_pt_state_t *state = (lz_pt_state_t *)ctx->module_data[LZ_MOD_PT];
    if (!state) return -1;
    if (state->fd >= 0) return state->fd;

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = lz_pt_type_id();
    attr.size = sizeof(attr);
    attr.config = 0;
    attr.disabled = 1;
    attr.inherit = 1;
    attr.exclude_hv = 1;
    attr.exclude_idle = 1;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    attr.sample_period = 1;

    int fd = lz_perf_event_open(&attr, pid, (int)cpu, -1, 0);
    if (fd < 0) {
        lz_log(ctx, LZ_LOG_WARN, LZ_MOD_PT, "perf_event_open PT failed: %s", strerror(errno));
        return -1;
    }

    size_t page = lz_pt_page_size();
    size_t base_size = page * 8;
    size_t aux_size = state->aux_size + page;

    void *base = mmap(NULL, base_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_PT, "mmap base failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)base;
    meta->aux_offset = base_size;
    meta->aux_size = aux_size;

    void *aux = mmap(NULL, aux_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)base_size);
    if (aux == MAP_FAILED) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_PT, "mmap aux failed: %s", strerror(errno));
        munmap(base, base_size);
        close(fd);
        return -1;
    }

    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) < 0 || ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_PT, "ioctl enable failed: %s", strerror(errno));
        munmap(aux, aux_size);
        munmap(base, base_size);
        close(fd);
        return -1;
    }

    state->fd = fd;
    state->base = base;
    state->base_size = base_size;
    state->aux = aux;
    state->aux_size = aux_size;
    state->pid = pid;
    state->cpu = cpu;

    if (ctx->shm) {
        __atomic_fetch_add(&ctx->shm->stats.total_bytes, 1, __ATOMIC_RELAXED);
    }

    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_PT, "PT started cpu=%u fd=%d aux=%zu", cpu, fd, aux_size);
    return fd;
}

int lz_pt_read(lz_context_t *ctx, uint8_t *buf, size_t size) {
    if (!ctx || !buf || size == 0) return -1;
    lz_pt_state_t *state = (lz_pt_state_t *)ctx->module_data[LZ_MOD_PT];
    if (!state || state->fd < 0 || !state->base) return -1;

    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)state->base;
    uint64_t head = __atomic_load_n(&meta->aux_head, __ATOMIC_ACQUIRE);
    uint64_t tail = __atomic_load_n(&meta->aux_tail, __ATOMIC_RELAXED);

    if (head == tail) return 0;

    uint64_t available = head - tail;
    size_t to_copy = (available < size) ? (size_t)available : size;
    size_t offset = (size_t)(tail % (state->aux_size - lz_pt_page_size()));
    size_t capacity = state->aux_size - lz_pt_page_size();

    if (offset + to_copy > capacity) {
        to_copy = capacity - offset;
    }

    memcpy(buf, (uint8_t *)state->aux + offset, to_copy);
    __atomic_store_n(&meta->aux_tail, tail + to_copy, __ATOMIC_RELEASE);

    return (int)to_copy;
}

int lz_pt_decode(lz_context_t *ctx, const uint8_t *buf, size_t size) {
    if (!ctx || !buf || size == 0) return LZ_ERR;

    size_t offset = 0;
    while (offset < size && (ctx->shm && ctx->shm->ring)) {
        lz_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.ts_ns = lz_time_ns();
        ev.type = LZ_EV_PT;
        ev.cpu = 0;
        ev.tid = (uint64_t)getpid();

        size_t chunk = size - offset;
        if (chunk > sizeof(ev.data)) chunk = sizeof(ev.data);
        
        memcpy(ev.data, buf + offset, chunk);
        ev.a0 = chunk;
        ev.a1 = offset;

        lz_ring_push(ctx, &ev);
        offset += chunk;
    }
    return LZ_OK;
}

int lz_pt_run(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_pt_state_t *state = (lz_pt_state_t *)ctx->module_data[LZ_MOD_PT];
    if (!state) {
        if (lz_pt_init(ctx) != LZ_OK) return LZ_ERR;
        state = (lz_pt_state_t *)ctx->module_data[LZ_MOD_PT];
    }

    pid_t pid = -1;
    uint32_t cpu = ctx->config.core_count > 0 ? ctx->config.cores[0] : 0;

    if (lz_pt_open(ctx, pid, cpu) < 0) {
        return LZ_ERR_PERF;
    }
    return LZ_OK;
}

int lz_pt_stop(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_pt_state_t *state = (lz_pt_state_t *)ctx->module_data[LZ_MOD_PT];
    if (!state) return LZ_OK;

    if (state->fd >= 0) {
        ioctl(state->fd, PERF_EVENT_IOC_DISABLE, 0);
        if (state->aux) munmap(state->aux, state->aux_size);
        if (state->base) munmap(state->base, state->base_size);
        close(state->fd);
        state->fd = -1;
        state->aux = NULL;
        state->base = NULL;
        lz_log(ctx, LZ_LOG_INFO, LZ_MOD_PT, "Intel PT stopped");
    }
    return LZ_OK;
}

void lz_pt_free(lz_context_t *ctx) {
    if (!ctx) return;
    lz_pt_stop(ctx);
    lz_pt_state_t *state = (lz_pt_state_t *)ctx->module_data[LZ_MOD_PT];
    if (state) {
        free(state);
        ctx->module_data[LZ_MOD_PT] = NULL;
    }
}