#include "../../include/lz.h"

typedef struct {
    int fds[LZ_MAX_PMCS];
    uint32_t count;
} lz_pmc_state_t;

int lz_perf_event_open(struct perf_event_attr *attr, pid_t pid,
                       int cpu, int group_fd, unsigned long flags) {
    return (int)syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int lz_pmc_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;

    lz_pmc_state_t *state = calloc(1, sizeof(lz_pmc_state_t));
    if (!state) return LZ_ERR_MEM;

    for (int i = 0; i < LZ_MAX_PMCS; i++) {
        state->fds[i] = -1;
    }

    ctx->module_data[LZ_MOD_PMC] = state;
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_PMC, "PMC module initialized");
    
    return LZ_OK;
}

int lz_pmc_open(lz_context_t *ctx, uint32_t type, uint64_t config, pid_t pid, uint32_t cpu) {
    if (!ctx) return -1;
    lz_pmc_state_t *state = (lz_pmc_state_t *)ctx->module_data[LZ_MOD_PMC];
    if (!state) return -1;

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 1;
    attr.inherit = 1;
    attr.exclude_kernel = 0;
    attr.exclude_hv = 1;

    int fd = lz_perf_event_open(&attr, pid, (int)cpu, -1, 0);
    if (fd < 0) {
        lz_log(ctx, LZ_LOG_WARN, LZ_MOD_PMC, "perf_event_open failed (type=%u, config=0x%llx): %s",
               type, (unsigned long long)config, strerror(errno));
        return -1;
    }

    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) < 0 || ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        lz_log(ctx, LZ_LOG_WARN, LZ_MOD_PMC, "ioctl PERF_EVENT_IOC failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (state->count < LZ_MAX_PMCS) {
        state->fds[state->count++] = fd;
    } else {
        close(fd);
        return -1;
    }

    if (ctx->shm) {
        __atomic_fetch_add(&ctx->shm->stats.pmc_count, 1, __ATOMIC_RELAXED);
    }

    return fd;
}

uint64_t lz_pmc_read(lz_context_t *ctx, int fd) {
    if (fd < 0) return 0;
    uint64_t value = 0;
    if (read(fd, &value, sizeof(value)) < 0) {
        if (ctx) lz_log(ctx, LZ_LOG_DEBUG, LZ_MOD_PMC, "read pmc failed: %s", strerror(errno));
        return 0;
    }
    return value;
}

int lz_pmc_close(lz_context_t *ctx, int fd) {
    if (fd < 0) return LZ_ERR;
    
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    close(fd);

    if (ctx) {
        lz_pmc_state_t *state = (lz_pmc_state_t *)ctx->module_data[LZ_MOD_PMC];
        if (state) {
            for (uint32_t i = 0; i < state->count; i++) {
                if (state->fds[i] == fd) {
                    state->fds[i] = -1;
                    break;
                }
            }
        }
    }
    return LZ_OK;
}

int lz_pmc_run(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    
    lz_pmc_state_t *state = (lz_pmc_state_t *)ctx->module_data[LZ_MOD_PMC];
    if (!state) {
        if (lz_pmc_init(ctx) != LZ_OK) return LZ_ERR;
        state = (lz_pmc_state_t *)ctx->module_data[LZ_MOD_PMC];
    }

    uint32_t pid = 0;
    uint32_t cpu = -1;

    if (ctx->config.core_count > 0) {
        cpu = ctx->config.cores[0];
    }

    lz_pmc_open(ctx, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, pid, cpu);
    lz_pmc_open(ctx, PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, pid, cpu);
    lz_pmc_open(ctx, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, pid, cpu);
    lz_pmc_open(ctx, PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES, pid, cpu);

    for (uint32_t i = 0; i < ctx->config.pmc_count; i++) {
        lz_pmc_open(ctx, PERF_TYPE_RAW, ctx->config.pmc_list[i], pid, cpu);
    }

    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_PMC, "PMCs running: %u counters active", state->count);
    
    return LZ_OK;
}

int lz_pmc_stop(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_pmc_state_t *state = (lz_pmc_state_t *)ctx->module_data[LZ_MOD_PMC];
    if (!state) return LZ_OK;

    for (uint32_t i = 0; i < LZ_MAX_PMCS; i++) {
        if (state->fds[i] >= 0) {
            ioctl(state->fds[i], PERF_EVENT_IOC_DISABLE, 0);
            close(state->fds[i]);
            state->fds[i] = -1;
        }
    }
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_PMC, "PMCs stopped");
    return LZ_OK;
}

void lz_pmc_free(lz_context_t *ctx) {
    if (!ctx) return;
    lz_pmc_stop(ctx);
    lz_pmc_state_t *state = (lz_pmc_state_t *)ctx->module_data[LZ_MOD_PMC];
    if (state) {
        free(state);
        ctx->module_data[LZ_MOD_PMC] = NULL;
    }
}