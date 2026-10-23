#include "../../include/lz.h"

int lz_iso_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus < 1) return LZ_ERR;
    
    if (ctx->config.core_count == 0) {
        uint32_t max_cores = (num_cpus > LZ_MAX_CORES) ? LZ_MAX_CORES : (uint32_t)num_cpus;
        for (uint32_t i = 0; i < max_cores; i++) {
            ctx->config.cores[i] = i;
        }
        ctx->config.core_count = max_cores;
    }
    
    if (ctx->shm) {
        ctx->shm->core_count = ctx->config.core_count;
        for (uint32_t i = 0; i < ctx->config.core_count && i < LZ_MAX_CORES; i++) {
            uint32_t cpu = ctx->config.cores[i];
            if (cpu < 64) {
                ctx->shm->core_mask[i] = 1ULL << cpu;
            }
        }
    }
    
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_ISO, "isolation initialized with %u cores", ctx->config.core_count);
    return LZ_OK;
}

int lz_iso_pin_core(lz_context_t *ctx, uint32_t cpu) {
    if (!ctx) return LZ_ERR;
    
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu >= (uint32_t)num_cpus) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_ISO, "invalid cpu %u", cpu);
        return LZ_ERR;
    }

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);

    pid_t pid = 0;
    if (sched_setaffinity(pid, sizeof(cpu_set_t), &set) < 0) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_ISO, "sched_setaffinity failed: %s", strerror(errno));
        return LZ_ERR_PERM;
    }

    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_ISO, "pinned to core %u", cpu);
    return LZ_OK;
}

int lz_iso_set_affinity(lz_context_t *ctx, pid_t tid, uint32_t cpu) {
    if (!ctx) return LZ_ERR;
    
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu >= (uint32_t)num_cpus) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_ISO, "invalid cpu %u", cpu);
        return LZ_ERR;
    }

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);

    if (sched_setaffinity(tid, sizeof(cpu_set_t), &set) < 0) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_ISO, "sched_setaffinity (tid=%d) failed: %s", tid, strerror(errno));
        return LZ_ERR_PERM;
    }

    return LZ_OK;
}

int lz_iso_run(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    
    if (ctx->config.core_count == 0) {
        return lz_iso_init(ctx);
    }

    for (uint32_t i = 0; i < ctx->config.core_count && i < LZ_MAX_CORES; i++) {
        uint32_t cpu = ctx->config.cores[i];
        lz_log(ctx, LZ_LOG_INFO, LZ_MOD_ISO, "preparing core %u for telemetry", cpu);
    }

    return LZ_OK;
}

int lz_iso_stop(lz_context_t *ctx) {
    (void)ctx;
    return LZ_OK;
}

void lz_iso_free(lz_context_t *ctx) {
    (void)ctx;
}