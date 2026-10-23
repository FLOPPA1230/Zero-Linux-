#include "../../include/lz.h"
#include <ctype.h>

lz_context_t *g_lz = NULL;

const char *lz_log_level_str(uint32_t level) {
    switch (level) {
        case LZ_LOG_DEBUG: return "DEBUG";
        case LZ_LOG_INFO:  return "INFO";
        case LZ_LOG_WARN:  return "WARN";
        case LZ_LOG_ERROR: return "ERROR";
        case LZ_LOG_FATAL: return "FATAL";
        default:           return "UNKWN";
    }
}

int lz_log_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    if (ctx->log) return LZ_OK;

    char path[LZ_PATH_MAX];
    snprintf(path, sizeof(path), "/dev/shm/%s_log", 
             ctx->config.shm_name[0] ? ctx->config.shm_name : "lz_default");
    
    ctx->log_fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (ctx->log_fd < 0) {
        return LZ_ERR_IO;
    }

    if (fchmod(ctx->log_fd, 0600) < 0) {
        close(ctx->log_fd);
        ctx->log_fd = -1;
        return LZ_ERR_PERM;
    }

    if (ftruncate(ctx->log_fd, sizeof(lz_log_t)) < 0) {
        close(ctx->log_fd);
        ctx->log_fd = -1;
        return LZ_ERR_IO;
    }

    void *mem = mmap(NULL, sizeof(lz_log_t), PROT_READ | PROT_WRITE, MAP_SHARED, ctx->log_fd, 0);
    if (mem == MAP_FAILED) {
        close(ctx->log_fd);
        ctx->log_fd = -1;
        return LZ_ERR_MEM;
    }

    ctx->log = (lz_log_t *)mem;
    memset(ctx->log, 0, sizeof(lz_log_t));
    ctx->log->magic = LZ_MAGIC;
    ctx->log->capacity = 4096;
    
    atomic_store_explicit(&ctx->log->write_idx, 0, memory_order_relaxed);
    atomic_store_explicit(&ctx->log->read_idx, 0, memory_order_relaxed);

    return LZ_OK;
}

void lz_log_free(lz_context_t *ctx) {
    if (!ctx) return;
    lz_log_flush(ctx);
    if (ctx->log) {
        munmap(ctx->log, sizeof(lz_log_t));
        ctx->log = NULL;
    }
    if (ctx->log_fd >= 0) {
        close(ctx->log_fd);
        ctx->log_fd = -1;
    }
}

void lz_log(lz_context_t *ctx, uint32_t level, uint32_t module, const char *fmt, ...) {
    if (!ctx || !fmt) return;
    
    if (level == LZ_LOG_DEBUG && !ctx->config.verbose) return;

    if (ctx->log) {
        uint32_t idx = atomic_fetch_add_explicit(&ctx->log->write_idx, 1, memory_order_relaxed) % ctx->log->capacity;
        lz_log_entry_t *e = &ctx->log->entries[idx];
        
        e->level = level;
        e->module = module;
        e->ts_ns = lz_time_ns();
        e->pid = getpid();
        e->tid = (uint32_t)syscall(SYS_gettid);
        
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(e->message, sizeof(e->message), fmt, ap);
        va_end(ap);
    }

    va_list ap2;
    va_start(ap2, fmt);
    char message[512];
    vsnprintf(message, sizeof(message), fmt, ap2);
    va_end(ap2);

    if (!ctx->config.no_color && isatty(STDERR_FILENO)) {
        const char *color = "";
        switch (level) {
            case LZ_LOG_DEBUG: color = "\033[36m"; break;
            case LZ_LOG_INFO:  color = "\033[32m"; break;
            case LZ_LOG_WARN:  color = "\033[33m"; break;
            case LZ_LOG_ERROR: color = "\033[31m"; break;
            case LZ_LOG_FATAL: color = "\033[35m"; break;
        }
        fprintf(stderr, "%s[%s] [mod%u] %s\033[0m\n", color, lz_log_level_str(level), module, message);
    } else {
        fprintf(stderr, "[%s] [mod%u] %s\n", lz_log_level_str(level), module, message);
    }

    if (level == LZ_LOG_FATAL) {
        lz_log_flush(ctx);
        abort();
    }
}

int lz_log_flush(lz_context_t *ctx) {
    if (!ctx || !ctx->log || !ctx->config.log_path[0]) return LZ_OK;
    
    FILE *f = fopen(ctx->config.log_path, "a");
    if (!f) return LZ_ERR_IO;

    uint32_t write_idx = atomic_load_explicit(&ctx->log->write_idx, memory_order_acquire);
    uint32_t read_idx = atomic_load_explicit(&ctx->log->read_idx, memory_order_relaxed);

    while (read_idx != write_idx) {
        lz_log_entry_t *e = &ctx->log->entries[read_idx % ctx->log->capacity];
        fprintf(f, "%llu [%s] [mod%u] [pid=%u, tid=%u] %s\n",
                (unsigned long long)e->ts_ns,
                lz_log_level_str(e->level),
                e->module, e->pid, e->tid, e->message);
        read_idx++;
    }
    
    atomic_store_explicit(&ctx->log->read_idx, write_idx, memory_order_release);
    fclose(f);
    return LZ_OK;
}

uint64_t lz_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

uint64_t lz_time_ms(void) {
    return lz_time_ns() / 1000000ULL;
}