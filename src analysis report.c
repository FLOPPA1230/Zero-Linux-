#include "../../include/lz.h"
#include <sys/utsname.h>

static const char *severity_str(uint32_t s) {
    switch (s) {
        case LZ_SEV_LOW:  return "LOW";
        case LZ_SEV_MED:  return "MEDIUM";
        case LZ_SEV_HIGH: return "HIGH";
        case LZ_SEV_CRIT: return "CRITICAL";
        default:          return "NONE";
    }
}

int lz_report_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    if (!ctx->config.output_dir[0]) {
        snprintf(ctx->config.output_dir, sizeof(ctx->config.output_dir), "./lz_report");
    }
    lz_mkdir_p(ctx->config.output_dir);
    return LZ_OK;
}

int lz_report_json(lz_context_t *ctx, const char *path) {
    (void)ctx; (void)path;
    return LZ_OK;
}

int lz_report_html(lz_context_t *ctx, const char *path) {
    (void)ctx; (void)path;
    return LZ_OK;
}

int lz_report_console(lz_context_t *ctx) {
    (void)ctx;
    return LZ_OK;
}

int lz_report_run(lz_context_t *ctx) {
    if (!ctx || !ctx->shm) return LZ_ERR;
    
    char path[LZ_PATH_MAX * 2];
    snprintf(path, sizeof(path), "%s/report.txt", ctx->config.output_dir);
    
    FILE *f = fopen(path, "w");
    if (!f) return LZ_ERR_IO;

    struct utsname u;
    uname(&u);
    char host[LZ_PATH_MAX] = {0};
    gethostname(host, sizeof(host) - 1);

    fprintf(f, "Hostname: %s\n", host);
    fprintf(f, "Kernel: %s %s %s\n", u.sysname, u.release, u.machine);
    fprintf(f, "Events: %llu\n", (unsigned long long)ctx->shm->stats.total_events);
    fprintf(f, "Findings: %llu\n", (unsigned long long)ctx->shm->stats.total_findings);
    fprintf(f, "Bytes: %llu\n", (unsigned long long)ctx->shm->stats.total_bytes);
    fprintf(f, "Dropped: %llu\n", (unsigned long long)ctx->shm->stats.total_dropped);
    
    uint32_t head = atomic_load_explicit(&ctx->shm->finding_head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&ctx->shm->finding_tail, memory_order_relaxed);
    uint32_t idx = tail;
    
    while (idx != head) {
        lz_finding_t *fi = &ctx->shm->findings[idx % LZ_MAX_FINDINGS];
        fprintf(f, "%s %s %s\n", severity_str(fi->severity), fi->name, fi->detail);
        idx++;
    }
    
    fclose(f);
    return LZ_OK;
}

int lz_report_stop(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_log_flush(ctx);
    return LZ_OK;
}

void lz_report_free(lz_context_t *ctx) {
    (void)ctx;
}