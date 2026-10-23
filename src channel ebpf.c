#include "../../include/lz.h"
#include <sys/utsname.h>

typedef struct {
    int perf_fds[16];
    uint32_t count;
    size_t page_size;
    void *meta;
    size_t meta_size;
    void *data;
    size_t data_size;
} lz_ebpf_state_t;

static int lz_ebpf_get_tracepoint_id(const char *category, const char *name) {
    char path[LZ_PATH_MAX];
    snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/%s/%s/id", category, name);
    
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%s/%s/id", category, name);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
    }
    
    char buf[32] = {0};
    if (read(fd, buf, sizeof(buf) - 1) <= 0) {
        close(fd);
        return -1;
    }
    close(fd);
    
    return (int)strtol(buf, NULL, 10);
}

int lz_ebpf_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;

    lz_ebpf_state_t *state = calloc(1, sizeof(lz_ebpf_state_t));
    if (!state) return LZ_ERR_MEM;

    state->page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (state->page_size == 0) state->page_size = 4096;
    
    state->data_size = state->page_size * 8;
    state->meta_size = state->page_size;
    state->count = 0;

    for (int i = 0; i < 16; i++) state->perf_fds[i] = -1;

    ctx->module_data[LZ_MOD_EBPF] = state;
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_EBPF, "eBPF monitor initialized");
    return LZ_OK;
}

int lz_ebpf_attach_syscall(lz_context_t *ctx, const char *prog) {
    if (!ctx || !prog) return -1;
    lz_ebpf_state_t *state = (lz_ebpf_state_t *)ctx->module_data[LZ_MOD_EBPF];
    if (!state) return -1;

    char category[64] = {0};
    char name[64] = {0};
    
    char *sep = strchr(prog, ':');
    if (sep) {
        size_t cat_len = sep - prog;
        if (cat_len >= sizeof(category)) cat_len = sizeof(category) - 1;
        memcpy(category, prog, cat_len);
        snprintf(name, sizeof(name), "%s", sep + 1);
    } else {
        snprintf(category, sizeof(category), "syscalls");
        snprintf(name, sizeof(name), "%s", prog);
    }

    int id = lz_ebpf_get_tracepoint_id(category, name);
    if (id < 0) {
        lz_log(ctx, LZ_LOG_WARN, LZ_MOD_EBPF, "tracepoint %s:%s not found", category, name);
        return -1;
    }

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = (uint64_t)id;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    attr.disabled = 1;

    int fd = lz_perf_event_open(&attr, -1, 0, -1, 0);
    if (fd < 0) {
        lz_log(ctx, LZ_LOG_WARN, LZ_MOD_EBPF, "perf_event_open for %s failed: %s", prog, strerror(errno));
        return -1;
    }

    if (state->count < 16) {
        state->perf_fds[state->count++] = fd;
    } else {
        close(fd);
        return -1;
    }

    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_EBPF, "attached to %s:%s (id=%d, fd=%d)", category, name, id, fd);
    return fd;
}

int lz_ebpf_poll(lz_context_t *ctx, lz_event_t *ev, uint32_t timeout_ms) {
    if (!ctx || !ev) return LZ_ERR;
    lz_ebpf_state_t *state = (lz_ebpf_state_t *)ctx->module_data[LZ_MOD_EBPF];
    if (!state || state->count == 0) return LZ_ERR;

    struct pollfd pfd[16];
    for (uint32_t i = 0; i < state->count; i++) {
        pfd[i].fd = state->perf_fds[i];
        pfd[i].events = POLLIN;
        pfd[i].revents = 0;
    }

    int ret = poll(pfd, state->count, (int)timeout_ms);
    if (ret <= 0) return LZ_ERR;

    for (uint32_t i = 0; i < state->count; i++) {
        if (pfd[i].revents & POLLIN) {
            uint8_t buffer[4096];
            ssize_t n = read(state->perf_fds[i], buffer, sizeof(buffer));
            if (n > 0) {
                memset(ev, 0, sizeof(lz_event_t));
                ev->ts_ns = lz_time_ns();
                ev->type = LZ_EV_SYSCALL;
                ev->cpu = 0;
                ev->tid = (uint64_t)getpid();
                ev->a0 = (uint64_t)state->perf_fds[i];
                
                size_t copy_size = (size_t)n > sizeof(ev->data) ? sizeof(ev->data) : (size_t)n;
                memcpy(ev->data, buffer, copy_size);
                
                if (ctx->shm && ctx->shm->ring) {
                    lz_ring_push(ctx, ev);
                }
                return LZ_OK;
            }
        }
    }
    return LZ_ERR;
}

int lz_ebpf_run(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_ebpf_state_t *state = (lz_ebpf_state_t *)ctx->module_data[LZ_MOD_EBPF];
    if (!state) {
        if (lz_ebpf_init(ctx) != LZ_OK) return LZ_ERR;
        state = (lz_ebpf_state_t *)ctx->module_data[LZ_MOD_EBPF];
    }

    lz_ebpf_attach_syscall(ctx, "sys_enter_execve");
    lz_ebpf_attach_syscall(ctx, "sys_enter_ptrace");
    lz_ebpf_attach_syscall(ctx, "sys_enter_init_module");
    lz_ebpf_attach_syscall(ctx, "sys_enter_bpf");

    if (state->count == 0) {
        lz_log(ctx, LZ_LOG_WARN, LZ_MOD_EBPF, "no tracepoints attached (requires root/debugfs)");
        return LZ_ERR_BPF;
    }

    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_EBPF, "eBPF monitor running with %u tracepoints", state->count);
    return LZ_OK;
}

int lz_ebpf_stop(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_ebpf_state_t *state = (lz_ebpf_state_t *)ctx->module_data[LZ_MOD_EBPF];
    if (!state) return LZ_OK;

    for (uint32_t i = 0; i < state->count; i++) {
        if (state->perf_fds[i] >= 0) {
            close(state->perf_fds[i]);
            state->perf_fds[i] = -1;
        }
    }
    state->count = 0;
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_EBPF, "eBPF monitor stopped");
    return LZ_OK;
}

void lz_ebpf_free(lz_context_t *ctx) {
    if (!ctx) return;
    lz_ebpf_stop(ctx);
    lz_ebpf_state_t *state = (lz_ebpf_state_t *)ctx->module_data[LZ_MOD_EBPF];
    if (state) {
        free(state);
        ctx->module_data[LZ_MOD_EBPF] = NULL;
    }
}