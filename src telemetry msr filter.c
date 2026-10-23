#include "../../include/lz.h"

typedef struct {
    int kvm_fd;
    int vm_fd;
    uint32_t msr_count;
    struct kvm_msr_filter filter;
} lz_msr_state_t;

int lz_msr_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;

    lz_msr_state_t *state = calloc(1, sizeof(lz_msr_state_t));
    if (!state) return LZ_ERR_MEM;

    state->kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (state->kvm_fd < 0) {
        lz_log(ctx, LZ_LOG_WARN, LZ_MOD_MSR, "/dev/kvm unavailable: %s", strerror(errno));
        free(state);
        return LZ_ERR_KVM;
    }

    state->vm_fd = ioctl(state->kvm_fd, KVM_CREATE_VM, 0);
    if (state->vm_fd < 0) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_MSR, "KVM_CREATE_VM failed: %s", strerror(errno));
        close(state->kvm_fd);
        free(state);
        return LZ_ERR_KVM;
    }

    memset(&state->filter, 0, sizeof(state->filter));
    state->filter.flags = KVM_MSR_FILTER_DEFAULT_ALLOW;
    
    state->msr_count = 0;
    ctx->module_data[LZ_MOD_MSR] = state;
    
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_MSR, "MSR filter initialized");
    return LZ_OK;
}

int lz_msr_filter_add(lz_context_t *ctx, uint32_t msr, uint32_t flags) {
    if (!ctx) return LZ_ERR;
    lz_msr_state_t *state = (lz_msr_state_t *)ctx->module_data[LZ_MOD_MSR];
    if (!state) return LZ_ERR;

    if (state->msr_count >= KVM_MSR_FILTER_MAX_RANGES) {
        lz_log(ctx, LZ_LOG_WARN, LZ_MOD_MSR, "MSR filter ranges full");
        return LZ_ERR_MEM;
    }

    struct kvm_msr_filter_range *range = &state->filter.ranges[state->msr_count];
    range->flags = flags;
    range->base = msr;
    range->nmsrs = 1;
    
    range->bitmap = calloc(1, 1);
    if (!range->bitmap) return LZ_ERR_MEM;

    state->msr_count++;
    
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_MSR, "intercept MSR 0x%x (flags=0x%x)", msr, flags);
    return LZ_OK;
}

int lz_msr_filter_apply(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_msr_state_t *state = (lz_msr_state_t *)ctx->module_data[LZ_MOD_MSR];
    if (!state || state->vm_fd < 0) return LZ_ERR;

    if (ioctl(state->vm_fd, KVM_X86_SET_MSR_FILTER, &state->filter) < 0) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_MSR, "KVM_X86_SET_MSR_FILTER failed: %s", strerror(errno));
        return LZ_ERR_KVM;
    }
    
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_MSR, "MSR filter applied with %u ranges", state->msr_count);
    return LZ_OK;
}

int lz_msr_handle_exit(lz_context_t *ctx, struct kvm_run *run) {
    if (!ctx || !run) return LZ_ERR;

    if (run->exit_reason != KVM_EXIT_X86_RDMSR && run->exit_reason != KVM_EXIT_X86_WRMSR) {
        return LZ_OK;
    }

    uint32_t msr = run->msr.index;
    uint64_t data = run->msr.data;
    uint32_t is_write = (run->exit_reason == KVM_EXIT_X86_WRMSR);

    if (ctx->shm && ctx->shm->ring) {
        lz_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.ts_ns = lz_time_ns();
        ev.type = LZ_EV_MSR;
        ev.cpu = 0;
        ev.tid = (uint64_t)getpid();
        ev.a0 = msr;
        ev.a1 = data;
        ev.a2 = is_write;
        
        lz_ring_push(ctx, &ev);
        __atomic_fetch_add(&ctx->shm->stats.msr_count, 1, __ATOMIC_RELAXED);
    }

    if (!is_write) {
        if (run->msr.error) {
            run->msr.data = 0;
        }
    } else {
        if (run->msr.error) {
            run->msr.error = 0;
        }
    }

    return LZ_OK;
}

int lz_msr_run(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_msr_state_t *state = (lz_msr_state_t *)ctx->module_data[LZ_MOD_MSR];
    if (!state) {
        if (lz_msr_init(ctx) != LZ_OK) return LZ_ERR_KVM;
        state = (lz_msr_state_t *)ctx->module_data[LZ_MOD_MSR];
    }

    lz_msr_filter_add(ctx, 0x1A0, KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE);
    lz_msr_filter_add(ctx, 0x199, KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE);
    lz_msr_filter_add(ctx, 0x1B,  KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE);
    lz_msr_filter_add(ctx, 0x10,  KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE);

    for (uint32_t i = 0; i < ctx->config.msr_count; i++) {
        lz_msr_filter_add(ctx, ctx->config.msr_list[i], KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE);
    }

    return lz_msr_filter_apply(ctx);
}

int lz_msr_stop(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_msr_state_t *state = (lz_msr_state_t *)ctx->module_data[LZ_MOD_MSR];
    if (!state) return LZ_OK;

    for (uint32_t i = 0; i < state->msr_count; i++) {
        if (state->filter.ranges[i].bitmap) {
            free(state->filter.ranges[i].bitmap);
            state->filter.ranges[i].bitmap = NULL;
        }
    }

    if (state->vm_fd >= 0) close(state->vm_fd);
    if (state->kvm_fd >= 0) close(state->kvm_fd);
    
    state->vm_fd = -1;
    state->kvm_fd = -1;
    
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_MSR, "MSR filter stopped");
    return LZ_OK;
}

void lz_msr_free(lz_context_t *ctx) {
    if (!ctx) return;
    lz_msr_stop(ctx);
    lz_msr_state_t *state = (lz_msr_state_t *)ctx->module_data[LZ_MOD_MSR];
    if (state) {
        free(state);
        ctx->module_data[LZ_MOD_MSR] = NULL;
    }
}