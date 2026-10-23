#include "../../include/lz.h"

typedef struct {
    uint64_t last_ip;
    uint64_t last_branch;
    uint32_t packet_count;
    uint32_t branch_count;
    uint32_t tnt_count;
} lz_decode_state_t;

int lz_decode_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;

    lz_decode_state_t *state = calloc(1, sizeof(lz_decode_state_t));
    if (!state) return LZ_ERR_MEM;

    state->last_ip = 0;
    state->last_branch = 0;
    state->packet_count = 0;
    state->branch_count = 0;
    state->tnt_count = 0;

    ctx->module_data[LZ_MOD_DECODE] = state;
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_DECODE, "Decoder initialized");
    return LZ_OK;
}

int lz_decode_branch(lz_context_t *ctx, uint64_t from, uint64_t to, lz_branch_event_t *out) {
    if (!ctx || !out) return LZ_ERR;

    memset(out, 0, sizeof(lz_branch_event_t));
    out->ip = from;
    out->target = to;
    out->tid = (uint64_t)getpid();
    out->taken = (from != to) ? 1 : 0;
    out->cpu = 0;
    out->ts_ns = lz_time_ns();

    if (ctx->shm && ctx->shm->ring) {
        lz_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.ts_ns = out->ts_ns;
        ev.type = LZ_EV_BRANCH;
        ev.cpu = out->cpu;
        ev.tid = out->tid;
        ev.a0 = out->ip;
        ev.a1 = out->target;
        ev.a2 = out->taken;
        lz_ring_push(ctx, &ev);
    }
    return LZ_OK;
}

int lz_decode_pt_packet(lz_context_t *ctx, const uint8_t *buf, size_t size, lz_event_t *out) {
    if (!ctx || !buf || size == 0 || !out) return LZ_ERR;

    lz_decode_state_t *state = (lz_decode_state_t *)ctx->module_data[LZ_MOD_DECODE];
    if (!state) return LZ_ERR;

    memset(out, 0, sizeof(lz_event_t));
    out->ts_ns = lz_time_ns();
    out->type = LZ_EV_PT;
    out->cpu = 0;
    out->tid = (uint64_t)getpid();

    size_t offset = 0;
    while (offset < size) {
        uint8_t byte = buf[offset];
        
        if ((byte & 0x1F) == 0x0D) {
            if (offset + 7 < size) {
                uint64_t ip = 0;
                memcpy(&ip, buf + offset + 1, 7);
                state->last_ip = ip;
                out->a0 = ip;
                out->a2 = 1;
                offset += 8;
            } else {
                break;
            }
        }
        else if ((byte & 0x1F) == 0x1D) {
            if (offset + 1 < size) {
                uint8_t tnt = buf[offset + 1];
                for (int i = 0; i < 8; i++) {
                    if (tnt & (1 << i)) {
                        state->branch_count++;
                    }
                }
                out->a1 = tnt;
                state->tnt_count++;
                offset += 2;
            } else {
                break;
            }
        }
        else {
            offset++;
        }
        state->packet_count++;
    }

    out->a3 = state->packet_count;
    
    if (ctx->shm) {
        __atomic_fetch_add(&ctx->shm->stats.total_events, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&ctx->shm->stats.total_bytes, size, __ATOMIC_RELAXED);
    }

    return LZ_OK;
}

int lz_decode_run(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_decode_state_t *state = (lz_decode_state_t *)ctx->module_data[LZ_MOD_DECODE];
    if (!state) {
        if (lz_decode_init(ctx) != LZ_OK) return LZ_ERR;
    }

    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_DECODE, "Decoder running");
    return LZ_OK;
}

void lz_decode_free(lz_context_t *ctx) {
    if (!ctx) return;
    lz_decode_state_t *state = (lz_decode_state_t *)ctx->module_data[LZ_MOD_DECODE];
    if (state) {
        lz_log(ctx, LZ_LOG_INFO, LZ_MOD_DECODE, "Decoder stats: %u packets, %u branches", 
               state->packet_count, state->branch_count);
        free(state);
        ctx->module_data[LZ_MOD_DECODE] = NULL;
    }
}