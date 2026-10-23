#include "../../include/lz.h"

typedef struct {
    FILE *fp;
    uint64_t total_events;
    uint64_t replayed_events;
    uint64_t start_ns;
    uint64_t end_ns;
} lz_replay_state_t;

int lz_replay_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;

    lz_replay_state_t *state = calloc(1, sizeof(lz_replay_state_t));
    if (!state) return LZ_ERR_MEM;

    state->fp = NULL;
    state->total_events = 0;
    state->replayed_events = 0;

    ctx->module_data[LZ_MOD_REPLAY] = state;
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_REPLAY, "Replay module initialized");
    return LZ_OK;
}

int lz_replay_load(lz_context_t *ctx, const char *path) {
    if (!ctx || !path) return LZ_ERR;
    lz_replay_state_t *state = (lz_replay_state_t *)ctx->module_data[LZ_MOD_REPLAY];
    if (!state) return LZ_ERR;

    if (state->fp) {
        fclose(state->fp);
        state->fp = NULL;
    }

    state->fp = fopen(path, "rb");
    if (!state->fp) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_REPLAY, "cannot open replay file %s: %s", path, strerror(errno));
        return LZ_ERR_IO;
    }

    lz_trace_hdr_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, state->fp) != 1) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_REPLAY, "cannot read trace header");
        fclose(state->fp);
        state->fp = NULL;
        return LZ_ERR_REPLAY;
    }

    if (hdr.flags != LZ_MAGIC) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_REPLAY, "invalid trace magic (0x%x)", hdr.flags);
        fclose(state->fp);
        state->fp = NULL;
        return LZ_ERR_REPLAY;
    }

    state->total_events = hdr.events;
    state->start_ns = hdr.start_ns;
    state->end_ns = hdr.end_ns;

    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_REPLAY, "loaded trace: %llu events, hash 0x%x", 
           (unsigned long long)hdr.events, hdr.hash);
    return LZ_OK;
}

int lz_replay_step(lz_context_t *ctx, lz_event_t *ev) {
    if (!ctx || !ev) return LZ_ERR;
    lz_replay_state_t *state = (lz_replay_state_t *)ctx->module_data[LZ_MOD_REPLAY];
    if (!state || !state->fp) return LZ_ERR_REPLAY;

    size_t n = fread(ev, sizeof(lz_event_t), 1, state->fp);
    if (n != 1) {
        if (feof(state->fp)) return 1;
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_REPLAY, "read trace event failed");
        return LZ_ERR_REPLAY;
    }

    state->replayed_events++;

    if (ctx->shm && ctx->shm->ring) {
        lz_ring_push(ctx, ev);
    }

    return LZ_OK;
}

int lz_replay_verify(lz_context_t *ctx, uint32_t expected_hash) {
    if (!ctx) return LZ_ERR;
    lz_replay_state_t *state = (lz_replay_state_t *)ctx->module_data[LZ_MOD_REPLAY];
    if (!state) return LZ_ERR_REPLAY;

    uint32_t running_hash = 0;
    uint32_t count = 0;

    if (state->fp) {
        fseek(state->fp, sizeof(lz_trace_hdr_t), SEEK_SET);
        lz_event_t ev;
        while (fread(&ev, sizeof(lz_event_t), 1, state->fp) == 1) {
            running_hash ^= lz_crc32(&ev, sizeof(lz_event_t));
            running_hash = (running_hash << 5) | (running_hash >> 27);
            count++;
        }
        fseek(state->fp, 0, SEEK_END);
    }

    if (running_hash != expected_hash) {
        lz_log(ctx, LZ_LOG_ERROR, LZ_MOD_REPLAY, "hash mismatch: got 0x%x, expected 0x%x", running_hash, expected_hash);
        return LZ_ERR_REPLAY;
    }

    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_REPLAY, "replay verified: %u events, hash 0x%x", count, running_hash);
    return LZ_OK;
}

int lz_replay_run(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_replay_state_t *state = (lz_replay_state_t *)ctx->module_data[LZ_MOD_REPLAY];
    if (!state) {
        if (lz_replay_init(ctx) != LZ_OK) return LZ_ERR;
        state = (lz_replay_state_t *)ctx->module_data[LZ_MOD_REPLAY];
    }

    if (!state->fp) {
        if (ctx->config.replay_input[0]) {
            if (lz_replay_load(ctx, ctx->config.replay_input) != LZ_OK) {
                return LZ_ERR_REPLAY;
            }
        } else {
            lz_log(ctx, LZ_LOG_WARN, LZ_MOD_REPLAY, "no replay input file specified");
            return LZ_ERR_REPLAY;
        }
    }

    lz_event_t ev;
    int ret;
    uint64_t replayed = 0;

    while ((ret = lz_replay_step(ctx, &ev)) == LZ_OK) {
        replayed++;
    }

    if (ret == 1) {
        lz_log(ctx, LZ_LOG_INFO, LZ_MOD_REPLAY, "replay completed: %llu events", (unsigned long long)replayed);
        return LZ_OK;
    }

    return LZ_ERR_REPLAY;
}

int lz_replay_stop(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    lz_replay_state_t *state = (lz_replay_state_t *)ctx->module_data[LZ_MOD_REPLAY];
    if (!state) return LZ_OK;

    if (state->fp) {
        fclose(state->fp);
        state->fp = NULL;
    }
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_REPLAY, "replay stopped");
    return LZ_OK;
}

void lz_replay_free(lz_context_t *ctx) {
    if (!ctx) return;
    lz_replay_stop(ctx);
    lz_replay_state_t *state = (lz_replay_state_t *)ctx->module_data[LZ_MOD_REPLAY];
    if (state) {
        free(state);
        ctx->module_data[LZ_MOD_REPLAY] = NULL;
    }
}

uint32_t lz_crc32(const void *data, size_t len) {
    if (!data) return 0;
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc & 1) ? (0xEDB88320u ^ (crc >> 1)) : (crc >> 1);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

uint32_t lz_hash_events(const lz_event_t *evs, uint32_t count) {
    if (!evs || count == 0) return 0;
    uint32_t hash = 0;
    for (uint32_t i = 0; i < count; i++) {
        hash ^= lz_crc32(&evs[i], sizeof(lz_event_t));
        hash = (hash << 5) | (hash >> 27);
    }
    return hash;
}