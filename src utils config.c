#include "../../include/lz.h"
#include <ctype.h>

static int parse_bool(const char *val) {
    if (!val) return 0;
    if (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0 || 
        strcasecmp(val, "yes") == 0 || strcasecmp(val, "on") == 0) {
        return 1;
    }
    return 0;
}

static void trim_str(char *str) {
    if (!str) return;
    char *p = str;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != str) memmove(str, p, strlen(p) + 1);
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }
}

int lz_load_config(lz_context_t *ctx, const char *path) {
    if (!ctx || !path) return LZ_ERR;

    FILE *f = fopen(path, "r");
    if (!f) return LZ_ERR_IO;

    char line[LZ_PATH_MAX * 2];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        trim_str(p);
        
        if (*p == '#' || *p == '\0') continue;

        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        
        char *key = p;
        char *val = eq + 1;
        
        trim_str(key);
        trim_str(val);

        if (strcmp(key, "output_dir") == 0)
            snprintf(ctx->config.output_dir, sizeof(ctx->config.output_dir), "%s", val);
        else if (strcmp(key, "trace_path") == 0)
            snprintf(ctx->config.trace_path, sizeof(ctx->config.trace_path), "%s", val);
        else if (strcmp(key, "log_path") == 0)
            snprintf(ctx->config.log_path, sizeof(ctx->config.log_path), "%s", val);
        else if (strcmp(key, "shm_name") == 0)
            snprintf(ctx->config.shm_name, sizeof(ctx->config.shm_name), "%s", val);
        else if (strcmp(key, "replay_input") == 0)
            snprintf(ctx->config.replay_input, sizeof(ctx->config.replay_input), "%s", val);
        
        else if (strcmp(key, "verbose") == 0)
            ctx->config.verbose = parse_bool(val);
        else if (strcmp(key, "daemon") == 0)
            ctx->config.daemon = parse_bool(val);
        else if (strcmp(key, "no_color") == 0)
            ctx->config.no_color = parse_bool(val);
        
        else if (strcmp(key, "isolation") == 0)
            ctx->config.isolation = parse_bool(val);
        else if (strcmp(key, "ringbuf") == 0)
            ctx->config.ringbuf = parse_bool(val);
        else if (strcmp(key, "replay") == 0)
            ctx->config.replay = parse_bool(val);
        else if (strcmp(key, "pt") == 0)
            ctx->config.pt = parse_bool(val);
        else if (strcmp(key, "pmc") == 0)
            ctx->config.pmc = parse_bool(val);
        else if (strcmp(key, "msr") == 0)
            ctx->config.msr = parse_bool(val);
        else if (strcmp(key, "ebpf") == 0)
            ctx->config.ebpf = parse_bool(val);

        else if (strcmp(key, "ring_size") == 0)
            ctx->config.ring_size = (uint32_t)strtoul(val, NULL, 10);
        else if (strcmp(key, "sample_hz") == 0)
            ctx->config.sample_hz = (uint32_t)strtoul(val, NULL, 10);
        else if (strcmp(key, "capture_secs") == 0)
            ctx->config.capture_secs = (uint32_t)strtoul(val, NULL, 10);
        
        else if (strncmp(key, "msr_", 4) == 0 && ctx->config.msr_count < LZ_MAX_MSRS) {
            ctx->config.msr_list[ctx->config.msr_count++] = (uint32_t)strtoul(val, NULL, 0);
        }
        else if (strncmp(key, "pmc_", 4) == 0 && ctx->config.pmc_count < LZ_MAX_PMCS) {
            ctx->config.pmc_list[ctx->config.pmc_count++] = (uint32_t)strtoul(val, NULL, 0);
        }
        else if (strncmp(key, "core_", 5) == 0 && ctx->config.core_count < LZ_MAX_CORES) {
            ctx->config.cores[ctx->config.core_count++] = (uint32_t)strtoul(val, NULL, 10);
        }
    }
    
    fclose(f);
    return LZ_OK;
}

int lz_save_config(lz_context_t *ctx, const char *path) {
    if (!ctx || !path) return LZ_ERR;

    FILE *f = fopen(path, "w");
    if (!f) return LZ_ERR_IO;

    fprintf(f, "verbose=%d\n", ctx->config.verbose);
    fprintf(f, "daemon=%d\n", ctx->config.daemon);
    fprintf(f, "no_color=%d\n", ctx->config.no_color);

    fprintf(f, "isolation=%d\n", ctx->config.isolation);
    fprintf(f, "ringbuf=%d\n", ctx->config.ringbuf);
    fprintf(f, "replay=%d\n", ctx->config.replay);
    fprintf(f, "pt=%d\n", ctx->config.pt);
    fprintf(f, "pmc=%d\n", ctx->config.pmc);
    fprintf(f, "msr=%d\n", ctx->config.msr);
    fprintf(f, "ebpf=%d\n", ctx->config.ebpf);

    fprintf(f, "output_dir=%s\n", ctx->config.output_dir);
    fprintf(f, "trace_path=%s\n", ctx->config.trace_path);
    fprintf(f, "log_path=%s\n", ctx->config.log_path);
    fprintf(f, "shm_name=%s\n", ctx->config.shm_name);
    fprintf(f, "replay_input=%s\n", ctx->config.replay_input);

    fprintf(f, "ring_size=%u\n", ctx->config.ring_size);
    fprintf(f, "sample_hz=%u\n", ctx->config.sample_hz);
    fprintf(f, "capture_secs=%u\n", ctx->config.capture_secs);

    for (uint32_t i = 0; i < ctx->config.msr_count; i++) {
        fprintf(f, "msr_%u=0x%x\n", i, ctx->config.msr_list[i]);
    }
    for (uint32_t i = 0; i < ctx->config.pmc_count; i++) {
        fprintf(f, "pmc_%u=0x%x\n", i, ctx->config.pmc_list[i]);
    }
    for (uint32_t i = 0; i < ctx->config.core_count; i++) {
        fprintf(f, "core_%u=%u\n", i, ctx->config.cores[i]);
    }

    fclose(f);
    return LZ_OK;
}

int lz_file_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int lz_dir_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int lz_mkdir_p(const char *path) {
    if (!path || !*path) return LZ_ERR;
    char tmp[LZ_PATH_MAX * 2];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return LZ_ERR;
    memcpy(tmp, path, len + 1);
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) < 0 && errno != EEXIST) return LZ_ERR;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) < 0 && errno != EEXIST) return LZ_ERR;
    return LZ_OK;
}

ssize_t lz_read_file(const char *path, void *buf, size_t size) {
    if (!path || !buf || size == 0) return LZ_ERR;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return LZ_ERR_IO;
    size_t total = 0;
    while (total < size) {
        ssize_t n = read(fd, (uint8_t *)buf + total, size - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return LZ_ERR_IO;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    close(fd);
    return (ssize_t)total;
}

ssize_t lz_write_file(const char *path, const void *buf, size_t size) {
    if (!path || !buf) return LZ_ERR;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return LZ_ERR_IO;
    size_t total = 0;
    while (total < size) {
        ssize_t n = write(fd, (const uint8_t *)buf + total, size - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return LZ_ERR_IO;
        }
        total += (size_t)n;
    }
    close(fd);
    return (ssize_t)total;
}