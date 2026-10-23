#include "../include/lz.h"
#include <getopt.h>

static void lz_print_banner(void) {
    fprintf(stderr,
        "\033[31m"
        "    __    _                  _____                 \n"
        "   / /   (_)___  __  ___  __/__  /__  ____  ____  \n"
        "  / /   / / __ \\/ / / / |/_/ / / _ \\/ __ \\/ __ \\ \n"
        " / /___/ / / / / /_/ />  </ /_/  __/ /_/ / / / / \n"
        "/_____/_/_/ /_/\\__,_/_/|_/____/\\___/\\____/_/ /_/  \n"
        "\033[0m"
        "       linux Project");
}

static void lz_print_usage(const char *prog) {
    fprintf(stderr,
        "usage: %s [options]\n"
        "  -h, --help              show this help\n"
        "  -v, --verbose           verbose logging\n"
        "  -c, --config FILE       load config file\n"
        "  -o, --output DIR        output directory (default ./lz_report)\n"
        "  -l, --log FILE          log file path\n"
        "  -n, --no-color          disable colored output\n"
        "  -d, --daemon            run in background\n"
        "      --iso               enable core isolation\n"
        "      --ring              enable ring buffer\n"
        "      --pt                enable Intel PT tracing\n"
        "      --pmc               enable PMCs\n"
        "      --msr               enable MSR interception\n"
        "      --ebpf              enable eBPF syscall monitor\n"
        "      --replay            enable deterministic replay\n"
        "      --all               enable all modules\n"
        "      --shm NAME          shared memory name (default lz_shm)\n",
        prog);
}

static int lz_daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) return LZ_ERR;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return LZ_ERR;
    pid = fork();
    if (pid < 0) return LZ_ERR;
    if (pid > 0) _exit(0);
    umask(077);
    if (chdir("/") < 0) return LZ_ERR;
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
    return LZ_OK;
}

int lz_parse_args(lz_context_t *ctx, int argc, char **argv) {
    if (!ctx) return LZ_ERR;
    static struct option long_opts[] = {
        {"help",      no_argument,       0, 'h'},
        {"verbose",   no_argument,       0, 'v'},
        {"config",    required_argument, 0, 'c'},
        {"output",    required_argument, 0, 'o'},
        {"log",       required_argument, 0, 'l'},
        {"no-color",  no_argument,       0, 'n'},
        {"daemon",    no_argument,       0, 'd'},
        {"iso",       no_argument,       0, 1000},
        {"ring",      no_argument,       0, 1001},
        {"pt",        no_argument,       0, 1002},
        {"pmc",       no_argument,       0, 1003},
        {"msr",       no_argument,       0, 1004},
        {"ebpf",      no_argument,       0, 1005},
        {"replay",    no_argument,       0, 1006},
        {"all",       no_argument,       0, 1007},
        {"shm",       required_argument, 0, 1008},
        {0, 0, 0, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "hvc:o:l:nd", long_opts, NULL)) != -1) {
        switch (c) {
            case 'h': lz_print_usage(argv[0]); exit(0);
            case 'v': ctx->config.verbose = 1; break;
            case 'c': lz_load_config(ctx, optarg); break;
            case 'o': snprintf(ctx->config.output_dir, sizeof(ctx->config.output_dir), "%s", optarg); break;
            case 'l': snprintf(ctx->config.log_path, sizeof(ctx->config.log_path), "%s", optarg); break;
            case 'n': ctx->config.no_color = 1; break;
            case 'd': ctx->config.daemon = 1; break;
            case 1000: ctx->config.isolation = 1; break;
            case 1001: ctx->config.ringbuf = 1; break;
            case 1002: ctx->config.pt = 1; break;
            case 1003: ctx->config.pmc = 1; break;
            case 1004: ctx->config.msr = 1; break;
            case 1005: ctx->config.ebpf = 1; break;
            case 1006: ctx->config.replay = 1; break;
            case 1007:
                ctx->config.isolation = 1;
                ctx->config.ringbuf = 1;
                ctx->config.pt = 1;
                ctx->config.pmc = 1;
                ctx->config.msr = 1;
                ctx->config.ebpf = 1;
                ctx->config.replay = 1;
                break;
            case 1008: snprintf(ctx->config.shm_name, sizeof(ctx->config.shm_name), "%s", optarg); break;
            default: lz_print_usage(argv[0]); return LZ_ERR;
        }
    }
    return LZ_OK;
}

int lz_shm_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    char path[LZ_PATH_MAX];
    snprintf(path, sizeof(path), "/dev/shm/%s", ctx->config.shm_name[0] ? ctx->config.shm_name : "lz_shm");
    
    ctx->shm_fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (ctx->shm_fd < 0) return LZ_ERR_IO;
    if (fchmod(ctx->shm_fd, 0600) < 0) { close(ctx->shm_fd); return LZ_ERR_PERM; }
    if (ftruncate(ctx->shm_fd, sizeof(lz_shm_t)) < 0) { close(ctx->shm_fd); return LZ_ERR_IO; }
    
    void *mem = mmap(NULL, sizeof(lz_shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, ctx->shm_fd, 0);
    if (mem == MAP_FAILED) { close(ctx->shm_fd); return LZ_ERR_MEM; }
    
    ctx->shm = (lz_shm_t *)mem;
    memset(ctx->shm, 0, sizeof(lz_shm_t));
    ctx->shm->magic = LZ_MAGIC;
    ctx->shm->version = 1;
    ctx->shm->state = LZ_STATE_IDLE;
    return LZ_OK;
}

void lz_shm_free(lz_context_t *ctx) {
    if (!ctx) return;
    if (ctx->shm) { munmap(ctx->shm, sizeof(lz_shm_t)); ctx->shm = NULL; }
    if (ctx->shm_fd >= 0) { close(ctx->shm_fd); ctx->shm_fd = -1; }
}

static void lz_register_modules(lz_context_t *ctx) {
    ctx->module_init[LZ_MOD_RING] = lz_ring_init;
    ctx->module_run[LZ_MOD_RING] = lz_ring_push;
    ctx->module_stop[LZ_MOD_RING] = lz_ring_pop;
    ctx->module_free[LZ_MOD_RING] = lz_ring_free;
    
    ctx->module_init[LZ_MOD_PT] = lz_pt_init;
    ctx->module_run[LZ_MOD_PT] = lz_pt_run;
    ctx->module_stop[LZ_MOD_PT] = lz_pt_stop;
    ctx->module_free[LZ_MOD_PT] = lz_pt_free;
    
    ctx->module_init[LZ_MOD_PMC] = lz_pmc_init;
    ctx->module_run[LZ_MOD_PMC] = lz_pmc_run;
    ctx->module_stop[LZ_MOD_PMC] = lz_pmc_stop;
    ctx->module_free[LZ_MOD_PMC] = lz_pmc_free;
    
    ctx->module_init[LZ_MOD_MSR] = lz_msr_init;
    ctx->module_run[LZ_MOD_MSR] = lz_msr_run;
    ctx->module_stop[LZ_MOD_MSR] = lz_msr_stop;
    ctx->module_free[LZ_MOD_MSR] = lz_msr_free;
}

int lz_init(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    if (ctx->magic == LZ_MAGIC) return LZ_OK;
    g_lz = ctx;
    
    if (lz_shm_init(ctx) != LZ_OK) return LZ_ERR;
    if (lz_log_init(ctx) != LZ_OK) { lz_shm_free(ctx); return LZ_ERR; }
    
    lz_register_modules(ctx);
    ctx->state = LZ_STATE_IDLE;
    ctx->magic = LZ_MAGIC;
    lz_log(ctx, LZ_LOG_INFO, LZ_MOD_REPORT, "Linux Zero initialized");
    return LZ_OK;
}

int lz_run(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    ctx->state = LZ_STATE_RUNNING;
    if (ctx->shm) ctx->shm->state = LZ_STATE_RUNNING;
    
    if (ctx->config.ringbuf) ctx->module_run[LZ_MOD_RING](ctx);
    if (ctx->config.pt) ctx->module_run[LZ_MOD_PT](ctx);
    if (ctx->config.pmc) ctx->module_run[LZ_MOD_PMC](ctx);
    if (ctx->config.msr) ctx->module_run[LZ_MOD_MSR](ctx);
    
    ctx->state = LZ_STATE_STOPPED;
    if (ctx->shm) ctx->shm->state = LZ_STATE_STOPPED;
    return LZ_OK;
}

int lz_stop(lz_context_t *ctx) {
    if (!ctx) return LZ_ERR;
    ctx->state = LZ_STATE_STOPPED;
    for (int i = LZ_MOD_MAX - 1; i >= 0; i--) {
        if (ctx->module_stop[i]) ctx->module_stop[i](ctx);
    }
    lz_log_flush(ctx);
    return LZ_OK;
}

void lz_free(lz_context_t *ctx) {
    if (!ctx) return;
    for (int i = LZ_MOD_MAX - 1; i >= 0; i--) {
        if (ctx->module_free[i]) ctx->module_free[i](ctx);
    }
    lz_log_free(ctx);
    lz_shm_free(ctx);
    ctx->magic = 0;
    g_lz = NULL;
}

static void lz_fill_defaults(lz_context_t *ctx) {
    memset(&ctx->config, 0, sizeof(ctx->config));
    snprintf(ctx->config.output_dir, sizeof(ctx->config.output_dir), "./lz_report");
    snprintf(ctx->config.shm_name, sizeof(ctx->config.shm_name), "lz_shm");
    ctx->config.ring_size = LZ_RING_SIZE;
    ctx->config.sample_hz = LZ_SAMPLE_HZ;
    ctx->config.core_count = 0;
}

int main(int argc, char **argv) {
    lz_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    lz_fill_defaults(&ctx);
    lz_print_banner();
    
    if (lz_parse_args(&ctx, argc, argv) != LZ_OK) {
        lz_print_usage(argv[0]);
        return 1;
    }
    
    if (ctx.config.daemon) {
        if (lz_daemonize() != LZ_OK) {
            fprintf(stderr, "daemonize failed: %s\n", strerror(errno));
            return 1;
        }
    }
    
    if (lz_init(&ctx) != LZ_OK) {
        fprintf(stderr, "lz_init failed\n");
        return 1;
    }
    
    lz_log(&ctx, LZ_LOG_INFO, LZ_MOD_REPORT, "modules: iso=%d ring=%d pt=%d pmc=%d msr=%d ebpf=%d",
           ctx.config.isolation, ctx.config.ringbuf, ctx.config.pt,
           ctx.config.pmc, ctx.config.msr, ctx.config.ebpf);
           
    lz_run(&ctx);
    lz_stop(&ctx);
    lz_free(&ctx);
    
    fprintf(stderr, "\033[35m[Linux Zero] shutdown complete.\033[0m\n");
    return 0;
}