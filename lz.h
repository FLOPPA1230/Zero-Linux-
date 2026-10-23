#ifndef LZ_H
#define LZ_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/perf_event.h>
#include <linux/kvm.h>

enum {
    LZ_MAGIC        = 0x4C5A0001,
    LZ_MAX_CORES    = 8,
    LZ_MAX_MSRS     = 64,
    LZ_MAX_PMCS     = 16,
    LZ_MAX_FINDINGS = 4096,
    LZ_PATH_MAX     = 512,
    LZ_NAME_MAX     = 128,
    LZ_RING_SIZE    = 16 * 1024 * 1024,
    LZ_LOG_SIZE     = 4 * 1024 * 1024,
    LZ_SAMPLE_HZ    = 1000
};

enum {
    LZ_OK = 0,
    LZ_ERR,
    LZ_ERR_PERM,
    LZ_ERR_MEM,
    LZ_ERR_IO,
    LZ_ERR_PERF,
    LZ_ERR_KVM,
    LZ_ERR_BPF,
    LZ_ERR_RING,
    LZ_ERR_REPLAY
};

enum {
    LZ_LOG_DEBUG = 0,
    LZ_LOG_INFO,
    LZ_LOG_WARN,
    LZ_LOG_ERROR,
    LZ_LOG_FATAL
};

enum {
    LZ_STATE_IDLE = 0,
    LZ_STATE_RUNNING,
    LZ_STATE_PAUSED,
    LZ_STATE_STOPPED
};

enum {
    LZ_EV_SYSCALL = 1,
    LZ_EV_MSR,
    LZ_EV_PMC,
    LZ_EV_PT,
    LZ_EV_BRANCH,
    LZ_EV_MARKER = 255
};

typedef enum {
    LZ_MOD_ISO = 0,
    LZ_MOD_RING,
    LZ_MOD_REPLAY,
    LZ_MOD_PT,
    LZ_MOD_PMC,
    LZ_MOD_MSR,
    LZ_MOD_EBPF,
    LZ_MOD_REPORT,
    LZ_MOD_MAX
} lz_module_t;

typedef enum {
    LZ_SEV_NONE = 0,
    LZ_SEV_LOW,
    LZ_SEV_MED,
    LZ_SEV_HIGH,
    LZ_SEV_CRIT
} lz_severity_t;

typedef struct {
    uint64_t ts_ns;
    uint64_t cpu;
    uint64_t tid;
    uint32_t type;
    uint32_t flags;
    uint64_t a0, a1, a2, a3;
    uint8_t  data[32];
} lz_event_t;

typedef struct {
    uint32_t id;
    uint32_t cpu;
    uint64_t msr;
    uint64_t value;
    uint32_t op;
    uint64_t ts_ns;
} lz_msr_event_t;

typedef struct {
    uint32_t id;
    uint32_t cpu;
    uint64_t counter;
    uint64_t value;
    uint32_t pmc_type;
    uint64_t ts_ns;
} lz_pmc_event_t;

typedef struct {
    uint64_t ip;
    uint64_t target;
    uint64_t tid;
    uint32_t taken;
    uint32_t cpu;
    uint64_t ts_ns;
} lz_branch_event_t;

typedef struct {
    uint64_t start_ns;
    uint64_t end_ns;
    uint64_t events;
    uint64_t bytes;
    uint32_t hash;
    uint32_t flags;
} lz_trace_hdr_t;

typedef struct {
    uint32_t id;
    uint32_t module;
    uint32_t severity;
    uint64_t ts_ns;
    char     name[LZ_NAME_MAX];
    char     detail[LZ_PATH_MAX];
} lz_finding_t;

typedef struct {
    uint64_t total_events;
    uint64_t total_dropped;
    uint64_t total_findings;
    uint64_t total_bytes;
    uint64_t start_ns;
    uint64_t end_ns;
    uint32_t active_cores;
    uint32_t msr_count;
    uint32_t pmc_count;
    uint32_t cpu_freq_mhz;
} lz_stats_t;

typedef struct {
    _Atomic uint32_t write_idx;
    _Atomic uint32_t read_idx;
    _Atomic uint32_t dropped;
    uint32_t capacity;
    uint32_t mask;
    uint32_t entry_size;
    uint8_t  data[];
} lz_ring_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t state;
    uint32_t core_count;
    uint64_t core_mask[LZ_MAX_CORES];
    lz_ring_t *ring;
    uint64_t   ring_phys;
    size_t     ring_size;
    lz_stats_t stats;
    lz_finding_t findings[LZ_MAX_FINDINGS];
    _Atomic uint32_t finding_head;
    _Atomic uint32_t finding_tail;
} lz_shm_t;

typedef struct {
    uint32_t level;
    uint32_t module;
    uint64_t ts_ns;
    uint32_t pid;
    uint32_t tid;
    char     message[512];
} lz_log_entry_t;

typedef struct {
    uint32_t magic;
    _Atomic uint32_t write_idx;
    _Atomic uint32_t read_idx;
    uint32_t capacity;
    lz_log_entry_t entries[4096];
} lz_log_t;

typedef struct {
    int      isolation;
    int      ringbuf;
    int      replay;
    int      pt;
    int      pmc;
    int      msr;
    int      ebpf;
    int      verbose;
    int      daemon;
    int      no_color;
    uint32_t cores[LZ_MAX_CORES];
    uint32_t core_count;
    uint32_t ring_size;
    uint32_t sample_hz;
    uint32_t capture_secs;
    uint32_t msr_list[LZ_MAX_MSRS];
    uint32_t msr_count;
    uint32_t pmc_list[LZ_MAX_PMCS];
    uint32_t pmc_count;
    char     output_dir[LZ_PATH_MAX];
    char     trace_path[LZ_PATH_MAX];
    char     log_path[LZ_PATH_MAX];
    char     shm_name[LZ_NAME_MAX];
    char     replay_input[LZ_PATH_MAX];
} lz_config_t;

typedef struct lz_context {
    lz_config_t config;
    lz_shm_t   *shm;
    lz_log_t   *log;
    int         shm_fd;
    int         log_fd;
    uint32_t    state;
    uint32_t    magic;
    void       *module_data[LZ_MOD_MAX];
    int       (*module_init[LZ_MOD_MAX])(struct lz_context *);
    int       (*module_run[LZ_MOD_MAX])(struct lz_context *);
    int       (*module_stop[LZ_MOD_MAX])(struct lz_context *);
    void      (*module_free[LZ_MOD_MAX])(struct lz_context *);
} lz_context_t;

int  lz_init(lz_context_t *ctx);
int  lz_run(lz_context_t *ctx);
int  lz_stop(lz_context_t *ctx);
void lz_free(lz_context_t *ctx);
int  lz_parse_args(lz_context_t *ctx, int argc, char **argv);
int  lz_load_config(lz_context_t *ctx, const char *path);
int  lz_save_config(lz_context_t *ctx, const char *path);

int  lz_log_init(lz_context_t *ctx);
void lz_log_free(lz_context_t *ctx);
void lz_log(lz_context_t *ctx, uint32_t level, uint32_t module, const char *fmt, ...);
int  lz_log_flush(lz_context_t *ctx);
const char *lz_log_level_str(uint32_t level);

int  lz_shm_init(lz_context_t *ctx);
void lz_shm_free(lz_context_t *ctx);
int  lz_shm_push_finding(lz_context_t *ctx, const lz_finding_t *f);
int  lz_shm_pop_finding(lz_context_t *ctx, lz_finding_t *f);
int  lz_shm_update_stats(lz_context_t *ctx);

int  lz_ring_init(lz_context_t *ctx, size_t size);
void lz_ring_free(lz_context_t *ctx);
int  lz_ring_push(lz_context_t *ctx, const lz_event_t *ev);
int  lz_ring_pop(lz_context_t *ctx, lz_event_t *ev);
uint64_t lz_ring_count(lz_context_t *ctx);
uint64_t lz_ring_dropped(lz_context_t *ctx);

int  lz_iso_init(lz_context_t *ctx);
int  lz_iso_run(lz_context_t *ctx);
int  lz_iso_stop(lz_context_t *ctx);
void lz_iso_free(lz_context_t *ctx);
int  lz_iso_pin_core(lz_context_t *ctx, uint32_t cpu);
int  lz_iso_set_affinity(lz_context_t *ctx, pid_t tid, uint32_t cpu);

int  lz_pt_init(lz_context_t *ctx);
int  lz_pt_run(lz_context_t *ctx);
int  lz_pt_stop(lz_context_t *ctx);
void lz_pt_free(lz_context_t *ctx);
int  lz_pt_open(lz_context_t *ctx, pid_t pid, uint32_t cpu);
int  lz_pt_read(lz_context_t *ctx, uint8_t *buf, size_t size);
int  lz_pt_decode(lz_context_t *ctx, const uint8_t *buf, size_t size);

int  lz_pmc_init(lz_context_t *ctx);
int  lz_pmc_run(lz_context_t *ctx);
int  lz_pmc_stop(lz_context_t *ctx);
void lz_pmc_free(lz_context_t *ctx);
int  lz_pmc_open(lz_context_t *ctx, uint32_t type, uint64_t config, pid_t pid, uint32_t cpu);
uint64_t lz_pmc_read(lz_context_t *ctx, int fd);
int  lz_pmc_close(lz_context_t *ctx, int fd);

int  lz_msr_init(lz_context_t *ctx);
int  lz_msr_run(lz_context_t *ctx);
int  lz_msr_stop(lz_context_t *ctx);
void lz_msr_free(lz_context_t *ctx);
int  lz_msr_filter_add(lz_context_t *ctx, uint32_t msr, uint32_t flags);
int  lz_msr_filter_apply(lz_context_t *ctx);
int  lz_msr_handle_exit(lz_context_t *ctx, struct kvm_run *run);

int  lz_ebpf_init(lz_context_t *ctx);
int  lz_ebpf_run(lz_context_t *ctx);
int  lz_ebpf_stop(lz_context_t *ctx);
void lz_ebpf_free(lz_context_t *ctx);
int  lz_ebpf_attach_syscall(lz_context_t *ctx, const char *prog);
int  lz_ebpf_poll(lz_context_t *ctx, lz_event_t *ev, uint32_t timeout_ms);

int  lz_replay_init(lz_context_t *ctx);
int  lz_replay_run(lz_context_t *ctx);
int  lz_replay_stop(lz_context_t *ctx);
void lz_replay_free(lz_context_t *ctx);
int  lz_replay_load(lz_context_t *ctx, const char *path);
int  lz_replay_step(lz_context_t *ctx, lz_event_t *ev);
int  lz_replay_verify(lz_context_t *ctx, uint32_t expected_hash);

int  lz_decode_init(lz_context_t *ctx);
int  lz_decode_run(lz_context_t *ctx);
void lz_decode_free(lz_context_t *ctx);
int  lz_decode_pt_packet(lz_context_t *ctx, const uint8_t *buf, size_t size, lz_event_t *out);
int  lz_decode_branch(lz_context_t *ctx, uint64_t from, uint64_t to, lz_branch_event_t *out);

int  lz_report_init(lz_context_t *ctx);
int  lz_report_run(lz_context_t *ctx);
int  lz_report_stop(lz_context_t *ctx);
void lz_report_free(lz_context_t *ctx);
int  lz_report_json(lz_context_t *ctx, const char *path);
int  lz_report_html(lz_context_t *ctx, const char *path);
int  lz_report_console(lz_context_t *ctx);

uint64_t lz_time_ns(void);
uint64_t lz_time_ms(void);
uint32_t lz_crc32(const void *data, size_t len);
uint32_t lz_hash_events(const lz_event_t *evs, uint32_t count);
int      lz_file_exists(const char *path);
int      lz_dir_exists(const char *path);
int      lz_mkdir_p(const char *path);
ssize_t  lz_read_file(const char *path, void *buf, size_t size);
ssize_t  lz_write_file(const char *path, const void *buf, size_t size);
int      lz_perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags);

extern lz_context_t *g_lz;

#endif