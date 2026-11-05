#ifndef MMAP_SHIELD_H
#define MMAP_SHIELD_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/timekeeping.h>

#define MODULE_NAME "mmap_shield"
#define MMAP_SHIELD_VERSION "1.0.0"

/* Maximum length for tracked file paths and process names */
#define MMAP_SHIELD_PATH_MAX   256
#define MMAP_SHIELD_COMM_MAX   16
#define MMAP_SHIELD_AUDIT_SIZE 64

/* Verdict codes for policy decisions */
typedef enum {
    SHIELD_ACTION_ALLOW = 0,
    SHIELD_BLOCK_WX,             /* W^X violation (PROT_WRITE + PROT_EXEC) */
    SHIELD_BLOCK_SENSITIVE_FILE, /* Unauthorized write to protected/sensitive file */
    SHIELD_BLOCK_DIRTY_COW,      /* Dirty COW pattern: RO file mapped MAP_PRIVATE | PROT_WRITE */
    SHIELD_BLOCK_SHARED_WRITE,   /* Unauthorized MAP_SHARED with PROT_WRITE */
} shield_action_t;

/* Policy enforcement mode */
typedef enum {
    SHIELD_MODE_PERMISSIVE = 0,  /* Log violations but allow execution */
    SHIELD_MODE_ENFORCING  = 1   /* Actively block violations returning error codes */
} shield_mode_t;

/* Interception point that produced an event */
typedef enum {
    SHIELD_ORIGIN_MMAP = 0,      /* security_mmap_file: new mapping */
    SHIELD_ORIGIN_MPROTECT,      /* security_file_mprotect: permission change on an existing VMA */
} shield_origin_t;

/* Audit log event recorded in the circular ring buffer */
struct shield_audit_event {
    u64 timestamp_sec;
    pid_t pid;
    pid_t tgid;
    kuid_t uid;
    char comm[MMAP_SHIELD_COMM_MAX];
    char path[MMAP_SHIELD_PATH_MAX];
    unsigned long prot;
    unsigned long flags;
    shield_action_t action;
    shield_origin_t origin;
    int enforced;                /* 1 if blocked, 0 if permissive warning */
};

/* Global telemetry counters (thread-safe atomic counters) */
struct shield_stats {
    atomic64_t total_intercepted;
    atomic64_t mprotect_intercepted;
    atomic64_t total_allowed;
    atomic64_t total_blocked;
    atomic64_t wx_violations;
    atomic64_t sensitive_violations;
    atomic64_t dirty_cow_detections;
    atomic64_t shared_write_violations;
};

/* Global policy configuration */
struct shield_config {
    shield_mode_t mode;          /* Enforcing vs Permissive */
    bool block_wx;               /* Enforce W^X prevention */
    bool block_dirty_cow;        /* Enforce Dirty COW pattern mitigation */
    bool block_sensitive;        /* Protect designated system files */
    bool audit_all;              /* Audit every mmap event (including benign) */
};

/* Global state exported to submodules */
extern struct shield_config g_shield_config;
extern struct shield_stats  g_shield_stats;

/* Audit ring buffer functions */
void shield_audit_init(void);
void shield_audit_log(pid_t pid, pid_t tgid, kuid_t uid, const char *comm,
                      const char *path, unsigned long prot, unsigned long flags,
                      shield_action_t action, shield_origin_t origin, int enforced);
size_t shield_audit_copy_entries(struct shield_audit_event *dest, size_t max_count);

/* Forward declarations for submodule initializers/cleanups */
int  shield_policy_init(void);
void shield_policy_cleanup(void);

int  shield_hook_init(void);
void shield_hook_cleanup(void);

int  shield_proc_init(void);
void shield_proc_cleanup(void);

#endif /* MMAP_SHIELD_H */
