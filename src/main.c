#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/utsname.h>
#include <generated/utsrelease.h>
#include "../include/mmap_shield.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Thomas Serna & SO2026B Team");
MODULE_DESCRIPTION("mmap-shield: LKM Security Monitor and Interceptor for mmap/file_mmap");
MODULE_VERSION(MMAP_SHIELD_VERSION);

/* Module parameters for initial configuration */
static int enforce_mode = 1;
module_param(enforce_mode, int, 0644);
MODULE_PARM_DESC(enforce_mode, "Enforcement mode: 1 = ENFORCING, 0 = PERMISSIVE (default: 1)");

static bool block_wx = true;
module_param(block_wx, bool, 0644);
MODULE_PARM_DESC(block_wx, "Block W^X violations (PROT_WRITE | PROT_EXEC) (default: true)");

static bool block_dirty_cow = true;
module_param(block_dirty_cow, bool, 0644);
MODULE_PARM_DESC(block_dirty_cow, "Mitigate Dirty COW attack patterns (default: true)");

static bool block_sensitive = true;
module_param(block_sensitive, bool, 0644);
MODULE_PARM_DESC(block_sensitive, "Protect designated sensitive system files (default: true)");

static bool audit_all = false;
module_param(audit_all, bool, 0644);
MODULE_PARM_DESC(audit_all, "Audit all mmap calls, including benign (default: false)");

/* Global state definitions */
struct shield_config g_shield_config;
struct shield_stats  g_shield_stats;

/* Circular audit buffer */
static struct shield_audit_event g_audit_ring[MMAP_SHIELD_AUDIT_SIZE];
static size_t g_audit_head = 0;
static size_t g_audit_count = 0;
static DEFINE_SPINLOCK(g_audit_lock);

void shield_audit_init(void)
{
    unsigned long flags;
    spin_lock_irqsave(&g_audit_lock, flags);
    g_audit_head = 0;
    g_audit_count = 0;
    memset(g_audit_ring, 0, sizeof(g_audit_ring));
    spin_unlock_irqrestore(&g_audit_lock, flags);
}

void shield_audit_log(pid_t pid, pid_t tgid, kuid_t uid, const char *comm,
                      const char *path, unsigned long prot, unsigned long flags_val,
                      shield_action_t action, int enforced)
{
    unsigned long irq_flags;
    struct shield_audit_event *ev;
    struct timespec64 ts;

    ktime_get_real_ts64(&ts);

    spin_lock_irqsave(&g_audit_lock, irq_flags);

    ev = &g_audit_ring[g_audit_head];
    ev->timestamp_sec = (u64)ts.tv_sec;
    ev->pid = pid;
    ev->tgid = tgid;
    ev->uid = uid;
    ev->prot = prot;
    ev->flags = flags_val;
    ev->action = action;
    ev->enforced = enforced;

    if (comm) {
        strscpy(ev->comm, comm, sizeof(ev->comm));
    } else {
        ev->comm[0] = '\0';
    }

    if (path) {
        strscpy(ev->path, path, sizeof(ev->path));
    } else {
        ev->path[0] = '\0';
    }

    g_audit_head = (g_audit_head + 1) % MMAP_SHIELD_AUDIT_SIZE;
    if (g_audit_count < MMAP_SHIELD_AUDIT_SIZE)
        g_audit_count++;

    spin_unlock_irqrestore(&g_audit_lock, irq_flags);
}

size_t shield_audit_copy_entries(struct shield_audit_event *dest, size_t max_count)
{
    unsigned long irq_flags;
    size_t i, copied = 0;
    size_t start_idx;

    if (!dest || max_count == 0)
        return 0;

    spin_lock_irqsave(&g_audit_lock, irq_flags);

    if (g_audit_count == 0) {
        spin_unlock_irqrestore(&g_audit_lock, irq_flags);
        return 0;
    }

    copied = (g_audit_count < max_count) ? g_audit_count : max_count;
    start_idx = (g_audit_head + MMAP_SHIELD_AUDIT_SIZE - g_audit_count) % MMAP_SHIELD_AUDIT_SIZE;

    for (i = 0; i < copied; i++) {
        size_t idx = (start_idx + i) % MMAP_SHIELD_AUDIT_SIZE;
        memcpy(&dest[i], &g_audit_ring[idx], sizeof(struct shield_audit_event));
    }

    spin_unlock_irqrestore(&g_audit_lock, irq_flags);
    return copied;
}

static int __init mmap_shield_init(void)
{
    int ret = 0;

    pr_info("========================================================\n");
    pr_info("[%s] Iniciando modulo de seguridad mmap-shield v%s\n",
            MODULE_NAME, MMAP_SHIELD_VERSION);
    pr_info("[%s] Kernel target: %s\n", MODULE_NAME, UTS_RELEASE);

    /* Initialize config */
    g_shield_config.mode = enforce_mode ? SHIELD_MODE_ENFORCING : SHIELD_MODE_PERMISSIVE;
    g_shield_config.block_wx = block_wx;
    g_shield_config.block_dirty_cow = block_dirty_cow;
    g_shield_config.block_sensitive = block_sensitive;
    g_shield_config.audit_all = audit_all;

    /* Initialize atomic stats */
    atomic64_set(&g_shield_stats.total_intercepted, 0);
    atomic64_set(&g_shield_stats.total_allowed, 0);
    atomic64_set(&g_shield_stats.total_blocked, 0);
    atomic64_set(&g_shield_stats.wx_violations, 0);
    atomic64_set(&g_shield_stats.sensitive_violations, 0);
    atomic64_set(&g_shield_stats.dirty_cow_detections, 0);
    atomic64_set(&g_shield_stats.shared_write_violations, 0);

    /* Initialize audit ring */
    shield_audit_init();

    /* Initialize policy engine */
    ret = shield_policy_init();
    if (ret) {
        pr_err("[%s] Error inicializando motor de politicas (err=%d)\n", MODULE_NAME, ret);
        return ret;
    }

    /* Initialize /proc interface */
    ret = shield_proc_init();
    if (ret) {
        pr_err("[%s] Error inicializando interfaz /proc (err=%d)\n", MODULE_NAME, ret);
        shield_policy_cleanup();
        return ret;
    }

    /* Initialize hook engine */
    ret = shield_hook_init();
    if (ret) {
        pr_err("[%s] Error inicializando motor de hooks (err=%d)\n", MODULE_NAME, ret);
        shield_proc_cleanup();
        shield_policy_cleanup();
        return ret;
    }

    pr_info("[%s] Modulo cargado con exito. Modo: %s | W^X: %s | DirtyCOW: %s\n",
            MODULE_NAME,
            g_shield_config.mode == SHIELD_MODE_ENFORCING ? "ENFORCING" : "PERMISSIVE",
            g_shield_config.block_wx ? "ACTIVO" : "INACTIVO",
            g_shield_config.block_dirty_cow ? "ACTIVO" : "INACTIVO");
    pr_info("========================================================\n");

    return 0;
}

static void __exit mmap_shield_exit(void)
{
    pr_info("[%s] Descargando modulo mmap-shield...\n", MODULE_NAME);

    /* Safely unregister hooks first */
    shield_hook_cleanup();

    /* Remove /proc interface */
    shield_proc_cleanup();

    /* Free policy resources */
    shield_policy_cleanup();

    pr_info("[%s] Modulo descargado correctamente. Total interceptados: %lld, Bloqueados: %lld\n",
            MODULE_NAME,
            atomic64_read(&g_shield_stats.total_intercepted),
            atomic64_read(&g_shield_stats.total_blocked));
}

module_init(mmap_shield_init);
module_exit(mmap_shield_exit);
