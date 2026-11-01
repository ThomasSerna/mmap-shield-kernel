#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include "../include/mmap_shield.h"
#include "../include/policy.h"

static struct protected_path g_protected_paths[MAX_PROTECTED_PATHS];
static DEFINE_SPINLOCK(g_paths_lock);

/* Default sensitive paths protected by the module */
static const char * const g_default_paths[] = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ld.so.preload",
    "/tmp/shield_protected.txt" /* Honeypot test target */
};

int shield_policy_init(void)
{
    unsigned long flags;
    size_t i;

    spin_lock_irqsave(&g_paths_lock, flags);
    memset(g_protected_paths, 0, sizeof(g_protected_paths));

    for (i = 0; i < ARRAY_SIZE(g_default_paths) && i < MAX_PROTECTED_PATHS; i++) {
        strscpy(g_protected_paths[i].path, g_default_paths[i], MMAP_SHIELD_PATH_MAX);
        g_protected_paths[i].active = true;
    }
    spin_unlock_irqrestore(&g_paths_lock, flags);

    pr_info("[%s] Motor de politicas inicializado con %zu rutas protegidas por defecto\n",
            MODULE_NAME, ARRAY_SIZE(g_default_paths));
    return 0;
}

void shield_policy_cleanup(void)
{
    unsigned long flags;
    spin_lock_irqsave(&g_paths_lock, flags);
    memset(g_protected_paths, 0, sizeof(g_protected_paths));
    spin_unlock_irqrestore(&g_paths_lock, flags);
    pr_info("[%s] Motor de politicas liberado\n", MODULE_NAME);
}

int shield_add_protected_path(const char *path)
{
    unsigned long flags;
    size_t i;
    int slot = -1;

    if (!path || path[0] == '\0')
        return -EINVAL;

    spin_lock_irqsave(&g_paths_lock, flags);

    /* Check if already present */
    for (i = 0; i < MAX_PROTECTED_PATHS; i++) {
        if (g_protected_paths[i].active && strcmp(g_protected_paths[i].path, path) == 0) {
            spin_unlock_irqrestore(&g_paths_lock, flags);
            return 0; /* Already registered */
        }
        if (!g_protected_paths[i].active && slot == -1) {
            slot = (int)i;
        }
    }

    if (slot == -1) {
        spin_unlock_irqrestore(&g_paths_lock, flags);
        return -ENOSPC; /* Table full */
    }

    strscpy(g_protected_paths[slot].path, path, MMAP_SHIELD_PATH_MAX);
    g_protected_paths[slot].active = true;

    spin_unlock_irqrestore(&g_paths_lock, flags);
    pr_info("[%s] Ruta protegida anadida: %s\n", MODULE_NAME, path);
    return 0;
}

int shield_del_protected_path(const char *path)
{
    unsigned long flags;
    size_t i;
    bool found = false;

    if (!path || path[0] == '\0')
        return -EINVAL;

    spin_lock_irqsave(&g_paths_lock, flags);
    for (i = 0; i < MAX_PROTECTED_PATHS; i++) {
        if (g_protected_paths[i].active && strcmp(g_protected_paths[i].path, path) == 0) {
            g_protected_paths[i].active = false;
            g_protected_paths[i].path[0] = '\0';
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&g_paths_lock, flags);

    if (found) {
        pr_info("[%s] Ruta protegida eliminada: %s\n", MODULE_NAME, path);
        return 0;
    }
    return -ENOENT;
}

void shield_list_protected_paths_seq(struct seq_file *m)
{
    unsigned long flags;
    size_t i;

    if (!m)
        return;

    spin_lock_irqsave(&g_paths_lock, flags);
    for (i = 0; i < MAX_PROTECTED_PATHS; i++) {
        if (g_protected_paths[i].active) {
            seq_printf(m, "  - %s\n", g_protected_paths[i].path);
        }
    }
    spin_unlock_irqrestore(&g_paths_lock, flags);
}

static bool is_path_protected(const char *file_path)
{
    unsigned long flags;
    size_t i;
    bool match = false;

    if (!file_path)
        return false;

    spin_lock_irqsave(&g_paths_lock, flags);
    for (i = 0; i < MAX_PROTECTED_PATHS; i++) {
        if (g_protected_paths[i].active && strcmp(g_protected_paths[i].path, file_path) == 0) {
            match = true;
            break;
        }
    }
    spin_unlock_irqrestore(&g_paths_lock, flags);
    return match;
}

/*
 * Evaluates policy for file_mmap (security_mmap_file).
 * Intercepts at the LSM layer before any VMA allocation or Page Cache access.
 */
shield_action_t shield_evaluate_file_mmap(struct file *file, unsigned long prot, unsigned long flags)
{
    char *path_buf = NULL;
    char *resolved_path = NULL;
    char path_str[MMAP_SHIELD_PATH_MAX] = "<anon>";
    kuid_t uid = current_uid();
    pid_t pid = current->pid;
    pid_t tgid = current->tgid;
    bool is_root = uid_eq(uid, GLOBAL_ROOT_UID);
    shield_action_t verdict = SHIELD_ACTION_ALLOW;

    atomic64_inc(&g_shield_stats.total_intercepted);

    /* Resolve file path if file pointer is present */
    if (file && file->f_path.dentry) {
        path_buf = kmalloc(PAGE_SIZE, GFP_ATOMIC);
        if (path_buf) {
            resolved_path = d_path(&file->f_path, path_buf, PAGE_SIZE);
            if (!IS_ERR(resolved_path)) {
                strscpy(path_str, resolved_path, sizeof(path_str));
            }
            kfree(path_buf);
        }
    }

    /* 1. Policy W^X (Write XOR Execute) */
    if (g_shield_config.block_wx && (prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        verdict = SHIELD_BLOCK_WX;
        atomic64_inc(&g_shield_stats.wx_violations);
        goto decide;
    }

    /*
     * 2. Policy: Dirty COW (CVE-2016-5195) Precursor Detection
     * The Dirty COW exploit relies on:
     *   - File opened read-only (f_mode & FMODE_READ && !(f_mode & FMODE_WRITE))
     *   - Mapped with MAP_PRIVATE | PROT_WRITE
     * This creates a COW mapping that racing threads (madvise + /proc/self/mem write)
     * abuse to force dirty page writes into the Page Cache.
     *
     * Evaluated before the sensitive-file rule so the precursor is classified
     * as DIRTY_COW instead of a generic sensitive-file violation.
     *
     * Restricted to protected paths: the dynamic loader (ld.so) and execve()
     * map the .data segment of every binary/library exactly this way
     * (O_RDONLY + MAP_PRIVATE | PROT_WRITE), so a global rule would prevent
     * any dynamically linked program from starting.
     */
    if (g_shield_config.block_dirty_cow && file) {
        bool file_opened_ro = !(file->f_mode & FMODE_WRITE);
        bool req_private_write = (flags & MAP_PRIVATE) && (prot & PROT_WRITE);

        if (file_opened_ro && req_private_write && is_path_protected(path_str)) {
            verdict = SHIELD_BLOCK_DIRTY_COW;
            atomic64_inc(&g_shield_stats.dirty_cow_detections);
            goto decide;
        }
    }

    /* 3. Policy: Sensitive System Files Protection */
    if (g_shield_config.block_sensitive && file && is_path_protected(path_str)) {
        /* Non-root process attempting write mapping on sensitive system file */
        if (!is_root && (prot & PROT_WRITE)) {
            verdict = SHIELD_BLOCK_SENSITIVE_FILE;
            atomic64_inc(&g_shield_stats.sensitive_violations);
            goto decide;
        }
    }

    /* 4. Policy: Unauthorized Shared Write */
    if ((flags & MAP_SHARED) && (prot & PROT_WRITE) && file) {
        if (!(file->f_mode & FMODE_WRITE)) {
            verdict = SHIELD_BLOCK_SHARED_WRITE;
            atomic64_inc(&g_shield_stats.shared_write_violations);
            goto decide;
        }
    }

decide:
    if (verdict != SHIELD_ACTION_ALLOW) {
        int enforced = (g_shield_config.mode == SHIELD_MODE_ENFORCING);
        if (enforced) {
            atomic64_inc(&g_shield_stats.total_blocked);
        }

        pr_warn("[%s] ALERTA DE SEGURIDAD: PID=%d (%s) UID=%u Path=%s Prot=0x%lx Flags=0x%lx Accion=%s [%s]\n",
                MODULE_NAME, pid, current->comm, from_kuid(&init_user_ns, uid),
                path_str, prot, flags,
                verdict == SHIELD_BLOCK_WX ? "BLOQUEO_W^X" :
                verdict == SHIELD_BLOCK_SENSITIVE_FILE ? "BLOQUEO_ARCHIVO_SENSIBLE" :
                verdict == SHIELD_BLOCK_DIRTY_COW ? "DETECCION_DIRTY_COW" : "BLOQUEO_MAP_SHARED",
                enforced ? "BLOQUEADO" : "PERMISIVO");

        shield_audit_log(pid, tgid, uid, current->comm, path_str, prot, flags, verdict, enforced);
        return verdict;
    }

    atomic64_inc(&g_shield_stats.total_allowed);

    if (g_shield_config.audit_all) {
        shield_audit_log(pid, tgid, uid, current->comm, path_str, prot, flags, SHIELD_ACTION_ALLOW, 0);
    }

    return SHIELD_ACTION_ALLOW;
}

/*
 * Evaluates policy at the raw syscall level (__x64_sys_mmap).
 * Handles anonymous memory allocations where file is NULL.
 */
shield_action_t shield_evaluate_syscall_mmap(const struct pt_regs *regs)
{
    unsigned long prot = regs->dx;
    unsigned long flags = regs->r10;
    kuid_t uid = current_uid();
    pid_t pid = current->pid;
    pid_t tgid = current->tgid;

    /* Enforce W^X on anonymous mappings (e.g., shellcode staging / JIT spray) */
    if (g_shield_config.block_wx && (prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        int enforced = (g_shield_config.mode == SHIELD_MODE_ENFORCING);

        atomic64_inc(&g_shield_stats.total_intercepted);
        atomic64_inc(&g_shield_stats.wx_violations);
        if (enforced) {
            atomic64_inc(&g_shield_stats.total_blocked);
        }

        pr_warn("[%s] ALERTA W^X ANONIMA: PID=%d (%s) UID=%u Prot=0x%lx Flags=0x%lx [%s]\n",
                MODULE_NAME, pid, current->comm, from_kuid(&init_user_ns, uid),
                prot, flags, enforced ? "BLOQUEADO" : "PERMISIVO");

        shield_audit_log(pid, tgid, uid, current->comm, "<anonymous>", prot, flags,
                         SHIELD_BLOCK_WX, enforced);

        return SHIELD_BLOCK_WX;
    }

    return SHIELD_ACTION_ALLOW;
}
