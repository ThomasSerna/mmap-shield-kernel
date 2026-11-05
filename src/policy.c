#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/personality.h>
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

    if (!path || path[0] != '/')
        return -EINVAL;
    if (strlen(path) >= MMAP_SHIELD_PATH_MAX)
        return -ENAMETOOLONG;

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

/* Request under evaluation, normalized for both interception points. */
struct shield_request {
    struct file *file;           /* Backing file, NULL for anonymous memory */
    unsigned long prot;          /* Protection being requested */
    unsigned long flags;         /* MAP_* flags (for mprotect: MAP_SHARED/MAP_PRIVATE of the VMA) */
    bool shared;                 /* Writes reach the page cache (MAP_SHARED / VM_SHARED) */
    bool shared_maywrite;        /* Shared view that is or can become writable */
    shield_origin_t origin;
};

/* Same test as path_noexec(), which is not exported to modules. */
static bool shield_path_noexec(const struct path *path)
{
    return (path->mnt->mnt_flags & MNT_NOEXEC) ||
           (path->mnt->mnt_sb->s_iflags & SB_I_NOEXEC);
}

/*
 * Effective protection of a new mapping, replicating mmap_prot() in
 * security/security.c. With the READ_IMPLIES_EXEC personality, do_mmap()
 * silently adds PROT_EXEC to readable mappings (PROT_READ | PROT_WRITE ends
 * up RWX), but security_mmap_file() only receives the requested value.
 */
static unsigned long shield_mmap_effective_prot(struct file *file, unsigned long prot)
{
    if ((prot & (PROT_READ | PROT_EXEC)) != PROT_READ)
        return prot;
    if (!(current->personality & READ_IMPLIES_EXEC))
        return prot;
    if (!file || !shield_path_noexec(&file->f_path))
        return prot | PROT_EXEC;
    return prot;
}

static const char *verdict_to_log(shield_action_t verdict)
{
    switch (verdict) {
    case SHIELD_BLOCK_WX:
        return "BLOQUEO_W^X";
    case SHIELD_BLOCK_SENSITIVE_FILE:
        return "BLOQUEO_ARCHIVO_SENSIBLE";
    case SHIELD_BLOCK_DIRTY_COW:
        return "DETECCION_DIRTY_COW";
    case SHIELD_BLOCK_SHARED_WRITE:
        return "BLOQUEO_MAP_SHARED";
    case SHIELD_BLOCK_WX_ALIAS:
        return "BLOQUEO_ALIAS_W^X";
    default:
        return "PERMITIDO";
    }
}

/*
 * Applies the security policy to a mapping request (mmap) or to a permission
 * change on an existing mapping (mprotect). Runs in the ftrace callback, so it
 * must not sleep. Returns true when the call must be denied.
 */
static bool shield_evaluate(const struct shield_request *req)
{
    struct file *file = req->file;
    unsigned long prot = req->prot;
    char *path_buf = NULL;
    char *resolved_path = NULL;
    char path_str[MMAP_SHIELD_PATH_MAX] = "<anon>";
    kuid_t uid = current_uid();
    pid_t pid = current->pid;
    pid_t tgid = current->tgid;
    bool is_root = uid_eq(uid, GLOBAL_ROOT_UID);
    shield_action_t verdict = SHIELD_ACTION_ALLOW;

    atomic64_inc(&g_shield_stats.total_intercepted);
    if (req->origin == SHIELD_ORIGIN_MPROTECT)
        atomic64_inc(&g_shield_stats.mprotect_intercepted);

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

    /* 1. Policy W^X (Write XOR Execute) on the effective protection */
    if (g_shield_config.block_wx && (prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        verdict = SHIELD_BLOCK_WX;
        atomic64_inc(&g_shield_stats.wx_violations);
        goto decide;
    }

    /*
     * 1b. Policy W^X across aliases of the same file.
     * Per-mapping W^X is not enough: a file (typically a memfd) can be mapped
     * twice, once writable and once executable, and code written through the
     * first view runs through the second. Executable access is denied while
     * the file has shared writable mappings, or when this very view is shared
     * and is or can become writable (writable descriptor / VM_MAYWRITE).
     */
    if (g_shield_config.block_wx && file && (prot & PROT_EXEC) &&
        (req->shared_maywrite || mapping_writably_mapped(file->f_mapping))) {
        verdict = SHIELD_BLOCK_WX_ALIAS;
        atomic64_inc(&g_shield_stats.wx_alias_violations);
        goto decide;
    }

    /*
     * 2. Policy: Dirty COW (CVE-2016-5195) Precursor Detection
     * The Dirty COW exploit relies on:
     *   - File opened read-only (f_mode & FMODE_READ && !(f_mode & FMODE_WRITE))
     *   - A private (COW) mapping of it that becomes writable
     * This creates a COW mapping that racing threads (madvise + /proc/self/mem write)
     * abuse to force dirty page writes into the Page Cache.
     *
     * The writable private mapping can be requested directly in mmap() or
     * obtained later with mprotect(), so both interception points apply it.
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
        bool req_private_write = !req->shared && (prot & PROT_WRITE);

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
    if (req->shared && (prot & PROT_WRITE) && file) {
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

        pr_warn_ratelimited("[%s] ALERTA DE SEGURIDAD: PID=%d (%s) UID=%u Origen=%s Path=%s Prot=0x%lx Flags=0x%lx Accion=%s [%s]\n",
                            MODULE_NAME, pid, current->comm, from_kuid(&init_user_ns, uid),
                            req->origin == SHIELD_ORIGIN_MPROTECT ? "mprotect" : "mmap",
                            path_str, prot, req->flags, verdict_to_log(verdict),
                            enforced ? "BLOQUEADO" : "PERMISIVO");

        shield_audit_log(pid, tgid, uid, current->comm, path_str, prot, req->flags,
                         verdict, req->origin, enforced);
        return enforced;
    }

    atomic64_inc(&g_shield_stats.total_allowed);

    if (g_shield_config.audit_all) {
        shield_audit_log(pid, tgid, uid, current->comm, path_str, prot, req->flags,
                         SHIELD_ACTION_ALLOW, req->origin, 0);
    }

    return false;
}

/*
 * Evaluates policy for file_mmap (security_mmap_file).
 * Intercepts at the LSM layer before any VMA allocation or Page Cache access.
 * Anonymous mappings arrive here too, with file == NULL.
 */
bool shield_check_mmap(struct file *file, unsigned long prot, unsigned long flags)
{
    unsigned long type = flags & MAP_TYPE;
    bool shared = (type == MAP_SHARED || type == MAP_SHARED_VALIDATE);
    struct shield_request req = {
        .file            = file,
        .prot            = shield_mmap_effective_prot(file, prot),
        .flags           = flags,
        .shared          = shared,
        .shared_maywrite = shared && file && (file->f_mode & FMODE_WRITE),
        .origin          = SHIELD_ORIGIN_MMAP,
    };

    return shield_evaluate(&req);
}

/*
 * Evaluates policy for file_mprotect (security_file_mprotect).
 * Called for each VMA whose permissions change, after the kernel checked
 * VM_MAY* bits. "prot" already includes PROT_EXEC added by READ_IMPLIES_EXEC.
 */
bool shield_check_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
                           unsigned long prot)
{
    bool shared = !!(vma->vm_flags & VM_SHARED);
    struct shield_request req = {
        .file            = vma->vm_file,
        .prot            = prot,
        .flags           = shared ? MAP_SHARED : MAP_PRIVATE,
        .shared          = shared,
        .shared_maywrite = shared && (vma->vm_flags & VM_MAYWRITE),
        .origin          = SHIELD_ORIGIN_MPROTECT,
    };

    return shield_evaluate(&req);
}
