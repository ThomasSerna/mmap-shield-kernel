#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "../include/mmap_shield.h"
#include "../include/proc_interface.h"
#include "../include/policy.h"

#define PROC_ENTRY_NAME "mmap_shield"

static struct proc_dir_entry *g_proc_entry = NULL;

static const char *action_to_str(shield_action_t action)
{
    switch (action) {
    case SHIELD_ACTION_ALLOW:
        return "PERMITIDO";
    case SHIELD_BLOCK_WX:
        return "BLOQUEO_W^X";
    case SHIELD_BLOCK_SENSITIVE_FILE:
        return "BLOQUEO_SENS";
    case SHIELD_BLOCK_DIRTY_COW:
        return "DIRTY_COW";
    case SHIELD_BLOCK_SHARED_WRITE:
        return "BLOQUEO_SHARED";
    case SHIELD_BLOCK_WX_ALIAS:
        return "BLOQUEO_ALIAS_WX";
    default:
        return "DESCONOCIDO";
    }
}

static int shield_proc_show(struct seq_file *m, void *v)
{
    struct shield_audit_event *events;
    size_t count, i;

    seq_puts(m, "================================================================================\n");
    seq_printf(m, " [mmap-shield v%s] Monitor de Seguridad de Memoria en Capa de Kernel\n",
               MMAP_SHIELD_VERSION);
    seq_puts(m, "================================================================================\n\n");

    /* Status and configuration */
    seq_printf(m, "Estado del Modulo:        ACTIVO\n");
    seq_printf(m, "Modo de Operacion:        [%s]\n",
               g_shield_config.mode == SHIELD_MODE_ENFORCING ? "ENFORCING (Bloqueo activo)" : "PERMISSIVE (Solo auditoria)");
    seq_printf(m, "Politica W^X:             [%s]\n", g_shield_config.block_wx ? "HABILITADO" : "DESHABILITADO");
    seq_printf(m, "Deteccion Dirty COW:      [%s]\n", g_shield_config.block_dirty_cow ? "HABILITADO" : "DESHABILITADO");
    seq_printf(m, "Proteccion Sensibles:     [%s]\n", g_shield_config.block_sensitive ? "HABILITADO" : "DESHABILITADO");
    seq_printf(m, "Auditoria Total (Benign): [%s]\n\n", g_shield_config.audit_all ? "HABILITADO" : "DESHABILITADO");

    /* Telemetry statistics */
    seq_puts(m, "--- Metricas y Telemetria en Tiempo Real ---\n");
    seq_printf(m, "  Total llamadas interceptadas:     %lld\n", atomic64_read(&g_shield_stats.total_intercepted));
    seq_printf(m, "    De ellas, cambios mprotect:     %lld\n", atomic64_read(&g_shield_stats.mprotect_intercepted));
    seq_printf(m, "  Mapeos permitidos:                %lld\n", atomic64_read(&g_shield_stats.total_allowed));
    seq_printf(m, "  Mapeos bloqueados:                %lld\n", atomic64_read(&g_shield_stats.total_blocked));
    seq_printf(m, "  Violaciones W^X prevenidas:       %lld\n", atomic64_read(&g_shield_stats.wx_violations));
    seq_printf(m, "  Alias W^X (doble mapeo) evitados: %lld\n", atomic64_read(&g_shield_stats.wx_alias_violations));
    seq_printf(m, "  Accesos sensibles bloqueados:     %lld\n", atomic64_read(&g_shield_stats.sensitive_violations));
    seq_printf(m, "  Patrones Dirty COW detectados:    %lld\n", atomic64_read(&g_shield_stats.dirty_cow_detections));
    seq_printf(m, "  Violaciones MAP_SHARED Write:     %lld\n\n", atomic64_read(&g_shield_stats.shared_write_violations));

    /* Protected paths list */
    seq_puts(m, "--- Rutas de Archivos Sensibles Protegidos ---\n");
    shield_list_protected_paths_seq(m);
    seq_puts(m, "\n");

    /* Audit ring buffer log */
    seq_puts(m, "--- Registro Circular de Auditoria de Seguridad (Ultimos Eventos) ---\n");
    seq_printf(m, "%-12s %-6s %-6s %-6s %-16s %-8s %-16s %-4s %-6s %-6s %s\n",
               "TIMESTAMP", "PID", "TGID", "UID", "COMANDO", "ORIGEN", "VERDICTO", "ENF", "PROT", "FLAGS", "RUTA");
    seq_puts(m, "--------------------------------------------------------------------------------------------------------------------------\n");

    events = kmalloc_array(MMAP_SHIELD_AUDIT_SIZE, sizeof(struct shield_audit_event), GFP_KERNEL);
    if (events) {
        count = shield_audit_copy_entries(events, MMAP_SHIELD_AUDIT_SIZE);
        for (i = 0; i < count; i++) {
            struct shield_audit_event *ev = &events[i];
            seq_printf(m, "[%10llu] %-6d %-6d %-6u %-16s %-8s %-16s %-4s 0x%04lx 0x%04lx %s\n",
                       ev->timestamp_sec,
                       ev->pid,
                       ev->tgid,
                       from_kuid(&init_user_ns, ev->uid),
                       ev->comm,
                       ev->origin == SHIELD_ORIGIN_MPROTECT ? "MPROTECT" : "MMAP",
                       action_to_str(ev->action),
                       ev->enforced ? "SI" : "NO",
                       ev->prot,
                       ev->flags,
                       ev->path);
        }
        kfree(events);
    }
    seq_puts(m, "================================================================================\n");

    return 0;
}

static int shield_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, shield_proc_show, NULL);
}

/*
 * Proc write handler for runtime reconfiguration.
 * Supports commands:
 *   mode=enforcing / mode=permissive
 *   block_wx=1 / block_wx=0
 *   block_dirty_cow=1 / block_dirty_cow=0
 *   block_sensitive=1 / block_sensitive=0
 *   audit_all=1 / audit_all=0
 *   add_path=/path/to/protect
 *   del_path=/path/to/remove
 *   reset_stats
 */
static ssize_t shield_proc_write(struct file *file, const char __user *ubuf,
                                 size_t count, loff_t *ppos)
{
    char *kbuf;
    char *cmd;
    int ret = 0;

    if (count == 0 || count > 512)
        return -EINVAL;

    kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, ubuf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }

    kbuf[count] = '\0';
    cmd = strstrip(kbuf);

    if (strcmp(cmd, "mode=enforcing") == 0) {
        g_shield_config.mode = SHIELD_MODE_ENFORCING;
        pr_info("[%s] Modo cambiado a ENFORCING (bloqueo activo)\n", MODULE_NAME);
    } else if (strcmp(cmd, "mode=permissive") == 0) {
        g_shield_config.mode = SHIELD_MODE_PERMISSIVE;
        pr_info("[%s] Modo cambiado a PERMISSIVE (solo auditoria)\n", MODULE_NAME);
    } else if (strcmp(cmd, "block_wx=1") == 0) {
        g_shield_config.block_wx = true;
        pr_info("[%s] Politica W^X activada\n", MODULE_NAME);
    } else if (strcmp(cmd, "block_wx=0") == 0) {
        g_shield_config.block_wx = false;
        pr_info("[%s] Politica W^X desactivada\n", MODULE_NAME);
    } else if (strcmp(cmd, "block_dirty_cow=1") == 0) {
        g_shield_config.block_dirty_cow = true;
        pr_info("[%s] Mitigacion Dirty COW activada\n", MODULE_NAME);
    } else if (strcmp(cmd, "block_dirty_cow=0") == 0) {
        g_shield_config.block_dirty_cow = false;
        pr_info("[%s] Mitigacion Dirty COW desactivada\n", MODULE_NAME);
    } else if (strcmp(cmd, "block_sensitive=1") == 0) {
        g_shield_config.block_sensitive = true;
        pr_info("[%s] Proteccion de archivos sensibles activada\n", MODULE_NAME);
    } else if (strcmp(cmd, "block_sensitive=0") == 0) {
        g_shield_config.block_sensitive = false;
        pr_info("[%s] Proteccion de archivos sensibles desactivada\n", MODULE_NAME);
    } else if (strcmp(cmd, "audit_all=1") == 0) {
        g_shield_config.audit_all = true;
        pr_info("[%s] Auditoria total activada\n", MODULE_NAME);
    } else if (strcmp(cmd, "audit_all=0") == 0) {
        g_shield_config.audit_all = false;
        pr_info("[%s] Auditoria total desactivada\n", MODULE_NAME);
    } else if (strncmp(cmd, "add_path=", 9) == 0) {
        ret = shield_add_protected_path(cmd + 9);
    } else if (strncmp(cmd, "del_path=", 9) == 0) {
        ret = shield_del_protected_path(cmd + 9);
    } else if (strcmp(cmd, "reset_stats") == 0) {
        atomic64_set(&g_shield_stats.total_intercepted, 0);
        atomic64_set(&g_shield_stats.mprotect_intercepted, 0);
        atomic64_set(&g_shield_stats.total_allowed, 0);
        atomic64_set(&g_shield_stats.total_blocked, 0);
        atomic64_set(&g_shield_stats.wx_violations, 0);
        atomic64_set(&g_shield_stats.wx_alias_violations, 0);
        atomic64_set(&g_shield_stats.sensitive_violations, 0);
        atomic64_set(&g_shield_stats.dirty_cow_detections, 0);
        atomic64_set(&g_shield_stats.shared_write_violations, 0);
        shield_audit_init();
        pr_info("[%s] Metricas y buffer de auditoria reiniciados\n", MODULE_NAME);
    } else {
        pr_warn("[%s] Comando desconocido en /proc/%s: '%s'\n", MODULE_NAME, PROC_ENTRY_NAME, cmd);
        ret = -EINVAL;
    }

    kfree(kbuf);
    return ret ? ret : count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops g_proc_fops = {
    .proc_open    = shield_proc_open,
    .proc_read    = seq_read,
    .proc_write   = shield_proc_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations g_proc_fops = {
    .owner   = THIS_MODULE,
    .open    = shield_proc_open,
    .read    = seq_read,
    .write   = shield_proc_write,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

int shield_proc_init(void)
{
    g_proc_entry = proc_create(PROC_ENTRY_NAME, 0660, NULL, &g_proc_fops);
    if (!g_proc_entry) {
        pr_err("[%s] Error creando entrada /proc/%s\n", MODULE_NAME, PROC_ENTRY_NAME);
        return -ENOMEM;
    }

    pr_info("[%s] Entrada /proc/%s creada exitosamente\n", MODULE_NAME, PROC_ENTRY_NAME);
    return 0;
}

void shield_proc_cleanup(void)
{
    if (g_proc_entry) {
        proc_remove(g_proc_entry);
        g_proc_entry = NULL;
        pr_info("[%s] Entrada /proc/%s eliminada\n", MODULE_NAME, PROC_ENTRY_NAME);
    }
}
