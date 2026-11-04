#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include "../include/mmap_shield.h"
#include "../include/hook_engine.h"
#include "../include/policy.h"

#if defined(CONFIG_X86_64)
#include <asm/ftrace.h>
#endif

/* Typedef for resolved kallsyms_lookup_name */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t g_kallsyms_lookup_name = NULL;

/* Forward declarations of hook thunks and handlers */
static struct ftrace_hook g_hook_sec_mmap;
static struct ftrace_hook g_hook_sys_mmap;

/*
 * Resolves kallsyms_lookup_name dynamically.
 * In Linux >= 5.7, kallsyms_lookup_name is no longer exported via EXPORT_SYMBOL.
 * We resolve it safely using a temporary kprobe, without disabling CR0.WP or
 * risking kernel page table corruption.
 */
static int resolve_kallsyms(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("[%s] Error registrando kprobe para kallsyms_lookup_name: %d\n", MODULE_NAME, ret);
        return ret;
    }

    g_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    if (!g_kallsyms_lookup_name) {
        pr_err("[%s] Direccion de kallsyms_lookup_name es nula\n", MODULE_NAME);
        return -EFAULT;
    }

    pr_info("[%s] kallsyms_lookup_name resuelto en %px via kprobe\n",
            MODULE_NAME, (void *)g_kallsyms_lookup_name);
#else
    g_kallsyms_lookup_name = kallsyms_lookup_name;
#endif
    return 0;
}

unsigned long shield_resolve_symbol(const char *name)
{
    if (!g_kallsyms_lookup_name) {
        if (resolve_kallsyms() < 0)
            return 0;
    }
    return g_kallsyms_lookup_name(name);
}

/*
 * Ftrace callback thunk.
 * Handles the redirection of execution flow to our hook function.
 *
 * Recursion guard: when our hook calls the original function, the ftrace
 * trampoline fires again. In that case the caller (parent_ip) lies inside
 * this module, so we let the original run untouched. Calls coming from
 * anywhere else in the kernel (including nested calls such as
 * __x64_sys_mmap -> vm_mmap_pgoff -> security_mmap_file) are still
 * redirected, and no per-CPU state is held across code that may sleep.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);

    if (!regs || within_module(parent_ip, THIS_MODULE))
        return;

    regs->ip = (unsigned long)hook->function;
}
#else
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (within_module(parent_ip, THIS_MODULE))
        return;

    regs->ip = (unsigned long)hook->function;
}
#endif

/*
 * Hook implementation for security_mmap_file.
 * The exported wrapper has kept the signature (file, prot, flags) across
 * 5.x / 6.x; "reqprot" only exists in the internal LSM mmap_file hook.
 */
static int hook_security_mmap_file(struct file *file,
                                   unsigned long prot,
                                   unsigned long flags)
{
    shield_action_t action;

    /* Evaluate security policy */
    action = shield_evaluate_file_mmap(file, prot, flags);
    if (action != SHIELD_ACTION_ALLOW && g_shield_config.mode == SHIELD_MODE_ENFORCING) {
        /* Reject the mapping before VMA creation */
        return -EACCES;
    }

    /* Call the original security_mmap_file (thunk skips calls from this module) */
    return ((int (*)(struct file *, unsigned long, unsigned long))g_hook_sec_mmap.address)(file, prot, flags);
}

/*
 * Hook implementation for __x64_sys_mmap (Syscall boundary)
 * Allows catching anonymous mappings and validating W^X directly.
 */
static asmlinkage long hook_sys_mmap(const struct pt_regs *regs)
{
    shield_action_t action;

    action = shield_evaluate_syscall_mmap(regs);
    if (action != SHIELD_ACTION_ALLOW && g_shield_config.mode == SHIELD_MODE_ENFORCING) {
        return -EPERM;
    }

    return ((long (*)(const struct pt_regs *))g_hook_sys_mmap.address)(regs);
}

static int install_hook(struct ftrace_hook *hook)
{
    int ret;

    hook->address = shield_resolve_symbol(hook->name);
    if (!hook->address) {
        pr_warn("[%s] Simbolo '%s' no encontrado en el kernel\n", MODULE_NAME, hook->name);
        return -ENOENT;
    }

    hook->ops.func = fh_ftrace_thunk;
    /*
     * FTRACE_OPS_FL_RECURSION exists only since 5.11 (it is an enum value,
     * so it cannot be tested with #ifdef). Before 5.11 ftrace already applies
     * recursion protection by default unless FTRACE_OPS_FL_RECURSION_SAFE is set.
     */
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
                    | FTRACE_OPS_FL_RECURSION
#endif
                    | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (ret) {
        pr_err("[%s] ftrace_set_filter_ip fallo para '%s' (err=%d)\n", MODULE_NAME, hook->name, ret);
        hook->address = 0;
        return ret;
    }

    ret = register_ftrace_function(&hook->ops);
    if (ret) {
        pr_err("[%s] register_ftrace_function fallo para '%s' (err=%d)\n", MODULE_NAME, hook->name, ret);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        hook->address = 0;
        return ret;
    }

    pr_info("[%s] Hook ftrace activado para '%s' en %px\n",
            MODULE_NAME, hook->name, (void *)hook->address);
    return 0;
}

static void remove_hook(struct ftrace_hook *hook)
{
    int ret;

    if (!hook->address)
        return;

    ret = unregister_ftrace_function(&hook->ops);
    if (ret) {
        pr_warn("[%s] unregister_ftrace_function fallo para '%s' (err=%d)\n", MODULE_NAME, hook->name, ret);
    }

    ret = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (ret) {
        pr_warn("[%s] ftrace_set_filter_ip limpieza fallo para '%s' (err=%d)\n", MODULE_NAME, hook->name, ret);
    }

    hook->address = 0;
    pr_info("[%s] Hook ftrace desactivado para '%s'\n", MODULE_NAME, hook->name);
}

int shield_hook_init(void)
{
    int ret;

    /* Initialize symbol resolver */
    ret = resolve_kallsyms();
    if (ret < 0) {
        pr_err("[%s] No fue posible inicializar resolutor de simbolos\n", MODULE_NAME);
        return ret;
    }

    /* 1. Hook security_mmap_file (LSM hook file_mmap) */
    g_hook_sec_mmap.name = "security_mmap_file";
    g_hook_sec_mmap.function = (void *)hook_security_mmap_file;
    ret = install_hook(&g_hook_sec_mmap);
    if (ret) {
        pr_err("[%s] No se pudo enganchar security_mmap_file (err=%d)\n",
               MODULE_NAME, ret);
        return ret;
    }

    /* 2. Hook __x64_sys_mmap (Syscall table / entry) */
#if defined(CONFIG_X86_64)
    g_hook_sys_mmap.name = "__x64_sys_mmap";
#else
    g_hook_sys_mmap.name = "sys_mmap";
#endif
    g_hook_sys_mmap.function = (void *)hook_sys_mmap;
    ret = install_hook(&g_hook_sys_mmap);
    if (ret) {
        pr_err("[%s] No se pudo enganchar syscall mmap (err=%d)\n",
               MODULE_NAME, ret);
        remove_hook(&g_hook_sec_mmap);
        return ret;
    }

    pr_info("[%s] Motor de intercepcion ftrace inicializado correctamente\n", MODULE_NAME);
    return 0;
}

void shield_hook_cleanup(void)
{
    remove_hook(&g_hook_sec_mmap);
    remove_hook(&g_hook_sys_mmap);

    /* Synchronize RCU and allow all in-flight hooks to drain */
    synchronize_rcu();
    pr_info("[%s] Motor de intercepcion ftrace descargado y sincronizado\n", MODULE_NAME);
}
