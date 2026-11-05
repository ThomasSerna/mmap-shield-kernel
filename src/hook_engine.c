#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include "../include/mmap_shield.h"
#include "../include/hook_engine.h"
#include "../include/policy.h"

/*
 * Arguments are read from pt_regs following the x86_64 calling convention and
 * the decision is applied by rewriting regs->ip, which needs ftrace with
 * register saving (FTRACE_OPS_FL_SAVE_REGS / IPMODIFY).
 */
#if !defined(CONFIG_X86_64)
#error "mmap-shield requiere x86_64"
#endif
#if !defined(CONFIG_DYNAMIC_FTRACE_WITH_REGS)
#error "mmap-shield requiere CONFIG_DYNAMIC_FTRACE_WITH_REGS"
#endif

/* Typedef for resolved kallsyms_lookup_name */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t g_kallsyms_lookup_name = NULL;

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
 * security_mmap_file(file, prot, flags)
 * Runs for every mapping request (file-backed and anonymous) coming from
 * mmap, mmap2/compat, remap_file_pages and shmat, before the VMA is created.
 */
static bool mmap_file_should_deny(struct pt_regs *regs)
{
    struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
    unsigned long prot = regs_get_kernel_argument(regs, 1);
    unsigned long flags = regs_get_kernel_argument(regs, 2);

    return shield_check_mmap(file, prot, flags);
}

/* Executed instead of security_mmap_file() when the mapping is denied. */
static noinline int deny_mmap_file(struct file *file, unsigned long prot,
                                   unsigned long flags)
{
    return -EACCES;
}

static struct ftrace_hook g_hooks[] = {
    {
        .name        = "security_mmap_file",
        .should_deny = mmap_file_should_deny,
        .deny_stub   = deny_mmap_file,
    },
};

/*
 * Ftrace callback. Runs at the entry of the hooked function with preemption
 * disabled and recursion protection provided by ftrace, so the policy code
 * must not sleep. If the policy denies the call, the saved instruction
 * pointer is redirected to the deny stub, which returns straight to the
 * caller of the hooked function.
 */
static void notrace fh_handle(struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (regs && hook->should_deny(regs))
        regs->ip = (unsigned long)hook->deny_stub;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    fh_handle(ops, ftrace_get_regs(fregs));
}
#else
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct pt_regs *regs)
{
    fh_handle(ops, regs);
}
#endif

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
    size_t i;
    int ret;

    /* Initialize symbol resolver */
    ret = resolve_kallsyms();
    if (ret < 0) {
        pr_err("[%s] No fue posible inicializar resolutor de simbolos\n", MODULE_NAME);
        return ret;
    }

    for (i = 0; i < ARRAY_SIZE(g_hooks); i++) {
        ret = install_hook(&g_hooks[i]);
        if (ret) {
            pr_err("[%s] No se pudo enganchar %s (err=%d)\n",
                   MODULE_NAME, g_hooks[i].name, ret);
            while (i--)
                remove_hook(&g_hooks[i]);
            return ret;
        }
    }

    pr_info("[%s] Motor de intercepcion ftrace inicializado correctamente\n", MODULE_NAME);
    return 0;
}

void shield_hook_cleanup(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(g_hooks); i++)
        remove_hook(&g_hooks[i]);

    /* Synchronize RCU and allow all in-flight callbacks to drain */
    synchronize_rcu();
    pr_info("[%s] Motor de intercepcion ftrace descargado y sincronizado\n", MODULE_NAME);
}
