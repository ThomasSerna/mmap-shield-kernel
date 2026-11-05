#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ftrace.h>
#include <linux/fs.h>
#include <linux/string.h>
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

/*
 * Hooks are attached by function name with ftrace_set_filter(), so the module
 * never needs the address of a kernel symbol. The usual alternative (finding
 * kallsyms_lookup_name with a temporary kprobe and calling it through a
 * pointer) crashes on kernels with IBT: kallsyms_lookup_name is not exported,
 * objtool seals its ENDBR and the indirect call raises #CP (Missing ENDBR).
 */

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

/*
 * security_file_mprotect(vma, reqprot, prot)
 * Runs for every VMA whose permissions change through mprotect/pkey_mprotect.
 * Without it, W^X and the Dirty COW rule could be bypassed by mapping with
 * harmless permissions and adding PROT_WRITE / PROT_EXEC afterwards.
 */
static bool file_mprotect_should_deny(struct pt_regs *regs)
{
    struct vm_area_struct *vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 0);
    unsigned long reqprot = regs_get_kernel_argument(regs, 1);
    unsigned long prot = regs_get_kernel_argument(regs, 2);

    return shield_check_mprotect(vma, reqprot, prot);
}

/* Executed instead of security_file_mprotect() when the change is denied. */
static noinline int deny_file_mprotect(struct vm_area_struct *vma,
                                       unsigned long reqprot, unsigned long prot)
{
    return -EACCES;
}

static struct ftrace_hook g_hooks[] = {
    {
        .name        = "security_mmap_file",
        .should_deny = mmap_file_should_deny,
        .deny_stub   = deny_mmap_file,
    },
    {
        .name        = "security_file_mprotect",
        .should_deny = file_mprotect_should_deny,
        .deny_stub   = deny_file_mprotect,
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

/* Drops the function filter of an ops that is not registered. */
static void clear_filter(struct ftrace_ops *ops)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
    ftrace_free_filter(ops);
#else
    /* ftrace_free_filter() is exported to modules only since 6.2 */
    ftrace_set_filter(ops, NULL, 0, 1);
#endif
}

static int install_hook(struct ftrace_hook *hook)
{
    int ret;

    char filter[KSYM_NAME_LEN];

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

    /* ftrace_set_filter() parses (and may modify) its buffer: use a copy */
    strscpy(filter, hook->name, sizeof(filter));
    ret = ftrace_set_filter(&hook->ops, (unsigned char *)filter, strlen(filter), 1);
    if (ret) {
        pr_err("[%s] '%s' no es trazable por ftrace en este kernel (err=%d)\n",
               MODULE_NAME, hook->name, ret);
        clear_filter(&hook->ops);
        return ret;
    }

    ret = register_ftrace_function(&hook->ops);
    if (ret) {
        pr_err("[%s] register_ftrace_function fallo para '%s' (err=%d)\n", MODULE_NAME, hook->name, ret);
        clear_filter(&hook->ops);
        return ret;
    }

    hook->installed = true;
    pr_info("[%s] Hook ftrace activado para '%s'\n", MODULE_NAME, hook->name);
    return 0;
}

static void remove_hook(struct ftrace_hook *hook)
{
    int ret;

    if (!hook->installed)
        return;

    ret = unregister_ftrace_function(&hook->ops);
    if (ret) {
        pr_warn("[%s] unregister_ftrace_function fallo para '%s' (err=%d)\n", MODULE_NAME, hook->name, ret);
    }
    clear_filter(&hook->ops);

    hook->installed = false;
    pr_info("[%s] Hook ftrace desactivado para '%s'\n", MODULE_NAME, hook->name);
}

int shield_hook_init(void)
{
    size_t i;
    int ret;

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
