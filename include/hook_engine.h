#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include <linux/types.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include "mmap_shield.h"

/*
 * ftrace-based interception point.
 *
 * The policy is decided inside the ftrace callback itself. When the call must
 * be denied, execution is redirected to deny_stub (same prototype as the
 * hooked function, it only returns an error). Otherwise nothing is touched and
 * the original kernel function runs normally. The module never calls the
 * hooked function through a pointer, which keeps it compatible with kernel
 * IBT (sealed ENDBR) and leaves no module frame on the stack while the
 * original function sleeps.
 */
struct ftrace_hook {
    const char *name;                            /* Kernel symbol to intercept */
    bool (*should_deny)(struct pt_regs *regs);   /* Policy decision (atomic context) */
    void *deny_stub;                             /* Executed instead of the original when denied */
    unsigned long address;                       /* Resolved address of the symbol */
    struct ftrace_ops ops;
};

/* Hook management functions */
int  shield_hook_init(void);
void shield_hook_cleanup(void);

/* Symbol resolution helper */
unsigned long shield_resolve_symbol(const char *name);

#endif /* HOOK_ENGINE_H */
