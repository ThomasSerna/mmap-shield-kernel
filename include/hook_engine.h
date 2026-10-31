#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include <linux/types.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include "mmap_shield.h"

/* Structure representing an ftrace-based function hook */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

/* Hook management functions */
int  shield_hook_init(void);
void shield_hook_cleanup(void);

/* Symbol resolution helper */
unsigned long shield_resolve_symbol(const char *name);

#endif /* HOOK_ENGINE_H */
