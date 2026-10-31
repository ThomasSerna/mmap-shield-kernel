#ifndef POLICY_H
#define POLICY_H

#include <linux/fs.h>
#include <linux/ptrace.h>
#include <linux/seq_file.h>
#include "mmap_shield.h"

#define MAX_PROTECTED_PATHS 16

/* Protected path entry in our policy registry */
struct protected_path {
    char path[MMAP_SHIELD_PATH_MAX];
    bool active;
};

/* Policy evaluation routines */
shield_action_t shield_evaluate_file_mmap(struct file *file, unsigned long prot, unsigned long flags);
shield_action_t shield_evaluate_syscall_mmap(const struct pt_regs *regs);

/* Protected path management */
int  shield_add_protected_path(const char *path);
int  shield_del_protected_path(const char *path);
void shield_list_protected_paths_seq(struct seq_file *m);

/* Policy lifecycle */
int  shield_policy_init(void);
void shield_policy_cleanup(void);

#endif /* POLICY_H */
