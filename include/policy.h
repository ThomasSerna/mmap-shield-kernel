#ifndef POLICY_H
#define POLICY_H

#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/seq_file.h>
#include "mmap_shield.h"

#define MAX_PROTECTED_PATHS 16

/* Protected path entry in our policy registry */
struct protected_path {
    char path[MMAP_SHIELD_PATH_MAX];
    dev_t dev;              /* Device of the inode resolved when the path was added */
    unsigned long ino;      /* Inode number resolved when the path was added */
    bool has_inode;         /* false if the path did not exist yet (match by path only) */
    bool active;
};

/*
 * Policy evaluation routines, called from the ftrace callback (atomic context).
 * They record telemetry/audit and return true when the call must be denied
 * (a violation was found and the module is in ENFORCING mode).
 */
bool shield_check_mmap(struct file *file, unsigned long prot, unsigned long flags);
bool shield_check_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
                           unsigned long prot);

/* Protected path management */
int  shield_add_protected_path(const char *path);
int  shield_del_protected_path(const char *path);
void shield_list_protected_paths_seq(struct seq_file *m);

/* Policy lifecycle */
int  shield_policy_init(void);
void shield_policy_cleanup(void);

#endif /* POLICY_H */
