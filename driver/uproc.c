// SPDX-License-Identifier: GPL-2.0
#include <asm/atomic.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include "uproc.h"

#define USERPROC_DEVNAME "userproc"

#define USERPROC_FATAL(fmt, ...) pr_err("USERPROC: " fmt, ##__VA_ARGS__)
#define USERPROC_ERR(fmt, ...)   pr_err("USERPROC: " fmt, ##__VA_ARGS__)
#define USERPROC_WARN(fmt, ...)  pr_warn("USERPROC: " fmt, ##__VA_ARGS__)
#define USERPROC_INFO(fmt, ...)  pr_info("USERPROC: " fmt, ##__VA_ARGS__)

/* Compatibility: define PDE_DATA if kernel headers don't provide it */
#ifndef PDE_DATA
#define PDE_DATA(inode) ((inode)->i_private)
#endif

#define USERPROC_K_LOCK(sema)                                                                                          \
    do {                                                                                                               \
        down(&sema);                                                                                                   \
    } while (0)
#define USERPROC_K_UNLOCK(sema)                                                                                        \
    do {                                                                                                               \
        up(&sema);                                                                                                     \
    } while (0)

typedef struct tagUMP_ENTRY_S {
    uint32_t entry_name_hash;
    struct rb_node node;
    struct proc_dir_entry *parent;
    USERPROC_USRMODEPROC_ENTRY_S stInfo;
    char entry_name[MAX_PROC_NAME_LEN + 1];
} UMP_ENTRY_S;

typedef struct tagUMP_DIR_S {
    uint32_t dir_name_hash;
    struct rb_node node;
    struct rb_root entry_root;
    struct file *pstFile;
    struct proc_dir_entry *entry;
    struct proc_dir_entry *parent;
    char dir_name[MAX_PROC_NAME_LEN + 12]; /* '_' 1 and pid 10 */
} UMP_DIR_S;

typedef struct tagUMP_PARAM_S {
    struct semaphore stSem;          /* Semaphore general */
    struct semaphore stSemReadWrite; /* Semaphore ReadWrite */
    struct rb_root root;
    wait_queue_head_t wq_for_read;
    wait_queue_head_t wq_for_write;
    int busy;
    USERPROC_USRMODEPROC_CMD_S current_cmd;
    atomic_t atmOpenCnt;
} UMP_PARAM_S;

struct proc_dir_entry *g_pUser_proc = NULL;
static const struct proc_ops ump_seq_ops;
static struct file_operations userproc_usrmodeproc_fops;

static UMP_PARAM_S g_stUProcParam = {
    .root = RB_ROOT,
    .atmOpenCnt = ATOMIC_INIT(0),
};

static UMP_DIR_S *g_pstUserDirent = NULL;

static void PROC_RemoveDirForcibly(UMP_DIR_S *pstDir);
static void PROC_RemoveEntry(UMP_DIR_S *pstDir, UMP_ENTRY_S *pstEntry);
UMP_DIR_S *PROC_AddDir(const char *pszName, const char *pszParent, struct file *pstFile);
int32_t PROC_RemoveDir(UMP_DIR_S *pstDir);
int32_t PROC_RemoveDirByName(const char *pszName);
UMP_DIR_S *PROC_AddPrivateDir(const char *pszName, struct proc_dir_entry *pstEntry);
int32_t PROC_RemovePrivateDir(const char *pszName);
UMP_ENTRY_S *PROC_AddEntry(const USERPROC_USRMODEPROC_ENTRY_S *pstParam, bool bUsrMode);
int32_t PROC_RemoveEntryByName(const char *pszName, const char *pszParent);
long userproc_usrmodeproc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
long userproc_usrmodeproc_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#endif

static UMP_DIR_S *RBTree_Find_Dirent(UMP_DIR_S *pszParent, const char *pszName) {
    uint32_t hash = full_name_hash(pszParent, pszName, strlen(pszName)) & 0x7fffffffU;
    struct rb_node *node = g_stUProcParam.root.rb_node;

    while (node) {
        int32_t result;
        UMP_DIR_S *this = rb_entry(node, UMP_DIR_S, node);

        if (hash != this->dir_name_hash) {
            result = hash - this->dir_name_hash;
        } else {
            result = strncmp(pszName, this->dir_name, sizeof(this->dir_name));
        }

        if (result < 0) {
            node = node->rb_left;
        } else if (result > 0) {
            node = node->rb_right;
        } else {
            return this;
        }
    }

    return NULL;
}

static int32_t RBTree_Insert_Dirent(UMP_DIR_S *pszParent, UMP_DIR_S *pszDirent) {
    struct rb_root *root = &g_stUProcParam.root;
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    while (*new) {
        int32_t result;
        UMP_DIR_S *this = rb_entry(*new, UMP_DIR_S, node);
        parent = *new;

        if (pszDirent->dir_name_hash != this->dir_name_hash) {
            result = pszDirent->dir_name_hash - this->dir_name_hash;
        } else {
            result = strncmp(pszDirent->dir_name, this->dir_name, sizeof(pszDirent->dir_name));
        }

        if (result < 0) {
            new = &((*new)->rb_left);
        } else if (result > 0) {
            new = &((*new)->rb_right);
        } else {
            USERPROC_ERR("dirent(%s) has existed.", pszDirent->dir_name);
            return USERPROC_FAILURE;
        }
    }

    rb_link_node(&pszDirent->node, parent, new);
    rb_insert_color(&pszDirent->node, root);

    return USERPROC_SUCCESS;
}

static void RBTree_Erase_Dirent(UMP_DIR_S *pszParent, UMP_DIR_S *pszDirent) {
    struct rb_root *root = &g_stUProcParam.root;

    rb_erase(&(pszDirent->node), root);
}

static UMP_ENTRY_S *RBTree_Find_Entry(UMP_DIR_S *pstDir, const char *pszName) {
    uint32_t hash = full_name_hash(NULL, pszName, strlen(pszName)) & 0x7fffffffU;
    struct rb_node *node = pstDir->entry_root.rb_node;

    while (node) {
        int32_t result;
        UMP_ENTRY_S *this = rb_entry(node, UMP_ENTRY_S, node);

        if (hash != this->entry_name_hash) {
            result = hash - this->entry_name_hash;
        } else {
            result = strncmp(pszName, this->entry_name, sizeof(this->entry_name));
        }

        if (result < 0) {
            node = node->rb_left;
        } else if (result > 0) {
            node = node->rb_right;
        } else {
            return this;
        }
    }

    return NULL;
}

static int32_t RBTree_Insert_Entry(UMP_DIR_S *pstDir, UMP_ENTRY_S *pszEntry) {
    struct rb_root *root = &(pstDir->entry_root);
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    while (*new) {
        int32_t result;
        UMP_ENTRY_S *this = rb_entry(*new, UMP_ENTRY_S, node);
        parent = *new;

        if (pszEntry->entry_name_hash != this->entry_name_hash) {
            result = pszEntry->entry_name_hash - this->entry_name_hash;
        } else {
            result = strncmp(pszEntry->entry_name, this->entry_name, sizeof(pszEntry->entry_name));
        }

        if (result < 0) {
            new = &((*new)->rb_left);
        } else if (result > 0) {
            new = &((*new)->rb_right);
        } else {
            USERPROC_ERR("entry(%s) has existed.", pszEntry->entry_name);
            return USERPROC_FAILURE;
        }
    }

    rb_link_node(&pszEntry->node, parent, new);
    rb_insert_color(&pszEntry->node, root);

    return USERPROC_SUCCESS;
}

static void RBTree_Erase_Entry(UMP_DIR_S *pstDir, UMP_ENTRY_S *pszEntry) {
    struct rb_root *root = &(pstDir->entry_root);

    rb_erase(&(pszEntry->node), root);
}

static UMP_ENTRY_S *RBTree_Find_Proc_Entry(const char *parent_name, const char *entry_name) {
    UMP_DIR_S *pstDir;
    UMP_ENTRY_S *pstEntry;

    if (!parent_name || !entry_name || !strlen(parent_name) || !strlen(entry_name)) {
        USERPROC_ERR("invalid proc entry.");
        goto out;
    }

    pstDir = RBTree_Find_Dirent(NULL, parent_name);
    if (!pstDir) {
        USERPROC_ERR("Can't find dirent:%s\n", parent_name);
        goto out;
    }

    pstEntry = RBTree_Find_Entry(pstDir, entry_name);
    if (!pstEntry) {
        USERPROC_ERR("Can't find entry:%s\n", entry_name);
        goto out;
    }

    return pstEntry;

out:
    return NULL;
}

static int userproc_usrmodeproc_open(struct inode *inode, struct file *file) {
    if (atomic_inc_return(&g_stUProcParam.atmOpenCnt) == 1) {
        memset(&g_stUProcParam.current_cmd, 0, sizeof(USERPROC_USRMODEPROC_CMD_S));
        init_waitqueue_head(&g_stUProcParam.wq_for_read);
        init_waitqueue_head(&g_stUProcParam.wq_for_write);
        g_stUProcParam.busy = 0;
        sema_init(&g_stUProcParam.stSem, 1);
        sema_init(&g_stUProcParam.stSemReadWrite, 1);
    }

    file->private_data = &g_stUProcParam;
    return 0;
}

static int userproc_usrmodeproc_close(struct inode *inode, struct file *file) {
    struct rb_node *node;

    if (atomic_dec_return(&g_stUProcParam.atmOpenCnt) >= 0) {
    scratch_dirent:
        for (node = rb_first(&(g_stUProcParam.root)); node; node = rb_next(node)) {
            UMP_DIR_S *dirent = rb_entry(node, UMP_DIR_S, node);

            if (file == dirent->pstFile) {
                PROC_RemoveDirForcibly(dirent);
                goto scratch_dirent;
            } else if (NULL == dirent->pstFile) {
                struct rb_node *entry_node;

            scratch_entry:
                for (entry_node = rb_first(&(dirent->entry_root)); entry_node; entry_node = rb_next(entry_node)) {
                    UMP_ENTRY_S *entry = rb_entry(entry_node, UMP_ENTRY_S, node);
                    if (file == entry->stInfo.pFile) {
                        PROC_RemoveEntry(dirent, entry);
                        goto scratch_entry;
                    }
                }
            }
        }
    }

    return 0;
}

static int ump_seq_show(struct seq_file *m, void *unused) {
    struct dentry *d = m->file->f_path.dentry;
    const char *entry_name = d->d_name.name;
    const char *parent_name = d->d_parent->d_name.name;
    UMP_PARAM_S *proc = (UMP_PARAM_S *)m->private;
    UMP_ENTRY_S *pstEntry;
    int32_t ret;
    DEFINE_WAIT(wait);

    USERPROC_K_LOCK(g_stUProcParam.stSem);

    pstEntry = RBTree_Find_Proc_Entry(parent_name, entry_name);
    if (!pstEntry) {
        USERPROC_ERR("Can't find entry:%s\n", entry_name);
        ret = -1;
        goto out;
    } else if (!pstEntry->stInfo.pfnShowFunc) {
        USERPROC_ERR("Entry don't support read.\n");
        ret = -1;
        goto out;
    }

    proc->current_cmd.pEntry = &(pstEntry->stInfo);
    strncpy(proc->current_cmd.aszCmd, USERPROC_READ_CMD, sizeof(proc->current_cmd.aszCmd) - 1);

    USERPROC_K_UNLOCK(g_stUProcParam.stSem);

    /* Wait write data over */
    prepare_to_wait(&proc->wq_for_read, &wait, TASK_INTERRUPTIBLE);
    schedule();
    finish_wait(&proc->wq_for_read, &wait);

    /* Find it again, pstEntry may be removed when wait event */
    pstEntry = RBTree_Find_Proc_Entry(parent_name, entry_name);
    if (!pstEntry) {
        USERPROC_ERR("Can't find entry:%s\n", entry_name);
        ret = -1;
        return ret;
    }

    if (NULL != pstEntry->stInfo.pfnShowFunc) {
        USERPROC_K_LOCK(g_stUProcParam.stSemReadWrite);
        if (pstEntry->stInfo.Read) {
            seq_printf(m, "%s", (char *)pstEntry->stInfo.Read);

            kfree(pstEntry->stInfo.Read);
            pstEntry->stInfo.Read = NULL;
        }
        USERPROC_K_UNLOCK(g_stUProcParam.stSemReadWrite);
    }

    ret = 0;
    return ret;
out:
    USERPROC_K_UNLOCK(g_stUProcParam.stSem);

    return ret;
}

static int ump_seq_open(struct inode *inode, struct file *file) {
    UMP_PARAM_S *proc = (UMP_PARAM_S *)PDE_DATA(inode);
    int res;

    if (NULL == proc) {
        USERPROC_ERR("ump_seq_open: PDE_DATA(inode) is NULL\n");
        return -ENODEV;
    }

    if (proc->busy)
        return -EAGAIN;

    proc->busy = 1;

    res = single_open(file, ump_seq_show, proc);

    if (res)
        proc->busy = 0;

    return res;
}

static int ump_seq_release(struct inode *inode, struct file *file) {
    UMP_PARAM_S *proc = (UMP_PARAM_S *)PDE_DATA(inode);

    if (proc)
        proc->busy = 0;

    return single_release(inode, file);
}

static int32_t StripString(char *string, uint32_t size) {
    char *p = string;
    uint32_t index = 0;

    if (!string || 0 == size)
        return USERPROC_FAILURE;

    /* strip '\n' as string end character */
    for (; index < size; index++) {
        if ('\n' == *(p + index)) {
            *(p + index) = '\0';
        }
    }

    if (strlen(string))
        return USERPROC_SUCCESS;
    else
        return USERPROC_FAILURE;
}

static ssize_t ump_seq_write(struct file *file, const char __user *buf, size_t size, loff_t *pos) {
    struct dentry *d = file->f_path.dentry;
    const char *entry_name = d->d_name.name;
    const char *parent_name = d->d_parent->d_name.name;
    UMP_PARAM_S *proc = (UMP_PARAM_S *)PDE_DATA(d->d_inode);
    UMP_ENTRY_S *pstEntry;
    int32_t ret;

    DEFINE_WAIT(wait);

    USERPROC_K_LOCK(g_stUProcParam.stSem);

    pstEntry = RBTree_Find_Proc_Entry(parent_name, entry_name);
    if (!pstEntry || size > sizeof(proc->current_cmd.aszCmd)) {
        USERPROC_ERR("Can't find entry:%s\n", entry_name);
        ret = -1;
        goto out;
    } else if (NULL == pstEntry->stInfo.pfnCmdFunc) {
        USERPROC_ERR("Entry don't support write.\n");
        ret = -1;
        goto out;
    }

    memset(proc->current_cmd.aszCmd, 0, sizeof(proc->current_cmd.aszCmd));
    if (copy_from_user(proc->current_cmd.aszCmd, buf, size)) {
        USERPROC_ERR("get cmd failed.");
        ret = -EIO;
        goto out;
    }
    proc->current_cmd.aszCmd[size > 1 ? size - 1 : 0] = '\0';

    if (USERPROC_FAILURE == StripString(proc->current_cmd.aszCmd, size)) {
        USERPROC_WARN("echo string invalid.");
        ret = -EINVAL;
        goto out;
    }

    proc->current_cmd.pEntry = &(pstEntry->stInfo);

    USERPROC_K_UNLOCK(g_stUProcParam.stSem);

    /* Wait write data over */
    prepare_to_wait(&proc->wq_for_write, &wait, TASK_INTERRUPTIBLE);
    schedule();
    finish_wait(&proc->wq_for_write, &wait);

    /* if buffer not empty , try echo to current terminal */
    pstEntry = RBTree_Find_Proc_Entry(parent_name, entry_name);
    if (NULL != pstEntry && pstEntry->stInfo.pfnCmdFunc) {
        USERPROC_INFO("ump_seq_write: proc=%p, entry=%s %d bytes\n", proc, entry_name, (int)size);

        USERPROC_K_LOCK(g_stUProcParam.stSemReadWrite);
        if (pstEntry->stInfo.Write) {
            if (strlen((char *)pstEntry->stInfo.Write)) {
                printk("%s", (char *)pstEntry->stInfo.Write);
            }

            kfree(pstEntry->stInfo.Write);
            pstEntry->stInfo.Write = NULL;
        }
        USERPROC_K_UNLOCK(g_stUProcParam.stSemReadWrite);
    }

    return size;

out:
    USERPROC_K_UNLOCK(g_stUProcParam.stSem);
    return ret;
}

UMP_DIR_S *PROC_AddDir(const char *pszName, const char *pszParent, struct file *pstFile) {
    UMP_DIR_S *pstDir;

    /* Check parameter */
    if ((NULL == pszName) || (strlen(pszName) == 0) || (strlen(pszName) > MAX_PROC_NAME_LEN)) {
        USERPROC_ERR("Invalid name\n");
        return NULL;
    }

    /* Find directory node, if exist, return success directlly */
    pstDir = RBTree_Find_Dirent(NULL, pszName);
    if (NULL != pstDir) {
        USERPROC_INFO("Dir %s exist\n", pszName);
        return pstDir;
    }

    /* Alloc directory resource */
    pstDir = kmalloc(sizeof(UMP_DIR_S), GFP_KERNEL);
    if (NULL == pstDir) {
        USERPROC_ERR("kmalloc fail\n");
        return NULL;
    }

    /* Init directory parameter */
    snprintf(pstDir->dir_name, sizeof(pstDir->dir_name), "%s", pszName);
    pstDir->dir_name_hash = full_name_hash(NULL, pszName, strlen(pszName)) & 0x7fffffffU;
    pstDir->entry_root = RB_ROOT;
    pstDir->parent = NULL;
    pstDir->pstFile = pstFile;

    /* Make proc directory */
    pstDir->entry = proc_mkdir(pstDir->dir_name, g_pUser_proc);
    if (NULL == pstDir->entry) {
        USERPROC_ERR("proc_mkdir fail\n");
        goto out1;
    }

    /* Add directory to rbtree */
    if (USERPROC_SUCCESS != RBTree_Insert_Dirent(NULL, pstDir)) {
        USERPROC_ERR("Insert new dirent failed.\n");
        goto out2;
    }

    return pstDir;

out2:
    remove_proc_entry(pstDir->dir_name, g_pUser_proc);

out1:
    kfree(pstDir);

    return NULL;
}

int32_t PROC_RemoveDir(UMP_DIR_S *pstDir) {
    /* Check parameter */
    if (NULL == pstDir) {
        USERPROC_ERR("Invalid name\n");
        return USERPROC_FAILURE;
    }

    /* If there are entries in this directory, remove fail */
    if (pstDir->entry_root.rb_node) {
        USERPROC_ERR("dir %s non-null\n", pstDir->dir_name);
        return USERPROC_FAILURE;
    }

    /* Remove proc directory */
    remove_proc_entry(pstDir->dir_name, g_pUser_proc);

    /* Remove directory from rbtree */
    RBTree_Erase_Dirent(NULL, pstDir);

    /* Free directory resource */
    kfree(pstDir);

    return USERPROC_SUCCESS;
}

int32_t PROC_RemoveDirByName(const char *pszName) {
    char aszDir[MAX_PROC_NAME_LEN + 12];
    UMP_DIR_S *pstDir = NULL;

    /* Check parameter */
    if ((NULL == pszName) || (strlen(pszName) == 0) || (strlen(pszName) > MAX_PROC_NAME_LEN)) {
        USERPROC_ERR("Invalid name\n");
        return USERPROC_FAILURE;
    }

    /* Make directory name */
    snprintf(aszDir, sizeof(aszDir), "%s", pszName);

    /* Find directory node */
    pstDir = RBTree_Find_Dirent(NULL, aszDir);
    if (NULL == pstDir) {
        USERPROC_ERR("Find dir %s fail\n", aszDir);
        return USERPROC_FAILURE;
    }

    return PROC_RemoveDir(pstDir);
}

UMP_DIR_S *PROC_AddPrivateDir(const char *pszName, struct proc_dir_entry *pstEntry) {
    UMP_DIR_S *pstDir;

    /* Check parameter */
    if ((NULL == pszName) || (strlen(pszName) > MAX_PROC_NAME_LEN) || (NULL == pstEntry)) {
        goto out;
    }

    /* Alloc directory resource */
    pstDir = kmalloc(sizeof(UMP_DIR_S), GFP_KERNEL);
    if (NULL == pstDir) {
        USERPROC_ERR("kmalloc fail\n");
        goto out;
    }

    /* Init other parameter */
    strncpy(pstDir->dir_name, pszName, sizeof(pstDir->dir_name) - 1);
    pstDir->dir_name_hash = full_name_hash(NULL, pszName, strlen(pszName)) & 0x7fffffffU;
    pstDir->entry_root = RB_ROOT;
    pstDir->entry = pstEntry;
    pstDir->parent = NULL;
    pstDir->pstFile = NULL;

    /* Add directory to rbtree */
    if (USERPROC_SUCCESS != RBTree_Insert_Dirent(NULL, pstDir)) {
        USERPROC_ERR("Insert new dirent failed.\n");
        goto out1;
    }

    return pstDir;

out1:

    kfree(pstDir);

out:

    return NULL;
}

int32_t PROC_RemovePrivateDir(const char *pszName) {
    UMP_DIR_S *pstDir = NULL;

    /* Check parameter */
    if (NULL == pszName) {
        return USERPROC_FAILURE;
    }

    /* Find directory node */
    pstDir = RBTree_Find_Dirent(NULL, pszName);
    if (NULL == pstDir) {
        USERPROC_ERR("Find dir %s fail\n", pszName);
        return USERPROC_FAILURE;
    }

    /* Remove directory from rbtree */
    RBTree_Erase_Dirent(NULL, pstDir);

    /* Free directory resource */
    kfree(pstDir);

    return USERPROC_SUCCESS;
}

UMP_ENTRY_S *PROC_AddEntry(const USERPROC_USRMODEPROC_ENTRY_S *pstParam, bool bUsrMode) {
    UMP_ENTRY_S *pstEntry = NULL;
    UMP_DIR_S *pstDir = NULL;
    char aszDir[MAX_PROC_NAME_LEN + 12];
    uint32_t u32EntryLen;

    /* Check parameter */
    if (NULL == pstParam) {
        return NULL;
    }

    u32EntryLen = strlen(pstParam->aszName);
    if ((0 == u32EntryLen) || (u32EntryLen > MAX_PROC_NAME_LEN)) {
        USERPROC_ERR("Invalid name\n");
        return NULL;
    }

    /* Make parent directory name */
    if (0 == strlen(pstParam->aszParent)) {
        strncpy(aszDir, "userproc", sizeof(aszDir) - 1);
    } else {
        snprintf(aszDir, sizeof(aszDir), "%s", pstParam->aszParent);
    }

    /* Find directory node, if don't exist, return fail */
    pstDir = RBTree_Find_Dirent(NULL, aszDir);
    if (NULL == pstDir) {
        USERPROC_ERR("Dir %s don't exist\n", pstParam->aszParent);
        goto out;
    }

    /* Find entry in the directory, if exist, return success directlly */
    pstEntry = RBTree_Find_Entry(pstDir, pstParam->aszName);
    if (NULL != pstEntry) {
        USERPROC_INFO("Entry %s exist\n", pstParam->aszName);
        goto out;
    }

    /* Alloc entry resource */
    pstEntry = kmalloc(sizeof(UMP_ENTRY_S), GFP_KERNEL);
    if (NULL == pstEntry) {
        USERPROC_ERR("kmalloc fail\n");
        goto out;
    }
    memset(pstEntry, 0, sizeof(UMP_ENTRY_S));

    /* Create proc entry - attach file's private_data as entry data when
     * available
     */
    {
        void *entry_data = NULL;
        if (pstParam->pFile) {
            struct file *f = (struct file *)pstParam->pFile;
            /* Only accept device file created by this driver */
            if (f->f_op == &userproc_usrmodeproc_fops) {
                entry_data = f->private_data;
                if (NULL == entry_data) {
                    USERPROC_ERR("create_proc_entry: device file private_data is NULL\n");
                    goto out1;
                }
            } else {
                USERPROC_ERR("create_proc_entry: pFile is not "
                             "userproc_usrmodeproc device\n");
                goto out1;
            }
        } else {
            USERPROC_ERR("create_proc_entry: pFile is NULL\n");
            goto out1;
        }

        pstEntry->stInfo.pEntry = proc_create_data(pstParam->aszName, 0, pstDir->entry, &ump_seq_ops, entry_data);
        if (NULL == pstEntry->stInfo.pEntry) {
            USERPROC_FATAL("create_proc_entry fail\n");
            goto out1;
        }
    }

    /* Init other parameter */
    strncpy(pstEntry->entry_name, pstParam->aszName, sizeof(pstEntry->entry_name) - 1);
    pstEntry->entry_name_hash = full_name_hash(NULL, pstParam->aszName, strlen(pstParam->aszName)) & 0x7fffffffU;
    pstEntry->parent = pstDir->entry;

    pstEntry->stInfo.pFile = pstParam->pFile;
    pstEntry->stInfo.pfnShowFunc = pstParam->pfnShowFunc;
    pstEntry->stInfo.pfnCmdFunc = pstParam->pfnCmdFunc;
    pstEntry->stInfo.pPrivData = pstParam->pPrivData;
    pstEntry->stInfo.Read = NULL;
    pstEntry->stInfo.Write = NULL;

    /* Add entry to rbtree */
    if (USERPROC_SUCCESS != RBTree_Insert_Entry(pstDir, pstEntry)) {
        USERPROC_ERR("Insert new file entry failed.\n");
        goto out2;
    }

    return pstEntry;

out2:
    remove_proc_entry(pstEntry->entry_name, pstEntry->parent);
out1:
    kfree(pstEntry);
out:
    return NULL;
}

void PROC_RemoveEntry(UMP_DIR_S *pstDir, UMP_ENTRY_S *pstEntry) {
    /* Check parameter */
    if (NULL == pstEntry || NULL == pstDir) {
        return;
    }

    /* Remove proc entry */
    remove_proc_entry(pstEntry->entry_name, pstEntry->parent);

    if (NULL != pstEntry->stInfo.Read) {
        kfree(pstEntry->stInfo.Read);
        pstEntry->stInfo.Read = NULL;
    }

    if (NULL != pstEntry->stInfo.Write) {
        kfree(pstEntry->stInfo.Write);
        pstEntry->stInfo.Write = NULL;
    }

    /* Remove entry from rbtree */
    RBTree_Erase_Entry(pstDir, pstEntry);

    /* If current command belongs to this entry, clear it. */
    if (g_stUProcParam.current_cmd.pEntry == (void *)&(pstEntry->stInfo)) {
        g_stUProcParam.current_cmd.pEntry = NULL;
        memset(&g_stUProcParam.current_cmd, 0, sizeof(g_stUProcParam.current_cmd));
    }

    /* Free resource */
    kfree(pstEntry);

    return;
}

int32_t PROC_RemoveEntryByName(const char *pszName, const char *pszParent) {
    UMP_ENTRY_S *pstEntry = NULL;
    UMP_DIR_S *pstDir = NULL;
    char aszDir[MAX_PROC_NAME_LEN + 12];

    /* Check parameter */
    if ((NULL == pszName) || (strlen(pszName) > MAX_PROC_NAME_LEN)) {
        USERPROC_ERR("Invalid name\n");
        return USERPROC_FAILURE;
    }
    if ((NULL == pszParent) || (strlen(pszParent) > MAX_PROC_NAME_LEN)) {
        USERPROC_ERR("Invalid parent name\n");
        return USERPROC_FAILURE;
    }

    /* Make parent directory name */
    if (0 == strlen(pszParent)) {
        strncpy(aszDir, "userproc", sizeof(aszDir) - 1);
    } else {
        snprintf(aszDir, sizeof(aszDir), "%s", pszParent);
    }

    /* Find directory node, if don't exist, return fail */
    pstDir = RBTree_Find_Dirent(NULL, aszDir);
    if (NULL == pstDir) {
        USERPROC_ERR("Dir %s don't exist\n", pszParent);
        return USERPROC_FAILURE;
    }

    /* Find entry in the directory, if don't exist, return fail */
    pstEntry = RBTree_Find_Entry(pstDir, pszName);
    if (NULL == pstEntry) {
        USERPROC_WARN("Entry %s don't exist\n", pszName);
        return USERPROC_FAILURE;
    }

    /* Remove entry */
    PROC_RemoveEntry(pstDir, pstEntry);

    return USERPROC_SUCCESS;
}

void PROC_RemoveDirForcibly(UMP_DIR_S *pstDir) {
    struct rb_node *node;
    UMP_ENTRY_S *this;

    /* Check parameter */
    if (NULL == pstDir) {
        return;
    }

    while (pstDir->entry_root.rb_node) {
        node = rb_first(&(pstDir->entry_root));
        this = rb_entry(node, UMP_ENTRY_S, node);
        PROC_RemoveEntry(pstDir, this);
    }

    PROC_RemoveDir(pstDir);
}

static const struct proc_ops ump_seq_ops = {
    .proc_open = ump_seq_open,
    .proc_read = seq_read,
    .proc_write = ump_seq_write,
    .proc_lseek = seq_lseek,
    .proc_release = ump_seq_release,
};

long userproc_usrmodeproc_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int32_t ret = USERPROC_SUCCESS;
    UMP_PARAM_S *proc = file->private_data;
    USERPROC_USRMODEPROC_ENTRY_S ump_entry;
    char aszName[MAX_PROC_NAME_LEN + 1];
    UMP_DIR_S *pstDir;
    UMP_ENTRY_S *pstEntry;
    USERPROC_USRMODEPROC_CMDINFO_S *pstCmdInfo;

    switch (cmd) {
    case USERPROCIOC_ADD_ENTRY: {
        if (copy_from_user(&ump_entry, (void __user *)arg, sizeof(ump_entry))) {
            ret = USERPROC_FAILURE;
            break;
        }
        ump_entry.aszName[sizeof(ump_entry.aszName) - 1] = 0;
        ump_entry.aszParent[sizeof(ump_entry.aszParent) - 1] = 0;
        ump_entry.pFile = (void *)file;

        USERPROC_K_LOCK(g_stUProcParam.stSem);
        pstEntry = PROC_AddEntry(&ump_entry, true);
        USERPROC_K_UNLOCK(g_stUProcParam.stSem);
        if (NULL == pstEntry) {
            ret = USERPROC_FAILURE;
            break;
        }

        /* proc entry data set via proc_create_data at creation time */

        break;
    }

    case USERPROCIOC_REMOVE_ENTRY: {
        if (copy_from_user(&ump_entry, (void __user *)arg, sizeof(ump_entry))) {
            ret = USERPROC_FAILURE;
            break;
        }
        ump_entry.aszName[sizeof(ump_entry.aszName) - 1] = 0;
        ump_entry.aszParent[sizeof(ump_entry.aszParent) - 1] = 0;

        USERPROC_K_LOCK(g_stUProcParam.stSem);
        /* Removed by name now, can be removed by ump_entry.pEntry  */
        ret = PROC_RemoveEntryByName((char *)ump_entry.aszName, (char *)ump_entry.aszParent);
        USERPROC_K_UNLOCK(g_stUProcParam.stSem);
        break;
    }

    case USERPROCIOC_ADD_DIR: {
        char *ptrDirName = aszName;
        if (copy_from_user(ptrDirName, (void __user *)arg, sizeof(USERPROC_DIR_NAME_S))) {
            ret = USERPROC_FAILURE;
            break;
        }
        aszName[sizeof(aszName) - 1] = 0;

        USERPROC_K_LOCK(g_stUProcParam.stSem);
        pstDir = PROC_AddDir(aszName, NULL, file);
        if (NULL == pstDir) {
            ret = USERPROC_FAILURE;
        }
        USERPROC_K_UNLOCK(g_stUProcParam.stSem);
        break;
    }
    case USERPROCIOC_REMOVE_DIR: {
        char *ptrDirName = aszName;

        if (copy_from_user(ptrDirName, (void __user *)arg, sizeof(USERPROC_DIR_NAME_S))) {
            ret = USERPROC_FAILURE;
            break;
        }
        aszName[sizeof(aszName) - 1] = 0;

        USERPROC_K_LOCK(g_stUProcParam.stSem);
        ret = PROC_RemoveDirByName(aszName);
        USERPROC_K_UNLOCK(g_stUProcParam.stSem);
        break;
    }
    case USERPROCIOC_GETCMD: {
        pstCmdInfo = (USERPROC_USRMODEPROC_CMDINFO_S *)arg;

        USERPROC_K_LOCK(g_stUProcParam.stSem);
        /* If there is a command */
        if ((strlen(proc->current_cmd.aszCmd) > 0) &&
            /* and it must belong to a entry */
            (NULL != proc->current_cmd.pEntry) &&
            /* and the entry must belong to this file(this process). */
            ((void *)file == ((USERPROC_USRMODEPROC_ENTRY_S *)proc->current_cmd.pEntry)->pFile)) {
            if (copy_to_user((void __user *)&(pstCmdInfo->stCmd), &(proc->current_cmd),
                             sizeof(USERPROC_USRMODEPROC_CMD_S))) {
                USERPROC_K_UNLOCK(g_stUProcParam.stSem);
                return -EFAULT;
            }
            if (copy_to_user((void __user *)&(pstCmdInfo->stEntry), proc->current_cmd.pEntry,
                             sizeof(USERPROC_USRMODEPROC_ENTRY_S))) {
                USERPROC_K_UNLOCK(g_stUProcParam.stSem);
                return -EFAULT;
            }

            memset(proc->current_cmd.aszCmd, 0, sizeof(proc->current_cmd.aszCmd));
        }
        USERPROC_K_UNLOCK(g_stUProcParam.stSem);
        break;
    }

    case USERPROCIOC_WAKE_READ_TASK: {
        USERPROC_SHOW_BUFFER_S ShowBuf;
        USERPROC_USRMODEPROC_ENTRY_S *ProcEntry = (USERPROC_USRMODEPROC_ENTRY_S *)proc->current_cmd.pEntry;
        if (NULL == ProcEntry) {
            USERPROC_ERR("ProcEntry[0x%p] invalid!\n", ProcEntry);
            ret = USERPROC_FAILURE;
            break;
        }

        if (0 == copy_from_user(&ShowBuf, (void __user *)arg, sizeof(ShowBuf))) {
            if (ShowBuf.u32Size <= USERPROC_BUFFER_SIZE) {
                USERPROC_K_LOCK(g_stUProcParam.stSemReadWrite);
                ProcEntry->Read = kmalloc(ShowBuf.u32Size, GFP_KERNEL);
                if (ProcEntry->Read) {
                    if (copy_from_user(ProcEntry->Read, (void __user *)ShowBuf.pu8Buf, ShowBuf.u32Size)) {
                        kfree(ProcEntry->Read);
                        ProcEntry->Read = NULL;
                    }
                }
                USERPROC_K_UNLOCK(g_stUProcParam.stSemReadWrite);
            }
        }

        wake_up_interruptible(&(proc->wq_for_read));
        break;
    }

    case USERPROCIOC_WAKE_WRITE_TASK: {
        USERPROC_SHOW_BUFFER_S ShowBuf;
        USERPROC_USRMODEPROC_ENTRY_S *ProcEntry = (USERPROC_USRMODEPROC_ENTRY_S *)proc->current_cmd.pEntry;
        if (NULL == ProcEntry) {
            USERPROC_ERR("ProcEntry[0x%p] invalid!\n", ProcEntry);
            ret = USERPROC_FAILURE;
            break;
        }

        if (0 == copy_from_user(&ShowBuf, (void __user *)arg, sizeof(ShowBuf))) {
            if (ShowBuf.u32Size <= USERPROC_BUFFER_SIZE) {
                USERPROC_K_LOCK(g_stUProcParam.stSemReadWrite);
                ProcEntry->Write = kmalloc(ShowBuf.u32Size, GFP_KERNEL);
                if (ProcEntry->Write) {
                    if (copy_from_user(ProcEntry->Write, (void __user *)ShowBuf.pu8Buf, ShowBuf.u32Size)) {
                        kfree(ProcEntry->Write);
                        ProcEntry->Write = NULL;
                    }
                }
                USERPROC_K_UNLOCK(g_stUProcParam.stSemReadWrite);
            }
        }

        wake_up_interruptible(&(proc->wq_for_write));
        break;
    }

    default:
        ret = USERPROC_FAILURE;
        USERPROC_ERR("Unknow cmd[%#x]!\n", cmd);
        break;
    }

    return ret;
}

#ifdef CONFIG_COMPAT
long userproc_usrmodeproc_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int32_t ret = USERPROC_SUCCESS;
    UMP_PARAM_S *proc = file->private_data;
    UMP_ENTRY_S *pstEntry;
    USERPROC_USRMODEPROC_Compat_CMDINFO_S *pstCmdInfo;

    switch (cmd) {
    case USERPROCIOC_ADD_Compat_ENTRY: {
        USERPROC_USRMODEPROC_ENTRY_S ump_entry = {{0}};
        USERPROC_USRMODEPROC_Compat_ENTRY_S *compat_ump_entry;

        compat_ump_entry = kmalloc(sizeof(*compat_ump_entry), GFP_KERNEL);
        if (!compat_ump_entry) {
            ret = USERPROC_FAILURE;
            break;
        }

        if (copy_from_user(compat_ump_entry, (void __user *)arg, sizeof(*compat_ump_entry))) {
            ret = USERPROC_FAILURE;
            kfree(compat_ump_entry);
            break;
        }

        memcpy(ump_entry.aszName, compat_ump_entry->aszName, sizeof(ump_entry.aszName));
        memcpy(ump_entry.aszParent, compat_ump_entry->aszParent, sizeof(ump_entry.aszParent));
        ump_entry.aszName[sizeof(ump_entry.aszName) - 1] = 0;
        ump_entry.aszParent[sizeof(ump_entry.aszParent) - 1] = 0;
        ump_entry.pfnShowFunc = (USERPROC_SHOW_FN)compat_ump_entry->pfnShowFunc;
        ump_entry.pfnCmdFunc = (USERPROC_CMD_FN)compat_ump_entry->pfnCmdFunc;
        ump_entry.pPrivData = compat_ump_entry->pPrivData;
        ump_entry.pEntry = compat_ump_entry->pEntry;
        ump_entry.pFile = (void *)file;
        ump_entry.Read = compat_ump_entry->Read;
        ump_entry.Write = compat_ump_entry->Write;

        kfree(compat_ump_entry);

        USERPROC_K_LOCK(g_stUProcParam.stSem);
        pstEntry = PROC_AddEntry(&ump_entry, true);
        USERPROC_K_UNLOCK(g_stUProcParam.stSem);
        if (NULL == pstEntry) {
            ret = USERPROC_FAILURE;
            break;
        }

        break;
    }

    case USERPROCIOC_REMOVE_Compat_ENTRY: {
        USERPROC_USRMODEPROC_ENTRY_S ump_entry = {{0}};
        USERPROC_USRMODEPROC_Compat_ENTRY_S *compat_ump_entry;

        compat_ump_entry = kmalloc(sizeof(*compat_ump_entry), GFP_KERNEL);
        if (!compat_ump_entry) {
            ret = USERPROC_FAILURE;
            break;
        }

        if (copy_from_user(compat_ump_entry, (void __user *)arg, sizeof(*compat_ump_entry))) {
            ret = USERPROC_FAILURE;
            kfree(compat_ump_entry);
            break;
        }
        memcpy(ump_entry.aszName, compat_ump_entry->aszName, sizeof(ump_entry.aszName));
        memcpy(ump_entry.aszParent, compat_ump_entry->aszParent, sizeof(ump_entry.aszParent));
        ump_entry.aszName[sizeof(ump_entry.aszName) - 1] = 0;
        ump_entry.aszParent[sizeof(ump_entry.aszParent) - 1] = 0;
        ump_entry.pfnShowFunc = (USERPROC_SHOW_FN)compat_ump_entry->pfnShowFunc;
        ump_entry.pfnCmdFunc = (USERPROC_CMD_FN)compat_ump_entry->pfnCmdFunc;
        ump_entry.pPrivData = compat_ump_entry->pPrivData;
        ump_entry.pEntry = compat_ump_entry->pEntry;
        ump_entry.pFile = (void *)file;
        ump_entry.Read = compat_ump_entry->Read;
        ump_entry.Write = compat_ump_entry->Write;

        kfree(compat_ump_entry);

        USERPROC_K_LOCK(g_stUProcParam.stSem);
        ret = PROC_RemoveEntryByName((char *)ump_entry.aszName, (char *)ump_entry.aszParent);
        USERPROC_K_UNLOCK(g_stUProcParam.stSem);
        break;
    }

    case USERPROCIOC_Compat_GETCMD: {
        pstCmdInfo = (USERPROC_USRMODEPROC_Compat_CMDINFO_S *)arg;

        USERPROC_K_LOCK(g_stUProcParam.stSem);
        if ((strlen(proc->current_cmd.aszCmd) > 0) && (NULL != proc->current_cmd.pEntry) &&
            ((void *)file == ((USERPROC_USRMODEPROC_ENTRY_S *)proc->current_cmd.pEntry)->pFile)) {
            USERPROC_USRMODEPROC_Compat_CMD_S *TmpCmdInfo;
            USERPROC_USRMODEPROC_Compat_ENTRY_S *TmpEntryInfo;

            TmpCmdInfo = kmalloc(sizeof(*TmpCmdInfo), GFP_KERNEL);
            TmpEntryInfo = kmalloc(sizeof(*TmpEntryInfo), GFP_KERNEL);
            if (!TmpCmdInfo || !TmpEntryInfo) {
                kfree(TmpCmdInfo);
                kfree(TmpEntryInfo);
                USERPROC_K_UNLOCK(g_stUProcParam.stSem);
                return -EFAULT;
            }

            memset(TmpCmdInfo, 0, sizeof(*TmpCmdInfo));
            memset(TmpEntryInfo, 0, sizeof(*TmpEntryInfo));

            memcpy(TmpCmdInfo->aszCmd, proc->current_cmd.aszCmd, sizeof(proc->current_cmd.aszCmd));

            if (copy_to_user((void __user *)&(pstCmdInfo->stCmd), TmpCmdInfo,
                             sizeof(USERPROC_USRMODEPROC_Compat_CMD_S))) {
                kfree(TmpCmdInfo);
                kfree(TmpEntryInfo);
                USERPROC_K_UNLOCK(g_stUProcParam.stSem);
                return -EFAULT;
            }

            TmpEntryInfo->pfnShowFunc = ((USERPROC_USRMODEPROC_ENTRY_S *)proc->current_cmd.pEntry)->pfnShowFunc;
            TmpEntryInfo->pfnCmdFunc = ((USERPROC_USRMODEPROC_ENTRY_S *)proc->current_cmd.pEntry)->pfnCmdFunc;
            TmpEntryInfo->pPrivData = ((USERPROC_USRMODEPROC_ENTRY_S *)proc->current_cmd.pEntry)->pPrivData;

            if (copy_to_user((void __user *)&(pstCmdInfo->stEntry), TmpEntryInfo,
                             sizeof(USERPROC_USRMODEPROC_Compat_ENTRY_S))) {
                kfree(TmpCmdInfo);
                kfree(TmpEntryInfo);
                USERPROC_K_UNLOCK(g_stUProcParam.stSem);
                return -EFAULT;
            }

            memset(proc->current_cmd.aszCmd, 0, sizeof(proc->current_cmd.aszCmd));
            kfree(TmpCmdInfo);
            kfree(TmpEntryInfo);
        }
        USERPROC_K_UNLOCK(g_stUProcParam.stSem);
        break;
    }

    case USERPROCIOC_Compat_WAKE_READ_TASK: {
        USERPROC_Compat_SHOW_BUFFER_S ShowBuf;
        USERPROC_USRMODEPROC_ENTRY_S *ProcEntry = (USERPROC_USRMODEPROC_ENTRY_S *)proc->current_cmd.pEntry;
        if (NULL == ProcEntry) {
            USERPROC_ERR("ProcEntry[0x%p] invalid!\n", ProcEntry);
            ret = USERPROC_FAILURE;
            break;
        }

        if (0 == copy_from_user(&ShowBuf, (void __user *)arg, sizeof(ShowBuf))) {
            if (ShowBuf.u32Size <= USERPROC_BUFFER_SIZE) {
                USERPROC_K_LOCK(g_stUProcParam.stSemReadWrite);
                ProcEntry->Read = kmalloc(ShowBuf.u32Size, GFP_KERNEL);
                if (ProcEntry->Read) {
                    if (copy_from_user(ProcEntry->Read, (void __user *)compat_ptr(ShowBuf.pu8Buf), ShowBuf.u32Size)) {
                        kfree(ProcEntry->Read);
                        ProcEntry->Read = NULL;
                    }
                }
                USERPROC_K_UNLOCK(g_stUProcParam.stSemReadWrite);
            }
        }

        wake_up_interruptible(&(proc->wq_for_read));
        break;
    }

    case USERPROCIOC_Compat_WAKE_WRITE_TASK: {
        USERPROC_Compat_SHOW_BUFFER_S ShowBuf;
        USERPROC_USRMODEPROC_ENTRY_S *ProcEntry = (USERPROC_USRMODEPROC_ENTRY_S *)proc->current_cmd.pEntry;
        if (NULL == ProcEntry) {
            USERPROC_ERR("ProcEntry[0x%p] invalid!\n", ProcEntry);
            ret = USERPROC_FAILURE;
            break;
        }

        if (0 == copy_from_user(&ShowBuf, (void __user *)arg, sizeof(ShowBuf))) {
            if (ShowBuf.u32Size <= USERPROC_BUFFER_SIZE) {
                USERPROC_K_LOCK(g_stUProcParam.stSemReadWrite);
                ProcEntry->Write = kmalloc(ShowBuf.u32Size, GFP_KERNEL);
                if (ProcEntry->Write) {
                    if (copy_from_user(ProcEntry->Write, (void __user *)compat_ptr(ShowBuf.pu8Buf), ShowBuf.u32Size)) {
                        kfree(ProcEntry->Write);
                        ProcEntry->Write = NULL;
                    }
                }
                USERPROC_K_UNLOCK(g_stUProcParam.stSemReadWrite);
            }
        }

        wake_up_interruptible(&(proc->wq_for_write));
        break;
    }

    default:
        return userproc_usrmodeproc_ioctl(file, cmd, arg);
    }

    return ret;
}
#endif

static struct file_operations userproc_usrmodeproc_fops = {
    .open = userproc_usrmodeproc_open,
    .release = userproc_usrmodeproc_close,
    .unlocked_ioctl = userproc_usrmodeproc_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = userproc_usrmodeproc_compat_ioctl,
#endif
};

static struct miscdevice userproc_usrmodeproc_dev = {MISC_DYNAMIC_MINOR, USERPROC_DEVNAME, &userproc_usrmodeproc_fops};

static int __init USRPROC_DRV_init_module(void) {
    int32_t ret;

    ret = misc_register(&userproc_usrmodeproc_dev);
    if (ret) {
        USERPROC_ERR("%s device register failed\n", USERPROC_DEVNAME);
        return ret;
    }

    g_pUser_proc = proc_mkdir("userproc", NULL);
    if (!g_pUser_proc) {
        USERPROC_ERR("create /proc/userproc failed\n");
        ret = -1;
        goto out;
    }

    g_pstUserDirent = PROC_AddPrivateDir("userproc", g_pUser_proc);
    if (!g_pstUserDirent) {
        USERPROC_ERR("add 'userproc' directory failed.\n");
        ret = -1;
        goto out;
    }

    return ret;

out:
    misc_deregister(&userproc_usrmodeproc_dev);
    return ret;
}

static void __exit USRPROC_DRV_cleanup_module(void) {
    if (g_pstUserDirent) {
        PROC_RemovePrivateDir(g_pstUserDirent->dir_name);
        g_pstUserDirent = NULL;
    }

    remove_proc_entry("userproc", NULL);
    g_pUser_proc = NULL;

    misc_deregister(&userproc_usrmodeproc_dev);
}

module_init(USRPROC_DRV_init_module);
module_exit(USRPROC_DRV_cleanup_module);

MODULE_AUTHOR("qiaoqm@aliyun.com");
MODULE_DESCRIPTION("User Mode Proc Driver");
MODULE_LICENSE("GPL v2");
