#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "uproc.h"
#include "userproc.h"

static int g_fd = -1;
static pthread_t g_thread;
static int g_running = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* simple linked list to track added entries (so we can remove them on deinit) */
struct entry_node {
    USERPROC_USRMODEPROC_ENTRY_S entry;
    struct entry_node *next;
};

static struct entry_node *g_entries = NULL;

static void add_entry_node(const USERPROC_USRMODEPROC_ENTRY_S *e) {
    struct entry_node *n = calloc(1, sizeof(*n));
    if (!n)
        return;
    memcpy(&n->entry, e, sizeof(n->entry));
    pthread_mutex_lock(&g_lock);
    n->next = g_entries;
    g_entries = n;
    pthread_mutex_unlock(&g_lock);
}

static void remove_all_entries(void) {
    struct entry_node *it, *tmp;
    pthread_mutex_lock(&g_lock);
    it = g_entries;
    g_entries = NULL;
    pthread_mutex_unlock(&g_lock);
    while (it) {
        tmp = it->next;
        free(it);
        it = tmp;
    }
}

static void *worker_thread(void *arg) {
    (void)arg;
    while (g_running) {
        USERPROC_USRMODEPROC_CMDINFO_S info;
        memset(&info, 0, sizeof(info));

        if (ioctl(g_fd, USERPROCIOC_GETCMD, &info) != 0) {
            /* no cmd, sleep briefly */
            usleep(200000);
            continue;
        }

        if (strlen(info.stCmd.aszCmd) == 0 || info.stCmd.pEntry == NULL) {
            continue;
        }

        /* If it's a read request, call the provided show func and wake read task */
        if (strcmp(info.stCmd.aszCmd, USERPROC_READ_CMD) == 0) {
            USERPROC_SHOW_BUFFER_S sb;
            memset(&sb, 0, sizeof(sb));
            sb.u32Size = 4096;
            sb.pu8Buf = malloc(sb.u32Size);
            USERPROC_SHOW_FN fn = (USERPROC_SHOW_FN)info.stEntry.pfnShowFunc;
            if (fn) {
                if (fn(&sb, info.stEntry.pPrivData) == 0 && sb.u32Size && sb.pu8Buf) {
                    USERPROC_SHOW_BUFFER_S send = {sb.pu8Buf, sb.u32Size, 0};
                    if (ioctl(g_fd, USERPROCIOC_WAKE_READ_TASK, &send) != 0) {
                        perror("USERPROCIOC_WAKE_READ_TASK");
                    }
                }
            }
            free(sb.pu8Buf);
        } else {
            /* other command: call cmd func if available and wake read task with result */
            USERPROC_SHOW_BUFFER_S sb;
            memset(&sb, 0, sizeof(sb));
            sb.u32Size = 4096;
            sb.pu8Buf = malloc(sb.u32Size);
            USERPROC_CMD_FN fn = (USERPROC_CMD_FN)info.stEntry.pfnCmdFunc;
            if (fn) {
                if (fn(&sb, 0, NULL, info.stEntry.pPrivData) == 0 && sb.u32Size && sb.pu8Buf) {
                    USERPROC_SHOW_BUFFER_S send = {sb.pu8Buf, sb.u32Size, 0};
                    ioctl(g_fd, USERPROCIOC_WAKE_READ_TASK, &send);
                }
            }
            free(sb.pu8Buf);
        }
    }
    return NULL;
}

int userproc_init(void) {
    if (g_fd >= 0)
        return 0; /* already initialized */
    g_fd = open("/dev/userproc", O_RDWR);
    if (g_fd < 0) {
        perror("open /dev/userproc");
        g_fd = -1;
        return -1;
    }

    g_running = 1;
    if (pthread_create(&g_thread, NULL, worker_thread, NULL) != 0) {
        perror("pthread_create");
        close(g_fd);
        g_fd = -1;
        g_running = 0;
        return -1;
    }

    return 0;
}

int userproc_deinit(void) {
    if (g_fd < 0)
        return 0;
    g_running = 0;
    pthread_join(g_thread, NULL);

    /* remove registered entries */
    pthread_mutex_lock(&g_lock);
    struct entry_node *it = g_entries;
    while (it) {
        /* best-effort remove via ioctl */
        ioctl(g_fd, USERPROCIOC_REMOVE_ENTRY, &it->entry);
        it = it->next;
    }
    pthread_mutex_unlock(&g_lock);
    remove_all_entries();

    close(g_fd);
    g_fd = -1;
    return 0;
}

int userproc_add_dir(const char *dir_name) {
    if (g_fd < 0)
        return -1;
    if (!dir_name)
        return -1;
    /* driver expects a fixed-size name buffer; pass pointer to string */
    if (ioctl(g_fd, USERPROCIOC_ADD_DIR, (void *)dir_name) != 0) {
        perror("USERPROCIOC_ADD_DIR");
        return -1;
    }
    return 0;
}

int userproc_remove_dir(const char *dir_name) {
    if (g_fd < 0)
        return -1;
    if (!dir_name)
        return -1;
    if (ioctl(g_fd, USERPROCIOC_REMOVE_DIR, (void *)dir_name) != 0) {
        perror("USERPROCIOC_REMOVE_DIR");
        return -1;
    }
    return 0;
}

int userproc_add_entry(userproc_entry_t *entry) {
    if (g_fd < 0 || !entry)
        return -1;
    USERPROC_USRMODEPROC_ENTRY_S *e = (USERPROC_USRMODEPROC_ENTRY_S *)entry;
    if (ioctl(g_fd, USERPROCIOC_ADD_ENTRY, e) != 0) {
        perror("USERPROCIOC_ADD_ENTRY");
        return -1;
    }
    add_entry_node(e);
    return 0;
}

int userproc_remove_entry(userproc_entry_t *entry) {
    if (g_fd < 0 || !entry)
        return -1;
    USERPROC_USRMODEPROC_ENTRY_S *e = (USERPROC_USRMODEPROC_ENTRY_S *)entry;
    if (ioctl(g_fd, USERPROCIOC_REMOVE_ENTRY, e) != 0) {
        perror("USERPROCIOC_REMOVE_ENTRY");
        /* continue to remove from list */
    }

    /* remove from local list */
    pthread_mutex_lock(&g_lock);
    struct entry_node **pp = &g_entries;
    while (*pp) {
        if (strncmp((*pp)->entry.aszName, e->aszName, sizeof(e->aszName)) == 0 &&
            strncmp((*pp)->entry.aszParent, e->aszParent, sizeof(e->aszParent)) == 0) {
            struct entry_node *t = *pp;
            *pp = t->next;
            free(t);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&g_lock);
    return 0;
}

int userproc_printf(void *showBuffer, const char *fmt, ...) {
    if (!showBuffer || !fmt)
        return -1;

    USERPROC_SHOW_BUFFER_S *sb = (USERPROC_SHOW_BUFFER_S *)showBuffer;
    if (sb->pu8Buf == NULL || sb->u32Size == 0) {
        return -1;
    }
    char *buf = (char *)sb->pu8Buf;
    buf += sb->u32Offset;
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, sb->u32Size - sb->u32Offset, fmt, args);
    va_end(args);
    if (n < 0) {
        return -1;
    }
    sb->u32Offset += n;
    return 0;
}
