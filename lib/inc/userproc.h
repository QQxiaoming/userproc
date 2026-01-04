#ifndef _USERPROC_H_
#define _USERPROC_H_

#include <stdint.h>

#define MAX_PROC_NAME_LEN 127

typedef int32_t (*userproc_show_fn)(void *showBuffer, void *privData);
typedef int32_t (*userproc_cmd_fn)(void *showBuffer, uint32_t argc, uint8_t *argv[], void *privData);

typedef struct {
    char aszName[MAX_PROC_NAME_LEN + 1];   /* Input, entry name */
    char aszParent[MAX_PROC_NAME_LEN + 1]; /* Input, directory name */
    userproc_show_fn pfnShowFunc;          /* Input, show function */
    userproc_cmd_fn pfnCmdFunc;            /* Input, cmd function */
    void *pPrivData;                       /* Input, private data*/
    void *pEntry;                          /* Output, entry pointer */
    void *pFile;                           /* Output, Belongs to which file */
    void *Read;                            /* Read Buffer */
    void *Write;                           /* Write Buffer */
} userproc_entry_t;

int userproc_init(void);
int userproc_deinit(void);
int userproc_add_dir(const char *dir_name);
int userproc_remove_dir(const char *dir_name);
int userproc_add_entry(userproc_entry_t *entry);
int userproc_remove_entry(userproc_entry_t *entry);
int userproc_printf(void *showBuffer, const char *fmt, ...);

#endif /* _USERPROC_H_ */
