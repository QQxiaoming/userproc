#include "userproc.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int32_t test_show_func(void *showBuffer, void *priv) {
    static int index = 0;
    const char *msg = "user-app log line: hello from test_show_func";
    return userproc_printf(showBuffer, "%s-%d\n", msg, index++);
}

static int32_t test_cmd_func(void *showBuffer, uint32_t argc, uint8_t *argv[], void *priv) {
    return 0;
}

int main(void) {
    userproc_init();

    userproc_add_dir("test");

    userproc_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.aszName, "userlog", sizeof(entry.aszName) - 1);
    strncpy(entry.aszParent, "test", sizeof(entry.aszParent) - 1);
    entry.pfnShowFunc = test_show_func;
    entry.pfnCmdFunc = test_cmd_func;
    entry.pPrivData = NULL;
    userproc_add_entry(&entry);

    printf("registered entry /proc/userproc/test/%s\n", entry.aszName);

    for (;;) {
    }

    userproc_remove_entry(&entry);

    userproc_remove_dir("test");

    userproc_deinit();

    return 0;
}