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
    (void)priv;
    if (!showBuffer) {
        return -1;
    }

    if (argc == 0) {
        userproc_printf(showBuffer, "no arguments\n");
        return 0;
    }

    /* If first arg is "echo", join remaining args and print them */
    if (argv[0] && strcmp((char *)argv[0], "echo") == 0) {
        for (uint32_t i = 1; i < argc; ++i) {
            userproc_printf(showBuffer, "%s", (char *)argv[i]);
            if (i + 1 < argc)
                userproc_printf(showBuffer, " ");
        }
        userproc_printf(showBuffer, "\n");
        return 0;
    }

    /* Default: print argc and each argument on its own line */
    userproc_printf(showBuffer, "argc=%u\n", argc);
    for (uint32_t i = 0; i < argc; ++i) {
        userproc_printf(showBuffer, "arg %u: %s\n", i, argv[i] ? (char *)argv[i] : "(null)");
    }

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