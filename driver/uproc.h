#ifndef __DRV_USERPROC_IOCTL_H__
#define __DRV_USERPROC_IOCTL_H__

#define MAX_PROC_NAME_LEN    127
#define MAX_PROC_CMD_LEN     255
#define USERPROC_READ_CMD    "__read"
#define USERPROC_BUFFER_SIZE 4096
#define USERPROC_ID          0x1

#define USERPROC_SUCCESS 0
#define USERPROC_FAILURE -1

typedef struct {
    uint8_t *pu8Buf;    /**<Buffer address*/
    uint32_t u32Size;   /**<Buffer size*/
    uint32_t u32Offset; /**<Print Offset*/
} USERPROC_SHOW_BUFFER_S;

typedef int32_t (*USERPROC_SHOW_FN)(USERPROC_SHOW_BUFFER_S *showBuffer, void *privData);
typedef int32_t (*USERPROC_CMD_FN)(USERPROC_SHOW_BUFFER_S *showBuffer, uint32_t argc, uint8_t *argv[], void *privData);

typedef struct {
    char aszName[MAX_PROC_NAME_LEN + 1];   /* Input, entry name */
    char aszParent[MAX_PROC_NAME_LEN + 1]; /* Input, directory name */
    USERPROC_SHOW_FN pfnShowFunc;          /* Input, show function */
    USERPROC_CMD_FN pfnCmdFunc;            /* Input, cmd function */
    void *pPrivData;                       /* Input, private data*/
    void *pEntry;                          /* Output, entry pointer */
    void *pFile;                           /* Output, Belongs to which file */
    void *Read;                            /* Read Buffer */
    void *Write;                           /* Write Buffer */
} USERPROC_USRMODEPROC_ENTRY_S;

/* compat define for USERPROC_USRMODEPROC_ENTRY_S. */
typedef struct {
    char aszName[MAX_PROC_NAME_LEN + 1];   /* Input, entry name */
    char aszParent[MAX_PROC_NAME_LEN + 1]; /* Input, directory name */
    void *pfnShowFunc;                     /* Input, show function */
    void *pfnCmdFunc;                      /* Input, cmd function */
    void *pPrivData;                       /* Input, private data*/
    void *pEntry;                          /* Output, entry pointer */
    void *pFile;                           /* Output, Belongs to which file */
    void *Read;                            /* Read Buffer */
    void *Write;                           /* Write Buffer */
} USERPROC_USRMODEPROC_Compat_ENTRY_S;

typedef struct {
    void *pEntry; /* The type is USERPROC_USRMODEPROC_ENTRY_S* */
    int32_t s32Write;
    char aszCmd[MAX_PROC_CMD_LEN + 1];
} USERPROC_USRMODEPROC_CMD_S;

/* compat define for USERPROC_USRMODEPROC_CMD_S. */
typedef struct {
    uint32_t pEntry; /* The type is USERPROC_USRMODEPROC_ENTRY_S* */
    int32_t s32Write;
    char aszCmd[MAX_PROC_CMD_LEN + 1];
} USERPROC_USRMODEPROC_Compat_CMD_S;

typedef struct {
    USERPROC_USRMODEPROC_CMD_S stCmd;
    USERPROC_USRMODEPROC_ENTRY_S stEntry;
} USERPROC_USRMODEPROC_CMDINFO_S;

/* compat define for USERPROC_USRMODEPROC_CMDINFO_S. */
typedef struct {
    USERPROC_USRMODEPROC_Compat_CMD_S stCmd;
    USERPROC_USRMODEPROC_Compat_ENTRY_S stEntry;
} USERPROC_USRMODEPROC_Compat_CMDINFO_S;

/* compat define for USERPROC_SHOW_BUFFER_S. */
typedef struct {
    uint32_t pu8Buf;    /**<Buffer address*/
    uint32_t u32Size;   /**<Buffer size*/
    uint32_t u32Offset; /**<Offset*/
} USERPROC_Compat_SHOW_BUFFER_S;

typedef char USERPROC_DIR_NAME_S[MAX_PROC_NAME_LEN + 1];

#define USERPROCIOC_ADD_ENTRY              _IOWR(USERPROC_ID, 1, USERPROC_USRMODEPROC_ENTRY_S)
#define USERPROCIOC_ADD_Compat_ENTRY       _IOWR(USERPROC_ID, 1, USERPROC_USRMODEPROC_Compat_ENTRY_S)
#define USERPROCIOC_REMOVE_ENTRY           _IOW(USERPROC_ID, 2, USERPROC_USRMODEPROC_ENTRY_S)
#define USERPROCIOC_REMOVE_Compat_ENTRY    _IOW(USERPROC_ID, 2, USERPROC_USRMODEPROC_Compat_ENTRY_S)
#define USERPROCIOC_ADD_DIR                _IOW(USERPROC_ID, 3, USERPROC_DIR_NAME_S)
#define USERPROCIOC_REMOVE_DIR             _IOW(USERPROC_ID, 4, USERPROC_DIR_NAME_S)
#define USERPROCIOC_GETCMD                 _IOR(USERPROC_ID, 5, USERPROC_USRMODEPROC_CMDINFO_S)
#define USERPROCIOC_Compat_GETCMD          _IOR(USERPROC_ID, 5, USERPROC_USRMODEPROC_Compat_CMDINFO_S)
#define USERPROCIOC_WAKE_READ_TASK         _IOW(USERPROC_ID, 6, USERPROC_SHOW_BUFFER_S)
#define USERPROCIOC_Compat_WAKE_READ_TASK  _IOW(USERPROC_ID, 6, USERPROC_Compat_SHOW_BUFFER_S)
#define USERPROCIOC_WAKE_WRITE_TASK        _IOW(USERPROC_ID, 7, USERPROC_SHOW_BUFFER_S)
#define USERPROCIOC_Compat_WAKE_WRITE_TASK _IOW(USERPROC_ID, 7, USERPROC_Compat_SHOW_BUFFER_S)

#endif /* __DRV_USERPROC_IOCTL_H__ */
