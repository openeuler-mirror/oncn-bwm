/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: Network bandwidth management tool
 */

#ifndef __BWMCLI_H__
#define __BWMCLI_H__

#define EXIT_OK             0
#define EXIT_FAIL           1
#define EXIT_FAIL_OPTION    2
#define EXIT_FAIL_BPF       3
#define EXIT_FAIL_MEM       4

#define PRIO_LEN            32
#define ARG_LEN             16

#define BPF_PROG_PATH       "/usr/share/bwmcli/"
#define CGRP_PRIO_PROG      BPF_PROG_PATH"bwm_prio_kern.o"
#define TC_PROG             BPF_PROG_PATH"bwm_tc.o"

#define MAX_PROG_CNT        10
#define MAX_CMD_LEN         (256 + NAME_MAX)

#define DECIMAL             10
#define BWM_VERSION         "1.0"
#define MINUM_ARGS          2

#define PRIO_GET            0
#define PRIO_SET            1

#define UNIT_LEN            2
#define GB                  (1024 * 1024 * 1024)
#define MB                  (1024 * 1024)
#define KB                  (1024)

enum {
    BYTE_UNIT   =       1,
    KB_UNIT     =       KB,
    MB_UNIT     =       MB,
    GB_UNIT     =       GB,
};

typedef int NetdevCallback(const char *ethdev, const void *arg);

struct CfgOperations {
    int (*setCfg)(void *, void *);
    int (*getCfg)(void *);
};

struct CfgOption {
    const char *name;
    struct CfgOperations op;
};

struct TcCmd {
    const char *cmdStr;
    bool verifyRet;
};

#define BWM_LOG_DEBUG(fmt, args...)     syslog(LOG_DEBUG, "[BWM_DEBUG]: " fmt, ## args)
#define BWM_LOG_ERR(fmt, args...)       syslog(LOG_ERR, "[BWM]: " fmt, ## args)
#define BWM_LOG_INFO(fmt, args...)      ((void)printf(fmt, ## args))

#endif /* __BWMCLI_H__ */
