/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: Network bandwidth management tool
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <syslog.h>
#include <sys/resource.h>
#include <linux/if.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <getopt.h>
#include <linux/bpf.h>

#include "bwm_tc.h"
#include "bwmcli.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static struct TcCmd g_enableSeq[] = {
    {
        .cmdStr = "tc qdisc del dev %s root >/dev/null 2>&1",
        .verifyRet = false,
    },
    {
        .cmdStr = "tc qdisc del dev %s clsact >/dev/null 2>&1",
        .verifyRet = false,
    },
    {
        .cmdStr = "tc qdisc add dev %s root fq",
        .verifyRet = true,
    },
    {
        .cmdStr = "tc qdisc add dev %s clsact",
        .verifyRet = true,
    },
    {
        .cmdStr = "tc filter add dev %s egress bpf direct-action obj " TC_PROG " sec tc >/dev/null 2>&1",
        .verifyRet = true,
    }
};

static struct TcCmd g_enableSeqIngress[] = {
    {
        .cmdStr = "tc qdisc del dev %s root >/dev/null 2>&1",
        .verifyRet = false,
    },
    {
        .cmdStr = "tc qdisc del dev %s clsact >/dev/null 2>&1",
        .verifyRet = false,
    },
    {
        .cmdStr = "tc qdisc add dev %s root fq",
        .verifyRet = true,
    },
    {
        .cmdStr = "tc qdisc add dev %s clsact",
        .verifyRet = true,
    },
    {
        .cmdStr = "tc filter add dev %s egress bpf direct-action obj " TC_PROG_I " sec tc >/dev/null 2>&1",
        .verifyRet = true,
    }
};

static struct TcCmd g_disableSeq[] = {
    {
        .cmdStr = "tc filter del dev %s egress",
        .verifyRet = false,
    },
    {
        .cmdStr = "tc qdisc del dev %s clsact",
        .verifyRet = false,
    },
    {
        .cmdStr = "tc qdisc del dev %s root",
        .verifyRet = false,
    },
};

static const struct option g_helps[] = {
    {"Display this information",                no_argument,            NULL, 'h' },
    {"Set egress configuration", required_argument,  NULL, 's' },
    {"Set ingress configuration", required_argument,  NULL, 'S' },
    {"Display egress configuration", required_argument,  NULL, 'p' },
    {"Display ingress configuration", required_argument,  NULL, 'P' },
    {"Enable egress bandwidth management of the network device <ethx>",        required_argument,      NULL, 'e' },
    {"Enable ingress bandwidth management of the network device <ethx>",        required_argument,      NULL, 'E' },
    {"Disable egress bandwidth management of the network device <ethx>",        required_argument,      NULL, 'd' },
    {"Disable ingress bandwidth management of the network device <ethx>",        required_argument,      NULL, 'D' },
    {"Display the version number of bwmcli",            no_argument,        NULL, 'v' },
    {0, 0, NULL,  0 }
};

static const struct option g_longOptions[] = {
    {"help",        no_argument,            NULL, 'h' },
    {"set=<<path> <prio>|bandwidth <low,hi>|waterline <val>> | egress",         required_argument,  NULL, 's' },
    {"set=<bandwidth <low,hi>|waterline <val>> | ingress",         required_argument,  NULL, 'S' },
    {"print=<<path>|bandwidth|waterline|stats|devs> | egress",       required_argument,  NULL, 'p' },
    {"print=<bandwidth|waterline|stats|devs> | ingress",       required_argument,  NULL, 'P' },
    {"enable[=<ethx>] | egress\t",      optional_argument,      NULL, 'e' },
    {"enable[=<ethx>] | ingress\t",      optional_argument,      NULL, 'E' },
    {"disable[=<ethx>] | egress\t",     optional_argument,      NULL, 'd' },
    {"disable[=<ethx>] | ingress\t",     optional_argument,      NULL, 'D' },
    {"version",     no_argument,        NULL, 'v' },
    {0, 0, NULL,  0 }
};

static char g_cmdBuf[MAX_CMD_LEN];

static int GetCgroupPrio(void *cgrpPath, int isIngress); // don't need isIngress
static int SetCgrpPrio(void *cgrpPath, void *args, int isIngress); // don't need isIngress
static int GetBandwidth(void *unused, int isIngress);
static int SetBandwidth(void *cgrpPath, void *args, int isIngress);
static int GetWaterline(void *unused, int isIngress);
static int SetWaterline(void *cgrpPath, void *args, int isIngress);
static int GetStats(void *unused, int isIngress);
static int GetDevs(void *unused, int isIngress);
static int ForeachEthdev(NetdevCallback fn, const void *arg, int isIngress);
static bool InitCfgMap(int isIngress);

static struct CfgOption g_defaultOption = {
    .name = "",
    .op = {
        .getCfg = GetCgroupPrio,
        .setCfg = SetCgrpPrio,
    },
};

static struct CfgOption g_cfgOptions[] = {
    {
        .name = "bandwidth",
        .op = {
            .getCfg = GetBandwidth,
            .setCfg = SetBandwidth,
        },
    },
    {
        .name = "waterline",
        .op = {
            .getCfg = GetWaterline,
            .setCfg = SetWaterline,
        },
    },
    {
        .name = "stats",
        .op = {
            .getCfg = GetStats,
            .setCfg = NULL,
        },
    },
    {
        .name = "devs",
        .op = {
            .getCfg = GetDevs,
            .setCfg = NULL,
        },
    },
    { }
};

static int BwmOption(const char *str)
{
    if (strlen(str) == 0) {
        return BYTE_UNIT;
    }

    if (strlen(str) != UNIT_LEN) {
        return -1;
    }

    if (strcmp(str, "kb") == 0 || strcmp(str, "KB") == 0) {
        return KB_UNIT;
    }
    if (strcmp(str, "mb") == 0 || strcmp(str, "MB") == 0) {
        return MB_UNIT;
    }
    if (strcmp(str, "gb") == 0 || strcmp(str, "GB") == 0) {
        return GB_UNIT;
    }

    return -1;
}

static void Usage(char *argv[])
{
    int i;

    BWM_LOG_INFO("Usage: %s <option(s)>\n", argv[0]);
    BWM_LOG_INFO(" Options are:\n");
    for (i = 0; g_helps[i].name != NULL; i++) {
        BWM_LOG_INFO(" -%c --%-18s", g_longOptions[i].val, g_longOptions[i].name);
        if (strlen(g_longOptions[i].name) > 25) { // 25 means line length
            BWM_LOG_INFO("\n\t\t\t%s\n", g_helps[i].name);
        } else {
            BWM_LOG_INFO("%s\n", g_helps[i].name);
        }
    }
}

static int BreakArgs(char *s, char *arg1, char *arg2, unsigned long arg1Len, unsigned long arg2Len)
{
    char *ns;
    *arg2 = '\0';
    *arg1 = '\0';

    ns = strchr(s, ',');
    if (ns) {
        /* there was a comma arg2 should be the second arg */
        *ns++ = '\0';
        // Negative sign is not counted in the length
        if (*ns != '-') {
            arg2Len--;
        }

        if (strlen(ns) > arg2Len) {
            return EXIT_FAIL_OPTION;
        }
        while ((*arg2++ = *ns++) != '\0') {
            ;
        }
    }

    if (*s != '-') {
        arg1Len--;
    }
    if (strlen(s) > arg1Len) {
        return EXIT_FAIL_OPTION;
    }

    while ((*arg1++ = *s++) != '\0') {
        ;
    }

    return EXIT_OK;
}

static int ProgLoad(char *prog, struct bpf_object ** obj, int * bpfprogFd)
{
    struct bpf_prog_load_attr progLoadAttr = {
        .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
        .file = prog,
        .expected_attach_type = BPF_CGROUP_INET_EGRESS,
        .ifindex = 0,
        .log_level = 0,
    };
    int mapFd;
    struct bpf_map *map = NULL;

    if (access(prog, O_RDONLY) < 0) {
        BWM_LOG_ERR("Error accessing file %s\n", prog);
        return -1;
    }
    if (bpf_prog_load_xattr(&progLoadAttr, &(*obj), bpfprogFd)) {
        BWM_LOG_ERR("ERROR: bpf_prog_load_xattr failed for: %s. errno:%d\n", prog, errno);
        return -1;
    }

    map = bpf_object__find_map_by_name(*obj, "cgrp_prio");
    if (!map) {
        BWM_LOG_ERR("Failed to load map cgrp_prio from bpf prog. errno:%d\n", errno);
        return -1;
    }

    mapFd = bpf_map__fd(map);
    if (mapFd < 0) {
        BWM_LOG_ERR("Map not found: %d. errno:%d\n", mapFd, errno);
        return -1;
    }

    return mapFd;
}

static int GetMapFdByProgId(__u32 progId)
{
    struct bpf_prog_info info = {};
    __u32 infoLen = sizeof(info);
    __u32 ids[1];
    int progFd;
    int mapFd = -1;

    progFd = bpf_prog_get_fd_by_id(progId);
    if (progFd < 0) {
        BWM_LOG_ERR("Failed to get fd by prog id %u. errno:%d", progId, errno);
        goto err;
    }

    info.nr_map_ids = 1;
    info.map_ids = (__u64)(unsigned long)ids;

    if (bpf_obj_get_info_by_fd(progFd, &info, &infoLen)) {
        BWM_LOG_ERR("Failed to get info by prog fd %d. errno:%d", progFd, errno);
        goto err;
    }

    if (!info.nr_map_ids) {
        BWM_LOG_ERR("No maps found for prog fd %d", progFd);
        goto err;
    }

    mapFd = bpf_map_get_fd_by_id(ids[0]);
    if (mapFd < 0) {
        BWM_LOG_ERR("Failed to get fd by map id %u. errno:%d", ids[0], errno);
    }

err:
    if (progFd >= 0) {
        (void)close(progFd);
    }
    return mapFd;
}

static bool CheckCgrpV1PathLegal(const char *cgrpPath, char *trustedPath)
{
    struct stat st = {0};
    char trustedCgrpPath[PATH_MAX + 1] = {0};

    if (realpath(cgrpPath, trustedCgrpPath) == NULL) {
        BWM_LOG_ERR("CgrpV1Prio realpath convert failed. path is %s. errno:%d", cgrpPath, errno);
        return false;
    }

    int ret = snprintf(trustedPath, PATH_MAX + 1, "%s/%s", trustedCgrpPath, "net_cls.classid");
    if (ret < 0 || stat(trustedPath, &st) < 0 || (st.st_mode & S_IFMT) != S_IFREG) {
        BWM_LOG_ERR("CgrpV1Prio get realPath failed. ret: %d\n", ret);
        return false;
    }

    return true;
}

static int CgrpV1Prio(const char *cgrpPath, int prio, int op)
{
    int fd = -1;
    int ret;
    int flags;
    ssize_t size;
    char trustedPath[PATH_MAX + 1] = {0};

#define BUF_SIZE 64
    char buf[BUF_SIZE];

    if (!CheckCgrpV1PathLegal(cgrpPath, trustedPath)) {
        return -1;
    }

    flags = (op == PRIO_GET) ? O_RDONLY : O_WRONLY;
    fd = open(trustedPath, flags);
    if (fd < 0) {
        BWM_LOG_ERR("CgrpV1Prio open trustedPath[%s] failed. errno:%d\n", trustedPath, errno);
        return -1;
    }

    switch (op) {
        case PRIO_SET:
            ret = snprintf(buf, BUF_SIZE, "%u\n", (__u32)prio);
            if (ret < 0) {
                BWM_LOG_ERR("CgrpV1Prio snprintf prio failed. ret: %d.\n", ret);
                (void)close(fd);
                return -1;
            }
            size = write(fd, buf, strlen(buf));
            ret = ((size_t)size != strlen(buf));
            break;
        case PRIO_GET:
            size = read(fd, buf, BUF_SIZE);
            ret = (size < 0);
            break;
        default:
            ret = -1;
    }

    (void)close(fd);

    if (ret == 0) {
        if (op == PRIO_GET) {
            BWM_LOG_INFO("%d\n", atoi(buf));
        } else {
            BWM_LOG_INFO("set prio success\n");
        }
    }

    return ret;
}

static int SetRlimit(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

    if (setrlimit(RLIMIT_MEMLOCK, &r) != EXIT_OK) {
        BWM_LOG_ERR("setrlimit(RLIMIT_MEMLOCK)");
        return EXIT_FAIL;
    }

    return EXIT_OK;
}

static int CgrpV2PrioSet(const char *cgrpPath, int prio)
{
    int key = 0;
    int cgFd;
    int mapFd;
    struct bpf_object *obj = NULL;
    int bpfprogFd;

    cgFd = open(cgrpPath, O_RDONLY);
    if (cgFd < 0) {
        BWM_LOG_ERR("Opening Cgroup failed: %s. errno:%d\n", cgrpPath, errno);
        return EXIT_FAIL_OPTION;
    }

    if (SetRlimit() != EXIT_OK) {
        BWM_LOG_ERR("ERROR: Could not update map element\n");
        (void)close(cgFd);
        return EXIT_FAIL;
    }

    mapFd = ProgLoad(CGRP_PRIO_PROG, &obj, &bpfprogFd);
    if (mapFd == -1) {
        goto err;
    }

    if (bpf_map_update_elem(mapFd, &key, &prio, BPF_ANY)) {
        BWM_LOG_ERR("ERROR: Could not update map element. errno:%d\n", errno);
        goto err;
    }

    /* Only one program is allowed to be attached to a cgroup with
     * NONE or BPF_F_ALLOW_OVERRIDE flag.
     * Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
     * release old program and attach the new one. Attach flags has to match.
     */
    (void)bpf_prog_detach(cgFd, BPF_CGROUP_INET_EGRESS);

    if (bpf_prog_attach(bpfprogFd, cgFd, BPF_CGROUP_INET_EGRESS, 0)) {
        BWM_LOG_ERR("ERROR: bpf_prog_attach fails! errno:%d\n", errno);
        goto err;
    }

    BWM_LOG_INFO("set prio success\n");
    (void)close(cgFd);
    bpf_object__close(obj);
    return EXIT_OK;
err:
    (void)close(cgFd);
    bpf_object__close(obj);
    return EXIT_FAIL_BPF;
}

static int CgrpV2PrioGet(const char *cgrpPath)
{
    int ret;
    int key = 0;
    int prio;
    int cgFd, mapFd = -1;
    __u32 progIds[MAX_PROG_CNT];
    __u32 progCnt = MAX_PROG_CNT;

    cgFd = open(cgrpPath, O_RDONLY);
    if (cgFd < 0) {
        BWM_LOG_ERR("Opening Cgroup fail: %s\n", cgrpPath);
        return EXIT_FAIL_BPF;
    }

    ret = bpf_prog_query(cgFd, BPF_CGROUP_INET_EGRESS, 0, NULL, progIds, &progCnt);
    if (ret != 0) {
        BWM_LOG_ERR("Failed to query bpf programs on cgroup: %s. errno:%d\n", cgrpPath, errno);
        ret = EXIT_FAIL_BPF;
        goto end;
    }

    ret = EXIT_FAIL_BPF;
    if (progCnt != 1) {
        BWM_LOG_ERR("Error: %u progs attach to this cgroup\n", progCnt);
        goto end;
    }

    mapFd = GetMapFdByProgId(progIds[0]);
    if (mapFd < 0) {
        BWM_LOG_ERR("can not find map in prog\n");
        goto end;
    }

    if (bpf_map_lookup_elem(mapFd, &key, &prio) != EXIT_OK) {
        BWM_LOG_ERR("can not find prio. errno:%d\n", errno);
        goto end;
    }

    BWM_LOG_INFO("%d\n", prio);
    if (mapFd >= 0) {
        (void)close(mapFd);
    }
    (void)close(cgFd);
    return EXIT_OK;

end:
    /* treat all another things as online task */
    BWM_LOG_INFO("%d\n", 0);
    if (mapFd >= 0) {
        (void)close(mapFd);
    }
    (void)close(cgFd);
    return ret;
}

static int NetdevEnabledSub(const char *format, const char *ethdev)
{
    int ret;
    ret = snprintf(g_cmdBuf, MAX_CMD_LEN, format, ethdev);
    if (ret < 0) {
        return 0;
    }

    ret = system(g_cmdBuf);
    if (ret < 0) {
        BWM_LOG_ERR("execute cmd[%s] error: %d\n", g_cmdBuf, ret);
        return 0;
    }
    ret = WEXITSTATUS(ret);
    if (ret != 0) {
        return 0;
    }
    return 1;
}

// return: 1 is enabled. 0 is disabled.
static int NetdevEnabled(const char *ethdev, int isIngress)
{
    const char *format = isIngress ? "tc filter show dev %s egress|grep bwm_tc_i.o >/dev/null 2>&1" : "tc filter show dev %s egress|grep bwm_tc.o >/dev/null 2>&1" ;
    
    if (NetdevEnabledSub(format, ethdev) != 0) {
        return 1;
    }

    return 0;
}

static int DisableSpecificNetdevice(const char *ethdev, const void *unused, int isIngress)
{
    size_t i;
    int ret;

    BWM_LOG_DEBUG("DisableSpecificNetdevice: %s\n", ethdev);

    if (NetdevEnabled(ethdev, isIngress) == 0) {
        BWM_LOG_INFO("%s %s has already disabled\n", ethdev, (isIngress ? "ingress" : "egress"));
        return EXIT_OK;
    }

    for (i = 0; i < sizeof(g_disableSeq) / sizeof(struct TcCmd); i++) {
        ret = snprintf(g_cmdBuf, MAX_CMD_LEN, g_disableSeq[i].cmdStr, ethdev);
        if (ret < 0 || g_cmdBuf[MAX_CMD_LEN - 1] != '\0') {
            BWM_LOG_ERR("Invalid net device: %s\n", ethdev);
            return EXIT_FAIL_OPTION;
        }

        ret = system(g_cmdBuf);
        if (ret < 0) {
            BWM_LOG_ERR("execute cmd[%s] error: %d\n", g_cmdBuf, ret);
            return EXIT_FAIL;
        }

        ret = WEXITSTATUS(ret);
        if (ret && g_disableSeq[i].verifyRet) {
            BWM_LOG_ERR("execute cmd ret wrong: %s\n", g_disableSeq[i].cmdStr);
            return EXIT_FAIL;
        }
    }

    BWM_LOG_INFO("disable %s success\n", ethdev);
    return EXIT_OK;
}

static bool execute_cmd(const char *format, const char *ethdev, const char *search)
{
    int ret;

    ret = snprintf(g_cmdBuf, MAX_CMD_LEN, format, ethdev, search);
    if (ret < 0 || g_cmdBuf[MAX_CMD_LEN - 1] != '\0') {
        g_cmdBuf[MAX_CMD_LEN - 1] = '\0';
        BWM_LOG_ERR("Invalid cmd: %s\n", g_cmdBuf);
        return false;
    }

    ret = system(g_cmdBuf);
    if (ret < 0) {
        BWM_LOG_ERR("execute cmd[%s] error: %d\n", g_cmdBuf, ret);
        return false;
    }

    ret = WEXITSTATUS(ret);
    return ret == 0 ? 1 : 0;
}

// return: 1 is can be enabled. 0 is can't be enabled.
static bool DefaultTc(const char *ethdev)
{
    char buf[IFNAMSIZ + 1] = {0};
    int fd;
    ssize_t size;
    bool ret;

    const char *format = "tc qdisc ls dev %s|grep %s >/dev/null 2>&1";

    ret = execute_cmd(format, ethdev, "clsact");
    if (ret) {
        return 0;
    }

    // Only devices configured with default qdisc or no qdisc can be enabled.
    fd = open("/proc/sys/net/core/default_qdisc", O_RDONLY);
    if (fd >= 0) {
        size = read(fd, buf, IFNAMSIZ);
        (void)close(fd);
        if (size <= 0) {
            goto qdisc;
        }

        buf[size - 1] = '\0';
        const char *bufChar = buf;
        ret = execute_cmd(format, ethdev, bufChar);
        if (ret) {
            return ret;
        }
    }

    ret = execute_cmd(format, ethdev, "noqueue");
    if (ret) {
        return ret;
    }

qdisc:
    // Determine if there are other qdiscs
    ret = execute_cmd(format, ethdev, "qdisc");
    return ret == 0 ? 1 : 0;
}

static int EnableSpecificNetdevice(const char *ethdev, const void *unused, int isIngress)
{
    unsigned long i;
    int ret;

    if (isIngress) {
        BWM_LOG_DEBUG("EnableSpecificNetdeviceIngress: %s\n", ethdev);

        if (NetdevEnabled(ethdev, isIngress) == 1) {
            BWM_LOG_INFO("%s %s has already enabled\n", ethdev, (isIngress ? "ingress" : "egress"));
            return EXIT_OK;
        }

        if (!DefaultTc(ethdev)) {
            BWM_LOG_INFO("%s has already enabled other TC\n", ethdev);
            return EXIT_OK;
        }

        for (i = 0; i < sizeof(g_enableSeqIngress) / sizeof(struct TcCmd); i++) {
            ret = snprintf(g_cmdBuf, MAX_CMD_LEN, g_enableSeqIngress[i].cmdStr, ethdev);
            if (ret < 0 || g_cmdBuf[MAX_CMD_LEN - 1] != '\0') {
                BWM_LOG_ERR("Invalid net device: %s\n", ethdev);
                return EXIT_FAIL_OPTION;
            }

            ret = system(g_cmdBuf);
            if (ret < 0) {
                BWM_LOG_ERR("execute cmd[%s] error: %d\n", g_cmdBuf, ret);
                goto clear;
            }

            ret = WEXITSTATUS(ret);
            if (ret && g_enableSeqIngress[i].verifyRet) {
                BWM_LOG_ERR("execute cmd ret wrong: %s\n", g_enableSeqIngress[i].cmdStr);
                goto clear;
            }
        }
    } else {
        BWM_LOG_DEBUG("EnableSpecificNetdevice: %s\n", ethdev);

        if (NetdevEnabled(ethdev, isIngress) == 1) {
            BWM_LOG_INFO("%s has already enabled %s\n", ethdev, isIngress ? "ingress" : "egress");
            return EXIT_OK;
        }

        if (!DefaultTc(ethdev)) {
            BWM_LOG_INFO("%s has already enabled other TC\n", ethdev);
            return EXIT_OK;
        }

        for (i = 0; i < sizeof(g_enableSeq) / sizeof(struct TcCmd); i++) {
            ret = snprintf(g_cmdBuf, MAX_CMD_LEN, g_enableSeq[i].cmdStr, ethdev);
            if (ret < 0 || g_cmdBuf[MAX_CMD_LEN - 1] != '\0') {
                BWM_LOG_ERR("Invalid net device: %s\n", ethdev);
                return EXIT_FAIL_OPTION;
            }

            ret = system(g_cmdBuf);
            if (ret < 0) {
                BWM_LOG_ERR("execute cmd[%s] error: %d\n", g_cmdBuf, ret);
                goto clear;
            }

            ret = WEXITSTATUS(ret);
            if (ret && g_enableSeq[i].verifyRet) {
                BWM_LOG_ERR("execute cmd ret wrong: %s\n", g_enableSeq[i].cmdStr);
                goto clear;
            }
        }
    }
    
    if (!InitCfgMap(isIngress)) {
        goto clear;
    }

    BWM_LOG_INFO("enable %s success\n", ethdev);
    return EXIT_OK;

clear:
    (void)DisableSpecificNetdevice(ethdev, NULL, isIngress);
    return EXIT_FAIL;
}

// return: true is legal, false is illegal
static bool CheckDevNameIsLegalChar(const char c)
{
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-'
        || c == '_') {
        return true;
    }
    return false;
}

static int ForeachEthdev(NetdevCallback fn, const void *arg, int isIngress)
{
    int ret = EXIT_OK;
    int i;
    char *ptr = NULL;
    char *start = NULL;
    char buf[MAX_CMD_LEN];
    FILE *fstream = NULL;
    bool legalDev = true;

    BWM_LOG_DEBUG("ForeachEthdev\n");

    fstream = fopen("/proc/net/dev", "r");
    if (fstream == NULL) {
        return EXIT_FAIL;
    }

    while (fgets(buf, MAX_CMD_LEN, fstream) != NULL) {
        ptr = strchr(buf, ':');
        if (ptr == NULL) {
            continue;
        }

        *ptr = '\0';

        for (start = buf; *start == ' '; start++) {
            ;
        }

        // arg is dev's name which cannot contain characters other than letters, numbers, '-' or "_".
        for (i = 0; start[i] != 0; i++) {
            if (!CheckDevNameIsLegalChar(start[i])) {
                BWM_LOG_ERR("invalid dev name: dev name cannot contain illegal char\n");
                legalDev = false;
                break;
            }
            if (i == NAME_MAX) {
                BWM_LOG_ERR("invalid dev name, too long\n");
                legalDev = false;
                break;
            }
        }

        if (!legalDev) {
            legalDev = true;
            continue;
        }

        ret = fn(start, arg, isIngress);
        if (ret != EXIT_OK) {
            (void)fclose(fstream);
            return ret;
        }
    }

    (void)fclose(fstream);
    return ret;
}

static int DisableAllNetdevice(int isIngress)
{
    int ret;
    BWM_LOG_DEBUG("DisableAllNetdevice\n");

    ret = ForeachEthdev(DisableSpecificNetdevice, NULL, isIngress);

    return ret;
}

static int EnableAllNetdevice(int isIngress)
{
    int ret;

    if (isIngress)
        BWM_LOG_DEBUG("EnableAllNetdevice\n");
    else
        BWM_LOG_DEBUG("EnableAllNetdeviceIngress\n");

    ret = ForeachEthdev(EnableSpecificNetdevice, NULL, isIngress);
    if (ret != EXIT_OK) {
        (void)DisableAllNetdevice(isIngress);
    }

    return ret;
}

static void PrintThrottle(const struct edt_throttle *throttle)
{
    BWM_LOG_INFO("offline_target_bandwidth: %llu\n", throttle->rate);
    BWM_LOG_INFO("online_pkts: %llu\n", throttle->stats.online_pkts);
    BWM_LOG_INFO("offline_pkts: %llu\n", throttle->stats.offline_pkts);
    BWM_LOG_INFO("online_rate: %llu\n", throttle->stats.rate_past);
    BWM_LOG_INFO("offline_rate: %llu\n", throttle->stats.offline_rate_past);
}

static int DevStatShow(const char *ethdev, const void *arg, int isIngress)
{
    int ret;

    ret = NetdevEnabled(ethdev, isIngress);
    BWM_LOG_INFO("%-16s: %s\n", ethdev, (ret == 0) ? "disabled" : (isIngress ? "ingress enabled" : "egress enabled"));

    return EXIT_OK;
}

static void PrintDevsStats(int isIngress)
{
    (void)ForeachEthdev(DevStatShow, NULL, isIngress);
}

static struct CfgOption *FindOptions(const char *cfg)
{
    int i;

    for (i = 0; g_cfgOptions[i].name != NULL; i++) {
        if (strcmp(cfg, g_cfgOptions[i].name) == 0) {
            return &g_cfgOptions[i];
        }
    }

    return &g_defaultOption;
}

static int GetCfgsInfo(char *cfg, int cfgLen, int isIngress)
{
    struct CfgOption *option;

    option = FindOptions(cfg);
    return option->op.getCfg(cfg, isIngress);
}

static int SetCfgsInfo(char *cfg, int cfgLen, char *args, int argsLen, int isIngress)
{
    struct CfgOption *option;

    option = FindOptions(cfg);
    return option->op.setCfg(cfg, args, isIngress);
}

static int BreakMultiArgs(char *args, char arg1[], char arg2[], int mutilArgs)
{
    int ret;

    ret = BreakArgs(args, arg1, arg2, ARG_LEN, ARG_LEN);
    if (ret != EXIT_OK) {
        (void)fprintf(stderr, "invalid arg length: break args failed\n");
        return EXIT_FAIL_OPTION;
    }

    if (mutilArgs == EXIT_OK) {
        if (arg1[0] == '\0' || arg2[0] != '\0') {
            (void)fprintf(stderr, "invalid option: need 1 args\n");
            return EXIT_FAIL_OPTION;
        }
    } else {
        if (arg1[0] == '\0' || arg2[0] == '\0') {
            (void)fprintf(stderr, "invalid option: need 2 args\n");
            return EXIT_FAIL_OPTION;
        }
    }
    return EXIT_OK;
}

static int ParseUnit(char arg[], int setPrio,  long long *val)
{
    int unit;
    char *ptr = NULL;
    long long tmp = strtol(arg, &ptr, DECIMAL);

    if (ptr[0] != 0) {
        unit = BwmOption(ptr);
        if (unit <= 0) {
            (void)fprintf(stderr, "invalid option: unit wrong\n");
            return EXIT_FAIL_OPTION;
        }
        if (tmp > LLONG_MAX / unit || tmp < -1) {
            (void)fprintf(stderr, "invalid arg: number too long\n");
            return EXIT_FAIL_OPTION;
        }
        tmp *= (long long)unit;
    } else if (setPrio == 0) {
        (void)fprintf(stderr, "invalid option: need unit\n");
        return EXIT_FAIL_OPTION;
    }

    *val = tmp;

    return EXIT_OK;
}

static int ParseArgs(char *args, long long *val1, long long *val2, int mutilArgs, int setPrio)
{
    char arg1[ARG_LEN + 1];
    char arg2[ARG_LEN + 1];

    if (BreakMultiArgs(args, arg1, arg2, mutilArgs) != EXIT_OK) {
        return EXIT_FAIL_OPTION;
    }

    // param like 001 or -001 is invalid
    if (arg1[0] == '-' && arg1[1] == '0') {
        (void)fprintf(stderr, "invalid arg: number start with 0 is invalid\n");
        return EXIT_FAIL_OPTION;
    }
    if ((arg1[0] == '0' && arg1[1] != 0) || (arg2[0] == '0' && arg2[1] != 0)) {
        (void)fprintf(stderr, "invalid arg: number start with 0 is invalid\n");
        return EXIT_FAIL_OPTION;
    }

    if (ParseUnit(arg1, setPrio, val1) != EXIT_OK) {
        return EXIT_FAIL_OPTION;
    }

    if (mutilArgs != 0) {
        if (ParseUnit(arg2, setPrio, val2) != EXIT_OK) {
            return EXIT_FAIL_OPTION;
        }
    }

    return EXIT_OK;
}

static int CfgsInfo(int argc, char **argv, int isSet, int isIngress)
{
    int ret;
    char option[PATH_MAX + 1] = {0};
    char args[PRIO_LEN] = {0};

    (void)strncpy(option, optarg, PATH_MAX);
    if (option[PATH_MAX] != '\0') {
        (void)fprintf(stderr, "invalid option, too long: %s\n", optarg);
        return EXIT_FAIL_OPTION;
    }

    if (optind >= argc || isSet == EXIT_OK) {
        if (isSet != EXIT_OK) {
            (void)fprintf(stderr, "invalid option, extra parameter: %s\n", optarg);
            return EXIT_FAIL_OPTION;
        }
        ret = GetCfgsInfo(option, PATH_MAX + 1, isIngress);
        return ret;
    }

    (void)strncpy(args, argv[optind], PRIO_LEN - 1);
    if (args[PRIO_LEN - 1] != '\0') {
        (void)fprintf(stderr, "invalid args, too long: %s\n", argv[optind]);
        return EXIT_FAIL_OPTION;
    }

    ret = SetCfgsInfo(option, PATH_MAX + 1, args, PRIO_LEN, isIngress);
    if (ret != EXIT_OK) {
        return ret;
    }

    /* move to next option */
    optind++;

    return EXIT_OK;
}

static int NetdevCmp(const char *ethdev, const void *arg, int isIngress)
{
    return (strcmp(ethdev, arg) == 0) ? 1 : 0;
}

inline static int IsValidEthdev(const char *dev)
{
    return ForeachEthdev(NetdevCmp, dev, 0);
}

static int ChangeNetdeviceStatus(int argc, char **argv, int enable, int isIngress)
{
    int ret;
    char ethdev[NAME_MAX + 1] = {0};

    if (optarg == NULL && (optind >= argc || argv[optind][0] == '-')) {
        /* enable all eth device */
        ret = (enable == 0) ? DisableAllNetdevice(isIngress) : EnableAllNetdevice(isIngress);
        return ret;
    }

    if (optarg != NULL) {
        (void)strncpy(ethdev, optarg, NAME_MAX);
    } else {
        (void)strncpy(ethdev, argv[optind], NAME_MAX);
        optind++;
    }

    if (ethdev[NAME_MAX] != '\0') {
        (void)fprintf(stderr, "invalid dev name: %s\n", optarg);
        return EXIT_FAIL_OPTION;
    }

    if (!IsValidEthdev(ethdev)) {
        BWM_LOG_INFO("invalid device: %s\n", ethdev);
        return EXIT_FAIL_OPTION;
    }

    ret = (enable == 1) ? EnableSpecificNetdevice(ethdev, NULL, isIngress) : DisableSpecificNetdevice(ethdev, NULL, isIngress);
    
    return ret;
}

static int GetCgroupPrio(void *cgrpPath, int isIngress)
{
    int ret;

    BWM_LOG_DEBUG("GetCgroupPrio\n");

    /* cgroup V1 */
    ret = CgrpV1Prio(cgrpPath, 0, PRIO_GET);
    if (ret == 0) {
        return EXIT_OK;
    }

    /* cgroup V2 */
    return CgrpV2PrioGet(cgrpPath);
}

static int SetCgrpPrio(void *cgrpPath, void *args, int isIngress)
{
    int ret;
    long long prio, tmp;

    BWM_LOG_DEBUG("SetCgrpPrio\n");

    ret = ParseArgs(args, &prio, &tmp, 0, 1);
    if (ret != EXIT_OK) {
        return ret;
    }

    if (prio != 0 && prio != -1) {
        (void)fprintf(stderr, "invalid prio value\n");
        return EXIT_FAIL_OPTION;
    }

    /* cgroup V1 */
    ret = CgrpV1Prio(cgrpPath, (int)prio, PRIO_SET);
    if (ret == 0) {
        return ret;
    }

    return CgrpV2PrioSet(cgrpPath, (int)prio);
}

static int ReadCfgByPath(char *path, struct edt_throttle_cfg *cfg)
{
    int ret;
    int mapIndex = 0;
    int fd;

    fd = bpf_obj_get(path);
    if (fd < 0) {
        BWM_LOG_ERR("ERROR: ReadCfg bpf_obj_get failed, Not enabled? %s fd:%d errno:%d\n",
            path, fd, errno);
        return EXIT_FAIL_BPF;
    }
    
    ret = bpf_map_lookup_elem(fd, &mapIndex, cfg);
    if (ret != 0) {
        BWM_LOG_ERR("ERROR: ReadCfg can't find map. %s ret:%d errno:%d\n",
            path, ret, errno);
        (void)close(fd);
        return EXIT_FAIL_BPF;
    }

    (void)close(fd);
    return EXIT_OK;
}

static int UpdateCfgByPath(char *path, struct edt_throttle_cfg *cfg)
{
    int ret;
    int mapIndex = 0;
    int fd;

    fd = bpf_obj_get(path);
    if (fd < 0) {
        BWM_LOG_ERR("ERROR: UpdateCfg bpf_obj_get failed, Not enabled? %s fd:%d errno:%d\n",
            path, fd, errno);
        return EXIT_FAIL_BPF;
    }
    
    ret = bpf_map_update_elem(fd, &mapIndex, cfg, BPF_ANY);
    if (ret != 0) {
        BWM_LOG_ERR("ERROR: UpdateCfg can't update map. %s ret:%d errno:%d\n",
            path, ret, errno);
        (void)close(fd);
        return EXIT_FAIL_BPF;
    }

    (void)close(fd);
    return EXIT_OK;
}

static int ReadStatsByPath(char *path, struct edt_throttle *stats)
{
    int ret;
    int mapIndex = 0;
    int fd;

    fd = bpf_obj_get(path);
    if (fd < 0) {
        BWM_LOG_ERR("ERROR: ReadStats bpf_obj_get failed, Not enabled? %s fd:%d errno:%d\n",
            path, fd, errno);
        return EXIT_FAIL_BPF;
    }
    
    ret = bpf_map_lookup_elem(fd, &mapIndex, stats);
    if (ret != 0) {
        BWM_LOG_ERR("ERROR: ReadStats can't find map. %s ret:%d errno:%d\n",
            path, ret, errno);
        (void)close(fd);
        return EXIT_FAIL_BPF;
    }

    (void)close(fd);
    return EXIT_OK;
}

static int ReadStats(struct edt_throttle *stats, int isIngress)
{
    int ret;

    if (isIngress) {
        ret = ReadStatsByPath(THROTTLE_I_MAP_PATH, stats);
    } else {
        ret = ReadStatsByPath(THROTTLE_MAP_PATH, stats);
    }

    return ret;
}

static int ReadCfg(struct edt_throttle_cfg *cfg, int isIngress)
{
    int ret;

    if (isIngress) {
        ret = ReadCfgByPath(THROTTLE_I_CFG_PATH, cfg);
    } else {
        ret = ReadCfgByPath(THROTTLE_CFG_PATH, cfg);
    }
    
    return ret;
}

static int UpdateCfg(struct edt_throttle_cfg *cfg, int isIngress)
{
    int ret;

    if (isIngress) {
        ret = UpdateCfgByPath(THROTTLE_I_CFG_PATH, cfg);
    } else {
        ret = UpdateCfgByPath(THROTTLE_CFG_PATH, cfg);
    }

    return ret;
}

static bool InitCfgMap(int isIngress)
{
    struct edt_throttle_cfg cfg = {0};
    int ret;

    ret = ReadCfg(&cfg, isIngress);
    if (ret != EXIT_OK) {
        BWM_LOG_ERR("InitCfgMap ReadCfg err: %d\n", ret);
        return false;
    }
    if (cfg.interval == 0) {
        cfg.water_line = DEFAULT_WATERLINE;
        cfg.interval = 10ULL * NSEC_PER_MSEC; // actually 10ms
        cfg.low_rate = DEFAULT_LOW_BANDWIDTH;
        cfg.high_rate = DEFAULT_HIGH_BANDWIDTH;

        ret = UpdateCfg(&cfg, isIngress);
        if (ret != EXIT_OK) {
            BWM_LOG_ERR("InitCfgMap UpdateCfg err: %d\n", ret);
            return false;
        }
    }

    return true;
}

static int UpdateIp(int isDelete)
{
    int ret;
    int fd;
    int priority = 1;
    struct in_addr ip;
    __u32 ipUint;

    char ipStr[IP_LEN + 1] = {0};
    
    (void)strncpy(ipStr, optarg, IP_LEN);
    if (ipStr[IP_LEN] != '\0') {
        (void)fprintf(stderr, "invalid ip, too long: %s\n", optarg);
        return EXIT_FAIL_OPTION;
    }

    // ip char* -> u32, convert result is network byte order
    ret = inet_pton(AF_INET, ipStr, &ip);
    if (ret == 0 || errno == EAFNOSUPPORT) {
        (void)fprintf(stderr, "invalid ip, transfer ip to u32 error\n");
        return EXIT_FAIL_OPTION;
    }

    ipUint = ip.s_addr;  // network byte order

    fd = bpf_obj_get(IPS_I_MAP_PATH);
    if (fd < 0) {
        BWM_LOG_ERR("ERROR: %s bpf_obj_get failed, Not enabled? %s fd:%d errno:%d\n",
            isDelete ? "RemoveIp" : "AddIp", IPS_I_MAP_PATH, fd, errno);
        return EXIT_FAIL_BPF;
    }

    ret = isDelete ? bpf_map_delete_elem(fd, &ipUint) : bpf_map_update_elem(fd, &ipUint, &priority, BPF_ANY);
    if (ret != 0) {
        BWM_LOG_ERR("ERROR: %s map fail. %s ret:%d errno:%d\n",
            isDelete ? "RemoveIp" : "AddIp", IPS_I_MAP_PATH, ret, errno);
        (void)close(fd);
        return EXIT_FAIL_BPF;
    }

    if (!isDelete)
        BWM_LOG_INFO("ip(network byte order): %u\n", ipUint);
    BWM_LOG_INFO("%s %s success\n", isDelete ? "RemoveIp" : "AddIp", ipStr);
    (void)close(fd);
    return EXIT_OK;
}

static int GetBandwidth(void *unused, int isIngress)
{
    int ret;
    struct edt_throttle_cfg cfg = {0};

    ret = ReadCfg(&cfg, isIngress);
    if (ret != EXIT_OK) {
        return ret;
    }

    BWM_LOG_INFO("bandwidth is %llu(B),%llu(B)\n", (cfg.low_rate == 0) ? DEFAULT_LOW_BANDWIDTH : cfg.low_rate,
        (cfg.high_rate == 0) ? DEFAULT_HIGH_BANDWIDTH : cfg.high_rate);
    return EXIT_OK;
}

static int SetBandwidth(void *cgrpPath, void *args, int isIngress)
{
    int ret;
    long long low, high;
    unsigned long long lowtemp, hightemp;
    struct edt_throttle_cfg cfg = {0};

    ret = ReadCfg(&cfg, isIngress);
    if (ret != EXIT_OK) {
        return ret;
    }

    ret = ParseArgs(args, &low, &high, 1, 0);
    if (ret != EXIT_OK) {
        return ret;
    }

    if (low < LOWEST_BANDWIDTH || high > HIGHEST_BANDWIDTH || (low > high)) {
        (void)fprintf(stderr, "invalid bandwidth: %lld,%lld, bandwidth should between %lld, %lld\n", low, high,
            LOWEST_BANDWIDTH, HIGHEST_BANDWIDTH);
        return EXIT_FAIL_OPTION;
    }

    lowtemp = (unsigned long long)low;
    hightemp = (unsigned long long)high;
    if (lowtemp != cfg.low_rate || hightemp != cfg.high_rate) {
        cfg.low_rate = lowtemp;
        cfg.high_rate = hightemp;

        ret = UpdateCfg(&cfg, isIngress);
        if (ret != EXIT_OK) {
            return ret;
        }
    }
    BWM_LOG_INFO("set bandwidth success\n");
    return EXIT_OK;
}

static int GetWaterline(void *unused, int isIngress)
{
    int ret;
    struct edt_throttle_cfg cfg = {0};

    ret = ReadCfg(&cfg, isIngress);
    if (ret != EXIT_OK) {
        return ret;
    }
    unsigned long long wl = (cfg.water_line == 0) ? DEFAULT_WATERLINE : cfg.water_line;
    BWM_LOG_INFO("waterline is %llu(B)\n", wl);
    return EXIT_OK;
}

static int SetWaterline(void *cgrpPath, void *args, int isIngress)
{
    int ret;
    long long val, tmp;
    struct edt_throttle_cfg cfg = {0};

    ret = ReadCfg(&cfg, isIngress);
    if (ret != EXIT_OK) {
        return ret;
    }

    ret = ParseArgs(args, &val, &tmp, 0, 0);
    if (ret != EXIT_OK) {
        return ret;
    }

    if (val < DEFAULT_WATERLINE || val > HIGHEST_BANDWIDTH) {
        (void)fprintf(stderr,
            "invalid waterline: %lld, "
            "waterline should between %lld, %lld\n",
            val, DEFAULT_WATERLINE, HIGHEST_BANDWIDTH);
        return EXIT_FAIL_OPTION;
    }

    if ((unsigned long long)val != cfg.water_line) {
        cfg.water_line = (unsigned long long)val;
        ret = UpdateCfg(&cfg, isIngress);
        if (ret != EXIT_OK) {
            return ret;
        }
    }
    BWM_LOG_INFO("set waterline success\n");
    return EXIT_OK;
}

static int GetStats(void *unused, int isIngress)
{
    int ret;
    struct edt_throttle stats = {0};

    ret = ReadStats(&stats, isIngress);
    if (ret != EXIT_OK) {
        return ret;
    }

    PrintThrottle(&stats);

    return EXIT_OK;
}

static int GetDevs(void *unused, int isIngress)
{
    PrintDevsStats(isIngress);
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    int hasOptions = 0;
    int ret;
    int opt, isSet, enable, isIngress;
    int longindex = 0;
    if (argc < MINUM_ARGS) {
        Usage(argv);
        return EXIT_FAIL_OPTION;
    }

    while ((opt = getopt_long(argc, argv, "vVhe::E::d::D::p:P:s:S:A:R:", g_longOptions, &longindex)) != -1) {
        hasOptions = 1;
        isSet = 1;
        enable = 1;
        isIngress = 0; // 0 -> egress; !0 -> ingress
        ret = EXIT_FAIL_OPTION;

        switch (opt) {
            case 'v':
            case 'V':
                BWM_LOG_INFO("version: %s\n", BWM_VERSION);
                break;
            case 'p':
                isSet = 0;
            //lint -fallthrough
            case 's':
                ret = CfgsInfo(argc, argv, isSet, isIngress);
                if (ret != EXIT_OK) {
                    return ret;
                }
                break;
            case 'P':
                isSet = 0;
            //lint -fallthrough
            case 'S':
                isIngress = 1;
                ret = CfgsInfo(argc, argv, isSet, isIngress);
                if (ret != EXIT_OK) {
                    return ret;
                }
                break;
            case 'd': // egress
                enable = 0;
            //lint -fallthrough
            case 'e':
                ret = ChangeNetdeviceStatus(argc, argv, enable, isIngress);
                if (ret != EXIT_OK) {
                    return ret;
                }
                break;
            case 'D': // ingress
                enable = 0;
            //lint -fallthrough
            case 'E':
                isIngress = 1;
                ret = ChangeNetdeviceStatus(argc, argv, enable, isIngress);
                if (ret != EXIT_OK) {
                    return ret;
                }
                break;
            case 'A':
                ret = UpdateIp(0);
                if (ret != EXIT_OK) {
                    return ret;
                }
                break;
            case 'R':
                ret = UpdateIp(1);
                if (ret != EXIT_OK) {
                    return ret;
                }
                break;
            case 'h':
                ret = EXIT_OK;
            //lint -fallthrough
            default:
                Usage(argv);
                return ret;
        }
    }

    if (hasOptions == EXIT_OK || optind < argc) {
        Usage(argv);
        return EXIT_FAIL_OPTION;
    }

    return EXIT_OK;
}
