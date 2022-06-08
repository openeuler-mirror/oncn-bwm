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
    {"Set configuration", required_argument,  NULL, 's' },
    {"Display configuration", required_argument,  NULL, 'p' },
    {"Enable bandwidth management of the network device <ethx>",        required_argument,      NULL, 'e' },
    {"Disable bandwidth management of the network device <ethx>",        required_argument,      NULL, 'd' },
    {"Display the version number of bwmcli",            no_argument,        NULL, 'v' },
    {0, 0, NULL,  0 }
};

static const struct option g_longOptions[] = {
    {"help",        no_argument,            NULL, 'h' },
    {"set=<<path> <prio>|bandwidth <low,hi>|waterline <val>>",         required_argument,  NULL, 's' },
    {"print=<<path>|bandwidth|waterline|stats|devs>",       required_argument,  NULL, 'p' },
    {"enable[=<ethx>]",      optional_argument,      NULL, 'e' },
    {"disable[=<ethx>]",     optional_argument,      NULL, 'd' },
    {"version",     no_argument,        NULL, 'v' },
    {0, 0, NULL,  0 }
};

static char g_cmdBuf[MAX_CMD_LEN];

static int GetCgroupPrio(void *cgrpPath);
static int SetCgrpPrio(void *cgrpPath, void *args);
static int GetBandwidth(void *unused);
static int SetBandwidth(void *cgrpPath, void *args);
static int GetWaterline(void *unused);
static int SetWaterline(void *cgrpPath, void *args);
static int GetStats(void *unused);
static int GetDevs(void *unused);
static int ForeachEthdev(NetdevCallback fn, const void *arg);
static bool InitCfgMap();

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

    ret = EXIT_FAIL_BPF;

    mapFd = GetMapFdByProgId(progIds[0]);

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
static int NetdevEnabled(const char *ethdev)
{
    const char *format = "tc filter show dev %s egress|grep bwm_tc.o >/dev/null 2>&1";
    if (NetdevEnabledSub(format, ethdev) == 0) {
        return 0;
    }

    const char *format1 = "tc qdisc ls dev %s|grep \"qdisc fq \" >/dev/null 2>&1";
    if (NetdevEnabledSub(format1, ethdev) == 0) {
        return 0;
    }

    return 1;
}

static int DisableSpecificNetdevice(const char *ethdev, const void *unused)
{
    size_t i;
    int ret;

    BWM_LOG_DEBUG("DisableSpecificNetdevice: %s\n", ethdev);

    if (NetdevEnabled(ethdev) == 0) {
        BWM_LOG_INFO("%s has already disabled\n", ethdev);
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

static int EnableSpecificNetdevice(const char *ethdev, const void *unused)
{
    unsigned long i;
    int ret;

    BWM_LOG_DEBUG("EnableSpecificNetdevice: %s\n", ethdev);

    if (NetdevEnabled(ethdev) == 1) {
        BWM_LOG_INFO("%s has already enabled\n", ethdev);
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

    if (!InitCfgMap()) {
        goto clear;
    }

    BWM_LOG_INFO("enable %s success\n", ethdev);
    return EXIT_OK;

clear:
    (void)DisableSpecificNetdevice(ethdev, NULL);
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

static int ForeachEthdev(NetdevCallback fn, const void *arg)
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

        ret = fn(start, arg);
        if (ret != EXIT_OK) {
            (void)fclose(fstream);
            return ret;
        }
    }

    (void)fclose(fstream);
    return ret;
}

static int DisableAllNetdevice(void)
{
    int ret;
    BWM_LOG_DEBUG("DisableAllNetdevice\n");

    ret = ForeachEthdev(DisableSpecificNetdevice, NULL);

    return ret;
}

static int EnableAllNetdevice(void)
{
    int ret;

    BWM_LOG_DEBUG("EnableAllNetdevice\n");

    ret = ForeachEthdev(EnableSpecificNetdevice, NULL);
    if (ret != EXIT_OK) {
        (void)DisableAllNetdevice();
    }

    return ret;
}


static int DevStatShow(const char *ethdev, const void *arg)
{
    int ret;

    ret = NetdevEnabled(ethdev);
    BWM_LOG_INFO("%-16s: %s\n", ethdev, (ret == 0) ? "disabled" : "enabled");

    return EXIT_OK;
}

static void PrintDevsStats(void)
{
    (void)ForeachEthdev(DevStatShow, NULL);
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

static int GetCfgsInfo(char *cfg, int cfgLen)
{
    struct CfgOption *option;

    option = FindOptions(cfg);
    return option->op.getCfg(cfg);
}

static int SetCfgsInfo(char *cfg, int cfgLen, char *args, int argsLen)
{
    struct CfgOption *option;

    option = FindOptions(cfg);
    return option->op.setCfg(cfg, args);
}

static int ParseUnit(char arg[], int setPrio,  long long *val)
{
    return EXIT_OK;
}

static int ParseArgs(char *args, long long *val1, long long *val2, int mutilArgs, int setPrio)
{
    char arg1[ARG_LEN + 1];
    char arg2[ARG_LEN + 1];

    return EXIT_OK;
}

static int CfgsInfo(int argc, char **argv, int isSet)
{
    int ret;
    char option[PATH_MAX + 1] = {0};
    char args[PRIO_LEN] = {0};

    (void)strncpy(option, optarg, PATH_MAX);

    if (optind >= argc || isSet == EXIT_OK) {
        if (isSet != EXIT_OK) {
            (void)fprintf(stderr, "invalid option, extra parameter: %s\n", optarg);
            return EXIT_FAIL_OPTION;
        }
        ret = GetCfgsInfo(option, PATH_MAX + 1);
        return ret;
    }

    (void)strncpy(args, argv[optind], PRIO_LEN - 1);
    ret = SetCfgsInfo(option, PATH_MAX + 1, args, PRIO_LEN);
    if (ret != EXIT_OK) {
        return ret;
    }

    /* move to next option */
    optind++;

    return EXIT_OK;
}

static int NetdevCmp(const char *ethdev, const void *arg)
{
    return (strcmp(ethdev, arg) == 0) ? 1 : 0;
}

inline static int IsValidEthdev(const char *dev)
{
    return ForeachEthdev(NetdevCmp, dev);
}

static int ChangeNetdeviceStatus(int argc, char **argv, int enable)
{
    int ret;
    char ethdev[NAME_MAX + 1] = {0};

    if (optarg == NULL && (optind >= argc || argv[optind][0] == '-')) {
        /* enable all eth device */
        ret = (enable == 0) ? DisableAllNetdevice() : EnableAllNetdevice();
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

    ret = (enable == 1) ? EnableSpecificNetdevice(ethdev, NULL) : DisableSpecificNetdevice(ethdev, NULL);

    return ret;
}

static int GetCgroupPrio(void *cgrpPath)
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

static int SetCgrpPrio(void *cgrpPath, void *args)
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

int main(int argc, char **argv)
{
    int hasOptions = 0;
    int ret;
    int opt, isSet, enable;
    int longindex = 0;
    if (argc < MINUM_ARGS) {
        Usage(argv);
        return EXIT_FAIL_OPTION;
    }

    while ((opt = getopt_long(argc, argv, "vVhe::d::p:s:", g_longOptions, &longindex)) != -1) {
        hasOptions = 1;
        isSet = 1;
        enable = 1;
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
                ret = CfgsInfo(argc, argv, isSet);
                if (ret != EXIT_OK) {
                    return ret;
                }
                break;
            case 'd':
                enable = 0;
            //lint -fallthrough
            case 'e':
                ret = ChangeNetdeviceStatus(argc, argv, enable);
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
