#ifndef _COMMON_H_
#define _COMMON_H_

enum bpf_loglevel {
    BPF_LOG_ERROR = 0,
    BPF_LOG_WARN,
    BPF_LOG_INFO,
    BPF_LOG_DEBUG,
};

//#define BPF_LOGLEVEL BPF_LOG_ERROR
#define BPF_LOGLEVEL BPF_LOG_INFO

#ifndef bpf_printk
#define bpf_printk(fmt, ...)                                                                                           \
    ({                                                                                                                 \
        char ____fmt[] = fmt;                                                                                          \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                                                     \
    })
#endif

#define bpf_log(l, f, ...)                                                                                             \
    do {                                                                                                               \
        if (BPF_LOG_##l <= BPF_LOGLEVEL)                                                                               \
            bpf_printk("[bwm " #l "] " f "", ##__VA_ARGS__);                                                      \
    } while (0)

#define MAX_MAP_SIZE 5000

#endif // _COMMON_H_
