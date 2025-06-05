package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE TcEdt bpf/tc_edt.c -- -Ibpf/include/common.h -Ibpf/include/tc_edt.h
