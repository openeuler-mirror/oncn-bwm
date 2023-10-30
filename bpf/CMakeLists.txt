cmake_minimum_required(VERSION 3.12.1)
project(bpf LANGUAGES C )
message(STATUS "Enter bpf folder")

include_directories("/usr/include/bpf/")
set(CMAKE_C_COMPILER "clang")

set(CMAKE_C_FLAGS "-g -Wall -O2 -Werror  --target=bpf -D__x86_64__ -fPIC -D_FORTIFY_SOURCE=2 -ftrapv")
add_library(bwm_tc OBJECT  bwm_tc)
add_library(bwm_tc_i OBJECT  bwm_tc_i)
add_library(bwm_prio_kern OBJECT bwm_prio_kern)
