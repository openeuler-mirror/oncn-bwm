cmake_minimum_required(VERSION 3.12.1)
project(bwmcli LANGUAGES C )
set(CMAKE_C_FLAGS "-g -Wall -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Werror -ftrapv -O2 -Wl,-z,noexecstack \
        -Wl,-z,relro -fPIE -pie -Wl,-z,now")

include_directories("${PROJECT_SOURCE_DIR}/")
include_directories("${PROJECT_SOURCE_DIR}/bpf")

add_subdirectory(bpf)

if($ENV{HS_COVERAGE_ENABLE})
        message("Enable Coverage compile option")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
endif($ENV{HS_COVERAGE_ENABLE})

add_executable(bwmcli bwmcli.c)
target_link_libraries(bwmcli -l:libbpf.so)
