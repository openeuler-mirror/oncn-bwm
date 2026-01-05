#!/bin/bash
###############################################################################
# Script: oci_hook_handler.sh
# Author: [zhangmingyi]
# Date: 2025-12-29
# Description: OCI Hook script for handling container network bandwidth management
# Usage: This script is triggered automatically by OCI hooks
###############################################################################

# === 配置常量 ===
readonly LOG_FILE="/var/log/my-oci-hook.log"
readonly JSON_FILE="/tmp/pod_ip_map.json"

# === 初始化环境 ===
init() {
    # 启用严格的错误处理
    set -euo pipefail
    
    # 创建日志目录（如果不存在）
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # 记录脚本开始执行
    log_info "OCI Hook triggered"
}

# === 日志函数 ===
log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*" | tee -a "$LOG_FILE" >&2
}

log_debug() {
    # if [[ "${DEBUG:-0}" == "1" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] $*" | tee -a "$LOG_FILE"
    # fi
}

# === 工具函数 ===
check_dependencies() {
    local dependencies=("jq" "nsenter" "ethtool" "ip")
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Missing required command: $cmd"
	    exit 1
        fi
    done
}

get_container_info() {
    local container_state_json="$1"
    
    # 从标准输入读取容器状态JSON
    local pid container_id
    pid=$(echo "$container_state_json" | jq -r '.pid')
    container_id=$(echo "$container_state_json" | jq -r '.id')
    
    # 验证获取的信息
    if [[ -z "$pid" || -z "$container_id" ]]; then
        log_error "Failed to extract PID or Container ID from state JSON"
        exit 1
    fi
    
    echo "$pid $container_id"
}

get_container_labels() {
    local container_id="$1"
    local config_path="/var/lib/docker/containers/$container_id/config.v2.json"
    
    if [[ ! -f "$config_path" ]]; then
        log_error "Container config file not found: $config_path"
        exit 1
    fi
    
    local bw_enabled ingress_bw egress_bw
    bw_enabled=$(jq -r '.Config.Labels["annotation.cni.bwm-plugin.com/enable-feature"] // "false"' "$config_path")
    ingress_bw=$(jq -r '.Config.Labels["annotation.cni.bwm-plugin.com/bandwidth-ingress"] // ""' "$config_path")
    egress_bw=$(jq -r '.Config.Labels["annotation.cni.bwm-plugin.com/bandwidth-egress"] // ""' "$config_path")
    
    # 转换带宽格式（将"-"替换为","）
    ingress_bw="${ingress_bw//-/,}"
    egress_bw="${egress_bw//-/,}"
#    log_info $(cat "$config_path")
    echo "$bw_enabled $ingress_bw $egress_bw $config_path"
}

#get_network_info() {
#    local pid="$1"
#    
#    local veth_index veth_host pod_ip
#    veth_index=$(nsenter -n -t "$pid" ethtool -S eth0 2>/dev/null | grep peer_ifindex | awk -F: '{print $2}' | tr -d ' ')
#    
#    if [[ -n "$veth_index" ]]; then
#        veth_host=$(ip -o link show | awk -F'[@:]' -v idx="$veth_index" '$1 == idx {print $2}')
#    else
#        veth_host="unknown"
#        log_debug "Could not determine veth host interface"
#    fi
#    
#    pod_ip=$(nsenter -n -t "$pid" ip -o -4 addr show eth0 2>/dev/null | awk '{print $4}' | cut -d'/' -f1 || echo "unknown")
#    
#    echo "$veth_host $pod_ip"
#}

get_network_info() {
    local pid="$1"
    local veth_index veth_host pod_ip

    # 1. 获取veth索引，并抑制所有输出（包括标准输出）
    veth_index=$(nsenter -n -t "$pid" ethtool -S eth0 2>&1 | grep peer_ifindex | awk -F: '{print $2}' | tr -d ' ')

    if [[ -n "$veth_index" ]]; then
        # 2. 获取veth主机端名称
        veth_host=$(ip -o link show 2>/dev/null | awk -F'[@:]' -v idx="$veth_index" '$1 == idx {print $2}')
        # 如果ip命令失败或找不到，设置为null
        if [[ -z "$veth_host" ]]; then
            veth_host="null"
        fi
    else
        veth_host="null"
        # 将调试日志输出到标准错误，避免影响函数返回结果
        echo "DEBUG: Could not determine veth host interface (veth_index not found)" >&2
    fi

    # 3. 获取Pod IP，明确处理失败情况
    pod_ip=$(nsenter -n -t "$pid" ip -o -4 addr show eth0 2>&1 | awk '{print $4}' | cut -d'/' -f1)
    # 严格验证IP地址格式
    if [[ -z "$pod_ip" ]]; then
        pod_ip="null"
    elif ! [[ "$pod_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        pod_ip="null"
    fi
    # 4. 返回结果
    echo "$veth_host $pod_ip"
}

manage_ip_mapping() {
    local container_id="$1"
    local pod_ip="$2"
    local operation="${3:-delete}" # 默认操作是删除
    local json_file="${4:-$JSON_FILE}" # 允许指定JSON文件路径，默认为预定义的JSON_FILE

    # 确保JSON文件存在，如果不存在则初始化为空JSON对象
    if [[ ! -f "$json_file" ]]; then
        echo "{}" > "$json_file"
        log_info "Created new JSON mapping file: $json_file"
    fi

    case "$operation" in
        "add"|"write")
            # 写入操作：添加或更新容器ID与Pod IP的映射
            if [[ -z "$container_id" || -z "$pod_ip" ]]; then
                log_error "For 'add' operation, both container ID and Pod IP must be provided."
                return 1
            fi

            # 使用jq安全地添加或更新键值对
            if jq --arg id "$container_id" --arg ip "$pod_ip" '.[$id] = $ip' "$json_file" > "${json_file}.tmp"; then
                mv "${json_file}.tmp" "$json_file"
                log_info "Added/Updated IP mapping for container '$container_id' -> '$pod_ip' in $json_file"
            else
                log_error "Failed to write IP mapping to $json_file"
                return 1
            fi
            ;;

        "delete")
            # 删除操作：移除指定容器ID的映射记录
            if [[ -z "$container_id" ]]; then
                log_error "For 'delete' operation, container ID must be provided."
                return 1
            fi

            local ip_address
            ip_address=$(jq -r --arg id "$container_id" '.[$id] // empty' "$json_file")

            if [[ -n "$ip_address" ]]; then
                if jq --arg id "$container_id" 'del(.[$id])' "$json_file" > "${json_file}.tmp"; then
                    mv "${json_file}.tmp" "$json_file"
                    log_info "Removed IP mapping for container '$container_id' (IP: $ip_address) from $json_file"
                else
                    log_error "Failed to delete IP mapping for container '$container_id' from $json_file"
                    return 1
                fi
            else
                log_debug "No IP mapping found for container: $container_id"
            fi
            ;;

        "read")
            # 读取操作：获取指定容器ID对应的Pod IP
            if [[ -z "$container_id" ]]; then
                log_error "For 'read' operation, container ID must be provided."
                return 1
            fi

            local ip_address
            ip_address=$(jq -r --arg id "$container_id" '.[$id] // empty' "$json_file")
            if [[ -n "$ip_address" ]]; then
                echo "$ip_address" # 输出IP地址，便于调用者捕获
            else
                return 1 # 或者根据需求返回空而不报错
            fi
            ;;

        *)
            log_error "Unknown operation: $operation. Supported operations are 'add', 'read', or 'delete'."
            return 1
            ;;
    esac
}

# === 主业务逻辑 ===
execute_bwm_operations() {
    local veth_host="$1" pod_ip="$2" pid="$3" ingress_bw="$4" egress_bw="$5"
    
    log_info "Executing BWM operations for Pod IP: $pod_ip"
    
    # 执行bwmcli命令
    if nsenter -n -t "${pid}" bwmcli -e eth0; then
        log_info "Successfully executed nsenter-n -t ${pid} bwmcli -e eth0"
    else
        log_error "Failed to executed nsenter-n -t ${pid} bwmcli -e eth0"
#       return 1
    fi

    if bwmcli -s bandwidth "$egress_bw"; then
        log_info "Successfully executed bwmcli -s bandwidth $egress_bw"
    else
        log_error "Failed to execute bwmcli -s bandwidth $egress_bw"
#        return 1
    fi

    if bwmcli -a "$pod_ip"; then
        log_info "Successfully executed bwmcli -a $pod_ip"
    else
        log_error "Failed to execute bwmcli -a $pod_ip"
#        return 1
    fi

    if bwmcli -E "$veth_host"; then
        log_info "Successfully executed bwmcli -E $pod_ip"
    else
        log_error "Failed to execute bwmcli -E $pod_ip"
#        return 1
    fi

    if bwmcli -A "$pod_ip"; then
        log_info "Successfully executed bwmcli -A $pod_ip"
    else
        log_error "Failed to execute bwmcli -A $pod_ip"
#        return 1
    fi

    if bwmcli -S bandwidth "$ingress_bw"; then
        log_info "Successfully executed bwmcli -S bandwidth $ingress_bw"
    else
        log_error "Failed to execute bwmcli -S bandwidth $ingress_bw"
#        return 1
    fi
    log_info "Executing BWM operations for pid: $pid"
}

execute_bwm_delete_operations() {
    local veth_host="$1" pod_ip="$2" pid ="$3" ingress_bw="$4" egress_bw="$5"
    
    log_info "Executing BWM operations for Pod IP: $pod_ip"
    
    # 执行bwmcli命令
    if bwmcli -r "$pod_ip"; then
        log_info "Successfully executed bwmcli -r $pod_ip"
    else
        log_error "Failed to execute bwmcli -r $pod_ip"
#        return 1
    fi

    if bwmcli -R "$pod_ip"; then
        log_info "Successfully executed bwmcli -R $pod_ip"
    else
        log_error "Failed to execute bwmcli -R $pod_ip"
#        return 1
    fi
}



