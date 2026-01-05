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

source /var/lib/docker/hooks/libhook.sh
set -x
# === 主函数 ===
main() {
    local container_state_json
    container_state_json=$(cat <&0)
    log_info "OCI Hook main ----------------------------------------------------------------"
    # 记录接收到的原始数据（调试用途）
    log_debug "Received container state JSON: $container_state_json"
    
    # 获取容器基本信息
    local pid container_id
    read -r pid container_id <<< "$(get_container_info "$container_state_json")"
    
    # 获取容器标签配置
    local bw_enabled ingress_bw egress_bw config_path
    read -r bw_enabled ingress_bw egress_bw config_path <<< "$(get_container_labels "$container_id")"
    
    log_info "Container $container_id (PID: $pid) - BWM enabled: $bw_enabled"
    log_debug "Ingress bandwidth: $ingress_bw, Egress bandwidth: $egress_bw"
    
    # 只有在BWM启用时才执行网络操作
    #if [[ "$bw_enabled" == "true" ]]; then
        local veth_host pod_ip
        read -r veth_host pod_ip <<< "$(get_network_info "$pid")"
        
        log_info "Network info - veth_host: $veth_host, pod_ip: $pod_ip"
        
        # 执行BWM操作
        if execute_bwm_operations "$veth_host" "$pod_ip" "$pid" "$ingress_bw" "$egress_bw"; then
            # 设置IP映射
	    if [ -n "$container_id" ] && [ -n "$pod_ip" ]; then
                manage_ip_mapping "$container_id" "$pod_ip" "add" "$JSON_FILE"
	    fi
            log_info "BWM operations completed successfully"
        else
            log_error "BWM operations failed"
            exit 1
        fi
    # else
    #     log_info "BWM plugin not enabled for this container, skipping operations"
    # fi
}

# === 脚本执行入口 ===
{
    init
    check_dependencies
    log_info "OCI Hook check_dependencies"
    main "$@"
    log_info "OCI Hook finished successfully"
} || {
    log_error "OCI Hook execution failed"
    exit 1
}
