#!/bin/bash
###############################################################################
# Script: oci_hook_handler.sh
# Author: [zhangmingyi]
# Date: 2025-12-29
# Description: OCI Hook script for handling container network bandwidth management
# Usage: This script is triggered automatically by OCI hooks
###############################################################################

source /var/lib/docker/hooks/libhook.sh
set -x

execute_bwm_delete_operationsss() {
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

# === 主函数 ===
main() {
    local container_state_json
    container_state_json=$(cat <&0)
   
    log_info "OCI Hook delete --------------------------------------------------------" 
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
    # if [[ "$bw_enabled" == "true" ]]; then
        local veth_host pod_ip
        
	pod_ip=$(manage_ip_mapping "$container_id" "" "read" "$IP_JSON_FILE" 2>&1 | tail -1)
	log_info "pod_ip:$pod_ip"
	# 执行BWM操作
        if execute_bwm_delete_operationsss "" "$pod_ip" "" "" ""; then
            # 清理IP映射
            log_info "BWM end -2"
	    manage_ip_mapping "$container_id" "$pod_ip" "delete" "$IP_JSON_FILE"
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
    main "$@"
    log_info "OCI Hook finished successfully"
} || {
    log_error "OCI Hook execution failed"
    exit 1
}
