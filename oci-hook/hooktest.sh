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
        cgroup_path=$(grep "net_cls,net_prio" "/proc/$pid/cgroup" | awk -F':' '{print $3}')
        log_info "cgroup_path: $cgroup_path"
        full_path="/sys/fs/cgroup/net_cls${cgroup_path}"
        log_info "方法一拼接结果: $full_path"
        POD_ID=$(extract_pod_id "$full_path")
        log_info "提取的Pod ID: $POD_ID"
        local veth_host pod_ip
        read -r veth_host pod_ip <<< "$(get_network_info "$pid")"
        
        log_info "Network info - veth_host: $veth_host, pod_ip: $pod_ip"
        #进入的是pause容器
        if [ "$pod_ip" == "null" ]; then

            update_json "$BAND_JSON_FILE" "$POD_ID" "$egress_bw" "$ingress_bw"

        else
            #业务容器
            log_info "POD_ID:$POD_ID"
            egress_bw=$(jq -r --arg key "$POD_ID" '.[$key].egress // empty' "$BAND_JSON_FILE")
            ingress_bw=$(jq -r --arg key "$POD_ID" '.[$key].ingress // empty' "$BAND_JSON_FILE")
            # 输出结果
            log_info "egress=$egress_bw"
            log_info "ingress=$ingress_bw"

            # 执行BWM操作
            if execute_bwm_operations "$veth_host" "$pod_ip" "$pid" "$ingress_bw" "$egress_bw"; then
                # 设置IP映射
                if [ -n "$container_id" ] && [ -n "$pod_ip" ]; then
                        manage_ip_mapping "$container_id" "$pod_ip" "add" "$IP_JSON_FILE"
                fi
            log_info "BWM operations completed successfully"
            else
                log_error "BWM operations failed"
                exit 1
            fi

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
