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

main() {
    local container_state_json
    container_state_json=$(cat <&0)

    local pid container_id
    read -r pid container_id <<< "$(get_container_info "$container_state_json")"

    local bw_enabled ingress_bw egress_bw config_path
    read -r bw_enabled ingress_bw egress_bw config_path <<< "$(get_container_labels "$container_id")"

    local veth_host pod_ip
    read -r veth_host pod_ip <<< "$(get_network_info "$pid")"

    cgroup_path=$(grep "net_cls,net_prio" "/proc/$pid/cgroup" | awk -F':' '{print $3}')
    full_path="/sys/fs/cgroup/net_cls${cgroup_path}"
    POD_ID=$(extract_pod_id "$full_path")+

    log_info "OCI Hook main ----------------------------------------------------------------
    Container $container_id (PID: $pid) bw_enabled:$bw_enabled ingress_bw:$ingress_bw egress_bw:$egress_bw veth_host:$veth_host pod_ip:$pod_ip POD_ID:$POD_ID cgroup_path:$full_path"

    if [[ "$bw_enabled" != "null" ]] && [[ "$pod_ip" == "null" ]]; then
        log_info "pause container update_json"
        update_json "$BAND_JSON_FILE" "$POD_ID" "$egress_bw" "$ingress_bw" "$bw_enabled"
    elif [[ "$pod_ip" != "null" ]] && [[ $(jq -r --arg key "$POD_ID" '.[$key].bw_enabled // empty' "$BAND_JSON_FILE") == "false" ]]; then
        log_info "pod container POD_ID:$POD_ID    execute_bwm_eth"
        execute_bwm_eth "$veth_host" "$pid"
    elif [[ "$pod_ip" != "null" ]] && [[ $(jq -r --arg key "$POD_ID" '.[$key].bw_enabled // empty' "$BAND_JSON_FILE") == "true" ]]; then
        log_info "pod container POD_ID:$POD_ID"
        egress_bw=$(jq -r --arg key "$POD_ID" '.[$key].egress // empty' "$BAND_JSON_FILE")
        ingress_bw=$(jq -r --arg key "$POD_ID" '.[$key].ingress // empty' "$BAND_JSON_FILE")
        log_info "egress=$egress_bw ingress=$ingress_bw"
        if execute_bwm_operations "$veth_host" "$pod_ip" "$pid" "$ingress_bw" "$egress_bw"; then
            if [ -n "$container_id" ] && [ -n "$pod_ip" ]; then
                    manage_ip_mapping "$container_id" "$pod_ip" "add" "$IP_JSON_FILE"
            fi
            log_info "BWM operations completed successfully"
        else
            log_error "BWM operations failed"
            exit 1
        fi
    else
        log_info "BWM plugin not enabled for this container, skipping operations"
    fi
}

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
