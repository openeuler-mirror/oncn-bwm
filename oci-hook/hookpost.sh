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

    if bwmcli -r "$pod_ip"; then
        log_info "Successfully executed bwmcli -r $pod_ip"
    else
        log_error "Failed to execute bwmcli -r $pod_ip"
    fi

    if bwmcli -R "$pod_ip"; then
        log_info "Successfully executed bwmcli -R $pod_ip"
    else
        log_error "Failed to execute bwmcli -R $pod_ip"
    fi
}

main() {
    local container_state_json
    container_state_json=$(cat <&0)

    local pid container_id
    read -r pid container_id <<< "$(get_container_info "$container_state_json")"

    local bw_enabled ingress_bw egress_bw config_path
    read -r bw_enabled ingress_bw egress_bw config_path <<< "$(get_container_labels "$container_id")"
    
    log_info "OCI Hook delete --------------------------------------------------------
    Container $container_id (PID: $pid) - BWM enabled: $bw_enabled"

    local veth_host pod_ip

	pod_ip=$(manage_ip_mapping "$container_id" "" "read" "$IP_JSON_FILE")
    if [[ -n "$pod_ip" ]];then
        if execute_bwm_delete_operationsss "" "$pod_ip" "" "" ""; then
            manage_ip_mapping "$container_id" "$pod_ip" "delete" "$IP_JSON_FILE"
            log_info "BWM operations completed successfully"
        else
            log_error "BWM operations failed"
        fi
    fi

    local pod_id_key
    pod_id_key=$(get_pod_id_from_config "$container_id")

    if [[ -n "$pod_id_key" ]]; then
        export FORCE=true 
        delete_from_json "$BAND_JSON_FILE" "$pod_id_key"
        log_info "Cleaned up bandwidth config for $pod_id_key"
    else
        log_info "Skip pod_band.json cleanup: Pod UID not found in config"
    fi
}

{
    init
    check_dependencies
    main "$@"
    log_info "OCI Hook finished successfully"
} || {
    log_error "OCI Hook execution failed"
    exit 1
}
