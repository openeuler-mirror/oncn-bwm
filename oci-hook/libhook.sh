#!/bin/bash
###############################################################################
# Script: oci_hook_handler.sh
# Author: [zhangmingyi]
# Date: 2025-12-29
# Description: OCI Hook script for handling container network bandwidth management
# Usage: This script is triggered automatically by OCI hooks
###############################################################################

readonly LOG_FILE="/var/log/my-oci-hook.log"
readonly BAND_JSON_FILE="/tmp/pod_band.json"
readonly GLOBAL_LOCK_FILE="/var/lock/oncn-bwm-oci.lock"

init() {
    set -euo pipefail
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$GLOBAL_LOCK_FILE")"
}

log_info() { echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*" >> "$LOG_FILE"; }
log_error() { echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*" >> "$LOG_FILE" >&2; }
log_debug() { echo "$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] $*" >> "$LOG_FILE"; }

check_dependencies() {
    local dependencies=("jq" "nsenter" "ethtool" "ip" "flock")
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Missing required command: $cmd"
            exit 1
        fi
    done
}

get_container_info() {
    local container_state_json="$1"
    local pid container_id
    pid=$(echo "$container_state_json" | jq -r '.pid // empty')
    container_id=$(echo "$container_state_json" | jq -r '.id // empty')
    
    if [[ -z "$pid" || -z "$container_id" ]]; then
        log_error "Failed to extract PID or Container ID from state JSON. Raw JSON: $container_state_json"
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
    bw_enabled=$(jq -r '.Config.Labels["annotation.enable-feature"] // "null"' "$config_path")
    ingress_bw=$(jq -r '.Config.Labels["annotation.bandwidth-ingress"] // ""' "$config_path")
    egress_bw=$(jq -r '.Config.Labels["annotation.bandwidth-egress"] // ""' "$config_path")

    ingress_bw="${ingress_bw//-/,}"
    egress_bw="${egress_bw//-/,}"
    echo "$bw_enabled $ingress_bw $egress_bw $config_path"
}

get_network_info() {
    local pid="$1"
    local veth_index veth_host pod_ip

    veth_index=$(nsenter -n -t "$pid" ethtool -S eth0 2>&1 | grep peer_ifindex | awk -F: '{print $2}' | tr -d ' ')
    if [[ -n "$veth_index" ]]; then
        veth_host=$(ip -o link show 2>/dev/null | awk -F'[@:]' -v idx="$veth_index" '$1 == idx {print $2}')
        [[ -z "$veth_host" ]] && veth_host="null"
    else
        log_error "Could not determine veth host interface (veth_index not found for PID $pid)"
        veth_host="null"
    fi

    pod_ip=$(nsenter -n -t "$pid" ip -o -4 addr show eth0 2>&1 | awk '{print $4}' | cut -d'/' -f1)
    if [[ -z "$pod_ip" ]] || ! [[ "$pod_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "Failed to extract valid IPv4 address for PID $pid. Got: $pod_ip"
        pod_ip="null"
    fi
    echo "$veth_host $pod_ip"
}

get_pod_id_from_config() {
    local container_id="$1"
    local config_path="/var/lib/docker/containers/$container_id/config.v2.json"
    if [[ ! -f "$config_path" ]]; then 
        log_error "Cannot get POD_ID, config not found: $config_path"
        return 1
    fi

    local pod_uid
    pod_uid=$(jq -r '.Config.Labels["io.kubernetes.pod.uid"] // empty' "$config_path")
    if [[ -n "$pod_uid" ]]; then
        echo "pod${pod_uid//_/-}"
    else
        log_error "Label io.kubernetes.pod.uid not found for container $container_id"
        echo ""
    fi
}

is_sandbox_container() {
    local container_id="$1"
    local config_path="/var/lib/docker/containers/$container_id/config.v2.json"
    if [[ ! -f "$config_path" ]]; then echo "false"; return; fi

    local container_name
    container_name=$(jq -r '.Config.Labels["io.kubernetes.container.name"] // empty' "$config_path")
    if [[ "$container_name" == "POD" ]]; then
        echo "true"
    else
        echo "false"
    fi
}

delete_from_json() {
    local json_file="$1"
    local key="$2"

    (
        flock -x 200
        if [ ! -f "$json_file" ]; then exit 0; fi
        if ! jq -e "has(\"$key\")" "$json_file" > /dev/null 2>&1; then exit 0; fi

        if jq "del(.\"$key\")" "$json_file" > "${json_file}.tmp"; then
            mv "${json_file}.tmp" "$json_file"
            log_info "Deleted key: $key from $json_file"
            if [ "$(jq 'length' "$json_file" 2>/dev/null || echo 1)" -eq 0 ]; then
                rm -f "$json_file"
            fi
        else
            log_error "Failed to delete key: $key from $json_file (jq process failed)"
            exit 1
        fi
    ) 200> "$GLOBAL_LOCK_FILE"
    return $?
}

execute_bwm_operations() {
    local veth_host="$1" pod_ip="$2" pid="$3" ingress_bw="$4" egress_bw="$5"
    
    if ! nsenter -n -t "${pid}" bwmcli -e eth0; then
        log_error "bwmcli error: Failed to enable egress on eth0 for PID $pid"
        return 1
    fi
    
    local cgroup_path full_path
    cgroup_path=$(grep "net_cls,net_prio" "/proc/$pid/cgroup" | awk -F':' '{print $3}')
    if [[ -z "$cgroup_path" ]]; then
        log_error "bwmcli error: Could not extract cgroup path for PID $pid"
        return 1
    fi
    
    full_path="/sys/fs/cgroup/net_cls${cgroup_path}"
    if ! bwmcli -s "$full_path" -1; then
        log_error "bwmcli error: Failed to set cgroup prio to -1 on $full_path"
        return 1
    fi

    if ! bwmcli -a "$pod_ip" "$egress_bw"; then
        log_error "bwmcli error: Failed to add egress rule for IP $pod_ip ($egress_bw)"
        return 1
    fi

    if ! bwmcli -E "$veth_host"; then
        log_error "bwmcli error: Failed to enable ingress on veth $veth_host"
        return 1
    fi

    if ! bwmcli -A "$pod_ip" "$ingress_bw"; then
        log_error "bwmcli error: Failed to add ingress rule for IP $pod_ip ($ingress_bw)"
        return 1
    fi
    
    return 0
}

execute_bwm_eth() {
    local veth_host="$1" pid="$2" 
    if ! nsenter -n -t "${pid}" bwmcli -e eth0; then
        log_error "bwmcli error: Failed to enable egress on eth0 for PID $pid"
        return 1
    fi
    if ! bwmcli -E "$veth_host"; then
        log_error "bwmcli error: Failed to enable ingress on veth $veth_host"
        return 1
    fi
    return 0
}

execute_bwm_delete_operations() {
    local pod_ip="$2"
    log_info "Executing BWM delete operations for Pod IP: $pod_ip"
    
    if ! bwmcli -r "$pod_ip"; then
        log_error "bwmcli cleanup error: Failed to remove egress rule for IP $pod_ip"
    fi
    
    if ! bwmcli -R "$pod_ip"; then
        log_error "bwmcli cleanup error: Failed to remove ingress rule for IP $pod_ip"
    fi
}