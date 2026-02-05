#!/bin/bash
###############################################################################
# Script: oci_hook_handler.sh
# Author: [zhangmingyi]
# Date: 2025-12-29
# Description: OCI Hook script for handling container network bandwidth management
# Usage: This script is triggered automatically by OCI hooks
###############################################################################

readonly LOG_FILE="/var/log/my-oci-hook.log"
readonly IP_JSON_FILE="/tmp/pod_ip_map.json"
readonly BAND_JSON_FILE="/tmp/pod_band.json"

init() {
    set -euo pipefail
    mkdir -p "$(dirname "$LOG_FILE")"
    log_info "OCI Hook triggered"
}

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*" >> "$LOG_FILE"
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*" >> "$LOG_FILE" >&2
}

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
    local pid container_id
    pid=$(echo "$container_state_json" | jq -r '.pid')
    container_id=$(echo "$container_state_json" | jq -r '.id')

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
        if [[ -z "$veth_host" ]]; then
            veth_host="null"
        fi
    else
        veth_host="null"
        echo "DEBUG: Could not determine veth host interface (veth_index not found)" >&2
    fi

    pod_ip=$(nsenter -n -t "$pid" ip -o -4 addr show eth0 2>&1 | awk '{print $4}' | cut -d'/' -f1)
    if [[ -z "$pod_ip" ]]; then
        pod_ip="null"
    elif ! [[ "$pod_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        pod_ip="null"
    fi
    echo "$veth_host $pod_ip"
}

extract_pod_id() {
    local path="$1"

    if [[ "$path" =~ /kubepods.*pod([^/._]+)[._] ]]; then
        local pod_id="${BASH_REMATCH[1]}"
        pod_id="${pod_id//_/-}"
        echo "pod$pod_id"
        return 0
    fi

    echo ""
    return 1
}

update_json() {
    local json_file="$1"
    local key="$2"
    local egress="$3"
    local ingress="$4"
    local bw_enabled="$5"

    if [ ! -f "$json_file" ]; then
        echo "{}" > "$json_file"
    fi

    jq --arg key "$key" \
       --arg egress "$egress" \
       --arg ingress "$ingress" \
       --arg bw_enabled "$bw_enabled" \
       'if has($key) then 
            .[$key].egress = $egress | 
            .[$key].ingress = $ingress |
            .[$key].bw_enabled = $bw_enabled
        else 
            .[$key] = { 
                egress: $egress, 
                ingress: $ingress, 
                bw_enabled: $bw_enabled 
            } 
        end' \
       "$json_file" > "${json_file}.tmp"

    mv "${json_file}.tmp" "$json_file"

    echo "write/update: $key -> egress=$egress, ingress=$ingress, bw_enabled=$bw_enabled"
}


delete_from_json() {
    local json_file="$1"
    local key="$2"

    if [ ! -f "$json_file" ]; then
        echo "error: JSON file is not exist: $json_file"
        return 1
    fi

    if ! jq -e "has(\"$key\")" "$json_file" > /dev/null; then
        echo "waring: not find Pod ID: $key"
        return 0
    fi

    echo "delete:"
    jq --arg key "$key" '.[$key]' "$json_file"

    if [ "$FORCE" = false ]; then
        read -p "are you sure delete(y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "op is cancel"
            return 0
        fi
    fi

    jq "del(.\"$key\")" "$json_file" > "${json_file}.tmp"

    if [ $? -eq 0 ]; then
        mv "${json_file}.tmp" "$json_file"
        echo "delete: $key"

        if [ "$(jq 'length' "$json_file")" -eq 0 ]; then
            rm "$json_file"
            echo "JSON file is not need delete"
        fi
    else
        echo "error: failed to delete"
        return 1
    fi
}

manage_ip_mapping() {
    local container_id="$1"
    local pod_ip="$2"
    local operation="${3:-delete}"
    local json_file="${4:-$IP_JSON_FILE}"
    log_info "manage_ip_mapping: operation=$operation, json_file=$json_file, container_id=$container_id, IP=$pod_ip"

    if [[ ! -f "$json_file" ]]; then
        echo "{}" > "$json_file"
        log_info "Created new JSON mapping file: $json_file"
    fi

    if ! jq empty "$json_file" 2>/dev/null; then
        echo "file: '$(cat "$json_file")'"
        echo "{}" > "$json_file"
    fi

    case "$operation" in
        "add"|"write")
            if [[ -z "$container_id" || -z "$pod_ip" ]]; then
                log_error "For 'add' operation, both container ID and Pod IP must be provided."
                return 1
            fi

            if jq --arg id "$container_id" --arg ip "$pod_ip" '.[$id] = $ip' "$json_file" > "${json_file}.tmp"; then
                mv "${json_file}.tmp" "$json_file"
                log_info "Current content of $json_file: $(cat "$json_file")"
                log_info "Added/Updated IP mapping for container '$container_id' -> '$pod_ip' in $json_file"
            else
                log_error "Failed to write IP mapping to $json_file"
                return 1
            fi
            ;;

        "delete")
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
            if [[ -z "$container_id" ]]; then
                log_error "For 'read' operation, container ID must be provided."
                return 1
            fi

            local ip_address
            ip_address=$(jq -r --arg id "$container_id" '.[$id] // empty' "$json_file")
            if [[ -n "$ip_address" ]]; then
                echo "$ip_address"
            else
                return 1
            fi
            ;;

        *)
            log_error "Unknown operation: $operation. Supported operations are 'add', 'read', or 'delete'."
            return 1
            ;;
    esac
}

execute_bwm_operations() {
    local veth_host="$1" pod_ip="$2" pid="$3" ingress_bw="$4" egress_bw="$5"

    log_info "Executing BWM operations for Pod IP: $pod_ip $ingress_bw $egress_bw"

    if nsenter -n -t "${pid}" bwmcli -e eth0; then
        log_info "Successfully executed nsenter-n -t ${pid} bwmcli -e eth0"
    else
        log_error "Failed to executed nsenter-n -t ${pid} bwmcli -e eth0"
        return 1
    fi

    cgroup_path=$(grep "net_cls,net_prio" "/proc/$pid/cgroup" | awk -F':' '{print $3}')
    full_path="/sys/fs/cgroup/net_cls${cgroup_path}"

    if bwmcli -s "$full_path" -1; then
        log_info "Successfully executed bwmcli -s $full_path"
    else
        log_error "Failed to execute bwmcli -s $full_path"
        return 1
    fi

    if bwmcli -a "$pod_ip" "$egress_bw"; then
        log_info "Successfully executed bwmcli -a $pod_ip $egress_bw"
    else
        log_error "Failed to execute bwmcli -a $pod_ip $egress_bw"
        return 1
    fi

    if bwmcli -E "$veth_host"; then
        log_info "Successfully executed bwmcli -E $pod_ip"
    else
        log_error "Failed to execute bwmcli -E $pod_ip"
        return 1
    fi

    if bwmcli -A "$pod_ip" "$ingress_bw"; then
        log_info "Successfully executed bwmcli -A $pod_ip $ingress_bw"
    else
        log_error "Failed to execute bwmcli -A $pod_ip $ingress_bw"
        return 1
    fi

    log_info "Executing BWM operations for pid: $pid"
}

execute_bwm_eth() {
    local veth_host="$1" pid="$2" 
    if nsenter -n -t "${pid}" bwmcli -e eth0; then
        log_info "Successfully executed nsenter-n -t ${pid} bwmcli -e eth0"
    else
        log_error "Failed to executed nsenter-n -t ${pid} bwmcli -e eth0"
        return 1
    fi

    if bwmcli -E "$veth_host"; then
        log_info "Successfully executed bwmcli -E $veth_host"
    else
        log_error "Failed to execute bwmcli -E $veth_host"
        return 1
    fi
}

execute_bwm_delete_operations() {
    local veth_host="$1" pod_ip="$2" pid ="$3" ingress_bw="$4" egress_bw="$5"
    
    log_info "Executing BWM operations for Pod IP: $pod_ip"

    if bwmcli -r "$pod_ip"; then
        log_info "Successfully executed bwmcli -r $pod_ip"
    else
        log_error "Failed to execute bwmcli -r $pod_ip"
        return 1
    fi

    if bwmcli -R "$pod_ip"; then
        log_info "Successfully executed bwmcli -R $pod_ip"
    else
        log_error "Failed to execute bwmcli -R $pod_ip"
        return 1
    fi
}
