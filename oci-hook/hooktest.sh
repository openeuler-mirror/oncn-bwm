#!/bin/bash
source /var/lib/docker/hooks/libhook.sh

main() {
    local container_state_json
    container_state_json=$(cat <&0)

    local pid container_id
    read -r pid container_id <<< "$(get_container_info "$container_state_json")"

    local bw_enabled ingress_bw egress_bw config_path
    read -r bw_enabled ingress_bw egress_bw config_path <<< "$(get_container_labels "$container_id")"

    local veth_host pod_ip
    read -r veth_host pod_ip <<< "$(get_network_info "$pid")"

    POD_ID=$(get_pod_id_from_config "$container_id")
    IS_PAUSE=$(is_sandbox_container "$container_id")

    log_info "OCI Hook Prestart --- Container:$container_id IS_PAUSE:$IS_PAUSE POD_ID:$POD_ID"

    if [[ -z "$POD_ID" ]]; then
        log_error "Prestart aborted: Cannot resolve POD_ID for container $container_id."
        return 0
    fi

    if [[ "$IS_PAUSE" == "true" ]]; then
        if [[ "$bw_enabled" != "null" ]]; then
            log_info "Pause container detected. Initializing pod_band.json (applied=false)..."
            (
                flock -x 200
                if [ ! -f "$BAND_JSON_FILE" ]; then echo "{}" > "$BAND_JSON_FILE"; fi
                
                if ! jq --arg key "$POD_ID" --arg eg "$egress_bw" --arg ig "$ingress_bw" --arg bw "$bw_enabled" \
                   '.[$key] = {egress: $eg, ingress: $ig, bw_enabled: $bw, applied: "false", pod_ip: ""}' \
                   "$BAND_JSON_FILE" > "${BAND_JSON_FILE}.tmp"; then
                    log_error "jq error: Failed to parse or write JSON for POD_ID: $POD_ID"
                    exit 1
                fi
                mv "${BAND_JSON_FILE}.tmp" "$BAND_JSON_FILE"
            ) 200> "$GLOBAL_LOCK_FILE"
        fi
    else
        if [[ -f "$BAND_JSON_FILE" ]]; then
            local bw_enabled_state applied_state
            bw_enabled_state=$(jq -r --arg key "$POD_ID" '.[$key].bw_enabled // empty' "$BAND_JSON_FILE")
            applied_state=$(jq -r --arg key "$POD_ID" '.[$key].applied // empty' "$BAND_JSON_FILE")

            if [[ -n "$bw_enabled_state" && "$applied_state" == "false" ]]; then
                if [[ "$pod_ip" == "null" ]]; then
                    log_error "Business container started but pod_ip is null. Skipping BWM application."
                    return 0
                fi

                log_info "First business container (IP: $pod_ip). Applying BWM rules..."
                local op_success="false"
                
                if [[ "$bw_enabled_state" == "false" ]]; then
                    if execute_bwm_eth "$veth_host" "$pid"; then op_success="true"; fi
                elif [[ "$bw_enabled_state" == "true" ]]; then
                    local saved_egress saved_ingress
                    saved_egress=$(jq -r --arg key "$POD_ID" '.[$key].egress // empty' "$BAND_JSON_FILE")
                    saved_ingress=$(jq -r --arg key "$POD_ID" '.[$key].ingress // empty' "$BAND_JSON_FILE")
                    if execute_bwm_operations "$veth_host" "$pod_ip" "$pid" "$saved_ingress" "$saved_egress"; then
                        op_success="true"
                    fi
                fi

                if [[ "$op_success" == "true" ]]; then
                    (
                        flock -x 200
                        if ! jq --arg key "$POD_ID" --arg ip "$pod_ip" '.[$key].applied = "true" | .[$key].pod_ip = $ip' \
                           "$BAND_JSON_FILE" > "${BAND_JSON_FILE}.tmp"; then
                            log_error "jq error: Failed to update applied status for POD_ID: $POD_ID"
                            exit 1
                        fi
                        mv "${BAND_JSON_FILE}.tmp" "$BAND_JSON_FILE"
                    ) 200> "$GLOBAL_LOCK_FILE"
                    log_info "BWM applied successfully for POD_ID:$POD_ID"
                else
                    log_error "BWM operations failed for container $container_id"
                    exit 1
                fi
            elif [[ "$applied_state" == "true" ]]; then
                log_info "BWM already applied by previous container in this Pod. Skipping."
            fi
        fi
    fi
}

{
    init
    check_dependencies
    main "$@"
} || {
    exit 1
}