#!/bin/bash
source /var/lib/docker/hooks/libhook.sh

main() {
    local container_state_json
    container_state_json=$(cat <&0)

    local pid container_id
    read -r pid container_id <<< "$(get_container_info "$container_state_json")"

    POD_ID=$(get_pod_id_from_config "$container_id")
    IS_PAUSE=$(is_sandbox_container "$container_id")

    log_info "OCI Hook Poststop --- Container:$container_id IS_PAUSE:$IS_PAUSE POD_ID:$POD_ID"

    if [[ -z "$POD_ID" ]]; then
        log_error "Poststop aborted: Cannot resolve POD_ID for container $container_id."
        return 0
    fi

    # Only perform cleanup if this is the pause container. 
    # Business containers may stop before the pause container, and we want
    # to keep BWM rules active until the entire pod is stopped.
    if [[ "$IS_PAUSE" != "true" ]]; then
        log_info "Business container stopped. Leaving Pod BWM intact."
        return 0
    fi

    # At this point, we know the pause container is stopping.
    # which means the entire pod is stopping. We should clean up any BWM
    # rules and remove the pod's entry from the configuration file.
    log_info "Pause container stopped. Final cleanup for POD_ID:$POD_ID"

    if [[ -f "$BAND_JSON_FILE" ]]; then
        local saved_ip applied_state
        saved_ip=$(jq -r --arg key "$POD_ID" '.[$key].pod_ip // empty' "$BAND_JSON_FILE")
        applied_state=$(jq -r --arg key "$POD_ID" '.[$key].applied // empty' "$BAND_JSON_FILE")

        if [[ "$applied_state" == "true" ]]; then
            if [[ -n "$saved_ip" && "$saved_ip" != "null" ]]; then
                log_info "Deleting eBPF BWM rules for IP: $saved_ip"
                execute_bwm_delete_operations "" "$saved_ip" "" "" ""
            else
                log_error "Inconsistent state: applied is true but pod_ip is missing for POD_ID: $POD_ID"
            fi
        fi
    else
        log_info "No configuration file found ($BAND_JSON_FILE). Nothing to clean up."
    fi

    if ! delete_from_json "$BAND_JSON_FILE" "$POD_ID"; then
        log_error "Failed to remove POD_ID $POD_ID from configuration file."
    fi
}

{
    init
    check_dependencies
    main "$@"
} || {
    exit 1
}