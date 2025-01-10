#!/bin/bash

# Use packaged rabbitmq if available - to handle rpm/deb installation
# #########
# ######### NOTE : All the rabbitmq executables used in this file has to be prepended with ${rabbitmqBin}
# ######### Example : ${rabbitmqBin}rabbitmqctl
# #########
rabbitmqBin=${JF_PRODUCT_HOME}/app/third-party/rabbitmq/sbin/
if ! [ -x ${rabbitmqBin}rabbitmqctl ]; then
    rabbitmqBin=""
fi

function local_log() {
    local result="0"
    # use the logger method if it is available
    LC_ALL=C type logger > /dev/null 2>&1 || result="$?"
    if [[ "$result" != "0" ]]; then
        echo "$1"
        return 0
    fi
    logger "$1"
}

function check_node_health(){
    local_log "About to begin checking node health"
    local rabbitmq_ping=1
    local max_retry=10
    local counter=0
    until [[ ${rabbitmq_ping} == 0 || counter -eq ${max_retry} ]]; do
        ((counter++))
        ${rabbitmqBin}rabbitmq-diagnostics -q check_running > /dev/null 2>&1
        rabbitmq_ping=$?
        sleep 1
    done
    if [ "${rabbitmq_ping}" != "0" ]; then
        logError "RabbitMQ diagnostics have failed"
    else
        local_log "Done checking node health"
    fi
}

function set_policy(){
    ${rabbitmqBin}rabbitmqctl set_policy ha-all "." '{"ha-mode":"all", "ha-sync-mode":"automatic"}' --apply-to all --priority 0
    local ret_code=$?
    if [[ ${ret_code} != 0 ]]; then
        logError "Could not set policy, command [ ${rabbitmqBin}rabbitmqctl set_policy ha-all \".\" '{\"ha-mode\":\"all\", \"ha-sync-mode\":\"automatic\"}' --apply-to all --priority 0 ] exited with status code ${ret_code}"
        exit 1
    fi
}

function join_to_existing_cluster(){
    if [ -z "$JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME" ] || [ "$JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME" == "None" ]; then
        local_log "Method: [join_to_existing_cluster]. This node is not part of a cluster"
        return 0;
    fi

    local secondNode=$(${rabbitmqBin}rabbitmqctl cluster_status --formatter json 2>/dev/null | tr -d '\n' | tr -d ' ' | awk -F ']' '{print $2}' | awk -F '[' '{print $2}'  | tr -d '"' | awk -F ',' '{print $2}' | tr -d '\n' 2>/dev/null)
    
    if [ ! -z "${secondNode}" ]; then
        local_log "Cluster is already formed, skipping join action to [${JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME}]"
        set_policy
        return 0;
    fi

    local isContainer=$(isRunningInsideAContainer 2>/dev/null)

    # In docker-compose there is no need to add this node to a cluster now.
    if [ ! -z "${isContainer}" ] && [ "${isContainer}"  == "$FLAG_Y" ]; then
        local_log "Active node for this node is: [${JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME}]"
        set_policy
        ${rabbitmqBin}rabbitmqctl --node "rabbit@${JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME}" status 2>/dev/null
        ret_code=$?
        if [[ ${ret_code} != 0 ]]; then
            logError "Active node is: [${JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME}] but this node is not part of a cluster"
            rabbitmqctl stop_app
            exit 1
        fi
    else
        local_log "Check if the local rabbit is already part of the cluster: [${JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME}]"
        ${rabbitmqBin}rabbitmqctl --node "rabbit@${JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME}" status >/dev/null 2>&1
        ret_code=$?
        if [[ ${ret_code} == 0 ]]; then
            ${rabbitmqBin}rabbitmqctl stop_app && \
            ${rabbitmqBin}rabbitmqctl join_cluster rabbit@${JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME} && \
            ${rabbitmqBin}rabbitmqctl start_app && \
            set_policy
        fi
    fi
}

function check_cluster_node_health(){
    node_for_check=${1}
    rabbitmq_ping=1
    max_retry=30
    counter=0
    timeout_secs=60
    start_time=$(date +%s)
    timeout="false"
    until [[ ${rabbitmq_ping} == 0 || counter -eq ${max_retry} ]]; do
        ((counter++))
        local_log "Checking HEALTH for node [${node_for_check}]... (Attempt: [${counter}])"
        timeout 10 ${rabbitmqBin}rabbitmq-diagnostics -q check_running -n ${node_for_check} > /dev/null 2>&1
        rabbitmq_ping=$?
        if [ ${rabbitmq_ping} == 0 ]; then
            local_log "Node [${node_for_check}] is healthy"
        fi 
        sleep 1
        current_time=$(date +%s)
        elapsed_time=$((current_time - start_time))
        if [ $elapsed_time -ge $timeout_secs ]; then
            local_log "Timeout searching for node [${node_for_check}]..."
            timeout="true"
            break
        fi
    done
    if [[ counter -eq ${max_retry} || ${timeout} == "true" ]]; then
        warn "Reached maximum attempts for node ${node_for_check}"
        clean_cluster_node_if_configured ${node_for_check}
    fi
}

function clean_cluster_nodes(){
    local nodes=$(${rabbitmqBin}rabbitmqctl cluster_status --formatter json 2>/dev/null | tr -d '\n' | tr -d ' ' | awk -F ']' '{print $2}' | awk -F '[' '{print $2}'  | tr -d '"' | tr -s ',' ' ')
    local_log "Registered nodes are: ${nodes}"
    for node in ${nodes}; do
        check_cluster_node_health ${node}
    done
}

function clean_cluster_node_if_configured(){
    stopped_rabbitmq_node=${1}

    if [[ ${JF_SHARED_RABBITMQ_CLEAN} = [yY] ]]; then
        local_log "Removing node '${stopped_rabbitmq_node}' from cluster..."
        ${rabbitmqBin}rabbitmqctl forget_cluster_node ${stopped_rabbitmq_node}
        if [[ $? -ne 0 ]]; then
            local_log "FAILED to remove ${stopped_rabbitmq_node} from cluster"
        fi
    else
        local_log "Skipping removal of node ${stopped_rabbitmq_node}..."
        local_log "To get more information, you can try running: '${rabbitmqBin}rabbitmq-diagnostics -q check_running -n ${stopped_rabbitmq_node}'"
    fi
}

waitForRabbitServiceToStart() {
    local rabbitmq_ping=1
    local max_retry=30
    local counter=0
    until [[ ${rabbitmq_ping} == 0 || counter -eq ${max_retry} ]]; do
        ((counter++))
        local_log "Checking if the service is up ... (Attempt: ${counter})"
        ${rabbitmqBin}rabbitmqctl status > /dev/null 2>&1
        rabbitmq_ping=$?
        sleep 10
    done
    if [[ counter -eq ${max_retry} ]]; then
        warn "Reached maximum attempts (${max_retry}). Service does not seem to have started"
        return 1
    fi
    return 0
}

changeRabbitmqPassword(){
    grep "^default_pass.*" ${RABBITMQ_CONFIG_FILE} > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        local rabbitmqPassValue=$(grep "default_pass*" "${RABBITMQ_CONFIG_FILE}")
        rabbitmqPassValue=$(echo "${rabbitmqPassValue}" | awk -F"=" '{print $2}')
        rabbitmqPassValue=$(io_trim "${rabbitmqPassValue}")
        local check=(${rabbitmqBin}rabbitmqctl authenticate_user guest ${rabbitmqPassValue})
        if [[ ${check} =~ *Success* ]]; then
            return
        fi
        ${rabbitmqBin}rabbitmqctl change_password guest ${rabbitmqPassValue} > /dev/null 2>&1
        local_log "Changed password for guest"
    fi
}

main() {
    waitForRabbitServiceToStart || {
        return 1;
    }
    check_node_health
    changeRabbitmqPassword
    join_to_existing_cluster
    clean_cluster_nodes
}

local_log "Executing script as $(whoami)"

if [ ! -z "$JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME" ]; then
    local_log "Value of JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME is $JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME"
fi

main