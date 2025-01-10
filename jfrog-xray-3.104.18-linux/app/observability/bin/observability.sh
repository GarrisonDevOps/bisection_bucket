#!/bin/bash
#
# Startup script for Observability service
#

getPid() {
    export myPID=$(ps -ef | grep -i "${SERVICE_BIN}" | grep -v grep | awk -F' ' '{print $2}' 2>/dev/null)
}

sourceScript(){
    local fileName=$1

    [ ! -z "${fileName}" ] || errorExit "Target file is not set"
    [   -f "${fileName}" ] || errorExit "${fileName} file is not found"
    source "${fileName}"   || errorExit "Unable to source ${fileName}, please check if the $USER user has permissions to perform this action"
}

initHelpers(){
    local systemYamlHelper="${JF_PRODUCT_HOME}"/app/bin/systemYamlHelper.sh
    local installerCommon="${JF_PRODUCT_HOME}"/app/bin/installerCommon.sh

    export YQ_PATH=""${JF_PRODUCT_HOME}"/app/third-party/yq"

    sourceScript "${systemYamlHelper}"
    sourceScript "${installerCommon}"

    export JF_SYSTEM_YAML="${JF_PRODUCT_HOME}/var/etc/system.yaml"
}

SERVICE_NAME=observability
SERVICE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_SCRIPT_NAME=${SERVICE_NAME}.sh

NAME=observability
export JF_PRODUCT_HOME=${JF_PRODUCT_HOME:-"$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"}

SERVICE_PID=${JF_PRODUCT_HOME}/app/run/${SERVICE_NAME}.pid

setServiceBin() {
    local os=$(uname -s)
    case ${os} in
        Linux)
            os=linux
        ;;
        Darwin)
            os=darwin
        ;;
        *)
            exitError "OS type ${os} is not supported"
        ;;
    esac

    SERVICE_BIN="${SERVICE_SCRIPT_DIR}/jf-${SERVICE_NAME}"
}
setServiceBin

usage() {
    cat << END_USAGE

${SERVICE_SCRIPT_NAME} - script for controlling ${NAME}

Usage: ./${SERVICE_SCRIPT_NAME} <action>

action:    help|start|stop|restart|status


END_USAGE

    exit 1
}

# Process command line options. See usage above for supported options
processOptions () {
    # Get action - help|start|stop|restart|status
    ACTION=${1}
    shift

    if [[ ! "${ACTION}" =~ ^(help|start|stop|restart|status)$ ]]; then
        usage
    fi

    if [[ "${ACTION}" =~ ^help$ ]]; then
        usage
    fi

    # Process the options
    while [[ $# > 0 ]]; do
        case "$1" in
            *)
                usage
            ;;
        esac
    done

}

serviceBinExists() {
    if [[ -f "${SERVICE_BIN}" ]]; then
        return 0
    else
        return 1
    fi
}

isRunning() {
    # Check running state by PID
    if [ -e "${SERVICE_PID}" ]; then
        PID_VALUE=$(cat ${SERVICE_PID})
        if [ -n "${PID_VALUE}" ]; then
            unset ps
            getPid
            if [[ ! -z "${myPID}" ]];then
                export ps="${myPID}"
            fi
        fi
    else
        # Try and find by process
        local ps=$(ps -ef | grep -i ${SERVICE_BIN} | grep -v grep 2> /dev/null)
        PID_VALUE=$(echo -n ${ps} | awk '{print $2}')
    fi
    if [[ -z "${ps}" ]]; then
        if [ -z "${PID_VALUE}" ]; then
            return 1 # Not running
        else
            return 2 # PID exists but process dead
        fi
    else
        return 0 # Is running
    fi
}

startupActions(){
    exportEnv "shared"
    exportEnv "${SERVICE_NAME}"
}

start() {
    if serviceBinExists;then
        echo "Starting ${NAME}..."

        # Check if running
        isRunning
        case $? in
            0)
                echo "${NAME} is already running (PID: ${PID_VALUE})"
                restart
                return 0
            ;;
            1)
                echo "${NAME} not running. Proceed to start it up."
            ;;
            2)
                echo "PID exists (${PID_VALUE}), but ${NAME} not running. Proceed to start it up."
            ;;
            *)
                exitError "Function isRunning() returned an unknown value ($?)"
            ;;
        esac

        mkdir -p ${JF_PRODUCT_HOME}/app/run
        
        startupActions

        if [ $(isRunningInsideAContainer)  == "$FLAG_Y" ]; then
            if $(isConsoleLogDisabled >/dev/null 2>&1); then
                ${SERVICE_BIN} &
            else
                ${SERVICE_BIN} > >(tee >( redirectServiceLogsToFile ) ) 2>&1 &
            fi
        else
            if $(isConsoleLogDisabled >/dev/null 2>&1); then
                ${SERVICE_BIN} >/dev/null 2>&1 &
            else
                _createConsoleLog
                ${SERVICE_BIN} >>"${JF_PRODUCT_HOME}"/var/log/console.log 2>&1 &
            fi
        fi
        
        local pid=$!
        echo -n ${pid} > ${SERVICE_PID}

        echo "${NAME} started. PID: ${pid}"
    fi
}

# Start process in foreground
run() {
    if serviceBinExists; then
        startupActions
        if $(isConsoleLogDisabled >/dev/null 2>&1); then
            exec ${SERVICE_BIN}
        else
            exec ${SERVICE_BIN} > >(tee >( redirectServiceLogsToFile ) ) 2>&1
        fi
    fi
}

stop() {
    echo "Stopping ${NAME}..."

    # Check if running
    isRunning
    case $? in
        0)
            echo "${NAME} is running (PID: ${PID_VALUE}). Stopping it..."
        ;;
        1)
            echo "${NAME} not running."
            return 0
        ;;
        2)
            echo "PID exists (${PID_VALUE}), but ${NAME} not running. Removing PID file..."
            rm -f ${SERVICE_PID}
            return 0
        ;;
        *)
            exitError "Function isRunning() returned an unknown value ($?)"
        ;;
    esac

    # Kill using PID
    kill ${PID_VALUE} || exitError "Stopping ${NAME} failed"
    rm -f ${SERVICE_PID}
    echo "${NAME} stopped"
}

restart() {
    echo "Restarting ${NAME}..."
    ${SERVICE_SCRIPT_DIR}/${SERVICE_SCRIPT_NAME} stop
    # Breathing space after stop - its too fast
    sleep 1
    ${SERVICE_SCRIPT_DIR}/${SERVICE_SCRIPT_NAME} start $*
}

status() {
    echo -n "${NAME} is "

    # Check if running
    isRunning
    case $? in
        0)
            echo "running (PID: ${PID_VALUE})"
        ;;
        1)
            echo "not running"
        ;;
        2)
            echo "PID exists (${PID_VALUE}), but ${NAME} not running."
        ;;
        *)
            exitError "Function isRunning() returned an unknown value ($?)"
        ;;
    esac
}

initHelpers

# run application in the foreground if nothing is passed - rpm and docker flow
if [[ $# == 0 ]]; then 
    run
else
    processOptions $*
fi

eval ${ACTION}
