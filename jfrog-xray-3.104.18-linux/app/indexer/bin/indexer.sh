#!/bin/bash
#
# Startup script for service
#

getPid() {
    # Identify process by its binary path
    export myPID=$(ps -ef | grep -i "${SERVICE_BIN}" | grep -v grep | awk -F' ' '{print $2}' 2>/dev/null)
}

exitError() {
    echo -e "\n\033[31mERROR: $1\033[0m\n"

    [ -z "${2}" ] || usage
    exit 1
}

PRODUCT_BIN_FOLDER="$(cd $(dirname "${BASH_SOURCE[0]}")/../../bin && pwd)"
defaultFile="${PRODUCT_BIN_FOLDER}/xray.default"

. ${defaultFile} || exitError "ERROR: $defaultFile does not exist or not executable"

: ${JF_PRODUCT_HOME:="$(cd ${PRODUCT_BIN_FOLDER}/../.. && pwd)"}

SCRIPT_NAME=indexer.sh
SERVICE_NAME=indexer
BINARY_NAME=jf-indexer
SERVICE_PID=${JF_PRODUCT_HOME}/app/run/${SERVICE_NAME}.pid

SERVICE_BIN="${JF_PRODUCT_HOME}/app/${SERVICE_NAME}/bin/${BINARY_NAME}"

usage() {
    cat << END_USAGE

${SCRIPT_NAME} - script for controlling ${SERVICE_NAME}

Usage: ./${SCRIPT_NAME} <action>

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

startupActions(){
    testVarPermissions
    syncEtc
    exportEnv "shared"
    exportEnv "${SERVICE_NAME}"
}

sourceScript(){
    local fileName=$1

    [ ! -z "${fileName}" ] || errorExit "target file is not passed to source a file"
    [   -f "${fileName}" ] || errorExit "${fileName} file is not found"
    source "${fileName}"   || errorExit "Unable to source ${fileName}, please check if the $USER user has permissions to perform this action"
}

initHelpers(){
    local systemYamlHelper="${PRODUCT_BIN_FOLDER}"/systemYamlHelper.sh
    local installerCommon="${PRODUCT_BIN_FOLDER}"/installerCommon.sh
    local xrayCommon="${PRODUCT_BIN_FOLDER}"/xrayCommon.sh

    export YQ_PATH="${PRODUCT_BIN_FOLDER}/../third-party/yq"
    sourceScript "${systemYamlHelper}"
    sourceScript "${xrayCommon}"
    sourceScript "${installerCommon}"

    # init at each service startup META
    export JF_SYSTEM_YAML="${JF_PRODUCT_HOME}/var/etc/system.yaml"
}

setExecutable() {
    local os=$(uname -s)
    local arch=$(uname -m)

    # Resolve OS
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

    # Resolve cpu Architecture
    case ${arch} in
        x86_64)
            arch=amd64
        ;;
        *)
            exitError "CPU architecture ${arch} is not supported"
        ;;
    esac
}

isRunning() {
    local ps=
    # Set binary to run
    setExecutable
    local bin=${SERVICE_BIN}
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
        ps=$(ps -ef | grep -i ${bin} | grep -v grep 2> /dev/null)
        PID_VALUE=$(echo -n ${ps} | awk '{print $2}')
    fi
    if [ -z "${ps}" ]; then
        if [ -z "${PID_VALUE}" ]; then
            return 1 # Not running
        else
            return 2 # PID exists but process dead
        fi
    else
        return 0 # Is running
    fi
}

runAppCommand() {
    exec ${SERVICE_BIN}
}

# Start process in background
start() {
    echo "Starting ${SERVICE_NAME}..."

    # Check if running
    isRunning
    case $? in
        0)
            echo "${SERVICE_NAME} is already running (PID: ${PID_VALUE})"
            restart
            return
        ;;
        1)
#            echo "${SERVICE_NAME} not running. Proceed to start it up."
        ;;
        2)
            echo "PID exists (${PID_VALUE}), but ${SERVICE_NAME} not running. Proceed to start it up."
        ;;
        *)
            exitError "Function isRunning() returned an unknown value ($?)"
        ;;
    esac

    if [ -n "$SERVICE_PID" ];
    then
        mkdir -p $(dirname "$SERVICE_PID") || \
        errorExit "Could not create dir for $SERVICE_PID";
    fi

    # Run from data directory to avoid nohup errors
    cd ${JF_PRODUCT_HOME}/var

    startupActions
    if $(isConsoleLogDisabled >/dev/null 2>&1); then
        runAppCommand >/dev/null 2>&1 &
    else
        _createConsoleLog
        runAppCommand >>"${JF_PRODUCT_HOME}"/var/log/console.log 2>&1 &
    fi

    local pid=$!
    echo -n "${pid}" > "${SERVICE_PID}"

    echo "${SERVICE_NAME} started. PID: ${pid}"
}

# Start process in foreground
run(){
    # Check if running
    isRunning
    case $? in
        0)
            echo "${SERVICE_NAME} is already running (PID: ${PID_VALUE})"
            return 0
        ;;
        1)
#            echo "${SERVICE_NAME} not running. Proceed to start it up."
        ;;
        2)
            echo "PID exists (${PID_VALUE}), but ${SERVICE_NAME} not running. Proceed to start it up."
        ;;
        *)
            exitError "Function isRunning() returned an unknown value ($?)"
        ;;
    esac

    startupActions
    if $(isConsoleLogDisabled >/dev/null 2>&1); then
        runAppCommand
    else
        runAppCommand > >(tee >( redirectServiceLogsToFile ) ) 2>&1
    fi
}

stop() {
    echo "Stopping ${SERVICE_NAME}..."

    # Check if running
    isRunning
    case $? in
        0)
            echo "${SERVICE_NAME} is running (PID: ${PID_VALUE}). Stopping it..."
        ;;
        1)
            echo "${SERVICE_NAME} not running."
            return 0
        ;;
        2)
            echo "PID exists (${PID_VALUE}), but ${SERVICE_NAME} not running. Removing PID file..."
            rm -f ${SERVICE_PID}
            return 0
        ;;
        *)
            exitError "Function isRunning() returned an unknown value ($?)"
        ;;
    esac

    # Kill using PID
    kill ${PID_VALUE} || exitError "Stopping ${SERVICE_NAME} failed"
    rm -f ${SERVICE_PID}
    echo "${SERVICE_NAME} stopped"
}

restart() {
    echo "Restarting ${SERVICE_NAME}..."
    ${JF_PRODUCT_HOME}/app/${SERVICE_NAME}/bin/${SCRIPT_NAME} stop
    sleep 1
    ${JF_PRODUCT_HOME}/app/${SERVICE_NAME}/bin/${SCRIPT_NAME} start $*
}

status() {
    echo -n "${SERVICE_NAME} is "

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
            echo "PID exists (${PID_VALUE}), but ${SERVICE_NAME} not running."
        ;;
        *)
            exitError "Function isRunning() returned an unknown value ($?)"
        ;;
    esac
}

initHelpers
processOptions $*
eval "${ACTION}"
