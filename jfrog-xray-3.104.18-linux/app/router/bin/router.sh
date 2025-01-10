#!/bin/bash
#
# Startup script for Artifactory Router
#

getPid() {
    # Identify process which is running router binary
    export myPID=$(ps -ef | grep -i "${ROUTER_BIN}" | grep -v grep | awk -F' ' '{print $2}' 2>/dev/null)
}

exitError() {
    echo -e "\n\033[31mERROR: $1\033[0m\n"

    [ -z "${2}" ] || usage
    exit 1
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

ROUTER_NAME=router
ROUTER_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROUTER_SCRIPT_NAME=${ROUTER_NAME}.sh

NAME=router
export JF_PRODUCT_HOME=${JF_PRODUCT_HOME:-"$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"}

ROUTER_PID=${JF_PRODUCT_HOME}/app/run/${ROUTER_NAME}.pid

# copy custom certificate and private key from ${JF_PRODUCT_HOME}/var/bootstrap/router/keys to ${JF_PRODUCT_HOME}/var/data/router/keys
bootstrapCustomCertsAndKeys() {
    local routerDataKeysPath="${JF_PRODUCT_HOME}/var/data/router/keys"
    local routerBootstrapKeysPath="${JF_PRODUCT_HOME}/var/bootstrap/router/keys"
    local customServerExtn="crt"
    local fileExtn=
    local supportFileExtns="crt cer pem"
    
    if [[ -d "${routerBootstrapKeysPath}" ]]; then
        for fileExtn in ${supportFileExtns}; do
            local customCertList=$(ls ${routerBootstrapKeysPath})
            if [[ "${customCertList}" == *"custom-server.${fileExtn}"* ]]; then
                customServerExtn="${fileExtn}"
            fi
        done
    fi

    if [[ -f "${routerBootstrapKeysPath}/custom-server.${customServerExtn}" && -f "${routerBootstrapKeysPath}/custom-server.key" ]]; then
        echo "Copying custom-server.${customServerExtn} and custom-server.key from  ${routerBootstrapKeysPath} to ${routerDataKeysPath}"
        mkdir -p ${routerDataKeysPath} || errorExit "Failed to create ${routerDataKeysPath}"
        cp -f "${routerBootstrapKeysPath}/custom-server.${customServerExtn}" "${routerDataKeysPath}/custom-server.${customServerExtn}" || errorExit "Failed to copy ${routerBootstrapKeysPath}/custom-server.${customServerExtn} to ${routerDataKeysPath}/custom-server.${customServerExtn}"
        cp -f "${routerBootstrapKeysPath}/custom-server.key" "${routerDataKeysPath}/custom-server.key" || errorExit "Failed to copy ${routerBootstrapKeysPath}/custom-server.key to ${routerDataKeysPath}/custom-server.key"
        rm -f "${routerBootstrapKeysPath}/custom-server.${customServerExtn}" || warn "Failed to remove ${routerBootstrapKeysPath}/custom-server.${customServerExtn}"
        rm -f "${routerBootstrapKeysPath}/custom-server.key" || warn "Failed to remove ${routerBootstrapKeysPath}/custom-server.key"
    elif [[ ! -f "${routerBootstrapKeysPath}/custom-server.${customServerExtn}" && -f "${routerBootstrapKeysPath}/custom-server.key" ]]; then
        errorExit "custom-server.key found, but could not find custom-server.${customServerExtn} in path ${routerBootstrapKeysPath}"
    elif [[ -f "${routerBootstrapKeysPath}/custom-server.${customServerExtn}" && ! -f "${routerBootstrapKeysPath}/custom-server.key" ]]; then
        errorExit "custom-server.${customServerExtn} found, but could not find custom-server.key in path ${routerBootstrapKeysPath}"
    else
        #Using default router's certificate and private key
        echo "Using default router's certificate and private key"
    fi
}

setRouterBin() {
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

    ROUTER_BIN="${ROUTER_SCRIPT_DIR}/jf-router"
}
setRouterBin

usage() {
    cat << END_USAGE

${ROUTER_SCRIPT_NAME} - script for controlling ${NAME}

Usage: ./${ROUTER_SCRIPT_NAME} <action>

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

routerBinExists() {
    if [[ -f "${ROUTER_BIN}" ]]; then
        return 0
    else
        return 1
    fi
}

isRunning() {
    # Check running state by PID
    if [ -e "${ROUTER_PID}" ]; then
        PID_VALUE=$(cat ${ROUTER_PID})
        if [ -n "${PID_VALUE}" ]; then
            unset ps
            getPid
            if [[ ! -z "${myPID}" ]];then
                export ps="${myPID}"
            fi
        fi
    else
        # Try and find by process
        local ps=$(ps -ef | grep -i ${ROUTER_BIN} | grep -v grep 2> /dev/null)
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
    exportEnv "${ROUTER_NAME}"
}

start() {
    if routerBinExists;then
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
                ${ROUTER_BIN} &
            else
                ${ROUTER_BIN} > >(tee >( redirectServiceLogsToFile ) ) 2>&1 &
            fi
        else
            if $(isConsoleLogDisabled >/dev/null 2>&1); then
                ${ROUTER_BIN} >/dev/null 2>&1 &
            else
                _createConsoleLog
                ${ROUTER_BIN} >>"${JF_PRODUCT_HOME}"/var/log/console.log 2>&1 &
            fi
        fi
        
        local pid=$!
        echo -n ${pid} > ${ROUTER_PID}

        echo "${NAME} started. PID: ${pid}"
    fi
}

# Start process in foreground
run() {
    if routerBinExists; then
        startupActions
        if $(isConsoleLogDisabled >/dev/null 2>&1); then
            exec ${ROUTER_BIN}
        else
            exec ${ROUTER_BIN} > >(tee >( redirectServiceLogsToFile ) ) 2>&1
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
            rm -f ${ROUTER_PID}
            return 0
        ;;
        *)
            exitError "Function isRunning() returned an unknown value ($?)"
        ;;
    esac

    # Kill using PID
    kill ${PID_VALUE} || exitError "Stopping ${NAME} failed"
    rm -f ${ROUTER_PID}
    echo "${NAME} stopped"
}

restart() {
    echo "Restarting ${NAME}..."
    ${ROUTER_SCRIPT_DIR}/${ROUTER_SCRIPT_NAME} stop
    # Breathing space after stop - its too fast
    sleep 1
    ${ROUTER_SCRIPT_DIR}/${ROUTER_SCRIPT_NAME} start $*
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
bootstrapCustomCertsAndKeys

# run application in the foreground if nothing is passed - rpm and docker flow
if [[ $# == 0 ]]; then 
    run
else
    processOptions $*
fi

eval ${ACTION}
