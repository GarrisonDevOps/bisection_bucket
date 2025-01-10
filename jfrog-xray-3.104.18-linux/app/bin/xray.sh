#!/bin/bash
#
# Startup script for Xray micro services

SCRIPT_NAME=$(basename "$0")

ROUTER_NAME=router
OBSERVABILITY_NAME=observability
PRODUCT_BINARIES="server persist analysis indexer ${ROUTER_NAME} ${OBSERVABILITY_NAME}"
PRODUCT_LABEL="Xray"

errorExit() {
    echo
    echo -e "\033[31m** $1\033[0m"
    echo
    exit 1
}

checkHome() {
    if [ -z "$JF_PRODUCT_HOME" ] || [ ! -d "$JF_PRODUCT_HOME" ]; then
        errorExit "ERROR: JF_PRODUCT_HOME is not set, this is required to perform any action on ${PRODUCT_LABEL} microservices"
    fi
}

checkData() {
    local productData=$JF_PRODUCT_HOME/var
    if [ ! -d "$productData" ]; then
        mkdir -p $productData || errorExit "ERROR: Could not create or access JF_PRODUCT_HOME/var directory : $productData"
    fi
}

# Check if conditions to run local services are met
runService() {
    local script="$1"
    if [[ -f "${script}" ]]; then
        return 0
    else
        return 1
    fi
}

startService() {
    local script="$1"

    if [[ -z "${script}" ]]; then
        errorExit "Script location is not passed to start service"
    fi

    if runService "${script}"; then
        chmod +x "${script}"
        . "${script}" start
    fi
}

stopService() {
    local script="$1"
    if runService "${script}"; then
        chmod +x "${script}"
        "${script}" stop
    fi
}

statusService() {
    local script="$1"
    if runService "${script}"; then
        chmod +x "${script}"
        "${script}" status
    fi
}

stop () {
    removeLogRotation "$JF_PRODUCT_HOME" "$(id -un)" || true
    for service in ${PRODUCT_BINARIES} ; do
        stopService "${JF_PRODUCT_HOME}/app/${service}/bin/${service}.sh"
    done

    ${RABBITMQ_MANAGE_SCRIPT} stop
}

status() {
    ${RABBITMQ_MANAGE_SCRIPT} status
    for service in ${PRODUCT_BINARIES} ; do
        statusService "${JF_PRODUCT_HOME}/app/${service}/bin/${service}.sh"
    done
}

start() {
    # init

    ${RABBITMQ_MANAGE_SCRIPT} init
    ${RABBITMQ_MANAGE_SCRIPT} setup

    for service in ${PRODUCT_BINARIES} ; do
        startService "${JF_PRODUCT_HOME}/app/${service}/bin/${service}.sh"
    done
}

check() {
    status

    exit $?
}

usage() {
    cat << END_USAGE

${SCRIPT_NAME} - script for controlling ${PRODUCT_LABEL} services

Usage:   ./${SCRIPT_NAME} <action>

action:  help|start|stop|restart|status


END_USAGE

    exit 1
}

sourceScript(){
    local file=$1

    [ ! -z "${file}" ] || errorExit "target file is not passed to source a file"

    if [ ! -f "${file}" ]; then
        errorExit "${file} file is not found"
    else
        source "${file}" || errorExit "Unable to source ${file}, please check if the $USER user has permissions to perform this action"
    fi
}

initHelpers(){
    local systemYamlHelper="${PRODUCT_BIN_FOLDER}"/systemYamlHelper.sh
    local installerCommon="${PRODUCT_BIN_FOLDER}"/installerCommon.sh
    local xrayCommon="${PRODUCT_BIN_FOLDER}"/xrayCommon.sh

    export YQ_PATH="${PRODUCT_BIN_FOLDER}/../third-party/yq"
    sourceScript "${systemYamlHelper}"

    sourceScript "${installerCommon}"
    sourceScript "${xrayCommon}"

    # init at each service startup 
    export JF_SYSTEM_YAML="${JF_PRODUCT_HOME}/var/etc/system.yaml"
    setupScriptLogsRedirection || true
}

init() {
    initHelpers
    checkUser 2>/dev/null
    setupNodeDetails
    setRouterTopology
    displayEnv

    mkdir -p "${JF_PRODUCT_HOME}/var/etc/logrotate"
    touch "${JF_PRODUCT_HOME}/var/etc/logrotate/logrotate.conf"
    configureLogRotation "xray" "${JF_PRODUCT_HOME}" "$(id -un)" "$(id -gn)" || true
}

PRODUCT_BIN_FOLDER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

defaultFile="${PRODUCT_BIN_FOLDER}/xray.default"
export JF_PRODUCT_HOME="$(cd ${PRODUCT_BIN_FOLDER}/../.. && pwd)"

. ${defaultFile} || errorExit "ERROR: $defaultFile does not exist or not executable"

RABBITMQ_MANAGE_SCRIPT=${JF_PRODUCT_HOME}/app/bin/rabbitmq/manageRabbitmq.sh

# Extra termination steps needed
terminate () {
    echo "Caught termination signal"
    stop
}

# Catch Ctrl+C and other termination signals to try graceful shutdown
trap terminate SIGINT SIGTERM SIGHUP

checkHome
checkData
init

process() {
    case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    status|check)
        check
        ;;
    help)
        usage
        ;;
    *)
        usage
        ;;
    esac
}

process "$@"