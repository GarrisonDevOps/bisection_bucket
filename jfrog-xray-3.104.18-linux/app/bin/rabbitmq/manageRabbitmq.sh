#!/bin/bash

SCRIPT_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export LC_ALL=C

: ${JF_PRODUCT_HOME:?"JF_PRODUCT_HOME environment variable is not set"}

PRODUCT_BIN_FOLDER=${JF_PRODUCT_HOME}/app/bin

# Use packaged rabbitmq if available - to handle rpm/deb installation
# #########
# ######### NOTE : All the rabbitmq executables used in this file has to be prepended with ${rabbitmqBin}
# ######### Example : ${rabbitmqBin}rabbitmqctl
# #########
rabbitmqBin=${JF_PRODUCT_HOME}/app/third-party/rabbitmq/sbin/

sourceScript(){
    local file=$1

    [ ! -z "${file}" ] || errorExit "target file is not passed to source a file"
    [   -f "${file}" ] || errorExit "${file} file is not found"
    source "${file}"   || errorExit "Unable to source ${file}, please check if the $USER user has permissions to perform this action"    
}

initHelpers(){
    local systemYamlHelper="${PRODUCT_BIN_FOLDER}"/systemYamlHelper.sh
    local installerCommon="${PRODUCT_BIN_FOLDER}"/installerCommon.sh
    local xrayCommon="${PRODUCT_BIN_FOLDER}"/xrayCommon.sh
    export YQ_PATH="${PRODUCT_BIN_FOLDER}/../third-party/yq"

    sourceScript "${installerCommon}"
    sourceScript "${systemYamlHelper}"
    sourceScript "${xrayCommon}"

    export JF_SYSTEM_YAML="${JF_PRODUCT_HOME}/var/etc/system.yaml"
    setupScriptLogsRedirection || true
}

rabbitMqInitEnv(){
    local nodeNameKey=shared.node.name
    local nodeName=

    getSystemValue "${nodeNameKey}" "NOT_SET"
    nodeName="${YAML_VALUE}"

    if [ "${nodeName}" == "NOT_SET" ]; then
        errorExit "Unable to get node name of the system, please set ${nodeNameKey} in system.yaml to proceed with rabbitmq initialisation"
    fi

    # Long name for installer is not supported by default
    # Use only short name as for hostname $(hostname -s)
    # Document active node name, needs to be shortname of hostname 
    # export RABBITMQ_USE_LONGNAME=true

    export RABBITMQ_NODENAME=rabbit@${nodeName}

    # Generic Unix: $RABBITMQ_HOME/var/lib/rabbitmq/mnesia
    # Ubuntu and Debian packages: /var/lib/rabbitmq/mnesia/
    # RPM: /var/lib/rabbitmq/plugins
    export RABBITMQ_MNESIA_BASE=${JF_PRODUCT_HOME}/var/data/rabbitmq/mnesia

    local logDir=${JF_PRODUCT_HOME}/var/log/rabbitmq
    export RABBITMQ_LOG_BASE=${logDir}
    mkdir -p ${logDir} || errorExit "Unable to create log directory (${logDir}) for rabbitmq"

    [ -d "${RABBITMQ_MNESIA_BASE}" ] || mkdir -p ${RABBITMQ_MNESIA_BASE}

    rabbitMqCheckAndCreateCookie

    export RABBITMQ_CONFIG_FILE="${JF_PRODUCT_HOME}/app/bin/rabbitmq/rabbitmq.conf"
    transformPropertiesToFile "${RABBITMQ_CONFIG_FILE}" "${SYS_KEY_RABBITMQ_NODE_RABBITMQCONF}" "${JF_SYSTEM_YAML}" "${IGNORE_RABBITMQ_CONFIGS}"
}

rabbitMqCreateCookie(){
    local rabbitmqCookieFile=$1
    local defaultCookieValue=JFXR_RABBITMQ_COOKIE
    local cookieValue=

    if [ ! -d $(dirname "$rabbitmqCookieFile") ]; then
        mkdir -p $(dirname "$rabbitmqCookieFile") || \
        warn "Could not create parent directory for rabbitmq cookie file : ${rabbitmqCookieFile}"
    fi

    # To support upgrade scenarios
    getSystemValue "shared.rabbitMq.erlangCookie.value" "${defaultCookieValue}"
    cookieValue="${YAML_VALUE}"
    
    logger "Creating ${rabbitmqCookieFile} with cookie content"
    [ -f "${rabbitmqCookieFile}" ] || touch "${rabbitmqCookieFile}"
    chmod 600 "${rabbitmqCookieFile}"
    echo -n "${cookieValue}" > "${rabbitmqCookieFile}"
    chmod 400 "${rabbitmqCookieFile}"
}

rabbitMqEnablePlugins(){
    local plugin="rabbitmq_management"

    # Check if plugins are already enabled
    # If its enabled, the plugin list will have "E" in square brackets next to it
    # [E ] rabbitmq_management
    # or
    # [e ] rabbitmq_management
    ${rabbitmqBin}rabbitmq-plugins list 2>/dev/null | grep -e "\[[Ee].*\] ${plugin} " >/dev/null 2>&1
    if [ $? == 0 ]; then
        return
    fi

    ${rabbitmqBin}rabbitmq-plugins enable ${plugin} >/dev/null \
            || warn "Enabling plugins failed on RabbitMQ, command : ${rabbitmqBin}rabbitmq-plugins enable ${plugin}"

    rabbitMqReStart
}

rabbitMqStart(){
    ${rabbitmqBin}rabbitmqctl status >/dev/null 2>&1 || \
            ${rabbitmqBin}rabbitmq-server -detached 1>/dev/null 2>&1
}

rabbitMqStatus(){
    if ${rabbitmqBin}rabbitmqctl status >/dev/null 2>&1; then 
        logger "Rabbitmq is running"
    else
        logger "Rabbitmq is not running or is in error state"
    fi
}

rabbitMqStop(){
    local exitStatus=
    ${rabbitmqBin}rabbitmqctl -q -s shutdown >/dev/null 2>&1 ; exitStatus=$?

    if [[ "$exitStatus" == "69" ]]; then
        # If you run a shutdown on a non running rabbitmq, a non zero (69) is returned
        logger "RabbitMQ is not running"
    elif [[ "$exitStatus" == "0" ]]; then
        logger "RabbitMQ stopped successfully"
    else
        warn "RabbitMQ stop is having issues, command : ${rabbitmqBin}/rabbitmqctl shutdown"
    fi
}

rabbitMqReStart(){
    rabbitMqStop
    rabbitMqStart
}

rabbitMqSetupCluster(){
    local activeNodeName=
    local activeNodeNameKey=shared.rabbitMq.active.node.name
    local cleanNodesKey=shared.rabbitMq.clean
    local cleanNode=

    getSystemValue "${activeNodeNameKey}" "NOT_SET"
    activeNodeName="${YAML_VALUE}"

    if [ "${activeNodeName}" == "NOT_SET" ]; then
        unset JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME
    else
        export JF_SHARED_RABBITMQ_ACTIVE_NODE_NAME="${activeNodeName}"
    fi

    getSystemValue "${cleanNodesKey}" "NOT_SET"
    cleanNode="${YAML_VALUE}"

    if [ "${cleanNode}" == "NOT_SET" ]; then
        unset JF_SHARED_RABBITMQ_CLEAN
    else
        export JF_SHARED_RABBITMQ_CLEAN="${cleanNode}"
    fi

    . ${JF_PRODUCT_HOME}/app/bin/rabbitmq/setRabbitCluster.sh || warn "RabbitMQ cluster setup did not end with success status"
}

rabbitMqCheckAndCreateCookie(){
    local cookieFile=

    if [ ! -f ${HOME}/.erlang.cookie ]; then
        # cookie used by cli for authentication
        cookieFile="${HOME}/.erlang.cookie"
        rabbitMqCreateCookie "${cookieFile}"

        # cookie used by server for authentication
        cookieFile="${JF_PRODUCT_HOME}/app/third-party/rabbitmq/.erlang.cookie"
        rabbitMqCreateCookie "${cookieFile}"
    else
        # Display this message only on start
        if [[ "${RABBITMQ_ACTION}" == "setup" ]]; then
            logger "Erlang cookie (${HOME}/.erlang.cookie and ${JF_PRODUCT_HOME}/app/third-party/rabbitmq/.erlang.cookie) already exists, skipping its creation"
        fi
    fi
}

rabbitMqInitialize(){
    logger "Enabling Rabbitmq plugins..."
    rabbitMqEnablePlugins
}

rabbitmqSetup(){
    logger "Setting up Rabbitmq ..."

    rabbitMqStart
    rabbitMqSetupCluster
}

###### MAIN #######

RABBITMQ_ACTION=$1

# Exit the script if only Xray needs to be started.
if [[ "${INSTALLATION_METHOD}" == "xray" ]]; then
    logger "Exiting RabbitMQ startup because the Xray only parameter is passed." 2>&1
    exit 0
fi

initHelpers
rabbitMqInitEnv
rabbitMqManageKey="shared.rabbitMq.autoStop"

if [[ "${RABBITMQ_ACTION}" =~ ^(stop|restart)$ ]]; then
    getSystemValue "${rabbitMqManageKey}" "NOT_SET"
    if [[ "${YAML_VALUE}" != "true" ]]; then
        exit 0
    fi
fi

case "${RABBITMQ_ACTION}" in
  start)
    rabbitMqStart
    ;;
  stop)
    rabbitMqStop
    ;;
  status)
    rabbitMqStatus
    ;;
  setup)
    rabbitmqSetup
    ;;  
  restart)
    rabbitMqStop
    rabbitMqStart
    ;;
  init)
    rabbitMqInitialize
    ;;
  *)
    logger "Usage: $0 {start|stop|setup|restart}"
esac
