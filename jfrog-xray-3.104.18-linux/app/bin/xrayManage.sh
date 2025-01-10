#!/bin/bash

export PATH="${PATH}:/sbin:/usr/sbin:/bin:/usr/bin"

JF_PRODUCT_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
PRODUCT_NAME=xray
PRODUCT_PID="/var/run/${PRODUCT_NAME}.pid"
SOURCE=${JF_PRODUCT_HOME}/app/bin/${PRODUCT_NAME}.default
MANAGE_SCRIPT=${JF_PRODUCT_HOME}/app/bin/${PRODUCT_NAME}.sh
XRAY_MAIN_PID=${JF_PRODUCT_HOME}/app/run/server.pid

# Exit code constants
EXIT_CODE_SUCCESS=0
EXIT_CODE_FAILURE=1

errorExit() {
    echo; echo -e "\033[31mERROR:\033[0m $1"; echo
    exit ${EXIT_CODE_FAILURE}
}

. ${JF_PRODUCT_HOME}/app/bin/${PRODUCT_NAME}.default || { EXIT_CODE_FAILURE=1; errorExit "Could not load ${JF_PRODUCT_HOME}/app/bin/${PRODUCT_NAME}.default"; }
. ${JF_PRODUCT_HOME}/app/bin/installerCommon.sh      || { EXIT_CODE_FAILURE=1; errorExit "Could not load ${JF_PRODUCT_HOME}/app/bin/installerCommon.sh"; }
. ${JF_PRODUCT_HOME}/app/bin/systemYamlHelper.sh     || { EXIT_CODE_FAILURE=1; errorExit "Could not load ${JF_PRODUCT_HOME}/app/bin/systemYamlHelper.sh"; }
. ${JF_PRODUCT_HOME}/app/bin/xrayCommon.sh           || { EXIT_CODE_FAILURE=1; errorExit "Could not load ${JF_PRODUCT_HOME}/app/bin/xrayCommon.sh"; }


checkFileExist () {
    if [[ -f "${MANAGE_SCRIPT}" ]]; then
        RETVAL=${EXIT_CODE_SUCCESS}
    else
        RETVAL=${EXIT_CODE_FAILURE}
        errorExit "File [${MANAGE_SCRIPT}] not found to manage services"
    fi
}

start () {
    changeRpmDebOwnership "${JF_PRODUCT_HOME}" "${JF_XRAY_USER}" "${JF_XRAY_GROUP}"

    su -c "${MANAGE_SCRIPT} start" "${JF_XRAY_USER}" \
        || RETVAL=${EXIT_CODE_FAILURE}

    [ -f "${XRAY_MAIN_PID}" ] || \
        {   \
            RETVAL=${EXIT_CODE_FAILURE}; \
            errorExit """Process id file ${XRAY_MAIN_PID} for xray server not found,
                services were not started properly. Check \"systemctl status ${PRODUCT_NAME}\", \"journalctl -xe\" and ${JF_PRODUCT_HOME}/var/log for details"""; \
        }

    cp -f ${XRAY_MAIN_PID} ${PRODUCT_PID} || \
        {   \
            RETVAL=${EXIT_CODE_FAILURE}; \
            errorExit """Failed to copy ${PRODUCT_NAME} process id,
                command [ cp -f ${XRAY_MAIN_PID} ${PRODUCT_PID} ]"""; \
        }
}

restart () {
    su -c "${MANAGE_SCRIPT} restart" "${JF_XRAY_USER}" \
        || RETVAL=${EXIT_CODE_FAILURE}
} 

stop () {
    su -c "${MANAGE_SCRIPT} stop" "${JF_XRAY_USER}" \
        || RETVAL=${EXIT_CODE_FAILURE}

    [ -f "${PRODUCT_PID}" ] && rm -f "${PRODUCT_PID}" || true  
}

status () {
    su -c "${MANAGE_SCRIPT} status" "${JF_XRAY_USER}" \
        || RETVAL=${EXIT_CODE_FAILURE}
}

main () {
case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  status)
    status
    ;;
  restart)
    restart
    ;;
  *)
    errorExit "Usage: service ${PRODUCT_NAME} {start|stop|status|restart}"
    RETVAL=${EXIT_CODE_FAILURE}
esac
}

###### MAIN #######
checkFileExist
setUserGroup
main $1

exit ${RETVAL:-$EXIT_CODE_SUCCESS}
