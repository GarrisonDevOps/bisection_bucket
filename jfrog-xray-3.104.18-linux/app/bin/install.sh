#!/bin/bash

JF_PRODUCT_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
RPM_DEB_INSTALLER_HOME="${JF_PRODUCT_HOME}"
SCRIPT_HOME="$(cd ${JF_PRODUCT_HOME}/app/bin && pwd)"
RPM_DEB_PRODUCT_PACK_NAME="xray"
RPM_DEB_PRODUCT_SERVICE_NAME="${RPM_DEB_PRODUCT_PACK_NAME}"
LINUX_PRODUCT_SERVICE_NAME="${RPM_DEB_PRODUCT_PACK_NAME}"
PRODUCT_NAME="Xray"

LINUX_USER_END_INSTALL_DOC="https://service.jfrog.org/installer/Installing+Xray#InstallingXray-LinuxArchiveInstallation"
LINUX_USER_END_INSTALL_LIST="erl=Erlang-25.0.3-1 db_dump=Db-Utils-5.3"

RPM_DEB_RECOMMENDED_MIN_RAM=4718592           # 4.5G Total RAM => 4.5*1024*1024k=4718592
RPM_DEB_RECOMMENDED_MAX_USED_STORAGE=90       # needs more than 10% available storage
RPM_DEB_RECOMMENDED_MIN_CPU=3                 # needs more than 3 CPU Cores

RPM_DEB_DEFAULT_ENV="${JF_PRODUCT_HOME}/app/bin/${RPM_DEB_PRODUCT_PACK_NAME}.default"

. ${SCRIPT_HOME}/systemYamlHelper.sh
. ${SCRIPT_HOME}/linuxHelper.sh

MANDATORY_FIELDS="JF_SHARED_JFROGURL JF_SHARED_SECURITY_JOINKEY"
CLUSTER_DATABASES="$DATABASE_RABBITMQ"

DEFAULT_PRODUCT_USER="xray"

LINUX_USER_KEY="shared.user"
LINUX_GROUP_KEY="shared.group"

rpmDeb_hook_writeInfoToYaml(){
    local type="${RPM_DEB_KEY_INSTALLER_TO_SYSTEM}"

    rpmDeb_syncYaml "${SYS_KEY_RABBITMQ_ACTIVE_NODE_NAME}" "${SYS_KEY_RABBITMQ_ACTIVE_NODE_NAME}" "${type}" || warn "Could not set ${SYS_KEY_RABBITMQ_ACTIVE_NODE_NAME}"    
}

rpmDeb_hook_postInstall() {
    _transformRabbitMqPasswordToConfFile
}

#This is the main method from commons responsible for the installation
rpmDeb_main $*

exit $?