#!/bin/bash

SCRIPT_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export JF_PRODUCT_HOME="$(cd "$(dirname "$SCRIPT_HOME")"/.. && pwd)"

source "${SCRIPT_HOME}"/systemYamlHelper.sh
source "${SCRIPT_HOME}"/linuxHelper.sh

PRODUCT_NAME="Xray"
LINUX_SERVICE_NAME="xray"
LINUX_INIT_SERVICE_FILE="/etc/init.d/${LINUX_SERVICE_NAME}"
LINUX_INIT_SERVICE_TEMPLATE=${JF_PRODUCT_HOME}/app/misc/service/${LINUX_SERVICE_NAME}-service.template
LINUX_SERVICE_DEFAULT_ENV=${JF_PRODUCT_HOME}/app/bin/${LINUX_SERVICE_NAME}.default

JF_SYSTEM_YAML=${JF_PRODUCT_HOME}/var/etc/system.yaml

LINUX_USER_KEY="shared.user"
LINUX_GROUP_KEY="shared.group"

RPM_DEB_RECOMMENDED_MIN_RAM=4718592           # 4.5G Total RAM => 4.5*1024*1024k=4718592
RPM_DEB_RECOMMENDED_MAX_USED_STORAGE=90       # needs more than 10% available storage
RPM_DEB_RECOMMENDED_MIN_CPU=3                 # needs more than 3 CPU Cores

PRODUCT_USER="xray"
IS_SYSTEMD_ENABLED="${FLAG_Y}"

linux_installService_main $*
