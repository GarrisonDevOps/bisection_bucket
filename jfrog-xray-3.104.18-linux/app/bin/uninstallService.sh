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

PRODUCT_USER="xray"

linux_uninstallService_main $*
