#!/bin/bash

# exit when any command fails
set -e

JF_PRODUCT_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
SCRIPT_HOME="$(cd ${JF_PRODUCT_HOME}/app/bin && pwd)"
ANSIBLE_SCRIPT_HOME="$(cd ${JF_PRODUCT_HOME}/app/bin/k3s-ansible && pwd)"
RPM_DEB_PRODUCT_PACK_NAME="xray"
DEFAULT_KUBE_CONFIG_LOCATION=${JF_PRODUCT_HOME}/var/etc/kube_config.yaml
kube_config_path=${kube_config_path:-${DEFAULT_KUBE_CONFIG_LOCATION}};

. ${SCRIPT_HOME}/systemYamlHelper.sh
. ${SCRIPT_HOME}/linuxHelper.sh

rpmDeb_setYQPath
rpmDeb_init

rpmDeb_setSystemValueOverride(){
    local key=$1
    local value=$2
    local yamlFile=$3
    local logMsg=${4:-false}

    # Return if any of the inputs are empty
    [[ -z "$key"      || "$key"      == "" ]] && return
    [[ -z "$value"    || "$value"    == "" ]] && return
    [[ -z "$yamlFile" || "$yamlFile" == "" ]] && return
    setSystemValue "${key}" "${value}" "${yamlFile}"
}

function get_confirmation {
  while true; do
    read -p "$1 [y/n]: " answer
    case $answer in
      [Yy]* ) return 0;;
      [Nn]* ) return 1;;
      * ) echo "Please answer y or n.";;
    esac
  done
}

function configure_localk3s_config_to_host_ini {
    masterips="127.0.0.1 ansible_connection=local";
    echo "[master]" > ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini;
    echo $masterips >> ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini;
    echo "[node]" >> ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini;
cat >> ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini <<EOF
[k3s_cluster:children]
master
node
EOF
}

function trim {
  echo "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

function configure_remotek3s_config_to_host_ini {
    echo "Enter ip address for the master vms (seperated by spaces)"
    read -p "Provide k3s master Ips: " master_ips
    echo "[master]" > ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini;
    for ip in $master_ips
    do
        echo "$ip" >> ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini;
    done

    echo "Enter ip address for the node vms (seperated by spaces)"
    read -p "Provide k3s node Ips: " node_ips
    echo "[node]" >> ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini;
    for ip in $node_ips
    do
        echo "$ip" >> ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini;
    done

    echo "Enter username for the vms, should have passwordless ssh access using ssh user@ip"
    read username_ssh
    sed -i'' -e "/^ansible_user:/ s/\(ansible_user:\).*/\1 ${username_ssh}/" ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/group_vars/all.yml


cat >> ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini <<EOF
[k3s_cluster:children]
master
node
[all:vars]
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF
}

validateSudoForXrayUser () {
    local OS_TYPE=$(uname)
    if [ "$OS_TYPE" == "Linux" ] && [ $EUID -ne 0 ]; then
        errorExit "In order to install Ansible, either the xray user needs to have sudo privileges or Ansible must be manually installed prior to running this script."
    fi
}

install_ansible() {
  if ! which ansible > /dev/null; then
    validateSudoForXrayUser
    logger "Installing ansible from official package manager"
    io_getLinuxDistribution
    case ${LINUX_DISTRIBUTION} in
        CentOS|RedHat|SLES)
            yum install -y ansible
        ;;
        Debian|Ubuntu)
            apt-get install -y ansible
        ;;
    esac
  else
    logger "Found ansible, proceeding"
  fi
}

install_playbook_with_ansible() {
      logger "It is recomended to have atleast 1 master and 2 worker nodes. These vms should have passwordless access using username from this machine." "NOTE"
      if get_confirmation "To proceed type y and provide the vms ips or type n to install k3s locally in the same machine"; then
          configure_remotek3s_config_to_host_ini
      else
          configure_localk3s_config_to_host_ini
      fi
      install_ansible
      ansible-playbook -v ${ANSIBLE_SCRIPT_HOME}/site.yml -i ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini -e "project_dir=${ANSIBLE_SCRIPT_HOME}"
      echo "Copying k3s config to $DEFAULT_KUBE_CONFIG_LOCATION"
      cp -r ${ANSIBLE_SCRIPT_HOME}/k3s_config.yaml $DEFAULT_KUBE_CONFIG_LOCATION
}
install_playbook_with_docker() {
      if [ "$airgap" == "true" ]; then
        logger "Prerequisite :  Load the image releases-docker.jfrog.io/ansible/ansible:2.15.0 manually and place the private key to access k3s nodes under k3s-ansible/keys/k3s_vms_private_key"
      else
        logger "Prerequisite :  Place the private key to access k3s nodes under k3s-ansible/keys/k3s_vms_private_key"
      fi
      logger "It is recomended to have atleast 1 master and 2 worker nodes." "NOTE"
      if get_confirmation "Please check the prerequisites above and to proceed with the vm ips, type y "; then
          configure_remotek3s_config_to_host_ini
      else
          exit 1
      fi
      docker run --rm --net host -v "$PWD":"$PWD" releases-docker.jfrog.io/ansible/ansible:2.15.0 /bin/sh -c "cd $PWD && ./k3s-ansible/keys/setupPrivateKeys.sh && ansible-playbook -v ${ANSIBLE_SCRIPT_HOME}/site.yml -i ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/hosts.ini -e project_dir=${ANSIBLE_SCRIPT_HOME}"
      echo "Copying k3s config to $DEFAULT_KUBE_CONFIG_LOCATION"
      cp -r ${ANSIBLE_SCRIPT_HOME}/k3s_config.yaml $DEFAULT_KUBE_CONFIG_LOCATION
}

bannerStart "Beginning JFrog JAS setup"

logger "Jas requires a kubernetes cluster to run its workloads" "NOTE"
logger "If you already have a kubernetes cluster you can provide your existing kube config file under location ${DEFAULT_KUBE_CONFIG_LOCATION}" "NOTE"


if get_confirmation "Do you want to create a k3s cluster now. Type y to create now or n to proceed with existing kube config"; then
  createK3sCluster="true"
  if get_confirmation "Is your system airgapped: type y/n"; then
    airgap="true"
    logger "The script requires either docker or ansible to be installed";
  else
    airgap="false"
  fi
else
  createK3sCluster="false"
  logger "Please provide your kube config location ${DEFAULT_KUBE_CONFIG_LOCATION} and proceed with the installation";
fi


if [ $createK3sCluster == "true" ]; then
    sed -i'' -e "/^ansible_airgap:/ s/\(ansible_airgap:\).*/\1 ${airgap}/" ${ANSIBLE_SCRIPT_HOME}/inventory/k3scluster/group_vars/all.yml
    if command -v ansible &> /dev/null; then
      logger "Installing playbook using ansible binary"
      install_playbook_with_ansible
    elif command -v docker &> /dev/null; then
      logger "Installing playbook using ansible docker image"
      install_playbook_with_docker
    else
      logger "Cannot find docker or ansible, exiting"
      exit 1
    fi
fi

getSystemValue "executionService.jobAesKey" "NOT_SET" "false" "$JF_SYSTEM_YAML"
if [[ "${YAML_VALUE}" == "NOT_SET" ]];then
  randExecKey=$(openssl rand -hex 16)
  read -p "Enter execution job aes key (default: ${randExecKey}): " job_aes_key
  job_aes_key=${job_aes_key:-${randExecKey}}
else
  logger "executionService.jobAesKey is already set in system yaml"
fi
rpmDeb_setSystemValueNoOverride "executionService.jobAesKey" "${job_aes_key}" "${JF_SYSTEM_YAML}"

rpmDeb_setSystemValueOverride "executionService.kubeconfig.path" "${kube_config_path}" "${JF_SYSTEM_YAML}"
rpmDeb_setSystemValueOverride "executionService.kubeconfig.namespace" "default" "${JF_SYSTEM_YAML}"
rpmDeb_setSystemValueOverride "executionService.kubeconfig.context" "default" "${JF_SYSTEM_YAML}"
rpmDeb_setSystemValueOverride "executionService.kubeconfig.enabled" "true" "${JF_SYSTEM_YAML}"

logger "The configuration for JAS has been applied. Please restart xray";
