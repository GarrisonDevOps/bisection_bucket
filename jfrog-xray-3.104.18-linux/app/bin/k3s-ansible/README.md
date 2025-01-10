# Automated build of HA k3s Cluster


This playbook will build an HA Kubernetes cluster with `k3s`

This is based on the work from [this fork](https://github.com/techno-tim/k3s-ansible) which is based on the work from [k3s-io/k3s-ansible](https://github.com/k3s-io/k3s-ansible).

## 📖 k3s Ansible Playbook

Build a Kubernetes cluster using Ansible with k3s. This is tested on the following machines:

- [x] Ubuntu (tested on version 22.04)
- [x] Ubuntu (tested on version 20)
- [x] Redhat (tested on version 8)

on processor architecture:

- [X] x64

## ✅ System requirements

- Deployment environment must have Ansible 2.9.0+.


- [`netaddr` package](https://pypi.org/project/netaddr/) must be available to Ansible. If you have installed Ansible via apt, this is already taken care of. If you have installed Ansible via `pip`, make sure to install `netaddr` into the respective virtual environment.

- `server` and `agent` nodes should have passwordless SSH access.

## 🚀 Getting Started

### 🍴 Preparation

Edit `inventory/k3scluster/hosts.ini` to match the system information gathered above

For example:

```ini
[master]
192.168.30.38

[node]
192.168.30.41
192.168.30.42

[k3s_cluster:children]
master
node
[all:vars]
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
```

Edit `inventory/k3scluster/group_vars/all.yml` to provide the Vm username under ansible_user
Note: the vms should be accessable by username@ip. For that you will need to configure your ssh.

To provide passwordless ssh acces follow the steps below

Edit the file vi /user/.ssh/config
```
IdentityFile /user/.ssh/yourPrivateKey
```
Add you private key under /user/.ssh/yourPrivateKey
chmod 600 /user/.ssh/yourPrivateKey


If multiple hosts are in the master group, the playbook will automatically set up k3s in [HA mode with etcd](https://rancher.com/docs/k3s/latest/en/installation/ha-embedded/). 

The loadbalancing part to the master nodes ips should be done manually.

This requires at least k3s version `1.19.1` however the version is configurable by using the `k3s_version` variable.

If needed, you can also edit `inventory/k3scluster/group_vars/all.yml` to match your environment.

### ☸️ Create Cluster

Start provisioning of the cluster using the following command:

```bash
ansible-playbook site.yml -i inventory/k3scluster/hosts.ini
```

### 🔥 Remove k3s cluster

```bash
ansible-playbook reset.yml -i inventory/my-cluster/hosts.ini
```

>You should also reboot these nodes due to the VIP not being destroyed

## ⚙️ Kube Config

After deployment the kube config file for the created cluster will be available in the Ansible control machine directory.

