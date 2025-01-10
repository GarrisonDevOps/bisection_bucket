#!/bin/bash

config_file=~/.ssh/config
identity_line="IdentityFile $PWD/k3s-ansible/keys/k3s_vms_private_key"
chmod 600 "$PWD/k3s-ansible/keys/k3s_vms_private_key"

# Check if the config file exists
if [ ! -f "$config_file" ]; then
    mkdir -p ~/.ssh/
    touch "$config_file"
fi

# Look for the line starting with "IdentityFile"
if grep -q "^IdentityFile" "$config_file"; then
    sed -i "/^IdentityFile/c\\$identity_line" "$config_file"
else
    echo "$identity_line" >> "$config_file"
fi