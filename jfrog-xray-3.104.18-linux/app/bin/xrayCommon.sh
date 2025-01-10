#!/bin/bash
# Add methods which is common across microservices

syncEtc() {
    local srcEtc=${JF_PRODUCT_HOME}/app/misc/etc
    local targetEtc=${JF_PRODUCT_HOME}/var/etc
    local filebeatDir=${JF_PRODUCT_HOME}/var/data/filebeat

    # Use this if there are any configuration files need to be copied over to specific service directory
    local relativeFolders=""
    # Add space seperated file list to copy only if not available
    local relativeFilesNoOverwrite=""

    local basicTemplate="system.basic-template.yaml"
    # Add space seperated file list to overwrite on copy
    local relativeFilesReplace="${basicTemplate} system.full-template.yaml filebeat.yaml"

    createDir "${targetEtc}" "${JF_XRAY_USER}" "${JF_XRAY_GROUP}" 

    for folder in ${relativeFolders}
    do
        createDir "${targetEtc}/${folder}" "${JF_XRAY_USER}" "${JF_XRAY_GROUP}"
    done

    for file in ${relativeFilesNoOverwrite}
    do
        copyFile "${srcEtc}/${file}" "${targetEtc}/${file}" "no_overwrite"
    done

    for file in ${relativeFilesReplace}
    do
        copyFile "${srcEtc}/${file}" "${targetEtc}/${file}"
    done
    copyFile "${srcEtc}/${basicTemplate}" "${targetEtc}/system.yaml" "no_overwrite"

    [ -d "${filebeatDir}" ] || \
        createRecursiveDir "${JF_PRODUCT_HOME}/var" "data filebeat" "${JF_XRAY_USER}" "${JF_XRAY_GROUP}" >/dev/null 2>&1 || true
}

syncDirectories() {
    local syncfolders="data etc log"
    if [[ "${JF_PRODUCT_VAR}" != "${JF_PRODUCT_DATA_DEFAULT}" ]]; then
        for folder in ${syncfolders}
        do  
            if [[ ! -d "${JF_PRODUCT_VAR}/${folder}"  && -d "${JF_PRODUCT_DATA_DEFAULT}/${folder}" ]]; then
                mv "${JF_PRODUCT_DATA_DEFAULT}/${folder}" "${JF_PRODUCT_VAR}"/ || errorExit "Could not perform move operation ${JF_PRODUCT_DATA_DEFAULT}/${folder} to ${JF_PRODUCT_VAR}/"
            fi
        done
    fi
}

setRouterTopology(){
    export JF_ROUTER_TOPOLOGY_LOCAL_REQUIREDSERVICETYPES="jfxr,jfxidx,jfxana,jfxpst,jfob"
}

setUserGroup(){
    local defaultUser=${1:-xray}
    local defaultGroup=${2:-${defaultUser}}
    local user=
    local group=
    local userKey="shared.user"
    local groupKey="shared.group"

    getSystemValue "${userKey}" "NOT_SET"
    user=$YAML_VALUE

    getSystemValue "${groupKey}" "NOT_SET"
    group=$YAML_VALUE

    # Consider user as group if ony user is set
    if [[ "$group" == "NOT_SET" && "$user" != "NOT_SET" ]]; then
        group="$user"
    fi

    [ "$user"  = "NOT_SET" ] && user=""  || true
    [ "$group" = "NOT_SET" ] && group="" || true

    # Default it to xray
    JF_XRAY_USER=${user:-${defaultUser}}
    JF_XRAY_GROUP=${group:-${defaultGroup}}
}

# NOTE : Move this to installer common once other products are ready for the change
# Set target directory to be owned by service
# This will expect JF_PRODUCT_HOME/var to be a link
setVarLinkOwnership(){
    local user=${1}
    local group=${2}
    local varLink=${3:-${JF_PRODUCT_HOME}/var}
    local defaultTargetVar=${4}
    local curTargetVar=
    local newTargetVar=
    local targetVar=
    local isCustomDataSet="no"
    local nonRecursiveFlag="yes"

    if [ ! -z "${JF_PRODUCT_VAR}" ]; then
        newTargetVar=${JF_PRODUCT_VAR}
        isCustomDataSet="yes"
    else
        newTargetVar=${defaultTargetVar}
    fi

    if [[ -z "${user}"  || -z "${group}" || -z "${varLink}" || -z "${defaultTargetVar}" ]]; then
        errorExit "A user, group, varLink and defaultTargetVar is mandatory to set ownership on JF_PRODUCT_HOME/var"
    fi

    # Handle if a non link exists as $varLink
    if [[ ! -L "${varLink}" && ( -f "${varLink}" || -d "${varLink}" ) ]]; then
        local timestamp=$(echo "$(date '+%T')" | tr -d ":")
        local currentTime="$(date '+%Y%m%d').${timestamp}"
        local backup="${varLink}.backup.${currentTime}"
        logger "Found a file/directory named var under ${JF_PRODUCT_HOME}, this needs to be a link pointing to data directory (default : ${defaultTargetVar}). A backup of this will be created with name ${backup}"
        mv -f "${varLink}" "${backup}" || errorExit "Could not move ${varLink}, command : mv -f ${varLink} ${varLink}.backup.${currentTime}"
    fi

    # Readlink will give the same path as response if it does not exist
    curTargetVar=$(readlink -f ${varLink} 2>/dev/null)

    if [[ "${curTargetVar}" == *"${varLink}"* ]]; then
        logger "Creating a symlink from ${varLink} pointing to directory ${newTargetVar}"
        createDir "${newTargetVar}" "${user}" "${group}"
        ln -s "${newTargetVar}" "${varLink}"                         || errorExit "Failed to link data directory to JF_PRODUCT_HOME/var, command : ln -s \"${newTargetVar}\" \"${varLink}\""
        io_setOwnership "${varLink}" "${user}" "${group}"
    else
        # If custom data is not set, use link that is read to create and change permission of target directory
        [[ "${isCustomDataSet}" == "no" ]] && targetVar="${curTargetVar}" || targetVar="${newTargetVar}"

        
        createDir "${targetVar}" "${user}" "${group}"

        if [[ "${isCustomDataSet}" == "yes" && "${curTargetVar}" != "${newTargetVar}" ]]; then
            bannerImportant "${varLink} is linked to ${curTargetVar}, this will be changed to point to new location ${newTargetVar}
Please move all files and folders from ${curTargetVar} to ${newTargetVar}
Data directory can be controlled using environment variable JF_PRODUCT_VAR"

            [ -L "${varLink}" ] && rm -f "${varLink}" || true
            ln -s "${newTargetVar}" "${varLink}"      || errorExit "Failed to link data directory to JF_PRODUCT_HOME/var, command : ln -s \"${newTargetVar}\" \"${varLink}\" "
            io_setOwnership "${varLink}" "${user}" "${group}"
        fi
    fi
}
