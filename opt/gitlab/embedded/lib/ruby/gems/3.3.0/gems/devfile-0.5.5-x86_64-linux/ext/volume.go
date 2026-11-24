package main

import (
	devfileApiV1Alpha2 "github.com/devfile/api/v2/pkg/apis/workspaces/v1alpha2"
	"github.com/devfile/library/v2/pkg/devfile/generator"
	"github.com/devfile/library/v2/pkg/devfile/parser"
	"github.com/devfile/library/v2/pkg/devfile/parser/data/v2/common"
	corev1 "k8s.io/api/core/v1"
	"strings"
)

// There's a bug in the devfile library
// When a container component which has events and commands attached to it, becomes a init container, the name is
// init container is a concatenation of component name, event/command.
// However, when generating containerNameToMountPaths, we are using the component name
// And in addVolumeMountToContainers, we are comparing the container name with a component name
// For init containers this will not match
// Temporary fix is to use a string prefix check in addVolumeMountToContainers and return the updatedAllContainers from
// getVolumesAndVolumeMounts
// TODO: This might not be a perfect fix because maybe a string prefix match can have undesirable effects.
// issue: https://gitlab.com/gitlab-org/gitlab/-/issues/408950

// getVolumesAndVolumeMounts gets the PVC volumes and updates the containers with the volume mounts.
func getVolumesAndVolumeMounts(devfileObj parser.DevfileObj, volumeParams generator.VolumeParams, options common.DevfileOptions) ([]corev1.Container, []corev1.Volume, error) {
	options.ComponentOptions = common.ComponentOptions{
		ComponentType: devfileApiV1Alpha2.ContainerComponentType,
	}
	containerComponents, err := devfileObj.Data.GetComponents(options)
	if err != nil {
		return nil, nil, err
	}

	options.ComponentOptions = common.ComponentOptions{
		ComponentType: devfileApiV1Alpha2.VolumeComponentType,
	}
	volumeComponent, err := devfileObj.Data.GetComponents(options)
	if err != nil {
		return nil, nil, err
	}

	var pvcVols []corev1.Volume
	for volName, volInfo := range volumeParams.VolumeNameToVolumeInfo {
		emptyDirVolume := false
		for _, volumeComp := range volumeComponent {
			if volumeComp.Name == volName && *volumeComp.Volume.Ephemeral {
				emptyDirVolume = true
				break
			}
		}

		// if `ephemeral=true`, a volume with emptyDir should be created
		if emptyDirVolume {
			pvcVols = append(pvcVols, getEmptyDirSource(volInfo.VolumeName))
		} else {
			pvcVols = append(pvcVols, getPVCSource(volInfo.VolumeName, volInfo.PVCName))
		}

		// containerNameToMountPaths is a map of the Devfile container name to their Devfile Volume Mount Paths for a given Volume Name
		containerNameToMountPaths := make(map[string][]string)
		for _, containerComp := range containerComponents {
			for _, volumeMount := range containerComp.Container.VolumeMounts {
				if volName == volumeMount.Name {
					containerNameToMountPaths[containerComp.Name] = append(containerNameToMountPaths[containerComp.Name], getVolumeMountPath(volumeMount))
				}
			}
		}

		addVolumeMountToContainers(volumeParams.Containers, volInfo.VolumeName, containerNameToMountPaths)
	}
	return volumeParams.Containers, pvcVols, nil
}

// getPVCSource gets a pvc type volume with the given volume name and pvc name.
func getPVCSource(volumeName, pvcName string) corev1.Volume {

	return corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: pvcName,
			},
		},
	}
}

// getEmptyDirSource gets a volume with emptyDir
func getEmptyDirSource(volumeName string) corev1.Volume {
	return corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
}

// addVolumeMountToContainers adds the Volume Mounts in containerNameToMountPaths to the containers for a given volumeName.
// containerNameToMountPaths is a map of a container name to an array of its Mount Paths.
func addVolumeMountToContainers(containers []corev1.Container, volumeName string, containerNameToMountPaths map[string][]string) {
	for containerName, mountPaths := range containerNameToMountPaths {
		for i := range containers {
			if strings.HasPrefix(containers[i].Name, containerName) {
				for _, mountPath := range mountPaths {
					containers[i].VolumeMounts = append(containers[i].VolumeMounts, corev1.VolumeMount{
						Name:      volumeName,
						MountPath: mountPath,
					},
					)
				}
			}
		}
	}
}

// getVolumeMountPath gets the volume mount's path.
func getVolumeMountPath(volumeMount devfileApiV1Alpha2.VolumeMount) string {
	// if there is no volume mount path, default to volume mount name as per devfile schema
	if volumeMount.Path == "" {
		volumeMount.Path = "/" + volumeMount.Name
	}

	return volumeMount.Path
}
