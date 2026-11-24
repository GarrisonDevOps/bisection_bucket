package main

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"text/template"

	"github.com/devfile/library/v2/pkg/devfile"
	"github.com/devfile/library/v2/pkg/devfile/generator"
	"github.com/devfile/library/v2/pkg/devfile/parser"
	"github.com/devfile/library/v2/pkg/devfile/parser/data/v2/common"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/printers"
	"sigs.k8s.io/yaml"
)

type Devfile struct {
	devfileObj parser.DevfileObj
}

type volumeOptions struct {
	Info        generator.VolumeInfo
	Size        string
	IsEphemeral bool
}

func (d Devfile) getDeployment(name, namespace string, labels, annotations map[string]string, replicas int) (*appsv1.Deployment, error) {
	containers, initContainers, volumes, _, err := d.getContainersAndVolumes(name)
	if err != nil {
		return nil, err
	}

	deployParams := generator.DeploymentParams{
		TypeMeta:          generator.GetTypeMeta("Deployment", "apps/v1"),
		ObjectMeta:        generator.GetObjectMeta(name, namespace, labels, annotations),
		InitContainers:    initContainers,
		Containers:        containers,
		Volumes:           volumes,
		PodSelectorLabels: labels,
		Replicas:          pointerTo(int32(replicas)),
	}

	deployment, err := generator.GetDeployment(d.devfileObj, deployParams)
	if err != nil {
		return nil, err
	}

	return deployment, err
}

func (d Devfile) getService(name, namespace string, labels, annotations map[string]string) (*corev1.Service, error) {
	service, err := generator.GetService(d.devfileObj, generator.ServiceParams{
		TypeMeta:       generator.GetTypeMeta("Service", "v1"),
		ObjectMeta:     generator.GetObjectMeta(name, namespace, labels, annotations),
		SelectorLabels: labels,
	}, common.DevfileOptions{})
	if err != nil {
		return nil, err
	}

	return service, err
}

func (d Devfile) getIngress(name, namespace string, labels, annotations map[string]string, domainTemplate, ingressClass string) (*networkingv1.Ingress, error) {

	if ingressClass == "none" {
		return nil, nil
	}

	components, err := d.devfileObj.Data.GetDevfileContainerComponents(common.DevfileOptions{})
	if err != nil {
		return nil, err
	}

	var hosts []string
	var rules []networkingv1.IngressRule

	// Create a new template and parse the letter into it.
	t, err := template.New("domainTemplate").Parse(domainTemplate)
	if err != nil {
		return nil, err
	}

	for _, component := range components {
		for _, endpoint := range component.Container.Endpoints {
			var domain bytes.Buffer
			err := t.Execute(&domain, map[string]string{"port": strconv.Itoa(endpoint.TargetPort)})
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, domain.String())
			rules = append(rules, networkingv1.IngressRule{
				Host: domain.String(),
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path:     "/",
								PathType: pointerTo(networkingv1.PathTypePrefix),
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: name,
										Port: networkingv1.ServiceBackendPort{
											Number: int32(endpoint.TargetPort),
										},
									},
								},
							},
						},
					},
				},
			})
		}
	}

	if len(rules) == 0 {
		return nil, nil
	}

	ingress := &networkingv1.Ingress{
		TypeMeta: generator.GetTypeMeta("Ingress", "networking.k8s.io/v1"),
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &ingressClass,
			//TLS: []networkingv1.IngressTLS{
			//	{
			//		Hosts:      hosts,
			//		SecretName: "tls",
			//	},
			//},
			Rules: rules,
		},
	}

	return ingress, nil
}

func (d Devfile) getPVC(name, namespace string, labels, annotations map[string]string) ([]*corev1.PersistentVolumeClaim, error) {
	_, _, volumes, volumeNameToVolumeOptions, err := d.getContainersAndVolumes(name)
	if err != nil {
		return nil, err
	}
	pvcs := make([]*corev1.PersistentVolumeClaim, 0)
	for _, volume := range volumes {
		volumeOptions := volumeNameToVolumeOptions[volume.Name]
		if volumeOptions.IsEphemeral {
			continue
		}
		quantity, err := resource.ParseQuantity(volumeOptions.Size)
		if err != nil {
			return nil, err
		}
		pvcParams := generator.PVCParams{
			TypeMeta: generator.GetTypeMeta("PersistentVolumeClaim", "v1"),
			ObjectMeta: metav1.ObjectMeta{
				Name:        volumeOptions.Info.PVCName,
				Namespace:   namespace,
				Labels:      labels,
				Annotations: annotations,
			},
			Quantity: quantity,
		}
		pvc := generator.GetPVC(pvcParams)
		pvcs = append(pvcs, pvc)
	}
	return pvcs, nil
}

func (d Devfile) getAll(name, namespace string, labels, annotations map[string]string, replicas int, domainTemplate, ingressClass string) ([]runtime.Object, error) {

	var result []runtime.Object

	deployment, err := d.getDeployment(name, namespace, labels, annotations, replicas)
	if err != nil {
		return nil, err
	}
	result = append(result, deployment)

	service, err := d.getService(name, namespace, labels, annotations)
	if err != nil {
		return nil, err
	}
	result = append(result, service)

	ingress, err := d.getIngress(name, namespace, labels, annotations, domainTemplate, ingressClass)
	if err != nil {
		return nil, err
	}
	if ingress != nil {
		result = append(result, ingress)
	}

	pvcs, err := d.getPVC(name, namespace, labels, annotations)
	if err != nil {
		return nil, err
	}
	for _, pvc := range pvcs {
		result = append(result, pvc)
	}

	return result, nil
}

func (d Devfile) getContainersAndVolumes(name string) ([]corev1.Container, []corev1.Container, []corev1.Volume, map[string]volumeOptions, error) {
	// TODO - Use `generator.GetPodTemplateSpec` since `generator.GetContainer`/`generator.GetInitContainer` are deprecated.
	// However, there is an issue with how the init containers are named in the devfile and in the generated pod template.
	// This results in a mismatch and the init containers are not correctly added. This also affects the volume mounting.
	// Resolving this upstream issue would most probably also mean that we can remove volume.go file
	// and directly use upstream functions.
	// Context - https://gitlab.com/gitlab-org/ruby/gems/devfile-gem/-/merge_requests/65#note_2144734460
	// Upstream issue - https://github.com/devfile/api/issues/1645
	containers, err := generator.GetContainers(d.devfileObj, common.DevfileOptions{})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	initContainers, err := generator.GetInitContainers(d.devfileObj)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	allContainers := append(containers, initContainers...)

	volumeComponents, err := d.devfileObj.Data.GetDevfileVolumeComponents(common.DevfileOptions{})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	volumeNameToVolumeOptions := map[string]volumeOptions{}
	volumeNameToVolumeInfo := map[string]generator.VolumeInfo{}
	for _, volumeComponent := range volumeComponents {
		info := generator.VolumeInfo{
			PVCName:    fmt.Sprintf("%s-%s", name, volumeComponent.Name),
			VolumeName: volumeComponent.Name,
		}
		volumeNameToVolumeInfo[volumeComponent.Name] = info
		volumeNameToVolumeOptions[volumeComponent.Name] = volumeOptions{
			Info:        info,
			Size:        volumeComponent.Volume.Size,
			IsEphemeral: *volumeComponent.Volume.Ephemeral,
		}
	}

	volumeParams := generator.VolumeParams{
		Containers:             allContainers,
		VolumeNameToVolumeInfo: volumeNameToVolumeInfo,
	}
	options := common.DevfileOptions{}
	// "containers" and "initContainers" are updated in place with the volume mounts parameters
	// after the following function is called
	//volumes, err := generator.GetVolumesAndVolumeMounts(d.devfileObj, volumeParams, options)
	updatedAllContainers, volumes, err := getVolumesAndVolumeMounts(d.devfileObj, volumeParams, options)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// sort all volumes and volume mounts in the containers and initContainers
	// to keep the array order deterministic
	sort.SliceStable(volumes, func(i, j int) bool {
		return volumes[i].Name < volumes[j].Name
	})

	updatedContainers := make([]corev1.Container, 0)
	updatedInitContainers := make([]corev1.Container, 0)
	for _, updated := range updatedAllContainers {
		sort.SliceStable(updated.VolumeMounts, func(i, j int) bool {
			return updated.VolumeMounts[i].Name < updated.VolumeMounts[j].Name
		})
		for _, container := range containers {
			if updated.Name == container.Name {
				updatedContainers = append(updatedContainers, updated)
			}
		}
		for _, initContainer := range initContainers {
			if updated.Name == initContainer.Name {
				updatedInitContainers = append(updatedInitContainers, updated)
			}
		}
	}

	return updatedContainers, updatedInitContainers, volumes, volumeNameToVolumeOptions, nil
}

func (d Devfile) hasContainerComponents() (bool, error) {
	// TODO - Use `generator.GetPodTemplateSpec` since `generator.GetContainer` are deprecated.
	// Context - https://gitlab.com/gitlab-org/ruby/gems/devfile-gem/-/merge_requests/65#note_2144734460
	containers, err := generator.GetContainers(d.devfileObj, common.DevfileOptions{})
	if err != nil {
		return false, err
	}
	if len(containers) > 0 {
		return true, nil
	}
	return false, nil
}

func (d Devfile) getFlattenedDevfileContent() (string, error) {
	b, err := yaml.Marshal(d.devfileObj.Data)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseDevfile(content string) (Devfile, error) {
	parserArgs := parser.ParserArgs{
		Data: []byte(content),
	}
	// TODO: figure out how to handle warnings
	// 		https://gitlab.com/gitlab-org/ruby/gems/devfile-gem/-/issues/6
	devfileObj, _, err := devfile.ParseDevfileAndValidate(parserArgs)
	return Devfile{
		devfileObj: devfileObj,
	}, err
}

func marshalResources(objs []runtime.Object) (string, error) {
	printer := printers.YAMLPrinter{}
	dest := bytes.NewBuffer([]byte{})
	for _, obj := range objs {
		if obj == nil {
			continue
		}
		err := printer.PrintObj(obj, dest)
		if err != nil {
			return "", err
		}
	}
	return dest.String(), nil
}

func marshalDevfile(devfile string) (string, error) {
	data, err := yaml.JSONToYAML([]byte(devfile))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// since it is not possible to get pointer of a constant directly
func pointerTo[T any](v T) *T {
	return &v
}
