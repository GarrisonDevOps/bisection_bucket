package main

import (
	"fmt"
	"k8s.io/apimachinery/pkg/util/yaml"
	"os"
	"strconv"

	"k8s.io/apimachinery/pkg/runtime"
)

func main() {
	args := os.Args

	if len(args) <= 1 {
		fmt.Fprint(os.Stderr, "Function name and devfile are required")
		os.Exit(1)
	}

	fnName := os.Args[1]
	devfile := os.Args[2]

	var content string
	var err error

	switch fnName {
	case "deployment":
		content, err = getDeployment(devfile, args[3], args[4], args[5], args[6], args[7])
	case "service":
		content, err = getService(devfile, args[3], args[4], args[5], args[6])
	case "ingress":
		content, err = getIngress(devfile, args[3], args[4], args[5], args[6], args[7], args[8])
	case "pvc":
		content, err = getPVC(devfile, args[3], args[4], args[5], args[6])
	case "all":
		content, err = getAll(devfile, args[3], args[4], args[5], args[6], args[7], args[8], args[9])
	case "flatten":
		content, err = flatten(devfile)
	}

	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Print(content)
}

func unmarshalKeyValuePair(data string) (map[string]string, error) {
	values := map[string]string{}
	err := yaml.Unmarshal([]byte(data), &values)
	if err != nil {
		return nil, err
	}
	return values, err
}

func getDeployment(devfile, name, namespace, labelsStr, annotationsStr, replicas string) (string, error) {
	d, err := parseDevfile(devfile)
	if err != nil {
		return "", err
	}
	exists, err := d.hasContainerComponents()
	if err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	labels, err := unmarshalKeyValuePair(labelsStr)
	if err != nil {
		return "", err
	}
	annotations, err := unmarshalKeyValuePair(annotationsStr)
	if err != nil {
		return "", err
	}
	replicasInt, err := strconv.Atoi(replicas)
	if err != nil {
		return "", err
	}
	deployment, err := d.getDeployment(name, namespace, labels, annotations, replicasInt)
	if err != nil {
		return "", err
	}
	content, err := marshalResources([]runtime.Object{deployment})
	if err != nil {
		return "", err
	}
	return content, nil
}

func getService(devfile, name, namespace, labelsStr, annotationsStr string) (string, error) {
	d, err := parseDevfile(devfile)
	if err != nil {
		return "", err
	}
	exists, err := d.hasContainerComponents()
	if err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	labels, err := unmarshalKeyValuePair(labelsStr)
	if err != nil {
		return "", err
	}
	annotations, err := unmarshalKeyValuePair(annotationsStr)
	if err != nil {
		return "", err
	}
	service, err := d.getService(name, namespace, labels, annotations)
	if err != nil {
		return "", err
	}
	content, err := marshalResources([]runtime.Object{service})
	if err != nil {
		return "", err
	}
	return content, nil
}

func getIngress(devfile, name, namespace, labelsStr, annotationsStr, domainTemplate, ingressClass string) (string, error) {
	d, err := parseDevfile(devfile)
	if err != nil {
		return "", err
	}
	exists, err := d.hasContainerComponents()
	if err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	labels, err := unmarshalKeyValuePair(labelsStr)
	if err != nil {
		return "", err
	}
	annotations, err := unmarshalKeyValuePair(annotationsStr)
	if err != nil {
		return "", err
	}
	ingress, err := d.getIngress(name, namespace, labels, annotations, domainTemplate, ingressClass)
	if err != nil {
		return "", err
	}

	if ingress == nil {
		return "", nil
	}

	content, err := marshalResources([]runtime.Object{ingress})
	if err != nil {
		return "", err
	}
	return content, nil
}

func getPVC(devfile, name, namespace, labelsStr, annotationsStr string) (string, error) {
	d, err := parseDevfile(devfile)
	if err != nil {
		return "", err
	}
	exists, err := d.hasContainerComponents()
	if err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	labels, err := unmarshalKeyValuePair(labelsStr)
	if err != nil {
		return "", err
	}
	annotations, err := unmarshalKeyValuePair(annotationsStr)
	if err != nil {
		return "", err
	}
	pvcs, err := d.getPVC(name, namespace, labels, annotations)
	if err != nil {
		return "", err
	}
	var result []runtime.Object
	for _, pvc := range pvcs {
		result = append(result, pvc)
	}
	content, err := marshalResources(result)
	if err != nil {
		return "", err
	}
	return content, nil
}

func getAll(devfile string, name, namespace, labelsStr, annotationsStr, replicas, domainTemplate, ingressClass string) (string, error) {
	d, err := parseDevfile(devfile)
	if err != nil {
		return "", err
	}
	exists, err := d.hasContainerComponents()
	if err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	labels, err := unmarshalKeyValuePair(labelsStr)
	if err != nil {
		return "", err
	}
	annotations, err := unmarshalKeyValuePair(annotationsStr)
	if err != nil {
		return "", err
	}
	replicasInt, err := strconv.Atoi(replicas)
	if err != nil {
		return "", err
	}
	resources, err := d.getAll(name, namespace, labels, annotations, replicasInt, domainTemplate, ingressClass)
	if err != nil {
		return "", err
	}
	content, err := marshalResources(resources)
	if err != nil {
		return "", err
	}
	return content, nil
}

func flatten(devfile string) (string, error) {
	d, err := parseDevfile(devfile)
	if err != nil {
		return "", err
	}
	flattenedDevfile, err := d.getFlattenedDevfileContent()
	if err != nil {
		return "", err
	}
	content, err := marshalDevfile(flattenedDevfile)
	if err != nil {
		return "", err
	}
	return content, err
}
