---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 패키지 및 레지스트리
description: "패키지 관리, 컨테이너 레지스트리, 아티팩트 스토리지 및 종속성 관리."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab [패키지 레지스트리](package_registry/_index.md)는 다양한 일반적인 패키지 관리자를 위한 비공개 또는 공개 레지스트리로 사용됩니다. 패키지를 게시하고 공유할 수 있으며, 다운스트림 프로젝트에서 종속성으로 사용할 수 있습니다.

## 컨테이너 레지스트리 {#container-registry}

GitLab [컨테이너 레지스트리](container_registry/_index.md)는 컨테이너 이미지를 위한 보안되고 비공개 레지스트리입니다. 오픈 소스 소프트웨어를 기반으로 하며 GitLab에 완전히 통합되어 있습니다. GitLab CI/CD를 사용하여 이미지를 생성하고 게시합니다. GitLab [API](../../api/container_registry.md)를 사용하여 그룹 및 프로젝트 전체에서 레지스트리를 관리합니다.

## Terraform 모듈 레지스트리 {#terraform-module-registry}

GitLab [Terraform 모듈 레지스트리](terraform_module_registry/_index.md)는 Terraform 모듈을 위한 보안되고 비공개 레지스트리입니다. GitLab CI/CD를 사용하여 모듈을 생성하고 게시할 수 있습니다.

## 가상 레지스트리 {#virtual-registry}

GitLab [가상 레지스트리](virtual_registry/_index.md)는 GitLab의 외부 레지스트리에서 패키지 관리를 개선하기 위한 고급 캐싱, 프록시 및 배포 기능을 제공합니다.

## 종속성 프록시 {#dependency-proxy}

[종속성 프록시](dependency_proxy/_index.md)는 자주 사용되는 상위 스트림 이미지 및 패키지에 대한 로컬 프록시입니다.
