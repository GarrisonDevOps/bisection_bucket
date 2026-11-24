---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: OpenTofu 및 GitLab을 사용한 코드 기반 인프라
description: "인프라 관리, 버전 관리, 자동화, 상태 저장소 및 모듈."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab을 사용하여 인프라를 관리하려면 OpenTofu와의 통합을 사용하여 버전 관리, 재사용 및 공유할 수 있는 리소스를 정의할 수 있습니다:

- 컴퓨팅, 스토리지 및 네트워킹 리소스와 같은 저수준 구성 요소를 관리합니다.
- DNS 항목 및 SaaS 기능과 같은 고수준 구성 요소를 관리합니다.
- GitLab을 OpenTofu 상태 저장소로 사용합니다.
- OpenTofu 모듈을 저장하고 사용하여 일반적이고 복잡한 인프라 패턴을 단순화합니다.
- GitOps 배포 및 코드 기반 인프라(IaC) 워크플로를 통합합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> [OpenTofu와의 통합으로 GitLab이 제공하는 기능의 비디오 개요](https://www.youtube.com/watch?v=iGXjUrkkzDI)를 시청하세요.

다음 예제는 주로 OpenTofu를 사용하지만 Terraform에서도 작동합니다.

## Terraform 및 OpenTofu 지원 {#terraform-and-opentofu-support}

GitLab은 Terraform 및 OpenTofu 모두와 통합됩니다. 대부분의 기능은 완전히 호환되며, 다음이 포함됩니다:

- [GitLab 관리 Terraform/OpenTofu 상태](terraform_state.md)
- [머지 리퀘스트의 Terraform/OpenTofu 통합](mr_integration.md)
- [Terraform/OpenTofu 모듈 레지스트리](../../packages/terraform_module_registry/_index.md)

단순성을 위해 GitLab 문서는 주로 OpenTofu를 다룹니다. 그러나 Terraform 및 OpenTofu 통합 간의 차이점이 문서화되어 있습니다.

## 파이프라인에서 OpenTofu 프로젝트 빠르게 시작 {#quickstart-an-opentofu-project-in-pipelines}

OpenTofu는 GitLab OpenTofu CI/CD 구성 요소로 모든 Terraform 관련 GitLab 기능과 통합할 수 있습니다.

구성 요소를 포함하여 파이프라인에 *검증*, *계획* 및 *적용* 워크플로를 추가할 수 있습니다:

```yaml
include:
  - component: gitlab.com/components/opentofu/validate-plan-apply@<VERSION>
    inputs:
      version: <VERSION>
      opentofu_version: <OPENTOFU_VERSION>
      root_dir: terraform/
      state_name: production

stages: [validate, build, deploy]
```

템플릿, 입력 및 OpenTofu CI/CD 구성 요소 사용 방법에 대한 자세한 내용은 [OpenTofu CI/CD 구성 요소 README](https://gitlab.com/components/opentofu)를 참조하세요.

## 자신만의 Terraform CI/CD 템플릿 빌드 및 호스팅 {#build-and-host-your-own-terraform-cicd-templates}

GitLab이 더 이상 Terraform CI/CD 템플릿 및 `terraform-images` (기본 작업 이미지, `terraform` 포함)을 배포하지 않지만 GitLab 파이프라인에서 여전히 Terraform을 사용할 수 있습니다.

자신만의 템플릿 및 이미지를 빌드하고 호스팅하는 방법을 알아보려면 [Terraform 이미지](https://gitlab.com/gitlab-org/terraform-images) 프로젝트를 참조하세요.

## 관련 항목 {#related-topics}

- GitLab을 [Terraform/OpenTofu 모듈 레지스트리](../../packages/terraform_module_registry/_index.md)로 사용합니다.
- 상태 파일을 로컬 저장소 또는 원격 저장소에 저장하려면 [GitLab 관리 Terraform/OpenTofu 상태](terraform_state.md)를 사용합니다.
- Terraform 코드 변경 및 IaC 워크플로에 협업하려면 [머지 리퀘스트의 Terraform 통합](mr_integration.md)을 사용합니다.
- 사용자, 그룹 및 프로젝트와 같은 GitLab 리소스를 관리하려면 [GitLab Terraform 공급자](https://gitlab.com/gitlab-org/terraform-provider-gitlab)를 사용합니다. GitLab Terraform 공급자 문서는 [Terraform 문서 사이트](https://registry.terraform.io/providers/gitlabhq/gitlab/latest/docs)에서 사용할 수 있습니다.
- [Amazon Elastic Kubernetes Service(EKS)에서 새 클러스터 생성](../clusters/connect/new_eks_cluster.md).
- GitLab 및 Terraform의 [문제 해결](troubleshooting.md).
- `gitlab-terraform` 셸 스크립트를 포함하는 [이미지를 봅니다](https://gitlab.com/gitlab-org/terraform-images).
