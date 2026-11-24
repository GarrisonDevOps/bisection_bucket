---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 자동 DevOps 요구 사항
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[자동 DevOps](_index.md)를 활성화하기 전에 배포를 준비해야 합니다. 그렇지 않으면 앱을 빌드하고 테스트한 후 나중에 배포를 구성할 수 있습니다.

배포를 준비하려면:

1. [배포 전략](#auto-devops-deployment-strategy)을 정의합니다.
1. [기본 도메인](#auto-devops-base-domain)을 준비합니다.
1. 배포할 위치를 정의합니다:

   1. [Kubernetes](#auto-devops-requirements-for-kubernetes).
   1. [Amazon Elastic Container Service(ECS)](cloud_deployments/auto_devops_with_ecs.md).
   1. [Amazon Elastic Kubernetes Service(EKS)](https://about.gitlab.com/blog/deploying-application-eks/).
   1. [Amazon EC2](cloud_deployments/auto_devops_with_ec2.md).
   1. [Google Kubernetes Engine](cloud_deployments/auto_devops_with_gke.md).
   1. [베어 메탈](#auto-devops-requirements-for-bare-metal).

1. [자동 DevOps 활성화](_index.md#enable-or-disable-auto-devops).

## 자동 DevOps 배포 전략 {#auto-devops-deployment-strategy}

자동 DevOps를 사용하여 애플리케이션을 배포할 때 필요에 맞는 [지속적 배포 전략](../../ci/_index.md)을 선택합니다:

| 배포 전략                                                     | 설정 | 방법론 |
|-------------------------------------------------------------------------|-------|-------------|
| **프로덕션 환경에 지속적인 배포**                                 | [자동 배포](stages.md#auto-deploy)를 활성화하고 기본 브랜치를 프로덕션에 지속적으로 배포합니다. | 프로덕션 환경에 지속적인 배포.|
| **점진적(incremental) 롤아웃을 사용하여 프로덕션 환경에 지속적 배포** | [`INCREMENTAL_ROLLOUT_MODE`](cicd_variables.md#timed-incremental-rollout-to-production) 변수를 `timed`으로 설정합니다. | 롤아웃 간 5분의 지연으로 프로덕션에 지속적으로 배포합니다. |
| **스테이징 환경에 자동 배포, 프로덕션 환경에 수동 배포**    | [`STAGING_ENABLED`](cicd_variables.md#deploy-policy-for-staging-and-production-environments)를 `1`으로 설정하고 [`INCREMENTAL_ROLLOUT_MODE`](cicd_variables.md#incremental-rollout-to-production)를 `manual`으로 설정합니다. | 기본 브랜치는 스테이징에 지속적으로 배포되고 프로덕션에 지속적으로 전달됩니다. |

자동 DevOps를 활성화할 때 또는 나중에 배포 방법을 선택할 수 있습니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **자동 DevOps**를 확장합니다.
1. 배포 전략을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

> [!note]
> [블루-그린 배포](../../ci/environments/incremental_rollouts.md#blue-green-deployment) 기법을 사용하여 다운타임과 위험을 최소화합니다.

## 자동 DevOps 기본 도메인 {#auto-devops-base-domain}

자동 DevOps 기본 도메인은 [자동 검토 앱](stages.md#auto-review-apps) 및 [자동 배포](stages.md#auto-deploy)를 사용하는 데 필요합니다.

기본 도메인을 정의하려면 다음 중 하나를 수행합니다:

- 프로젝트, 그룹 또는 인스턴스 수준에서: 클러스터 설정으로 이동하여 추가합니다.
- 프로젝트 또는 그룹 수준에서: 환경 변수로 추가합니다: `KUBE_INGRESS_BASE_DOMAIN`.
- 인스턴스 수준에서: **운영자** 영역으로 이동한 후 **설정** > **CI/CD** > **지속적 통합 및 전달**로 이동하여 추가합니다.

기본 도메인 변수 `KUBE_INGRESS_BASE_DOMAIN`은 [다른 환경 변수와 동일한 우선 순위](../../ci/variables/_index.md#cicd-variable-precedence)를 따릅니다.

프로젝트 및 그룹에서 기본 도메인을 지정하지 않으면 자동 DevOps는 인스턴스 전체 **Auto DevOps 도메인**을 사용합니다.

자동 DevOps는 기본 도메인과 일치하는 와일드카드 DNS `A` 레코드를 필요로 합니다. 기본 도메인이 `example.com`인 경우 다음과 같은 DNS 항목이 필요합니다:

```plaintext
*.example.com   3600     A     10.0.2.2
```

이 경우 배포된 애플리케이션은 `example.com`에서 제공되며 `10.0.2.2`는 로드 밸런서(일반적으로 NGINX)의 IP 주소입니다(요구 사항 참조). DNS 레코드 설정은 이 문서의 범위를 벗어나므로 DNS 제공자에게 정보를 확인합니다.

또는 [nip.io](https://nip.io)와 같은 무료 공개 서비스를 사용할 수 있으며, 이들은 구성 없이 자동 와일드카드 DNS를 제공합니다. [nip.io](https://nip.io)의 경우 자동 DevOps 기본 도메인을 `10.0.2.2.nip.io`으로 설정합니다.

설정을 완료한 후 모든 요청은 로드 밸런서에 도달하며, 로드 밸런서는 애플리케이션을 실행 중인 Kubernetes 포드로 요청을 라우팅합니다.

## Kubernetes 자동 DevOps 요구 사항 {#auto-devops-requirements-for-kubernetes}

자동 DevOps를 Kubernetes와 완벽하게 사용하려면 다음이 필요합니다:

- **Kubernetes** ([자동 검토 앱](stages.md#auto-review-apps) 및 [자동 배포](stages.md#auto-deploy)용)

  배포를 활성화하려면 다음이 필요합니다:

  1. 프로젝트용 [Kubernetes 1.12+ 클러스터](../../user/infrastructure/clusters/_index.md). Kubernetes 1.16+ 클러스터의 경우 [Kubernetes 1.16+용 자동 배포](stages.md#kubernetes-116)를 위해 추가 구성을 수행해야 합니다.
  1. 외부 HTTP 트래픽의 경우 Ingress 컨트롤러가 필요합니다. 일반 배포의 경우 모든 Ingress 컨트롤러가 작동하지만 [카나리 배포](../../user/project/canary_deployments.md)는 NGINX Ingress를 필요로 합니다. GitLab [클러스터 관리 프로젝트 템플릿](../../user/clusters/management_project_template.md) 또는 [`ingress-nginx`](https://github.com/kubernetes/ingress-nginx/tree/master/charts/ingress-nginx) Helm 차트를 수동으로 사용하여 NGINX Ingress 컨트롤러를 Kubernetes 클러스터에 배포할 수 있습니다.

     [사용자 정의 차트 사용](customize.md#custom-helm-chart) 시 Prometheus에서 스크래핑하도록 Ingress 매니페스트를 [주석 처리](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/)해야 하며 `prometheus.io/scrape: "true"` 및 `prometheus.io/port: "10254"`를 사용합니다.

     > [!note]
     > 클러스터가 베어 메탈에 설치된 경우 [베어 메탈 자동 DevOps 요구 사항](#auto-devops-requirements-for-bare-metal)을 참조합니다.

- **기본 도메인** ([자동 검토 앱](stages.md#auto-review-apps) 및 [자동 배포](stages.md#auto-deploy)용)

  모든 자동 DevOps 애플리케이션이 사용하는 [자동 DevOps 기본 도메인을 지정](#auto-devops-base-domain)해야 합니다. 이 도메인은 와일드카드 DNS로 구성되어야 합니다.
- **GitLab Runner** (모든 스테이지용)

  러너는 Docker를 실행하도록 구성되어야 하며 일반적으로 [Docker](https://docs.gitlab.com/runner/executors/docker/) 또는 [Kubernetes](https://docs.gitlab.com/runner/executors/kubernetes/) 실행기 중 하나와 [권한 있는 모드 활성화](https://docs.gitlab.com/runner/executors/docker/#use-docker-in-docker-with-privileged-mode)로 구성됩니다. 러너는 Kubernetes 클러스터에 설치될 필요는 없지만 Kubernetes 실행기를 사용하면 쉽고 자동으로 자동 확장됩니다. [Docker Machine](https://docs.gitlab.com/runner/executors/docker_machine/)을 사용하여 Docker 기반 러너도 자동 확장하도록 구성할 수 있습니다.

  러너는 전체 GitLab 인스턴스에 대해 [인스턴스 러너](../../ci/runners/runners_scope.md#instance-runners)로 등록되거나 특정 프로젝트에 할당되는 [프로젝트 러너](../../ci/runners/runners_scope.md#project-runners)로 등록되어야 합니다.
- **cert-manager** (선택 사항, TLS/HTTPS용)

  애플리케이션에 대해 HTTPS 엔드포인트를 활성화하려면 [cert-manager 설치](https://cert-manager.io/docs/releases/)할 수 있으며, 이는 인증서 발급을 지원하는 네이티브 Kubernetes 인증서 관리 컨트롤러입니다. 클러스터에 cert-manager를 설치하면 [Let's Encrypt](https://letsencrypt.org/) 인증서가 발급되고 인증서가 유효하고 최신 상태임을 보장합니다.

Kubernetes 또는 Prometheus를 구성하지 않으면 [자동 검토 앱](stages.md#auto-review-apps) 및 [자동 배포](stages.md#auto-deploy)가 건너뜁니다.

모든 요구 사항이 충족되면 [자동 DevOps를 활성화](_index.md#enable-or-disable-auto-devops)할 수 있습니다.

## 베어 메탈 자동 DevOps 요구 사항 {#auto-devops-requirements-for-bare-metal}

[Kubernetes Ingress-NGINX 문서](https://kubernetes.github.io/ingress-nginx/deploy/baremetal/)에 따르면:

> 기존의 클라우드 환경에서 네트워크 로드 밸런서를 온디맨드로 사용할 수 있는 경우 단일 Kubernetes 매니페스트로 NGINX Ingress 컨트롤러에 대한 단일 연락처 지점을 외부 클라이언트에 제공하고 간접적으로 클러스터 내에서 실행 중인 모든 애플리케이션에 제공할 수 있습니다. 베어 메탈 환경에는 이 편의가 부족하므로 외부 사용자에게 동일한 종류의 액세스를 제공하려면 약간 다른 설정이 필요합니다.

이전에 연결된 문서는 문제를 설명하고 가능한 해결책을 제공합니다. 예를 들면:

- [MetalLB](https://github.com/metallb/metallb) 사용.
- [OpenELB(이전의 PorterLB)](https://github.com/openelb/openelb) 사용.
