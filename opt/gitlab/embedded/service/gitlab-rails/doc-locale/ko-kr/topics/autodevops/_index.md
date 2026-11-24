---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Auto DevOps
description: "자동화된 DevOps, 언어 감지, 배포 및 커스터마이제이션."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

자동 DevOps는 일반적인 설정 오버헤드 없이 코드를 프로덕션 준비가 된 애플리케이션으로 변환합니다. 전체 DevOps 수명 주기가 업계 모범 사례를 사용하여 사전 구성됩니다. 기본값으로 시작하여 빠르게 배포한 후 더 많은 제어가 필요할 때 커스터마이제이션합니다. 복잡한 설정 파일이나 깊은 DevOps 전문 지식이 필요하지 않습니다.

자동 DevOps를 사용하면 다음을 얻습니다:

- 자동으로 언어 및 프레임워크를 감지하는 CI/CD 파이프라인
- 프로덕션에 도달하기 전에 취약점을 찾기 위한 기본 제공 보안 스캔
- 모든 커밋에 대한 코드 품질 및 성능 테스트
- 라이브 환경에서 변경 사항을 미리 보기 위한 준비된 검토 앱
- Kubernetes 클러스터에 빠른 배포
- 위험 및 다운타임을 줄이는 점진적 배포 전략

<i class="fa-youtube-play" aria-hidden="true"></i> 자동 DevOps 소개를 보려면 [자동 DevOps](https://youtu.be/0Tc0YYBxqi4)를 참조하세요.
<!-- Video published on 2018-06-22 -->

## 자동 DevOps 기능 {#auto-devops-features}

자동 DevOps는 각 [DevOps 스테이지](stages.md)에서 개발을 지원합니다.

| 스테이지  | 자동 DevOps 기능 |
|--------|---------------------|
| 빌드  | [자동 빌드](stages.md#auto-build) |
| 빌드  | [자동 종속성 검사](stages.md#auto-dependency-scanning) |
| 테스트   | [자동 테스트](stages.md#auto-test) |
| 테스트   | [자동 브라우저 성능 테스트](stages.md#auto-browser-performance-testing) |
| 테스트   | [자동 코드 인텔리전스](stages.md#auto-code-intelligence) |
| 테스트   | [자동 코드 품질](stages.md#auto-code-quality) |
| 테스트   | [자동 컨테이너 스캔](stages.md#auto-container-scanning) |
| 배포 | [자동 검토 앱](stages.md#auto-review-apps) |
| 배포 | [자동 배포](stages.md#auto-deploy) |
| 보안 | [자동 동적 애플리케이션 보안 테스트(DAST)](stages.md#auto-dast) |
| 보안 | [자동 정적 애플리케이션 보안 테스트(SAST)](stages.md#auto-sast) |
| 보안 | [자동 시크릿 검색](stages.md#auto-secret-detection) |

### 애플리케이션 플랫폼 및 PaaS와의 비교 {#comparison-to-application-platforms-and-paas}

자동 DevOps는 애플리케이션 플랫폼이나 PaaS(Platform as a Service)에 자주 포함되는 기능을 제공합니다.

[Heroku](https://www.heroku.com/)에서 영감을 받은 자동 DevOps는 여러 방면에서 이를 초월합니다:

- 자동 DevOps는 모든 Kubernetes 클러스터에서 작동합니다.
- 추가 비용이 없습니다.
- 자신이 호스팅하거나 공용 클라우드에서 클러스터를 사용할 수 있습니다.
- 자동 DevOps는 점진적 발전 경로를 제공합니다. [커스터마이제이션](customize.md)이 필요하면 템플릿을 변경하여 시작하고 그곳에서 발전시킵니다.

## 자동 DevOps 시작 {#get-started-with-auto-devops}

시작하려면 [자동 DevOps 활성화](#enable-or-disable-auto-devops)만 하면 됩니다. 이것으로 자동 DevOps 파이프라인을 실행하여 애플리케이션을 빌드하고 테스트할 수 있습니다.

앱을 빌드, 테스트 및 배포하려면:

1. [배포 요구사항](requirements.md)을(를) 확인합니다.
1. [자동 DevOps 활성화](#enable-or-disable-auto-devops)합니다.
1. [클라우드 제공자에 앱 배포](#deploy-your-app-to-a-cloud-provider)합니다.

### 자동 DevOps 활성화 또는 비활성화 {#enable-or-disable-auto-devops}

자동 DevOps는 [`Dockerfile` 또는 일치하는 빌드팩](stages.md#auto-build)이 존재할 때만 자동으로 파이프라인을 실행합니다.

프로젝트 또는 전체 그룹에 대해 자동 DevOps를 활성화 또는 비활성화할 수 있습니다. 인스턴스 관리자는 또한 인스턴스의 모든 프로젝트에 대해 [자동 DevOps를 기본으로 설정](../../administration/settings/continuous_integration.md#configure-auto-devops-for-all-projects)할 수 있습니다.

자동 DevOps를 활성화하기 전에 [배포를 위해 준비](requirements.md)하는 것을 고려하세요. 그렇지 않으면 자동 DevOps는 앱을 빌드하고 테스트할 수 있지만 배포할 수 없습니다.

#### 프로젝트별 {#per-project}

개별 프로젝트에 자동 DevOps를 사용하려면 프로젝트별로 활성화할 수 있습니다. 더 많은 프로젝트에 사용할 계획이면 [그룹](#per-group) 또는 [인스턴스](../../administration/settings/continuous_integration.md#configure-auto-devops-for-all-projects)에 대해 활성화할 수 있습니다. 이것은 각 프로젝트에서 활성화하는 시간을 절약할 수 있습니다.

전제 조건:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 프로젝트에 `.gitlab-ci.yml`이(가) 없어야 합니다. 있는 경우 CI/CD 구성은 자동 DevOps 파이프라인보다 우선합니다.

프로젝트에 대해 자동 DevOps를 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **자동 DevOps**를 확장합니다.
1. **Auto DevOps 파이프라인을 기본으로 사용** 확인란을 선택합니다.
1. 선택 사항이지만 권장됩니다. [기본 도메인](requirements.md#auto-devops-base-domain)을(를) 추가합니다.
1. 선택 사항이지만 권장됩니다. [배포 전략](requirements.md#auto-devops-deployment-strategy)을(를) 선택합니다.
1. **변경 사항 저장**을 선택합니다.

GitLab은 기본 브랜치에서 자동 DevOps 파이프라인을 실행합니다.

자동 DevOps가 작동하는지 확인하려면:

1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. 기본 브랜치에서 실행된 파이프라인을 검색합니다. 실행 중이거나 최근에 완료되어야 합니다.
1. 파이프라인을 선택하여 해당 작업 및 스테이지를 봅니다.

파이프라인에는 `build`, `test`, `code_quality` 및 `sast`와 같은 자동 DevOps 스테이지의 작업이 프로젝트에 대해 구성되어 있습니다.

파이프라인이 실행되지 않거나 이러한 작업이 누락된 경우:

- 프로젝트가 [자동 DevOps 요구사항](requirements.md)을(를) 충족하는지 확인합니다.
- **Auto DevOps 파이프라인을 기본으로 사용**이(가) **설정** > **CI/CD** > **자동 DevOps**에서 선택되어 있는지 확인합니다.

비활성화하려면 같은 프로세스를 따르고 **Auto DevOps 파이프라인을 기본으로 사용** 확인란을 선택 취소합니다.

#### 그룹별 {#per-group}

그룹에 대해 자동 DevOps를 활성화하면 해당 그룹의 하위 그룹과 프로젝트가 구성을 상속합니다. 각 하위 그룹 또는 프로젝트에 대해 활성화하는 것 대신 그룹에 대해 자동 DevOps를 활성화하여 시간을 절약할 수 있습니다.

그룹에 대해 활성화된 경우 사용하지 않으려는 하위 그룹 및 프로젝트에 대해서는 여전히 자동 DevOps를 비활성화할 수 있습니다.

전제 조건:

- 그룹의 Owner 역할이 있어야 합니다.

그룹에 대해 자동 DevOps를 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **자동 DevOps**를 확장합니다.
1. **Auto DevOps 파이프라인을 기본으로 사용** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

그룹에 대해 자동 DevOps를 비활성화하려면 같은 프로세스를 따르고 **Auto DevOps 파이프라인을 기본으로 사용** 확인란을 선택 취소합니다.

그룹에 대해 자동 DevOps를 활성화한 후 해당 그룹에 속한 모든 프로젝트에 대해 자동 DevOps 파이프라인을 실행할 수 있습니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 프로젝트에 `.gitlab-ci.yml` 파일이 없는지 확인합니다.
1. **빌드** > **파이프라인**을 선택합니다.
1. 자동 DevOps 파이프라인을 실행하려면 **새 파이프라인**을(를) 선택합니다.

### 클라우드 제공자에 앱 배포 {#deploy-your-app-to-a-cloud-provider}

- [Google Kubernetes Engine(GKE)의 Kubernetes 클러스터에 자동 DevOps 배포](cloud_deployments/auto_devops_with_gke.md)
- [Amazon Elastic Kubernetes Service(EKS)의 Kubernetes 클러스터에 자동 DevOps 배포](cloud_deployments/auto_devops_with_eks.md)
- [EC2에 자동 DevOps 배포](cloud_deployments/auto_devops_with_ec2.md)
- [ECS에 자동 DevOps 배포](cloud_deployments/auto_devops_with_ecs.md)

## GitLab 업데이트 시 자동 DevOps 종속성 업그레이드 {#upgrade-auto-devops-dependencies-when-updating-gitlab}

GitLab을 업데이트할 때 새 GitLab 버전과 일치하도록 자동 DevOps 종속성을 업그레이드해야 할 수 있습니다:

- [자동 DevOps 리소스 업그레이드](upgrading_auto_deploy_dependencies.md):
  - 자동 DevOps 템플릿.
  - 자동 배포 템플릿.
  - 자동 배포 이미지.
  - Helm.
  - Kubernetes.
  - 환경 변수.
- [PostgreSQL 업그레이드](upgrading_postgresql.md).

## 개인 레지스트리 지원 {#private-registry-support}

자동 DevOps로 개인 컨테이너 레지스트리를 사용할 수 있다는 보장은 없습니다.

대신 자동 DevOps와 함께 [GitLab 컨테이너 레지스트리](../../user/packages/container_registry/_index.md)를 사용하여 구성을 단순화하고 예상치 못한 문제를 방지합니다.

## 프록시 뒤에 애플리케이션 설치 {#install-applications-behind-a-proxy}

Helm과의 GitLab 통합은 프록시 뒤에서 애플리케이션 설치를 지원하지 않습니다.

이를 수행하려면 런타임 시 설치 포드에 프록시 설정을 주입해야 합니다.

## 관련 항목 {#related-topics}

- [지속적인 방법론](../../ci/_index.md)
- [Docker](https://docs.docker.com)
- [GitLab Runner](https://docs.gitlab.com/runner/)
- [Helm](https://helm.sh/docs/)
- [Kubernetes](https://kubernetes.io/docs/home/)
- [Prometheus](https://prometheus.io/docs/introduction/overview/)

## 문제 해결 {#troubleshooting}

[자동 DevOps 문제 해결](troubleshooting.md)을(를) 참조하세요.
