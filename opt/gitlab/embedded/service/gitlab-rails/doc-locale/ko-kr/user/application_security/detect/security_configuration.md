---
stage: Security Risk Management
group: Security Platform Management
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 보안 구성
description: "구성, 테스트, 규정 준수, 스캔, 활성화."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

프로젝트별로 개별적으로 보안 스캐너를 구성하거나 여러 프로젝트에서 공유하는 스캐너 구성을 만들 수 있습니다. 각 프로젝트를 수동으로 구성하면 최대 유연성을 얻을 수 있지만 규모에 따라 유지 관리가 어려워집니다. 여러 프로젝트 또는 그룹의 경우 공유 스캐너 구성을 사용하면 필요한 경우 일부 사용자 정의를 허용하면서 더 쉬운 관리를 제공합니다.

예를 들어 수동으로 동일한 보안 스캔 구성이 적용된 10개의 프로젝트가 있으면 단일 변경을 10번 수행해야 합니다. 대신 공유 CI/CD 구성을 만들면 단일 변경을 한 번만 수행하면 됩니다.

## 개별 프로젝트 구성 {#configure-an-individual-project}

개별 프로젝트에서 보안 스캔을 구성하려면 다음 중 하나를 수행하세요:

- CI/CD 구성 파일을 편집합니다.
- UI에서 CI/CD 구성을 편집합니다.

### CI/CD 파일 사용 {#with-a-cicd-file}

개별 프로젝트의 보안 스캔을 수동으로 활성화하려면 다음 중 하나를 수행하세요:

- 개별 보안 스캐너를 활성화합니다.
- AutoDevOps를 사용하여 모든 보안 스캐너를 활성화합니다.

AutoDevOps는 대부분의 보안 스캐너를 활성화하는 최소 노력 경로를 제공합니다. 그러나 개별 보안 스캐너를 활성화하는 것과 비교하여 사용자 정의 옵션이 제한적입니다.

#### 개별 보안 스캐너 활성화 {#enable-individual-security-scanners}

설정을 사용자 정의할 수 있는 옵션을 사용하여 개별 보안 스캔 도구를 활성화하려면 보안 스캐너의 템플릿을 `.gitlab-ci.yml` 파일에 포함시킵니다.

개별 보안 스캐너를 활성화하는 방법에 대한 지침은 해당 설명서를 참조하세요.

#### Auto DevOps를 사용하여 보안 스캔 활성화 {#enable-security-scanning-by-using-auto-devops}

다음 보안 스캔 도구를 기본 설정으로 활성화하려면 [Auto DevOps](../../../topics/autodevops/_index.md)를 활성화합니다:

- [Auto SAST](../../../topics/autodevops/stages.md#auto-sast)
- [Auto 시크릿 검색](../../../topics/autodevops/stages.md#auto-secret-detection)
- [Auto DAST](../../../topics/autodevops/stages.md#auto-dast)
- [Auto 종속성 검사](../../../topics/autodevops/stages.md#auto-dependency-scanning)
- [Auto 컨테이너 스캔](../../../topics/autodevops/stages.md#auto-container-scanning)

Auto DevOps를 직접 사용자 정의할 수는 없지만 [프로젝트의 `.gitlab-ci.yml` 파일에 Auto DevOps 템플릿을 포함](../../../topics/autodevops/customize.md#customize-gitlab-ciyml)하고 필요에 따라 설정을 재정의할 수 있습니다.

### UI 사용 {#with-the-ui}

**보안 구성** 페이지를 사용하여 프로젝트의 보안 테스트 및 취약성 관리 설정을 보고 구성합니다.

**보안 테스트** 탭은 기본 브랜치의 최근 커밋에서 CI/CD 파이프라인을 확인하여 각 보안 도구의 상태를 반영합니다.

활성화됨 : 보안 테스트 도구의 아티팩트가 파이프라인의 출력에서 발견되었습니다.

활성화되지 않음 : CI/CD 파이프라인이 없거나 보안 테스트 도구의 아티팩트가 파이프라인의 출력에서 발견되지 않았습니다.

#### 보안 구성 페이지 보기 {#view-security-configuration-page}

사전 요구 사항:

- 프로젝트에 대한 Security Manager, Maintainer 또는 Owner 역할.

프로젝트의 보안 구성을 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **보안** > **보안 구성**을 선택합니다.

CI/CD 구성 파일의 변경 사항을 보려면 **구성 이력**을 선택합니다.

#### 프로젝트의 보안 구성 편집 {#edit-a-projects-security-configuration}

사전 요구 사항:

- 프로젝트에 대한 Security Manager, Maintainer 또는 Owner 역할.

프로젝트의 보안 구성을 편집하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **보안** > **보안 구성**을 선택합니다.
1. 활성화하거나 구성하려는 보안 스캐너를 선택하고 지침을 따릅니다.

개별 보안 스캐너를 활성화하고 구성하는 방법에 대한 자세한 내용은 해당 설명서를 참조하세요.

## 공유 구성 만들기 {#create-a-shared-configuration}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

동일한 보안 스캔 구성을 여러 프로젝트에 적용하려면 다음 방법 중 하나를 사용합니다:

- [검사 실행 정책](../policies/scan_execution_policies.md)
- [파이프라인 실행 정책](../policies/pipeline_execution_policies.md)

이러한 각 방법을 통해 보안 스캔을 포함한 CI/CD 구성을 한 번 정의하고 여러 프로젝트 및 그룹에 적용할 수 있습니다. 이러한 방법에는 각 프로젝트를 개별적으로 구성하는 것에 비해 여러 가지 장점이 있습니다:

- 구성 변경을 각 프로젝트마다 여러 번 하지 않고 한 번만 수행하면 됩니다.
- 구성 변경 권한이 제한되어 있어 업무 분리가 제공됩니다.

## 보안 스캔 사용자 정의 {#customize-security-scanning}

보안 스캔을 사용자 정의하여 요구 사항과 환경에 맞게 할 수 있습니다. 개별 보안 스캐너를 사용자 정의하는 방법에 대한 자세한 내용은 해당 설명서를 참조하세요.

### 모범 사례 {#best-practices}

보안 스캔 구성을 사용자 정의할 때:

- 변경 사항을 기본 브랜치에 병합하기 전에 머지 리퀘스트를 사용하여 보안 스캔 도구의 모든 사용자 정의를 테스트합니다. 테스트를 거치지 않으면 수많은 거짓 양성을 포함하여 예상치 못한 결과가 발생할 수 있습니다.
- 스캔 도구의 CI/CD 템플릿을 [포함](../../../ci/yaml/_index.md#include)합니다. 템플릿의 내용을 복사하지 마세요.
- 필요한 경우에만 템플릿의 값을 재정의합니다. 다른 모든 값은 템플릿에서 상속됩니다.
- 프로덕션 워크플로우의 경우 각 템플릿의 안정 버전을 사용합니다. 안정 버전은 덜 자주 변경되며 주요 GitLab 버전 간에만 주요 변경 사항이 발생합니다. 최신 버전에는 가장 최근의 변경 사항이 포함되어 있지만 부 GitLab 버전 간에 중대한 변경 사항이 있을 수 있습니다.

### 템플릿 버전 {#template-editions}

GitLab 애플리케이션 보안 도구에는 최대 3가지 템플릿 버전이 있습니다:

- **안정**: 안정 템플릿이 기본입니다. 신뢰할 수 있고 일관된 애플리케이션 보안 환경을 제공합니다. 안정성과 CI/CD 파이프라인의 예측 가능한 동작이 필요한 대부분의 사용자 및 프로젝트에는 안정 템플릿을 사용해야 합니다.
- **최신**: 최신 템플릿은 최신 기능에 접근하고 테스트하려는 사용자를 위한 것입니다. 템플릿의 이름에서 `latest` 단어로 식별됩니다. 안정적이지 않으며 다음 주요 릴리스를 위해 계획된 주요 변경 사항이 포함될 수 있습니다. 이 템플릿을 사용하면 안정 릴리스의 일부가 되기 전에 새로운 기능과 업데이트를 시도할 수 있습니다.
- **버전 지정**: 버전이 지정된 템플릿은 안정 템플릿과 역호환 불가능한 주요 변경 사항을 소개합니다. 버전이 지정된 템플릿의 템플릿 이름에 버전 접미사(예: `v2`, `v3`)가 있습니다. 각 버전은 주 버전에서 안정적이지만 주요 변경 사항 때문에 채택을 선택해야 합니다. 종속성 검사만 버전이 지정된 템플릿(`Dependency-Scanning.v2.gitlab-ci.yml`)을 제공하며, 이는 [SBOM을 사용한 종속성 검사](../dependency_scanning/dependency_scanning_sbom/_index.md)를 실행합니다. 자세한 내용은 [마이그레이션 가이드](../dependency_scanning/migration_guide_to_sbom_based_scans.md)를 참조하세요.

> [!note]
> **안정** 및 **최신** 보안 템플릿을 동일한 프로젝트에서 혼합하지 마세요. 다양한 보안 템플릿 버전을 혼합하면 머지 리퀘스트 파이프라인과 브랜치 파이프라인이 모두 실행될 수 있습니다.

### 기본 레지스트리 기본 주소 재정의 {#override-the-default-registry-base-address}

기본적으로 GitLab 보안 스캐너는 `registry.gitlab.com/security-products`을 Docker 이미지의 기본 주소로 사용합니다. CI/CD 변수 `SECURE_ANALYZERS_PREFIX`을 다른 위치로 설정하여 대부분의 스캐너에 대해 이를 재정의할 수 있습니다. 이는 모든 스캐너에 한 번에 영향을 줍니다.

[컨테이너 스캔](../container_scanning/_index.md) 분석기는 예외이며 `SECURE_ANALYZERS_PREFIX` 변수를 사용하지 않습니다. Docker 이미지를 재정의하려면 [오프라인 환경에서 컨테이너 스캔 실행](../container_scanning/_index.md#offline-environment)에 대한 지침을 참조하세요.

### 머지 리퀘스트 파이프라인으로 보안 스캔 도구 사용 {#use-security-scanning-tools-with-merge-request-pipelines}

기본적으로 애플리케이션 보안 작업은 브랜치 파이프라인만 실행하도록 구성됩니다. 이를 [머지 리퀘스트 파이프라인](../../../ci/pipelines/merge_request_pipelines.md)과 함께 사용하려면 다음 중 하나를 수행하세요:

- CI/CD 변수 `AST_ENABLE_MR_PIPELINES`을 `"true"`로 설정합니다([18.0에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/410880)) (권장)
- [`latest` 버전 템플릿](#template-editions)을 사용합니다. 이는 기본적으로 머지 리퀘스트 파이프라인을 활성화합니다.

예를 들어 머지 리퀘스트 파이프라인을 활성화하여 SAST와 종속성 검사를 모두 실행하려면 다음 구성을 사용합니다:

```yaml
include:
  - template: Jobs/Dependency-Scanning.v2.gitlab-ci.yml
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  AST_ENABLE_MR_PIPELINES: "true"
```

### 사용자 정의 스캔 단계 사용 {#use-a-custom-scanning-stage}

보안 스캐너 템플릿은 기본적으로 사전 정의된 `test` 단계를 사용합니다. 대신 다른 단계에서 실행하려면 사용자 정의 단계의 이름을 `.gitlab-ci.yml` 파일의 `stages:` 섹션에 추가합니다.

보안 작업 재정의에 대한 자세한 내용은 다음을 참조하세요:

- [SAST 작업 재정의](../sast/_index.md#override-sast-jobs).
- [종속성 검사 작업 재정의](../dependency_scanning/dependency_scanning_sbom/_index.md#customizing-analyzer-behavior).
- [컨테이너 스캔 작업 재정의](../container_scanning/_index.md#overriding-the-container-scanning-template).
- [시크릿 검색 작업 재정의](../secret_detection/pipeline/configure.md).
- [DAST 작업 재정의](../dast/browser/_index.md).

## 문제 해결 {#troubleshooting}

보안 스캔을 구성할 때 다음과 같은 문제가 발생할 수 있습니다.

### 오류: `chosen stage test does not exist` {#error-chosen-stage-test-does-not-exist}

파이프라인을 실행할 때 `chosen stage test does not exist`이 나타나는 오류가 발생할 수 있습니다.

이 문제는 보안 스캔 작업에서 사용하는 단계가 `.gitlab-ci.yml` 파일에 선언되지 않았을 때 발생합니다.

이를 해결하려면 다음 중 하나를 수행하세요:

- `.gitlab-ci.yml`에서 `test` 단계를 추가합니다:

  ```yaml
  stages:
    - test
    - unit-tests

  include:
    - template: Jobs/Dependency-Scanning.v2.gitlab-ci.yml
    - template: Jobs/SAST.gitlab-ci.yml
    - template: Jobs/Secret-Detection.gitlab-ci.yml

  custom job:
    stage: unit-tests
    script:
      - echo "custom job"
  ```

- 각 보안 작업의 기본 단계를 재정의합니다. 예를 들어 `unit-tests` 이라는 사전 정의된 단계를 사용하려면:

  ```yaml
  stages:
    - unit-tests

  include:
    - template: Jobs/Dependency-Scanning.v2.gitlab-ci.yml
      inputs:
        stage: unit-tests
    - template: Jobs/SAST.gitlab-ci.yml
    - template: Jobs/Secret-Detection.gitlab-ci.yml

  sast:
    stage: unit-tests

  .secret-analyzer:
    stage: unit-tests

  custom job:
    stage: unit-tests
    script:
      - echo "custom job"
  ```
