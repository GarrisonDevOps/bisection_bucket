---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 오프라인 환경
description: 오프라인 보안 검사 및 취약성 해결.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

> [!note]
> 오프라인 환경을 설정하려면 구매 전에 [클라우드 라이선싱의 옵트아웃 예외](https://about.gitlab.com/pricing/licensing-faq/cloud-licensing/#offline-cloud-licensing)를 받아야 합니다. 자세한 내용은 GitLab 영업 담당자에게 문의하세요.

인터넷에 연결되지 않았을 때 대부분의 GitLab 보안 스캐너를 실행할 수 있습니다.

이 문서에서는 오프라인 환경에서 보안 카테고리(즉, 스캐너 유형)를 운영하는 방법을 설명합니다. 이러한 지침은 보안이 설정되어 있거나 보안 정책(예: 방화벽 정책)을 가지고 있거나 전체 인터넷 액세스가 제한된 GitLab Self-Managed 인스턴스에도 적용됩니다. GitLab은 이러한 환경을 _오프라인 환경_이라고 부릅니다. 기타 일반적인 명칭은 다음과 같습니다:

- 에어갭 환경
- 제한된 연결 환경
- 근거리 네트워크(LAN) 환경
- 인트라넷 환경

이러한 환경은 인터넷 액세스를 방지하거나 제한하는 물리적 장벽 또는 보안 정책(예: 방화벽)을 가지고 있습니다. 이러한 지침은 물리적으로 연결이 끊긴 네트워크를 위해 설계되었지만 다른 사용 사례에도 적용할 수 있습니다.

## 오프라인 환경 정의 {#defining-offline-environments}

오프라인 환경에서 GitLab 인스턴스는 로컬 네트워크에서 통신할 수 있지만 인터넷에 액세스할 수 없거나 매우 제한된 하나 이상의 서버 및 서비스입니다. GitLab 인스턴스 및 지원 인프라(예: 개인 Maven 리포지토리)의 모든 항목은 로컬 네트워크 연결을 통해 액세스할 수 있다고 가정하세요. 인터넷의 모든 파일은 물리적 미디어(USB 드라이브, 하드 드라이브, 쓰기 가능한 DVD 등)를 통해 들어온다고 가정하세요.

## 오프라인 스캐너 사용 {#use-offline-scanners}

GitLab 스캐너는 일반적으로 인터넷에 연결하여 최신 서명, 규칙 및 패치 세트를 다운로드합니다. 로컬 네트워크에서 사용 가능한 리소스를 사용하여 도구가 제대로 작동하도록 구성하기 위해 몇 가지 추가 단계가 필요합니다.

### 컨테이너 레지스트리 및 패키지 리포지토리 {#container-registries-and-package-repositories}

높은 수준에서 보안 분석기는 Docker 이미지로 전달되며 다양한 패키지 리포지토리를 활용할 수 있습니다. 인터넷에 연결된 GitLab 설치에서 작업을 실행하면 GitLab은 GitLab.com에서 호스팅하는 컨테이너 레지스트리를 확인하여 이러한 Docker 이미지의 최신 버전을 가지고 있는지 확인하고 패키지 리포지토리에 연결하여 필요한 종속성을 설치할 수 있습니다.

오프라인 환경에서는 GitLab.com이 쿼리되지 않도록 이러한 확인을 비활성화해야 합니다. GitLab.com 레지스트리 및 리포지토리를 사용할 수 없으므로 각 스캐너를 업데이트하여 다른 내부 호스팅 레지스트리를 참조하거나 개별 스캐너 이미지에 대한 액세스를 제공해야 합니다.

또한 GitLab.com에서 호스팅하지 않는 npm, yarn 또는 Ruby gems와 같은 일반적인 패키지 리포지토리에 앱이 액세스할 수 있는지 확인해야 합니다. 이러한 리포지토리의 패키지는 일시적으로 네트워크에 연결하거나 자신의 오프라인 네트워크 내에서 패키지를 미러링하여 얻을 수 있습니다.

### 취약성과의 상호 작용 {#interacting-with-the-vulnerabilities}

취약성이 발견되면 이와 상호 작용할 수 있습니다. [취약성을 해결하는](../vulnerabilities/_index.md) 방법에 대해 자세히 알아보세요.

경우에 따라 보고된 취약성은 UI에 표시되는 외부 링크를 포함할 수 있는 메타데이터를 제공합니다. 이러한 링크는 오프라인 환경 내에서 액세스하지 못할 수 있습니다.

### 취약성 해결 {#resolving-vulnerabilities}

[취약성 해결](../vulnerabilities/_index.md#resolve-a-vulnerability) 기능은 오프라인 종속성 검사 및 컨테이너 검사에 사용할 수 있지만 인스턴스 구성에 따라 작동하지 않을 수 있습니다. GitLab은 최신 버전의 종속성 또는 이미지를 호스팅하는 최신 레지스트리 서비스에 액세스할 수 있을 때만 솔루션(일반적으로 최신의 패치된 버전)을 제시할 수 있습니다.

### 스캐너 서명 및 규칙 업데이트 {#scanner-signature-and-rule-updates}

인터넷에 연결되면 일부 스캐너는 확인할 최신 서명 및 규칙 세트에 대해 공개 데이터베이스를 참조합니다. 연결이 없으면 이는 불가능합니다. 스캐너에 따라 이러한 자동 업데이트 확인을 비활성화하고 함께 제공되는 데이터베이스를 사용하고 해당 데이터베이스를 수동으로 업데이트하거나 네트워크 내에서 호스팅하는 자신의 복사본에 대한 액세스를 제공해야 합니다.

## 특정 스캐너 지침 {#specific-scanner-instructions}

각 개별 스캐너는 이전에 설명한 단계와 약간 다를 수 있습니다. 아래 페이지에서 자세한 정보를 찾을 수 있습니다:

- [컨테이너 검사 오프라인 지침](../container_scanning/_index.md#offline-environment)
- [SAST 오프라인 지침](../sast/_index.md#running-sast-in-an-offline-environment)
- [시크릿 검색 오프라인 지침](../secret_detection/pipeline/configure.md#offline-configuration)
- [DAST 오프라인 지침](../dast/browser/configuration/offline_configuration.md)
- [API 퍼징 오프라인 지침](../api_fuzzing/configuration/offline_configuration.md)
- [라이선스 스캔 오프라인 지침](../../compliance/license_scanning_of_cyclonedx_files/_index.md#running-in-an-offline-environment)
- [종속성 검사 오프라인 지침](../dependency_scanning/dependency_scanning_sbom/_index.md#offline-environment)
- [IaC 검사 오프라인 지침](../iac_scanning/_index.md#offline-configuration)

### 패키지 메타데이터 데이터베이스 {#package-metadata-database}

[종속성 검사](../dependency_scanning/_index.md) 및 [지속적 취약성 검사](../continuous_vulnerability_scanning/_index.md)는 라이선스, 권고 및 취약성 위험 평가 데이터에 대해 패키지 메타데이터 데이터베이스를 읽습니다. 이 데이터베이스는 분석기 이미지가 아닌 데이터 아티팩트이므로 분석기 이미지를 로드해도 이 데이터베이스는 제공되지 않습니다. 내보내기를 복사할 때까지 오프라인 인스턴스에는 아무것도 없습니다.

절차는 [패키지 메타데이터 데이터베이스 활성화](../../../topics/offline/quick_start_guide.md#enabling-the-package-metadata-database)를 참조하세요.

## 오프라인 호스트로 Docker 이미지 로드 {#loading-docker-images-onto-your-offline-host}

보안 스캔 및 [Auto DevOps](../../../topics/autodevops/_index.md)를 포함한 많은 GitLab 기능을 사용하려면 러너가 관련 Docker 이미지를 가져올 수 있어야 합니다.

공용 인터넷에 직접 액세스하지 않고 이러한 이미지를 사용 가능하게 하는 프로세스는 이미지를 다운로드한 다음 오프라인 호스트로 패키징하고 전송하는 것입니다. 다음은 이러한 전송의 예입니다:

1. 공용 인터넷에서 Docker 이미지를 다운로드합니다.
1. Docker 이미지를 tar 아카이브로 패키징합니다.
1. 이미지를 오프라인 환경으로 전송합니다.
1. 전송된 이미지를 오프라인 Docker 레지스트리로 로드합니다.

### 공식 GitLab 템플릿 사용 {#using-the-official-gitlab-template}

GitLab은 이 프로세스를 쉽게 하기 위해 [벤더링된 템플릿](../../../ci/yaml/_index.md#includetemplate)을 제공합니다.

이 템플릿은 새 빈 프로젝트에서 `.gitlab-ci.yml` 파일을 포함하여 사용해야 합니다:

```yaml
include:
  - template: Security/Secure-Binaries.gitlab-ci.yml
```

파이프라인은 보안 스캐너에 필요한 Docker 이미지를 다운로드하고 [작업 아티팩트](../../../ci/jobs/job_artifacts.md)로 저장하거나 파이프라인이 실행되는 프로젝트의 [컨테이너 레지스트리](../../packages/container_registry/_index.md)로 푸시합니다. 이러한 아카이브를 다른 위치로 전송하고 Docker 데몬에서 [로드](https://docs.docker.com/reference/cli/docker/image/load/)할 수 있습니다. 이 방법을 사용하려면 `gitlab.com`(포함 `registry.gitlab.com`) 및 로컬 오프라인 인스턴스 모두에 액세스할 수 있는 러너가 필요합니다. 이 러너는 작업 내에서 `docker` 명령을 사용할 수 있도록 [특권 모드](https://docs.gitlab.com/runner/executors/docker/#use-docker-in-docker-with-privileged-mode)에서 실행해야 합니다. 이 러너는 DMZ 또는 배스천에 설치할 수 있으며 이 특정 프로젝트에만 사용할 수 있습니다.

> [!warning]
> 이 템플릿에는 컨테이너 스캐닝 분석기의 업데이트가 포함되지 않습니다. [컨테이너 검사 오프라인 지침](../container_scanning/_index.md#offline-environment)을 참조하세요.

#### 업데이트 예약 {#scheduling-the-updates}

기본적으로 이 프로젝트의 파이프라인은 `.gitlab-ci.yml`이 리포지토리에 추가될 때 한 번만 실행됩니다. GitLab 보안 스캐너 및 서명을 업데이트하려면 이 파이프라인을 정기적으로 실행해야 합니다. GitLab은 [파이프라인 예약](../../../ci/pipelines/schedules.md)하는 방법을 제공합니다. 예를 들어 매주 Docker 이미지를 다운로드하고 저장하도록 설정할 수 있습니다.

#### 생성된 보안 번들 사용 {#using-the-secure-bundle-created}

`Secure-Binaries.gitlab-ci.yml` 템플릿을 사용하는 프로젝트는 이제 GitLab 보안 기능을 실행하는 데 필요한 모든 필수 이미지 및 리소스를 호스팅해야 합니다.

다음으로 오프라인 인스턴스에 GitLab.com의 기본값 대신 이러한 리소스를 사용하도록 지시해야 합니다. 이렇게 하려면 CI/CD 변수 `SECURE_ANALYZERS_PREFIX`을 프로젝트 [컨테이너 레지스트리](../../packages/container_registry/_index.md)의 URL로 설정합니다.

프로젝트의 `.gitlab-ci.yml`에서 이 변수를 설정하거나 프로젝트 또는 그룹의 GitLab UI에서 설정할 수 있습니다. 자세한 내용은 [GitLab CI/CD 변수 페이지](../../../ci/variables/_index.md#define-a-cicd-variable-in-the-ui)를 참조하세요.

#### 변수 {#variables}

다음 표는 `Secure-Binaries.gitlab-ci.yml` 템플릿과 함께 사용할 수 있는 CI/CD 변수를 보여줍니다:

| CI/CD 변수                            | 설명                                   | 기본값                     |
|-------------------------------------------|-----------------------------------------------|-----------------------------------|
| `SECURE_BINARIES_ANALYZERS`               | 다운로드할 분석기의 쉼표로 구분된 목록 | `"bandit, brakeman, gosec, ..."` |
| `SECURE_BINARIES_DOWNLOAD_IMAGES`         | 작업을 비활성화하는 데 사용됨                          | `"true"`                          |
| `SECURE_BINARIES_PUSH_IMAGES`             | 프로젝트 레지스트리에 파일 푸시            | `"true"`                          |
| `SECURE_BINARIES_SAVE_ARTIFACTS`          | 이미지 아카이브를 아티팩트로도 저장         | `"false"`                         |
| `SECURE_BINARIES_ANALYZER_VERSION`        | 기본 분석기 버전(Docker 태그)         | `"2"`                             |

### 공식 템플릿 없이 대체 방법 {#alternate-way-without-the-official-template}

이전 방법을 따르는 것이 불가능한 경우 이미지를 대신 수동으로 전송할 수 있습니다:

#### 예제 이미지 패키저 스크립트 {#example-image-packager-script}

```shell
#!/bin/bash
set -ux

# Specify needed analyzer images
analyzers=${SAST_ANALYZERS:-"bandit eslint gosec"}
gitlab=registry.gitlab.com/security-products/

for i in "${analyzers[@]}"
do
  tarname="${i}_2.tar"
  docker pull $gitlab$i:2
  docker save $gitlab$i:2 -o ./analyzers/${tarname}
  chmod +r ./analyzers/${tarname}
done
```

#### 예제 이미지 로더 스크립트 {#example-image-loader-script}

이 예제는 배스천 호스트에서 오프라인 호스트로 이미지를 로드합니다. 특정 구성에서는 이러한 전송에 물리적 미디어가 필요할 수 있습니다:

```shell
#!/bin/bash
set -ux

# Specify needed analyzer images
analyzers=${SAST_ANALYZERS:-"bandit eslint gosec"}
registry=$GITLAB_HOST:4567

for i in "${analyzers[@]}"
do
  tarname="${i}_2.tar"
  scp ./analyzers/${tarname} ${GITLAB_HOST}:~/${tarname}
  ssh $GITLAB_HOST "sudo docker load -i ${tarname}"
  ssh $GITLAB_HOST "sudo docker tag $(sudo docker images | grep $i | awk '{print $3}') ${registry}/analyzers/${i}:2"
  ssh $GITLAB_HOST "sudo docker push ${registry}/analyzers/${i}:2"
done
```

### 오프라인 환경에서 GitLab Secure와 AutoDevOps 사용 {#using-gitlab-secure-with-autodevops-in-an-offline-environment}

오프라인 환경에서 GitLab AutoDevOps를 Secure 스캔에 사용할 수 있습니다. 그러나 먼저 다음 단계를 수행해야 합니다:

1. 컨테이너 이미지를 로컬 레지스트리로 로드합니다. GitLab Secure는 분석기 컨테이너 이미지를 활용하여 다양한 스캔을 수행합니다. 이러한 이미지는 AutoDevOps 실행의 일부로 사용 가능해야 합니다. AutoDevOps를 실행하기 전에 [공식 GitLab 템플릿](#using-the-official-gitlab-template)의 단계를 따라 해당 컨테이너 이미지를 로컬 컨테이너 레지스트리로 로드하세요.

1. AutoDevOps가 이러한 이미지에 대해 올바른 위치를 보도록 CI/CD 변수를 설정합니다. AutoDevOps 템플릿은 `SECURE_ANALYZERS_PREFIX` 변수를 활용하여 분석기 이미지의 위치를 식별합니다. 자세한 내용은 [생성된 보안 번들 사용](#using-the-secure-bundle-created)을 참조하세요. 분석기 이미지를 로드한 위치에 대해 이 변수를 올바른 값으로 설정했는지 확인하세요. 프로젝트 CI/CD 변수로 이 작업을 수행하거나 `.gitlab-ci.yml` 파일을 직접 [수정](../../../topics/autodevops/customize.md#customize-gitlab-ciyml)하는 것을 고려할 수 있습니다.

이러한 단계가 완료되면 GitLab에는 Secure 분석기의 로컬 복사본이 있으며 인터넷 호스팅 컨테이너 이미지 대신 사용하도록 설정되었습니다. 이를 통해 오프라인 환경에서 AutoDevOps에서 Secure를 실행할 수 있습니다.

이 단계는 GitLab Secure와 AutoDevOps에만 해당됩니다. AutoDevOps와 함께 다른 스테이지를 사용하면 [Auto DevOps 설명서](../../../topics/autodevops/_index.md)에서 다루는 다른 단계가 필요할 수 있습니다.
