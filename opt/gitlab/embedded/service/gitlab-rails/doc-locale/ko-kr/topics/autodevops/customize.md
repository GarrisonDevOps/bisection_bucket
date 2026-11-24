---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Auto DevOps 커스터마이징
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Auto DevOps 구성 요소를 커스터마이징하여 필요에 맞게 조정할 수 있습니다. 예를 들어 다음과 같이 할 수 있습니다:

- 사용자 정의 [buildpack](#custom-buildpacks), [Dockerfile](#custom-dockerfiles), [Helm 차트](#custom-helm-chart)를 추가합니다.
- 사용자 정의 [CI/CD 구성](#customize-gitlab-ciyml)으로 스테이징 및 카나리 배포를 활성화합니다.
- [GitLab API](#extend-auto-devops-with-the-api)로 Auto DevOps를 확장합니다.

## 사용자 정의 buildpack {#custom-buildpacks}

다음 중 한 경우에 buildpack을 커스터마이징할 수 있습니다:

- 프로젝트에 대해 자동 buildpack 감지가 실패합니다.
- 빌드를 더 잘 제어해야 합니다.

### Cloud Native Buildpack으로 buildpack 커스터마이징 {#customize-buildpacks-with-cloud-native-buildpacks}

다음 중 하나를 지정합니다:

- CI/CD 변수 `BUILDPACK_URL`을(를) [`pack`의 URI 사양 형식](https://buildpacks.io/docs/app-developer-guide/specify-buildpacks/) 중 하나와 함께 지정합니다.
- 포함할 buildpack이 있는 [`project.toml` 프로젝트 설명자](https://buildpacks.io/docs/app-developer-guide/using-project-descriptor/)를 지정합니다.

### 여러 buildpack {#multiple-buildpacks}

Auto Test가 `.buildpacks` 파일을 사용할 수 없으므로 Auto DevOps는 여러 buildpack을 지원하지 않습니다. 백엔드에서 `.buildpacks` 파일을 구문 분석하는 데 사용되는 buildpack [heroku-buildpack-multi](https://github.com/heroku/heroku-buildpack-multi/)는 필요한 명령 `bin/test-compile` 및 `bin/test`를 제공하지 않습니다.

단일 사용자 정의 buildpack만 사용하려면 프로젝트 CI/CD 변수 `BUILDPACK_URL`을(를) 대신 제공해야 합니다.

## 사용자 정의 Dockerfile {#custom-dockerfiles}

프로젝트 리포지토리의 루트에 Dockerfile이 있으면 Auto DevOps는 Dockerfile을 기반으로 Docker 이미지를 빌드합니다. 이는 buildpack을 사용하는 것보다 빠를 수 있습니다. 특히 Dockerfile이 [Alpine](https://hub.docker.com/_/alpine/)을(를) 기반으로 하는 경우 더 작은 이미지를 만들 수 있습니다.

`DOCKERFILE_PATH` CI/CD 변수를 설정하면 Auto Build가 대신 여기서 Dockerfile을 찾습니다.

### `docker build`에 인수 전달 {#pass-arguments-to-docker-build}

`docker build` 명령에 `AUTO_DEVOPS_BUILD_IMAGE_EXTRA_ARGS` 프로젝트 CI/CD 변수를 사용하여 인수를 전달할 수 있습니다.

예를 들어, 기본값 `ruby:latest` 대신 `ruby:alpine`을(를) 기반으로 Docker 이미지를 빌드하려면:

1. `AUTO_DEVOPS_BUILD_IMAGE_EXTRA_ARGS`을 `--build-arg=RUBY_VERSION=alpine`로 설정합니다.
1. 사용자 정의 Dockerfile에 다음을 추가합니다:

   ```dockerfile
   ARG RUBY_VERSION=latest
   FROM ruby:$RUBY_VERSION

   # Include your content here
   ```

공백과 줄 바꿈과 같은 복잡한 값을 전달하려면 Base64 인코딩을 사용합니다. 인코딩되지 않은 복잡한 값은 문자 이스케이프 문제를 발생시킬 수 있습니다.

> [!warning]
> Docker 빌드 인수로 비밀을 전달하지 마세요. 비밀이 이미지에 유지될 수 있습니다. 자세한 내용은 [비밀을 사용하는 모범 사례 논의](https://github.com/moby/moby/issues/13490)를 참조하세요.

## 사용자 정의 컨테이너 이미지 {#custom-container-image}

기본적으로 [Auto Deploy](stages.md#auto-deploy)는 [Auto Build](stages.md#auto-build)에 의해 GitLab 레지스트리에 빌드 및 푸시된 컨테이너 이미지를 배포합니다. 특정 변수를 정의하여 이 동작을 무시할 수 있습니다:

| 항목 | 기본값 | 재정의 가능한 항목 |
| ----- | -----   | -----    |
| 이미지 경로 | 브랜치 파이프라인의 경우 `$CI_REGISTRY_IMAGE/$CI_COMMIT_REF_SLUG`, 태그 파이프라인의 경우 `$CI_REGISTRY_IMAGE`. | `$CI_APPLICATION_REPOSITORY` |
| 이미지 태그 | 브랜치 파이프라인의 경우 `$CI_COMMIT_SHA`, 태그 파이프라인의 경우 `$CI_COMMIT_TAG`. | `$CI_APPLICATION_TAG` |

이러한 변수는 Auto Build 및 자동 컨테이너 스캔에도 영향을 줍니다. `$CI_APPLICATION_REPOSITORY:$CI_APPLICATION_TAG`에 이미지를 빌드 및 푸시하지 않으려면 `Jobs/Deploy.gitlab-ci.yml`만 포함하거나 [`build` 작업 건너뛰기](cicd_variables.md#job-skipping-variables)를 선택합니다.

자동 컨테이너 스캔을 사용하고 `$CI_APPLICATION_REPOSITORY`의 값을 설정하면 `$CS_DEFAULT_BRANCH_IMAGE`도 업데이트해야 합니다. 자세한 내용은 [기본 브랜치 이미지 설정](../../user/application_security/container_scanning/_index.md#setting-the-default-branch-image)을(를) 참조하세요.

다음은 `.gitlab-ci.yml`의 예제 설정입니다:

```yaml
variables:
  CI_APPLICATION_REPOSITORY: <your-image-repository>
  CI_APPLICATION_TAG: <the-tag>
```

## API로 Auto DevOps 확장 {#extend-auto-devops-with-the-api}

GitLab API를 사용하여 Auto DevOps 구성을 확장하고 관리할 수 있습니다:

- [API 호출을 사용하여 설정에 액세스](../../api/settings.md#available-settings)합니다. 여기에는 Auto DevOps를 프로젝트에서 기본적으로 활성화하는 `auto_devops_enabled`이(가) 포함됩니다.
- [새 프로젝트 생성](../../api/projects.md#create-a-project).
- [그룹 편집](../../api/groups.md#update-group-attributes).
- [프로젝트 편집](../../api/projects.md#update-a-project).

## 빌드 환경으로 CI/CD 변수 전달 {#forward-cicd-variables-to-the-build-environment}

CI/CD 변수를 빌드 환경으로 전달하려면 전달할 변수의 이름을 `AUTO_DEVOPS_BUILD_IMAGE_FORWARDED_CI_VARIABLES` CI/CD 변수에 추가합니다. 여러 변수는 쉼표로 구분합니다.

예를 들어, `CI_COMMIT_SHA` 및 `CI_ENVIRONMENT_NAME` 변수를 전달하려면:

```yaml
variables:
  AUTO_DEVOPS_BUILD_IMAGE_FORWARDED_CI_VARIABLES: CI_COMMIT_SHA,CI_ENVIRONMENT_NAME
```

buildpack을 사용하는 경우 전달된 변수는 환경 변수로 자동으로 사용 가능합니다.

Dockerfile을 사용하는 경우:

1. 실험적 Dockerfile 구문을 활성화하려면 Dockerfile에 다음을 추가합니다:

   ```dockerfile
   # syntax = docker/dockerfile:experimental
   ```

1. `Dockerfile`의 모든 `RUN $COMMAND`에서 비밀을 사용 가능하게 하려면 비밀 파일을 마운트하고 `$COMMAND`을(를) 실행하기 전에 소싱합니다:

   ```dockerfile
   RUN --mount=type=secret,id=auto-devops-build-secrets . /run/secrets/auto-devops-build-secrets && $COMMAND
   ```

`AUTO_DEVOPS_BUILD_IMAGE_FORWARDED_CI_VARIABLES`이(가) 설정되면 Auto DevOps는 `--secret` 플래그를 사용하기 위해 실험적 [Docker BuildKit](https://docs.docker.com/build/buildkit/) 기능을 활성화합니다.

## 사용자 정의 Helm 차트 {#custom-helm-chart}

Auto DevOps는 [Helm](https://helm.sh/)을(를) 사용하여 애플리케이션을 Kubernetes에 배포합니다. 프로젝트 리포지토리에 차트를 번들링하거나 프로젝트 CI/CD 변수를 지정하여 사용되는 Helm 차트를 무시할 수 있습니다:

- **번들 차트** \- 프로젝트에 `./chart` 디렉토리와 `Chart.yaml` 파일이 있으면 Auto DevOps가 차트를 감지하고 [기본 차트](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app) 대신 사용합니다.
- **프로젝트 변수** - [프로젝트 CI/CD 변수](../../ci/variables/_index.md) `AUTO_DEVOPS_CHART`을(를) 사용자 정의 차트의 URL로 생성합니다. 5개의 프로젝트 변수를 만들 수도 있습니다:

  - `AUTO_DEVOPS_CHART_REPOSITORY` - 사용자 정의 차트 리포지토리의 URL입니다.
  - `AUTO_DEVOPS_CHART` - 차트 경로입니다.
  - `AUTO_DEVOPS_CHART_REPOSITORY_INSECURE` - 비어 있지 않은 값으로 설정하여 Helm 명령에 `--insecure-skip-tls-verify` 인수를 추가합니다.
  - `AUTO_DEVOPS_CHART_CUSTOM_ONLY` - 비어 있지 않은 값으로 설정하여 사용자 정의 차트만 사용합니다. 기본적으로 최신 차트는 GitLab에서 다운로드됩니다.
  - `AUTO_DEVOPS_CHART_VERSION` - 배포 차트의 버전입니다.

### Helm 차트 값 커스터마이징 {#customize-helm-chart-values}

[기본 Helm 차트](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app)의 `values.yaml` 파일에서 기본값을 무시하려면 다음 중 하나를 수행합니다:

- 리포지토리에 `.gitlab/auto-deploy-values.yaml`이라는 파일을 추가합니다. 이 파일은 기본적으로 Helm 업그레이드에 사용됩니다.
- 리포지토리에 다른 이름이나 경로를 가진 파일을 추가합니다. `HELM_UPGRADE_VALUES_FILE` [CI/CD 변수](cicd_variables.md)를 파일의 경로 및 이름으로 설정합니다.

일부 값은 이전 옵션으로 무시할 수 없지만 [이 이슈](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/issues/31)는 이 동작을 변경할 것을 제안합니다. `replicaCount`과(와) 같은 설정을 무시하려면 `REPLICAS` [빌드 및 배포](cicd_variables.md#build-and-deployment-variables) CI/CD 변수를 사용합니다.

### `helm upgrade` 커스터마이징 {#customize-helm-upgrade}

[auto-deploy-image](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image)는 `helm upgrade` 명령을 사용합니다. 이 명령을 커스터마이징하려면 `HELM_UPGRADE_EXTRA_ARGS` CI/CD 변수를 사용하여 옵션을 전달합니다.

예를 들어 `helm upgrade`이(가) 실행될 때 업그레이드 전/후 후크를 비활성화하려면:

```yaml
variables:
  HELM_UPGRADE_EXTRA_ARGS: --no-hooks
```

옵션의 전체 목록은 [`helm upgrade` 공식 문서](https://helm.sh/docs/helm/helm_upgrade/)를 참조하세요.

### Helm 차트를 한 환경으로 제한 {#limit-a-helm-chart-to-one-environment}

사용자 정의 차트를 한 환경으로 제한하려면 CI/CD 변수에 환경 범위를 추가합니다. 자세한 내용은 [CI/CD 변수의 환경 범위 제한](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable)을(를) 참조하세요.

## `.gitlab-ci.yml` 커스터마이징 {#customize-gitlab-ciyml}

Auto DevOps는 [Auto DevOps 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Auto-DevOps.gitlab-ci.yml)이 `.gitlab-ci.yml` 파일의 구현이므로 고도로 커스터마이징할 수 있습니다. 템플릿은 `.gitlab-ci.yml`의 모든 구현에서 사용 가능한 기능만 사용합니다.

Auto DevOps에서 사용하는 CI/CD 파이프라인에 사용자 정의 동작을 추가하려면:

1. 리포지토리의 루트에 다음 내용이 포함된 `.gitlab-ci.yml` 파일을 추가합니다:

   ```yaml
   include:
     - template: Auto-DevOps.gitlab-ci.yml
   ```

1. `.gitlab-ci.yml` 파일에 변경 사항을 추가합니다. 변경 사항이 Auto DevOps 템플릿과 병합됩니다. `include`가 변경 사항을 병합하는 방식에 대한 자세한 내용은 [`include` 문서](../../ci/yaml/_index.md#include)를 참조하세요.

Auto DevOps 파이프라인에서 동작을 제거하려면:

1. [Auto DevOps 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Auto-DevOps.gitlab-ci.yml)을(를) 프로젝트에 복사합니다.
1. 필요에 따라 템플릿의 사본을 편집합니다.

### Auto DevOps의 개별 구성 요소 사용 {#use-individual-components-of-auto-devops}

Auto DevOps에서 제공하는 기능의 일부만 필요한 경우 자신의 `.gitlab-ci.yml`에 개별 Auto DevOps 작업을 포함할 수 있습니다. `.gitlab-ci.yml` 파일에서 각 작업에 필요한 스테이지를 정의하는 것을 잊지 마세요.

예를 들어 [Auto Build](stages.md#auto-build)를 사용하려면 `.gitlab-ci.yml`에 다음을 추가할 수 있습니다:

```yaml
stages:
  - build

include:
  - template: Jobs/Build.gitlab-ci.yml
```

사용 가능한 작업 목록은 [Auto DevOps 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Auto-DevOps.gitlab-ci.yml)을(를) 참조하세요.

## 여러 Kubernetes 클러스터 사용 {#use-multiple-kubernetes-clusters}

[Auto DevOps용 여러 Kubernetes 클러스터](multiple_clusters_auto_devops.md)를 참조하세요.

## Kubernetes 네임스페이스 커스터마이징 {#customizing-the-kubernetes-namespace}

이전에는 `environment:kubernetes:namespace`을(를) 사용하여 환경의 네임스페이스를 지정할 수 있었습니다. 하지만 이 기능은 [더 이상 사용되지 않으며](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) 인증서 기반 통합과 함께 제공됩니다.

이제 `KUBE_NAMESPACE` 환경 변수를 사용하고 [환경 범위를 제한](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable)해야 합니다.

## 로컬 Docker 레지스트리에서 호스팅되는 이미지 사용 {#use-images-hosted-in-a-local-docker-registry}

많은 Auto DevOps 작업을 [오프라인 환경](../../user/application_security/offline_deployments/_index.md)에서 실행하도록 구성할 수 있습니다:

1. 필요한 Auto DevOps Docker 이미지를 Docker Hub 및 `registry.gitlab.com`에서 로컬 GitLab 컨테이너 레지스트리로 복사합니다.
1. 이미지가 로컬 레지스트리에서 호스팅되고 사용 가능하면 `.gitlab-ci.yml`을(를) 편집하여 로컬로 호스팅된 이미지를 가리킵니다. 예를 들어:

   ```yaml
   include:
     - template: Auto-DevOps.gitlab-ci.yml

   variables:
     REGISTRY_URL: "registry.gitlab.example"

   build:
     image: "$REGISTRY_URL/docker/auto-build-image:v0.6.0"
     services:
       - name: "$REGISTRY_URL/greg/docker/docker:20.10.16-dind"
         command: ['--tls=false', '--host=tcp://0.0.0.0:2375']
   ```

## PostgreSQL 데이터베이스 지원 {#postgresql-database-support}

> [!warning]
> 기본적으로 PostgreSQL 데이터베이스를 프로비저닝하는 것은 [더 이상 사용되지 않으며](https://gitlab.com/gitlab-org/gitlab/-/issues/387766) 더 이상 기본값이 아닙니다. 데이터베이스 프로비저닝을 활성화하려면 관련된 [CI/CD 변수](cicd_variables.md#database-variables)를 설정합니다.

데이터베이스가 필요한 애플리케이션을 지원하기 위해 [PostgreSQL](https://www.postgresql.org/)이(가) 기본적으로 프로비저닝됩니다. 데이터베이스에 액세스하기 위한 자격 증명은 미리 구성되어 있습니다.

자격 증명을 커스터마이징하려면 관련된 [CI/CD 변수](cicd_variables.md)를 설정합니다. 사용자 정의 `DATABASE_URL`을(를) 정의할 수도 있습니다:

```yaml
postgres://user:password@postgres-host:postgres-port/postgres-database
```

### PostgreSQL 업그레이드 {#upgrading-postgresql}

GitLab은 기본적으로 PostgreSQL을 프로비저닝하기 위해 차트 버전 8.2.1을 사용합니다. 버전을 0.7.1에서 8.2.1로 설정할 수 있습니다.

이전 차트 버전을 사용하는 경우 [데이터베이스를 마이그레이션](upgrading_postgresql.md)하여 더 새로운 PostgreSQL로 이동해야 합니다.

기본 프로비저닝된 PostgreSQL을 제어하는 CI/CD 변수 `AUTO_DEVOPS_POSTGRES_CHANNEL`은(는) `2`로 설정됩니다. 이전 PostgreSQL을 사용하려면 `AUTO_DEVOPS_POSTGRES_CHANNEL` 변수를 `1`로 설정합니다.

### PostgreSQL Helm 차트의 값 커스터마이징 {#customize-values-for-postgresql-helm-chart}

사용자 정의 값을 설정하려면 다음 중 하나를 수행합니다:

- 리포지토리에 `.gitlab/auto-deploy-postgres-values.yaml`이라는 파일을 추가합니다. 발견되면 이 파일이 자동으로 사용됩니다. 이 파일은 기본적으로 PostgreSQL Helm 업그레이드에 사용됩니다.
- 리포지토리에 다른 이름이나 경로를 가진 파일을 추가하고 `POSTGRES_HELM_UPGRADE_VALUES_FILE` [환경 변수](cicd_variables.md#database-variables)를 경로 및 이름으로 설정합니다.
- `POSTGRES_HELM_UPGRADE_EXTRA_ARGS` [환경 변수](cicd_variables.md#database-variables)를 설정합니다.

### 외부 PostgreSQL 데이터베이스 제공자 사용 {#use-external-postgresql-database-providers}

Auto DevOps는 프로덕션 환경용 PostgreSQL 컨테이너를 기본으로 지원합니다. 하지만 AWS Relational Database Service와 같은 외부 관리형 제공자를 사용할 수 있습니다.

외부 관리형 제공자를 사용하려면:

1. 환경 범위 [CI/CD 변수](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable)를 사용하여 필요한 환경의 기본 제공 PostgreSQL 설치를 비활성화합니다. 검토 앱 및 스테이징용 기본 제공 PostgreSQL 설정이 충분하므로 `production`의 설치만 비활성화하면 될 수 있습니다.

   ![자동 메트릭](img/disable_postgres_v12_4.png)
1. `DATABASE_URL` 변수를 애플리케이션에서 사용 가능한 환경 범위 변수로 정의합니다. 이는 다음과 같은 형식의 URL이어야 합니다:

   ```yaml
   postgres://user:password@postgres-host:postgres-port/postgres-database
   ```

1. Kubernetes 클러스터가 PostgreSQL이 호스팅되는 위치에 네트워크 액세스할 수 있는지 확인합니다.
