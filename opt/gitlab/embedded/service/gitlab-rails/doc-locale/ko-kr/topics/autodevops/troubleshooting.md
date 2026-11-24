---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Auto DevOps 문제 해결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 설명서 페이지는 Auto DevOps 사용 시 발생하는 일반적인 오류와 사용 가능한 해결 방법을 설명합니다.

## Helm 명령 추적 {#trace-helm-commands}

CI/CD 변수 `TRACE`을(를) 임의의 값으로 설정하여 Helm 명령이 상세한 출력을 생성하도록 합니다. 이 출력을 사용하여 Auto DevOps 배포 문제를 진단할 수 있습니다.

고급 Auto DevOps 구성 변수를 변경하여 Auto DevOps 배포의 일부 문제를 해결할 수 있습니다. [Auto DevOps CI/CD 변수 사용자 지정](cicd_variables.md)에 대해 자세히 알아보세요.

## 빌드팩을 선택할 수 없음 {#unable-to-select-a-buildpack}

Auto Test는 다음 오류로 언어 또는 프레임워크를 감지하지 못할 수 있습니다:

```plaintext
Step 5/11 : RUN /bin/herokuish buildpack build
 ---> Running in eb468cd46085
    -----> Unable to select a buildpack
The command '/bin/sh -c /bin/herokuish buildpack build' returned a non-zero code: 1
```

다음은 가능한 이유입니다:

- 애플리케이션에 빌드팩이 찾고 있는 주요 파일이 없을 수 있습니다. Ruby 애플리케이션은 제대로 감지되려면 `Gemfile`이(가) 필요하지만, `Gemfile` 없이도 Ruby 앱을 작성할 수 있습니다.
- 애플리케이션에 빌드팩이 없을 수 있습니다. [사용자 지정 빌드팩](customize.md#custom-buildpacks)을 지정해 보세요.

## 빌더 종료 오류 {#builder-sunset-error}

이 [Heroku 업데이트](https://github.com/heroku/cnb-builder-images/pull/478)로 인해 레거시 shimmed `heroku/buildpacks:20` 및 `heroku/builder-classic:22` 이미지는 이제 경고 대신 오류를 생성합니다.

이 문제를 해결하려면 `heroku/builder:*` 빌더 이미지로 마이그레이션해야 합니다. 임시 해결 방법으로, 오류를 건너뛰도록 환경 변수를 설정할 수도 있습니다.

### `heroku/builder:*`로 마이그레이션 {#migrating-to-herokubuilder}

마이그레이션하기 전에 잠재적 주요 변경 사항을 확인하기 위해 각 [사양 릴리스](https://github.com/buildpacks/spec/releases)에 대한 릴리스 정보를 읽어야 합니다. 이 경우 관련 빌드팩 API 버전은 0.6 및 0.7입니다. 이러한 주요 변경 사항은 빌드팩 유지자에게 특히 관련이 있습니다.

변경 사항에 대한 자세한 정보는 [사양 자체](https://github.com/buildpacks/spec/compare/buildpack/v0.5...buildpack/v0.7#files_bucket)를 diff할 수도 있습니다.

### 오류 건너뛰기 {#skipping-errors}

임시 해결 방법으로, `ALLOW_EOL_SHIMMED_BUILDER` 환경 변수를 설정 및 전달하여 오류를 건너뛸 수 있습니다:

```yaml
  variables:
    ALLOW_EOL_SHIMMED_BUILDER: "1"
    AUTO_DEVOPS_BUILD_IMAGE_FORWARDED_CI_VARIABLES: ALLOW_EOL_SHIMMED_BUILDER
```

## only / except만 사용하여 Auto DevOps를 확장하는 파이프라인이 실패함 {#pipeline-that-extends-auto-devops-with-only--except-fails}

파이프라인이 다음 메시지로 실패하면:

```plaintext
Unable to run pipeline

  jobs:test config key may not be used with `rules`: only
```

포함된 작업의 규칙 구성이 `only` 또는 `except` 구문으로 재정의되었을 때 이 오류가 나타납니다. 이 문제를 해결하려면 `only/except` 구문을 규칙으로 전환해야 합니다.

## Kubernetes 네임스페이스를 만드는 데 실패함 {#failure-to-create-a-kubernetes-namespace}

GitLab이 프로젝트에 대한 Kubernetes 네임스페이스 및 서비스 계정을 만들 수 없으면 Auto Deploy가 실패합니다. 이 문제 디버깅에 대한 도움은 [배포 작업 실패 문제 해결](../../user/project/clusters/deploy_to_cluster.md#troubleshooting)을 참조하세요.

## Auto DevOps가 프로젝트에 대해 자동으로 비활성화됨 {#auto-devops-is-automatically-disabled-for-a-project}

Auto DevOps가 프로젝트에 대해 자동으로 비활성화되면 다음과 같은 이유일 수 있습니다:

- Auto DevOps 설정이 [프로젝트](_index.md#per-project) 자체에서 명시적으로 활성화되지 않았습니다. 부모 [그룹](_index.md#per-group) 또는 해당 [인스턴스](../../administration/settings/continuous_integration.md#configure-auto-devops-for-all-projects)에서만 활성화되어 있습니다.
- 프로젝트에 성공한 Auto DevOps 파이프라인의 기록이 없습니다.
- Auto DevOps 파이프라인이 실패했습니다.

이 이슈를 해결하려면:

- 프로젝트에서 Auto DevOps 설정을 활성화합니다.
- 파이프라인이 다시 실행되도록 파이프라인을 중단하는 오류를 수정합니다.

## 오류: `unable to recognize "": no matches for kind "Deployment" in version "extensions/v1beta1"` {#error-unable-to-recognize--no-matches-for-kind-deployment-in-version-extensionsv1beta1}

Kubernetes 클러스터를 [v1.16+](stages.md#kubernetes-116)로 업그레이드한 후 Auto DevOps를 사용하여 배포할 때 이 메시지가 나타날 수 있습니다:

```plaintext
UPGRADE FAILED
Error: failed decoding reader into objects: unable to recognize "": no matches for kind "Deployment" in version "extensions/v1beta1"
```

환경 네임스페이스의 현재 배포가 Kubernetes v1.16+에 없는 더 이상 사용되지 않거나 제거된 API로 배포된 경우 이 문제가 발생할 수 있습니다.

이러한 오래된 리소스를 복구하려면 레거시 API를 최신 API로 매핑하여 현재 배포를 변환해야 합니다.

## `Error: not a valid chart repository or cannot be reached` {#error-not-a-valid-chart-repository-or-cannot-be-reached}

[공식 CNCF 블로그 게시물에 공지된 대로](https://www.cncf.io/blog/2020/10/07/important-reminder-for-all-helm-users-stable-incubator-repos-are-deprecated-and-all-images-are-changing-location/), 안정적인 Helm 차트 리포지토리는 2020년 11월 13일에 더 이상 사용되지 않으며 제거되었습니다. 그 이후 이 오류가 발생할 수 있습니다:

```plaintext
Error: error initializing: Looks like "https://kubernetes-charts.storage.googleapis.com"
is not a valid chart repository or cannot be reached
```

일부 GitLab 기능은 안정적인 차트에 대한 종속성이 있었습니다. 영향을 완화하기 위해 종속성은 새로운 공식 리포지토리 또는 [GitLab에서 유지보수하는 Helm 안정 아카이브 리포지토리](https://gitlab.com/gitlab-org/cluster-integration/helm-stable-archive)를 사용합니다. Auto Deploy에 [예제 수정](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/merge_requests/127)이 포함되어 있습니다.

Auto Deploy에서 `auto-deploy-image`의 `v1.0.6+`는 더 이상 사용되지 않는 안정적인 리포지토리를 `helm` 명령에 추가하지 않습니다. 사용자 지정 차트를 사용하고 더 이상 사용되지 않는 안정적인 리포지토리에 의존하는 경우 다음과 같이 이전 `auto-deploy-image`을(를) 지정합니다:

```yaml
include:
  - template: Auto-DevOps.gitlab-ci.yml

.auto-deploy:
  image: "registry.gitlab.com/gitlab-org/cluster-integration/auto-deploy-image:v1.0.5"
```

안정적인 리포지토리가 제거될 때 이 방법이 작동을 멈추므로 결국 사용자 지정 차트를 수정해야 합니다.

사용자 지정 차트를 수정하려면:

1. 차트 디렉토리에서 `requirements.yaml` 파일의 `repository` 값을 다음에서 업데이트합니다:

   ```yaml
   repository: "https://kubernetes-charts.storage.googleapis.com/"
   ```

   다음으로:

   ```yaml
   repository: "https://charts.helm.sh/stable"
   ```

1. 차트 디렉토리에서 Auto DevOps와 동일한 Helm 주 버전을 사용하여 `helm dep update .`을(를) 실행합니다.
1. `requirements.yaml` 파일에 대한 변경 사항을 커밋합니다.
1. 이전에 `requirements.lock` 파일이 있었던 경우 파일에 대한 변경 사항을 커밋합니다. 이전에 차트에 `requirements.lock` 파일이 없었던 경우 새 파일을 커밋할 필요가 없습니다. 이 파일은 선택 사항이지만 있을 때 다운로드된 종속성의 무결성을 확인하는 데 사용됩니다.

[이슈 #263778, "안정적인 Helm 리포지토리에서 PostgreSQL 마이그레이션"](https://gitlab.com/gitlab-org/gitlab/-/issues/263778)에서 자세한 정보를 찾을 수 있습니다.

## `Error: release .... failed: timed out waiting for the condition` {#error-release--failed-timed-out-waiting-for-the-condition}

Auto DevOps를 시작할 때 처음 애플리케이션을 배포할 때 이 오류가 발생할 수 있습니다:

```plaintext
INSTALL FAILED
PURGING CHART
Error: release staging failed: timed out waiting for the condition
```

이는 배포 프로세스 중에 시도된 실패한 생존성(또는 준비) 프로브로 인해 가장 가능성이 높습니다. 기본적으로 이러한 프로브는 포트 5000의 배포된 애플리케이션의 루트 페이지에 대해 실행됩니다. 애플리케이션이 루트 페이지에서 아무것도 제공하지 않도록 구성되어 있거나 5000 *이외의* 특정 포트에서 실행되도록 구성된 경우 이 확인이 실패합니다.

실패하면 관련 Kubernetes 네임스페이스의 이벤트에서 이러한 실패를 확인할 수 있습니다. 이러한 이벤트는 다음과 같은 예를 보입니다:

```plaintext
LAST SEEN   TYPE      REASON                   OBJECT                                            MESSAGE
3m20s       Warning   Unhealthy                pod/staging-85db88dcb6-rxd6g                      Readiness probe failed: Get http://10.192.0.6:5000/: dial tcp 10.192.0.6:5000: connect: connection refused
3m32s       Warning   Unhealthy                pod/staging-85db88dcb6-rxd6g                      Liveness probe failed: Get http://10.192.0.6:5000/: dial tcp 10.192.0.6:5000: connect: connection refused
```

Auto DevOps에서 사용하는 생존성 확인에 사용되는 포트를 변경하려면 [Helm 차트에 사용자 지정 값을 전달](customize.md#customize-helm-chart-values)합니다:

1. `.gitlab/auto-deploy-values.yaml` 이름으로 리포지토리의 루트에 디렉토리 및 파일을 만듭니다.
1. 파일을 다음 콘텐츠로 채우고 포트 값을 애플리케이션이 사용하도록 구성된 실제 포트 번호로 바꿉니다:

   ```yaml
   service:
     internalPort: <port_value>
     externalPort: <port_value>
   ```

1. 변경 사항을 커밋합니다.

변경 사항을 커밋한 후 후속 프로브는 새로 정의된 포트를 사용해야 합니다. 프로브되는 페이지는 `livenessProbe.path` 및 `readinessProbe.path` 값을 재정의하여 변경할 수도 있습니다([기본 `values.yaml`](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/blob/master/assets/auto-deploy-app/values.yaml) 파일에 표시됨).
