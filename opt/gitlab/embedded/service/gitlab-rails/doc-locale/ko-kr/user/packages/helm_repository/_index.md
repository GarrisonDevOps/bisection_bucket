---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 패키지 레지스트리의 Helm 차트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

프로젝트의 패키지 레지스트리에 Helm 패키지를 게시합니다. 그런 다음 패키지를 종속성으로 사용해야 할 때마다 설치합니다.

Helm 패키지 관리자 클라이언트가 사용하는 특정 API 엔드포인트의 문서를 보려면 [Helm API 문서](../../../api/packages/helm.md)를 참조하세요.

## Helm 패키지 빌드 {#build-a-helm-package}

Helm 문서에서 다음 항목에 대해 자세히 알아보세요:

- [고유한 Helm 차트 생성](https://helm.sh/docs/intro/using_helm/#creating-your-own-charts)
- [Helm 차트를 차트 아카이브로 패키징](https://helm.sh/docs/helm/helm_package/#helm-package)

## Helm 리포지토리에 인증 {#authenticate-to-the-helm-repository}

Helm 리포지토리에 인증하려면 다음 중 하나가 필요합니다:

- [개인 액세스 토큰](../../profile/personal_access_tokens.md)(범위가 `api`(으)로 설정됨)
- [배포 토큰](../../project/deploy_tokens/_index.md)(범위가 `read_package_registry`, `write_package_registry` 또는 둘 다로 설정됨)
- [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)

## 패키지 게시 {#publish-a-package}

> [!note]
> 중복된 이름이나 버전으로 Helm 차트를 게시할 수 있습니다. 중복된 항목이 있는 경우, GitLab은 항상 최신 버전의 차트를 반환합니다.

빌드한 차트는 `curl` 또는 `helm cm-push`을(를) 사용하여 원하는 채널에 업로드할 수 있습니다:

- `curl`를 사용하면:

  ```shell
  curl --fail-with-body --request POST \
       --form 'chart=@mychart-0.1.0.tgz' \
       --user <username>:<access_token> \
       https://gitlab.example.com/api/v4/projects/<project_id>/packages/helm/api/<channel>/charts
  ```

  - `<username>`: GitLab 사용자 이름 또는 배포 토큰 사용자 이름
  - `<access_token>`: 개인 액세스 토큰 또는 배포 토큰
  - `<project_id>`: 프로젝트 ID(예: `42`) 또는 프로젝트의 [URL 인코딩](../../../api/rest/_index.md#namespaced-paths) 경로(예: `group%2Fproject`)
  - `<channel>`: 채널의 이름(예: `stable`)
- [`helm cm-push`](https://github.com/chartmuseum/helm-push/#readme) 플러그인 포함:

  ```shell
  helm repo add --username <username> --password <access_token> project-1 https://gitlab.example.com/api/v4/projects/<project_id>/packages/helm/<channel>
  helm cm-push mychart-0.1.0.tgz project-1
  ```

  - `<username>`: GitLab 사용자 이름 또는 배포 토큰 사용자 이름
  - `<access_token>`: 개인 액세스 토큰 또는 배포 토큰
  - `<project_id>`: 프로젝트 ID(예: `42`)
  - `<channel>`: 채널의 이름(예: `stable`)

### 릴리스 채널 {#release-channels}

GitLab에서 Helm 차트를 채널에 게시할 수 있습니다. 채널은 Helm 차트 리포지토리를 구분하는 데 사용할 수 있는 방법입니다. 예를 들어 `stable`과(와) `devel`를 채널로 사용하면 사용자가 `stable` 리포지토리를 추가하는 동안 `devel` 차트는 격리됩니다.

## CI/CD를 사용하여 Helm 패키지 게시 {#use-cicd-to-publish-a-helm-package}

[GitLab CI/CD](../../../ci/_index.md)를 통해 자동으로 Helm 패키지를 게시하려면, 명령에서 개인 액세스 토큰 대신 `CI_JOB_TOKEN`을(를) 사용할 수 있습니다.

예를 들어:

```yaml
stages:
  - upload

upload:
  image: curlimages/curl:latest
  stage: upload
  script:
    - 'curl --fail-with-body --request POST --user gitlab-ci-token:$CI_JOB_TOKEN --form "chart=@mychart-0.1.0.tgz" "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/helm/api/<channel>/charts"'
```

- `<username>`: GitLab 사용자 이름 또는 배포 토큰 사용자 이름
- `<access_token>`: 개인 액세스 토큰 또는 배포 토큰
- `<channel>`: 채널의 이름(예: `stable`)

## 패키지 설치 {#install-a-package}

> [!note]
> 각 패키지에 대해 가장 최근의 패키지 파일만 반환됩니다.

차트의 최신 버전을 설치하려면 다음 명령을 사용하세요:

```shell
helm repo add --username <username> --password <access_token> project-1 https://gitlab.example.com/api/v4/projects/<project_id>/packages/helm/<channel>
helm install my-release project-1/mychart
```

- `<username>`: GitLab 사용자 이름 또는 배포 토큰 사용자 이름
- `<access_token>`: 개인 액세스 토큰 또는 배포 토큰
- `<project_id>`: 프로젝트 ID(예: `42`)
- `<channel>`: 채널의 이름(예: `stable`)

리포지토리가 이전에 추가된 경우, 다음을 실행해야 할 수도 있습니다:

```shell
helm repo update
```

Helm 클라이언트를 가장 최근에 사용 가능한 차트로 업데이트합니다.

자세한 내용은 [Helm 사용](https://helm.sh/docs/intro/using_helm/)을(를) 참조하세요.

## Helm 패키지 삭제 {#delete-a-helm-package}

사전 요구 사항:

- 유지 관리자 또는 소유자 역할이 있어야 합니다.

패키지를 삭제하기 전에 [관련된 보안 위험](../package_registry/supported_functionality.md#deleting-packages)을(를) 이해해야 합니다.

패키지를 삭제하려면 다음 중 하나를 수행할 수 있습니다:

- [UI 사용](../package_registry/reduce_package_registry_storage.md#delete-a-package)
- [API 사용](../../../api/packages.md#delete-a-project-package)

## 문제 해결 {#troubleshooting}

### 업로드 후 차트가 패키지 레지스트리에 표시되지 않음 {#the-chart-is-not-visible-in-the-package-registry-after-uploading}

[Sidekiq 로그](../../../administration/logs/_index.md#sidekiqlog)에서 관련 오류를 확인하세요. `Validation failed: Version is invalid`이(가) 표시되면, `Chart.yaml` 파일의 버전이 [Helm 차트 버전 관리 사양](https://helm.sh/docs/topics/charts/#charts-and-versioning)을 따르지 않음을 의미합니다. 오류를 해결하려면 올바른 버전 구문을 사용하고 차트를 다시 업로드하세요.

### `helm push`으(로) 인해 오류 발생 {#helm-push-results-in-an-error}

Helm 3.7은 `helm-push` 플러그인에 대한 주요 변경 사항을 도입했습니다. [Chart Museum 플러그인](https://github.com/chartmuseum/helm-push/#readme)을(를) 업데이트하여 `helm cm-push`을(를) 사용할 수 있습니다.
