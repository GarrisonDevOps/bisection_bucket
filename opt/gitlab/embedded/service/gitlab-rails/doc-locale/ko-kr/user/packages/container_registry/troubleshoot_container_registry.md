---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 컨테이너 레지스트리 문제 해결
description: GitLab 컨테이너 레지스트리의 일반적인 오류를 문제 해결하기 위한 팁입니다.
---

GitLab 컨테이너 레지스트리 관련 대부분의 문제를 해결하려면 관리자 권한으로 GitLab에 로그인해야 합니다.

GitLab 컨테이너 레지스트리 관리 문서에서 [추가 문제 해결 정보](../../../administration/packages/container_registry_troubleshooting.md)를 찾을 수 있습니다.

## OCI 컨테이너 이미지를 GitLab 컨테이너 레지스트리로 마이그레이션 {#migrating-oci-container-images-to-gitlab-container-registry}

GitLab 레지스트리로의 컨테이너 이미지 마이그레이션은 지원되지 않지만, [에픽 5210](https://gitlab.com/groups/gitlab-org/-/epics/5210)에서 이 동작을 변경할 것을 제안합니다.

타사 도구를 사용하여 컨테이너 이미지를 마이그레이션할 수 있습니다. 예를 들어, [skopeo](https://github.com/containers/skopeo)는 [컨테이너 이미지를 복사](https://github.com/containers/skopeo#copying-images)할 수 있으므로 다양한 저장 메커니즘 간에 사용할 수 있습니다. skopeo를 사용하여 컨테이너 레지스트리, 컨테이너 저장소 백엔드, 로컬 디렉터리 및 로컬 OCI 레이아웃 디렉터리에서 GitLab 컨테이너 레지스트리로 복사할 수 있습니다.

## Docker 연결 오류 {#docker-connection-error}

그룹, 프로젝트 또는 브랜치 이름에 특수 문자가 포함되어 있으면 Docker 연결 오류가 발생할 수 있습니다. 특수 문자는 다음을 포함합니다:

- 앞에 밑줄이 있는 경우입니다.
- 뒤에 하이픈 또는 대시가 있는 경우입니다.

이 오류를 해결하려면 [그룹 경로](../../group/manage.md#change-a-groups-path), [프로젝트 경로](../../project/working_with_projects.md#rename-a-repository) 또는 브랜치 이름을 변경할 수 있습니다.

Docker Engine 17.11 이하를 사용하면 `404 Not Found` 또는 `Unknown Manifest` 오류 메시지가 표시될 수 있습니다. 현재 버전의 Docker Engine은 [v2 API](https://distribution.github.io/distribution/spec/manifest-v2-2/)를 사용합니다.

GitLab 컨테이너 레지스트리의 이미지는 Docker v2 API를 사용해야 합니다. 버전 1 이미지를 버전 2로 업데이트하는 방법에 대한 자세한 내용은 [Docker 문서](https://distribution.github.io/distribution/spec/deprecated-schema-v1/)를 참조하세요.

## `Blob unknown to registry` 오류(매니페스트 목록 푸시 시) {#blob-unknown-to-registry-error-when-pushing-a-manifest-list}

[Docker 매니페스트 목록을 푸시](https://docs.docker.com/reference/cli/docker/manifest/#create-and-push-a-manifest-list)할 때 GitLab 컨테이너 레지스트리에 `manifest blob unknown: blob unknown to registry` 오류가 표시될 수 있습니다. 이 오류는 여러 이미지가 동일한 리포지토리 대신 여러 리포지토리에 분산되어 있고 아키텍처가 다를 때 발생할 가능성이 높습니다.

예를 들어, 아키텍처를 나타내는 두 개의 이미지가 있을 수 있습니다:

- `amd64` 플랫폼입니다.
- `arm64v8` 플랫폼입니다.

이러한 이미지로 멀티 아키텍처 이미지를 빌드하려면 이 이미지들을 멀티 아키텍처 이미지와 동일한 리포지토리로 푸시해야 합니다.

`Blob unknown to registry` 오류를 해결하려면 개별 이미지의 태그 이름에 아키텍처를 포함하세요. 예를 들어, `mygroup/myapp:1.0.0-amd64`와 `mygroup/myapp:1.0.0-arm64v8`을 사용하세요. 그런 다음 매니페스트 목록에 `mygroup/myapp:1.0.0`로 태그를 지정할 수 있습니다.

## 프로젝트 경로를 변경하거나 프로젝트를 전송할 수 없음 {#unable-to-change-project-path-or-transfer-a-project}

프로젝트 경로를 변경하거나 프로젝트를 새로운 네임스페이스로 전송하려고 하면 다음 오류 중 하나가 표시될 수 있습니다:

- 컨테이너 레지스트리에 태그가 있으므로 프로젝트를 전송할 수 없습니다.
- 최소한 하나의 프로젝트에 컨테이너 레지스트리의 태그가 있으므로 네임스페이스를 이동할 수 없습니다.

이 오류는 프로젝트에 컨테이너 레지스트리의 이미지가 있을 때 발생합니다. 경로를 변경하거나 프로젝트를 전송하기 전에 이 이미지를 삭제하거나 이동해야 합니다.

다음 절차에서는 이러한 샘플 프로젝트 이름을 사용합니다:

- 현재 프로젝트의 경우: `gitlab.example.com/org/build/sample_project/cr:v2.9.1`.
- 새 프로젝트의 경우: `gitlab.example.com/new_org/build/new_sample_project/cr:v2.9.1`.

1. 컴퓨터에서 Docker 이미지를 다운로드합니다:

   ```shell
   docker login gitlab.example.com
   docker pull gitlab.example.com/org/build/sample_project/cr:v2.9.1
   ```

   > [!note]
   > [개인 액세스 토큰](../../profile/personal_access_tokens.md) 또는 [배포 토큰](../../project/deploy_tokens/_index.md)을(를) 사용하여 사용자 계정을 인증합니다.

1. 새 프로젝트 이름과 일치하도록 이미지의 이름을 바꾸세요:

   ```shell
   docker tag gitlab.example.com/org/build/sample_project/cr:v2.9.1 gitlab.example.com/new_org/build/new_sample_project/cr:v2.9.1
   ```

1. [UI](delete_container_registry_images.md) 또는 [API](../../../api/packages.md#delete-a-project-package)를 사용하여 이전 프로젝트의 이미지를 삭제합니다. 이미지가 대기 중이고 삭제되는 동안 지연이 있을 수 있습니다.
1. 경로를 변경하거나 프로젝트를 전송합니다:

   1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
   1. **설정** > **일반**을 선택합니다.
   1. **고급** 섹션을 펼치세요.
   1. **경로 변경** 텍스트 상자에서 경로를 편집합니다.
   1. **경로 변경**을 선택합니다.

1. 이미지를 복원합니다:

   ```shell
   docker push gitlab.example.com/new_org/build/new_sample_project/cr:v2.9.1
   ```

자세한 내용은 이 [이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/18383)를 참조하세요.

## `Failed to pull image` 메시지 {#failed-to-pull-image-messages}

CI/CD 작업이 제한된 [CI/CD 작업 토큰 범위](../../../ci/jobs/ci_job_token.md#limit-job-token-scope-for-public-or-internal-projects)가 있는 프로젝트에서 컨테이너 이미지를 가져올 수 없을 때 [`Failed to pull image`](../../../ci/debugging.md#failed-to-pull-image-messages) 오류 메시지가 표시될 수 있습니다.

## `OCI manifest found, but accept header does not support OCI manifests` 오류 {#oci-manifest-found-but-accept-header-does-not-support-oci-manifests-error}

이미지를 가져올 수 없으면 레지스트리 로그에 유사한 오류가 있을 수 있습니다:

```plaintext
manifest unknown: OCI manifest found, but accept header does not support OCI manifests
```

이 오류는 클라이언트가 올바른 `Accept: application/vnd.oci.image.manifest.v1+json` 헤더를 제출하지 않을 때 발생합니다. Docker 클라이언트 버전이 최신 상태인지 확인하세요. 타사 도구를 사용 중인 경우 OCI 매니페스트를 처리할 수 있는지 확인하세요.
