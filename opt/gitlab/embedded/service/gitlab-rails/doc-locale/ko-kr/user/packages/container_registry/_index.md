---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 컨테이너 레지스트리
description: GitLab 컨테이너 레지스트리를 사용하여 GitLab 프로젝트의 컨테이너 이미지를 저장합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

통합 컨테이너 레지스트리를 사용하여 각 GitLab 프로젝트의 컨테이너 이미지를 저장할 수 있습니다.

관리자는 GitLab 인스턴스의 컨테이너 레지스트리를 활성화해야 합니다. 자세한 내용은 [GitLab 컨테이너 레지스트리 관리](../../../administration/packages/container_registry.md)를 참조하세요.

> [!note]
> Docker Hub에서 컨테이너 이미지를 가져오는 경우 [GitLab 종속성 프록시](../dependency_proxy/_index.md#use-the-dependency-proxy-for-docker-images)를 사용하여 속도 제한을 피하고 파이프라인을 가속화할 수 있습니다.

## 컨테이너 레지스트리 보기 {#view-the-container-registry}

프로젝트 또는 그룹의 컨테이너 레지스트리를 볼 수 있습니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **컨테이너 레지스트리**를 선택합니다.

컨테이너 이미지를 검색, 정렬, 필터링, [삭제](delete_container_registry_images.md#use-the-gitlab-ui)할 수 있습니다. 브라우저에서 URL을 복사하여 필터링된 보기를 공유할 수 있습니다.

### 컨테이너 레지스트리의 특정 컨테이너 이미지의 태그 보기 {#view-the-tags-of-a-specific-container-image-in-the-container-registry}

컨테이너 레지스트리 **태그 세부정보** 페이지를 사용하여 주어진 컨테이너 이미지와 연결된 태그 목록을 볼 수 있습니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **컨테이너 레지스트리**를 선택합니다.
1. 컨테이너 이미지를 선택합니다.

게시된 시점, 사용하는 스토리지 양, 매니페스트 및 구성 다이제스트와 같은 각 태그에 대한 세부정보를 볼 수 있습니다.

이 페이지에서 태그를 검색, 정렬, 삭제할 수 있습니다. 태그는 **이름**으로 정렬됩니다. 컨테이너 레지스트리 메타데이터 데이터베이스가 활성화되면 **게시됨**으로도 정렬할 수 있으며, 이는 기본값이며 최근에 게시된 태그를 먼저 나열합니다. 브라우저에서 URL을 복사하여 필터링된 보기를 공유할 수 있습니다.

### 다중 아키텍처 이미지의 지원 플랫폼 보기 {#view-supported-platforms-for-multi-architecture-images}

{{< history >}}

- GitLab 19.1에서 `container_registry_display_supported_platforms` [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228384)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 19.2에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/240791)입니다. 기능 플래그 `container_registry_display_supported_platforms`이 제거되었습니다.

{{< /history >}}

Docker 매니페스트 목록 또는 OCI 이미지 인덱스(다중 아키텍처 이미지)를 가리키는 태그를 보고 지원되는 플랫폼을 확인합니다.

사전 요구 사항:

- GitLab Self-Managed의 경우 메타데이터 데이터베이스로 구성된 컨테이너 레지스트리입니다. 자세한 내용은 [컨테이너 레지스트리 메타데이터 데이터베이스](../../../administration/packages/container_registry_metadata_database.md)를 참조하세요.

지원되는 플랫폼을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **컨테이너 레지스트리**를 선택합니다.
1. 컨테이너 이미지를 선택합니다.
1. 다중 아키텍처 태그의 세부정보를 확장합니다.

**지원되는 플랫폼** 행에는 각 플랫폼의 배지가 표시됩니다(예: `linux/amd64` 또는 `linux/arm64/v8`). Windows 이미지의 경우 알려진 빌드 번호가 친화적인 레이블로 매핑됩니다(예: `windows/amd64 (ltsc2022)`).

### 스토리지 사용량 {#storage-usage}

컨테이너 레지스트리 스토리지 사용량을 보고 프로젝트와 그룹 전체에서 컨테이너 리포지토리의 크기를 추적하고 관리합니다.

자세한 내용은 [컨테이너 레지스트리 사용량 보기](reduce_container_registry_storage.md#view-container-registry-usage)를 참조하세요.

## 컨테이너 레지스트리의 컨테이너 이미지 사용 {#use-container-images-from-the-container-registry}

컨테이너 레지스트리에 호스팅된 컨테이너 이미지를 다운로드하고 실행하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **컨테이너 레지스트리**를 선택합니다.
1. 작업할 컨테이너 이미지를 찾고 **이미지 경로 복사**({{< icon name="copy-to-clipboard" >}})를 선택합니다.
1. `docker run`을 복사한 링크와 함께 사용합니다:

   ```shell
   docker run [options] registry.example.com/group/project/image [arguments]
   ```

> [!note]
> 개인 리포지토리에서 컨테이너 이미지를 다운로드하려면 컨테이너 레지스트리로 인증해야 합니다. 자세한 내용은 [컨테이너 레지스트리로 인증](authenticate_with_container_registry.md)을 참조하세요.

## 컨테이너 이미지의 명명 규칙 {#naming-convention-for-your-container-images}

컨테이너 이미지는 다음 명명 규칙을 따라야 합니다:

```plaintext
<registry server>/<namespace>/<project>[/<optional path>]
```

예를 들어, 프로젝트가 `gitlab.example.com/mynamespace/myproject`인 경우 컨테이너 이미지는 `gitlab.example.com/mynamespace/myproject`로 이름이 지어져야 합니다.

컨테이너 이미지 이름의 끝에 최대 2단계까지 추가 이름을 추가할 수 있습니다.

예를 들어, `myproject` 프로젝트의 컨테이너 이미지의 유효한 이름은 다음과 같습니다:

```plaintext
registry.example.com/mynamespace/myproject:some-tag
```

```plaintext
registry.example.com/mynamespace/myproject/image:latest
```

```plaintext
registry.example.com/mynamespace/myproject/my/image:rc1
```

## 컨테이너 레지스트리 리포지토리 이동 또는 이름 변경 {#move-or-rename-container-registry-repositories}

컨테이너 리포지토리의 경로는 항상 관련 프로젝트의 리포지토리 경로와 일치하므로 컨테이너 레지스트리만 이름을 변경하거나 이동할 수 없습니다. 대신 다음 중 하나를 수행할 수 있습니다:

- [프로젝트의 리포지토리 이름 변경](../../project/working_with_projects.md#rename-a-repository).
- [프로젝트 전송](../../project/working_with_projects.md#transfer-a-project).

성능상의 이유로, 채워진 컨테이너 리포지토리가 있는 프로젝트의 이름 변경은 최대 1,000개의 컨테이너 리포지토리가 있는 프로젝트로 제한됩니다.

GitLab Self-Managed 인스턴스에서 그룹 또는 프로젝트를 이동하거나 이름을 변경하기 전에 모든 컨테이너 이미지를 삭제할 수 있습니다. 또는 [이슈 18383](https://gitlab.com/gitlab-org/gitlab/-/issues/18383#possible-workaround)에는 이러한 제한을 해결할 수 있는 커뮤니티 제안이 포함되어 있습니다. [에픽 9459](https://gitlab.com/groups/gitlab-org/-/epics/9459)는 GitLab Self-Managed에 컨테이너 리포지토리가 있는 프로젝트 및 그룹 이동 지원을 추가할 것을 제안합니다.

## 프로젝트에 대한 컨테이너 레지스트리 비활성화 {#disable-the-container-registry-for-a-project}

컨테이너 레지스트리는 기본적으로 활성화됩니다.

그러나 프로젝트의 컨테이너 레지스트리를 제거할 수 있습니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한** 섹션을 확장하고 **컨테이너 레지스트리**를 비활성화합니다.
1. **변경 사항 저장**을 선택합니다.

**배포** > **컨테이너 레지스트리** 항목이 프로젝트의 사이드바에서 제거됩니다.

## 컨테이너 레지스트리의 표시 여부 변경 {#change-visibility-of-the-container-registry}

기본적으로 컨테이너 레지스트리는 프로젝트에 액세스할 수 있는 모든 사용자에게 표시됩니다. 그러나 프로젝트의 컨테이너 레지스트리의 표시 여부를 변경할 수 있습니다.

이 설정이 사용자에게 부여하는 권한에 대한 자세한 내용은 [컨테이너 레지스트리 표시 여부 권한](#container-registry-visibility-permissions)을 참조하세요.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한** 섹션을 확장합니다.
1. **컨테이너 레지스트리** 아래에서 드롭다운 목록의 옵션을 선택합니다:

   - **액세스 권한이 있는 모든 사용자**(기본값): 컨테이너 레지스트리는 프로젝트에 액세스할 수 있는 모든 사용자에게 표시됩니다. 프로젝트가 공개인 경우 컨테이너 레지스트리도 공개입니다. 프로젝트가 내부 또는 개인 프로젝트인 경우 컨테이너 레지스트리도 내부 또는 개인입니다.

   - **프로젝트 멤버만**: 컨테이너 레지스트리는 보고자, 개발자, 유지관리자 또는 소유자 역할이 있는 프로젝트 멤버에게만 표시됩니다. 이 표시 여부는 컨테이너 레지스트리 표시 여부가 **액세스 권한이 있는 모든 사용자**로 설정된 개인 프로젝트의 동작과 유사합니다.

1. **변경 사항 저장**을 선택합니다.

## 컨테이너 레지스트리 표시 여부 권한 {#container-registry-visibility-permissions}

컨테이너 레지스트리를 보고 컨테이너 이미지를 가져올 수 있는 기능은 컨테이너 레지스트리의 표시 여부 권한에 의해 제어됩니다. UI의 표시 여부 설정 또는 [API](../../../api/container_registry.md#change-the-visibility-of-the-container-registry)를 통해 표시 여부를 변경할 수 있습니다.

컨테이너 레지스트리 업데이트, 컨테이너 이미지 푸시 또는 삭제와 같은 기타 권한은 이 설정의 영향을 받지 않습니다. 그러나 컨테이너 레지스트리를 비활성화하면 모든 컨테이너 레지스트리 작업이 비활성화됩니다. 자세한 내용은 [역할 및 권한](../../permissions.md)을 참조하세요.

|                                                                                                                   |                                               | 익명<br/>(인터넷의 모든 사람) | Guest | 보고자, 개발자, 유지 관리자, 소유자 |
|-------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|--------------------------------------|-------|----------------------------------------|
| 컨테이너 레지스트리 표시 여부가 있는 공개 프로젝트 <br/> **액세스 권한이 있는 모든 사용자**(UI) 또는 `enabled`(API)로 설정   | 컨테이너 레지스트리 <br/> 및 이미지 풀 보기 | 예                                  | 예   | 예                                    |
| 컨테이너 레지스트리 표시 여부가 있는 공개 프로젝트 <br/> **프로젝트 멤버만**(UI) 또는 `private`(API)로 설정   | 컨테이너 레지스트리 <br/> 및 이미지 풀 보기 | 아니요                                   | 아니요    | 예                                    |
| 컨테이너 레지스트리 표시 여부가 있는 내부 프로젝트 <br/> **액세스 권한이 있는 모든 사용자**(UI) 또는 `enabled`(API)로 설정 | 컨테이너 레지스트리 <br/> 및 이미지 풀 보기 | 아니요                                   | 예   | 예                                    |
| 컨테이너 레지스트리 표시 여부가 있는 내부 프로젝트 <br/> **프로젝트 멤버만**(UI) 또는 `private`(API)로 설정 | 컨테이너 레지스트리 <br/> 및 이미지 풀 보기 | 아니요                                   | 아니요    | 예                                    |
| 컨테이너 레지스트리 표시 여부가 있는 개인 프로젝트 <br/> **액세스 권한이 있는 모든 사용자**(UI) 또는 `enabled`(API)로 설정  | 컨테이너 레지스트리 <br/> 및 이미지 풀 보기 | 아니요                                   | 아니요    | 예                                    |
| 컨테이너 레지스트리 표시 여부가 있는 개인 프로젝트 <br/> **프로젝트 멤버만**(UI) 또는 `private`(API)로 설정  | 컨테이너 레지스트리 <br/> 및 이미지 풀 보기 | 아니요                                   | 아니요    | 예                                    |
| 컨테이너 레지스트리 `disabled`이 있는 모든 프로젝트                                                                    | 컨테이너 레지스트리의 모든 작업          | 아니요                                   | 아니요    | 아니요                                     |

## 지원되는 이미지 유형 {#supported-image-types}

컨테이너 레지스트리는 [Docker V2](https://distribution.github.io/distribution/spec/manifest-v2-2/) 및 [OCI(Open Container Initiative)](https://github.com/opencontainers/image-spec/blob/main/spec.md) 이미지 형식을 지원합니다. 또한 컨테이너 레지스트리는 [OCI 배포 사양을 준수합니다](https://conformance.opencontainers.org/#gitlab-container-registry).

OCI 지원은 Helm 3+ 차트 패키지와 같은 OCI 기반 이미지 형식을 레지스트리에서 호스팅할 수 있음을 의미합니다. GitLab API와 UI의 이미지 형식 간에는 구별이 없습니다. [이슈 38047](https://gitlab.com/gitlab-org/gitlab/-/issues/38047)은 Helm부터 시작하여 이러한 구별을 다룹니다.

## 컨테이너 이미지 서명 {#container-image-signatures}

{{< history >}}

- 컨테이너 이미지 서명 표시가 GitLab 17.1에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/7856)되었습니다.

{{< /history >}}

GitLab 컨테이너 레지스트리에서 [OCI 1.1 매니페스트 `subject` 필드](https://github.com/opencontainers/image-spec/blob/v1.1.0/manifest.md)를 사용하여 컨테이너 이미지를 [Cosign 서명](../../../ci/yaml/signing_examples.md)과 연결할 수 있습니다. 그런 다음 해당 서명의 태그를 검색할 필요 없이 서명 정보를 관련 컨테이너 이미지와 함께 볼 수 있습니다.

컨테이너 이미지의 태그를 볼 때 연결된 서명이 있는 각 태그 옆에 표시된 아이콘이 표시됩니다. 서명의 세부정보를 보려면 아이콘을 선택합니다.

사전 요구 사항:

- 컨테이너 이미지에 서명하려면 Cosign v2.0 이상이 필요합니다.
- GitLab Self-Managed의 경우 서명을 표시하기 위해 메타데이터 데이터베이스로 구성된 GitLab 컨테이너 레지스트리가 필요합니다. 자세한 내용은 [컨테이너 레지스트리 메타데이터 데이터베이스](../../../administration/packages/container_registry_metadata_database.md)를 참조하세요.

### OCI 참조 데이터를 사용하여 컨테이너 이미지에 서명 {#sign-container-images-with-oci-referrer-data}

Cosign을 사용하여 서명에 참조 데이터를 추가하려면 다음을 수행해야 합니다:

- `COSIGN_EXPERIMENTAL` 환경 변수를 `1`로 설정합니다.
- `--registry-referrers-mode oci-1-1`을 서명 명령에 추가합니다.

예를 들어:

```shell
COSIGN_EXPERIMENTAL=1 cosign sign --registry-referrers-mode oci-1-1 <container image>
```

> [!note]
> GitLab 컨테이너 레지스트리는 OCI 1.1 매니페스트 `subject` 필드를 지원하지만 [OCI 1.1 참조 API](https://github.com/opencontainers/distribution-spec/blob/v1.1.0/spec.md#listing-referrers)를 완전히 구현하지는 않습니다.
