---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 보호된 컨테이너 태그
description: 역할 기반 보호 규칙 및 정규식 패턴을 사용하여 컨테이너 태그를 푸시하거나 삭제할 수 있는 사용자를 제어합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/505455)되었으며 [실험](../../../policy/development_stages_support.md)으로 GitLab 17.9에서 [기능 플래그](../../../administration/feature_flags/_index.md) `container_registry_protected_tags`를 사용합니다. 기본적으로 비활성화되었습니다.
- GitLab 17.10에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/505455)되었습니다.
- GitLab 17.11에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/524076)입니다. 기능 플래그 `container_registry_protected_tags`이 제거되었습니다.

{{< /history >}}

프로젝트에서 컨테이너 태그를 푸시하고 삭제할 수 있는 사용자를 제어합니다.

기본적으로 개발자, 유지 관리자 또는 소유자 역할을 가진 사용자는 모든 프로젝트 컨테이너 리포지토리에서 이미지 태그를 푸시하고 삭제할 수 있습니다. 태그 보호 규칙을 사용하면 다음을 수행할 수 있습니다:

- 특정 사용자 역할로 태그의 푸시 및 삭제를 제한합니다.
- 프로젝트당 최대 5개의 보호 규칙을 생성합니다.
- 프로젝트의 모든 컨테이너 리포지토리에 이러한 규칙을 적용합니다.

태그는 최소 하나의 보호 규칙이 이름과 일치할 때 보호됩니다. 여러 규칙이 일치하면 가장 제한적인 규칙이 적용됩니다.

보호된 태그는 [정리 정책](reduce_container_registry_storage.md#cleanup-policy)으로 삭제할 수 없습니다.

## 사전 요구 사항 {#prerequisites}

보호된 컨테이너 태그를 사용하려면 먼저 다음을 수행해야 합니다:

- 새로운 컨테이너 레지스트리 버전을 사용해야 합니다:
  - GitLab.com: 기본적으로 활성화됨
  - GitLab Self-Managed: [메타데이터 데이터베이스 활성화](../../../administration/packages/container_registry_metadata_database.md)

## 보호 규칙 생성 {#create-a-protection-rule}

사전 요구 사항:

- 유지 관리자 또는 소유자 역할이 있어야 합니다

보호 규칙을 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **컨테이너 레지스트리**를 확장합니다.
1. **보호된 컨테이너 태그** 아래에서 **보호 규칙 추가**를 선택합니다.
1. 필드를 완성합니다:
   - **일치하는 컨테이너 태그 보호**: [RE2 구문](https://github.com/google/re2/wiki/Syntax)을 사용하여 정규식 패턴을 입력합니다. 패턴은 100자를 초과할 수 없습니다. [정규식 패턴 예제](#regex-pattern-examples)를 참조하세요.
   - **푸시를 위한 최소 역할**: 유지 관리자, 소유자 또는 관리자를 선택합니다.
   - **삭제를 위한 최소 역할**: 유지 관리자, 소유자 또는 관리자를 선택합니다.
1. **규칙 추가**를 선택합니다.

보호 규칙이 생성되고 일치하는 태그가 보호됩니다.

## 정규식 패턴 예제 {#regex-pattern-examples}

컨테이너 태그를 보호하는 데 사용할 수 있는 예제 패턴:

| 패턴           | 설명 |
|-------------------|-------------|
| `.*`              | 모든 태그를 보호합니다 |
| `^v.*`            | "v"로 시작하는 태그를 보호합니다 (`v1.0.0`, `v2.1.0-rc1`) |
| `\d+\.\d+\.\d+`   | 의미 버전 태그를 보호합니다 (`1.0.0`, `2.1.0`) |
| `^latest$`        | `latest` 태그를 보호합니다 |
| `.*-stable$`      | "-stable"로 끝나는 태그를 보호합니다 (`1.0-stable`, `main-stable`) |
| `stable\|release` | "stable" 또는 "release"를 포함하는 태그를 보호합니다 (`1.0-stable`) |

## 보호 규칙 삭제 {#delete-a-protection-rule}

사전 요구 사항:

- 유지 관리자 또는 소유자 역할이 있어야 합니다

보호 규칙을 삭제하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **컨테이너 레지스트리**를 확장합니다.
1. **보호된 컨테이너 태그** 아래에서 삭제하려는 보호 규칙 다음에 **삭제** ({{< icon name="remove" >}})를 선택합니다.
1. 확인 메시지가 표시되면 **삭제**를 선택합니다.

보호 규칙이 삭제되고 일치하는 태그는 더 이상 보호되지 않습니다.

## 전파 지연 {#propagation-delay}

규칙 변경은 JWT 토큰을 사용하여 서비스 간에 전파됩니다. 결과적으로 보호 규칙 및 사용자 액세스 역할에 대한 변경 사항은 현재 JWT 토큰이 만료된 후에만 적용될 수 있습니다. 지연은 [구성된 토큰 지속 시간](../../../administration/packages/container_registry.md#increase-token-duration)과 같습니다:

- 기본값은 5분
- GitLab.com: [15분](../../gitlab_com/_index.md#container-registry)

대부분의 컨테이너 레지스트리 클라이언트(Docker, GitLab UI 및 API 포함)는 각 작업에 대해 새로운 토큰을 요청하지만 사용자 지정 클라이언트는 전체 유효성 기간 동안 토큰을 유지할 수 있습니다.

## 이미지 매니페스트 삭제 {#image-manifest-deletions}

GitLab UI 및 API는 직접 이미지 매니페스트 삭제를 지원하지 않습니다. 직접 컨테이너 레지스트리 API 호출을 통해 매니페스트 삭제는 모든 관련 태그에 영향을 줍니다.

태그 보호를 보장하려면 직접 매니페스트 삭제 요청은 다음의 경우에만 허용됩니다:

- 태그 보호가 비활성화됨
- 사용자는 보호된 태그를 삭제할 권한이 있습니다

## 컨테이너 이미지 삭제 {#deleting-container-images}

다음 조건이 모두 참인 경우 [컨테이너 이미지를 삭제](delete_container_registry_images.md)할 수 없습니다:

- 컨테이너 이미지에 태그가 있습니다.
- 프로젝트에 컨테이너 레지스트리 태그 보호 규칙이 있습니다.
- 액세스 레벨이 규칙에서 정의한 `minimum_access_delete_level`보다 낮습니다.

이 제한 사항은 규칙 패턴이 컨테이너 이미지 태그와 일치하는지 여부와 관계없이 적용됩니다.
