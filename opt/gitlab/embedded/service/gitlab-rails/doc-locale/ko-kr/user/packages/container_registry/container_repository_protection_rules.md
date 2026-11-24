---
stage: Container
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
gitlab_dedicated: yes
title: 보호된 컨테이너 리포지토리
description: GitLab의 보호된 컨테이너 리포지토리는 이미지를 푸시하거나 삭제할 수 있는 사용자 역할을 제한합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 16.7에서 `container_registry_protected_containers`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/463669)되었습니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md) 기능입니다.
- [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/429074) \- GitLab 17.8
- [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/480385) \- GitLab 17.8 `container_registry_protected_containers` 기능 플래그가 제거되었습니다.

{{< /history >}}

기본적으로 Developer, Maintainer 또는 Owner 역할을 가진 모든 사용자는 컨테이너 리포지토리에서 컨테이너 이미지를 푸시하고 삭제할 수 있습니다. 컨테이너 리포지토리를 보호하여 컨테이너 이미지를 변경할 수 있는 사용자를 제한합니다.

컨테이너 리포지토리가 보호되면 기본 동작은 컨테이너 리포지토리 및 해당 이미지에 다음 제한을 적용합니다:

| 작업                                                                                   | 최소 역할         |
|------------------------------------------------------------------------------------------|----------------------|
| 컨테이너 리포지토리 및 해당 컨테이너 이미지를 보호합니다.                                 | Maintainer 역할입니다. |
| 컨테이너 리포지토리에서 새 이미지를 푸시하거나 생성합니다.                                    | [**푸시를 위한 최소 액세스 수준**](#create-a-container-repository-protection-rule) 설정에서 설정한 역할입니다. |
| 컨테이너 리포지토리에서 기존 이미지를 푸시하거나 업데이트합니다.                              | [**푸시를 위한 최소 액세스 수준**](#create-a-container-repository-protection-rule) 설정에서 설정한 역할입니다. |
| 배포 토큰으로 컨테이너 리포지토리에서 이미지를 푸시, 생성 또는 업데이트합니다. | 해당 없음. 배포 토큰은 보호되지 않은 리포지토리에서 사용할 수 있지만 범위에 관계없이 보호된 컨테이너 리포지토리에 이미지를 푸시하는 데 사용할 수 없습니다. |

와일드카드(`*`)를 사용하여 동일한 컨테이너 보호 규칙으로 여러 컨테이너 리포지토리를 보호할 수 있습니다. 예를 들어 CI/CD 파이프라인 중에 빌드된 임시 컨테이너 이미지가 포함된 다양한 컨테이너 리포지토리를 보호할 수 있습니다.

다음 표에는 여러 컨테이너 리포지토리와 일치하는 컨테이너 보호 규칙의 예가 포함되어 있습니다:

| 와일드카드 경로 패턴 | 예제 일치 컨테이너 리포지토리 |
|----------------------------|-----------------------------------------|
| `group/container-*`        | `group/container-prod`, `group/container-prod-sha123456789` |
| `group/*container`         | `group/container`, `group/prod-container`, `group/prod-sha123456789-container` |
| `group/*container*`        | `group/container`, `group/prod-sha123456789-container-v1` |

동일한 컨테이너 리포지토리에 여러 보호 규칙을 적용할 수 있습니다. 최소 하나의 보호 규칙이 일치하면 컨테이너 리포지토리가 보호됩니다.

## 컨테이너 리포지토리 보호 규칙 만들기 {#create-a-container-repository-protection-rule}

사전 요구 사항:

- Maintainer 또는 Owner 역할이 있어야 합니다.

보호 규칙을 만들려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **컨테이너 레지스트리**를 확장합니다.
1. **보호된 컨테이너 리포지토리** 아래에서 **보호 규칙 추가**를 선택합니다.
1. 필드를 완성합니다:
   - **리포지토리 경로 패턴**은 보호할 컨테이너 리포지토리 경로입니다. 패턴에는 와일드카드(`*`)를 포함할 수 있습니다.
   - **푸시를 위한 최소 액세스 수준**은 보호된 컨테이너 리포지토리 경로에 푸시(생성 또는 업데이트)하는 데 필요한 최소 액세스 수준을 설명합니다.
1. **보호**를 선택합니다.

보호 규칙이 생성되었고 컨테이너 리포지토리가 이제 보호됩니다.

## 컨테이너 리포지토리 보호 규칙 삭제 {#delete-a-container-repository-protection-rule}

{{< history >}}

- GitLab 17.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/146622)되었습니다.

{{< /history >}}

사전 요구 사항:

- Maintainer 또는 Owner 역할이 있어야 합니다.

보호 규칙을 삭제하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **컨테이너 레지스트리**를 확장합니다.
1. **보호된 컨테이너 리포지토리** 아래에서 삭제할 보호 규칙 옆에 **삭제**({{< icon name="remove" >}})를 선택합니다.
1. 확인 대화에서 **삭제**를 선택합니다.

보호 규칙이 삭제되었고 컨테이너 리포지토리는 더 이상 보호되지 않습니다.
