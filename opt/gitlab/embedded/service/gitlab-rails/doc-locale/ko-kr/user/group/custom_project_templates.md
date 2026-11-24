---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 그룹에서 프로젝트 생성을 빠르게 하려면 커스텀 프로젝트 템플릿을 빌드하고 그룹과 공유합니다.
title: 그룹의 커스텀 프로젝트 템플릿
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 그룹 컨텍스트 외부에서 그룹 템플릿을 찾기 위한 그룹 선택기가 GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/590012)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)가 `constrain_group_project_templates`입니다. 기본적으로 비활성화되었습니다.
- 그룹 컨텍스트 외부에서 그룹 템플릿을 찾기 위한 그룹 선택기가 GitLab 19.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/586332)합니다. `constrain_group_project_templates` 기능 플래그가 제거되었습니다.

{{< /history >}}

프로젝트를 생성할 때 [템플릿 목록에서 선택](../project/_index.md)할 수 있습니다. 이러한 템플릿은 GitLab Pages 또는 Ruby와 같은 것들에 대해 템플릿에 포함된 파일의 복사본으로 새 프로젝트를 채웁니다. 이 정보는 [GitLab 프로젝트 가져오기/내보내기](../project/settings/import_export.md)에서 사용하는 정보와 동일하며 새 프로젝트를 더 빠르게 시작할 수 있습니다.

사용 가능한 템플릿의 [목록을 사용자 지정](../project/_index.md)하여 그룹의 모든 프로젝트가 동일한 목록을 가지도록 할 수 있습니다. 이렇게 하려면 템플릿으로 사용할 프로젝트로 하위 그룹을 채웁니다.

[인스턴스의 커스텀 템플릿](../../administration/project_templates.md)을 구성할 수도 있습니다.

## 그룹의 프로젝트 템플릿 설정 {#set-up-project-templates-for-a-group}

사전 요구 사항:

- 그룹의 Owner 역할이 있어야 합니다.

그룹의 커스텀 프로젝트 템플릿을 설정하려면 프로젝트 템플릿이 포함된 하위 그룹을 그룹 설정에 추가합니다:

1. 그룹에서 [하위 그룹](subgroups/_index.md)을 생성합니다.
1. [새 하위 그룹에 프로젝트 추가](_index.md#add-projects-to-a-group)를 템플릿으로 사용합니다.
1. 그룹의 왼쪽 메뉴에서 **설정** > **일반**을 선택합니다.
1. **커스텀 프로젝트 템플릿**을 확장하고 하위 그룹을 선택합니다.

다음에 그룹 멤버가 프로젝트를 생성할 때 하위 그룹의 프로젝트 중 하나를 선택할 수 있습니다.

중첩된 하위 그룹의 프로젝트는 템플릿 목록에 포함되지 않습니다.

## 템플릿으로 사용 가능한 프로젝트 {#which-projects-are-available-as-templates}

- 공개 및 내부 프로젝트는 모든 [프로젝트 기능](../project/settings/_index.md#configure-project-features-and-permissions)이 **GitLab 페이지** 및 **보안 및 규정 준수**를 제외하고 **액세스 권한이 있는 모든 사용자**로 설정된 경우 모든 인증된 사용자가 새 프로젝트의 템플릿으로 선택할 수 있습니다.
- 비공개 프로젝트는 프로젝트의 멤버인 사용자만 선택할 수 있습니다.

그룹 컨텍스트 외부에서 프로젝트를 생성할 때 드롭다운 목록에서 그룹을 선택한 후 템플릿을 찾아볼 수 있습니다. 액세스할 수 있는 그룹만 나열됩니다.

## 예 구조 {#example-structure}

다음은 프로젝트 템플릿의 샘플 그룹 및 프로젝트 구조이며 `myorganization`에 대한 것입니다:

```plaintext
# GitLab instance and group
gitlab.com/myorganization/
    # Subgroups
    internal
    tools
    # Subgroup for handling project templates
    websites
        templates
            # Project templates
            client-site-django
            client-site-gatsby
            client-site-html

        # Other projects
        client-site-a
        client-site-b
        client-site-c
        ...
```

## 템플릿에서 복사되는 항목 {#what-is-copied-from-the-templates}

템플릿에서 프로젝트를 생성할 때 모든 내보낼 수 있는 프로젝트 항목이 템플릿에서 새 프로젝트로 복사됩니다. 이 항목에는 다음이 포함됩니다:

- 리포지토리 브랜치, 커밋 및 태그.
- 프로젝트 업로드.
- 프로젝트 구성.
- 댓글 및 기타 메타데이터가 포함된 이슈 및 머지 리퀘스트.
- 레이블, 마일스톤, 스니펫 및 릴리스.
- CI/CD 파이프라인 구성.

복사되는 항목의 전체 목록을 보려면 [내보낼 수 있는 프로젝트 항목](../project/settings/import_export.md#project-items-that-are-exported)을 참조합니다.

### 권한 및 민감한 데이터 {#permissions-and-sensitive-data}

복사 동작은 사용자의 권한에 따라 다릅니다:

- GitLab 관리자인 경우 프로젝트 멤버를 포함한 모든 프로젝트 설정이 새 프로젝트로 복사됩니다.
- 인스턴스의 커스텀 템플릿이 포함된 프로젝트의 소유자 역할을 가지고 있지만 GitLab 관리자가 아닌 경우: 프로젝트 설정은 복사되지만 프로젝트 멤버는 복사되지 않습니다.
- 프로젝트의 소유자 역할을 가지지 않고 GitLab 관리자가 아닌 경우: 프로젝트 배포 키 및 프로젝트 웹후크는 민감한 데이터가 포함되어 있어 복사되지 않습니다.

템플릿이 복사될 때 보호된 브랜치 및 태그 액세스 수준도 영향을 받습니다:

- 새 프로젝트의 최상위 그룹의 소유자 역할을 가지거나 GitLab 관리자인 경우 이 액세스 수준이 새 프로젝트에 복사됩니다.
- 그렇지 않으면 보호된 브랜치 및 태그 액세스 수준이 유지자로 재설정됩니다. 아무도 아님으로 설정된 액세스 수준은 유지됩니다. 자세한 내용은 [가져온 항목에 대한 변경 사항](../project/settings/import_export.md#changes-to-imported-items)을 참조합니다.

배포 키 및 웹후크에는 민감한 암호가 포함됩니다. 프로젝트를 생성하는 ID가 템플릿 프로젝트의 소유자 역할을 가지거나 관리자 액세스 권한이 있을 때만 복사됩니다. API를 사용하여 템플릿에서 프로젝트를 생성할 때 이 ID는 토큰에 따라 다릅니다:

- 개인 액세스 토큰: 토큰 소유자의 권한을 사용합니다. 배포 키 및 웹후크는 해당 사용자가 템플릿 프로젝트의 소유자 역할을 가지거나 관리자인 경우 복사됩니다.
- 그룹 액세스 토큰 또는 프로젝트 액세스 토큰: [봇 사용자](settings/group_access_tokens.md#bot-users-for-groups)로 작동합니다. 봇 사용자는 토큰을 생성하는 그룹 또는 프로젝트의 멤버입니다. 해당 범위에 템플릿 프로젝트가 포함되지 않으면 봇 사용자는 템플릿 프로젝트의 소유자 역할을 가지지 않으며 배포 키 및 웹후크는 복사되지 않습니다. 복사하려면 템플릿 프로젝트의 소유자 역할을 가진 사용자의 개인 액세스 토큰을 사용합니다.

## 템플릿의 사용자 할당 {#user-assignments-in-templates}

다른 사용자가 생성한 템플릿을 사용할 때 템플릿의 사용자에게 할당된 모든 항목이 다시 할당됩니다. 보호된 브랜치 및 태그와 같은 보안 기능을 구성할 때 이 재할당을 이해하는 것이 중요합니다. 예를 들어 템플릿에 보호된 브랜치가 포함된 경우:

- 템플릿에서 브랜치는 템플릿 소유자가 기본 브랜치로 병합할 수 있습니다.
- 템플릿에서 생성된 프로젝트에서 브랜치는 기본 브랜치로 병합할 수 있습니다.

템플릿이 복사될 때 보호된 브랜치 및 태그 액세스 수준도 영향을 받습니다. 자세한 내용은 [권한 및 민감한 데이터](#permissions-and-sensitive-data)를 참조합니다.

## 문제 해결 {#troubleshooting}

### 관리자가 프로젝트를 생성할 때 그룹의 커스텀 프로젝트 템플릿을 볼 수 없음 {#administrator-cannot-see-custom-project-templates-for-the-group-when-creating-a-project}

그룹의 커스텀 프로젝트 템플릿은 그룹 멤버만 사용할 수 있습니다. 사용 중인 관리자 계정이 그룹의 멤버가 아닌 경우 템플릿에 액세스할 수 없습니다.
