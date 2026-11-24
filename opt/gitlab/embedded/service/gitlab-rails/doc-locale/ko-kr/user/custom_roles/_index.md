---
stage: Software Supply Chain Security
group: Authorization
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 사용자 지정 역할
description: 특정 조직의 필요에 맞는 사용자 지정 권한으로 사용자 지정 역할을 생성합니다.
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- UI를 사용하여 사용자 지정 역할을 생성 및 제거하는 기능이 [GitLab 16.4에서 도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/393235).
- UI를 사용하여 사용자 지정 역할로 그룹에 사용자를 추가하거나, 사용자의 사용자 지정 역할을 변경하거나, 그룹 구성원에서 사용자 지정 역할을 제거하는 기능이 [GitLab 16.7에서 도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/393239).
- GitLab Self-Managed에서 인스턴스 전체 사용자 지정 역할을 생성 및 제거하는 기능이 [GitLab 16.9에서 도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/141562).
- 사용자 지정 관리자 역할이 GitLab 17.7에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/15854)되었으며 [실험](../../policy/development_stages_support.md)으로 [기능 플래그](../../administration/feature_flags/_index.md) `custom_ability_read_admin_dashboard`로 명명되어 있습니다.
- UI를 사용하여 사용자 지정 운영자 역할을 관리하는 기능이 GitLab 17.9에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181346) [기능 플래그](../../administration/feature_flags/_index.md) 이름 `custom_admin_roles`. 기본적으로 비활성화되었습니다.
- 사용자 지정 운영자 역할이 GitLab 18.3에서 [일반 공개되었습니다](https://gitlab.com/groups/gitlab-org/-/epics/15957). `custom_admin_roles` 기능 플래그가 기본적으로 사용으로 설정됩니다.
- 기능 플래그 `custom_admin_roles`이 GitLab 19.0에서 제거되었습니다.

{{< /history >}}

사용자 지정 역할을 사용하면 조직에 필요한 특정 [사용자 지정 권한](abilities.md)만 포함된 역할을 생성할 수 있습니다. 각 사용자 지정 역할은 기존 기본 역할을 기반으로 합니다. 예를 들어, 게스트 역할을 기반으로 사용자 지정 역할을 생성하되 프로젝트 리포지토리에서 코드를 보는 권한을 포함할 수 있습니다.

GitLab은 두 가지 유형의 사용자 지정 역할을 제공합니다:

- 사용자 지정 멤버 역할:
  - 그룹 또는 프로젝트의 멤버에게 할당할 수 있습니다.
  - 모든 하위 그룹 또는 프로젝트에서 동일한 권한을 얻습니다. 자세한 내용은 [멤버십 유형](../project/members/_index.md#membership-types)을 참조하세요.
  - [사용자를 사용하며](../../subscriptions/manage_seats.md#gitlabcom-billing-and-usage) [청구 대상 사용자](../../subscriptions/manage_seats.md#billable-users)가 됩니다.
    - `read_code` 권한만 포함하는 사용자 지정 게스트 멤버 역할은 사용자를 사용하지 않습니다.
  - SAML 또는 LDAP 그룹의 멤버에게 할당할 수 있습니다.
- 사용자 지정 운영자 역할:
  - 인스턴스의 모든 사용자에게 할당할 수 있습니다.
  - 특정 운영자 작업을 수행할 권한을 얻습니다.
  - LDAP 그룹의 멤버에게 할당할 수 있습니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 사용자 지정 역할 기능의 데모는 [[데모] Ultimate 게스트는 사용자 지정 역할을 통해 비공개 리포지토리의 코드를 볼 수 있습니다](https://www.youtube.com/watch?v=46cp_-Rtxps)를 참조하세요.
<!-- Video published on 2023-02-13 -->

## 사용자 지정 멤버 역할 생성 {#create-a-custom-member-role}

사용자 지정 멤버 역할을 생성하려면 기본 GitLab 역할을 선택하고 추가 [권한](abilities.md)을 추가합니다. 기본 역할은 사용자 지정 역할에서 사용 가능한 최소 권한을 정의합니다. [감사자](../../administration/auditor_users.md)를 기본 역할로 사용할 수 없습니다.

사용자 지정 권한은 일반적으로 유지 관리자 또는 소유자 역할로 제한되는 작업을 허용할 수 있습니다. 예를 들어, CI/CD 변수를 관리할 권한이 있는 사용자 지정 역할은 다른 유지 관리자 또는 소유자가 추가한 CI/CD 변수도 관리할 수 있습니다.

사용자 지정 멤버 역할은 그룹 및 프로젝트에서 사용 가능합니다:

- GitLab.com에서는 사용자 지정 역할이 생성된 최상위 그룹 아래에 있습니다.
- GitLab Self-Managed 및 GitLab Dedicated에서는 전체 인스턴스에서 사용 가능합니다.

사전 요구 사항:

- GitLab.com의 경우 그룹의 소유자 역할이 있어야 합니다.
- GitLab Self-Managed 및 GitLab Dedicated의 경우 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.
- 10개 미만의 사용자 지정 역할이 있어야 합니다.

사용자 지정 멤버 역할을 생성하려면:

1. 왼쪽 사이드바에서:
   - GitLab.com의 경우 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
   - GitLab Self-Managed 및 GitLab Dedicated의 경우 오른쪽 위 모서리에서 **운영자**를 선택합니다.
1. **설정** > **역할 및 권한**을 선택합니다.
1. **새 역할**을 선택합니다.
1. GitLab Self-Managed 및 GitLab Dedicated 인스턴스만 해당. **멤버 역할**을 선택합니다.
1. 사용자 지정 역할의 이름과 설명을 입력합니다.
1. **기본 역할** 드롭다운 목록에서 기본 역할을 선택합니다.
1. 사용자 지정 역할에 대한 권한을 선택합니다.
1. **역할 생성**을 선택합니다.

[API를 사용하여](../../api/graphql/reference/_index.md#mutationmemberrolecreate) 사용자 지정 역할을 생성할 수도 있습니다.

## 사용자 지정 운영자 역할 생성 {#create-a-custom-admin-role}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

사용자 지정 운영자 역할을 생성하려면 일반적으로 관리자로 제한되는 작업을 허용하는 [권한](abilities.md)을 추가합니다. 각 사용자 지정 운영자 역할은 하나 이상의 권한을 가질 수 있습니다.

사전 요구 사항:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.
- 10개 미만의 사용자 지정 역할이 있어야 합니다.

사용자 지정 운영자 역할을 생성하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **역할 및 권한**을 선택합니다.
1. **새 역할**을 선택합니다.
1. **운영자 역할**을 선택합니다.
1. 사용자 지정 역할의 이름과 설명을 입력합니다.
1. 사용자 지정 역할에 대한 권한을 선택합니다.
1. **역할 생성**을 선택합니다.

[API를 사용하여](../../api/graphql/reference/_index.md#mutationmemberroleadmincreate) 사용자 지정 역할을 생성할 수도 있습니다.

## 사용자 지정 역할 편집 {#edit-a-custom-role}

{{< history >}}

- GitLab 17.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/437590)되었습니다.

{{< /history >}}

사용자 지정 역할의 이름, 설명 및 권한을 편집할 수 있지만 기본 역할은 편집할 수 없습니다. 기본 역할을 변경해야 하는 경우 새 사용자 지정 역할을 만들어야 합니다.

사전 요구 사항:

- GitLab.com의 경우 그룹의 소유자 역할이 있어야 합니다.
- GitLab Self-Managed 및 GitLab Dedicated의 경우 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

사용자 지정 역할을 편집하려면:

1. 왼쪽 사이드바에서:
   - GitLab.com의 경우 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
   - GitLab Self-Managed 및 GitLab Dedicated의 경우 오른쪽 위 모서리에서 **운영자**를 선택합니다.
1. **설정** > **역할 및 권한**을 선택합니다.
1. 사용자 지정 역할 옆에서 세로 줄임표({{< icon name="ellipsis_v" >}}) > **역할 편집**을 선택합니다.
1. 역할을 수정합니다.
1. **역할 저장**을 선택합니다.

또한 API를 사용하여 [사용자 지정 멤버 역할](../../api/graphql/reference/_index.md#mutationmemberroleupdate) 또는 [사용자 지정 운영자 역할](../../api/graphql/reference/_index.md#mutationmemberroleadminupdate)을 편집할 수 있습니다.

## 사용자 지정 역할의 세부 정보 보기 {#view-details-of-a-custom-role}

**역할 및 권한** 페이지에는 사용 가능한 모든 기본 및 사용자 지정 역할에 대한 기본 정보가 나열됩니다. 여기에는 이름, 설명, 각 사용자 지정 역할에 할당된 사용자 수 등의 정보가 포함됩니다. 각 사용자 지정 역할에는 `Custom member role` 또는 `Custom admin role` 배지가 포함됩니다.

또한 역할 ID, 기본 역할 및 특정 권한을 포함하여 사용자 지정 역할에 대한 더 자세한 정보를 볼 수 있습니다.

사전 요구 사항:

- GitLab.com의 경우 그룹의 소유자 역할이 있어야 합니다.
- GitLab Self-Managed 및 GitLab Dedicated의 경우 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

사용자 지정 역할의 세부 정보를 보려면:

1. 왼쪽 사이드바에서:
   - GitLab.com의 경우 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
   - GitLab Self-Managed 및 GitLab Dedicated의 경우 오른쪽 위 모서리에서 **운영자**를 선택합니다.
1. **설정** > **역할 및 권한**을 선택합니다.
1. 사용자 지정 역할 옆에서 세로 줄임표({{< icon name="ellipsis_v" >}}) > **상세 보기**를 선택합니다.

## 사용자 지정 역할 삭제 {#delete-a-custom-role}

여전히 사용자에게 할당된 사용자 지정 역할은 삭제할 수 없습니다. [사용자 지정 역할 할당](#assign-a-custom-member-role)을 참조하세요.

사전 요구 사항:

- GitLab.com의 경우 그룹의 소유자 역할이 있어야 합니다.
- GitLab Self-Managed 및 GitLab Dedicated의 경우 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

사용자 지정 역할을 삭제하려면:

1. 왼쪽 사이드바에서:
   - GitLab.com의 경우 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
   - GitLab Self-Managed 및 GitLab Dedicated의 경우 오른쪽 위 모서리에서 **운영자**를 선택합니다.
1. **설정** > **역할 및 권한**을 선택합니다.
1. 사용자 지정 역할 옆에서 세로 줄임표({{< icon name="ellipsis_v" >}}) > **역할 삭제**를 선택합니다.
1. 확인 대화상자에서 **역할 삭제**를 선택합니다.

또한 API를 사용하여 [사용자 지정 멤버 역할](../../api/graphql/reference/_index.md#mutationmemberroledelete) 또는 [사용자 지정 운영자 역할](../../api/graphql/reference/_index.md#mutationmemberroleadmindelete)을 삭제할 수 있습니다.

## 사용자 지정 멤버 역할 할당 {#assign-a-custom-member-role}

그룹 및 프로젝트의 구성원에 대한 역할을 할당하거나 수정할 수 있습니다. 이를 기존 사용자에게 수행하거나 [그룹](../group/_index.md#add-users-to-a-group), [프로젝트](../project/members/_index.md#add-users-to-a-project) 또는 [인스턴스](../profile/account/create_accounts.md)에 사용자를 추가할 때 수행할 수 있습니다.

사전 요구 사항:

- 그룹의 경우 그룹의 소유자 역할이 있어야 합니다.
- 프로젝트의 경우 프로젝트의 유지 관리자 또는 소유자 역할이 있어야 합니다.

기존 사용자에게 사용자 지정 멤버 역할을 할당하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹 또는 프로젝트를 찾습니다.
1. **관리** > **멤버**를 선택하세요.
1. **역할** 열에서 기존 멤버의 역할을 선택합니다. **역할 세부정보** 드로어가 열립니다.
1. **역할** 드롭다운 목록에서 멤버에게 할당할 역할을 선택합니다.
1. **역할 업데이트**를 선택하여 역할을 할당합니다.

[API를 사용하여](../../api/graphql/reference/_index.md#mutationmemberroletouserassign) 사용자 지정 역할 할당을 할당하거나 수정할 수도 있습니다.

## 사용자 지정 운영자 역할 할당 {#assign-a-custom-admin-role}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

인스턴스의 사용자에게 운영자 역할을 할당하거나 수정할 수 있습니다. 이를 기존 사용자에게 수행하거나 [인스턴스](../profile/account/create_accounts.md)에 사용자를 추가할 때 수행할 수 있습니다.

사전 요구 사항:

- GitLab 인스턴스의 관리자여야 합니다.

기존 사용자에게 사용자 지정 운영자 역할을 할당하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **개요** > **사용자**를 선택합니다.
1. 사용자에 대해 **편집**을 선택합니다.
1. **액세스** 섹션에서 액세스 수준을 **일반** 또는 **감사자**로 설정합니다.
1. **운영자 영역** 드롭다운 목록에서 사용자 지정 운영자 역할을 선택합니다.

[API를 사용하여](../../api/graphql/reference/_index.md#mutationmemberroletouserassign) 사용자 지정 역할 할당을 할당하거나 수정할 수도 있습니다.

## 초대된 그룹에 사용자 지정 역할 할당 {#assign-a-custom-role-to-an-invited-group}

{{< history >}}

- 초대된 그룹에 대한 사용자 지정 역할 지원이 [GitLab 17.4에서 도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/443369) 기능 플래그 이름 `assign_custom_roles_to_group_links_sm` 뒤에서. 기본적으로 비활성화되었습니다.
- GitLab 17.4의 [GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/471999)되었습니다.
- GitLab 18.10에서 [일반 공개되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225008). 기능 플래그 `assign_custom_roles_to_group_links_sm`이 제거되었습니다.

{{< /history >}}

[그룹을 그룹에 초대](../project/members/sharing_projects_groups.md#invite-a-group-to-a-group)할 때 그룹의 모든 사용자에게 사용자 지정 역할을 할당할 수 있습니다.

할당된 역할은 원래 그룹의 사용자 역할 및 권한과 비교됩니다. 일반적으로 사용자는 액세스 수준이 가장 낮은 역할을 할당받습니다. 그러나 사용자가 원래 그룹에 사용자 지정 역할을 가지고 있는 경우:

- 액세스 수준 비교에는 기본 역할만 사용됩니다. 사용자 지정 권한은 비교되지 않습니다.
- 사용자 지정 역할이 모두 동일한 기본 역할을 가진 경우 사용자는 원래 그룹의 사용자 지정 역할을 유지합니다.

다음 표는 그룹에 초대된 사용자가 사용 가능한 최대 역할의 예를 제공합니다:

| 시나리오                                                | 게스트 역할이 있는 사용자 | 게스트 역할 + `read_code`이 있는 사용자 | 게스트 역할 + `read_vulnerability`이 있는 사용자 | 개발자 역할이 있는 사용자     | 개발자 역할 + `admin_vulnerability`이 있는 사용자 |
| ------------------------------------------------------- | -------------------- | ---------------------------------- | ------------------------------------------- | ---------------------------- | ------------------------------------------------ |
| **게스트 역할로 초대됨**                             | Guest                | Guest                            | Guest                                     | Guest                        | Guest                                          |
| **게스트 역할 + `read_code`로 초대됨**               | Guest                | 게스트 + `read_code`              | 게스트 + `read_vulnerability`              | 게스트 + `read_code`          | 게스트 + `read_code`                            |
| **게스트 역할 + `read_vulnerability`로 초대됨**      | Guest                | 게스트 + `read_code`              | 게스트 + `read_vulnerability`              | 게스트 + `read_vulnerability` | 게스트 + `read_vulnerability`                   |
| **개발자 역할로 초대됨**                         | Guest                | 게스트 + `read_code`              | 게스트 + `read_vulnerability`              | Developer                    | Developer                                      |
| **개발자 역할 + `admin_vulnerability`로 초대됨** | Guest                | 게스트 + `read_code`              | 게스트 + `read_vulnerability`              | Developer                    | 개발자 + `admin_vulnerability`              |

그룹을 다른 그룹에 초대할 때만 사용자 지정 역할을 할당할 수 있습니다. [이슈 468329](https://gitlab.com/gitlab-org/gitlab/-/issues/468329)는 그룹을 프로젝트에 초대할 때 사용자 지정 역할을 할당할 것을 제안합니다.

## 지원되는 개체 {#supported-objects}

다음에 사용자 지정 역할 및 권한을 할당할 수 있습니다:

| 개체 | 버전       | 이슈 |
|--------|---------------|-------|
| 사용자  | 15.9          | 릴리스됨 |
| 그룹 | 17.7          | 부분적으로 지원됩니다. 프로젝트의 그룹 할당에 대한 추가 지원은 [이슈 468329](https://gitlab.com/gitlab-org/gitlab/-/issues/468329)에서 제안됩니다 |
| 토큰 | 지원되지 않음 | [이슈 434354](https://gitlab.com/gitlab-org/gitlab/-/issues/434354) |

## 외부 그룹에 사용자 지정 역할 할당 {#assign-a-custom-role-to-an-external-group}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

외부 LDAP 또는 SAML 그룹의 모든 사용자에게 사용자 지정 멤버 역할을 할당하거나 LDAP 그룹에서만 동기화된 사용자에게 사용자 지정 운영자 역할을 할당할 수 있습니다.

LDAP 또는 SAML 그룹에 사용자 지정 역할을 할당하려면:

- [SAML 그룹에 사용자 지정 멤버 역할 할당](../group/saml_sso/group_sync.md#configure-saml-group-links).
- [LDAP 그룹에 사용자 지정 멤버 역할 할당](../group/access_and_permissions.md#manage-group-memberships-with-ldap).
- [LDAP 그룹에 사용자 지정 운영자 역할 할당](../../administration/auth/ldap/ldap_synchronization.md#assign-a-custom-admin-role-to-an-ldap-group).

## 새 권한 기여 {#contribute-new-permissions}

권한이 없으면 다음을 수행할 수 있습니다:

- [이슈 391760](https://gitlab.com/gitlab-org/gitlab/-/issues/391760)에서 개별 사용자 지정 역할 및 권한 요청을 논의합니다.
- [권한 제안 이슈 템플릿](https://gitlab.com/gitlab-org/gitlab/-/work_items/new?description_template=Permission%20Proposal)을 사용하여 권한을 요청하는 이슈를 생성합니다.
- GitLab에 기여하고 권한을 추가합니다.
