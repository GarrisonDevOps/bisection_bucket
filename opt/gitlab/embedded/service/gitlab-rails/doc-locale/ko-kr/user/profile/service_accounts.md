---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 서비스 계정
description: 자동화된 프로세스 및 타사 서비스 통합을 위한 비인간 계정을 만듭니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Free 티어의 서비스 계정:
  - `service_accounts_available_on_free_or_unlicensed`라는 이름의 [기능 플래그](../../administration/feature_flags/_index.md)로 GitLab 18.10에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225913)되었습니다. 기본적으로 비활성화되었습니다.
  - GitLab 18.11에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/227910)되었습니다. 기능 플래그가 제거되었습니다.
- 프로젝트 서비스 계정이 GitLab 18.10에서 [소개](https://gitlab.com/gitlab-org/gitlab/-/work_items/585509)되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `allow_projects_to_create_service_accounts`를 포함합니다. 기본적으로 비활성화되었습니다.
- 하위 그룹 서비스 계정이 GitLab 18.10에서 [소개](https://gitlab.com/gitlab-org/gitlab/-/work_items/585513)되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `allow_subgroups_to_create_service_accounts`를 포함합니다. 기본적으로 비활성화되었습니다.
- 하위 그룹 및 프로젝트 서비스 계정이 GitLab 18.11에서 [일반적으로 제공](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225485/)됩니다. 기능 플래그 `allow_subgroups_to_create_service_accounts` 및 `allow_projects_to_create_service_accounts`이 제거되었습니다.

{{< /history >}}

서비스 계정은 개인이 아닌 비인간 엔티티를 나타내는 사용자 계정입니다. 서비스 계정을 사용하여 자동화된 작업을 수행하고, 데이터에 액세스하거나, 예약된 프로세스를 실행합니다. 서비스 계정은 일반적으로 팀 멤버십이 변경되어도 자격 증명이 안정적으로 유지되어야 하는 파이프라인 또는 타사 통합에 사용됩니다.

서비스 계정은 [개인 액세스 토큰](personal_access_tokens.md)으로 인증합니다. [패키지 및 컨테이너 레지스트리](../packages/_index.md)와 상호작용하고, [Git 작업](personal_access_tokens.md#clone-repository-using-personal-access-token)을 수행하고, API에 액세스할 수 있습니다.

서비스 계정의 특성은 다음과 같습니다:

- 좌석을 사용하지 않습니다.
- [청구 대상 사용자](../../subscriptions/manage_seats.md#billable-users) 또는 [내부 사용자](../../administration/internal_users.md)가 아닙니다.
- 항상 [외부 사용자](../../administration/external_users.md)로 표시됩니다.
- UI를 통해 GitLab에 로그인할 수 없습니다.
- LDAP와 같은 서비스를 통해 관리할 수 없습니다.
- 하위 그룹 또는 프로젝트에서 프로비저닝된 경우 최상위 그룹 또는 다른 서비스 계정을 만들 수 없습니다.
- 그룹 및 프로젝트 멤버십 목록에 일반 사용자가 아닌 서비스 계정으로 나열됩니다.
- [사용자 지정 이메일 주소](../../api/service_accounts.md#create-an-instance-service-account)를 추가하지 않으면 알림 이메일을 받지 않습니다.
- GitLab의 [평가판 버전](https://gitlab.com/-/trial_registrations/new?glm_source=docs.gitlab.com&glm_content=free-user-limit-faq/ee/user/free_user_limit.html)에서 사용할 수 있습니다. GitLab.com에서는 최상위 그룹의 소유자가 먼저 신원을 확인해야 합니다.

[서비스 계정 API](../../api/service_accounts.md)를 통해 서비스 계정을 관리할 수도 있습니다. 서비스 계정의 SSH 키를 관리하려면 [사용자 SSH 및 GPG 키 API](../../api/user_keys.md)를 사용합니다. GitLab UI를 통해 SSH 키를 관리할 수 없습니다.

생성할 수 있는 서비스 계정의 수는 구독 및 제공 서비스에 따라 다릅니다:

- GitLab Premium 및 Ultimate에서는 모든 제공 서비스에 대해 무제한의 서비스 계정을 만들 수 있습니다.
- GitLab Free에서는 제공 서비스에 따라 제한이 다릅니다:
  - GitLab.com의 경우 각 최상위 그룹마다 최대 100개의 서비스 계정을 만들 수 있습니다. 여기에는 하위 그룹 또는 프로젝트에서 생성된 서비스 계정이 포함됩니다.
  - GitLab Self-Managed의 경우 전체 인스턴스에 대해 최대 100개의 서비스 계정을 만들 수 있습니다. 여기에는 인스턴스, 그룹 또는 프로젝트 수준에서 생성된 서비스 계정이 포함됩니다.

## 서비스 계정의 유형 {#types-of-service-accounts}

서비스 계정에는 각각 다른 범위와 전제 조건이 있는 세 가지 유형이 있습니다:

{{< tabs >}}

{{< tab title="인스턴스 서비스 계정" >}}

인스턴스 서비스 계정은 관리자 영역을 통해 만들어지며 인스턴스의 모든 그룹 또는 프로젝트에 초대될 수 있습니다.

사전 요구 사항:

- 인스턴스에 대한 관리자 액세스입니다.

{{< /tab >}}

{{< tab title="그룹 서비스 계정" >}}

그룹 서비스 계정은 특정 그룹에서 만들어지며 생성된 그룹 또는 모든 하위 그룹 또는 프로젝트에 초대될 수 있습니다. 최상위 그룹 또는 서비스 계정을 만들 수 없습니다.

사전 요구 사항:

- GitLab.com에서는 그룹에 대한 소유자 역할이 있어야 합니다.
- GitLab Self-Managed 또는 GitLab Dedicated에서는 다음 중 하나를 수행해야 합니다:
  - 인스턴스의 관리자입니다.
  - 그룹에서 소유자 역할을 가지고 [서비스 계정 생성이 허용](../../administration/settings/account_and_limit_settings.md#allow-top-level-group-owners-to-create-service-accounts)됩니다.

{{< /tab >}}

{{< tab title="프로젝트 서비스 계정" >}}

프로젝트 서비스 계정은 특정 프로젝트에서 만들어지며 해당 프로젝트에만 사용할 수 있습니다. 최상위 그룹 또는 서비스 계정을 만들 수 없습니다.

사전 요구 사항:

- GitLab.com에서는 프로젝트에 대한 유지 관리자 또는 소유자 역할이 있어야 합니다.
- GitLab Self-Managed 또는 GitLab Dedicated에서는 다음 중 하나를 수행해야 합니다:
  - 인스턴스의 관리자입니다.
  - 프로젝트에서 유지 관리자 또는 소유자 역할을 가집니다.

{{< /tab >}}

{{< /tabs >}}

## 서비스 계정 보기 및 관리 {#view-and-manage-service-accounts}

{{< history >}}

- GitLab 17.11에서 GitLab.com에 소개됨

{{< /history >}}

서비스 계정 페이지에는 그룹, 프로젝트 또는 인스턴스의 서비스 계정에 대한 정보가 표시됩니다. 각 그룹, 프로젝트 및 GitLab Self-Managed 인스턴스에는 별도의 서비스 계정 페이지가 있습니다. 이 페이지에서 다음을 수행할 수 있습니다:

- 그룹 또는 인스턴스의 모든 서비스 계정을 봅니다.
- 서비스 계정을 삭제합니다.
- 서비스 계정의 이름 또는 사용자 이름을 편집합니다.
- 서비스 계정의 개인 액세스 토큰을 관리합니다.

{{< tabs >}}

{{< tab title="인스턴스 서비스 계정" >}}

전체 인스턴스의 서비스 계정을 보려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **서비스 계정**을 선택합니다.

{{< /tab >}}

{{< tab title="그룹 서비스 계정" >}}

그룹의 서비스 계정을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **서비스 계정**을 선택합니다.

{{< /tab >}}

{{< tab title="프로젝트 서비스 계정" >}}

프로젝트의 서비스 계정을 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **서비스 계정**을 선택합니다.

{{< /tab >}}

{{< /tabs >}}

### 서비스 계정 만들기 {#create-a-service-account}

{{< history >}}

- GitLab 16.3에서 GitLab.com에 소개됨
- 최상위 그룹 소유자는 GitLab 17.5에서 서비스 계정을 만들 수 있으며 [소개](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163726)되었으며 GitLab Self-Managed의 경우 [기능 플래그](../../administration/feature_flags/_index.md) `allow_top_level_group_owners_to_create_service_accounts`를 포함합니다. 기본적으로 비활성화되었습니다.
- 최상위 그룹 소유자는 GitLab 17.6에서 서비스 계정을 [만들 수 있으며 일반적으로 제공](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/172502)됩니다. 기능 플래그 `allow_top_level_group_owners_to_create_service_accounts`이 제거되었습니다.

{{< /history >}}

GitLab.com에서는 최상위 그룹 소유자만 서비스 계정을 만들 수 있습니다.

기본적으로 GitLab Self-Managed 및 GitLab Dedicated에서는 관리자만 서비스 계정 유형을 만들 수 있습니다. 하지만 [인스턴스를 구성](../../administration/settings/account_and_limit_settings.md#allow-top-level-group-owners-to-create-service-accounts)하여 최상위 그룹 소유자가 그룹 서비스 계정을 만들 수 있도록 허용할 수 있습니다.

생성할 수 있는 서비스 계정의 수는 구독 및 제공 서비스에 따라 다릅니다:

- GitLab Premium 및 Ultimate에서는 모든 제공 서비스에 대해 무제한의 서비스 계정을 만들 수 있습니다.
- GitLab Free에서는 제공 서비스에 따라 제한이 다릅니다:
  - GitLab.com의 경우 각 최상위 그룹마다 최대 100개의 서비스 계정을 만들 수 있습니다. 여기에는 하위 그룹 또는 프로젝트에서 생성된 서비스 계정이 포함됩니다.
  - GitLab Self-Managed의 경우 전체 인스턴스에 대해 최대 100개의 서비스 계정을 만들 수 있습니다. 여기에는 인스턴스, 그룹 또는 프로젝트 수준에서 생성된 서비스 계정이 포함됩니다.

서비스 계정을 만들려면:

1. [서비스 계정](#view-and-manage-service-accounts) 페이지로 이동합니다.
1. **서비스 계정 추가**를 선택합니다.
1. 서비스 계정의 이름을 입력합니다. 사용자 이름은 이름을 기반으로 자동으로 생성됩니다. 필요한 경우 사용자 이름을 수정할 수 있습니다.
1. **서비스 계정 생성**를 선택합니다.

### 서비스 계정 편집 {#edit-a-service-account}

{{< history >}}

- GitLab 18.9에서 복합 ID를 가진 서비스 계정에 대한 [사용자 이름 제한이 추가](https://gitlab.com/gitlab-org/gitlab/-/work_items/581050)되었습니다.

{{< /history >}}

서비스 계정의 이름 또는 사용자 이름을 편집할 수 있습니다.

> [!note]
> [복합 ID](../duo_agent_platform/composite_identity.md)와 연관된 서비스 계정의 사용자 이름은 업데이트할 수 없습니다.

서비스 계정을 편집하려면:

1. [서비스 계정](#view-and-manage-service-accounts) 페이지로 이동합니다.
1. 서비스 계정을 식별합니다.
1. 세로 줄임표({{< icon name="ellipsis_v" >}}) > **편집**을 선택합니다.
1. 서비스 계정의 이름 또는 사용자 이름을 편집합니다.
1. **변경 사항 저장**을 선택합니다.

### 그룹 또는 프로젝트에 서비스 계정 추가 {#add-a-service-account-to-a-group-or-project}

서비스 계정은 그룹 또는 프로젝트의 멤버로 추가될 때까지 액세스 권한이 제한됩니다. 그룹 또는 프로젝트에 임의의 수의 서비스 계정을 추가할 수 있으며, 각 서비스 계정은 각 그룹, 하위 그룹 또는 프로젝트에서 다른 역할을 가질 수 있습니다.

서비스 계정 액세스는 서비스 계정의 유형에 따라 다릅니다:

- 인스턴스 서비스 계정: 인스턴스의 모든 그룹 또는 프로젝트에 초대될 수 있습니다.
- 그룹 서비스 계정: 생성된 그룹 또는 모든 하위 그룹 또는 프로젝트에 초대될 수 있습니다.
- 프로젝트 서비스 계정: 생성된 프로젝트에만 초대될 수 있습니다.

[다른 그룹과 그룹을 공유](../project/members/sharing_projects_groups.md#invite-a-group-to-a-group)할 때 공유된 그룹의 모든 멤버(서비스 계정 포함)는 공유된 그룹에 대한 액세스 권한을 얻습니다.

그룹에 대한 소유자 역할을 서비스 계정에 할당하면 서비스 계정의 개인 액세스 토큰도 해당 그룹에 대한 소유자 역할을 갖습니다.

다음을 사용하여 그룹 및 프로젝트에 서비스 계정을 할당할 수 있습니다:

- GitLab UI:
  - [그룹에 사용자 추가](../group/_index.md#add-users-to-a-group).
  - [프로젝트에 사용자 추가](../project/members/_index.md#add-users-to-a-project).
- API:
  - [그룹 멤버 API](../../api/group_members.md).
  - [프로젝트 멤버 API](../../api/project_members.md).

> [!note]
> [전역 SAML 그룹 멤버십 잠금](../group/saml_sso/group_sync.md#global-saml-group-memberships-lock) 또는 [전역 LDAP 그룹 멤버십 잠금](../../administration/auth/ldap/ldap_synchronization.md#global-ldap-group-memberships-lock) 설정이 활성화되어 있으면 API를 사용하여 서비스 계정 멤버십을 제어해야 합니다.

## 서비스 계정으로 프로젝트 포크 {#fork-projects-with-a-service-account}

서비스 계정은 [프로젝트 포크 API](../../api/project_forks.md)를 통해 프로젝트를 포크할 수 있지만 개인 네임스페이스로는 포크할 수 없습니다. 서비스 계정으로 포크할 때는 대상 그룹 네임스페이스를 지정해야 합니다.

사전 요구 사항:

- 서비스 계정에 개발자 역할이 있고 대상 그룹의 멤버입니다.
- `api` 범위가 서비스 계정의 개인 액세스 토큰에 대해 켜져 있습니다.

서비스 계정을 사용하여 프로젝트를 포크하려면:

1. 포크가 생성되는 대상 그룹을 식별합니다.
1. 서비스 계정이 적절한 권한이 있는 해당 그룹의 멤버인지 확인합니다.
1. [포크 프로젝트 API](../../api/project_forks.md)를 `namespace_id` 또는 `namespace_path`와 함께 사용합니다:

   ```shell
    curl --request POST --header "PRIVATE-TOKEN: <service_account_token>" \
      --data "namespace_path=target-group" \
      "https://gitlab.example.com/api/v4/projects/<project_id>/fork"
   ```

### 서비스 계정 삭제 {#delete-a-service-account}

서비스 계정을 삭제하면 계정에서 만든 모든 기여는 유지되고 소유권이 유령 사용자로 이전됩니다. 이러한 기여에는 머지 리퀘스트, 이슈, 프로젝트 및 그룹과 같은 활동이 포함될 수 있습니다.

서비스 계정을 삭제하려면:

1. [서비스 계정](#view-and-manage-service-accounts) 페이지로 이동합니다.
1. 서비스 계정을 식별합니다.
1. 세로 줄임표({{< icon name="ellipsis_v" >}}) > **계정 삭제**를 선택합니다.
1. 서비스 계정의 이름을 입력합니다.
1. **사용자 삭제**를 선택합니다.

서비스 계정 및 계정에서 만든 모든 기여를 삭제할 수도 있습니다. 이러한 기여에는 머지 리퀘스트, 이슈, 그룹 및 프로젝트와 같은 활동이 포함될 수 있습니다.

1. [서비스 계정](#view-and-manage-service-accounts) 페이지로 이동합니다.
1. 서비스 계정을 식별합니다.
1. 세로 줄임표({{< icon name="ellipsis_v" >}}) > **계정 및 기여 삭제**를 선택합니다.
1. 서비스 계정의 이름을 입력합니다.
1. **사용자와 기여 삭제**를 선택합니다.

API를 통해 서비스 계정을 삭제할 수도 있습니다.

- 인스턴스 서비스 계정의 경우 [사용자 API](../../api/users.md#delete-a-user)를 사용합니다.
- 그룹 서비스 계정의 경우 [서비스 계정 API](../../api/service_accounts.md#delete-a-group-service-account)를 사용합니다.

## 서비스 계정의 개인 액세스 토큰 보기 및 관리 {#view-and-manage-personal-access-tokens-for-a-service-account}

개인 액세스 토큰 페이지에는 최상위 그룹 또는 인스턴스의 서비스 계정과 연관된 개인 액세스 토큰에 대한 정보가 표시됩니다. 이 페이지에서 다음을 수행할 수 있습니다:

- 개인 액세스 토큰을 필터링, 정렬 및 세부 정보를 봅니다.
- 개인 액세스 토큰을 교체합니다.
- 개인 액세스 토큰을 해지합니다.

API를 통해 서비스 계정의 개인 액세스 토큰을 관리할 수도 있습니다.

- 인스턴스 서비스 계정의 경우 [개인 액세스 토큰 API](../../api/personal_access_tokens.md)를 사용합니다.
- 그룹 서비스 계정의 경우 [서비스 계정 API](../../api/service_accounts.md)를 사용합니다.

서비스 계정의 개인 액세스 토큰 페이지를 보려면:

1. [서비스 계정](#view-and-manage-service-accounts) 페이지로 이동합니다.
1. 서비스 계정을 식별합니다.
1. 세로 줄임표({{< icon name="ellipsis_v" >}}) > **액세스 토큰 관리**를 선택합니다.

### 서비스 계정의 개인 액세스 토큰 만들기 {#create-a-personal-access-token-for-a-service-account}

서비스 계정을 사용하려면 요청을 인증하기 위해 개인 액세스 토큰을 만들어야 합니다.

서비스 계정의 개인 액세스 토큰을 만들려면:

1. [서비스 계정](#view-and-manage-service-accounts) 페이지로 이동합니다.
1. 서비스 계정을 식별합니다.
1. 세로 줄임표({{< icon name="ellipsis_v" >}}) > **액세스 토큰 관리**를 선택합니다.
1. **새 토큰 추가**를 선택합니다.
1. **토큰 이름**에 토큰의 이름을 입력합니다.
1. 선택 사항. **토큰 설명**에 토큰에 대한 설명을 입력합니다.
1. **만료일**에서 토큰의 만료일을 입력합니다.
   - 토큰은 UTC 자정에 그 날짜에 만료됩니다. 2024-01-01의 만료일이 있는 토큰은 2024-01-01에 UTC 00:00:00에 만료됩니다.
   - 만료일을 입력하지 않으면 만료일이 자동으로 현재 날짜보다 365일 뒤로 설정됩니다.
   - 만료일이 필요하지 않으면 토큰이 만료일 없이 생성됩니다.
   - 기본적으로 이 날짜는 현재 날짜보다 최대 365일 뒤일 수 있습니다. GitLab 17.6 이상에서는 [이 제한을 400일로 확장](https://gitlab.com/gitlab-org/gitlab/-/issues/461901)할 수 있습니다.
1. [원하는 범위](../../security/tokens/access_token_scopes.md)를 선택합니다.
1. **개인 액세스 토큰 만들기**를 선택합니다.

### 개인 액세스 토큰 교체 {#rotate-a-personal-access-token}

개인 액세스 토큰을 교체하여 현재 토큰을 무효화하고 새 값을 생성할 수 있습니다.

> [!warning]
> 이를 취소할 수 없습니다. 교체된 토큰을 사용하는 서비스가 작동을 중지합니다.

서비스 계정의 개인 액세스 토큰을 교체하려면:

1. [서비스 계정](#view-and-manage-service-accounts) 페이지로 이동합니다.
1. 서비스 계정을 식별합니다.
1. 세로 줄임표({{< icon name="ellipsis_v" >}}) > **액세스 토큰 관리**를 선택합니다.
1. 활성 토큰 옆에서 수직 줄임표({{< icon name="ellipsis_v" >}})를 선택합니다.
1. **교체**를 선택합니다.
1. 확인 대화 상자에서 **교체**를 선택합니다.

### 개인 액세스 토큰 해지 {#revoke-a-personal-access-token}

개인 액세스 토큰을 교체하여 현재 토큰을 무효화할 수 있습니다.

> [!warning]
> 이를 취소할 수 없습니다. 해지된 토큰을 사용하는 서비스가 작동을 중지합니다.

서비스 계정의 개인 액세스 토큰을 해지하려면:

1. [서비스 계정](#view-and-manage-service-accounts) 페이지로 이동합니다.
1. 서비스 계정을 식별합니다.
1. 세로 줄임표({{< icon name="ellipsis_v" >}}) > **액세스 토큰 관리**를 선택합니다.
1. 활성 토큰 옆에서 수직 줄임표({{< icon name="ellipsis_v" >}})를 선택합니다.
1. **해지**를 선택합니다.
1. 확인 대화 상자에서 **해지**를 선택합니다.

## 서비스 계정 이메일 {#service-account-emails}

서비스 계정을 만들 때 GitLab은 다음 접두사 중 하나가 있는 회신 불가 이메일 주소를 생성합니다:

- 인스턴스: `service_account_`
- 그룹: `service_account_group_`
- 프로젝트: `service_account_project_`

사용자 지정 이메일 주소는 최상위 그룹에 일치하는 [확인된 도메인](../enterprise_user/_index.md#manage-group-domains)이 있거나 이메일 확인 설정이 [비활성화](../../administration/settings/sign_up_restrictions.md#confirm-user-email)되지 않으면 확인이 필요합니다.

## 속도 제한 {#rate-limits}

[속도 제한](../../rate_limits/_index.md)이 서비스 계정에 적용됩니다:

- GitLab.com에서는 [GitLab.com 특정 속도 제한](../gitlab_com/rate_limits.md)이 적용됩니다.
- GitLab Self-Managed 및 GitLab Dedicated에서는 다음 속도 제한이 적용됩니다:
  - [구성 가능한 속도 제한](../../rate_limits/_index.md#configuration-options)
  - [구성 불가능한 속도 제한](../../rate_limits/non_configurable.md)

## 관련 항목 {#related-topics}

- [청구 대상 사용자](../../subscriptions/manage_seats.md#billable-users)
- [연관된 레코드](account/delete_account.md#associated-records)
- [프로젝트 액세스 토큰 - 봇 사용자](../project/settings/project_access_tokens.md#bot-users-for-projects)
- [그룹 액세스 토큰 - 봇 사용자](../group/settings/group_access_tokens.md#bot-users-for-groups)
- [내부 사용자](../../administration/internal_users.md)
