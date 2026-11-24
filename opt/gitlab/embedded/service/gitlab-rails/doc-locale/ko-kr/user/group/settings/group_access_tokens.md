---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 그룹 액세스 토큰
availability_details: no
---

{{< details >}}

- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 액세스 토큰은 그룹 및 그 프로젝트에 대한 인증된 액세스를 제공합니다. 개인 액세스 토큰 및 프로젝트 액세스 토큰과 유사하지만, 사용자나 프로젝트가 아닌 그룹에 연결됩니다. 그룹 액세스 토큰을 사용하여 다른 그룹, 프로젝트 또는 개인 액세스 토큰을 생성할 수 없습니다.

그룹 액세스 토큰을 사용하여 다음에 인증할 수 있습니다:

- [GitLab API](../../../api/rest/authentication.md#personal-project-and-group-access-tokens)를 사용합니다.
- HTTPS를 통한 Git 사용:
  - 사용자 이름으로 공백이 아닌 값을 사용합니다.
  - 암호로 그룹 액세스 토큰을 사용합니다.

사전 요구 사항:

- 그룹에 대한 소유자 역할이 있어야 합니다.

> [!note]
> GitLab.com에서는 그룹 액세스 토큰이 Premium 또는 Ultimate 구독을 필요로 합니다. [평가판](https://about.gitlab.com/free-trial/#what-is-included-in-my-free-trial-what-is-excluded) 중에는 사용할 수 없습니다.
>
> GitLab Self-Managed 및 GitLab Dedicated에서 그룹 액세스 토큰은 모든 라이선스에서 사용할 수 있습니다.

## 그룹 액세스 토큰 생성 {#create-a-group-access-token}

{{< history >}}

- 최대 허용 수명 제한이 GitLab 17.6에서 [400일로 확대](https://gitlab.com/gitlab-org/gitlab/-/issues/461901)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `buffered_token_expiration_limit`(으)로 지정됩니다. 기본적으로 비활성화되었습니다.
- 그룹 액세스 토큰 설명이 GitLab 17.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/443819)되었습니다.

{{< /history >}}

> [!flag]
> 확장된 최대 허용 수명 제한의 사용 가능성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

### UI 사용 {#with-the-ui}

그룹 액세스 토큰을 생성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **액세스 토큰**을(를) 선택합니다.
1. **새 토큰 추가**를 선택합니다.
1. **토큰 이름**에 이름을 입력합니다. 토큰 이름은 그룹을 볼 수 있는 권한이 있는 모든 사용자에게 표시됩니다.
1. 선택 사항. **토큰 설명**에 토큰에 대한 설명을 입력합니다.
1. **만료일**에 토큰의 만료 날짜를 입력합니다.
   - 토큰은 그 날짜의 자정 UTC에 만료됩니다.
   - 날짜를 입력하지 않으면 만료일이 오늘로부터 365일로 설정됩니다.
   - 기본적으로 만료일은 오늘로부터 365일을 초과할 수 없습니다. GitLab 17.6 이상에서는 관리자가 [액세스 토큰의 최대 수명을 수정](../../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens)할 수 있습니다.
1. 토큰에 대한 역할을 선택합니다.
1. 하나 이상의 [그룹 액세스 토큰 범위](../../../security/tokens/access_token_scopes.md)를 선택합니다.
1. **그룹 액세스 토큰 생성**을 선택합니다.

그룹 액세스 토큰이 표시됩니다. 그룹 액세스 토큰을 안전한 곳에 저장하세요. 페이지를 떠나거나 새로 고친 후에는 다시 볼 수 없습니다.

모든 그룹 액세스 토큰은 개인 액세스 토큰에 대해 구성된 [기본 접두사 설정](../../../administration/settings/account_and_limit_settings.md#personal-access-token-prefix)을(를) 상속합니다.

> [!warning]
> 그룹 액세스 토큰은 내부 사용자로 처리됩니다. 내부 사용자가 그룹 액세스 토큰을 생성하면 해당 토큰은 표시 수준이 내부로 설정된 모든 프로젝트에 액세스할 수 있습니다.

### Rails 콘솔 사용 {#with-the-rails-console}

관리자인 경우 Rails 콘솔에서 그룹 액세스 토큰을 생성할 수 있습니다:

1. [Rails 콘솔](../../../administration/operations/rails_console.md)에서 다음 명령을 실행합니다:

   ```ruby
   # Set the GitLab administration user to use. If user ID 1 is not available or is not an administrator, use 'admin = User.admins.first' instead to select an administrator.
   admin = User.find(1)

   # Set the group you want to create a token for. For example, group with ID 109.
   group = Group.find(109)

   # Create the group bot user. For further group access tokens, the username should be `group_{group_id}_bot_{random_string}` and email address `group_{group_id}_bot_{random_string}@noreply.{Gitlab.config.gitlab.host}`.
   random_string = SecureRandom.hex(16)
   service_response = Users::CreateService.new(admin, { name: 'group_token', username: "group_#{group.id}_bot_#{random_string}", email: "group_#{group.id}_bot_#{random_string}@noreply.#{Gitlab.config.gitlab.host}", user_type: :project_bot }).execute
   bot = service_response.payload[:user] if service_response.success?

   # Confirm the group bot.
   bot.confirm

   # Add the bot to the group with the required role.
   group.add_member(bot, :maintainer)

   # Give the bot a personal access token.
   token = bot.personal_access_tokens.create(scopes:[:api, :write_repository], name: 'group_token')

   # Get the token value.
   gtoken = token.token
   ```

1. 생성된 그룹 액세스 토큰이 작동하는지 테스트하세요:

   1. GitLab REST API에서 `PRIVATE-TOKEN` 헤더에서 그룹 액세스 토큰을 사용합니다. 예를 들어:

      - 그룹에서 [에픽 생성](../../../api/epics.md#create-an-epic)
      - 그룹의 프로젝트 중 하나에서 [프로젝트 파이프라인 생성](../../../api/pipelines.md#create-a-new-pipeline)
      - 그룹의 프로젝트 중 하나에서 [이슈 생성](../../../api/issues.md#create-an-issue)

   1. 그룹 토큰을 사용하여 HTTPS를 사용하여 [그룹의 프로젝트 복제](../../../topics/git/clone.md#clone-with-https)

## 액세스 토큰 보기 {#view-your-access-tokens}

{{< history >}}

- IP 주소 보기 기능이 GitLab 17.8에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/428577)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `pat_ip`(으)로 지정됩니다. 17.9에서 기본적으로 활성화됩니다.
- IP 주소 보기 기능이 GitLab 17.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/513302)해졌습니다. 기능 플래그 `pat_ip`이 제거되었습니다.

{{< /history >}}

그룹 액세스 토큰 페이지에는 액세스 토큰에 대한 정보가 표시됩니다.

이 페이지에서 다음 작업을 수행할 수 있습니다:

- 그룹 액세스 토큰을 생성, 교체 및 해지합니다.
- 모든 활성 및 비활성 그룹 액세스 토큰을 봅니다.
- 범위, 할당된 역할 및 만료 날짜를 포함한 토큰 정보를 봅니다.
- 사용 날짜 및 마지막 5개의 서로 다른 연결 IP 주소를 포함한 사용 정보를 봅니다.
  > [!note]
  > GitLab은 토큰이 Git 작업을 수행하거나 [REST](../../../api/rest/_index.md) 또는 [GraphQL](../../../api/graphql/_index.md) API를 사용하여 작업을 인증할 때 토큰 사용 정보를 주기적으로 업데이트합니다. 토큰 사용 시간은 10분마다 업데이트되며, 토큰 사용 IP 주소는 1분마다 업데이트됩니다.

그룹 액세스 토큰을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **액세스 토큰**을(를) 선택합니다.

활성 및 사용 가능한 액세스 토큰은 **활성 그룹 액세스 토큰** 섹션에 저장됩니다. 만료되었거나, 교체되었거나, 해지된 토큰은 **비활성 그룹 액세스 토큰** 섹션에 저장됩니다.

## 그룹 액세스 토큰 교체 {#rotate-a-group-access-token}

{{< history >}}

- 만료되고 해지된 토큰을 볼 수 있는 기능이 GitLab 17.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/462217)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `retain_resource_access_token_user_after_revoke`(으)로 지정됩니다. 기본적으로 비활성화되었습니다.
- 만료되고 해지된 토큰을 자동으로 삭제될 때까지 볼 수 있는 기능이 GitLab 17.9에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/471683)해졌습니다. 기능 플래그 `retain_resource_access_token_user_after_revoke`이 제거되었습니다.

{{< /history >}}

토큰을 교체하여 원본과 동일한 권한 및 범위를 가진 새 토큰을 생성합니다. 원본 토큰은 즉시 비활성화되며 GitLab은 감사 목적상 두 버전을 모두 유지합니다. 액세스 토큰 페이지에서 활성 및 비활성 토큰을 모두 볼 수 있습니다.

GitLab Self-Managed 및 GitLab Dedicated에서 [비활성 토큰의 보존 기간](../../../administration/settings/account_and_limit_settings.md#inactive-project-and-group-access-token-retention-period)을(를) 수정할 수 있습니다.

> [!warning]
> 이 작업은 실행 취소할 수 없습니다. 교체된 액세스 토큰을 사용하는 도구는 새 토큰을 참조할 때까지 작동이 중지됩니다.

그룹 액세스 토큰을 교체하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **액세스 토큰**을(를) 선택합니다.
1. 관련 토큰에 대해 **교체**({{< icon name="retry" >}})를 선택합니다.
1. 확인 대화에서 **교체**를 선택합니다.

## 그룹 액세스 토큰 해지 {#revoke-a-group-access-token}

{{< history >}}

- 만료되고 해지된 토큰을 볼 수 있는 기능이 GitLab 17.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/462217)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `retain_resource_access_token_user_after_revoke`(으)로 지정됩니다. 기본적으로 비활성화되었습니다.
- 만료되고 해지된 토큰을 자동으로 삭제될 때까지 볼 수 있는 기능이 GitLab 17.9에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/471683)해졌습니다. 기능 플래그 `retain_resource_access_token_user_after_revoke`이 제거되었습니다.

{{< /history >}}

토큰을 해지하여 즉시 무효화하고 추가 사용을 방지합니다. 해지된 토큰은 즉시 삭제되지 않지만 토큰 목록을 필터링하여 활성 토큰만 표시할 수 있습니다. 기본적으로 GitLab은 해지된 그룹 및 프로젝트 액세스 토큰을 30일 후에 삭제합니다. 자세한 내용은 [비활성 토큰 보존](../../../administration/settings/account_and_limit_settings.md#inactive-project-and-group-access-token-retention-period)을(를) 참조하세요.

> [!warning]
> 이 작업은 실행 취소할 수 없습니다. 해지된 액세스 토큰을 사용하는 도구는 새 토큰을 추가할 때까지 작동이 중지됩니다.

그룹 액세스 토큰을 해지하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **액세스 토큰**을(를) 선택합니다.
1. 관련 토큰에 대해 **해지**({{< icon name="remove" >}})를 선택합니다.
1. 확인 대화에서 **해지**를 선택합니다.

## 액세스 토큰 만료 {#access-token-expiration}

개인, 그룹 및 프로젝트 액세스 토큰은 만료 날짜의 자정 UTC에 만료됩니다. 만료된 후에는 더 이상 요청을 인증하는 데 사용할 수 없습니다.

새 액세스 토큰은 만료 날짜를 가져야 합니다. 토큰 생성 중에 만료 날짜를 명시적으로 설정하지 않으면 현재 날짜로부터 365일의 만료 날짜가 적용됩니다. GitLab Ultimate에서 관리자는 액세스 토큰의 [최대 허용 수명](../../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens)을(를) 구성할 수 있습니다.

GitLab 버전 및 제공 서비스에 따라 기존 액세스 토큰이 GitLab 버전을 업그레이드할 때 만료 날짜가 자동으로 적용될 수 있습니다. 자세한 내용은 [만료되지 않는 액세스 토큰](../../../update/deprecations.md#non-expiring-access-tokens)을(를) 참조하세요.

### 그룹 액세스 토큰 만료 이메일 {#group-access-token-expiry-emails}

{{< history >}}

- 60일 및 30일 만료 알림이 GitLab 17.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/464040)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `expiring_pats_30d_60d_notifications`(으)로 지정됩니다. 기본적으로 비활성화되었습니다.
- 60일 및 30일 알림이 GitLab 17.7에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/173792)해졌습니다. 기능 플래그 `expiring_pats_30d_60d_notifications`이 제거되었습니다.
- 상속된 그룹 멤버에 대한 알림이 GitLab 17.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/463016)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `pat_expiry_inherited_members_notification`(으)로 지정됩니다. 기본적으로 비활성화되었습니다.
- 기능 플래그 `pat_expiry_inherited_members_notification`은 GitLab 17.10에서 [기본적으로 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/393772)됩니다.
- 기능 플래그 `pat_expiry_inherited_members_notification`은 GitLab `17.11`에서 제거되었습니다.

{{< /history >}}

GitLab은 매일 오전 1:00 UTC에 곧 만료될 그룹 액세스 토큰을 식별하기 위해 정기적인 확인을 실행합니다. 소유자 역할이 있는 직접 멤버는 토큰이 만료되기 7일 전에 이메일로 알림을 받습니다. GitLab 17.6 이상에서는 토큰이 만료되기 30일 및 60일 전에도 알림이 전송됩니다.

GitLab 17.7 이상에서는 소유자 역할이 있는 상속된 멤버도 이 이메일을 받을 수 있습니다. 모든 그룹의 경우 [GitLab 인스턴스](../../../administration/settings/email.md#group-and-project-access-token-expiry-emails-to-inherited-members)에서 또는 [특정 그룹](../manage.md#expiry-emails-for-group-and-project-access-tokens)에서 이를 구성할 수 있습니다. 상위 그룹에 적용되는 경우 이 설정은 모든 하위 그룹 및 프로젝트에 상속됩니다.

만료된 토큰은 자동으로 삭제될 때까지 비활성 그룹 액세스 토큰 섹션에 나타납니다. GitLab Self-Managed에서 [보존 기간](../../../administration/settings/account_and_limit_settings.md#inactive-project-and-group-access-token-retention-period)을(를) 수정할 수 있습니다.

## 그룹용 봇 사용자 {#bot-users-for-groups}

그룹 액세스 토큰을 생성하면 GitLab은 봇 사용자를 생성하고 토큰과 연결합니다.

봇 사용자는 다음과 같은 특성을 가집니다:

- 관련 액세스 토큰의 역할 및 범위와 일치하는 권한이 부여됩니다.
- 그룹의 멤버이며 하위 그룹 및 프로젝트의 멤버십을 상속하지만 다른 그룹이나 프로젝트에 직접 추가할 수 없습니다.
- [청구 불가능한 사용자](../../../subscriptions/manage_seats.md#criteria-for-non-billable-users)이며 라이선스 제한에 계산되지 않습니다.
- 그들의 기여는 봇 사용자 계정과 연결됩니다.
- 제거하면 그들의 기여는 [고스트 사용자](../../profile/account/delete_account.md#associated-records)로 이동됩니다.

봇 사용자가 생성될 때 다음 특성이 정의됩니다:

| 속성 | 값                                                                                                | 예제 |
| --------- | ---------------------------------------------------------------------------------------------------- | ------- |
| 이름      | 관련 액세스 토큰의 이름입니다.                                                             | `Main token - Read registry` |
| 사용자 이름  | 이 형식으로 생성됨: `group_{group_id}_bot_{random_string}`                                     | `group_123_bot_4ffca233d8298ea1` |
| 이메일     | 이 형식으로 생성됨: `group_{group_id}_bot_{random_string}@noreply.{Gitlab.config.gitlab.host}` | `group_123_bot_4ffca233d8298ea1@noreply.example.com` |

## 그룹 및 프로젝트 액세스 토큰 생성 제한 {#restrict-the-creation-of-group-and-project-access-tokens}

잠재적 남용을 제한하기 위해 사용자가 그룹 및 프로젝트 액세스 토큰을 생성하지 못하도록 제한할 수 있습니다. 이 제한은 모든 하위 그룹 및 해당 프로젝트를 포함한 전체 그룹에 적용됩니다. 기존 토큰은 만료되거나 해지될 때까지 유효합니다.

사전 요구 사항:

- 그룹에 대한 소유자 역할이 있어야 합니다.
- 그룹은 최상위 그룹이어야 합니다.
- GitLab.com에서 그룹은 GitLab Premium 또는 Ultimate 구독을 가져야 합니다.

액세스 토큰 생성을 제한하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **사용자는 이 그룹에서 그룹 액세스 토큰 및 프로젝트 액세스 토큰을 생성할 수 있습니다** 확인란을 선택 취소합니다.
1. **변경 사항 저장**을 선택합니다.

## 관련 항목 {#related-topics}

- [개인 액세스 토큰](../../profile/personal_access_tokens.md)
- [프로젝트 액세스 토큰](../../project/settings/project_access_tokens.md)
- [그룹 액세스 토큰 API](../../../api/group_access_tokens.md)
