---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 엔터프라이즈 사용자
description: 도메인 인증 및 중앙화된 엔터프라이즈 컨트롤을 통해 조직 사용자를 관리합니다.
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

엔터프라이즈 사용자는 표준 GitLab 사용자와 유사하지만 조직에서 관리합니다. 각 엔터프라이즈 사용자는 특정 최상위 그룹에 의해 청구되고 관리됩니다. 엔터프라이즈 사용자를 청구하려면 그룹 도메인을 확인하고 활성 [구독](../../subscriptions/_index.md)이 있어야 합니다.

구독이 만료되거나 취소되면:

- 기존 엔터프라이즈 사용자는 그룹의 엔터프라이즈 사용자로 유지됩니다.
- 그룹 소유자는 엔터프라이즈 사용자를 관리할 수 없습니다.
- 사용자 계정의 기본 이메일은 확인된 도메인에서 가져와야 합니다.
- 새 엔터프라이즈 사용자는 구독이 갱신될 때까지 그룹에 연결할 수 없습니다.

## 그룹 도메인 관리 {#manage-group-domains}

GitLab.com 사용자를 엔터프라이즈 사용자로 청구하려면 도메인 소유권을 추가하고 확인해야 합니다. 그룹 도메인은 최상위 그룹에 추가되며 그룹의 모든 하위 그룹 및 프로젝트에 적용됩니다.

각 그룹에는 여러 도메인이 있을 수 있지만 한 번에 각 도메인은 하나의 그룹하고만 연결할 수 있습니다. 도메인을 다른 유료 그룹으로 이동하면 모든 엔터프라이즈 사용자가 새 그룹에 의해 자동으로 청구됩니다.

그룹 도메인은 최상위 그룹의 프로젝트에 연결됩니다. 연결된 프로젝트는 도메인을 확인하기 위해 [GitLab Pages](../project/pages/_index.md)가 활성화되어야 하지만 GitLab Pages 웹사이트를 만들거나 배포할 필요는 없습니다. GitLab.com에서는 모든 프로젝트에 대해 GitLab Pages가 기본적으로 활성화되어 있으므로 구성이 필요하지 않습니다.

도메인이 프로젝트에 연결되어 있더라도 모든 중첩 하위 그룹 및 프로젝트를 포함하여 전체 그룹 계층 구조에서 사용 가능합니다. 연결된 프로젝트의 [유지보수 담당자 또는 소유자 역할](../permissions.md#project-permissions) 멤버는 도메인을 수정하거나 제거할 수 있습니다. 이 프로젝트가 삭제되면 연결된 도메인도 제거됩니다.

그룹 도메인에 대한 자세한 내용은 [에픽 5299](https://gitlab.com/groups/gitlab-org/-/epics/5299)를 참조하세요.

### 그룹 도메인 추가 {#add-group-domains}

사전 요구 사항:

- 최상위 그룹의 소유자 역할이 있어야 합니다.
- 확인하려는 이메일 도메인과 일치하는 사용자 정의 도메인 `example.com` 또는 하위 도메인 `subdomain.example.com`을 제어해야 합니다.
- 도메인 소유권을 증명하기 위해 도메인에 대한 DNS `TXT` 레코드를 만들 수 있어야 합니다.
- 최상위 그룹에 [GitLab Pages](../project/pages/_index.md)를 사용하는 전용 프로젝트가 있어야 합니다.

그룹에 사용자 정의 도메인을 추가하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **도메인 인증**을 선택합니다.
1. 오른쪽 위에서 **도메인 추가**를 선택합니다.
1. 도메인 설정을 구성합니다:
   - **도메인**: 도메인 이름을 입력합니다.
   - **프로젝트**: 그룹의 기존 프로젝트에 링크합니다.
   - **인증서**: 인증서 옵션을 선택합니다:
     - SSL/TLS 인증서가 없거나 사용하지 않으려면 **Let's Encrypt를 사용하여 인증서를 자동으로 관리**를 선택합니다.
     - 자신의 SSL/TLS 인증서를 제공하려면 **인증 정보 수동 입력**을 선택합니다.

       > [!note]
       > 도메인 확인에는 유효한 인증서가 필요하지 않습니다. GitLab Pages를 사용하지 않으면 자체 서명된 인증서 경고를 무시할 수 있습니다.

1. **도메인 추가**를 선택합니다. GitLab이 도메인 정보를 저장합니다.
1. 도메인 소유권을 확인합니다:
   1. **TXT**에서 확인 코드를 복사합니다.
   1. 도메인 공급자 DNS 설정에서 확인 코드를 `TXT` 레코드로 추가합니다.
   1. GitLab의 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
   1. **설정** > **도메인 인증**을 선택합니다.
   1. 도메인 이름 옆에서 **검증 재시도** ({{< icon name="retry" >}})를 선택합니다.

확인이 성공하면 도메인 상태가 **검증됨**으로 변경되고 엔터프라이즈 사용자 관리에 사용할 수 있습니다.

> [!note]
> 일반적으로 DNS 전파는 몇 분 내에 완료되지만 최대 24시간이 걸릴 수 있습니다. 완료될 때까지 도메인은 GitLab에서 확인되지 않은 상태로 유지됩니다.
>
> 7일 후에도 도메인이 여전히 확인되지 않으면 GitLab이 자동으로 도메인을 제거합니다.
>
> 확인 후 GitLab은 정기적으로 도메인을 재검증합니다. 잠재적 문제를 피하려면 도메인 공급자에서 `TXT` 레코드를 유지하세요.

### 그룹 도메인 보기 {#view-group-domains}

그룹의 모든 사용자 정의 도메인을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **도메인 인증**을 선택합니다.

### 그룹 도메인 편집 {#edit-group-domains}

그룹의 사용자 정의 도메인을 편집하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **도메인 인증**을 선택합니다.
1. 도메인 이름 옆에서 **편집** ({{< icon name="pencil" >}})을 선택합니다.

여기서 다음을 수행할 수 있습니다:

- 사용자 정의 도메인을 봅니다.
- 추가할 DNS 레코드를 봅니다.
- TXT 확인 항목을 봅니다.
- 검증을 재시도합니다.
- 인증서 설정을 편집합니다.

### 그룹 도메인 삭제 {#delete-group-domains}

그룹 도메인을 삭제하면 그룹의 엔터프라이즈 사용자에게 영향을 줄 수 있습니다. 도메인을 삭제한 후:

- 기존 엔터프라이즈 사용자는 그룹의 엔터프라이즈 사용자로 유지됩니다.
- 다른 도메인이 검증될 때까지 새 엔터프라이즈 사용자를 그룹에 연결할 수 없습니다.

그룹의 사용자 정의 도메인을 삭제하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **도메인 인증**을 선택합니다.
1. 도메인 이름 옆에서 **도메인 제거** ({{< icon name="remove" >}})를 선택합니다.
1. 메시지가 표시되면 **도메인 삭제**를 선택합니다.

## 엔터프라이즈 사용자 관리 {#manage-enterprise-users}

표준 [그룹 멤버 권한](../permissions.md#group-permissions) 외에도 최상위 그룹의 소유자는 그룹의 엔터프라이즈 사용자를 관리할 수 있습니다.

[API를 사용](../../api/group_enterprise_users.md)하여 엔터프라이즈 사용자와 상호 작용할 수 있습니다.

### 엔터프라이즈 사용자의 자동 청구 {#automatic-claims-of-enterprise-users}

사전 요구 사항:

- 최상위 그룹이 [그룹 도메인을 추가하고 확인](#add-group-domains)해야 합니다.
- 사용자의 기본 이메일이 확인된 도메인과 일치해야 합니다.
- 사용자 계정이 다음 조건 중 하나 이상을 충족해야 합니다:
  - 사용자 계정이 2021년 2월 1일 이후에 생성되었습니다.
  - 사용자 계정에 조직의 그룹과 연결된 SAML 또는 SCIM ID가 있습니다.
  - 사용자 계정에 그룹 ID와 일치하는 `provisioned_by_group_id` 특성이 있습니다.
  - 사용자 계정이 2021년 2월 1일 이후에 구매하거나 갱신한 그룹 구독의 멤버입니다.

그룹이 도메인의 소유권을 확인한 후 해당 도메인의 이메일 주소를 가진 사용자는 자동으로 그룹에 의해 엔터프라이즈 사용자로 청구됩니다. 그룹 소유자의 직접적인 작업이 필요하지 않습니다.

다른 도메인의 이메일 주소를 가진 기존 그룹 멤버는 기존 액세스를 유지하지만 그룹 소유자가 관리할 수 없습니다. 이러한 사용자를 청구하려면 기본 이메일 주소를 그룹 도메인과 일치하도록 업데이트해야 합니다.

청구 프로세스는 트리거되는 데 최대 4일이 걸릴 수 있습니다. 그룹 도메인을 수동으로 [재검증](#edit-group-domains)하여 이 프로세스를 즉시 실행할 수 있습니다.

그룹이 엔터프라이즈 사용자를 청구한 후:

- 사용자는 [환영 이메일](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/app/views/notify/user_associated_with_enterprise_group_email.html.haml)을 받습니다.
- 그룹 ID가 사용자의 `enterprise_group_id` 특성에 추가됩니다.

### 엔터프라이즈 사용자 식별 {#identifying-enterprise-users}

[멤버 목록](../group/_index.md#filter-and-sort-members-in-a-group)에서 엔터프라이즈 사용자를 식별할 수 있습니다. 모든 엔터프라이즈 사용자는 이름 옆에 `Enterprise` 배지가 있습니다.

청구 가능한 사용자 목록을 분석하여 엔터프라이즈 그룹 멤버가 아닌 멤버를 발견할 수 있습니다: `https://gitlab.com/groups/<group_id>/-/usage_quotas#seats-quota-tab`.

이 목록에서 엔터프라이즈 사용자가 아닌 사용자는 다음 중 하나를 가지고 있습니다:

- 확인되지 않은 도메인의 이메일 주소입니다.
- 표시되는 이메일 주소가 없습니다.

### 인증 방법 제한 {#restrict-authentication-methods}

엔터프라이즈 사용자가 사용할 수 있는 특정 인증 방법을 제한하여 사용자의 보안 범위를 줄일 수 있습니다.

- [비밀번호 인증 비활성화](../group/saml_sso/_index.md#disable-password-and-passkey-authentication-for-enterprise-users).
- [개인 액세스 토큰 비활성화](../profile/personal_access_tokens.md#disable-personal-access-tokens-for-enterprise-users).
- [SSH 키 비활성화](../ssh_advanced.md#disable-ssh-keys-for-enterprise-users).
- [2단계 인증 비활성화](../../security/two_factor_authentication.md#enterprise-users).

### 개인 스니펫 제한 {#restrict-personal-snippets}

엔터프라이즈 사용자가 개인 네임스페이스에서 [개인 스니펫](../snippets.md)을 만드는 것을 방지할 수 있습니다. 자세한 내용은 [엔터프라이즈 사용자를 위한 개인 스니펫 제한](../group/manage.md#restrict-personal-snippets-for-enterprise-users)을 참조하세요.

### 그룹 및 프로젝트 생성 제한 {#restrict-group-and-project-creation}

엔터프라이즈 사용자의 그룹 및 프로젝트 생성을 제한할 수 있으며, 이는 다음을 정의하는 데 도움이 됩니다:

- 엔터프라이즈 사용자가 최상위 그룹을 만들 수 있는지 여부입니다.
- 각 엔터프라이즈 사용자가 만들 수 있는 최대 개인 프로젝트 수입니다.

이러한 제한은 SAML 응답에서 정의됩니다. 자세한 내용은 [SAML 응답에서 엔터프라이즈 사용자 설정 구성](../group/saml_sso/_index.md#configure-enterprise-user-settings-from-saml-response)을 참조하세요.

### 프로비저닝된 사용자의 이메일 확인 우회 {#bypass-email-confirmation-for-provisioned-users}

기본적으로 SAML 또는 SCIM으로 프로비저닝된 사용자에게는 신원을 확인하기 위해 확인 이메일이 전송됩니다. 대신 사용자 정의 도메인으로 GitLab을 구성하고 GitLab이 사용자 계정을 자동으로 확인하도록 할 수 있습니다. 사용자는 여전히 엔터프라이즈 사용자 환영 이메일을 받습니다.

자세한 내용은 [확인된 도메인으로 사용자 이메일 확인 우회](../group/saml_sso/_index.md#bypass-user-email-confirmation-with-verified-domains)를 참조하세요.

### 엔터프라이즈 사용자의 이메일 주소 보기 {#view-the-email-addresses-for-an-enterprise-user}

사전 요구 사항:

- 최상위 그룹의 소유자 역할이 있어야 합니다.

엔터프라이즈 사용자의 이메일 주소를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **관리** > **멤버**를 선택합니다.
1. 엔터프라이즈 사용자의 이름 위에 마우스를 올립니다.

[그룹 멤버 API](../../api/group_members.md) 및 [프로젝트 멤버 API](../../api/project_members.md)를 사용하여 사용자 정보에 액세스할 수 있습니다. 그룹의 엔터프라이즈 사용자의 경우 이 정보에는 사용자의 이메일 주소가 포함됩니다.

### 엔터프라이즈 사용자의 이메일 주소 변경 {#change-the-email-addresses-for-an-enterprise-user}

엔터프라이즈 사용자는 다른 GitLab 사용자와 동일한 프로세스를 따라 [기본 이메일 주소를 변경](../profile/_index.md#change-your-primary-email)할 수 있습니다. 새 이메일 주소는 확인된 도메인에서 가져와야 합니다. 조직에 확인된 도메인이 없으면 엔터프라이즈 사용자는 기본 이메일 주소를 변경할 수 없습니다.

그룹 소유자는 [그룹 엔터프라이즈 사용자 API](../../api/group_enterprise_users.md#update-an-enterprise-user)로 그룹의 엔터프라이즈 사용자의 이메일 주소를 수정할 수 있습니다.

GitLab 지원만 기본 이메일 주소를 확인되지 않은 도메인의 이메일 주소로 변경할 수 있습니다. 이 작업은 [엔터프라이즈 사용자를 해제](#release-an-enterprise-user)합니다.

### 엔터프라이즈 사용자 삭제 {#delete-an-enterprise-user}

사전 요구 사항:

- 최상위 그룹에 대한 소유자 역할이 있어야 합니다.

[그룹 엔터프라이즈 사용자 API](../../api/group_enterprise_users.md#delete-an-enterprise-user)를 사용하여 엔터프라이즈 사용자를 삭제하고 GitLab에서 계정을 영구적으로 제거할 수 있습니다. 이 작업은 사용자를 해제하는 것과 다르며, 사용자의 엔터프라이즈 관리 기능만 제거합니다. 사용자를 삭제할 때 다음 중 하나를 선택할 수 있습니다:

- 사용자 및 해당 [기여](../profile/account/delete_account.md#associated-records)를 영구적으로 삭제합니다.
- 기여를 유지하고 가상 사용자에게 양도합니다.

### 엔터프라이즈 사용자 해제 {#release-an-enterprise-user}

엔터프라이즈 사용자 계정에서 엔터프라이즈 관리 기능을 제거할 수 있습니다. 예를 들어 사용자가 회사를 떠난 후 GitLab 계정을 유지하려는 경우 이 작업을 수행해야 할 수 있습니다. 사용자를 해제하면 계정 역할 및 권한은 유지되지만 그룹 소유자는 해당 사용자에 대한 관리 옵션을 잃습니다. 예를 들어 해제된 사용자는 그룹 소유자가 이전에 비활성화한 인증 방법에 액세스할 수 있습니다.

계정을 영구적으로 제거해야 하는 경우 대신 [사용자를 삭제](#delete-an-enterprise-user)하세요.

개별 엔터프라이즈 사용자를 그룹에서 해제하려면 GitLab 지원팀이 사용자의 기본 이메일 주소를 확인되지 않은 도메인의 이메일로 업데이트해야 합니다. 이 작업은 계정을 자동으로 해제합니다.

청구된 모든 엔터프라이즈 사용자를 해제하려면 그룹 도메인이 아닌 [그룹 자체를 삭제](../group/_index.md#schedule-a-group-for-deletion)할 수 있습니다. 이는 엔터프라이즈 사용자 기능을 테스트하는 조직에 유용합니다.

그룹 소유자가 기본 이메일을 변경할 수 있도록 하는 것은 [이슈 412966](https://gitlab.com/gitlab-org/gitlab/-/issues/412966)에서 제안되었습니다.

### 휴면 엔터프라이즈 사용자 재활성화 {#dormant-enterprise-user-reactivation}

[휴면 멤버 자동 제거](../group/moderate_users.md#automatically-remove-dormant-members)가 활성화되면 휴면 엔터프라이즈 사용자는 그룹에서 제거되지 않고 비활성화됩니다. 이러한 사용자가 다시 로그인하면 계정이 재활성화됩니다.

그러나 엔터프라이즈 그룹에서 [제한된 액세스](../../subscriptions/manage_seats.md#restricted-access)가 활성화되고 사용 가능한 사용자가 없으면 사용자는 재활성화되는 대신 승인 대기 중으로 설정됩니다. 기존 그룹 및 프로젝트 멤버십이 유지됩니다.

### 엔터프라이즈 사용자를 위한 이메일 주소 숨기기 {#hide-email-addresses-for-enterprise-users}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197475)되었습니다.

{{< /history >}}

그룹 소유자는 그룹의 모든 엔터프라이즈 사용자의 공개 이메일 주소를 프로필 페이지에서 숨길 수 있습니다. 소유자는 [멤버 페이지에서 이메일 주소를 볼 수 있습니다](#view-the-email-addresses-for-an-enterprise-user).

사전 요구 사항:

- 최상위 그룹의 소유자 역할이 있어야 합니다.
- 그룹이 [도메인 인증](#manage-group-domains)을 구성해야 합니다.

엔터프라이즈 사용자의 이메일 주소를 숨기려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **엔터프라이즈 사용자** 아래에서 **공개 프로필에서 이메일 주소 숨기기** 체크박스를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 엔터프라이즈 사용자가 자신의 계정을 삭제하는 것을 방지 {#prevent-enterprise-users-from-deleting-their-own-account}

{{< history >}}

- [GitLab 19.2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241926)에 [플래그](../../administration/feature_flags/_index.md) `deleting_account_disabled_for_enterprise_users`와 함께 도입되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 19.4에서 [일반적으로 사용 가능합니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248605). 기능 플래그 `deleting_account_disabled_for_enterprise_users`이 제거되었습니다.

{{< /history >}}

그룹 소유자는 그룹의 엔터프라이즈 사용자가 자신의 계정을 삭제하는 것을 방지할 수 있습니다. 이 설정이 비활성화되면 엔터프라이즈 사용자는 사용자 설정에서 계정을 삭제할 수 없습니다. 계정 삭제 섹션에는 계정 삭제가 허용되지 않는다는 메시지가 표시됩니다. 그룹 소유자는 [엔터프라이즈 사용자를 삭제](#delete-an-enterprise-user)할 수 있습니다.

사전 요구 사항:

- 최상위 그룹의 소유자 역할입니다.
- 그룹이 [도메인 인증](#manage-group-domains)을 구성해야 합니다.

엔터프라이즈 사용자가 자신의 계정을 삭제하는 것을 방지하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **엔터프라이즈 사용자** 아래에서 **기업 사용자가 자신의 계정을 삭제하도록 허용** 체크박스를 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

### 엔터프라이즈 사용자를 위한 Extension Marketplace 활성화 {#enable-the-extension-marketplace-for-enterprise-users}

{{< history >}}

- [GitLab 17.4](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/161819)에서 [베타](../../policy/development_stages_support.md#beta)로 [기능 플래그](../../administration/feature_flags/_index.md)와 함께 `web_ide_oauth` 및 `web_ide_extensions_marketplace`라는 이름으로 도입되었습니다. 기본적으로 비활성화되었습니다.
- `web_ide_oauth` GitLab 17.4에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163181)되었습니다.
- `web_ide_extensions_marketplace` GitLab 17.4에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/459028)되었습니다.
- `web_ide_oauth` GitLab 17.5에서 [제거](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/167464)되었습니다.
- [GitLab 17.10](https://gitlab.com/gitlab-org/gitlab/-/issues/508996)에서 `vscode_extension_marketplace_settings` [기능 플래그](../../administration/feature_flags/_index.md)가 도입되었습니다. 기본적으로 비활성화되었습니다.
- `web_ide_extensions_marketplace` GitLab 17.11에서 [GitLab Self-Managed에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184662)되었으며, `vscode_extension_marketplace_settings` [GitLab.com 및 GitLab Self-Managed에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184662)되었습니다.
- GitLab 18.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192659)하게 되었습니다. 기능 플래그 `web_ide_extensions_marketplace` 및 `vscode_extension_marketplace_settings`이 제거되었습니다.

{{< /history >}}

VS Code Extension Marketplace는 Web IDE 및 Workspaces의 기능을 강화하는 확장 프로그램에 액세스할 수 있도록 합니다. 최상위 그룹 소유자는 그룹의 엔터프라이즈 사용자를 위한 마켓플레이스 액세스를 제어할 수 있습니다.

사전 요구 사항:

- 최상위 그룹의 소유자 역할이 있어야 합니다.

엔터프라이즈 사용자를 위한 Extension Marketplace를 활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **엔터프라이즈 사용자** 아래에서 **extension marketplace 활성화** 체크박스를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 문제 해결 {#troubleshooting}

### 엔터프라이즈 사용자를 위한 2단계 인증을 비활성화할 수 없음 {#cannot-disable-two-factor-authentication-for-an-enterprise-user}

사용자에게 **Enterprise** 배지가 없으면 그룹 소유자는 해당 계정에 대해 2FA를 비활성화하거나 재설정할 수 없습니다. 대신 소유자는 엔터프라이즈 사용자에게 사용 가능한 [복구 옵션](../profile/account/two_factor_authentication_troubleshooting.md#recovery-options-and-2fa-reset)을 고려하도록 말해야 합니다.

## 관련 항목 {#related-topics}

- [GitLab Pages 사용자 정의 도메인](../project/pages/custom_domains_ssl_tls_certification/_index.md).
