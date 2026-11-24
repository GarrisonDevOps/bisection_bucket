---
stage: Fulfillment
group: Seat Management
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: SCIM 문제 해결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 섹션에는 발생할 수 있는 문제에 대한 가능한 솔루션이 포함되어 있습니다.

## 제거한 후 사용자를 추가할 수 없음 {#user-cannot-be-added-after-they-are-removed}

사용자를 제거하면 그룹에서 제거되지만 계정은 삭제되지 않습니다([액세스 제거](scim_setup.md#remove-access) 참조).

사용자가 SCIM 앱에 다시 추가되면 GitLab은 사용자가 이미 존재하기 때문에 새 사용자를 만들지 않습니다.

사용자가 SCIM을 통해 프로비전 해제되면 GitLab은 해당 액세스를 제거하지만 연결된 SAML ID는 제거하지 않습니다. 해당 사용자가 SCIM 앱에 다시 추가되면:

- 해당 SCIM ID `active` 특성이 `true`로 설정됩니다.
- SSO를 사용하여 로그인할 수 있습니다.

> [!note]
> 드물게 이 동작이 일반적으로 사용 가능하기 전에 프로비전 해제된 사용자는 SAML ID를 다시 연결해야 할 수 있습니다. 다시 추가된 후 로그인에 문제가 발생하면 [기존 GitLab.com 계정에 SAML을 연결](_index.md#link-saml-to-your-existing-gitlabcom-account)할 수 있습니다.

### GitLab Self-Managed {#gitlab-self-managed}

GitLab Self-Managed의 경우 해당 인스턴스의 관리자가 [사용자 ID를 직접 추가](../../../administration/admin_area.md#user-identities)할 수 있습니다. 관리자가 여러 ID를 다시 추가해야 하는 경우 시간을 절약할 수 있습니다.

## 사용자가 로그인할 수 없음 {#user-cannot-sign-in}

다음은 사용자가 로그인할 수 없는 문제에 대한 가능한 솔루션입니다:

- 사용자가 SCIM 앱에 추가되었는지 확인하세요.
- `User is not linked to a SAML account` 오류가 수신되면 사용자가 이미 GitLab에 존재합니다. 사용자에게 [SCIM 및 SAML ID 연결](scim_setup.md#link-scim-and-saml-identities) 지침을 따르도록 하세요. 또는 GitLab Self-Managed 관리자가 [사용자 ID를 추가](../../../administration/admin_area.md#user-identities)할 수 있습니다.
- GitLab에 저장된 **ID** (`extern_uid`) 값은 `id` 또는 `externalId`가 변경될 때마다 SCIM에 의해 업데이트됩니다. 사용자는 로그인 방법의 GitLab 식별자(`extern_uid`)가 SAML에서 전송한 `NameId` 같은 공급자가 전송한 ID와 일치하지 않으면 로그인할 수 없습니다. 이 값은 SCIM이 `id`의 사용자와 일치하는 데도 사용되며, `id` 또는 `externalId` 값이 변경될 때마다 SCIM에 의해 업데이트됩니다.
- GitLab.com에서는 SCIM `id`과 SCIM `externalId`이 SAML `NameId`과 같은 값으로 구성되어야 합니다. [디버깅 도구](troubleshooting.md#saml-debugging-tools)를 사용하여 SAML 응답을 추적하고 [SAML 문제 해결](troubleshooting.md) 정보에 대해 오류를 확인할 수 있습니다.

## 사용자의 SAML `NameId`이 SCIM `externalId`과 일치하는지 확실하지 않음 {#unsure-if-users-saml-nameid-matches-the-scim-externalid}

사용자의 SAML `NameId`이 SCIM `externalId`과 일치하는지 확인하려면:

- 관리자는 **운영자** 영역을 사용하여 [사용자의 SCIM ID를 나열](../../../administration/admin_area.md#user-identities)할 수 있습니다.
- 그룹 소유자는 그룹 SAML SSO 설정 페이지에서 사용자 목록과 각 사용자에 대해 저장된 식별자를 볼 수 있습니다.
- [SCIM API](../../../api/scim.md)를 사용하여 GitLab이 저장한 `extern_uid`을 수동으로 검색하고 [SAML API](../../../api/saml.md)의 각 사용자 값과 비교할 수 있습니다.
- 사용자에게 [SAML Tracer](troubleshooting.md#saml-debugging-tools)를 사용하도록 하고 `extern_uid`를 SAML `NameId`로 반환된 값과 비교하세요.

## 일치하지 않는 SCIM `extern_uid` 및 SAML `NameId` {#mismatched-scim-extern_uid-and-saml-nameid}

값이 변경되었거나 다른 필드에 매핑해야 하는 경우 다음이 같은 필드에 매핑되어야 합니다:

- `extern_Id`
- `NameId`

SCIM `extern_uid`이 SAML `NameId`과 일치하지 않으면 사용자가 로그인하도록 SCIM `extern_uid`을 업데이트해야 합니다.

SCIM ID 공급자가 사용하는 필드(일반적으로 `extern_Id`)를 수정하는 경우 주의하세요. ID 공급자는 이 업데이트를 수행하도록 구성해야 합니다. 경우에 따라 ID 공급자는 업데이트를 수행할 수 없습니다. 예를 들어 사용자 조회가 실패할 때입니다.

GitLab은 이러한 ID를 사용하여 사용자를 조회합니다. ID 공급자가 이러한 필드의 현재 값을 모르면 공급자는 중복 사용자를 만들거나 예상 작업을 완료하지 못할 수 있습니다.

식별자 값을 일치시키도록 변경하려면 다음 중 하나를 수행할 수 있습니다:

- [SAML 인증 실패: 사용자가 이미 사용됨](troubleshooting.md#message-saml-authentication-failed-user-has-already-been-taken) 섹션을 기반으로 사용자가 직접 연결을 해제하고 다시 연결하도록 합니다.
- 프로비저닝이 켜져 있는 동안 SCIM 앱에서 모든 사용자를 제거하여 모든 사용자를 동시에 연결 해제합니다.

  > [!warning]
  > 이렇게 하면 최상위 그룹 및 하위 그룹의 모든 사용자 역할이 [구성된 기본 멤버십 역할](_index.md#configure-gitlab)로 재설정됩니다.

- [SAML API](../../../api/saml.md) 또는 [SCIM API](../../../api/scim.md)를 사용하여 사용자에 대해 저장된 `extern_uid`을 수동으로 수정하여 SAML `NameId` 또는 SCIM `externalId`과 일치하도록 합니다.

다음을 수행하면 안 됩니다:

- 사용자가 로그인할 수 없게 되므로 이를 잘못된 값으로 업데이트하지 마세요.
- 사용자가 잘못된 계정에 로그인되므로 잘못된 사용자에게 값을 할당하지 마세요.

또한 사용자의 기본 이메일이 SCIM ID 공급자의 이메일과 일치해야 합니다.

## SCIM 앱 변경 {#change-scim-app}

SCIM 앱이 변경될 때:

- 사용자는 [SAML 앱 변경](_index.md#change-the-identity-provider) 섹션의 지침을 따를 수 있습니다.
- ID 공급자의 관리자는 다음을 수행할 수 있습니다:
  1. SCIM 앱에서 사용자를 제거하면:
     - GitLab.com에서는 제거된 모든 사용자를 그룹에서 제거합니다.
     - GitLab Self-Managed에서는 사용자를 차단합니다.
  1. 새 SCIM 앱에 대한 동기화를 켜서 [기존 사용자를 연결](scim_setup.md#link-scim-and-saml-identities)합니다.

## SCIM 앱이 `"User has already been taken","status":409` 오류를 반환합니다 {#scim-app-returns-user-has-already-been-takenstatus409-error}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

SAML 또는 SCIM 구성 또는 공급자를 변경하면 다음 문제가 발생할 수 있습니다:

- SAML 및 SCIM ID 불일치입니다. 이 문제를 해결하려면:
  1. [사용자의 SAML `NameId`이 SCIM `extern_uid`과 일치하는지 확인](#unsure-if-users-saml-nameid-matches-the-scim-externalid)하세요.
  1. [일치하지 않는 SCIM `extern_uid` 및 SAML `NameId`을 업데이트하거나 수정](#mismatched-scim-extern_uid-and-saml-nameid)하세요.
- GitLab과 ID 공급자 SCIM 앱 간의 SCIM ID 불일치입니다. 이 문제를 해결하려면:
  1. [SCIM API](../../../api/scim.md)를 사용하면 GitLab에 저장된 사용자의 `extern_uid`을 표시하고 SCIM 앱의 사용자 `externalId`과 비교합니다.
  1. 동일한 SCIM API를 사용하여 GitLab.com의 사용자에 대한 SCIM `extern_uid`을 업데이트합니다.

## 구성원의 이메일 주소가 이 그룹에 허용되지 않음 {#the-members-email-address-is-not-allowed-for-this-group}

SCIM 프로비저닝은 HTTP 상태 `412`과 함께 실패할 수 있으며 다음 오류 메시지가 표시됩니다:

```plaintext
The member's email address is not allowed for this group. Check with your administrator.
```

이 오류는 다음 두 경우가 모두 참일 때 발생합니다:

- [도메인별 그룹 액세스 제한](../access_and_permissions.md)이 그룹에 대해 구성됩니다.
- 프로비저닝되는 사용자 계정의 이메일 도메인이 허용되지 않습니다.

이 문제를 해결하려면 다음 중 하나를 수행할 수 있습니다:

- 사용자 계정의 이메일 도메인을 허용된 도메인 목록에 추가합니다.
- 모든 도메인을 제거하여 [도메인별 그룹 액세스 제한](../access_and_permissions.md) 기능을 비활성화합니다.

## SCIM 요청에 대해 Rails 로그 검색 {#search-rails-logs-for-scim-requests}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

GitLab.com 관리자는 Kibana의 `pubsub-rails-inf-gprd-*` 인덱스를 사용하여 `api_json.log`에서 SCIM 요청을 검색할 수 있습니다. 내부 [그룹 SCIM API](../../../development/internal_api/_index.md#group-scim-api)를 기반으로 다음 필터를 사용합니다:

- `json.path`: `/scim/v2/groups/<group-path>`
- `json.params.value`: `<externalId>`

관련 로그 항목에서 `json.params.value`은 GitLab이 수신하는 SCIM 매개변수의 값을 표시합니다. SCIM 앱에서 구성된 SCIM 매개변수가 의도한 대로 GitLab에 전달되는지 확인하려면 이 값을 사용하세요.

예를 들어 이 값을 계정이 특정 세부 정보 집합으로 프로비저닝된 이유에 대한 결정적 소스로 사용합니다. 이 정보는 계정이 SCIM 앱 구성과 일치하지 않는 세부 정보로 SCIM 프로비저닝된 경우를 파악하는 데 도움이 될 수 있습니다.

## 구성원의 이메일 주소가 SCIM 로그에 연결되지 않은 오류 {#members-email-address-is-not-linked-error-in-scim-log}

GitLab.com에서 SCIM 사용자를 프로비저닝하려고 할 때 GitLab은 해당 이메일 주소를 가진 사용자가 이미 존재하는지 확인합니다. 다음 오류는 다음 경우에 표시될 수 있습니다:

- 사용자가 존재하지만 SAML ID가 연결되지 않았습니다.
- 사용자가 존재하고 SAML ID가 있으며 `active: false`로 설정된 SCIM ID가 있습니다.
- 사용자가 존재하지만 연결된 최상위 그룹의 구성원이 아니며 SAML SSO 강제가 활성화되어 있습니다.

```plaintext
The member's email address is not linked to a SAML account or has an inactive
SCIM identity.
```

이 오류 메시지는 상태 `412`과 함께 반환됩니다.

이로 인해 영향을 받는 최종 사용자가 계정에 올바르게 액세스하지 못할 수 있습니다.

첫 번째 해결 방법은:

1. 최종 사용자에게 [기존 GitLab.com 계정에 SAML을 연결](_index.md#link-saml-to-your-existing-gitlabcom-account)하도록 합니다.
1. 사용자가 이를 수행한 후 ID 공급자에서 SCIM 동기화를 시작합니다. SCIM 동기화가 동일한 오류 없이 완료되면 GitLab이 SCIM ID를 기존 사용자 계정에 성공적으로 연결했으며 사용자가 이제 SAML SSO를 사용하여 로그인할 수 있어야 합니다.

오류가 지속되면 사용자는 이미 존재하고 SAML 및 SCIM ID가 모두 있으며 `active: false`로 설정된 SCIM ID가 있을 가능성이 높습니다. 이 문제를 해결하려면:

1. 선택 사항. 처음 SCIM을 구성할 때 SCIM 토큰을 저장하지 않은 경우 [새 토큰을 생성](scim_setup.md#configure-gitlab)하세요. 새 SCIM 토큰을 생성하는 경우 ID 공급자의 SCIM 구성에서 토큰을 업데이트해야 하거나 SCIM이 작동을 중지합니다.
1. SCIM 토큰을 찾습니다.
1. API를 사용하여 [단일 SCIM 프로비저닝된 사용자를 가져옵니다](../../../development/internal_api/_index.md#get-a-single-scim-provisioned-user).
1. 반환된 정보를 확인하여 다음을 확인하세요:

   - 사용자의 식별자(`id`)와 이메일이 ID 공급자가 전송하는 것과 일치합니다.
   - `active`은 `false`로 설정됩니다.

   이 정보 중 일치하지 않는 것이 있으면 [GitLab 지원팀에 문의](https://support.gitlab.com/)하세요.
1. API를 사용하여 [SCIM 프로비저닝된 사용자의 `active` 값을 `true`으로 업데이트](../../../development/internal_api/_index.md#update-a-single-scim-provisioned-user)합니다.
1. 업데이트가 상태 코드 `204`을 반환하면 사용자에게 SAML SSO를 사용하여 로그인을 시도하도록 합니다.

## 오류: `User is pending deprovisioning` {#error-user-is-pending-deprovisioning}

{{< history >}}

- `group_scim_async_member_removal`라는 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)와 함께 GitLab 18.11에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228156)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 19.0에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/233454)되었습니다. 기능 플래그 `group_scim_async_member_removal`이 제거되었습니다.

{{< /history >}}

SCIM 프로비전 해제는 비동기식으로 처리됩니다. SCIM 사용자가 프로비전 해제되면 후속 `POST` 또는 `PATCH` SCIM 요청이 HTTP 상태 `409`과 함께 실패하고 다음 오류 메시지가 표시됩니다:

```plaintext
User is pending deprovisioning. Please wait for the user to be deprovisioned and try again later.
```

이 오류를 해결하려면 시스템이 사용자의 멤버십 레코드 처리를 완료할 때까지 기다립니다. 프로세스가 완료되면 사용자를 다시 프로비저닝할 수 있습니다.

## Azure Active Directory {#azure-active-directory}

다음 문제 해결 정보는 Azure Active Directory를 통해 프로비저닝된 SCIM에만 해당됩니다.

### SCIM 구성이 올바른지 확인 {#verify-my-scim-configuration-is-correct}

다음을 확인하세요:

- `externalId`의 일치 우선순위는 1입니다.
- `externalId`의 SCIM 값이 `NameId`의 SAML 값과 일치합니다.

다음 SCIM 매개변수를 검토하여 타당한 값을 확인하세요:

- `userName`
- `displayName`
- `emails[type eq "work"].value`

### 연결을 테스트할 때 `invalid credentials` 오류 {#invalid-credentials-error-when-testing-connection}

연결을 테스트할 때 오류가 발생할 수 있습니다:

```plaintext
You appear to have entered invalid credentials. Please confirm
you are using the correct information for an administrative account
```

`Tenant URL` 및 `secret token`이 올바르면 그룹 경로에 유효하지 않은 JSON 기본형(예: `.`)으로 간주될 수 있는 문자가 포함되어 있는지 확인하세요. 그룹 경로에서 이 문자를 제거하거나 URL 인코딩하면 일반적으로 오류가 해결됩니다.

### `(Field) can't be blank` 동기화 오류 {#field-cant-be-blank-sync-error}

프로비저닝에 대한 감사 이벤트를 확인할 때 때때로 `Namespace can't be blank, Name can't be blank, and User can't be blank.` 오류가 표시됩니다.

이 오류는 필요한 모든 필드(예: 이름 및 성)가 매핑되는 모든 사용자에 대해 존재하지 않기 때문에 발생할 수 있습니다.

해결 방법으로 대체 매핑을 시도하세요:

1. [Azure 매핑 지침](scim_setup.md#configure-attribute-mappings)을 따르세요.
1. `name.formatted` 대상 특성 항목을 삭제합니다.
1. `displayName` 소스 특성을 변경하여 `name.formatted` 대상 특성을 가지도록 합니다.

### `Failed to match an entry in the source and target systems Group 'Group-Name'` 오류 {#failed-to-match-an-entry-in-the-source-and-target-systems-group-group-name-error}

Azure의 그룹 프로비저닝은 `Failed to match an entry in the source and target systems Group 'Group-Name'` 오류와 함께 실패할 수 있습니다. 오류 응답은 GitLab URL `https://gitlab.com/users/sign_in`의 HTML 결과를 포함할 수 있습니다.

이 오류는 무해하며 그룹 프로비저닝이 켜져 있지만 GitLab SCIM 통합이 이를 지원하지 않거나 필요하지 않기 때문에 발생합니다. 오류를 제거하려면 Azure 구성 가이드의 지침을 따르세요. [Azure Active Directory 그룹을 AppName에 동기화](scim_setup.md#configure-microsoft-entra-id)하는 옵션을 비활성화합니다.

## Okta {#okta}

다음 문제 해결 정보는 Okta를 통해 프로비저닝된 SCIM에만 해당됩니다.

### `Error authenticating: null` 메시지(SCIM API 자격 증명 테스트 중) {#error-authenticating-null-message-when-testing-api-scim-credentials}

Okta SCIM 애플리케이션에서 API 자격 증명을 테스트할 때 오류가 발생할 수 있습니다:

```plaintext
Error authenticating: null
```

Okta는 사용자를 프로비저닝하거나 프로비전 해제하기 위해 GitLab 인스턴스에 연결할 수 있어야 합니다.

Okta SCIM 애플리케이션에서 SCIM **기본 URL**이 올바르고 유효한 GitLab SCIM API 엔드포인트 URL을 가리키는지 확인합니다. 다음 설명서를 확인하여 이 URL에 대한 정보를 찾습니다:

- [GitLab.com 그룹](scim_setup.md#configure-gitlab).
- [GitLab Self-Managed](../../../administration/settings/scim_setup.md#configure-gitlab).

GitLab Self-Managed의 경우 Okta가 연결할 수 있도록 인스턴스가 공개적으로 사용 가능한지 확인합니다. 필요한 경우 방화벽에서 [Okta IP 주소에 대한 액세스를 허용](https://help.okta.com/en-us/Content/Topics/Security/ip-address-allow-listing.htm)할 수 있습니다.
