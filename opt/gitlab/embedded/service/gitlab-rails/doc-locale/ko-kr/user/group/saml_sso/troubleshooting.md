---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: SAML 문제 해결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 페이지는 다음을 사용할 때 발생할 수 있는 문제에 대한 가능한 해결책을 포함합니다:

- [GitLab.com 그룹의 SAML SSO](_index.md).
- GitLab Self-Managed 인스턴스 수준의 [SAML OmniAuth 공급자](../../../integration/saml.md).
- [Switchboard](../../../administration/dedicated/configure_instance/authentication/saml.md#add-a-saml-provider-with-switchboard)를 사용하여 GitLab Dedicated 인스턴스에 대해 SAML을 구성합니다.

## SAML 디버깅 도구 {#saml-debugging-tools}

SAML 응답은 base64로 인코딩됩니다. 즉시 디코딩하려면 **SAML-tracer** 브라우저 확장 프로그램([Firefox](https://addons.mozilla.org/en-US/firefox/addon/saml-tracer/), [Chrome](https://chromewebstore.google.com/detail/saml-tracer/mpdajninpobndbfcldcmbpnnbhibjmch?hl=en))을 사용할 수 있습니다.

브라우저 플러그인을 설치할 수 없는 경우 대신 [SAML 응답을 수동으로 생성하고 캡처](#manually-generate-a-saml-response)할 수 있습니다.

다음 항목에 특히 주의하세요:

- `NameID` - 로그인하는 사용자를 식별합니다. 사용자가 이전에 로그인한 경우 [GitLab이 저장한](#verify-nameid) 값과 일치해야 합니다.
- `X509Certificate`의 존재 여부 - 응답 서명을 확인하는 데 필요합니다.
- `SubjectConfirmation` 및 `Conditions` \- 구성이 잘못되면 오류가 발생할 수 있습니다.

### SAML 응답 생성 {#generate-a-saml-response}

SAML 응답을 사용하여 ID 공급자를 사용하여 로그인을 시도하는 동안 어설션 목록에서 전송된 특성 이름과 값을 미리 봅니다.

SAML 응답을 생성하려면:

1. [브라우저 디버깅 도구](#saml-debugging-tools) 중 하나를 설치합니다.
1. 새 브라우저 탭을 엽니다.
1. SAML tracer 콘솔을 엽니다:
   - Chrome: 페이지의 컨텍스트 메뉴에서 **검사**를 선택한 다음 개발자 콘솔에서 **SAML** 탭을 선택합니다.
   - Firefox: 브라우저 도구 모음에 있는 SAML-tracer 아이콘을 선택합니다.
1. GitLab.com 그룹의 경우:
   - 그룹의 GitLab 통합 인증(SSO) URL로 이동합니다.
   - **권한 부여**를 선택하거나 로그인을 시도합니다.
1. GitLab Self-Managed 인스턴스의 경우:
   - 인스턴스 홈페이지로 이동합니다.
   - `SAML Login` 버튼을 선택하여 로그인합니다.
1. tracer 콘솔에 [예시 SAML 응답](_index.md#example-saml-response)과 비슷한 SAML 응답이 표시됩니다.
1. SAML tracer 내에서 **내보내기** 아이콘을 선택하여 응답을 JSON 형식으로 저장합니다.

#### SAML 응답을 수동으로 생성 {#manually-generate-a-saml-response}

<i class="fa-youtube-play" aria-hidden="true"></i> 개요는 [브라우저 플러그인을 사용하지 않고 SAML 응답을 수동으로 생성하는 방법에 대한 동영상(Google Chrome 사용)](https://youtu.be/umMPj6ohF_I)을 참조하세요. GitLab Support에서 업로드했습니다.
<!-- Video published on 2024-09-09 -->

어떤 브라우저를 사용하든 프로세스는 다음과 유사합니다:

1. 새 브라우저에서 마우스 오른쪽 단추를 클릭하고 **검사**를 선택하여 **DevTools** 창을 엽니다.
1. **네트워크** 탭을 선택합니다. **로그 유지**가 선택되어 있는지 확인합니다.
1. 브라우저 페이지로 전환하고 SAML SSO를 사용하여 GitLab에 로그인합니다.
1. **DevTools** 창으로 돌아가서 `callback` 이벤트를 필터링합니다.
1. 콜백 이벤트의 **페이로드** 탭을 선택하고 마우스 오른쪽 단추를 클릭하여 값을 복사합니다.
1. 이 값을 다음 명령에 붙여넣습니다: `echo "<value>" | base64 --decode > saml_response.xml`.
1. `saml_response.xml`을 코드 편집기에서 엽니다.

   코드 편집기에 XML "prettifier"가 설치되어 있으면 응답을 자동으로 서식 지정하여 더 쉽게 읽을 수 있어야 합니다.

## SAML 로그인을 위한 Rails 로그 검색 {#search-rails-logs-for-a-saml-sign-in}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

[`audit_json.log` 파일](../../../administration/logs/_index.md#audit_jsonlog)에서 SAML 로그인에 대한 자세한 정보를 찾을 수 있습니다.

예를 들어 `system_access`을(를) 검색하면 사용자가 SAML을 사용하여 GitLab에 로그인한 시기를 보여주는 항목을 찾을 수 있습니다:

```json
{
  "severity": "INFO",
  "time": "2024-08-13T06:05:35.721Z",
  "correlation_id": "01J555EZK136DQ8S7P32G9GEND",
  "meta.caller_id": "OmniauthCallbacksController#saml",
  "meta.remote_ip": "45.87.213.198",
  "meta.feature_category": "system_access",
  "meta.user": "bbtest",
  "meta.user_id": 16,
  "meta.client_id": "user/16",
  "author_id": 16,
  "author_name": "bbtest@agounder.onmicrosoft.com",
  "entity_id": 16,
  "entity_type": "User",
  "created_at": "2024-08-13T06:05:35.708+00:00",
  "ip_address": "45.87.213.198",
  "with": "saml",
  "target_id": 16,
  "target_type": "User",
  "target_details": "bbtest@agounder.onmicrosoft.com",
  "entity_path": "bbtest"
}
```

SAML 그룹 링크를 구성한 경우 로그는 멤버십이 제거되었음을 자세히 설명하는 항목도 표시합니다:

```json
{
  "severity": "INFO",
  "time": "2024-08-13T05:24:07.769Z",
  "correlation_id": "01J55330SRTKTD5CHMS96DNZEN",
  "meta.caller_id": "Auth::SamlGroupSyncWorker",
  "meta.remote_ip": "45.87.213.206",
  "meta.feature_category": "system_access",
  "meta.client_id": "ip/45.87.213.206",
  "meta.root_caller_id": "OmniauthCallbacksController#saml",
  "id": 179,
  "author_id": 6,
  "entity_id": 2,
  "entity_type": "Group",
  "details": {
    "remove": "user_access",
    "member_id": 7,
    "author_name": "BB Test",
    "author_class": "User",
    "target_id": 6,
    "target_type": "User",
    "target_details": "BB Test",
    "custom_message": "Membership destroyed",
    "ip_address": "45.87.213.198",
    "entity_path": "group1"
  }
}
```

GitLab이 SAML 공급자로부터 받은 사용자의 세부 정보를 `auth_json.log`에서 볼 수도 있습니다. 예:

```json
{
  "severity": "INFO",
  "time": "2024-08-20T07:01:20.979Z",
  "correlation_id": "01J5Q9E59X4P40ZT3MCE35C2A9",
  "meta.caller_id": "OmniauthCallbacksController#saml",
  "meta.remote_ip": "xxx.xxx.xxx.xxx",
  "meta.feature_category": "system_access",
  "meta.client_id": "ip/xxx.xxx.xxx.xxx",
  "payload_type": "saml_response",
  "saml_response": {
    "issuer": [
      "https://sts.windows.net/03b8c6c5-104b-43e2-aed3-abb07df387cc/"
    ],
    "name_id": "ab260d59-0317-47f5-9afb-885c7a1257ab",
    "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    "name_id_spnamequalifier": null,
    "name_id_namequalifier": null,
    "destination": "https://dh-gitlab.agounder.com/users/auth/saml/callback",
    "audiences": [
      "https://dh-gitlab.agounder.com/16.11.6"
    ],
    "attributes": {
      "http://schemas.microsoft.com/identity/claims/tenantid": [
        "03b8c6c5-104b-43e2-aed3-abb07df387cc"
      ],
      "http://schemas.microsoft.com/identity/claims/objectidentifier": [
        "ab260d59-0317-47f5-9afb-885c7a1257ab"
      ],
      "http://schemas.microsoft.com/identity/claims/identityprovider": [
        "https://sts.windows.net/03b8c6c5-104b-43e2-aed3-abb07df387cc/"
      ],
      "http://schemas.microsoft.com/claims/authnmethodsreferences": [
        "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password"
      ],
      "email": [
        "bbtest@agounder.com"
      ],
      "firstname": [
        "BB"
      ],
      "name": [
        "bbtest@agounder.onmicrosoft.com"
      ],
      "lastname": [
        "Test"
      ]
    },
    "in_response_to": "_f8863f68-b5f1-43f0-9534-e73933e6ed39",
    "allowed_clock_drift": 2.220446049250313e-16,
    "success": true,
    "status_code": "urn:oasis:names:tc:SAML:2.0:status:Success",
    "status_message": null,
    "session_index": "_b4f253e2-aa61-46a4-902b-43592fe30800",
    "assertion_encrypted": false,
    "response_id": "_392cc747-7c8b-41de-8be0-23f5590d5ded",
    "assertion_id": "_b4f253e2-aa61-46a4-902b-43592fe30800"
  }
}
```

## GitLab SAML 테스트 {#testing-gitlab-saml}

SAML 문제를 해결하기 위해 다음 중 하나를 사용할 수 있습니다:

- [Docker Compose를 사용한 완전한 GitLab 및 SAML 테스트 환경](https://gitlab.com/gitlab-com/support/toolbox/replication/-/tree/main/compose_files).
- SAML 공급자만 필요한 경우 [Docker 컨테이너를 시작하는 빠른 시작 가이드](../../../administration/troubleshooting/test_environments.md#saml)(플러그 앤 플레이 SAML 2.0 ID 공급자 포함).
- [GitLab Self-Managed 인스턴스에서 그룹에 대해 SAML을 활성화](../../../integration/saml.md#configure-group-saml-sso-on-gitlab-self-managed)하여 로컬 환경을 만듭니다.

## 구성 검증 {#verify-configuration}

편의상 GitLab Support 팀에서 사용하는 일부 [예시 리소스](example_saml_config.md)가 포함되어 있습니다. SAML 앱 구성을 검증하는 데 도움이 될 수 있지만 타사 제품의 현재 상태를 반영할 수 있다는 보장은 없습니다.

### 지문 계산 {#calculate-the-fingerprint}

`idp_cert_fingerprint`을(를) 구성할 때는 가능할 때마다 SHA256 지문을 사용해야 합니다. SHA1도 지원되지만 권장되지 않습니다. 지문을 계산하려면 인증서 파일에서 다음 명령을 실행하세요:

```shell
openssl x509 -in <certificate.crt> -noout -fingerprint -sha256
```

`<certificate.crt>`을(를) 인증서 파일의 이름으로 바꾸세요.

> [!note]
> GitLab 17.11 이상에서는 지문 알고리즘이 [자동으로 감지](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184530)되며 지문 길이를 기준으로 합니다.
>
> GitLab 17.10 이하에서는 SHA1이 기본 지문 알고리즘입니다. SHA256 지문을 사용하려면 알고리즘을 지정해야 합니다:
>
> ```ruby
> idp_cert_fingerprint_algorithm: "http://www.w3.org/2001/04/xmlenc#sha256"
> ```

## SSO 인증서 업데이트 {#sso-certificate-updates}

ID 공급자에 사용되는 인증서가 변경되면(예: 인증서 업데이트 또는 갱신 시) 인증서 지문도 업데이트해야 합니다. ID 공급자의 UI에서 인증서 지문을 찾을 수 있습니다. ID 공급자 UI에서 인증서를 얻을 수 없는 경우 [지문 계산](#calculate-the-fingerprint) 문서의 단계를 따르세요.

## 구성 오류 {#configuration-errors}

### 잘못된 대상 {#invalid-audience}

이 오류는 ID 공급자가 GitLab을 SAML 요청의 유효한 발신자 및 수신자로 인식하지 못함을 의미합니다. 다음을 확인하세요:

- GitLab 콜백 URL을 ID 공급자 서버의 승인된 대상에 추가합니다.
- `issuer` 문자열의 뒤따르는 공백을 피합니다.

### 키 검증 오류, 다이제스트 불일치 또는 지문 불일치 {#key-validation-error-digest-mismatch-or-fingerprint-mismatch}

이러한 오류는 모두 SAML 인증서라는 유사한 원인에서 발생합니다. SAML 요청은 지문, 인증서 또는 검증기를 사용하여 검증되어야 합니다.

이 요구 사항의 경우 다음을 고려해야 합니다:

- 지문을 사용하는 경우 SHA256 지문을 확인하세요:
  1. 인증서 파일을 다시 다운로드합니다.
  1. [지문 계산](#calculate-the-fingerprint)을 수행합니다.
  1. 지문을 `idp_cert_fingerprint`에서 제공한 값과 비교합니다. 값이 동일해야 합니다.
- 설정에 인증서가 제공되지 않은 경우 지문 또는 지문 검증기를 제공해야 하고 서버의 응답에 인증서(`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>`)가 포함되어야 합니다.
- 설정에 인증서가 제공된 경우 요청에 인증서를 포함할 필요가 없습니다. 이 경우 지문 또는 지문 검증기는 선택 사항입니다.

위에서 설명한 시나리오가 유효하지 않은 경우 요청이 언급된 오류 중 하나로 실패합니다.

### 누락된 클레임 또는 `Email can't be blank` 오류 {#missing-claims-or-email-cant-be-blank-errors}

ID 공급자 서버가 GitLab이 계정을 생성하거나 로그인 정보를 기존 계정과 일치시키기 위해 특정 정보를 전달해야 합니다. `email`이(가) 전달되어야 하는 최소 정보입니다. ID 공급자 서버가 이 정보를 제공하지 않으면 모든 SAML 요청이 실패합니다.

이 정보가 제공되는지 확인하세요.

ID 공급자가 올바른 정보를 보내고 있지만 특성이 OmniAuth `info` 해시의 이름과 일치하지 않는 경우 발생할 수 있는 또 다른 문제가 있습니다. 이 경우 SAML 구성에서 `attribute_statements`을(를) 설정하여 [SAML 응답의 특성 이름을 해당하는 OmniAuth `info` 해시 이름에 매핑](../../../integration/saml.md#map-saml-response-attribute-names)해야 합니다.

### SAML 그룹 링크가 있지만 멤버십이 변경되지 않음 {#saml-group-links-exist-but-no-memberships-change}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

SAML 그룹 링크를 구성하고 SAML 응답이 예상된 그룹을 전달하는지 확인했지만 멤버십이 추가되거나 제거되지 않습니다. 사용자가 성공적으로 로그인했으며 로그인이나 로그에서 오류를 보고하지 않습니다.

GitLab이 사용자를 인증한 공급자에 대해 `groups_attribute` 값을 확인할 수 없을 때 이 문제가 발생합니다. 일반적인 원인은 `groups_attribute`을(를) 공급자 수준에서 `name` 및 `label`의 형제로 배치하지 않고 공급자의 `args` 해시 내부에 배치하는 것입니다. 값이 확인되지 않으면 그룹 동기화가 실행되지 않고 아무것도 보고하지 않습니다.

이 이슈를 해결하려면:

1. `groups_attribute`을(를) 구성의 공급자 수준으로 이동합니다. 예시는 [SAML 그룹 동기화 구성](group_sync.md#configure-saml-group-sync)을 참조하세요.
1. 파일을 저장하고 GitLab을 다시 구성합니다.

   ```shell
   sudo gitlab-ctl reconfigure
   ```

1. 다시 로그인합니다.
1. `audit_json.log`에서 `"meta.caller_id": "Auth::SamlGroupSyncWorker"`인 항목을 검색합니다. 그룹 동기화는 멤버십을 변경할 때 이 항목을 작성합니다. 멤버십을 변경해야 하는 로그인 후 항목이 없으면 그룹 동기화가 실행되지 않습니다.

## 사용자 로그인 배너 오류 메시지 {#user-sign-in-banner-error-messages}

### 메시지: `SAML authentication failed: SAML NameID is missing from your SAML response.` {#message-saml-authentication-failed-saml-nameid-is-missing-from-your-saml-response}

`SAML authentication failed: SAML NameID is missing from your SAML response. Please contact your administrator.`를 나타내는 오류가 발생할 수 있습니다.

이 문제는 Group SSO를 사용하여 GitLab에 로그인을 시도했지만 SAML 응답에 `NameID`이(가) 포함되지 않은 경우에 발생합니다.

이 이슈를 해결하려면:

- 관리자에게 문의하여 IdP 계정에 `NameID`이(가) 할당되었는지 확인하세요.
- [SAML 디버깅 도구](#saml-debugging-tools)를 사용하여 SAML 응답에 유효한 `NameID`이(가) 있는지 확인합니다.

### 메시지: `SAML authentication failed: Extern uid has already been taken.` {#message-saml-authentication-failed-extern-uid-has-already-been-taken}

`SAML authentication failed: Extern uid has already been taken. Please contact your administrator to generate a unique external_uid (NameID).`를 나타내는 오류가 발생할 수 있습니다.

이 문제는 Group SSO를 사용하여 기존 GitLab 계정을 SAML 신원에 연결하려고 할 때 발생합니다. 그러나 현재 `NameID`을(를) 가진 기존 GitLab 계정이 있습니다.

이 문제를 해결하려면 관리자에게 IdP 계정에 대해 고유한 `Extern UID` (`NameID`)을(를) 다시 생성하도록 지시하세요. 이 새 `Extern UID`이(가) [GitLab `NameID` 제약](_index.md#manage-user-saml-identity)을 준수하는지 확인하세요.

해당 GitLab 사용자를 SAML 로그인과 함께 사용하지 않으려면 [GitLab 계정을 SAML 앱에서 연결 해제](_index.md#unlink-accounts)할 수 있습니다.

### 메시지: `SAML authentication failed: User has already been taken` {#message-saml-authentication-failed-user-has-already-been-taken}

현재 로그인한 사용자는 이미 다른 신원에 연결된 SAML을 가지고 있거나 `NameID` 값이 변경되었습니다. 가능한 원인 및 해결책은 다음과 같습니다:

| 원인                                                                                          | 해결책 |
|------------------------------------------------------------------------------------------------|----------|
| 특정 ID 공급자에 대해 동일한 사용자에 여러 SAML 신원을 연결하려고 시도했습니다. | 로그인하는 신원을 변경합니다. 이렇게 하려면 [이전 SAML 신원을 연결 해제](_index.md#unlink-accounts)한 후 이 GitLab 계정에서 다시 로그인을 시도하세요. |
| `NameID`이(가) 사용자가 SSO 식별을 요청할 때마다 변경됨                           | [`NameID`](#verify-nameid)가 `Transient` 형식으로 설정되지 않았는지 확인하거나 `NameID`이(가) 후속 요청에서 변경되지 않는지 확인합니다. |

### 메시지: `SAML authentication failed: Email has already been taken` {#message-saml-authentication-failed-email-has-already-been-taken}

| 원인                                                                                                                | 해결책 |
|----------------------------------------------------------------------------------------------------------------------|----------|
| 같은 이메일 주소를 가진 GitLab 사용자 계정이 있지만 계정이 SAML 신원과 연결되지 않은 경우. | GitLab.com에서 사용자는 [계정을 연결](_index.md#user-access-and-management)해야 합니다. GitLab Self-Managed에서 관리자는 인스턴스를 구성하여 처음 로그인할 때 [SAML 신원을 GitLab 사용자 계정과 자동으로 연결](../../../integration/saml.md#link-saml-identity-for-an-existing-user)할 수 있습니다. |

사용자 계정은 다음 방법 중 하나로 생성됩니다:

- 사용자 등록
- OAuth를 통한 로그인
- SAML을 통한 로그인
- SCIM 프로비저닝

### 오류: 사용자가 이미 사용 중 {#error-user-has-already-been-taken}

이 두 오류를 동시에 받으면 ID 공급자가 제공한 `NameID` 대소문자 표기가 해당 사용자의 이전 값과 정확히 일치하지 않음을 시사합니다:

- `SAML authentication failed: Extern UID has already been taken`
- `User has already been taken`

`NameID`을(를) 구성하여 일관된 값을 반환하도록 할 수 있습니다. 개별 사용자에 대해 이를 수정하려면 사용자의 식별자를 변경해야 합니다. GitLab.com의 경우 사용자는 [SAML을 GitLab 계정에서 연결 해제](_index.md#unlink-accounts)해야 합니다.

### 메시지: `Request to link SAML account must be authorized` {#message-request-to-link-saml-account-must-be-authorized}

GitLab 계정을 연결하려는 사용자가 ID 공급자의 SAML 앱 내의 사용자로 추가되었는지 확인하세요.

또는 SAML 응답이 `samlp:Response` 태그의 `InResponseTo` 특성을 놓쳤을 수 있습니다. [SAML gem에서 예상](https://github.com/onelogin/ruby-saml/blob/9f710c5028b069bfab4b9e2b66891e0549765af5/lib/onelogin/ruby-saml/response.rb#L307-L316)됩니다. ID 공급자 관리자는 로그인이 ID 공급자가 아닌 서비스 공급자에 의해 시작되도록 해야 합니다.

### 메시지: `There is already a GitLab account associated with this email address.` {#message-there-is-already-a-gitlab-account-associated-with-this-email-address}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

사용자는 [기존 GitLab.com 계정에 SAML을 수동으로 연결](_index.md#link-saml-to-your-existing-gitlabcom-account)하려고 할 때 이 메시지를 볼 수 있습니다:

```plaintext
There is already a GitLab account associated with this email address.
Sign in with your existing credentials to connect your organization's account
```

이 문제를 해결하려면 사용자가 올바른 GitLab 비밀번호를 사용하여 로그인하고 있는지 확인해야 합니다. 사용자가 먼저 다음이 모두 해당하는 경우 [비밀번호를 재설정](https://gitlab.com/users/password/new)해야 합니다:

- 계정이 SCIM에 의해 프로비저닝되었습니다.
- 사용자 이름과 비밀번호로 처음 로그인하는 중입니다.

### 메시지: `SAML Name ID and email address do not match your user account` {#message-saml-name-id-and-email-address-do-not-match-your-user-account}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

사용자는 "SAML Name ID와 이메일 주소가 사용자 계정과 일치하지 않습니다. 관리자에게 문의하세요."라는 오류가 표시될 수 있습니다. 이는 다음을 의미합니다:

- SAML이 보낸 NameID 값이 기존 SAML 신원 `extern_uid` 값과 일치하지 않습니다. NameID와 `extern_uid`은(는) 대소문자를 구분합니다. 자세한 정보는 [사용자 SAML 신원 관리](_index.md#manage-user-saml-identity)를 참조하세요.
- SAML 응답에 이메일 주소가 포함되지 않았거나 이메일 주소가 사용자의 GitLab 이메일 주소와 일치하지 않습니다.

해결 방법은 GitLab 그룹 소유자가 [SAML API](../../../api/saml.md)를 사용하여 사용자의 SAML `extern_uid`을(를) 업데이트하는 것입니다. `extern_uid` 값은 SAML ID 공급자(IdP)가 보낸 Name ID 값과 일치해야 합니다. IdP 구성에 따라 생성된 고유 ID, 이메일 주소 또는 다른 값일 수 있습니다.

### 오류: `Certificate element missing in response (ds:x509certificate)` {#error-certificate-element-missing-in-response-dsx509certificate}

이 오류는 IdP가 SAML 응답에 X.509 인증서를 포함하도록 구성되지 않았음을 나타냅니다:

```plaintext
Certificate element missing in response (ds:x509certificate) and not cert provided at settings
```

X.509 인증서는 응답에 포함되어야 합니다. 이 문제를 해결하려면 IdP를 구성하여 SAML 응답에 X.509 인증서를 포함하도록 하세요.

자세한 정보는 [IdP의 SAML 앱에 대한 추가 구성](../../../integration/saml.md#additional-configuration-for-saml-apps-on-your-idp)에 대한 문서를 참조하세요.

## 기타 사용자 로그인 문제 {#other-user-sign-in-issues}

### `NameID` 검증 {#verify-nameid}

문제 해결 시 인증된 사용자는 API를 사용하여 GitLab이 사용자에게 이미 연결한 `NameID`을(를) 확인할 수 있습니다. <https://gitlab.com/api/v4/user>를 방문하여 신원 아래의 `extern_uid`을(를) 확인합니다.

GitLab Self-Managed의 경우 관리자는 [사용자 API](../../../api/users.md)를 사용하여 동일한 정보를 볼 수 있습니다.

그룹에 대해 SAML을 사용할 때 적절한 권한이 있는 역할의 그룹 구성원은 [멤버 API](../../../api/group_members.md)를 사용하여 그룹의 구성원에 대한 그룹 SAML 신원 정보를 볼 수 있습니다.

이를 ID 공급자가 보낸 `NameID`과(와) 비교할 수 있습니다. [SAML 디버깅 도구](#saml-debugging-tools)로 메시지를 디코딩합니다. 이 값들은 사용자를 식별하기 위해 일치해야 합니다.

### 로그인 "루프"에 갇힘 {#stuck-in-a-login-loop}

**GitLab 통합 인증(SSO) URL**(GitLab.com의 경우) 또는 인스턴스 URL(GitLab Self-Managed의 경우)이 ID 공급자의 SAML 앱에서 "로그인 URL"(또는 유사하게 명명된 필드)로 구성되었는지 확인하세요.

GitLab.com의 경우 사용자가 [기존 GitLab.com 계정에 SAML을 연결](_index.md#link-saml-to-your-existing-gitlabcom-account)해야 할 때 **GitLab 통합 인증(SSO) URL**을(를) 제공하고 처음 로그인할 때 SAML 앱을 사용하지 말도록 사용자에게 지시합니다.

### 사용자가 404를 받습니다 {#users-receive-a-404}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

사용자가 성공적으로 로그인한 후 `404`을(를) 받으면 IP 제한이 구성되어 있는지 확인하세요. IP 제한 설정은 다음과 같이 구성됩니다:

- GitLab.com에서는 [그룹 수준에서](../access_and_permissions.md#restrict-group-access-by-ip-address).
- GitLab Self-Managed의 경우 [인스턴스 수준에서](../../../administration/reporting/ip_addr_restrictions.md).

SAML SSO for groups는 유료 기능이므로 구독이 만료되면 GitLab.com에서 SAML SSO를 사용하여 로그인할 때 `404` 오류가 발생할 수 있습니다. 모든 사용자가 SAML을 사용하여 로그인할 때 `404`을(를) 받으면 이 SAML SSO 네임스페이스에서 [활성 구독이 있는지 확인](../../../subscriptions/manage_subscription.md#view-subscription)하세요.

"구성 검증" 사용 중에 설정 중에 `404`을(를) 받으면 올바른 [SHA-1로 생성된 지문](../../../integration/saml.md#configure-saml-on-your-idp)을(를) 사용했는지 확인하세요.

사용자가 처음 로그인하려고 할 때 GitLab 통합 인증(SSO) URL이 [구성되지 않은](_index.md#set-up-your-identity-provider) 경우 404가 표시될 수 있습니다. [사용자 액세스 섹션](_index.md#link-saml-to-your-existing-gitlabcom-account)에 설명된 대로 그룹 소유자가 사용자에게 URL을 제공해야 합니다.

최상위 그룹이 [이메일 도메인별로 멤버십을 제한](../access_and_permissions.md#restrict-group-access-by-domain)했고 허용되지 않는 이메일 도메인을 가진 사용자가 SSO로 로그인하려고 하면 해당 사용자가 404를 받을 수 있습니다. 사용자는 여러 계정을 가질 수 있으며 SAML 신원이 회사 도메인과 다른 이메일 주소를 가진 개인 계정에 연결될 수 있습니다. 이를 확인하려면 다음을 확인하세요:

- 최상위 그룹이 이메일 도메인별로 멤버십을 제한했습니다.
- 최상위 그룹의 [감사 이벤트](../../../administration/compliance/audit_event_reports.md)에서:
  - 해당 사용자에 대해 **GROUP_SAML 인증으로 로그인** 작업을 볼 수 있습니다.
  - 사용자 이름이 SAML SSO에 대해 구성한 사용자 이름과 동일한지 확인하려면 **작성자** 이름을 선택합니다.
    - 사용자 이름이 SAML SSO에 대해 구성한 사용자 이름과 다르면 사용자에게 [SAML 신원을 연결 해제](_index.md#unlink-accounts)하도록 개인 계정에서 요청합니다.

모든 사용자가 ID 공급자(IdP)에 로그인한 후 `404`을(를) 받는 경우:

- `assertion_consumer_service_url`을(를) 검증합니다:
  - GitLab 구성에서 [GitLab의 HTTPS 엔드포인트와 일치](../../../integration/saml.md#configure-saml-support-in-gitlab)하는지 확인합니다.
  - IdP에서 SAML 앱을 설정할 때 `Assertion Consumer Service URL` 또는 해당하는 것으로.
- `404`이(가) [사용자가 Azure IdP에 할당된 많은 그룹](group_sync.md#microsoft-azure-active-directory-integration)과 관련이 있는지 확인합니다.
- IdP 서버와 GitLab의 시계가 같은 시간으로 동기화되어 있는지 확인합니다.

사용자 부분이 IdP에 로그인한 후 `404` 오류를 받으면 먼저 사용자가 그룹에 추가된 다음 즉시 제거된 경우 반환되는 감사 이벤트를 확인합니다. 또는 사용자가 성공적으로 로그인할 수 있지만 [최상위 그룹의 구성원](../_index.md#search-a-group)으로 표시되지 않은 경우:

- 사용자가 [SAML ID 공급자에 추가](_index.md#user-access-and-management)되었는지 확인하고 구성된 경우 [SCIM](scim_setup.md).
- 사용자의 SCIM 신원의 `active` 특성이 `true`인지 [SCIM API](../../../api/scim.md)를 사용하여 확인합니다. `active` 특성이 `false`인 경우 다음 중 하나를 수행하여 문제를 해결할 수 있습니다:

  - SCIM ID 공급자에서 사용자의 동기화를 트리거합니다. 예를 들어 Azure에는 "필요 시 프로비전" 옵션이 있습니다.
  - SCIM ID 공급자에서 사용자를 제거하고 다시 추가합니다.
  - 사용자가 [계정을 연결 해제](_index.md#unlink-accounts)한 다음 [계정을 연결](_index.md#link-saml-to-your-existing-gitlabcom-account)할 수 있는 경우.
  - [내부 SCIM API](../../../development/internal_api/_index.md#update-a-single-scim-provisioned-user)를 사용하여 그룹의 SCIM 토큰을 사용하여 사용자의 SCIM 신원을 업데이트합니다. 그룹의 SCIM 토큰을 모르는 경우 토큰을 재설정하고 새 토큰으로 SCIM ID 공급자 앱을 업데이트합니다. 예시 요청:

    ```plaintext
    curl --request PATCH "https://gitlab.example.com/api/scim/v2/groups/test_group/Users/f0b1d561c-21ff-4092-beab-8154b17f82f2" --header "Authorization: Bearer <SCIM_TOKEN>" --header "Content-Type: application/scim+json" --data '{ "Operations": [{"op":"Replace","path":"active","value":"true"}] }'
    ```

### 로그인 후 500 오류 {#500-error-after-login}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

SAML 로그인 페이지에서 리디렉션될 때 GitLab에서 "500 오류"가 표시되면 다음을 나타낼 수 있습니다:

- GitLab이 SAML 사용자의 이메일 주소를 가져올 수 없습니다. ID 공급자가 클레임 이름 `email` 또는 `mail`를 사용하여 사용자의 이메일 주소가 포함된 클레임을 제공하는지 확인합니다.
- `gitlab.rb` 파일에 `identity provider_cert_fingerprint` 또는 `identity provider_cert` 파일에 대해 설정된 인증서가 잘못되었습니다.
- `gitlab.rb` 파일이 `identity provider_cert_fingerprint`을(를) 활성화하도록 설정되어 있고 `identity provider_cert`이(가) 제공 중이거나 그 반대입니다.

### 로그인 후 422 오류 {#422-error-after-login}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

SAML 로그인 페이지에서 리디렉션될 때 GitLab에서 "422 오류"가 표시되면 ID 공급자에서 ACS(Assertion Consumer Service) URL이 잘못 구성되었을 수 있습니다.

ACS URL이 `https://gitlab.example.com/users/auth/saml/callback`을(를) 가리키는지 확인하세요. 여기서 `gitlab.example.com`은(는) GitLab 인스턴스의 URL입니다.

ACS URL이 올바르고 여전히 오류가 있는 경우 기타 문제 해결 섹션을 검토하세요.

#### 허용되지 않는 이메일이 있는 422 오류 {#422-error-with-non-allowed-email}

"이메일이 허용되지 않습니다. 정규 이메일 주소를 사용하세요."라는 422 오류가 표시될 수 있습니다.

이 메시지는 도메인 허용 목록 또는 거부 목록 설정에서 도메인을 추가하거나 제거해야 함을 나타낼 수 있습니다.

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.

이 해결 방법을 구현하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **사용자 계정 생성 제한사항**을 확장합니다.
1. **사용자 생성이 허용된 도메인** 및 **사용자 생성이 거부된 도메인**에 적절하게 도메인을 추가하거나 제거합니다.
1. **변경 사항 저장**을 선택합니다.

### SAML을 통해 로그인할 때 사용자가 차단됨 {#user-is-blocked-when-signing-in-through-saml}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

SAML을 통해 로그인할 때 사용자가 차단되는 가장 가능성 높은 이유는 다음과 같습니다:

- 구성에서 `gitlab_rails['omniauth_block_auto_created_users'] = true`이(가) 설정되어 있고 이것이 사용자의 첫 번째 로그인입니다.
- [`required_groups`](../../../integration/saml.md#required-groups)이(가) 구성되었지만 사용자가 하나의 구성원도 아닙니다.

## Google Workspace 문제 해결 팁 {#google-workspace-troubleshooting-tips}

Google Workspace에서 로그인 중 오류가 표시되면 [SAML 앱 오류 메시지](https://support.google.com/a/answer/6301076?hl=en) 관련 Google Workspace 문서가 디버깅에 도움이 됩니다. 다음 403 오류에 특히 주의하세요:

- `app_not_configured`
- `app_not_configured_for_user`

## 메시지: `The member's email address is not linked to a SAML account` {#message-the-members-email-address-is-not-linked-to-a-saml-account}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

이 오류는 [SAML SSO 적용](_index.md#sso-enforcement)이 활성화된 GitLab.com 그룹(또는 그룹 내 부분 그룹 또는 프로젝트)에 사용자를 초대하려고 할 때 나타납니다.

그룹에 사용자를 초대한 후 이 메시지가 표시되면:

1. 사용자가 [SAML ID 공급자에 추가](_index.md#user-access-and-management)되었는지 확인하세요.
1. 사용자에게 [기존 GitLab.com 계정에 SAML을 연결](_index.md#link-saml-to-your-existing-gitlabcom-account)하도록 요청합니다(있는 경우). 그렇지 않으면 사용자에게 [ID 공급자의 대시보드를 통해 GitLab.com에 액세스](_index.md#user-access-and-management)하거나 [수동으로 가입](https://gitlab.com/users/sign_up)하여 GitLab.com 계정을 만들고 새 계정에 SAML을 연결하도록 요청합니다.
1. 사용자가 [최상위 그룹의 구성원](../_index.md#search-a-group)인지 확인하세요.

또한 [로그인 후 404를 받는 사용자 문제 해결](#users-receive-a-404)을 참조하세요.

## 메시지: `The SAML response did not contain an email address.` {#message-the-saml-response-did-not-contain-an-email-address}

이 오류가 표시되면:

```plaintext
The SAML response did not contain an email address.
Either the SAML identity provider is not configured to send the attribute, or the
identity provider directory does not have an email address value for your user
```

이 오류는 다음 경우에 나타납니다:

- SAML 응답이 **이메일** 또는 **메일** 특성의 사용자 이메일 주소를 포함하지 않습니다.
- 사용자가 [SAML을 연결](_index.md#user-access-and-management)하려고 하지만 아직 [신원 확인 프로세스](../../../security/identity_verification.md)를 완료하지 않은 경우.

SAML ID 공급자가 [지원되는 메일 특성](../../../integration/saml.md)을 전송하도록 구성되어 있는지 확인하세요:

```xml
<Attribute Name="email">
  <AttributeValue>user@example.com</AttributeValue>
</Attribute>
```

`http://schemas.xmlsoap.org/ws/2005/05/identity/claims` 및 `http://schemas.microsoft.com/ws/2008/06/identity/claims/`와 같은 문구로 시작하는 특성 이름은 기본적으로 지원됩니다.

```xml
<Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress">
  <AttributeValue>user@example.com</AttributeValue>
</Attribute>
```

## 전역 SAML 그룹 멤버십 잠금으로 서비스 계정을 추가할 수 없음 {#cannot-add-service-accounts-with-global-saml-group-memberships-lock}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[전역 SAML 그룹 멤버십 잠금](group_sync.md#global-saml-group-memberships-lock)이 활성화되면 관리자만 UI를 통해 그룹 구성원 및 서비스 계정을 관리할 수 있습니다. 그룹 소유자가 서비스 계정을 관리해야 하는 경우 대신 [그룹 멤버 API](../../../api/group_members.md)를 사용할 수 있습니다.

## 지원 기술 자료 {#support-knowledge-base}

문제가 계속되면 [GitLab 지원 기술 자료](https://support.gitlab.com/hc/en-us/)를 참조하세요.
