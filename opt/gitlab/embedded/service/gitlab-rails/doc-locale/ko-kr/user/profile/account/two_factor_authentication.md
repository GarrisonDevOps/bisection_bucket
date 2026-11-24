---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
gitlab_dedicated: yes
title: 2단계 인증
description: 향상된 계정 보호를 위해 다중 인증을 활성화합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

2단계 인증(2FA)은 GitLab 계정에 추가 보안 수준을 제공합니다. 다른 사람이 계정에 액세스하려면 사용자 이름, 비밀번호 및 2단계 인증 요소에 액세스해야 합니다.

GitLab은 다음 2FA 방법을 지원합니다:

- 패스키. 로그인 시 GitLab은 패스키로 인증하도록 요청합니다. 2FA를 활성화하면 패스키가 추가 및 기본 2FA 옵션이 됩니다. 자세한 내용은 [패스키](../../../auth/passkeys.md)를 참조하세요.
- 일회용 비밀번호([OTP](https://datatracker.ietf.org/doc/html/rfc6238)) 인증기. 로그인 시 GitLab은 OTP 인증기에서 생성한 코드를 입력하도록 요청합니다.
- WebAuthn 장치. 로그인 시 GitLab은 WebAuthn 장치의 소유권을 증명하도록 요청합니다. 일반적으로 YubiKey, 휴대폰 또는 노트북 같은 물리적 장치입니다.
- 이메일 OTP. 로그인 시 GitLab은 이메일 주소로 전송된 코드를 입력하도록 요청합니다.

장치를 설정한 경우 OTP도 설정하여 장치를 잃어버린 경우에도 계정에 액세스할 수 있습니다.

## 2단계 인증 활성화 {#enable-two-factor-authentication}

2FA를 활성화하려면 이메일 주소를 확인하고 OTP 인증기, WebAuthn 장치 또는 이메일 OTP를 등록합니다.

### OTP 인증기 등록 {#register-an-otp-authenticator}

> [!warning]
> OTP 인증기에 대한 액세스 권한을 잃으면 계정이 잠길 수 있습니다.
>
> 이 위험을 최소화하려면:
>
> - 인증기 앱에서 클라우드 백업을 활성화합니다.
> - 백업 비밀번호, 비밀 키 또는 복구 자격 증명을 안전한 위치에 저장합니다.
> - 특정 OTP 인증기에 대한 설명서를 검토합니다.
>
> 이미 계정이 잠긴 경우 [복구 옵션 및 2FA 재설정](two_factor_authentication_troubleshooting.md#recovery-options-and-2fa-reset)을 참조하세요.

OTP 인증기를 등록하려면:

1. GitLab을 구성합니다.
   1. 오른쪽 위 모서리에서 아바타를 선택합니다.
   1. **프로필 편집**을 선택합니다.
   1. 왼쪽 사이드바에서 **액세스** > **비밀번호와 인증**을 선택합니다.
   1. **일회용 비밀번호 (OTP) 인증기** 섹션에서 **인증기 등록**을 선택합니다. QR 코드와 OTP 세부정보가 표시됩니다.
1. 장치를 구성합니다.
   1. 장치에 호환되는 OTP 애플리케이션을 설치합니다. 예를 들어:
      - 클라우드 기반(권장 - 하드웨어 장치를 잃어버린 경우 액세스 권한을 복구할 수 있음):
        - [Authy](https://authy.com/).
        - [Cisco Duo](https://duo.com/).
      - 기타(소유):
        - [Google Authenticator](https://support.google.com/accounts/answer/1066447?hl=en).
        - [Microsoft Authenticator](https://www.microsoft.com/en-us/security/mobile-authenticator-app).
      - 기타(무료 소프트웨어)
        - [Aegis Authenticator](https://getaegis.app/).
        - [FreeOTP](https://freeotp.github.io/).
   1. 애플리케이션에서 두 가지 방법 중 하나로 새 항목을 추가합니다:
      - GitLab에 표시된 코드를 장치의 카메라로 스캔하여 항목을 자동으로 추가합니다.
      - 제공된 세부정보를 입력하여 항목을 수동으로 추가합니다.
1. 등록을 완료합니다:
   1. 현재 비밀번호를 입력합니다.
   1. 인증기에서 생성한 6자리 PIN을 입력합니다.
   1. **이중 인증 앱으로 등록**을 선택합니다.

올바른 PIN을 입력하면 GitLab에서 [복구 코드](#recovery-codes) 목록을 표시합니다. 이를 다운로드하여 안전한 장소에 보관합니다.

OTP 인증기가 클라우드 백업을 지원하는 경우 지금 기능을 구성하는 것을 고려합니다. 자세한 내용은 특정 인증기에 대한 설명서를 참조하세요.

### WebAuthn 장치 등록 {#register-a-webauthn-device}

{{< history >}}

- WebAuthn 장치에 대한 선택적 일회용 비밀번호 인증이 GitLab 15.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/378844)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `webauthn_without_totp`가 있습니다.
- GitLab 17.6에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/396931)합니다. 기능 플래그 `webauthn_without_totp`이 제거되었습니다.

{{< /history >}}

WebAuthn은 다음에서 [지원](https://caniuse.com/#search=webauthn)됩니다:

- 데스크톱 브라우저:
  - Chrome
  - 에지
  - Firefox
  - Opera
  - Safari
- 모바일 브라우저:
  - Chrome for Android
  - Firefox for Android
  - iOS Safari(iOS 13.3 이후)

WebAuthn 호환 장치를 등록하려면:

1. 물리적 장치를 사용하는 경우 컴퓨터에 연결합니다.
1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **비밀번호와 인증**을 선택합니다.
1. **WebAuthn 장치** 섹션에서 **장치 등록**을 선택합니다.
1. **새 장치 설정**을 선택합니다.
1. 브라우저 창의 지침을 따릅니다.
1. 장치에 따라 버튼을 누르거나 센서를 터치해야 할 수도 있습니다.
1. GitLab 계정 비밀번호와 장치 이름을 입력합니다. ID 공급자를 통해 로그인한 경우 이 비밀번호를 입력할 필요가 없을 수 있습니다.
1. **장치 등록**을 선택합니다.

장치를 성공적으로 설정했음을 나타내는 메시지가 표시됩니다.

WebAuthn 호환 장치로 2FA를 설정하면 해당 장치는 특정 컴퓨터의 특정 브라우저에 연결됩니다. 브라우저 및 WebAuthn 장치에 따라 다른 브라우저 또는 컴퓨터에서 WebAuthn 장치를 사용하도록 설정을 구성할 수 있습니다.

처음으로 2FA를 설정하는 경우 [복구 코드를 다운로드](#recovery-codes)하여 액세스 권한을 잃은 경우 계정 액세스를 복구할 수 있습니다.

> [!warning]
> 브라우저 데이터를 지우면 계정에 대한 액세스 권한을 잃을 수 있습니다.

### 이메일 OTP 활성화 {#enable-email-otp}

{{< history >}}

- GitLab 18.7에서 [기능 플래그](../../../administration/feature_flags/_index.md) `email_based_mfa`와 함께 도입되었습니다. 기본적으로 비활성화되었습니다.
- GitLab.com에서 GitLab 18.7로 활성화되었으며 2026년 전체 기간에 걸쳐 모든 사용자에게 점진적으로 배포됩니다.
- 새 애플리케이션 설정 `email_otp_enabled`이 GitLab 19.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/599948)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 19.2에서 `email_based_mfa` 기능 플래그가 [제거](https://gitlab.com/gitlab-org/gitlab/-/work_items/599948)되었습니다. 이메일 OTP는 이제 `email_otp_enabled` 애플리케이션 설정으로 제어됩니다.

{{< /history >}}

이메일 OTP를 사용하면 이메일 주소로 6자리 확인 코드를 전송하여 [신원을 확인](../../../security/email_verification.md)할 수 있습니다.

사전 요구 사항:

- 이메일 OTP는 인스턴스에 대해 활성화되어야 합니다.

계정에 대해 이메일 OTP를 활성화하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **비밀번호와 인증**을 선택합니다.
1. **이메일 OTP 활성화**를 선택합니다.
1. 현재 비밀번호를 입력하고 **이메일 OTP 설정 업데이트**를 선택합니다.

### Cisco Duo 인증기 추가 {#add-a-cisco-duo-authenticator}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

Cisco Duo를 GitLab의 OTP 공급자로 사용할 수 있습니다.

DUO®은 미국 및 특정 기타 국가에서 Cisco Systems, Inc. 및/또는 자회사의 등록 상표입니다.

사전 요구 사항:

- 계정은 Cisco Duo 및 GitLab에 모두 있어야 하며 두 애플리케이션에서 동일한 사용자 이름을 가져야 합니다.
- [Cisco Duo를 구성](https://admin.duosecurity.com/)했어야 하며 통합 키, 비밀 키 및 API 호스트명이 있어야 합니다.

자세한 내용은 [Cisco Duo API 설명서](https://duo.com/docs/authapi)를 참조하세요.

1. GitLab 구성 파일을 엽니다.

   Linux 패키지 설치의 경우:

   ```shell
   sudo editor /etc/gitlab/gitlab.rb
   ```

   자체 컴파일 설치의 경우:

   ```shell
   cd /home/git/gitlab
   sudo -u git -H editor config/gitlab.yml
   ```

1. 공급자 구성을 추가합니다.

   Linux 패키지 설치의 경우:

   ```ruby
    gitlab_rails['duo_auth_enabled'] = true
    gitlab_rails['duo_auth_integration_key'] = '<duo_integration_key_value>'
    gitlab_rails['duo_auth_secret_key'] = '<duo_secret_key_value>'
    gitlab_rails['duo_auth_hostname'] = '<duo_api_hostname>'
   ```

   자체 컴파일 설치의 경우:

   ```yaml
   duo_auth:
     enabled: true
     hostname: <duo_api_hostname>
     integration_key: <duo_integration_key_value>
     secret_key: <duo_secret_key_value>
   ```

1. 구성 파일을 저장합니다.
1. Linux 패키지 설치의 경우 [GitLab을 재구성](../../../administration/restart_gitlab.md#reconfigure-a-linux-package-installation)합니다. 자체 컴파일 설치의 경우 [GitLab을 다시 시작](../../../administration/restart_gitlab.md#self-compiled-installations)합니다.

### FortiAuthenticator 인증기 추가 {#add-a-fortiauthenticator-authenticator}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

> [!flag]
> GitLab Self-Managed에서 기본적으로 이 기능은 사용할 수 없습니다. 사용자별로 사용 가능하게 하려면 관리자가 [기능 플래그를 활성화](../../../administration/feature_flags/_index.md)할 수 있으며 `forti_authenticator`라는 이름이 지정됩니다. GitLab.com 및 GitLab Dedicated에서는 이 기능을 사용할 수 없습니다.

FortiAuthenticator를 GitLab의 OTP 공급자로 사용할 수 있습니다. 사용자는 다음을 수행해야 합니다:

- FortiAuthenticator 및 GitLab에 모두 있어야 하며 동일한 사용자 이름을 가져야 합니다.
- FortiAuthenticator에서 FortiToken이 구성되어 있어야 합니다.

FortiAuthenticator에 대한 사용자 이름 및 액세스 토큰이 필요합니다. 아래 표시된 `access_token`는 FortiAuthenticator 액세스 키입니다. 토큰을 얻으려면 [Fortinet 문서 라이브러리](https://docs.fortinet.com/document/fortiauthenticator/6.2.0/rest-api-solution-guide/158294/the-fortiauthenticator-api)에서 REST API 솔루션 가이드를 참조하세요. FortiAuthenticator 버전 6.2.0으로 테스트되었습니다.

GitLab에서 FortiAuthenticator를 구성합니다. GitLab 서버에서:

1. 구성 파일을 엽니다.

   Linux 패키지 설치의 경우:

   ```shell
   sudo editor /etc/gitlab/gitlab.rb
   ```

   자체 컴파일 설치의 경우:

   ```shell
   cd /home/git/gitlab
   sudo -u git -H editor config/gitlab.yml
   ```

1. 공급자 구성을 추가합니다.

   Linux 패키지 설치의 경우:

   ```ruby
   gitlab_rails['forti_authenticator_enabled'] = true
   gitlab_rails['forti_authenticator_host'] = 'forti_authenticator.example.com'
   gitlab_rails['forti_authenticator_port'] = 443
   gitlab_rails['forti_authenticator_username'] = '<some_username>'
   gitlab_rails['forti_authenticator_access_token'] = 's3cr3t'
   ```

   자체 컴파일 설치의 경우:

   ```yaml
   forti_authenticator:
     enabled: true
     host: forti_authenticator.example.com
     port: 443
     username: <some_username>
     access_token: s3cr3t
   ```

1. 구성 파일을 저장합니다.
1. [재구성](../../../administration/restart_gitlab.md#reconfigure-a-linux-package-installation)(Linux 패키지 설치) 또는 [다시 시작](../../../administration/restart_gitlab.md#self-compiled-installations)(자체 컴파일 설치)합니다.

### FortiToken Cloud 인증기 추가 {#add-a-fortitoken-cloud-authenticator}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

> [!flag]
> GitLab Self-Managed에서 기본적으로 이 기능은 사용할 수 없습니다. 사용자별로 사용 가능하게 하려면 관리자가 [기능 플래그를 활성화](../../../administration/feature_flags/_index.md)할 수 있으며 `forti_token_cloud`라는 이름이 지정됩니다. GitLab.com 및 GitLab Dedicated에서는 이 기능을 사용할 수 없습니다. 이 기능은 프로덕션 사용을 위해 준비되지 않았습니다.

FortiToken Cloud를 GitLab의 OTP 공급자로 사용할 수 있습니다. 사용자는 다음을 수행해야 합니다:

- FortiToken Cloud 및 GitLab에 모두 있어야 하며 동일한 사용자 이름을 가져야 합니다.
- FortiToken Cloud에서 FortiToken이 구성되어 있어야 합니다.

FortiToken Cloud를 구성하려면 `client_id` 및 `client_secret`가 필요합니다. 이를 얻으려면 [Fortinet 문서 라이브러리](https://docs.fortinet.com/document/fortitoken-cloud/latest/rest-api/456035/overview)에서 REST API 가이드를 참조하세요.

GitLab에서 FortiToken Cloud를 구성합니다. GitLab 서버에서:

1. 구성 파일을 엽니다.

   Linux 패키지 설치의 경우:

   ```shell
   sudo editor /etc/gitlab/gitlab.rb
   ```

   자체 컴파일 설치의 경우:

   ```shell
   cd /home/git/gitlab
   sudo -u git -H editor config/gitlab.yml
   ```

1. 공급자 구성을 추가합니다.

   Linux 패키지 설치의 경우:

   ```ruby
   gitlab_rails['forti_token_cloud_enabled'] = true
   gitlab_rails['forti_token_cloud_client_id'] = '<your_fortinet_cloud_client_id>'
   gitlab_rails['forti_token_cloud_client_secret'] = '<your_fortinet_cloud_client_secret>'
   ```

   자체 컴파일 설치의 경우:

   ```yaml
   forti_token_cloud:
     enabled: true
     client_id: YOUR_FORTI_TOKEN_CLOUD_CLIENT_ID
     client_secret: YOUR_FORTI_TOKEN_CLOUD_CLIENT_SECRET
   ```

1. 구성 파일을 저장합니다.
1. [재구성](../../../administration/restart_gitlab.md#reconfigure-a-linux-package-installation)(Linux 패키지 설치) 또는 [다시 시작](../../../administration/restart_gitlab.md#self-compiled-installations)(자체 컴파일 설치)합니다.

## 복구 코드 {#recovery-codes}

OTP 인증기로 2FA를 성공적으로 활성화한 직후 생성된 복구 코드 집합을 다운로드하라는 메시지가 표시됩니다. OTP 인증기에 대한 액세스 권한을 잃으면 이러한 복구 코드 중 하나를 사용하여 계정에 로그인할 수 있습니다.

코드를 복사하여 인쇄하거나 **코드 다운로드**를 사용하여 안전한 장소에 저장하기 위해 다운로드해야 합니다. 다운로드하도록 선택하면 파일의 이름이 `gitlab-recovery-codes.txt`입니다.

> [!note]
>
> - 각 코드를 한 번만 사용하여 계정에 로그인할 수 있습니다.
> - WebAuthn 장치에 대해 복구 코드가 생성되지 않습니다.

복구 코드를 다시 생성하거나 복원하는 방법에 대한 내용은 [복구 옵션 및 2FA 재설정](two_factor_authentication_troubleshooting.md#recovery-options-and-2fa-reset)을 참조하세요.

## 2단계 인증으로 로그인 {#sign-in-with-two-factor-authentication}

2FA가 활성화되면 사용자 이름과 비밀번호를 입력한 다음 추가 인증 방법을 사용하여 신원을 확인합니다. 2FA 방법이 두 개 이상인 경우 로그인할 때 그 사이를 전환할 수 있습니다.

### OTP 인증기로 로그인 {#sign-in-with-an-otp-authenticator}

**인증 앱 코드를 입력** 화면에서 OTP 인증기로 생성된 6자리 코드를 입력한 다음 **코드 확인**을 선택합니다.

대신 복구 코드를 사용하여 로그인하려면 **계정 복구**를 선택한 다음 **계정 복구 코드를 입력** 화면에 복구 코드를 입력합니다.

### WebAuthn 장치로 로그인 {#sign-in-with-a-webauthn-device}

**보안 장치로 검증** 화면에서 브라우저 또는 비밀번호 관리자에서 WebAuthn 장치를 활성화하도록 요청하며, 예를 들어 터치하거나 버튼을 누르는 방식입니다. 장치가 인증 요청에 응답하면 로그인됩니다.

장치가 응답하지 않으면 **다시 시도하십시오**를 선택합니다.

### 이메일 OTP로 로그인 {#sign-in-with-email-otp}

**이메일로 인증** 화면에서 GitLab은 이메일 주소로 6자리 확인 코드를 보냅니다. 코드를 입력한 다음 **코드 확인**을 선택합니다. 코드는 60분 동안 유효합니다.

코드가 도착하지 않거나 만료된 경우 **코드 재전송**을 선택하여 새 코드를 요청합니다. 기타 문제의 경우 [이메일 OTP 문제 해결](two_factor_authentication_troubleshooting.md#email-otp-troubleshooting)을 참조하세요.

### 개인 액세스 토큰으로 로그인 {#sign-in-with-a-personal-access-token}

2FA가 활성화되면 HTTPS를 통해 Git으로 인증하거나 [GitLab API](../../../api/rest/_index.md)를 사용하기 위해 비밀번호를 사용할 수 없습니다. 대신 [개인 액세스 토큰](../personal_access_tokens.md)을 사용해야 합니다.

## 2단계 인증 비활성화 {#disable-two-factor-authentication}

{{< history >}}

- OTP 인증기 및 WebAuthn 장치를 개별적으로 또는 동시에 비활성화할 수 있는 기능이 GitLab 17.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/393419)되었습니다.

{{< /history >}}

OTP 인증기 및 WebAuthn 장치를 개별적으로 또는 동시에 비활성화할 수 있습니다. 동시에 비활성화하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **비밀번호와 인증**을 선택합니다.
1. **2FA 비활성화**를 선택합니다.
1. 대화 상자에서 현재 비밀번호를 입력하고 **2FA 비활성화**를 선택합니다.

그룹 또는 인스턴스 설정에서 계정이 2FA를 사용하도록 요구할 수 있습니다. GitLab.com에서 비밀번호 기반 로그인은 이메일 OTP 확인을 완료해야 합니다.

## OAuth 자격 증명 도우미 {#oauth-credential-helpers}

다음 Git 자격 증명 도우미는 OAuth를 사용하여 GitLab에 인증합니다. 이는 2단계 인증과 호환됩니다. 처음 인증할 때 도우미가 웹 브라우저를 열고 GitLab에서 앱을 승인하도록 요청합니다. 후속 인증은 상호 작용이 필요하지 않습니다.

### Git 자격 증명 관리자 {#git-credential-manager}

[Git 자격 증명 관리자](https://github.com/git-ecosystem/git-credential-manager)(GCM)는 기본적으로 OAuth를 사용하여 인증합니다. GCM은 수동 구성 없이 GitLab.com을 지원합니다. GitLab Self-Managed에서 GCM을 사용하려면 [GitLab 지원](https://github.com/git-ecosystem/git-credential-manager/blob/main/docs/gitlab.md)을 참조하세요.

매번 푸시할 때마다 다시 인증할 필요가 없도록 GCM은 캐싱 및 세션 간에 유지되는 다양한 플랫폼별 자격 증명 저장소를 지원합니다. 이 기능은 개인 액세스 토큰이든 OAuth든 사용할 수 있습니다.

Git for Windows는 Git 자격 증명 관리자를 포함합니다.

Git 자격 증명 관리자는 주로 GitHub, Inc.에서 개발합니다. 오픈 소스 프로젝트이며 커뮤니티에서 지원합니다.

### git-credential-oauth {#git-credential-oauth}

[git-credential-oauth](https://github.com/hickford/git-credential-oauth)는 수동 구성 없이 GitLab.com 및 여러 인기 있는 공개 호스트를 지원합니다. GitLab Self-Managed에서 사용하려면 [git-credential-oauth 사용자 지정 호스트 설명서](https://github.com/hickford/git-credential-oauth#custom-hosts)를 참조하세요.

많은 Linux 배포판은 git-credential-oauth를 패키지로 포함합니다.

git-credential-oauth는 커뮤니티에서 지원하는 오픈 소스 프로젝트입니다.

## GitLab 관리자 정보 {#information-for-gitlab-administrators}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

- [GitLab 백업 복원](../../../administration/backup_restore/_index.md) 후 2FA가 계속 작동하도록 주의합니다.
- 2FA가 OTP 서버로 올바르게 승인되도록 하려면 NTP와 같은 서비스를 사용하여 GitLab 서버의 시간을 동기화합니다. 그렇지 않으면 시간 차이로 인해 항상 승인이 실패할 수 있습니다.
- GitLab WebAuthn 구현은 여러 호스트명 또는 FQDN에서 GitLab 인스턴스에 액세스할 때 작동하지 않습니다. 각 WebAuthn 등록은 등록 시점의 현재 호스트명에 연결되며 다른 호스트명 또는 FQDN에 사용할 수 없습니다.

  예를 들어 사용자가 `first.host.xyz` 및 `second.host.xyz`에서 GitLab 인스턴스에 액세스하려고 하는 경우:

  - 사용자는 `first.host.xyz`을 사용하여 로그인하고 WebAuthn 키를 등록합니다.
  - 사용자가 로그아웃하고 `first.host.xyz`을 사용하여 로그인하려고 시도합니다 - WebAuthn 인증이 성공합니다.
  - 사용자가 로그아웃하고 `second.host.xyz`을 사용하여 로그인하려고 시도합니다 - WebAuthn 인증이 실패합니다. WebAuthn 키가 `first.host.xyz`에만 등록되어 있기 때문입니다.

- 시스템 또는 그룹 수준에서 2FA를 적용하려면 [2단계 인증 적용](../../../security/two_factor_authentication.md)을 참조하세요.
