---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
gitlab_dedicated: yes
title: 2단계 인증 문제 해결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

## 오류: `HTTP Basic: Access denied. If a password was provided for Git authentication ...` {#error-http-basic-access-denied-if-a-password-was-provided-for-git-authentication-}

요청을 할 때 다음과 같은 오류가 나타날 수 있습니다:

```plaintext
HTTP Basic: Access denied. If a password was provided for Git authentication,
the password was incorrect or you're required to use a token instead of a password.
If a token was provided, it was either incorrect, expired, or improperly scoped.
```

이 오류는 다음의 경우에 발생합니다:

- 2FA를 활성화했고 사용자 이름과 비밀번호로 인증을 시도했습니다.
- 2FA를 활성화하지 않았지만 GitLab 인스턴스에서 필수입니다. 이는 GitLab.com에 적용됩니다. 자세한 내용은 [필수 MFA 변경](https://support.gitlab.com/hc/en-us/articles/26704344871452-Upcoming-Mandatory-MFA-Changes)과 [이메일 OTP 문제 해결](#email-otp-troubleshooting)을 참조하세요.
- 2FA를 활성화하지 않았고 잘못된 사용자 이름 또는 비밀번호로 인증을 시도했습니다.
- 2FA를 활성화하지 않았고 [모든 사용자에게 2FA 강제 실행](../../../security/two_factor_authentication.md#enforce-2fa-for-all-users) 설정이 활성화되어 있습니다.
- 2FA를 활성화하지 않았고 [**HTTP(S)를 통한 Git 비밀번호 인증 허용**](../../../administration/settings/sign_in_restrictions.md#allow-password-authentication-for-git-over-https) 확인란이 선택되지 않았습니다.

이 오류를 해결하려면:

- 올바른 범위를 가진 [개인 액세스 토큰](../personal_access_tokens.md)을 사용합니다:
  - HTTP(S)를 통한 Git 요청: `read_repository` 또는 `write_repository`
  - [GitLab 컨테이너 레지스트리](../../packages/container_registry/authenticate_with_container_registry.md) 요청: `read_registry` 또는 `write_registry`
  - [종속성 프록시](../../packages/dependency_proxy/_index.md#authenticate-with-the-dependency-proxy-for-container-images) 요청: `read_registry`과 `write_registry`

  이러한 범위는 레거시 개인 액세스 토큰에 적용됩니다. 세분화된 개인 액세스 토큰은 대신 리소스와 권한을 사용합니다. 세분화된 동등항목에 대해서는 [Git 및 기타 작업을 위한 세분화된 권한](../../../auth/tokens/fine_grained_access_tokens_other.md)을 참조하세요. 세분화된 개인 액세스 토큰을 사용하여 컨테이너 이미지를 푸시할 수 없습니다.
- LDAP를 구성한 경우 [LDAP 비밀번호](../../../administration/auth/ldap/_index.md)를 사용합니다.
- [OAuth 자격증명 도우미](two_factor_authentication.md#oauth-credential-helpers)를 사용합니다.

## 오류: `invalid pin code` {#error-invalid-pin-code}

`invalid pin code` 오류는 인증 애플리케이션과 GitLab 인스턴스 자체 간에 시간 동기화 문제가 있음을 나타낼 수 있습니다.

이 문제를 해결하려면 2FA 코드를 생성하는 디바이스에서 시간 동기화를 켜십시오.

{{< tabs >}}

{{< tab title="Android" >}}

1. **설정** > **시스템** > **날짜 및 시간**으로 이동합니다.
1. **자동으로 시간 설정**을 켭니다. 이 설정이 이미 켜져 있으면 끄고 몇 초 기다린 후 다시 켜십시오.

{{< /tab >}}

{{< tab title="iOS" >}}

1. **설정** > **일반** > **날짜 및 시간**으로 이동합니다.
1. **자동으로 설정**을 켭니다. 이 설정이 이미 켜져 있으면 끄고 몇 초 기다린 후 다시 켜십시오.

{{< /tab >}}

{{< /tabs >}}

## 오류: 복구 코드 생성 시 `Permission denied (publickey)` {#error-permission-denied-publickey-when-generating-recovery-codes}

`Permission denied (publickey)`라는 오류가 표시될 수 있습니다.

기본이 아닌 SSH 키 쌍 파일 경로를 사용하고 [SSH를 사용하여 복구 코드를 생성](#regenerate-recovery-codes-with-ssh)하려고 할 때 이 문제가 발생합니다.

이를 해결하려면 [SSH를 다른 디렉터리를 가리키도록 구성](../../ssh_advanced.md#use-ssh-keys-in-another-directory)하고 `ssh-agent`을 사용합니다.

## 이메일 OTP 문제 해결 {#email-otp-troubleshooting}

이메일 OTP로 작업할 때 다음과 같은 문제가 발생할 수 있습니다.

> [!note]
> 2026년 4월부터 GitLab.com에서 사용자 이름과 비밀번호를 사용하는 모든 로그인 또는 API 요청에 대해 다중 인증이 필수입니다. [이메일 OTP](two_factor_authentication.md#sign-in-with-email-otp)는 다른 인증 요소가 구성되지 않은 경우 GitLab.com의 필수 두 번째 인증 요소입니다.

### 향상된 인증 배너 및 암호 요구 사항 {#enhanced-authentication-banner-and-passcode-requirement}

**향상된 인증 곧 제공** 배너는 GitLab이 암호 기반 로그인 시 계정에 대해 [이메일 일회용 암호](two_factor_authentication.md#sign-in-with-email-otp) 강제 실행을 시작함을 나타냅니다. SSO로 로그인하거나 이미 2FA를 구성한 사용자는 영향을 받지 않습니다.

이 배너는 강제 실행 14일 전에 나타납니다. 강제 실행 7일 전부터 GitLab은 각 암호 기반 로그인 시 일회용 암호를 보냅니다. 이 기간 동안 암호 입력을 건너뛸 수 있습니다.

강제 실행 날짜가 지나면 모든 암호 기반 로그인 시 일회용 암호를 입력해야 합니다. 잠금되지 않으려면 기본 이메일 주소에 액세스할 수 있는지 확인하거나 [기본 이메일 주소를 변경](../_index.md#change-your-primary-email)하세요.

### 이메일 인증 코드를 받지 못했거나 코드가 만료됨 {#didnt-receive-email-verification-code-or-code-has-expired}

이메일이 도착할 때까지 1분 정도 기다린 다음 스팸 폴더를 확인하세요. GitLab.com에서는 `gitlab@mg.gitlab.com`에서 이메일을 보내며 [정품으로 확인](https://handbook.gitlab.com/handbook/security/corporate/systems/google/mail/verification/#verify-an-email-from-gitlabcom-is-genuine)할 수 있습니다.

코드가 도착하지 않거나 만료된 경우 로그인 화면에서 **코드 재전송**을 선택합니다. 각 재전송은 새로운 코드를 생성하고 이전 코드를 무효화하므로 다시 요청하기 전에 각 이메일을 기다리세요.

### 이메일 주소에 액세스할 수 없음 {#cannot-access-your-email-address}

기본 이메일 주소에 액세스할 수 없으면 계정과 연결된 다른 주소로 코드를 보낼 수 있습니다.

연결된 이메일 주소에 액세스할 수 없는 경우:

- 이전에 SSO를 구성한 경우 사용자 이름과 비밀번호 대신 SSO로 로그인하세요.
- GitLab.com 엔터프라이즈 사용자인 경우 그룹 소유자에게 [이메일 주소를 변경](../../enterprise_user/_index.md#change-the-email-addresses-for-an-enterprise-user)해 달라고 요청하세요.
- GitLab Self-Managed에서는 GitLab 관리자에게 문의하세요.
- [GitLab 지원팀에 문의](https://support.gitlab.com/)하세요.

### 이메일 OTP를 활성화하거나 비활성화할 수 없음 {#email-otp-cannot-be-enabled-or-disabled}

다음의 경우 이메일 OTP를 비활성화할 수 없습니다:

- 인스턴스에서 2FA를 요구하고 [OTP 인증자](two_factor_authentication.md#register-an-otp-authenticator) 또는 [WebAuthn 디바이스](two_factor_authentication.md#register-a-webauthn-device)를 등록하지 않았습니다.
- 계정이 향후 날짜에 자동 활성화되도록 예약되어 있습니다.

다음의 경우 이메일 OTP를 활성화할 수 없습니다:

- 그룹, 인스턴스 또는 관리자 정책이 OTP 인증자 또는 WebAuthn 디바이스를 사용하도록 요구합니다.
- 계정이 외부 ID 공급자를 사용합니다.
- 계정이 향후 날짜에 자동 활성화되도록 예약되어 있습니다.

## 복구 옵션 및 2FA 재설정 {#recovery-options-and-2fa-reset}

### 복구 코드 사용 {#use-a-recovery-code}

일회용 비밀번호(OTP) 인증자를 활성화했을 때 GitLab은 일련의 [복구 코드](two_factor_authentication.md#recovery-codes)를 제공했습니다. 이 코드를 사용하여 계정에 로그인할 수 있습니다.

복구 코드를 사용하려면:

1. GitLab 로그인 페이지에서 사용자 이름 또는 이메일과 비밀번호를 입력합니다.
1. 2단계 인증 화면에서 **계정 복구**를 선택합니다.
1. **계정 복구 코드를 입력** 화면에서 복구 코드를 입력한 다음 **코드 확인**을 선택합니다.

복구 코드를 사용한 후에는 같은 코드를 다시 사용할 수 없습니다. 다른 복구 코드는 유효하게 유지됩니다.

### UI를 사용하여 복구 코드 재생성 {#regenerate-recovery-codes-with-the-ui}

계정에 여전히 액세스할 수 있으면 사용자 설정을 통해 복구 코드를 재생성할 수 있습니다.

UI를 사용하여 복구 코드를 재생성하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **비밀번호와 인증**을 선택합니다.
1. **복구 코드** 섹션에서 **복구 코드 재생성**을 선택합니다.
1. 대화 상자에서 현재 비밀번호를 입력한 후 **복구 코드 재생성**을 선택합니다.

> [!note]
> 2FA 복구 코드를 재생성할 때마다 저장합니다. 이전에 생성한 2FA 코드는 사용할 수 없습니다.

### SSH를 사용하여 복구 코드 재생성 {#regenerate-recovery-codes-with-ssh}

[GitLab 계정에 SSH 키를 추가](../../ssh.md#add-an-ssh-key-to-your-gitlab-account)했으면 SSH를 사용하여 복구 코드를 재생성할 수 있습니다.

사전 요구 사항:

- GitLab 계정에 등록된 SSH 공개 키와 연결된 개인 SSH 키에 대한 액세스입니다.

> [!note]
> `gitlab-sshd`를 사용하여 복구 코드를 재생성할 수 없습니다.

SSH를 사용하여 복구 코드를 재생성하려면:

1. 터미널에서 SSH 에이전트가 디바이스에서 실행 중인지 확인합니다.
   - macOS 및 Linux에서 다음 명령을 실행합니다:

     ```shell
     eval "$(ssh-agent -s)"
     ```

   - Microsoft Windows에서 PowerShell에서 다음 명령을 실행합니다:

     ```pwsh
     Set-Service -Name ssh-agent -StartupType Automatic; Start-Service ssh-agent
     ```

     자세한 내용은 [Windows SSH 설정 지침](../../ssh_advanced.md#use-ssh-on-microsoft-windows)을 참조하세요.

1. 다음 명령을 사용하여 개인 키를 SSH 에이전트로 로드합니다:
   - macOS 및 Linux에서 다음 명령을 실행합니다:

     ```shell
     ssh-add <path to private SSH key file>
     ```

   자세한 내용은 [다른 디렉터리에서 SSH 키 사용](../../ssh_advanced.md#use-ssh-keys-in-another-directory)을 참조하세요.

1. 다음 명령을 사용하여 SSH 연결을 엽니다:

   ```shell
   ssh git@gitlab.com 2fa_recovery_codes
   ```

   GitLab Self-Managed 인스턴스에서 `gitlab.com`를 GitLab 서버 호스트 이름(`gitlab.example.com`)으로 바꿉니다.

1. 확인 메시지에서 `yes`을 입력합니다.
1. GitLab이 생성한 복구 코드를 저장합니다. 이전 복구 코드는 더 이상 유효하지 않습니다.
1. 로그인 페이지에서 사용자 이름 또는 이메일과 비밀번호를 입력합니다.
1. 2단계 인증 화면에서 **계정 복구**를 선택합니다.
1. **계정 복구 코드를 입력** 화면에서 복구 코드를 입력한 다음 **코드 확인**을 선택합니다.

로그인한 후 즉시 새 디바이스로 2FA를 설정하세요.

### 인증자 백업에서 2FA 코드 복원 {#restore-2fa-codes-from-authenticator-backup}

GitLab 복구 코드 외에도 많은 인증자 앱이 자체 백업 및 복구 방법을 제공합니다. 디바이스를 잃어버린 경우 백업 기능을 미리 활성화했으면 새 디바이스에서 인증자 앱에 로그인하여 2FA 코드를 복원할 수 있습니다.

사전 요구 사항:

- 디바이스에 대한 액세스를 잃기 전에 인증자 백업 기능을 활성화해야 합니다.

> [!note]
> GitLab은 복구 코드를 기본 복구 방법으로 사용할 것을 권장합니다. 2FA를 활성화할 때 복구 코드를 저장했는지 확인하세요.

GitLab 지원팀은 타사 인증자 앱과 관련된 복구 문제를 지원할 수 없습니다.

자세한 내용은 특정 인증자 앱의 설명서를 참조하세요. 일반적인 인증자의 설명서는 다음 위치를 통해 사용할 수 있습니다:

- [Microsoft Authenticator](https://support.microsoft.com/en-US/authenticator/restore-account-credentials-from-microsoft-authenticator)
- [Google Authenticator](https://support.google.com/accounts/answer/1066447)
- [Authy](https://www.twilio.com/en-us/blog/how-the-authy-two-factor-backups-work)
- [1Password](https://support.1password.com/recovery-codes/?mac#recover-your-account)

### 계정에서 2FA 재설정 {#reset-2fa-on-your-account}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

이전 복구 옵션이 작동하지 않으면 계정에서 2FA를 비활성화하기 위해 지원 요청을 만들 수 있습니다. 이 서비스는 GitLab.com 구독이 있는 계정에만 제공됩니다.

GitLab 지원팀은 Free 계정의 2FA를 재설정할 수 없습니다. 2FA 방법을 복구할 수 없으면 계정에서 영구적으로 잠금되며 새 계정을 만들어야 합니다. 자세한 내용은 [블로그 공지사항](https://about.gitlab.com/blog/gitlab-support-no-longer-processing-mfa-resets-for-free-users/)을 참조하세요.

지원 요청을 만들려면:

1. [GitLab 지원팀](https://support.gitlab.com)으로 이동합니다.
1. **티켓 제출**을 선택합니다.
1. GitLab 지원팀 계정으로 로그인합니다. 지원 계정은 GitLab 계정과 다르며 2FA 문제의 영향을 받지 않습니다.
1. 이슈 드롭다운 목록에서 **GitLab.com 사용자 계정 및 로그인 문제**를 선택합니다.
1. 지원 양식의 필드를 완료합니다.
1. **제출**을 선택합니다.

계정에 다시 액세스한 후 계정을 안전하게 유지하기 위해 최대한 빨리 2FA를 다시 활성화하세요.

### 엔터프라이즈 사용자의 2FA 재설정 {#reset-2fa-for-enterprise-users}

유료 요금제의 최상위 그룹 소유자인 경우 엔터프라이즈 사용자의 2FA를 비활성화할 수 있습니다. 자세한 내용은 [엔터프라이즈 사용자의 2FA 비활성화](../../../security/two_factor_authentication.md#enterprise-users)를 참조하세요.
