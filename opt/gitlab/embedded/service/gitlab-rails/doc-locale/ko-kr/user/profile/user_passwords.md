---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 사용자 비밀번호
description: 요구사항 적용 및 비밀번호 재설정 절차를 통해 사용자 비밀번호를 보호합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab에 로그인하려면 강력한 비밀번호를 사용하는 것이 매우 중요합니다. 약한 비밀번호나 쉽게 추측할 수 있는 비밀번호는 권한이 없는 사람들이 계정에 로그인하기 쉽게 만듭니다.

일부 조직에서는 비밀번호를 선택할 때 특정 요구사항을 충족하도록 요구합니다.

[2단계 인증](account/two_factor_authentication.md)으로 계정의 보안을 개선합니다.

## 비밀번호 요구사항 {#password-requirements}

비밀번호 요구사항은 다음과 같은 경우에 적용됩니다:

- 등록 중에 비밀번호를 선택합니다.
- 비밀번호를 재설정합니다.
- 비밀번호를 변경합니다.
- 관리자가 계정을 생성하거나 업데이트합니다.

기본적으로 GitLab은 다음 요구사항을 적용합니다:

- 최소 비밀번호 길이: 8자(문자).
- 최대 비밀번호 길이: 128자(문자).
- 4,500개 이상의 알려진 유출된 비밀번호 목록과 일치하지 않아야 합니다.
- 이름, 사용자명 또는 이메일 주소의 일부를 포함하지 않아야 합니다.
- 예측 가능한 단어(`gitlab` 또는 `devops`)를 포함하지 않아야 합니다.

GitLab Self-Managed 및 GitLab Dedicated에서 관리자는 [비밀번호 복잡성 요구사항을 수정](../../administration/settings/sign_up_restrictions.md#modify-password-complexity-requirements)할 수 있습니다.

## 손상된 비밀번호 감지 {#compromised-password-detection}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- GitLab 18.0에서 `notify_compromised_passwords` [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/188723)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.1에서 GitLab.com에 활성화되었습니다. 기능 플래그 `notify_compromised_passwords`이 제거되었습니다.

{{< /history >}}

GitLab은 GitLab.com 자격증명이 다른 서비스나 플랫폼의 데이터 유출 일부로 손상된 경우 이를 알립니다. GitLab 자격증명은 암호화되어 있으며 GitLab 자체는 이에 직접 액세스할 수 없습니다.

손상된 자격증명이 감지되면 GitLab은 보안 배너를 표시하고 비밀번호를 변경하는 방법과 계정 보안을 강화하는 방법에 대한 지침이 포함된 이메일 알림을 보냅니다.

손상된 비밀번호 감지는 [외부 제공자로 인증](../../administration/auth/_index.md)할 때 또는 계정이 이미 [잠긴](../../security/unlock_user.md) 경우에는 사용할 수 없습니다.

## 비밀번호 선택 {#choose-your-password}

[사용자 계정을 생성](account/create_accounts.md)할 때 비밀번호를 선택할 수 있습니다.

### 외부 인증 계정의 비밀번호 {#passwords-for-externally-authenticated-accounts}

외부 [인증 및 인가 제공자](../../administration/auth/_index.md)를 사용하여 계정을 생성한 경우 GitLab은 데이터 일관성을 유지하기 위해 무작위 비밀번호를 자동으로 생성합니다.

이 비밀번호의 속성은 다음과 같습니다:

- 길이 128자(문자)
- Devise gem의 [`friendly_token` 메서드](https://github.com/heartcombo/devise/blob/f26e05c20079c9acded3c0ee16da0df435a28997/lib/devise.rb#L492)를 사용하여 생성됨
- 고유하고 안전함

일반적으로 이 비밀번호를 알거나 사용할 필요가 없습니다. 그러나 passkey를 만들거나 다른 유사한 상황에서 입력해야 할 수도 있습니다.

GitLab 비밀번호를 입력해야 하는 경우 [비밀번호 재설정 프로세스](#reset-your-password)를 따라 사용할 수 있는 새 비밀번호를 만들 수 있습니다.

이는 외부 ID 제공자의 비밀번호에는 영향을 주지 않습니다.

## 비밀번호 변경 {#change-your-password}

비밀번호를 변경할 수 있습니다. 새 비밀번호는 비밀번호 요구사항을 충족해야 합니다.

비밀번호를 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **비밀번호와 인증**을 선택합니다.
1. **비밀번호 변경**을 선택합니다.
1. **현재 비밀번호** 텍스트 상자에 현재 비밀번호를 입력합니다.
1. **새 비밀번호** 및 **비밀번호 확인** 텍스트 상자에 새 비밀번호를 입력합니다.
1. **비밀번호 저장**을 선택합니다.

## 비밀번호 재설정 {#reset-your-password}

비밀번호를 잊어버린 경우 비밀번호 재설정 요청을 제출할 수 있습니다.

비밀번호를 재설정하려면:

1. GitLab 로그인 페이지로 이동합니다.
   - GitLab.com에서는 [https://gitlab.com/users/sign_in](https://gitlab.com/users/sign_in/)에서 사용할 수 있습니다.
   - GitLab Self-Managed 및 GitLab Dedicated에서는 사용자의 도메인을 사용합니다. 예를 들어, `gitlab.example.com/users/sign_in`입니다.
1. **비밀번호를 잊어버리셨나요?**를 선택합니다.
1. 이메일을 입력합니다.
1. **비밀번호 재설정**을 선택합니다.

로그인 페이지로 리디렉션됩니다. 제공된 이메일이 확인되고 기존 계정과 연결되어 있으면 GitLab이 비밀번호 재설정 이메일을 보냅니다.

> [!note]
> 계정에는 확인된 이메일 주소가 여러 개 있을 수 있으며, 계정과 연결된 모든 이메일 주소를 확인할 수 있습니다. 그러나 비밀번호가 재설정되면 기본 이메일 주소만 로그인에 사용할 수 있습니다.

## 자격증명 저장소 {#credential-storage}

GitLab은 사용자 비밀번호를 일반 텍스트가 아닌 해시된 형식으로 저장합니다. 비밀번호를 해시하기 위해 GitLab은 [Devise](https://github.com/heartcombo/devise) 인증 라이브러리를 사용합니다.

비밀번호 해시는 다음과 같은 보안 조치를 사용합니다:

- 해싱 알고리즘:
  - Bcrypt: 기본적으로 사용됩니다.
  - PBKDF2+SHA512: FIPS 모드가 활성화되었을 때 사용됩니다.
- 스트레칭: 비밀번호는 무차별 공격으로부터 보호하기 위해 [스트레칭](https://en.wikipedia.org/wiki/Key_stretching)됩니다. 스트레칭 계수는 해싱 알고리즘에 따라 다릅니다:
  - Bcrypt: 10
  - PBKDF2+SHA512: 20,000
- 솔팅(Salting): 무작위 [암호화 솔트](https://en.wikipedia.org/wiki/Salt_(cryptography))는 미리 계산된 해시 및 사전 공격으로부터 보호하기 위해 각 비밀번호에 대해 생성됩니다. 각 비밀번호는 고유한 솔트를 가집니다.

OAuth 액세스 토큰도 PBKDF2+SHA512 형식으로 데이터베이스에 저장되고 20,000번 스트레칭됩니다.
