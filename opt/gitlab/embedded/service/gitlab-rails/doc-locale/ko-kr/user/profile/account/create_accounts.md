---
stage: Fulfillment
group: Provision
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab에서 사용자 계정을 생성합니다.
title: 사용자 생성
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

사용자 계정은 GitLab 협업의 기초를 이룹니다. GitLab 프로젝트에 접근해야 하는 모든 사람은 계정이 필요합니다. 사용자 계정은 액세스 권한을 제어하고 기여도를 추적하며 인스턴스 전체의 보안을 유지합니다.

GitLab에서 다양한 방식으로 사용자 계정을 생성할 수 있습니다:

- 자율성을 중시하는 팀을 위해 사용자 계정을 수동으로 생성
- 제어된 온보딩을 위한 관리자 주도 생성
- 엔터프라이즈 환경을 위한 인증 통합
- 자동화 및 대량 작업을 위한 콘솔 액세스

[사용자 API 엔드포인트](../../../api/users.md#create-a-user)를 사용하여 사용자를 자동으로 생성할 수도 있습니다.

조직의 규모, 보안 요구사항 및 워크플로우에 따라 적절한 방법을 선택합니다.

## 로그인 페이지에서 사용자 생성 {#create-a-user-on-the-sign-in-page}

기본적으로 GitLab 인스턴스를 방문하는 모든 사용자는 계정을 생성할 수 있습니다. 이전에 [이 설정을 비활성화](../../../administration/settings/sign_up_restrictions.md#disable-new-user-account-creation)했다면 다시 활성화해야 합니다.

사용자는 다음 방법 중 하나로 자신의 계정을 생성할 수 있습니다:

- 로그인 페이지에서 **지금 등록하세요** 링크를 선택합니다.
- GitLab 인스턴스의 새 사용자 계정 링크로 이동합니다(예: `https://gitlab.example.com/users/sign_up`).

## 관리 영역에서 사용자 생성 {#create-a-user-in-the-admin-area}

사전 요구 사항:

- 인스턴스의 관리자여야 합니다.

사용자를 생성하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **개요** > **사용자**를 선택합니다.
1. **새 사용자**를 선택합니다.
1. **계정** 섹션에서 필수 계정 정보를 입력합니다.
1. 선택 사항. **액세스** 섹션에서 프로젝트 제한이나 사용자 유형 설정을 구성합니다.
1. **사용자 생성**을 선택합니다.

GitLab은 사용자에게 로그인 링크가 포함된 이메일을 보내며, 사용자는 처음 로그인할 때 비밀번호를 생성해야 합니다. [비밀번호를 설정](../../../security/reset_user_password.md#use-the-ui)하여 사용자용으로 직접 설정할 수도 있습니다.

## 인증 통합을 사용하여 사용자 생성 {#create-a-user-with-an-authentication-integration}

GitLab은 인증 통합을 통해 사용자 계정을 자동으로 생성할 수 있습니다. 사용자는 다음 경우에 생성됩니다:

- ID 공급자에서 [SCIM](../../group/saml_sso/scim_setup.md)을 통해 프로비저닝됩니다.
- 처음으로 다음을 사용하여 로그인합니다:
  - [LDAP](../../../administration/auth/ldap/_index.md)
  - [그룹 SAML](../../group/saml_sso/_index.md)
  - [OmniAuth 공급자](../../../integration/omniauth.md)(설정 `allow_single_sign_on`가 켜져 있는)

## Rails 콘솔을 통해 사용자 생성 {#create-a-user-through-the-rails-console}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 잘못된 조건에서 실행되면 손상을 일으킬 수 있습니다. 항상 먼저 테스트 환경에서 명령을 실행하고 복원할 준비가 된 백업 인스턴스를 준비합니다.

Rails 콘솔을 통해 사용자를 생성하려면:

1. [Rails 콘솔 세션](../../../administration/operations/rails_console.md#starting-a-rails-console-session)을 시작합니다.
1. GitLab 버전에 따라 명령을 실행합니다:

   {{< tabs >}}

   {{< tab title="16.10 이전" >}}

   ```ruby
   u = User.new(username: 'test_user', email: 'test@example.com', name: 'Test User', password: 'password', password_confirmation: 'password')
   # u.assign_personal_namespace
   u.skip_confirmation! # Use only if you want the user to be automatically confirmed. If you do not use this, the user receives a confirmation email.
   u.save!
   ```

   {{< /tab >}}

   {{< tab title="16.11~17.6" >}}

   ```ruby
   u = User.new(username: 'test_user', email: 'test@example.com', name: 'Test User', password: 'password', password_confirmation: 'password')
   u.assign_personal_namespace(Organizations::Organization.default_organization)
   u.skip_confirmation! # Use only if you want the user to be automatically confirmed. If you do not use this, the user receives a confirmation email.
   u.save!
   ```

   {{< /tab >}}

   {{< tab title="17.7 이상" >}}

   ```ruby
   u = Users::CreateService.new(nil,
     username: 'test_user',
     email: 'test@example.com',
     name: 'Test User',
     password: '123password',
     password_confirmation: '123password',
     organization_id: Organizations::Organization.first.id,
     skip_confirmation: true
   ).execute
   ```

   > [!note]
   > [새 사용자 계정을 비활성화](../../../administration/settings/sign_up_restrictions.md#disable-new-user-account-creation)한 경우 관리자로 이 명령을 실행해야 합니다. 이전 명령에서 `Users::CreateService.new(nil,`을 `Users::CreateService.new(User.find_by(admin: true),`로 바꿉니다

   {{< /tab >}}

   {{< /tabs >}}
