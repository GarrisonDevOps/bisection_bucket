---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "개인 액세스 토큰을 사용하여 GitLab API 또는 Git over HTTPS로 인증합니다. 생성, 교체, 해지, 범위 및 만료 설정을 포함합니다."
title: 개인 액세스 토큰
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

개인 액세스 토큰은 GitLab에 대한 인증된 액세스를 제공합니다. [OAuth2 토큰](../../api/oauth2.md)의 대안이며 그룹 액세스 토큰 및 프로젝트 액세스 토큰과 유사하지만, 그룹이나 프로젝트가 아닌 사용자에게 연결됩니다.

개인 액세스 토큰을 사용하여 다음과 같이 인증할 수 있습니다:

- [GitLab API](../../api/rest/authentication.md#personal-project-and-group-access-tokens)를 사용합니다.
- Git over HTTPS를 사용합니다. 사용:
  - 빈 값이 아닌 모든 값을 사용자 이름으로 사용합니다.
  - 개인 액세스 토큰을 암호로 사용합니다.

> [!note]
> [2단계 인증(2FA)](account/two_factor_authentication.md) 또는 [SAML](../../integration/saml.md#password-generation-for-users-created-through-saml)이 활성화된 경우 개인 액세스 토큰으로 인증해야 합니다.

[GitLab에서 관리하는 Terraform 상태 백엔드](../infrastructure/iac/terraform_state.md#use-your-gitlab-backend-as-a-remote-data-source)및 [컨테이너 레지스트리](../packages/container_registry/authenticate_with_container_registry.md)와 같이 사용자 이름이 필요한 일부 GitLab 기능은 GitLab 사용자 이름으로 개인 액세스 토큰을 사용합니다. 이 경우 사용자 이름은 필요하지만 인증의 일부로 평가되지 않습니다. 자세한 내용은 [issue 212953](https://gitlab.com/gitlab-org/gitlab/-/issues/212953)을 참조하세요.

GitLab Self-Managed 및 GitLab Dedicated 인스턴스에서 관리자는 [사용자 토큰 API](../../api/user_tokens.md#create-an-impersonation-token)를 사용하여 특정 사용자로 인증하기 위한 가장 행 토큰을 생성할 수 있습니다.

## 개인 액세스 토큰 생성 {#create-a-personal-access-token}

{{< history >}}

- 최대 허용 수명 제한이 GitLab 17.6에서 [400일로 확장](https://gitlab.com/gitlab-org/gitlab/-/issues/461901)되었으며 [기능 플래그](../../administration/feature_flags/list.md)(`buffered_token_expiration_limit`)를 사용합니다. 기본적으로 비활성화되었습니다.
- 개인 액세스 토큰 설명이 GitLab 17.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/443819)되었습니다.

{{< /history >}}

> [!flag]
> 확장된 최대 허용 수명 제한의 사용 가능성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

개인 액세스 토큰을 생성하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **개인 액세스 토큰**을 선택합니다.
1. **토큰 생성** 드롭다운 목록에서 **레거시 토큰**을 선택합니다.
1. **토큰 이름**에 토큰의 이름을 입력합니다.
1. 선택 사항. **토큰 설명**에 토큰에 대한 설명을 입력합니다.
1. **만료일**에 토큰의 만료 날짜를 입력합니다.
   - 토큰은 그 날짜의 자정 UTC에 만료됩니다.
   - 날짜를 입력하지 않으면 만료일이 오늘로부터 365일로 설정됩니다.
   - 기본적으로 만료일은 오늘로부터 365일을 초과할 수 없습니다. GitLab 17.6 이상에서는 관리자가 [액세스 토큰의 최대 수명을 수정](../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens)할 수 있습니다.
1. 하나 이상의 [개인 액세스 토큰 범위](../../security/tokens/access_token_scopes.md)를 선택합니다.
1. **토큰 생성**을 선택합니다.

개인 액세스 토큰이 표시됩니다. 개인 액세스 토큰을 안전한 위치에 저장합니다. 페이지를 떠나거나 새로 고친 후에는 다시 볼 수 없습니다.

모든 액세스 토큰은 개인 액세스 토큰에 대해 구성된 [기본 접두사 설정](../../administration/settings/account_and_limit_settings.md#personal-access-token-prefix)을 상속합니다.

### 개인 액세스 토큰 세부 정보 미리 채우기 {#prefill-personal-access-token-details}

`name`, `description` 및 `scopes` 매개 변수를 URL에 추가하여 개인 액세스 토큰의 세부 정보를 미리 채울 수 있습니다. 예를 들어:

```plaintext
https://gitlab.example.com/-/user_settings/personal_access_tokens?name=Example+Access+token&description=My+description&scopes=api,read_user
```

URL에는 최소한 하나의 유효한 범위가 포함되어야 합니다. `name` 및 `description` 매개 변수는 URL에서 선택 사항이지만, URL에 포함되지 않은 경우 생성 양식에서 토큰 이름을 입력해야 합니다.

> [!note]
> 개인 액세스 토큰은 신중하게 처리해야 합니다. 개인 액세스 토큰 관리에 대한 지침은 [토큰 보안 고려 사항](../../security/tokens/_index.md#security-considerations)을 참조하세요.

## 액세스 토큰으로 인증 {#authenticate-with-an-access-token}

액세스 토큰을 사용하여 GitLab REST API, Git over HTTPS 및 GitLab과 통합된 타사 도구로 인증합니다.

### REST API 사용 {#use-rest-api}

`PRIVATE-TOKEN` 헤더에 토큰을 전달합니다:

```shell
curl --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/projects"
```

자세한 내용은 [REST API 인증](../../api/rest/authentication.md#personal-project-and-group-access-tokens)을 참조하세요.

### Git over HTTPS 사용 {#use-git-over-https}

Git에서 자격 증명을 입력하라는 메시지가 표시될 때 토큰을 암호로 사용합니다:

- 사용자 이름: 비어 있지 않은 문자열(GitLab은 이 값을 검증하지 않음)입니다.
- 암호: 개인 액세스 토큰입니다.

예를 들어:

```shell
git clone https://oauth2:<your_access_token>@gitlab.example.com/gitlab-org/gitlab.git
```

### 타사 도구 및 IDE 확장 프로그램 사용 {#use-third-party-tools-and-ide-extensions}

IDE 확장 프로그램, CI/CD 도구 및 자동화 스크립트와 같이 GitLab과 통합되는 도구는 인증을 위해 개인 액세스 토큰을 허용합니다. 각 도구의 설명서는 필요한 범위와 토큰을 입력하는 방법을 설명합니다:

- [GitLab CLI(`glab`)](https://docs.gitlab.com/cli/#authenticate-with-gitlab)
- [GitLab for VS Code 확장](../../editor_extensions/visual_studio_code/setup.md#authenticate-with-gitlab)
- [GitLab Duo plugin for JetBrains IDEs](../../editor_extensions/jetbrains_ide/setup.md#authenticate-with-gitlab)
- [GitLab for Visual Studio extension](../../editor_extensions/visual_studio/setup.md#authenticate-with-gitlab)
- [GitLab for Eclipse](../../editor_extensions/eclipse/setup.md#authenticate-with-gitlab)
- [GitLab plugin for Neovim](../../editor_extensions/neovim/setup.md#authenticate-with-gitlab)

CI/CD 파이프라인의 경우 대신 [CI/CD 작업 토큰](../../ci/jobs/ci_job_token.md)을 사용하는 것이 좋습니다.

개인 액세스 토큰 보안 지침은 [토큰 보안 고려 사항](../../security/tokens/_index.md#security-considerations)을 참조하세요.

## 토큰 사용 정보 보기 {#view-token-usage-information}

{{< history >}}

- IP 주소를 볼 수 있는 기능이 GitLab 17.8에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/428577)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)(`pat_ip`)를 사용합니다. 17.9에서 기본적으로 활성화됩니다.
- IP 주소를 보는 기능이 GitLab 17.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/513302)해졌습니다. 기능 플래그 `pat_ip`이 제거되었습니다.

{{< /history >}}

개인 액세스 토큰 페이지에는 액세스 토큰에 대한 정보가 표시됩니다.

이 페이지에서 다음 작업을 수행할 수 있습니다:

- 개인 액세스 토큰을 생성, 교체 및 해지합니다.
- 모든 활성 및 비활성 개인 액세스 토큰을 봅니다.
- 범위, 할당된 역할 및 만료 날짜를 포함한 토큰 정보를 봅니다.
- 사용 날짜 및 마지막 5개의 서로 다른 연결 IP 주소를 포함한 사용 정보를 봅니다.
  > [!note]
  > 토큰이 Git 작업을 수행하거나 [REST](../../api/rest/_index.md) 또는 [GraphQL](../../api/graphql/_index.md) API로 작업을 인증할 때 GitLab은 주기적으로 토큰 사용 정보를 업데이트합니다. 토큰 사용 시간은 10분마다 업데이트됩니다. 토큰 사용 IP 주소는 1분마다 업데이트됩니다.

개인 액세스 토큰을 보려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **개인 액세스 토큰**을 선택합니다.

토큰의 이름을 선택하여 세부 정보 패널을 엽니다. 기본적으로 활성 토큰만 표시됩니다. 검색 표시줄을 사용하여 액세스 토큰 목록을 필터링합니다.

## 개인 액세스 토큰 교체 {#rotate-a-personal-access-token}

{{< history >}}

- 개인 액세스 토큰을 교체하기 위해 UI를 사용하는 기능이 GitLab 17.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/241523)되었습니다.
- GitLab 18.1에서 [UI가 업데이트](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/194582)되었습니다.

{{< /history >}}

토큰을 교체하여 원본과 동일한 권한 및 범위를 가진 새 토큰을 생성합니다. 원본 토큰은 즉시 비활성화되고 GitLab은 감사 목적으로 두 버전 모두를 유지합니다.

> [!warning]
> 이 작업은 실행 취소할 수 없습니다. 교체된 액세스 토큰을 사용하는 도구는 새 토큰을 참조할 때까지 작동하지 않습니다.

개인 액세스 토큰을 교체하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **개인 액세스 토큰**을 선택합니다.
1. 활성 토큰 옆에서 수직 줄임표({{< icon name="ellipsis_v" >}})를 선택합니다.
1. **교체**({{< icon name="retry" >}})를 선택합니다.
1. 확인 대화 상자에서 **교체**를 선택합니다.

## 개인 액세스 토큰 해지 {#revoke-a-personal-access-token}

{{< history >}}

- GitLab 18.1에서 [UI가 업데이트](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/194582)되었습니다.

{{< /history >}}

토큰을 해지하여 즉시 무효화하고 추가 사용을 방지합니다. GitLab은 감사 목적으로 토큰을 유지합니다. 토큰을 영구적으로 삭제할 수 없지만 토큰 목록을 필터링하여 활성 토큰만 표시할 수 있습니다.

> [!warning]
> 이 작업은 실행 취소할 수 없습니다. 해지된 액세스 토큰을 사용하는 도구는 새 토큰을 추가할 때까지 작동하지 않습니다.

개인 액세스 토큰을 해지하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **개인 액세스 토큰**을 선택합니다.
1. 활성 토큰 옆에서 수직 줄임표({{< icon name="ellipsis_v" >}})를 선택합니다.
1. **해지**({{< icon name="remove" >}})를 선택합니다.
1. 확인 대화 상자에서 **해지**를 선택합니다.

## 액세스 토큰 만료 {#access-token-expiration}

개인, 그룹, 프로젝트 및 가장 행 액세스 토큰은 만료 날짜의 자정 UTC에 만료됩니다. 만료된 토큰은 더 이상 요청을 인증하는 데 사용할 수 없으며 다시 활성화할 수 없습니다. 대신 새 토큰을 만들어야 합니다.

기본적으로 새 액세스 토큰에는 만료 날짜가 있어야 합니다. 토큰 생성 중에 명시적으로 만료 날짜를 설정하지 않으면 현재 날짜로부터 365일의 만료 날짜가 적용됩니다. 관리자가 [이 요구 사항을 비활성화](../../administration/settings/account_and_limit_settings.md#require-expiration-dates-for-new-access-tokens)하면 만료 날짜 없이 생성된 새 토큰은 절대 만료되지 않습니다.

GitLab Ultimate에서 관리자는 액세스 토큰에 대한 [최대 허용 수명](../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens)을 구성할 수 있습니다.

GitLab 버전 및 제공 서비스에 따라 기존 액세스 토큰은 GitLab 버전 업그레이드 시 자동으로 만료 날짜가 적용될 수 있습니다. 자세한 내용은 [만료되지 않는 액세스 토큰](../../update/deprecations.md#non-expiring-access-tokens)을 참조하세요.

### 개인 액세스 토큰 만료 이메일 {#personal-access-token-expiry-emails}

{{< history >}}

- 60일 및 30일 만료 알림이 GitLab 17.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/464040)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)(`expiring_pats_30d_60d_notifications`)를 사용합니다. 기본적으로 비활성화되었습니다.
- 60일 및 30일 알림이 GitLab 17.7에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/173792)해졌습니다. 기능 플래그 `expiring_pats_30d_60d_notifications`이 제거되었습니다.

{{< /history >}}

GitLab은 매일 UTC 1:00 AM에 곧 만료될 개인 액세스 토큰을 식별하기 위해 일일 확인을 실행합니다. 사용자는 토큰이 만료되기 7일 전에 이메일로 알림을 받습니다. GitLab 17.6 이상에서는 토큰이 만료되기 30일 및 60일 전에도 알림을 보냅니다.

### 개인 액세스 토큰 만료 캘린더 {#personal-access-token-expiry-calendar}

각 토큰의 만료 날짜에 이벤트가 포함된 iCalendar 엔드포인트를 구독할 수 있습니다. 로그인한 후 이 엔드포인트는 `/-/user_settings/personal_access_tokens.ics`에서 사용할 수 있습니다.

### 만료 날짜가 없는 서비스 계정 개인 액세스 토큰 생성 {#create-a-service-account-personal-access-token-with-no-expiry-date}

[서비스 계정에 대한 개인 액세스 토큰을 생성](../../api/service_accounts.md#create-a-personal-access-token-for-a-group-service-account)할 수 있으며 만료 날짜가 없습니다. 이러한 개인 액세스 토큰은 절대 만료되지 않습니다.

> [!note]
> 서비스 계정에 대해 만료 날짜 없이 생성되도록 개인 액세스 토큰을 허용하는 것은 이 설정을 변경한 후에 생성된 토큰에만 영향을 미칩니다. 기존 토큰에는 영향을 주지 않습니다.

#### GitLab.com {#gitlabcom}

사전 요구 사항:

- 최상위 그룹에 대한 Owner 역할이 있어야 합니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **개인 액세스 토큰** 아래에서 **서비스 계정에 대한 만료일이 필요함** 확인란을 선택 취소합니다.

이제 만료 날짜가 없는 서비스 계정 사용자에 대한 개인 액세스 토큰을 생성할 수 있습니다.

#### GitLab Self-Managed {#gitlab-self-managed}

사전 요구 사항:

- GitLab Self-Managed 인스턴스의 관리자여야 합니다.

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **계정 및 제한**을 펼칩니다.
1. **서비스 계정에 대한 만료일이 필요함** 확인란을 선택 취소합니다.

이제 만료 날짜가 없는 서비스 계정 사용자에 대한 개인 액세스 토큰을 생성할 수 있습니다.

GitLab Self-Managed Community Edition(CE)에서 **서비스 계정에 대한 만료일이 필요함** 확인란은 사용할 수 없습니다. 대신 [**만료일 필요**](../../administration/settings/account_and_limit_settings.md#require-expiration-dates-for-new-access-tokens) 설정을 사용합니다.

## 개인 액세스 토큰을 사용하여 리포지토리 복제 {#clone-repository-using-personal-access-token}

SSH가 비활성화되어 있을 때 리포지토리를 복제하려면 다음 명령을 실행하여 개인 액세스 토큰을 사용하여 복제합니다:

```shell
git clone https://<username>:<personal_token>@gitlab.com/gitlab-org/gitlab.git
```

이 방법은 개인 액세스 토큰을 bash 기록에 저장합니다. 이를 방지하려면 다음 명령을 실행합니다:

```shell
git clone https://<username>@gitlab.com/gitlab-org/gitlab.git
```

`https://gitlab.com`에서 암호를 입력하라는 메시지가 나타나면 개인 액세스 토큰을 입력합니다.

`clone` 명령에서 `username`:

- 모든 문자열 값이 될 수 있습니다.
- 빈 문자열이 아니어야 합니다.

인증에 따라 다르는 자동화 파이프라인을 설정하는 경우 이를 기억하세요.

## 액세스 토큰 비활성화 {#disable-access-tokens}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/436991) `Disable access tokens` 설정이 GitLab 17.3에서 도입되었습니다.

{{< /history >}}

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.

전체 GitLab 인스턴스에서 사용자가 액세스 토큰으로 인증하지 못하도록 방지할 수 있습니다. 이 설정은 개인 액세스 토큰, 그룹 액세스 토큰, 프로젝트 액세스 토큰 및 가장 행 토큰에 영향을 미칩니다. 이 설정은 서비스 계정의 개인 액세스 토큰에도 적용됩니다.

액세스 토큰을 비활성화하면 다음 규칙이 적용됩니다:

- 사용자는 개인 액세스 토큰으로 GitLab에 로그인할 수 없습니다.
- 개인 액세스 토큰 페이지에서 `404 Not Found` 오류를 반환합니다.
- RSS, Atom 및 캘린더 피드에 대한 피드 토큰이 작동하지 않습니다.
- 개인 액세스 토큰으로 인증된 API 요청이 거부됩니다.

인스턴스에서 액세스 토큰을 비활성화하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **계정 및 제한**을 펼칩니다.
1. **억세스 토큰 비활성화** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

애플리케이션 설정 API에서 [`disable_personal_access_tokens` 속성](../../api/settings.md#available-settings)을 사용할 수도 있습니다.

## 엔터프라이즈 사용자를 위해 개인 액세스 토큰 비활성화 {#disable-personal-access-tokens-for-enterprise-users}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- GitLab 16.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/369504)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)(`enterprise_disable_personal_access_tokens`)를 사용합니다. 기본적으로 비활성화되었습니다.
- GitLab 17.2에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/369504)되었습니다.
- GitLab 17.3에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/369504)해졌습니다. 기능 플래그 `enterprise_disable_personal_access_tokens`이 제거되었습니다.

{{< /history >}}

사전 요구 사항:

- 엔터프라이즈 사용자가 속한 그룹의 소유자 역할입니다.

그룹의 [엔터프라이즈 사용자](../enterprise_user/_index.md)의 개인 액세스 토큰을 비활성화합니다:

- 엔터프라이즈 사용자가 새로운 개인 액세스 토큰을 생성하지 못하도록 합니다. 이 동작은 엔터프라이즈 사용자가 그룹의 관리자인 경우에도 적용됩니다.
- 엔터프라이즈 사용자의 기존 개인 액세스 토큰을 비활성화합니다.

> [!warning]
> 엔터프라이즈 사용자를 위해 개인 액세스 토큰을 비활성화하는 것은 [서비스 계정](service_accounts.md)에 대한 개인 액세스 토큰을 비활성화하지 않습니다.

엔터프라이즈 사용자의 개인 액세스 토큰을 비활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **엔터프라이즈 사용자** 아래에서 **개인 액세스 토큰 비활성화**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

엔터프라이즈 사용자 계정을 삭제하거나 차단하면 해당 개인 액세스 토큰이 자동으로 해지됩니다.

## 개인 액세스 토큰을 프로그래밍 방식으로 생성 {#create-a-personal-access-token-programmatically}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

테스트 또는 자동화의 일부로 미리 정해진 개인 액세스 토큰을 생성할 수 있습니다.

사전 요구 사항:

- GitLab 인스턴스에 대해 [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)을 실행할 수 있는 충분한 액세스 권한이 필요합니다.

개인 액세스 토큰을 프로그래밍 방식으로 생성하려면:

1. Rails 콘솔을 엽니다:

   ```shell
   sudo gitlab-rails console
   ```

1. 다음 명령을 실행하여 사용자 이름, 토큰 및 범위를 참조합니다.

   토큰은 20자 이상이어야 합니다. 범위는 유효해야 하며 [소스 코드](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/auth.rb)에 표시됩니다.

   예를 들어 사용자 이름이 `automation-bot`인 사용자에 속하고 1년 후 만료되는 토큰을 생성하려면:

   ```ruby
   user = User.find_by_username('automation-bot')
   token = user.personal_access_tokens.create(scopes: ['read_user', 'read_repository'], name: 'Automation token', expires_at: 365.days.from_now)
   token.set_token('token-string-here123')
   token.save!
   ```

이 코드는 [Rails runner](../../administration/operations/rails_console.md#using-the-rails-runner)를 사용하여 단일 라인 셸 명령으로 단축될 수 있습니다:

```shell
sudo gitlab-rails runner "token = User.find_by_username('automation-bot').personal_access_tokens.create(scopes: ['read_user', 'read_repository'], name: 'Automation token', expires_at: 365.days.from_now); token.set_token('token-string-here123'); token.save!"
```

## 개인 액세스 토큰을 프로그래밍 방식으로 해지 {#revoke-a-personal-access-token-programmatically}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

테스트 또는 자동화의 일부로 프로그래밍 방식으로 개인 액세스 토큰을 해지할 수 있습니다.

사전 요구 사항:

- GitLab 인스턴스에 대해 [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)을 실행할 수 있는 충분한 액세스 권한이 필요합니다.

토큰을 프로그래밍 방식으로 해지하려면:

1. Rails 콘솔을 엽니다:

   ```shell
   sudo gitlab-rails console
   ```

1. `token-string-here123` 토큰을 해지하려면 다음 명령을 실행합니다:

   ```ruby
   token = PersonalAccessToken.find_by_token('token-string-here123')
   token.revoke!
   ```

이 코드는 [Rails runner](../../administration/operations/rails_console.md#using-the-rails-runner)를 사용하여 단일 라인 셸 명령으로 단축될 수 있습니다:

```shell
sudo gitlab-rails runner "PersonalAccessToken.find_by_token('token-string-here123').revoke!"
```

## 개인 액세스 토큰에서 DPoP 사용 {#use-dpop-with-personal-access-tokens}

{{< details >}}

- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- GitLab 17.10에서 `dpop_authentication`라는 [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181053)되었습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트 가능하지만 프로덕션 사용은 준비되지 않았습니다.

소유 증명(DPoP) 시연은 개인 액세스 토큰의 보안을 강화하고 의도하지 않은 토큰 누수의 영향을 최소화합니다. 계정에서 이 기능을 활성화하면 PAT를 포함하는 모든 REST 및 GraphQL API 요청도 서명된 DPoP 헤더를 제공해야 합니다. 서명된 DPoP 헤더를 생성하려면 해당 개인 SSH 키가 필요합니다.

> [!note]
> 이 기능을 활성화하면 유효한 DPoP 헤더 없는 모든 API 요청이 `DpopValidationError` 오류를 반환합니다.
>
> DPoP 헤더는 액세스 토큰을 포함하는 Git over HTTPS 작업에는 필요하지 않습니다.

사전 요구 사항:

- 계정에 [최소 하나의 공개 SSH 키](../ssh.md#add-an-ssh-key-to-your-gitlab-account)를 추가해야 하며 **사용 유형**은 **서명** 또는 **인증 및 서명**이어야 합니다.
  - SSH 키 유형은 RSA여야 합니다.
- GitLab 계정에 대해 [GitLab CLI](../../editor_extensions/gitlab_cli/_index.md)를 설치 및 구성해야 합니다.

REST 및 GraphQL API에 대한 모든 호출에서 DPoP를 요구하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **개인 액세스 토큰**을 선택합니다.
1. **소유 증명(DPoP)을 사용** 섹션으로 이동하여 **DPoP 활성화**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.
1. [GitLab CLI](../../editor_extensions/gitlab_cli/_index.md)를 사용하여 DPoP 헤더를 생성하려면 터미널에서 이 명령을 실행합니다. `<your_access_token>`을(를) 액세스 토큰으로 바꾸고 `~/.ssh/id_rsa`을(를) 개인 키의 위치로 바꿉니다:

   ```shell
    glab auth dpop-gen --pat "<your_access_token>" --private-key ~/.ssh/id_rsa
   ```

CLI에서 생성한 DPoP 헤더를 사용할 수 있습니다:

- REST API 사용:

  ```shell
  curl --header "PRIVATE-TOKEN: <your_access_token>" \
    --header "DPoP: <dpop-from-glab>" \
    "https://gitlab.example.com/api/v4/projects"
  ```

- GraphQL 사용:

  ```shell
   curl --request POST \
   --header "Content-Type: application/json" \
   --header "PRIVATE-TOKEN: <your_access_token>" \
   --header "DPoP: <dpop-from-glab>" \
   --data '{
   "query": "query { currentUser { id } }"
   }' \
   "https://gitlab.example.com/api/graphql"
  ```

DPoP에 대해 자세히 알아보려면 [개인 액세스 토큰 보낸 사람 제약](https://gitlab.com/gitlab-com/gl-security/product-security/appsec/security-feature-blueprints/-/tree/main/sender_constraining_access_tokens) 청사진을 참조하세요.

## 개인 액세스 토큰의 대체 {#alternatives-to-personal-access-tokens}

Git over HTTPS의 경우 개인 액세스 토큰의 대안은 OAuth 자격 증명 도우미를 사용하는 것입니다.

CI/CD 작업의 인증을 위해 다음을 고려하세요:

- [CI/CD 작업 토큰](../../ci/jobs/ci_job_token.md)과 함께 [세밀한 권한](../../ci/jobs/fine_grained_permissions.md)을(를) 파이프라인 인증에 사용합니다.
- [프로젝트 액세스 토큰](../project/settings/project_access_tokens.md)과 함께 최소 필수 권한을 프로젝트별 자동화에 사용합니다.

## 관련 항목 {#related-topics}

- [그룹 액세스 토큰](../group/settings/group_access_tokens.md)
- [프로젝트 액세스 토큰](../project/settings/project_access_tokens.md)
- [개인 액세스 토큰 API](../../api/personal_access_tokens.md)
- [세분화된 개인 액세스 토큰](../../auth/tokens/fine_grained_access_tokens.md)
- [권한 도우미](../duo_agent_platform/agents/foundational_agents/permissions_assistant.md), 토큰을 생성할 때 세밀한 권한을 선택하는 데 도움이 되는 GitLab Duo 에이전트
