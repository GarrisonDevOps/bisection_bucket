---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 사용자 계정
description: "프로필 설정, 환경설정, 인증 및 알림입니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

각 GitLab 계정에는 사용자 프로필이 있으며, 여기에는 본인과 GitLab 활동에 대한 정보가 포함되어 있습니다.

프로필에는 또한 GitLab 환경을 사용자 지정하는 데 사용하는 설정이 포함되어 있습니다.

## 사용자 프로필 액세스 {#access-your-user-profile}

{{< history >}}

- 사용자 ID로 프로필에 액세스하는 기능은 GitLab 17.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185387)되었습니다.

{{< /history >}}

프로필에 액세스하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. 사용자 이름 또는 사용자명을 선택하세요.

사용자명 대신 `https://gitlab.example.com/-/u/<id>`의 ID를 사용하여 사용자의 프로필 페이지에 액세스할 수도 있습니다. 예를 들어 사용자명이 `gitlab-user`이고 ID가 `12345`인 경우 `https://gitlab.example.com/gitlab-user` 또는 `https://gitlab.example.com/-/u/12345`에서 프로필 페이지에 액세스할 수 있습니다.

## 사용자 ID 찾기 {#find-the-user-id}

[GitLab API](../../api/_index.md)를 사용하여 상호 작용하려는 경우 사용자 ID가 필요할 수 있습니다.

사용자 ID를 찾으려면:

1. 사용자의 프로필 페이지로 이동합니다.
1. 프로필 페이지의 오른쪽 위 모서리에서 **조치**({{< icon name="ellipsis_v" >}})을 선택하세요.
1. **사용자 ID 복사**를 선택하세요.

## 사용자 설정 액세스 {#access-your-user-settings}

사용자 설정에 액세스하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.

## Support PIN 생성 또는 변경 {#generate-or-change-your-support-pin}

GitLab Support는 신원을 확인하기 위해 개인 식별 번호(PIN)를 요청할 수 있습니다. PIN은 생성 후 7일 후 만료됩니다.

새로운 Support PIN을 생성하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **계정**을 선택하세요.
1. **새로운 PIN 생성**을 선택하세요.

## Support PIN 액세스 {#access-your-support-pin}

이전에 Support PIN을 만든 경우 PIN은 프로필에서 액세스할 수 있으며 생성 후 7일 후 만료됩니다.

Support PIN에 액세스하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **계정**을 선택하세요.

## 사용자명 변경 {#change-your-username}

사용자명은 고유한 [네임스페이스](../namespace/_index.md)를 가지며, 사용자명을 변경하면 업데이트됩니다. 사용자명을 변경하기 전에 [리디렉션이 어떻게 작동하는지](../project/repository/_index.md#repository-path-changes) 읽어보세요. 네임스페이스를 업데이트하지 않으려면 새로운 사용자 또는 그룹을 만들고 프로젝트를 이동할 수 있습니다.

사전 요구 사항:

- 네임스페이스는 다음을 포함하면 안 됩니다:
  - [컨테이너 레지스트리](../packages/container_registry/_index.md) 태그가 있는 프로젝트를 포함합니다.
  - [GitLab Pages](../project/pages/_index.md)를 호스팅하는 프로젝트가 있습니다.
- 사용자명:
  - 길이가 2~255자 사이여야 합니다.
  - 억양 없는 문자, 숫자, `_`, `-` 및 `.`만 포함해야 합니다.
  - 다음을 포함하면 안 됩니다:
    - `_`, `-` 또는 `.`으로 시작하면 안 됩니다.
    - 이모지를 포함합니다.
    - `.` 또는 `.<reserved file extension>`으로 끝나면 안 됩니다(예: `jon.png`, `jon.git` 또는 `jon.atom`). 그러나 `jonpng`은 유효합니다.

사용자명을 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **계정**을 선택하세요.
1. **사용자명 변경** 섹션에서 경로로 새 사용자명을 입력하세요.
1. **사용자명 업데이트**를 선택하세요.

## 사용자 프로필에 이메일 추가 {#add-emails-to-your-user-profile}

계정에 새 이메일 주소를 추가하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **이메일**을 선택하세요.
1. **새 이메일 추가**를 선택하세요.
1. **이메일** 텍스트 상자에 새 이메일을 입력하세요.
1. **이메일 주소 추가**를 선택하세요.
1. 받은 확인 이메일로 이메일 주소를 확인하세요.

새 이메일 주소는 보조 이메일 주소로 추가됩니다. 보조 이메일 주소를 사용하여 비밀번호를 재설정할 수 있지만 인증할 수는 없습니다. [기본 이메일 주소](#change-your-primary-email)를 업데이트할 수 있습니다.

> [!note]
> [이메일을 공개하지 않음](#set-your-public-email)으로 설정해도 커밋 일치 및 [그룹 및 프로젝트 가져오기](../import/_index.md)에 사용되는 것을 방지하지는 않습니다.

## 사용자 프로필에서 이메일 주소 삭제 {#delete-email-addresses-from-your-user-profile}

{{< history >}}

- 확인되지 않은 보조 이메일 주소의 자동 삭제는 GitLab 17.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/151562)되었습니다.

{{< /history >}}

계정에서 보조 이메일 주소를 삭제할 수 있습니다. 기본 이메일 주소는 삭제할 수 없습니다.

삭제된 이메일 주소가 어떤 사용자 이메일에 사용되는 경우 해당 사용자 이메일은 대신 기본 이메일 주소로 전송됩니다.

확인되지 않은 보조 이메일 주소는 3일 후 자동으로 삭제됩니다.

계정에서 이메일 주소를 삭제하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **이메일**을 선택하세요.
1. **삭제**({{< icon name="remove" >}})를 선택하고 **삭제**를 확인하세요.

[API를 사용하여 보조 이메일 주소 삭제](../../api/user_email_addresses.md#delete-an-email-address)할 수도 있습니다.

## 사용자 프로필 페이지를 비공개로 설정 {#make-your-user-profile-page-private}

사용자 프로필을 본인과 GitLab 관리자만 볼 수 있도록 설정할 수 있습니다.

> [!note]
> GitLab 관리자는 이 설정을 [비활성화](../../administration/settings/account_and_limit_settings.md#prevent-users-from-making-their-profiles-private)하여 모든 프로필을 공개로 설정할 수 있습니다.

프로필을 비공개로 설정하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **비공개 프로필** 확인란을 선택하세요.
1. **프로필 설정 업데이트**를 선택합니다.

다음은 사용자 프로필 페이지(`https://gitlab.example.com/username`)에서 숨겨집니다:

- Atom 피드
- 계정이 생성된 날짜
- 활동, 그룹, 기여한 프로젝트, 개인 프로젝트, 별표 표시된 프로젝트, 스니펫에 대한 탭

> [!note]
> 사용자 프로필 페이지를 비공개로 설정해도 REST 또는 GraphQL API에서 모든 공개 리소스가 숨겨지지는 않습니다. 예를 들어 커밋 서명과 연결된 이메일 주소는 [자동으로 생성된 비공개 커밋 이메일을 사용](#use-an-automatically-generated-private-commit-email)하지 않는 한 액세스할 수 있습니다.

### 사용자 표시 {#user-visibility}

`/username`에 위치한 사용자의 공개 페이지는 로그인했는지 여부에 관계없이 항상 표시됩니다.

사용자의 공개 페이지를 방문할 때 권한이 있는 프로젝트만 볼 수 있습니다.

[공개 수준이 제한](../../administration/settings/visibility_and_access_controls.md#restrict-visibility-levels)된 경우 사용자 프로필은 인증된 사용자만 볼 수 있습니다.

## README로 프로필에 세부 정보 추가 {#add-details-to-your-profile-with-a-readme}

README 파일로 프로필 페이지에 더 많은 정보를 추가할 수 있습니다. README 파일에 정보를 입력하면 프로필 페이지에 포함됩니다.

### 새 프로젝트에서 {#from-a-new-project}

새 프로젝트를 만들고 해당 README를 프로필에 추가하려면:

1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택하세요.
1. **빈 프로젝트 생성**을 선택하세요.
1. 프로젝트 세부 정보를 입력하세요:
   - **프로젝트 이름** 필드에 새 프로젝트의 이름을 입력하세요.
   - **프로젝트 URL** 필드에서 GitLab 사용자명을 선택하세요.
   - **프로젝트 슬러그** 필드에 GitLab 사용자명을 입력하세요. 이러한 모든 필드는 대소문자를 구분합니다. 사용자명에 대문자가 있으면 프로젝트 슬러그 필드에 대문자를 포함하여 입력하세요.
1. **공개 수준**에서 **공개**를 선택하세요. ![호스팅된 제품의 개인 사용자를 위한 올바른 프로젝트 경로](img/personal_readme_setup_v14_5.png)
1. **프로젝트 구성**에서 **README 파일을 포함하여 리포지토리 초기화**가 선택되어 있는지 확인하세요.
1. **프로젝트 생성**을 선택하세요.
1. 이 프로젝트 내에 README 파일을 만드세요. 파일은 [유효한 README 또는 색인 파일](../project/repository/files/_index.md#readme-and-index-files)일 수 있습니다.
1. README 파일을 [Markdown](../markdown.md)으로 또는 다른 [지원되는 마크업 언어](../project/repository/files/_index.md#supported-markup-languages)로 채우세요.

GitLab은 기여도 그래프 아래에 README의 내용을 표시합니다.

### 기존 프로젝트에서 {#from-an-existing-project}

기존 프로젝트의 README를 프로필에 추가하려면 프로젝트의 [경로를 업데이트](../project/working_with_projects.md#rename-a-repository)하여 사용자명과 일치하도록 하세요.

## 사용자 프로필 페이지에 외부 계정 추가 {#add-external-accounts-to-your-user-profile-page}

Discord 및 X(구 Twitter)와 같이 가질 수 있는 특정 외부 계정으로의 링크를 추가할 수 있습니다. 다른 플랫폼에서 다른 사용자와 연결하는 데 도움이 될 수 있습니다.

다른 계정에 대한 링크를 추가하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **주요 설정** 섹션에서 다음을 추가하세요:
   - Discord [사용자 ID](https://support.discord.com/hc/en-us/articles/206346498-Where-can-I-find-my-User-Server-Message-ID).
   - BlueSky [`did:plc` 식별자](https://atproto.com/specs/did). 식별자를 찾으려면 [사용자 핸들 확인](https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=USER_HANDLE)하세요.
   - Discord [사용자 ID](https://support.discord.com/hc/en-us/articles/206346498-Where-can-I-find-my-User-Server-Message-ID).
   - GitHub 사용자명.
   - LinkedIn 프로필 이름.
   - [Mastodon 핸들](#add-a-mastodon-handle).
   - [ORCID](https://orcid.org/).
   - X(구 Twitter) @사용자명.

   사용자 ID 또는 사용자명은 500자 이하여야 합니다.
1. **프로필 설정 업데이트**를 선택합니다.

### Mastodon 핸들 추가 {#add-a-mastodon-handle}

{{< history >}}

- GitLab 사용자 프로필을 사용하여 Mastodon 계정을 확인하는 기능은 GitLab 17.4에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/433391)되었으며 [기능 플래그](../../administration/feature_flags/list.md) 이름은 `verify_mastodon_user`입니다. 기본적으로 비활성화되었습니다.
- GitLab 사용자 프로필을 사용하여 Mastodon 계정을 확인하는 기능은 GitLab 18.8에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/work_items/504194)되었습니다. 기능 플래그 `verify_mastodon_user`이 제거되었습니다.

{{< /history >}}

Mastodon 핸들을 추가하려면:

1. GitLab 프로필에 Mastodon 핸들을 추가하세요.
   1. GitLab에 로그인합니다.
   1. 오른쪽 위 모서리에서 아바타를 선택합니다.
   1. **프로필 편집**을 선택합니다.
   1. **SNS 계정** 섹션에서 **Mastodon**으로 이동하여 핸들을 입력하세요. 예: `@alex.garcia@exampleServer`.
   1. **프로필 설정 업데이트**를 선택합니다.
1. 확인 URI를 가져옵니다.
   1. 오른쪽 위 모서리에서 아바타를 선택합니다.
   1. 사용자 이름 또는 사용자명을 선택하세요.
   1. 오른쪽 편에서 Mastodon 핸들을 선택하세요.
   1. 열리는 페이지에서 URI를 복사하세요.
1. Mastodon에 확인을 추가하세요.
   1. Mastodon 프로필 설정으로 이동하세요.
   1. **추가 필드** 섹션에 이전의 URI를 입력하세요.
   1. Mastodon 프로필 변경 사항을 저장하세요.

Mastodon의 GitLab 사이트 추가 필드 옆에 녹색 확인 표시가 표시되는지 확인하세요. 녹색 확인 표시가 표시되지 않으면 추가 문제 해결을 수행해야 할 수 있습니다.

## 사용자 프로필 페이지에서 비공개 기여도 표시 {#show-private-contributions-on-your-user-profile-page}

사용자 기여도 달력 그래프 및 최근 활동 목록에서 비공개 프로젝트에 대한 [기여도 작업](contributions_calendar.md#user-contribution-events)을 볼 수 있습니다.

비공개 기여도를 표시하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **주요 설정** 섹션에서 **프로필에 비공개 기여도 포함** 확인란을 선택하세요.
1. **프로필 설정 업데이트**를 선택합니다.

## 성별 대명사 추가 {#add-your-gender-pronouns}

성별 대명사를 GitLab 계정에 추가하여 프로필의 이름 옆에 표시되도록 할 수 있습니다.

대명사를 지정하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **대명사** 텍스트 상자에 대명사를 입력하세요. 텍스트는 50자 이하여야 합니다.
1. **프로필 설정 업데이트**를 선택합니다.

## 이름 발음 추가 {#add-your-name-pronunciation}

GitLab 계정에 이름 발음을 추가할 수 있습니다. 이는 프로필의 이름 아래에 표시됩니다.

이름 발음을 추가하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **발음** 텍스트 상자에 이름이 발음되는 방식을 입력하세요. 발음은 일반 텍스트이며 255자 이하여야 합니다.
1. **프로필 설정 업데이트**를 선택합니다.

## 상태 설정 {#set-your-status}

상태를 설정하여 다른 사용자에게 가용성을 알릅니다. 다른 사용자들은 아바타, 이름 또는 사용자명 위에 마우스를 올릴 때 상태를 볼 수 있습니다. 상태는 [프로필 페이지를 비공개로 설정](#make-your-user-profile-page-private)한 경우에도 공개적으로 표시됩니다.

상태는 다음 요소들로 구성됩니다. 각각을 별도로 사용하여 상태를 나타낼 수 있습니다.

- 상태를 나타내는 이모지.
- 가용성을 설명하는 메시지. `:palm_tree:` 또는 `:bulb:`와 같은 이모지 코드를 포함할 수 있습니다. 최대 100자.
- 상태에 `Busy` 배지를 추가하는 확인란.

현재 상태를 설정하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **상태 설정**을 선택하세요. 이전에 상태를 설정한 경우 대신 **상태 수정**을 선택하세요.
1. 선택 사항. 상태 메시지를 입력하세요.
1. 선택 사항. **바쁨으로 설정** 확인란을 선택하세요.
1. 선택 사항. **다음 이후 상태를 지움:** 드롭다운 목록에서 값을 선택하세요.
1. **상태 설정**을 선택하세요.

상태가 업데이트됩니다. [사용자 설정](#access-your-user-settings) 페이지 또는 [Users API](../../api/users.md#set-your-user-status)를 사용하여 상태를 설정할 수도 있습니다.

## 시간대 설정 {#set-your-time-zone}

로컬 시간대를 설정할 수 있습니다:

- 프로필에서 로컬 시간을 표시합니다. 또한 이름 위에 마우스를 올릴 때 정보가 표시되는 위치입니다.
- 기여도 달력을 로컬 시간과 정렬하여 기여도가 언제 이루어졌는지를 더 잘 반영합니다

시간대를 설정하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **시간 설정** 섹션에서 드롭다운 목록에서 시간대를 선택하세요.

## 커밋에 표시된 이메일 변경 {#change-the-email-displayed-on-your-commits}

커밋 이메일은 GitLab 인터페이스를 통해 수행된 모든 Git 관련 작업에 표시되는 이메일 주소입니다.

확인된 이메일 주소 중 하나를 커밋 이메일로 사용할 수 있습니다. 기본 이메일은 기본적으로 사용됩니다.

커밋 이메일을 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **커밋 이메일** 드롭다운 목록에서 이메일 주소를 선택하세요.
1. **프로필 설정 업데이트**를 선택합니다.

## 기본 이메일 변경 {#change-your-primary-email}

기본 이메일은 로그인, 커밋 이메일 및 알림 이메일의 기본 이메일 주소입니다. 기본 이메일이 변경되면 원래 기본 이메일이 보조 이메일로 추가됩니다. 이 기능을 사용하면 원래 기본 이메일로 만든 커밋이 계정과 연결된 상태로 유지됩니다.

기본 이메일을 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **이메일** 필드에 새 이메일 주소를 입력하세요.
1. **프로필 설정 업데이트**를 선택합니다.
1. 선택 사항. 이전에 이 이메일을 GitLab.com 계정에 추가하지 않은 경우 확인 이메일을 선택하세요.

## 공개 이메일 설정 {#set-your-public-email}

[구성된 이메일 주소](#add-emails-to-your-user-profile) 중 하나를 선택하여 공개 프로필에 표시할 수 있습니다:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **공개 이메일** 필드에서 사용 가능한 이메일 주소 중 하나를 선택하세요.
1. **프로필 설정 업데이트**를 선택합니다.

### 자동으로 생성된 비공개 커밋 이메일 사용 {#use-an-automatically-generated-private-commit-email}

GitLab은 자동으로 생성된 비공개 커밋 이메일 주소를 제공하므로 이메일 정보를 비공개로 유지할 수 있습니다.

비공개 커밋 이메일을 사용하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **커밋 이메일** 드롭다운 목록에서 **비공개 이메일 사용**을 선택하세요.
1. **프로필 설정 업데이트**를 선택합니다.

모든 Git 관련 작업은 비공개 커밋 이메일을 사용합니다.

완전히 익명으로 유지하려면 비공개 커밋 이메일을 복사하고 다음 명령을 사용하여 로컬 컴퓨터에서 구성할 수도 있습니다:

```shell
git config --global user.email <your email address>
```

## 사용자 팔로우 {#follow-users}

다음 중 하나에서 사용자를 팔로우하거나 언팔로우할 수 있습니다:

- 그들의 [사용자 프로필](#access-your-user-profile).
- 사용자 이름 위에 마우스를 올릴 때 나타나는 작은 팝오버.

팔로우할 수 있는 최대 사용자 수는 300명입니다.

차단된 사용자는 사용자 프로필의 팔로워 목록에 나타나지 않습니다.

### 다른 사용자의 팔로우 및 팔로우 비활성화 {#disable-following-and-being-followed-by-other-users}

다른 사용자의 팔로우 및 팔로우를 비활성화할 수 있습니다.

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **환경설정**을 선택합니다.
1. **사용자 팔로우 활성화** 확인란을 선택 해제하세요.
1. **변경 사항 저장**을 선택합니다.

> [!note]
> 이 기능이 비활성화되면 현재 팔로우/팔로우 중인 모든 연결이 삭제됩니다.

## 사용자의 활동 보기 {#view-a-users-activity}

GitLab은 [사용자 기여도 활동](contributions_calendar.md)을 추적합니다. 사용자의 활동을 보려면:

1. 사용자의 프로필로 이동합니다.
1. GitLab 메뉴에서 **활동**을 선택하세요.

**가장 최근 활동** 기여도 목록이 표시됩니다.

## 활동 보기 {#view-your-activity}

활동을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
1. **귀하의 작업**을 선택하세요.
1. **활동**을 선택하세요.
1. 선택 사항. 기여도 유형으로 활동을 필터링하려면 **당신의 활동** 탭에서 탭을 선택하세요:

   - **전체**: 그룹 및 프로젝트에서 만든 모든 기여도.
   - **푸시 이벤트**: 프로젝트에서 만든 푸시 이벤트.
   - **머지 이벤트**: 프로젝트에서 수락한 머지 요청.
   - **이슈 이벤트**: 프로젝트에서 열고 닫은 이슈.
   - **댓글**: 프로젝트에 게시한 댓글.
   - **위키**: 프로젝트에서 생성 및 업데이트한 위키 페이지.
   - **디자인**: 프로젝트에서 추가, 업데이트 및 제거한 디자인.
   - **팀**: 참여하고 떠난 프로젝트.
1. 선택 사항. 이 활동의 RSS 피드를 구독하려면 오른쪽 위 모서리에서 피드 기호({{< icon name="rss" >}})를 선택하세요.

피드는 항상 선택한 탭이나 필터와 관계없이 사용자가 구성원인 프로젝트의 모든 활동을 포함합니다. 피드 URL에는 사용자를 인증하는 [피드 토큰](../../security/tokens/_index.md#feed-token)이 포함되어 있습니다.

## 로그인 서비스 {#sign-in-services}

GitLab에 로그인하기 위해 일반 사용자명과 비밀번호를 사용하는 대신 로그인 서비스를 사용할 수 있습니다.

### 로그인 서비스 연결 {#connect-a-sign-in-service}

GitLab에 로그인하기 위해 사용할 로그인 서비스를 연결하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **비밀번호와 인증**을 선택합니다.
1. **서비스 로그인** 섹션을 찾으세요.
1. **연결된 계정** 섹션 아래에서 로그인하려는 서비스에 해당하는 버튼을 선택하세요.
1. 선택한 서비스에 대한 지침을 따라 해당 서비스로 로그인을 시작하세요.

### 로그인 서비스 연결 해제 {#disconnect-a-sign-in-service}

GitLab에 로그인하기 위해 사용하는 로그인 서비스의 연결을 해제하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **비밀번호와 인증**을 선택합니다.
1. **서비스 로그인** 섹션을 찾으세요.
1. **연결된 계정** 섹션 아래에서 더 이상 로그인하지 않으려는 서비스에 해당하는 버튼 옆의 **연결해제**를 선택하세요.

## 세션 기간 {#session-duration}

### 일주일 동안 로그인 상태 유지 {#stay-signed-in-for-one-week}

기본적으로 비활동 7일(10080분) 후 또는 브라우저 창을 닫을 때까지(둘 중 먼저 오는 시간) GitLab에서 로그아웃됩니다.

GitLab 관리자는 [이 기본값을 변경](../../administration/settings/account_and_limit_settings.md#customize-the-default-session-duration)할 수 있습니다.

### 무한정 로그인 상태 유지 {#stay-signed-in-indefinitely}

무한정 로그인 상태를 유지하려면 GitLab 로그인 페이지에서 **계정 정보 저장** 확인란을 선택하세요.

로그인 상태를 유지하는 이유는 서버가 1주일의 세션 시간을 설정하지만 브라우저가 자동 재인증을 가능하게 하는 보안 토큰을 저장하기 때문입니다.

GitLab 관리자는 보안 또는 규정 준수 목적으로 세션을 주기적으로 만료되도록 하는 환경에 대해 [**계정 정보 저장** 설정을 끄기](../../administration/settings/account_and_limit_settings.md#session-duration) 할 수 있습니다.

### 로그인에 사용되는 쿠키 {#cookies-used-for-sign-in}

로그인하면 3개의 쿠키가 설정됩니다:

- `_gitlab_session`이라고 불리는 세션 쿠키. 이 쿠키는 만료 날짜가 설정되어 있지 않습니다. 그러나 `session_expire_delay`에 따라 만료됩니다.
- `gitlab_user`이라고 불리는 세션 쿠키. 이 쿠키는 [마케팅 사이트](https://about.gitlab.com/)에서 사용자가 활성 GitLab 세션을 가지고 있는지 여부를 확인하는 데 사용됩니다. 사용자 정보가 쿠키에 전달되지 않으며 로그인 후 2주 후에 만료됩니다.
- `remember_user_token`이라고 불리는 지속성 쿠키이며, 로그인 페이지에서 **계정 정보 저장**을 선택한 경우에만 설정됩니다.

브라우저를 닫으면 `_gitlab_session` 및 `gitlab_user` 쿠키는 일반적으로 클라이언트 쪽에서 지워집니다. 만료되거나 사용할 수 없는 경우 GitLab:

- `remember_user_token` 쿠키를 사용하여 새 `_gitlab_session` 쿠키를 얻고 브라우저를 닫은 경우에도 로그인 상태를 유지합니다.
- `gitlab_user`을(를) `true`(으)로 설정합니다.

`remember_user_token` 및 `_gitlab_session` 쿠키가 모두 사라지거나 만료되면 다시 로그인해야 합니다.

> [!note]
> 세션이 로그아웃되거나 [활성 세션 목록](active_sessions.md)에서 세션이 취소되면 모든 **계정 정보 저장** 토큰이 취소됩니다. 다른 세션이 활성 상태인 동안 **계정 정보 저장** 기능은 브라우저가 닫히거나 기존 세션이 만료된 경우 세션을 복원하지 않습니다.

## 관련 항목 {#related-topics}

- [사용자 생성](account/create_accounts.md)
- [GitLab 계정에 로그인](../../administration/auth/_index.md)
- [잠긴 사용자 계정](../../security/unlock_user.md)
- [비밀번호 변경](user_passwords.md)
- 다음에 대한 이메일 수신:
  - [알 수 없는 IP 주소 또는 기기에서의 로그인](notifications.md#notifications-for-unknown-sign-ins)
  - [잘못된 확인 코드를 사용한 로그인 시도](notifications.md#notifications-for-attempted-sign-ins-using-incorrect-verification-codes)
- [GitLab을 OAuth 공급자로 사용](../../integration/oauth_provider.md)할 수 있는 애플리케이션 관리
- API 및 승인된 애플리케이션을 통해 계정에 액세스하기 위한 [개인 액세스 토큰](personal_access_tokens.md) 관리
- SSH를 사용하여 계정에 액세스하기 위한 [SSH 키](../ssh.md) 관리
- [구문 강조 테마 변경](preferences.md#change-the-syntax-highlighting-theme)
- [활성 세션 보기](active_sessions.md) 및 필요한 경우 취소
