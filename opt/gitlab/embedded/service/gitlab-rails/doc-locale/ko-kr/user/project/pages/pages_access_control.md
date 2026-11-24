---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Pages 액세스 제어
description: GitLab Pages 사이트에 대한 액세스를 인증된 프로젝트 멤버로 제한합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Pages의 그룹 SAML SSO 지원이 GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/326288)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `ff_oauth_redirect_to_sso_login`로 명명되었습니다. 기본적으로 비활성화되었습니다.
- OAuth 애플리케이션에 대한 그룹 SAML SSO 지원이 GitLab 18.3에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200682)되었습니다.
- GitLab 18.5에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/561778)합니다. 기능 플래그 `ff_oauth_redirect_to_sso_login`이 제거되었습니다.

{{< /history >}}

관리자가 GitLab 인스턴스에서 [액세스 제어 기능을 활성화](../../../administration/pages/_index.md#access-control)한 경우 프로젝트에 대해 Pages 액세스 제어를 활성화할 수 있습니다. 활성화하면 기본적으로 인증된 [프로젝트 멤버](../../permissions.md#project-permissions)(최소 게스트)만 웹사이트에 액세스할 수 있습니다:

<i class="fa-youtube-play" aria-hidden="true"></i> 데모는 [Pages 액세스 제어](https://www.youtube.com/watch?v=tSPAr5mQYc8)를 참조하세요.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한**을 확장합니다.
1. 액세스 제어를 활성화하려면 **Pages** 토글을 활성화하세요. 토글이 표시되지 않으면 활성화되지 않았다는 의미입니다. 관리자에게 [활성화하도록](../../../administration/pages/_index.md#access-control) 요청하세요.

1. Pages 액세스 제어 드롭다운 목록을 사용하여 프로젝트의 가시성에 따라 GitLab Pages로 호스팅되는 페이지를 볼 수 있는 사람을 설정합니다:

   - 프로젝트가 비공개인 경우:
     - **프로젝트 멤버만**: [프로젝트 멤버](../members/_index.md)만 웹사이트를 탐색할 수 있습니다.
     - **모두**: GitLab에 로그인하거나 로그아웃한 모든 사용자가 프로젝트 멤버십과 관계없이 웹사이트를 탐색할 수 있습니다.
   - 프로젝트가 내부인 경우:
     - **프로젝트 멤버만**: 프로젝트 멤버만 웹사이트를 탐색할 수 있습니다.
     - **액세스 권한이 있는 모든 사용자**: GitLab에 로그인한 모든 사용자가 프로젝트 멤버십과 관계없이 웹사이트를 탐색할 수 있습니다. [외부 사용자](../../../administration/external_users.md)는 프로젝트에 멤버십이 있는 경우에만 웹사이트에 액세스할 수 있습니다.
     - **모두**: GitLab에 로그인하거나 로그아웃한 모든 사용자가 프로젝트 멤버십과 관계없이 웹사이트를 탐색할 수 있습니다.
   - 프로젝트가 공개인 경우:
     - **프로젝트 멤버만**: 프로젝트 멤버만 웹사이트를 탐색할 수 있습니다.
     - **액세스 권한이 있는 모든 사용자**: GitLab에 로그인하거나 로그아웃한 모든 사용자가 프로젝트 멤버십과 관계없이 웹사이트를 탐색할 수 있습니다.

1. **변경 사항 저장**을 선택합니다. 변경 사항이 즉시 적용되지 않을 수 있습니다. GitLab Pages는 효율성을 위해 캐싱 메커니즘을 사용합니다. 일반적으로 1분 이내에 캐시가 무효화될 때까지 변경 사항이 적용되지 않을 수 있습니다.

누군가 웹사이트에 액세스하려고 할 때 액세스 제어가 활성화되면 GitLab에 로그인하고 웹사이트에 액세스할 수 있는지 확인하는 페이지가 표시됩니다.

[SAML SSO](../../group/saml_sso/_index.md)가 관련 그룹에 대해 구성되고 액세스 제어가 활성화된 경우 사용자는 웹사이트에 액세스하기 전에 SSO를 사용하여 인증해야 합니다.

공개 액세스가 [인스턴스](../../../administration/pages/_index.md#disable-public-access-to-all-pages-sites) 또는 [그룹](#remove-public-access-for-group-pages) 수준에서 비활성화되면 프로젝트는 **모두** 가시성 수준 옵션을 잃게 되며 프로젝트의 가시성 설정에 따라 프로젝트 멤버 또는 액세스 권한이 있는 모든 사용자로 제한됩니다.

## 그룹 Pages에 대한 공개 액세스 삭제 {#remove-public-access-for-group-pages}

{{< history >}}

- GitLab 17.9에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/254962)되었습니다.

{{< /history >}}

그룹에 대한 설정을 구성하여 Pages의 공개 가시성 옵션을 제거합니다. 활성화하면 그룹 및 해당 하위 그룹의 모든 프로젝트가 "모두" 가시성 수준을 사용하는 옵션을 잃게 되며 프로젝트의 가시성 설정에 따라 프로젝트 멤버 또는 액세스 권한이 있는 모든 사용자로 제한됩니다.

사전 요구 사항

- Pages에 대한 공개 액세스를 [인스턴스에 대해 비활성화](../../../administration/pages/_index.md#disable-public-access-to-all-pages-sites)하지 않아야 합니다.
- 그룹의 Owner 역할이 있어야 합니다.

다음과 같이 설정합니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **Pages 공개 액세스** 아래에서 **공개 액세스 삭제** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

GitLab Pages는 효율성을 위해 캐시를 사용합니다. 액세스 설정 변경은 일반적으로 캐시가 업데이트될 때 1분 내에 적용됩니다.

## 액세스 토큰으로 인증 {#authenticate-with-an-access-token}

{{< history >}}

- GitLab 17.10에서 [도입](https://gitlab.com/gitlab-org/gitlab-pages/-/issues/388)되었습니다.

{{< /history >}}

제한된 GitLab Pages 사이트에 대해 인증하려면 `Authorization` 헤더를 액세스 토큰과 함께 제공할 수 있습니다.

사전 요구 사항:

- `read_api` 범위가 있는 다음 액세스 토큰 중 하나가 필요합니다:
  - [개인 액세스 토큰](../../profile/personal_access_tokens.md#create-a-personal-access-token)
  - [프로젝트 액세스 토큰](../settings/project_access_tokens.md#create-a-project-access-token)
  - [그룹 액세스 토큰](../../group/settings/group_access_tokens.md#create-a-group-access-token)
  - [OAuth 2.0 토큰](../../../api/oauth2.md)

예를 들어 OAuth 호환 헤더와 함께 액세스 토큰을 사용하려면:

```shell
curl --header "Authorization: Bearer <your_access_token>" <published_pages_url>
```

잘못되거나 권한이 없는 액세스 토큰의 경우 [`404`](../../../api/rest/troubleshooting.md#status-codes)를 반환합니다.

## Pages 세션 종료 {#terminating-a-pages-session}

GitLab Pages 웹사이트에서 로그아웃하려면 GitLab Pages의 애플리케이션 액세스 토큰을 해지합니다:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **응용 프로그램**을 선택합니다.
1. **승인된 애플리케이션** 섹션에서 **GitLab 페이지** 항목을 찾고 **해지**를 선택합니다.
