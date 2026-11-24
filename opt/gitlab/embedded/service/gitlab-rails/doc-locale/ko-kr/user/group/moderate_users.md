---
stage: Software Supply Chain Security
group: Authorization
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 사용자 관리
---

그룹의 소유자 역할을 할당받은 경우 [승인](manage.md#approve-pending-members-for-a-group), 계정 정지, 또는 휴면 멤버를 자동으로 제거할 수 있습니다.

> [!note]
> 이 항목은 그룹의 사용자 관리와 관련된 내용입니다. GitLab Self-Managed와 관련된 정보는 [관리 설명서](../../administration/moderate_users.md)를 참조하세요.

## 사용자 계정정지 및 해제 {#ban-and-unban-users}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- GitLab 15.8에서 [도입](https://gitlab.com/gitlab-org/modelops/anti-abuse/team-tasks/-/issues/155)되었습니다. [기능 플래그](../../administration/feature_flags/_index.md) 이름은 `limit_unique_project_downloads_per_namespace_user`입니다. 기본적으로 비활성화되었습니다.
- [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/365724) (GitLab 15.6).
- GitLab 18.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/183101)하게 되었습니다. `limit_unique_project_downloads_per_namespace_user` 기능 플래그가 제거되었습니다.

{{< /history >}}

그룹 소유자는 사용자를 계정정지 및 해제하여 사용자 액세스를 관리할 수 있습니다. 그룹에서 사용자를 차단하려는 경우 사용자를 계정정지해야 합니다.

계정정지된 사용자:

- 그룹 또는 해당 리포지토리에 액세스할 수 없습니다.
- [슬래시 명령어](../project/integrations/gitlab_slack_application.md#slash-commands)를 사용할 수 없습니다.
- [사용자](../free_user_limit.md) 수를 점유하지 않습니다.

### 사용자 계정정지 {#ban-a-user}

<i class="fa-youtube-play" aria-hidden="true"></i> 그룹 수준에서 사용자 계정정지에 대한 데모는 [네임스페이스 수준 계정정지 - 사용자 계정정지](https://youtu.be/1rbi1uEJmOI)를 참조하세요.

사전 요구 사항:

- 최상위 그룹에서 소유자 역할을 해야 합니다.
- 최상위 그룹에서 계정정지하려는 사용자가 소유자 역할을 가지고 있는 경우 [사용자를 강등](manage.md#change-the-owner-of-a-group)해야 합니다.

사용자를 수동으로 계정정지하려면:

1. 최상위 그룹으로 이동합니다.
1. 왼쪽 사이드바에서 **관리** > **멤버**를 선택합니다.
1. 계정정지하려는 멤버 옆에서 세로 줄임표({{< icon name="ellipsis_v" >}})를 선택합니다.
1. 드롭다운 목록에서 **멤버 계정정지**를 선택합니다.

### 사용자 계정정지 해제 {#unban-a-user}

GraphQL API로 사용자 계정정지를 해제하려면 [`Mutation.namespaceBanDestroy`](../../api/graphql/reference/_index.md#mutationnamespacebandestroy)를 참조하세요.

<i class="fa-youtube-play" aria-hidden="true"></i> 그룹 수준에서 사용자 계정정지 해제에 대한 데모는 [네임스페이스 수준 계정정지 - 사용자 계정정지 해제](https://www.youtube.com/watch?v=mTQVbP3MQrs)를 참조하세요.

사전 요구 사항:

- 최상위 그룹에서 소유자 역할을 해야 합니다.

사용자 계정정지를 해제하려면:

1. 최상위 그룹으로 이동합니다.
1. 왼쪽 사이드바에서 **관리** > **멤버**를 선택합니다.
1. **계정정지됨** 탭을 선택합니다.
1. 계정정지를 해제하려는 계정에 대해 **계정정지 해제**를 선택합니다.

## 휴면 멤버 자동 제거 {#automatically-remove-dormant-members}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com
- 상태:  베타

{{< /details >}}

{{< history >}}

- GitLab 17.1에서 `group_remove_dormant_members`이라는 [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/461339)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.9에서 [릴리스](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/178851)된 [베타](../../policy/development_stages_support.md#beta) 기능입니다.

{{< /history >}}

사전 요구 사항:

- 그룹의 Owner 역할이 있어야 합니다.

지정된 기간(기본값 및 최소값은 90일) 동안 그룹에서 활동이 없는 그룹 멤버를 자동으로 제거할 수 있습니다. 다음 작업이 활동으로 계산됩니다:

- Git HTTP/SSH 이벤트(예: `clone` 및 `push`)를 통해 프로젝트와 상호작용합니다.
- 대시보드, 프로젝트, 이슈, 병합 요청 또는 설정 등 GitLab의 페이지를 방문합니다.
- 그룹 범위에서 REST 또는 GraphQL API를 사용합니다.

> [!note]
> 2025-01-22 이전에 추가된 멤버에 대한 활동이 기록되지 않았습니다. 90일 이상 휴면 상태였더라도 이 멤버는 2025-04-22까지 제거되지 않습니다.

- 휴면 그룹 소유자는 비활성화되거나 그룹에서 제거되지 않습니다.
- 휴면 [엔터프라이즈 사용자](../enterprise_user/_index.md)는 제거되지 않지만 [비활성화](../../administration/moderate_users.md#deactivate-and-reactivate-users)됩니다. 이 사용자들이 다시 로그인하면 계정이 재활성화되고 액세스가 복원됩니다. 그러나 [제한된 액세스](../../subscriptions/manage_seats.md#restricted-access)가 엔터프라이즈 그룹에서 활성화되고 사용 가능한 사용자가 없는 경우 사용자는 재활성화되지 않고 승인 대기 중으로 설정됩니다. 자세한 내용은 [휴면 엔터프라이즈 사용자 재활성화](../../subscriptions/manage_seats.md#dormant-user-reactivation)를 참조하세요.

휴면 멤버 자동 제거를 활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **Settings** > **General**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **휴면 멤버**로 스크롤합니다.
1. **일정 기간 동안 활동하지 않은 휴면 회원 제거** 확인란을 선택합니다.
1. **제거 전 비활동 기간(일)** 필드에 제거 전 날짜 수를 입력합니다. 최소값은 90일이고 최대값은 1827일(5년)입니다.
1. **변경 사항 저장**을 선택합니다.

멤버가 비활동 기간에 도달하고 그룹에서 제거된 후:

- GitLab.com에 대한 액세스 권한이 여전히 있습니다.
- 그룹에 대한 액세스 권한이 없습니다.
- 그룹에 대해 수행한 기여도는 여전히 제거된 멤버에게 할당됩니다.
