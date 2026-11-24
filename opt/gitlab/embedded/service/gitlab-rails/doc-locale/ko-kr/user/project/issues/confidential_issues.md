---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 기밀 이슈
description: 이슈의 비공개 활성화를 켜서 플래너 이상의 역할을 가진 프로젝트 멤버에게만 표시되도록 제한합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

기밀 이슈는 [이슈](_index.md)로서 [충분한 권한](#who-can-see-confidential-issues)을 가진 프로젝트 멤버에게만 표시됩니다. 기밀 이슈는 오픈 소스 프로젝트와 회사가 보안 취약점을 비공개로 유지하거나 정보 유출을 방지하기 위해 사용할 수 있습니다.

## 이슈를 기밀로 만들기 {#make-an-issue-confidential}

{{< history >}}

- 이슈를 기밀로 만들기 위한 최소 역할이 GitLab 17.7에서 리포터에서 플래너로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

이슈를 생성하거나 편집할 때 이슈를 기밀로 만들 수 있습니다.

사전 요구 사항:

- 기존 이슈를 기밀로 변환하려면 프로젝트에서 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 있어야 합니다.
- 기밀로 만들려는 이슈에 하위 [작업](../../tasks.md)이 있는 경우 먼저 모든 하위 작업을 기밀로 만들어야 합니다. 기밀 이슈는 기밀 자식만 가질 수 있습니다.

### 새 이슈에서 {#in-a-new-issue}

새 이슈를 생성할 때 텍스트 영역 바로 아래에 이슈를 기밀로 표시할 수 있는 체크박스가 있습니다. 해당 상자를 선택하고 **이슈 생성**을 선택하여 이슈를 생성합니다.

프로젝트에서 기밀 이슈를 생성하면 프로젝트가 **기여한 프로젝트** 섹션의 [프로필](../../profile/_index.md)에 나열됩니다. **기여한 프로젝트**는 기밀 이슈에 대한 정보를 표시하지 않습니다. 프로젝트 이름만 표시합니다.

기밀 이슈를 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}})를 선택합니다.
1. 드롭다운 목록에서 **새 이슈**를 선택합니다.
1. [필드](create_issues.md#fields-in-the-new-issue-form)를 완성합니다.
   - **비공개 활성화** 체크박스를 선택합니다.
1. **이슈 만들기**를 선택합니다.

### 기존 이슈에서 {#in-an-existing-issue}

기존 이슈의 기밀성을 변경하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 위 모서리에서 **이슈 작업**({{< icon name="ellipsis_v" >}}) 및 **비공개 활성화**(또는 기밀이 아닌 이슈로 만들려면 **비공개 해제**)를 선택합니다.

또는 [`/confidential` 빠른 명령](../quick_actions.md#confidential)을 사용할 수 있습니다.

## 누가 기밀 이슈를 볼 수 있나요 {#who-can-see-confidential-issues}

{{< history >}}

- 기밀 이슈를 보기 위한 최소 역할이 GitLab 17.7에서 리포터에서 플래너로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

이슈가 기밀로 설정되면 프로젝트에 대해 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할을 가진 사용자만 이슈에 접근할 수 있습니다. 게스트 또는 [최소 액세스](../../permissions.md#users-with-minimal-access) 역할을 가진 사용자는 변경 전에 적극적으로 참여하고 있었더라도 이슈에 접근할 수 없습니다.

그러나 **게스트 역할**을 가진 사용자는 기밀 이슈를 생성할 수 있지만 자신이 생성한 이슈만 볼 수 있습니다.

게스트 역할을 가진 사용자 또는 비멤버는 이슈에 할당된 경우 기밀 이슈를 읽을 수 있습니다. 게스트 사용자 또는 비멤버가 기밀 이슈에서 할당 해제되면 더 이상 볼 수 없습니다.

기밀 이슈는 필요한 권한이 없는 사용자의 검색 결과에서 숨겨집니다.

## 기밀 이슈 표시기 {#confidential-issue-indicators}

기밀 이슈는 일반 이슈와 여러 방면에서 시각적으로 다릅니다. **이슈** 및 **이슈 보드** 페이지에서 기밀로 표시된 이슈 옆의 기밀({{< icon name="eye-slash" >}}) 아이콘을 볼 수 있습니다.

[충분한 권한](#who-can-see-confidential-issues)이 없으면 기밀 이슈를 전혀 볼 수 없습니다.

마찬가지로 이슈 내부에서 이슈 번호 바로 옆의 기밀({{< icon name="eye-slash" >}}) 아이콘을 볼 수 있습니다. 댓글 영역에도 작성 중인 이슈가 기밀임을 나타내는 표시기가 있습니다.

사이드바에도 기밀성을 나타내는 표시기가 있습니다.

정상 기밀성에서 기밀성으로의 모든 변경 및 그 반대는 이슈의 댓글에 시스템 메모로 표시됩니다. 예를 들어:

- {{< icon name="eye-slash" >}} Jo Garcia가 5분 전에 이슈를 기밀로 만들었습니다
- {{< icon name="eye" >}} Jo Garcia가 방금 이슈를 모두에게 표시했습니다

## 기밀 이슈에 대한 머지 리퀘스트 {#merge-requests-for-confidential-issues}

공개 프로젝트에서 기밀 이슈를 생성하고 기존 이슈를 기밀로 만들 수 있지만 기밀 머지 리퀘스트는 만들 수 없습니다. 개인 데이터 유출을 방지하는 [기밀 이슈에 대한 머지 리퀘스트](../merge_requests/confidential.md)를 생성하는 방법을 알아봅니다.

## 관련 항목 {#related-topics}

- [기밀 이슈에 대한 머지 리퀘스트](../merge_requests/confidential.md)
- [에픽을 기밀로 만들기](../../group/epics/manage_epics.md#make-an-epic-confidential)
- [내부 노트 추가](../../discussions/_index.md#add-an-internal-note)
- [기밀 머지 리퀘스트에 대한 보안 관행](https://gitlab.com/gitlab-org/release/docs/blob/master/general/security/engineer.md#security-releases-critical-non-critical-as-a-developer) (GitLab)
