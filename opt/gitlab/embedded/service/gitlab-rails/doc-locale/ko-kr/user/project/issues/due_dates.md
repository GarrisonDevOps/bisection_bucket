---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 마감일
description: "이슈, 에픽 및 기타 작업 항목에 마감일을 설정하여 마감 기한을 추적하고, 향후 작업을 확인하며, 마감일을 캘린더로 내보냅니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 마감일을 설정할 수 있는 최소 역할이 [변경되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256). GitLab 17.7에서 리포터에서 플래너로 변경되었습니다.

{{< /history >}}

마감일을 사용하여 작업 항목의 마감 기한을 추적하고 기능이 제시간에 출시되는지 확인합니다.

마감일은 다음에서 지원됩니다:

- [이슈](_index.md)
- [에픽](../../group/epics/_index.md)
- [태스크](../../tasks.md)
- [목표 및 핵심 결과(OKR)](../../okrs.md)
- [인시던트](../../../operations/incident_management/incidents.md)

항목이 마감되기 하루 전에 모든 참가자에게 이메일이 발송됩니다.
<!-- For issue due timing source, see 'issue_due_scheduler_worker' in <https://gitlab.com/gitlab-org/gitlab/-/blob/master/config/initializers/1_settings.rb> -->
알림은 서버의 시간대(GitLab.com의 경우 UTC)에서 00:50에 다음 날짜의 마감일이 있는 모든 개방된 항목에 대해 발송됩니다.

마감일은 [할 일 항목](../../todos.md)에도 표시됩니다.

## 마감일이 있는 이슈 보기 {#view-issues-with-due-dates}

**작업 항목** 페이지에서 마감일과 함께 이슈를 확인할 수 있습니다. 이슈에 마감일이 있으면 이슈 제목 아래에 표시됩니다:

![2024년 마감일이 있는 이슈.](img/overdue_issue_v17_9.png)

과거 날짜의 이슈는 빨간색 아이콘({{< icon name="calendar-overdue" >}})으로 표시됩니다.

프로젝트에서 마감일이 있는 이슈를 보고 정렬하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링합니다.
1. 필터 바의 오른쪽에서 **표시**({{< icon name="preferences" >}})를 선택하여 표시 기본 설정 드로어를 엽니다.
1. 드로어의 위쪽에서 **다음으로 정렬** 드롭다운 목록에서 **마감일**을 선택합니다.
1. 선택 사항. 정렬 순서를 반대로 하려면 표시 기본 설정 드로어에서 **다음으로 정렬** 드롭다운 목록 옆에 **정렬 순서**({{< icon name="sort-lowest" >}})를 선택합니다.

## 이슈의 마감일 설정 {#set-a-due-date-for-an-issue}

이슈를 볼 수 있는 권한이 있는 모든 사용자가 해당 마감일을 볼 수 있습니다.

### 이슈를 만들 때 {#when-creating-an-issue}

플래너, 리포터, 개발자, 유지 관리자 또는 소유자 역할이 있는 경우 이슈를 만들 때 **마감일**을 선택하여 캘린더를 표시합니다. 이 날짜는 서버의 시간대를 사용하며 현재 사용자의 시간대를 사용하지 않습니다.

날짜를 제거하려면 날짜 텍스트를 선택한 다음 텍스트를 삭제합니다.

### 기존 이슈에서 {#in-an-existing-issue}

사전 요구 사항:

- 플래너, 리포터, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

다음과 같이 설정합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음 **유형** = **이슈**로 필터링하고 이슈를 선택합니다.
1. 오른쪽 사이드바의 **날짜** 섹션에서 **편집**을 선택합니다.
1. 원하는 날짜를 선택한 다음 **적용**을 선택하여 변경 사항을 저장합니다.

### 빠른 작업 사용 {#with-a-quick-action}

이슈의 설명 또는 댓글에서 빠른 작업을 사용하여 마감일을 설정합니다:

- [`/due`](../quick_actions.md#due): 마감일을 설정합니다.
- [`/remove_due_date`](../quick_actions.md#remove_due_date): 기존 마감일을 제거합니다.

## 이슈 마감일을 캘린더로 내보내기 {#export-issue-due-dates-to-a-calendar}

마감일이 있는 이슈는 iCalendar 피드로도 내보낼 수 있습니다. 피드의 URL을 캘린더 애플리케이션에 추가할 수 있습니다.

- **프로젝트 작업 항목** 페이지
- **그룹 작업 항목** 페이지

1. 구독하려는 이슈 목록이 있는 페이지로 이동합니다. 예를 들어:

   - [나에게 할당된 이슈](managing_issues.md#view-all-issues-assigned-to-you)
   - [특정 프로젝트의 이슈](managing_issues.md#issue-list)
   - 그룹의 모든 프로젝트에 대한 [이슈](../../group/_index.md)

1. 오른쪽의 **조치**({{< icon name="ellipsis_v" >}}) 드롭다운 목록에서 **캘린더 구독**을 선택하여 `.ics` 파일을 표시합니다.
1. 페이지의 전체 링크(전체 쿼리 문자열 포함)를 복사하여 원하는 캘린더 애플리케이션에서 사용합니다.
