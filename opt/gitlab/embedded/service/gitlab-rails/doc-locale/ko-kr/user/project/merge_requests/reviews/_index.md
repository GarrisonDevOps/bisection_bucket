---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 머지 리퀘스트 검토를 사용하여 코드를 프로젝트에 병합하기 전에 논의하고 개선합니다.
title: 머지 리퀘스트 검토
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

머지 리퀘스트 검토 프로세스는 주제 전문가가 제안된 변경 사항을 병합하기 전에 검토하도록 합니다. 검토자는 머지 리퀘스트에 검토 의견을 추가하고, [변경 사항 제안](suggestions.md)을 하면 저자가 GitLab UI에서 직접 적용할 수 있습니다.

검토자가 담당자와 어떻게 관련되는지에 대한 정보는 [담당자 및 검토자](../_index.md#assignees-and-reviewers)를 참조하세요.

검토자는 머지 리퀘스트를 검토하기 위해 다음 도구를 사용할 수 있습니다:

- GitLab 인터페이스입니다.
- Visual Studio Code와 [GitLab for VS Code 확장](../../../../editor_extensions/visual_studio_code/_index.md).
- 터미널 창과 [GitLab CLI](../../../../editor_extensions/gitlab_cli/_index.md).

승인은 머지 리퀘스트가 정말 준비되었을 때만 병합되도록 보장하는 여러 머지 검사 중 하나입니다. 프로젝트 구성에 따라 검토자는 **변경 요청**을 설정하여 머지 리퀘스트의 병합을 차단할 수도 있습니다.

GitLab Premium 및 Ultimate은 **검토자 지정** 서랍을 제공하여 [승인 규칙을 충족하는](#find-reviewers-who-fulfill-approval-rules) 검토자를 찾는 데 도움이 됩니다:

![이 머지 리퀘스트는 4개의 승인이 필요하며, 승인 요구 사항 중 3개가 충족되지 않습니다.](img/reviewer_drawer_v18_2.png)

[정의된 검토 플로우](#start-a-review)를 따르면 각 검토자가 머지 리퀘스트를 수락할지 거절할지 결정합니다. 오른쪽 사이드바에 검토자 목록과 (검토 플로우를 따르면) 검토 상태가 표시됩니다:

![다양한 검토 상태의 검토자 예제입니다.](img/reviewer_list_v18_2.png)

- {{< icon name="dash-circle" >}} 검토가 아직 시작되지 않았습니다.
- {{< icon name="status_running" >}} 검토가 진행 중입니다.
- {{< icon name="check-circle" >}} 검토되고 승인되었습니다.
- {{< icon name="comment-lines" >}} 검토되고, 변경을 요청했으며, [이 머지 리퀘스트를 차단](#prevent-merge-when-you-request-changes)했습니다(변경이 완료될 때까지). 이 차단은 [우회할 수 있습니다](#prevent-merge-when-you-request-changes).

<i class="fa-youtube-play" aria-hidden="true"></i> 개요는 [머지 리퀘스트 검토](https://www.youtube.com/watch?v=2MayfXKpU08&list=PLFGfElNsQthYDx0A_FaNNfUm9NHsK6zED&index=183) 동영상을 참조하세요.
<!-- Video published on 2023-04-29 -->

## 검토할 머지 리퀘스트 찾기 {#find-merge-requests-to-review}

귀의 [머지 리퀘스트 홈페이지](../homepage.md)는 진행 중인 머지 리퀘스트와 검토 대기 중인 머지 리퀘스트를 표시합니다. 검토이 필요한 머지 리퀘스트는 **검토가 요청됨** 범주에 있습니다. 주의가 필요한 모든 머지 리퀘스트를 보려면 다음 방법 중 하나를 사용하세요:

- <kbd>Shift</kbd>+<kbd>m</kbd> [키보드 단축키](../../../shortcuts.md)를 누르세요.
- 왼쪽 사이드바에서 **머지 리퀘스트**({{< icon name="merge-request" >}})를 선택합니다.
- 상단 바에서 **검색 또는 이동**을 선택한 다음 드롭다운 목록에서 **내가 작업 중인 머지 리퀘스트**를 선택합니다.

## 머지 리퀘스트의 검토 상태 보기 {#view-the-review-status-of-a-merge-request}

다음과 같이 설정합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **머지 리퀘스트**를 선택하고 머지 리퀘스트을 찾습니다.
1. 머지 리퀘스트의 제목을 선택하여 봅니다.
1. [머지 리퀘스트 위젯](../widgets.md)으로 스크롤하여 머지 리퀘스트의 병합 가능성과 승인 상태를 확인합니다. 예를 들어, 필요한 승인이 부족하면 이 머지 리퀘스트가 차단됩니다:

   ![머지 리퀘스트 위젯은 '모든 필수 승인이 주어져야 합니다'를 표시합니다.](img/reviews_missing_v17_3.png)

## 리뷰 요청 {#request-a-review}

{{< history >}}

- **검토자 지정** 서랍이 GitLab 17.5에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/12878)되었으며 [기능 플래그](../../../../administration/feature_flags/_index.md) `reviewer_assign_drawer`로 명명되었습니다.
- 서랍이 GitLab 17.5에서 GitLab.com 및 GitLab Self-Managed에서 [활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/467205)되었습니다.
- [기능 플래그](https://gitlab.com/gitlab-org/gitlab/-/issues/467205) `reviewer_assign_drawer`가 GitLab 17.8에서 제거되었습니다.

{{< /history >}}

변경 사항 준비를 마쳤으면 이제 검토를 요청할 시간입니다. 머지 리퀘스트에 검토자를 할당하려면 모든 텍스트 필드에서 [`/assign_reviewer` 빠른 작업](../../quick_actions.md#assign_reviewer)을 사용하거나:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **머지 리퀘스트**를 선택하고 머지 리퀘스트을 찾습니다.
1. 머지 리퀘스트의 제목을 선택하여 봅니다.
1. 이름으로 검토자를 찾으려면: 오른쪽 사이드바의 **검토자** 섹션에서 **편집**을 선택합니다.
1. GitLab Premium 및 Ultimate에서 승인 규칙을 충족하는 검토자를 찾으려면:
   1. 오른쪽 사이드바의 **검토자** 섹션에서 **할당**을 선택하여 **검토자 지정** 서랍을 엽니다.
   1. 각 승인 규칙에 대해 **편집**을 선택하여 해당 승인 규칙을 충족하는 검토자를 찾습니다.

GitLab은 머지 리퀘스트를 사용자의 검토 요청에 추가합니다.

코드 소유자를 검토자로 할당하려면(수동으로 선택하지 않음) [자동 검토자 할당](automatic_reviewer_assignment.md)을 참조하세요.

### 승인 규칙을 충족하는 검토자 찾기 {#find-reviewers-who-fulfill-approval-rules}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Premium 및 Ultimate은 머지 리퀘스트에 가장 적합한 검토자를 더 빠르게 찾는 데 도움이 됩니다. **검토자 지정** 서랍을 사용하여 검토자 목록을 필터링합니다. 머지 리퀘스트에서 변경된 파일의 코드 소유자와 프로젝트의 승인 규칙을 만족하는 사용자를 확인합니다.

이 예제에서 머지 리퀘스트는 3개의 코드 소유자 승인이 필요하지만 지금까지 없습니다:

![3개의 코드 소유자 승인이 필요하지만 없는 머지 리퀘스트의 검토자 할당 서랍입니다. 각 코드 소유자 규칙에 대해 한 줄씩, 각 승인 규칙에 대해 한 줄씩 표시합니다. 각 규칙에 대해 검토자를 선택합니다.](img/select_good_reviewers_v17_5.png)

머지 리퀘스트에서 적격 승인자를 할당하려면:

1. **검토자** 섹션에서 **할당**을 선택합니다.
1. 선택적 승인 규칙이나 코드 소유자를 보려면 **선택적 승인 규칙**({{< icon name="chevron-lg-up" >}})을 선택하여 표시합니다.
1. 필요한 검토자 유형 옆에서 **편집**을 선택합니다:
   - **코드 소유자**는 해당 파일 유형의 코드 소유자만 표시합니다.
   - **승인 규칙**은 해당 승인 규칙을 충족하는 사용자만 표시합니다.
1. 원하는 검토자를 선택합니다. (GitLab Premium 및 Ultimate을 사용하면 둘 이상의 검토자를 선택할 수 있습니다.)
1. 각 필수 **코드 소유자** 및 **승인 규칙** 항목에 대해 반복합니다.
1. 검토자를 선택했으면 오른쪽 상단에서 **닫기**({{< icon name="close" >}})를 선택하여 **검토자 지정** 서랍을 숨깁니다.

### 검토 재요청 {#re-request-a-review}

검토자가 [머지 리퀘스트 검토](../../../discussions/_index.md)를 완료한 후 머지 리퀘스트의 저자는 검토자에게 새로운 검토를 요청할 수 있습니다. 이렇게 하려면 머지 리퀘스트의 모든 텍스트 필드에서 `/request_review @user` 빠른 작업을 사용하거나:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **머지 리퀘스트**를 선택하고 머지 리퀘스트을 찾습니다.
1. 머지 리퀘스트의 제목을 선택하여 봅니다.
1. 머지 리퀘스트에서 오른쪽 사이드바를 축소한 경우 {{< icon name="chevron-double-lg-left" >}} **사이드바 확장**을 선택하여 확장합니다.
1. **검토자** 섹션에서 검토자 이름 옆의 **검토 재요청** 아이콘({{< icon name="redo" >}})을 선택합니다.

GitLab은 검토자를 위해 새로운 [할 일 항목](../../../todos.md)을 생성하고 알림 이메일을 전송합니다.

## 리뷰 시작 {#start-a-review}

{{< history >}}

- **검토자 지정** 서랍이 GitLab 17.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185795)되었으며 [기능 플래그](../../../../administration/feature_flags/_index.md) `improved_review_experience`로 명명되었습니다. 기본적으로 비활성화되었습니다.
- **검토자 지정** 서랍이 GitLab 18.1에서 [기본적으로 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/535461)되었습니다.

{{< /history >}}

머지 리퀘스트를 검토할 때 개별 의견을 남기는 대신 검토 프로세스를 따르세요. **리뷰 시작**을 선택하면 오른쪽 사이드바의 **검토자** 섹션에서 상태가 **리뷰 대기 중**({{< icon name="dash-circle" >}})에서 **검토자가 리뷰를 시작했습니다.**({{< icon name="comment-dots" >}})로 업데이트됩니다.

머지 리퀘스트 검토를 시작하려면:

1. 다음 중 하나를 선택합니다.
   - <kbd>Shift</kbd>+<kbd>r</kbd>을 눌러 **머지 리퀘스트** 페이지로 이동합니다.
   - 오른쪽 상단 모서리에서 **머지 리퀘스트**({{< icon name="merge-request" >}})를 선택합니다.

1. 머지 리퀘스트를 찾아 머지 리퀘스트의 제목을 선택하여 봅니다.
1. 머지 리퀘스트 설명과 의견을 읽어 머지 리퀘스트에 대해 알아봅니다.
1. **변경사항**을 선택하여 제안된 변경 사항의 차이를 봅니다. **변경사항** 페이지에 대해 자세히 알아보려면 [머지 리퀘스트의 변경 사항](../changes.md)을 참조하세요.
1. [다중 줄 또는 단일 줄 변경 사항 제안](suggestions.md)을 필요에 따라 합니다. 첫 번째 검토 의견을 저장할 준비가 되면 **리뷰 시작**을 선택하여:

   - 오른쪽 사이드바의 상태를 **검토자가 리뷰를 시작했습니다.**({{< icon name="comment-dots" >}})로 업데이트합니다.
   - 검토 의견을 저장하되 게시하지 않으면 다음과 같습니다:

     !['대기 중'으로 표시된 게시되지 않은 다중 줄 검토 의견입니다.](img/pending_state_v18_1.png)

   **댓글 추가**를 선택하는 대신 **리뷰 시작**을 선택하면 GitLab이 댓글을 즉시 게시합니다.

1. **변경사항** 탭 또는 **개요** 탭에서 검토 의견을 계속 작성합니다. **리뷰 추가**를 선택하면 리뷰를 제출할 때까지 게시되지 않습니다:

   ![새로운 스레드](img/mr_review_new_comment_v16_6.png)

다음으로 검토를 제출합니다.

### 댓글로 스레드 해결 또는 다시 열기 {#resolve-or-reopen-thread-with-a-comment}

댓글은 댓글 스레드를 해결하거나 다시 열 수도 있습니다. 댓글에 회신할 때 스레드를 해결하거나 다시 열려면:

1. 댓글 텍스트 영역에 댓글을 작성합니다.
1. **스레드 해결** 또는 **스레드 다시 열기**를 선택하거나 해제합니다.
1. **댓글 추가** 또는 **리뷰 추가**를 선택합니다.

대기 중인 댓글은 지연된 작업에 대한 정보를 표시합니다. 이러한 작업은 검토를 제출할 때 실행됩니다.

## 리뷰 제출 {#submit-a-review}

{{< history >}}

- **승인**을 사용하여 대기 중인 검토 의견을 제출합니다. GitLab 18.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/562579)되었습니다.

{{< /history >}}

검토를 제출하면 GitLab은:

- 검토의 의견을 게시합니다.
- 머지 리퀘스트의 모든 알림 가능한 사용자에게 단일 이메일을 보내고 검토 의견이 첨부됩니다. 이 이메일에 회신하면 머지 리퀘스트에 새로운 댓글이 생성됩니다.
- 검토 의견에 추가한 모든 빠른 작업을 수행합니다.
- 검토의 결과를 표시합니다.

머지 리퀘스트 검토를 빠르게 제출하려면:

- 머지 리퀘스트 위젯으로 이동하여 **승인**을 선택합니다. 머지 리퀘스트도 승인됩니다.
- 비검토 댓글의 텍스트에서 [`/submit_review` 빠른 작업](../../quick_actions.md#submit_review)을 사용합니다.

검토를 제출할 때 검토 의견을 검토하고 편집하려면:

1. 오른쪽 상단에서 **귀하의 리뷰**를 선택하여 검토에 대한 세부 정보를 표시합니다:

   ![진행 중인 검토를 보여주는 검토 서랍입니다. 단일 줄 검토 의견과 코드의 두 줄에 걸쳐 있는 댓글이 포함되어 있습니다.](img/review_drawer_v18_3.png)

1. 대기 중인 의견을 검토합니다. 필요에 따라 편집합니다.
1. 검토의 결과를 선택합니다.

   - **승인**: 피드백을 남기고 변경 사항을 승인합니다.
   - **댓글**: 명시적 승인이나 변경 요청 없이 일반 피드백을 남깁니다.
   - **변경 요청**: 저자가 피드백을 해결할 때까지 머지 리퀘스트가 병합되지 않도록 차단합니다.

1. 선택 사항. 검토의 요약을 작성합니다. GitLab Premium 및 Ultimate 사용자는 **요약 추가**({{< icon name="tanuki-ai" >}})를 선택하여 요약을 생성할 수 있습니다. 수행하려는 모든 빠른 작업을 포함합니다.

### 대기 중인 검토 폐기 {#discard-your-pending-review}

검토를 폐기하면 게시되지 않은 의견이 삭제되며 복원할 수 없습니다. 다음과 같이 설정합니다.

1. 오른쪽 상단에서 **귀하의 리뷰**를 선택하여 검토에 대한 세부 정보를 표시합니다:

   ![진행 중인 검토를 보여주는 검토 서랍입니다. 단일 줄 검토 의견과 코드의 두 줄에 걸쳐 있는 댓글이 포함되어 있습니다.](img/review_drawer_v18_3.png)

1. **리뷰 폐기**를 선택합니다.

### 변경 요청 시 병합 방지 {#prevent-merge-when-you-request-changes}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 16.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/430728)되었으며 [기능 플래그](../../../../administration/feature_flags/_index.md) `mr_reviewer_requests_changes`로 명명되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.2에서 [GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/451211) 및 [GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/158226)에서 기본적으로 활성화되었습니다.
- [기능 플래그 제거됨](https://gitlab.com/gitlab-org/gitlab/-/issues/451211) GitLab 17.3에서 제거되었습니다.

{{< /history >}}

검토자가 [변경을 요청](#submit-a-review)하면 머지 리퀘스트의 병합이 차단됩니다. 이 경우 머지 리퀘스트 보고서 영역에 **변경 요청은 요청자가 승인해야 합니다** 메시지가 표시됩니다. 머지 리퀘스트를 차단 해제하려면 변경을 요청한 검토자가 [다시 검토하고 승인](#re-request-a-review)해야 합니다.

### 변경 요청 제거 {#remove-a-change-request}

{{< history >}}

- GitLab 17.8에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/480412)되었습니다.

{{< /history >}}

이전에 변경을 요청했다면 변경 요청을 제거할 수 있습니다. 다음 두 조건이 모두 참이면 이를 수행해야 할 수도 있습니다:

- 더 이상 머지 리퀘스트를 승인할 수 없습니다.
- 변경 요청을 취소하고 싶지만 새로운 검토를 제출하고 싶지 않습니다.

새로운 검토를 제출하지 않고 변경 요청을 제거하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **머지 리퀘스트**를 선택하고 머지 리퀘스트을 찾습니다.
1. 머지 리퀘스트의 제목을 선택하여 봅니다.
1. 머지 리퀘스트 **개요**에서 머지 리퀘스트 보고서 영역으로 스크롤합니다.
1. **변경 요청은 요청자가 승인해야 합니다** 옆에서 **삭제**를 선택합니다:

   ![사용자가 변경을 요청했기 때문에 차단된 머지 리퀘스트](img/remove_v17_8.png)

### 변경 요청 우회 {#bypass-a-request-for-changes}

변경을 요청한 사용자를 다시 검토하거나 승인할 수 없는 경우 머지 리퀘스트를 병합할 수 있는 권한이 있는 다른 사용자가 이 검사를 무시할 수 있습니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **머지 리퀘스트**를 선택하고 머지 리퀘스트을 찾습니다.
1. 머지 리퀘스트의 제목을 선택하여 봅니다.
1. 머지 리퀘스트 **개요**에서 머지 리퀘스트 보고서 영역으로 스크롤합니다.
1. **변경 요청은 요청자가 승인해야 합니다** 옆에서 **우회**를 선택합니다:

   ![사용자가 변경을 요청했기 때문에 차단된 머지 리퀘스트](img/bypass_v17_2.png)

1. 머지 보고서 영역에 `Merge with caution: Override added`가 표시됩니다. 사용자가 무시한 검사를 확인하려면 **머지 검사 펼침**({{< icon name="chevron-lg-down" >}})을 선택하고 경고({{< icon name="status_warning" >}}) 아이콘이 포함된 검사를 찾습니다. 이 예제에서 저자가 **변경 요청은 요청자가 승인해야 합니다**를 무시했습니다:

   ![이 머지 리퀘스트에는 무시된 검사가 포함되어 있으므로 주의해서 병합해야 합니다.](img/status_warning_v17_4.png)

## 머지 리퀘스트 변경 사항 다운로드 {#download-merge-request-changes}

머지 리퀘스트에서 [변경 사항을 다운로드](../changes.md#download-merge-request-changes)할 수 있습니다(diff 또는 patch 파일로).

## 관련 기능 {#associated-features}

머지 리퀘스트는 다음 기능과 관련이 있습니다:

- [Cherry-pick 변경 사항](../cherry_pick_changes.md): GitLab UI에서 병합된 머지 리퀘스트 또는 커밋에서 **Cherry-pick**을 선택하여 cherry-pick합니다.
- [변경 사항 비교](../changes.md): 머지 리퀘스트에 포함된 변경 사항의 차이를 보고 다운로드합니다.
- [빨리 감기 머지 리퀘스트](../methods/_index.md#fast-forward-merge): 선형 Git 히스토리 및 병합 커밋을 생성하지 않고 머지 리퀘스트를 수락하는 방법
- [변경을 도입한 머지 리퀘스트 찾기](../versions.md): 커밋 세부 정보 페이지를 볼 때 GitLab은 해당 커밋이 포함된 머지 리퀘스트에 대한 링크를 제공합니다.
- [머지 리퀘스트 버전](../versions.md): 머지 리퀘스트 차이의 다양한 버전을 선택하고 비교합니다.
- [충돌 해결](../conflicts.md): GitLab은 GitLab UI에서 특정 머지 리퀘스트 충돌을 해결하는 옵션을 제공할 수 있습니다.
- [변경 사항 되돌리기](../revert_changes.md): 머지 리퀘스트의 모든 커밋에서 변경 사항을 되돌립니다.
- [키보드 단축키](../../../shortcuts.md#merge-requests): 키보드 명령으로 머지 리퀘스트의 특정 부분에 액세스하고 변경합니다.
- [가치 흐름 분석](../../../group/value_stream_analytics/_index.md): 주요 머지 리퀘스트 단계(예: `reviewed` 및 `approved`)를 추적하여 팀이 소프트웨어 개발 수명 주기에서 가장 많은 시간을 소비하는 위치를 파악합니다. 이 정보는 머지 리퀘스트 워크플로우를 최적화하고 개발자 생산성을 향상시키기 위한 실행 가능한 통찰력을 드러냅니다. 블로그 게시물에서 [가치 흐름 분석으로 MR 검토 시간을 단축한 방법](https://about.gitlab.com/blog/how-we-reduced-mr-review-time-with-value-stream-management/)에 대해 자세히 알아보세요.

## 관련 항목 {#related-topics}

- [머지 리퀘스트에서 변경 사항 비교](../changes.md)
- [버전 비교](../../repository/compare_revisions.md)
- [머지 방법](../methods/_index.md)
- [Draft Notes API](../../../../api/draft_notes.md)
