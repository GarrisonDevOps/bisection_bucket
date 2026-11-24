---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "이슈 편집, 이동, 닫기, 대량 작업 및 담당자, 헬스 체크 상태, 자동화 등 다양한 이슈 기능을 사용하여 GitLab 이슈를 관리하는 방법을 배웁니다."
title: 이슈 관리
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 이슈를 통해 작업을 추적하고 팀과 협력할 수 있습니다. 다음을 위해 이슈를 관리할 수 있습니다:

- 제목, 설명, 담당자, 메타데이터 등 세부 정보를 편집합니다.
- 프로젝트 간에 이슈를 이동하면서 컨텍스트와 히스토리를 유지합니다.
- 완료된 이슈를 닫고 필요한 경우 다시 열 수 있습니다.
- 대량 편집을 사용하여 여러 이슈를 효율적으로 업데이트합니다.
- 이슈 헬스 체크 상태를 추적하여 진행 상황을 모니터링하고 위험을 식별합니다.

이슈의 하위 항목 관리에 대한 정보는 [하위 항목](../../work_items/child_items.md)을 참조하세요.

## 이슈 편집 {#edit-an-issue}

{{< history >}}

- 이슈를 편집하기 위한 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

이슈의 제목과 설명을 편집할 수 있습니다.

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나, 이슈의 작성자이거나, 이슈에 할당되어야 합니다.

이슈를 편집하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 제목 오른쪽에서 **편집**을 선택합니다.
1. 사용 가능한 필드를 편집합니다.
1. **변경 사항 저장**을 선택합니다.

### 이슈 설명 생성으로 이슈 채우기 {#populate-an-issue-with-issue-description-generation}

{{< details >}}

- 티어: Premium, Ultimate
- 추가 기능: GitLab Duo Enterprise
- 제공 서비스: GitLab.com
- 상태:  실험적 기능

{{< /details >}}

{{< collapsible title="모델 정보" >}}

- 기본 LLM: Anthropic [Claude Sonnet 4.6](https://console.cloud.google.com/agent-platform/publishers/anthropic/model-garden/claude-sonnet-4-6)
- GitLab Duo에서 자체 호스팅 모델을 사용할 수 없습니다.

{{< /collapsible >}}

{{< history >}}

- GitLab 16.3에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/10762)되었으며 [실험](../../../policy/development_stages_support.md#experiment) 상태입니다.
- GitLab 17.6 이상에서 GitLab Duo 애드온을 요구하도록 변경되었습니다.
- GitLab 18.0에서 Premium 계층을 포함하도록 변경되었습니다.

{{< /history >}}

제공한 짧은 요약을 기반으로 이슈에 대한 자세한 설명을 생성합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> [개요 보기](https://www.youtube.com/watch?v=-BWBQat7p5M)
<!-- Video published on 2024-12-18 -->

사전 요구 사항:

- [실험 및 베타 기능 설정](../../gitlab_duo/turn_on_off.md#turn-on-beta-and-experimental-features)이 켜져 있는 최소 1개 그룹에 속해야 합니다.
- 이슈를 생성할 수 있는 권한이 있어야 합니다.
- 일반 텍스트 편집기에서만 사용할 수 있습니다.
- 새 이슈를 생성할 때만 사용할 수 있습니다. 기존 이슈를 편집할 때 설명 생성 지원을 추가하는 제안은 [이슈 474141](https://gitlab.com/gitlab-org/gitlab/-/issues/474141)을 참조하세요.

이슈 설명을 생성하려면:

1. 새 이슈를 생성합니다.
1. **설명** 텍스트 상자 위에서 **GitLab Duo** ({{< icon name="tanuki-ai" >}}) > **이슈 설명 생성**을 선택합니다.
1. 짧은 설명을 작성하고 **제출**을 선택합니다.

이슈 설명이 AI 생성 텍스트로 대체됩니다.

이 실험 기능에 대한 피드백을 [이슈 409844](https://gitlab.com/gitlab-org/gitlab/-/issues/409844)에서 제공하세요.

**데이터 사용**: 이 기능을 사용하면 입력한 텍스트가 대형 언어 모델로 전송됩니다.

## 이슈 대량 편집 {#bulk-edit-issues}

{{< history >}}

- 이슈를 대량으로 편집하기 위한 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.
- GitLab 18.7에서 더 많은 대량 편집 특성이 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/520791)되었습니다.

{{< /history >}}

그룹 또는 프로젝트에 있을 때 여러 이슈를 한 번에 편집할 수 있습니다.

사전 요구 사항:

- 그룹 또는 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

여러 이슈를 동시에 편집하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음, **유형** = **이슈**로 필터링합니다.
1. **대량 편집**을 선택합니다. 오른쪽에 편집 가능한 필드가 있는 사이드바가 나타납니다.
1. 편집하려는 각 이슈 옆의 체크박스를 선택합니다.
1. 사이드바에서 사용 가능한 필드를 편집합니다.
1. **선택한 업데이트**를 선택합니다.

이슈를 대량으로 편집할 때 다음 특성을 편집할 수 있습니다:

- 상태 (열림 또는 닫힘)
- [상태](../../work_items/status.md)
- [담당자](#assignees)
- [레이블](../labels.md)
- [헬스 체크 상태](#health-status)
- [알림](../../profile/notifications.md) 구독
- [기밀성](confidential_issues.md)
- [반복](../../group/iterations/_index.md)
- [마일스톤](../milestones/_index.md)
- 부모 항목
- [다른 프로젝트로 이동](#move-an-issue)

## 이슈 이동 {#move-an-issue}

{{< history >}}

- 이슈를 이동하기 위한 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

이슈를 이동하면 닫히고 대상 프로젝트로 복사됩니다. 원본 이슈는 삭제되지 않습니다. 출처와 목적지를 나타내는 [시스템 노트](../system_notes.md)가 두 이슈에 모두 추가됩니다.

GitLab은 또한 이슈의 설명 또는 댓글에 첨부된 파일을 대상 프로젝트로 복사합니다. [업로드된 파일이 프로젝트로 범위가 지정](../../../security/user_file_uploads.md)되어 있으므로 GitLab은 대상 프로젝트에서 새 URL 암호를 사용하여 각 사본을 생성합니다:

- 원본 첨부 파일 URL로의 직접 링크는 `404` 오류를 반환합니다.
- 복사된 파일은 소스 프로젝트가 아닌 대상 프로젝트의 [마크다운 업로드](../../../api/project_markdown_uploads.md)에 나열됩니다.

액세스 규칙이 다른 프로젝트로 이슈를 이동할 때는 주의하세요. 이슈를 이동하기 전에 민감한 데이터가 포함되지 않았는지 확인하세요.

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

이슈를 이동하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 위 모서리에서 **추가 작업** ({{< icon name="ellipsis_v" >}}) > **이동**을 선택합니다.
1. 이슈를 이동할 프로젝트를 검색합니다.
1. **이동**을 선택합니다.

댓글 또는 설명에서 [`/move` 빠른 작업](../quick_actions.md#move)을 사용할 수도 있습니다.

### 이슈 대량 이동 {#bulk-move-issues}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 이슈를 대량으로 이동하기 위한 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

#### 작업 항목 목록에서 {#from-the-work-items-list}

프로젝트에 있을 때 여러 이슈를 동시에 이동할 수 있습니다. 작업 또는 테스트 케이스는 이동할 수 없습니다.

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

여러 이슈를 동시에 이동하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음, **유형** = **이슈**로 필터링합니다.
1. **대량 편집**을 선택합니다. 오른쪽에 편집 가능한 필드가 있는 사이드바가 나타납니다.
1. 이동하려는 각 이슈 옆의 체크박스를 선택합니다.
1. **이동** 드롭다운 목록에서 대상 프로젝트를 선택합니다.
1. **항목 이동**을 선택합니다.

#### Rails 콘솔에서 {#from-the-rails-console}

한 프로젝트에서 다른 프로젝트로 모든 열린 이슈를 이동할 수 있습니다.

사전 요구 사항:

- GitLab 인스턴스의 Rails 콘솔에 액세스할 수 있어야 합니다.

이렇게 하려면:

1. 선택 사항 (권장됨). 콘솔에서 변경을 시도하기 전에 [백업을 생성](../../../administration/backup_restore/_index.md)합니다.
1. [Rails 콘솔](../../../administration/operations/rails_console.md)을 엽니다.
1. 다음 스크립트를 실행합니다. `project`, `admin_user`, `target_project`을(를) 사용자의 값으로 변경해야 합니다.

   ```ruby
   project = Project.find_by_full_path('full path of the project where issues are moved from')
   issues = project.issues
   admin_user = User.find_by_username('username of admin user') # make sure user has permissions to move the issues
   target_project = Project.find_by_full_path('full path of target project where issues moved to')

   issues.each do |issue|
      if issue.state != "closed" && issue.moved_to.nil?
         Issues::MoveService.new(container: project, current_user: admin_user).execute(issue, target_project)
      else
         puts "issue with id: #{issue.id} and title: #{issue.title} was not moved"
      end
   end; nil
   ```

1. Rails 콘솔을 종료하려면 `quit`을(를) 입력합니다.

## 설명 목록 및 작업 목록 {#description-lists-and-task-lists}

이슈 설명에서 순서 목록, 순서 없는 목록 또는 작업 목록을 사용할 때 다음을 할 수 있습니다:

- 드래그 앤 드롭으로 모든 목록 항목을 다시 정렬합니다.
- 작업 목록 항목을 삭제합니다.
- [작업 목록 항목을 작업 항목으로 변환](../../tasks.md#from-a-task-list-item)합니다.

### 작업 목록 항목 삭제 {#delete-a-task-list-item}

사전 요구 사항:

- 프로젝트의 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나, 이슈의 작성자 또는 담당자여야 합니다.

작업 목록 항목이 있는 이슈 설명에서:

1. 작업 목록 항목에 마우스를 올리고 옵션 메뉴 ({{< icon name="ellipsis_v" >}})를 선택합니다.
1. **삭제**를 선택합니다.

작업 목록 항목이 이슈 설명에서 제거됩니다. 중첩된 작업 목록 항목이 중첩 수준이 하나 올라갑니다.

### 이슈 설명의 목록 항목 다시 정렬 {#reorder-list-items-in-the-issue-description}

{{< history >}}

- 이슈 설명의 목록 항목을 다시 정렬하기 위한 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.
- <kbd>Esc</kbd> 키로 목록 항목 드래그 작업 취소가 GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248854)되었습니다.

{{< /history >}}

설명에 목록이 있는 이슈를 볼 때 목록 항목을 다시 정렬할 수도 있습니다.

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나, 이슈의 작성자이거나, 이슈에 할당되어야 합니다.
- 이슈의 설명에는 [순서 목록 또는 순서 없는](../../markdown.md#lists) 목록 또는 [작업](../../markdown.md#task-lists) 목록이 있어야 합니다.

목록 항목을 다시 정렬하려면 이슈를 볼 때:

1. 목록 항목 행에 마우스를 올려서 그립 아이콘 ({{< icon name="grip" >}})을 표시합니다.
1. 그립 아이콘을 선택하고 누릅니다.
1. 행을 목록의 새 위치로 드래그합니다.
1. 그립 아이콘을 놓습니다.

다시 정렬을 취소하려면 그립 아이콘을 놓기 전에 <kbd>Esc</kbd> 키를 누르세요.

## 이슈 닫기 {#close-an-issue}

{{< history >}}

- 이슈를 닫기 위한 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

이슈가 해결되었거나 더 이상 필요하지 않다고 판단되면 닫을 수 있습니다. 이슈는 닫힘으로 표시되지만 삭제되지는 않습니다.

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나, 이슈의 작성자이거나, 이슈에 할당되어야 합니다.

이슈를 닫으려면 다음 중 하나를 수행할 수 있습니다:

- [이슈 보드](../issue_board.md)에서 이슈 카드를 목록에서 **닫힘** 목록으로 드래그합니다.
- GitLab UI의 다른 페이지에서:
  1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
  1. **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
  1. 오른쪽 위 모서리에서 **추가 작업** ({{< icon name="ellipsis_v" >}}) 다음 **이슈 닫기**를 선택합니다.

댓글 또는 설명에서 [`/close` 빠른 작업](../quick_actions.md#close)을 사용할 수도 있습니다.

### 닫힌 이슈 다시 열기 {#reopen-a-closed-issue}

{{< history >}}

- 닫힌 이슈를 다시 열기 위한 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나, 이슈의 작성자이거나, 이슈에 할당되어야 합니다.

닫힌 이슈를 다시 열려면 오른쪽 위 모서리에서 **추가 작업** ({{< icon name="ellipsis_v" >}}) 다음 **이슈 다시 열기**를 선택합니다. 다시 열린 이슈는 다른 열린 이슈와 다르지 않습니다.

댓글 또는 설명에서 [`/reopen` 빠른 작업](../quick_actions.md#reopen)을 사용할 수도 있습니다.

### 이슈 자동 닫기 {#closing-issues-automatically}

커밋 메시지 또는 병합 요청 설명에서 _닫기 패턴_이라고 하는 특정 단어를 사용하여 이슈를 자동으로 닫을 수 있습니다. GitLab Self-Managed 관리자는 [기본 닫기 패턴을 변경](../../../administration/issue_closing_pattern.md)할 수 있습니다.

커밋 메시지 또는 병합 요청 설명에 [닫기 패턴](#default-closing-pattern)과 일치하는 텍스트가 포함되어 있으면 일치하는 텍스트에 참조된 모든 이슈는 다음 중 하나가 발생할 때 닫힙니다:

- 커밋이 프로젝트의 [**기본값** 브랜치](../repository/branches/default.md)로 푸시됩니다.
- 커밋 또는 병합 요청이 기본 브랜치로 병합됩니다.

예를 들어 병합 요청 설명에 `Closes #4, #6, Related to #5`을(를) 포함하는 경우:

- 이슈 `#4` 및 `#6`은(는) MR이 병합될 때 자동으로 닫힙니다.
- 이슈 `#5`은(는) [관련 이슈](related_issues.md)로 표시되지만 자동으로 닫히지 않습니다.

또는 [이슈에서 병합 요청을 생성](../merge_requests/creating_merge_requests.md#from-an-issue)할 때 이슈의 마일스톤과 레이블을 상속합니다.

성능상의 이유로 기존 리포지토리에서 처음 푸시할 때 자동 이슈 닫기가 꺼져 있습니다.

#### 병합 시 사용자 책임 {#user-responsibility-when-merging}

병합 요청을 병합할 때 대상 이슈를 닫기에 적절한지 확인하는 것은 사용자의 책임입니다. 사용자는 병합 요청 설명에 이슈 닫기 패턴을 포함할 수 있으며 커밋 메시지 본문에도 포함할 수 있습니다. 커밋 메시지의 닫기 메시지는 덜 눈에 띕니다. 두 경우 모두 병합 요청 위젯은 병합 시 닫을 이슈에 대한 정보를 표시합니다:

![이 병합 요청은 이슈 #2754를 닫습니다.](img/closing_pattern_v17_4.png)

병합 요청을 병합할 때 GitLab은 닫기 패턴으로 대상이 지정된 이슈를 닫을 권한이 있는지 확인합니다. 공개 리포지토리에서 이 확인은 중요합니다. 외부 사용자가 닫기 패턴을 포함하는 병합 요청과 커밋을 모두 생성할 수 있기 때문입니다. 병합하는 사용자인 경우 병합이 코드와 프로젝트의 이슈에 미치는 영향을 인식하는 것이 중요합니다.

닫기 패턴 없이 이슈를 병합 요청에 연결할 수도 있습니다. GraphQL API 또는 병합 요청의 **작업 항목** 위젯을 사용합니다. 어느 방식으로든 만든 링크의 경우 GitLab은 병합 요청이 병합될 때가 아니라 링크를 생성할 때 권한을 확인합니다. 링크는 유지되므로 이슈의 프로젝트에 대한 액세스 권한이 없어도 병합 시 이슈가 여전히 닫힙니다. 자세한 내용은 [작업 항목을 수동으로 연결](../../work_items/_index.md#link-work-items-manually)을(를) 참조하세요.

[자동 병합](../merge_requests/auto_merge.md)이 병합 요청에 대해 켜져 있으면 자동으로 닫힐 이슈의 목록을 더 이상 변경할 수 없습니다.

#### 기본 닫기 패턴 {#default-closing-pattern}

{{< history >}}

- GitLab 17.3에서 작업 항목 (작업, 목표 또는 핵심 결과) 참조가 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/465391)되었습니다.

{{< /history >}}

이슈를 자동으로 닫으려면 이슈 참조 앞에 다음 키워드를 사용합니다.

사용 가능한 키워드:

- `Close`, `Closes`, `Closed`, `Closing`, `close`, `closes`, `closed`, `closing`
- `Fix`, `Fixes`, `Fixed`, `Fixing`, `fix`, `fixes`, `fixed`, `fixing`
- `Resolve`, `Resolves`, `Resolved`, `Resolving`, `resolve`, `resolves`, `resolved`, `resolving`
- `Implement`, `Implements`, `Implemented`, `Implementing`, `implement`, `implements`, `implemented`, `implementing`

사용 가능한 이슈 참조 형식:

- 로컬 이슈 (`#123`).
- 교차 프로젝트 이슈 (`group/project#123`).
- 이슈의 전체 URL (`https://gitlab.example.com/<project_full_path>/-/issues/123`).
- 작업 항목의 전체 URL (예: 작업, 목표 또는 핵심 결과):
  - 프로젝트에서 (`https://gitlab.example.com/<project_full_path>/-/work_items/123`).
  - 그룹에서 (`https://gitlab.example.com/groups/<group_full_path>/-/work_items/123`).

예를 들어:

```plaintext
Awesome commit message

Fix #20, Fixes #21 and Closes group/otherproject#22.
This commit is also related to #17 and fixes #18, #19
and https://gitlab.example.com/group/otherproject/-/issues/23.
```

이전 커밋 메시지는 이 커밋이 푸시되는 프로젝트에서 `#18`, `#19`, `#20` 및 `#21`을(를) 닫고 `group/otherproject`에서 `#22` 및 `#23`을(를) 닫습니다. `#17`은(는) 패턴과 일치하지 않아 닫히지 않습니다.

`git commit -m`을(를) 사용하여 명령줄에서 수행한 다중 라인 커밋 메시지 또는 한 줄짜리에서 닫기 패턴을 사용할 수 있습니다.

기본 이슈 닫기 패턴 정규식:

```shell
\b((?:[Cc]los(?:e[sd]?|ing)|\b[Ff]ix(?:e[sd]|ing)?|\b[Rr]esolv(?:e[sd]?|ing)|\b[Ii]mplement(?:s|ed|ing)?)(:?) +(?:(?:issues? +)?%{issue_ref}(?:(?: *,? +and +| *,? *)?)|([A-Z][A-Z0-9_]+-\d+))+)
```

#### 자동 이슈 닫기 비활성화 {#disable-automatic-issue-closing}

[프로젝트 설정](#disable-automatic-issue-closing)에서 프로젝트 기준으로 자동 이슈 닫기 기능을 끌 수 있습니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

자동 이슈 닫기를 끄려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **브랜치 기본값**을 확장합니다.
1. **기본 브랜치에서 참조된 이슈 자동 닫기** 체크박스를 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

참조된 이슈는 여전히 표시되지만 자동으로 닫히지 않습니다.

이 설정을 변경하는 것은 새로운 병합 요청 또는 커밋에만 적용됩니다. 이미 닫힌 이슈는 그대로 유지됩니다. 자동 이슈 닫기를 끄는 것은 설정이 꺼진 프로젝트의 이슈에만 적용됩니다. 이 프로젝트의 병합 요청과 커밋은 여전히 다른 프로젝트의 이슈를 닫을 수 있습니다.

#### 이슈 닫기 패턴 사용자 정의 {#customize-the-issue-closing-pattern}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

사전 요구 사항:

- GitLab 인스턴스에 [관리자 액세스](../../../administration/_index.md)권한이 있어야 합니다.

설치의 기본 [이슈 닫기 패턴](../../../administration/issue_closing_pattern.md)을 변경하는 방법을 알아봅니다.

## **더 읽기**로 설명 축약 방지 {#prevent-truncating-descriptions-with-read-more}

{{< history >}}

- GitLab 17.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181184)되었습니다.

{{< /history >}}

이슈 설명이 길면 GitLab은 일부만 표시합니다. 전체 설명을 보려면 **더 읽기**를 선택해야 합니다. 이 축약으로 인해 긴 텍스트를 스크롤하지 않고도 페이지의 다른 요소를 더 쉽게 찾을 수 있습니다.

설명이 축약되는지 여부를 변경하려면:

1. 이슈에서 오른쪽 위 모서리에 **추가 작업** ({{< icon name="ellipsis_v" >}})을 선택합니다.
1. **설명 축약**을 기본 설정에 따라 켜거나 끕니다.

이 설정은 기억되며 모든 이슈, 작업, 에픽, 목표 및 핵심 결과에 영향을 줍니다.

## 오른쪽 사이드바 숨기기 {#hide-the-right-sidebar}

{{< history >}}

- GitLab 17.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181184)되었습니다.

{{< /history >}}

이슈 특성은 공간이 허락할 때 설명 오른쪽의 사이드바에 표시됩니다.

사이드바를 숨기고 설명 공간을 늘리려면:

1. 이슈에서 오른쪽 위 모서리에 **추가 작업** ({{< icon name="ellipsis_v" >}})을 선택합니다.
1. **사이드바 숨기기**를 선택합니다.

이 설정은 기억되며 모든 이슈, 작업, 에픽, 목표 및 핵심 결과에 영향을 줍니다.

사이드바를 다시 표시하려면:

- 이전 단계를 반복하고 **사이드바 표시**를 선택합니다.

## 이슈 삭제 {#delete-an-issue}

{{< history >}}

- 이슈를 삭제하기 위한 필수 역할이 GitLab 17.7에서 소유자에서 소유자 또는 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트의 계획자 또는 소유자 역할이 있어야 합니다.

이슈를 삭제하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 위 모서리에서 **추가 작업** ({{< icon name="ellipsis_v" >}})을 선택합니다.
1. **이슈 삭제**를 선택합니다.

## 이슈 유형 변경 {#change-the-issue-type}

{{< history >}}

- 이슈 유형을 변경하기 위한 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.
- 이슈를 핵심 결과, 목표 및 작업으로 변경하는 것이 GitLab 18.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/520791)되었습니다.

{{< /history >}}

사전 요구 사항:

- 이슈 작성자이거나 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나, 이슈의 작성자이거나, 이슈에 할당되어야 합니다.

이슈 유형을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 위 모서리에서 **추가 작업** ({{< icon name="ellipsis_v" >}})을 선택합니다.
1. **유형 변경**을 선택합니다.
1. **유형** 드롭다운 목록에서 새 유형을 선택합니다:

   - 핵심 결과
   - 목표
   - 작업
   - 에픽 (이슈를 부모 그룹으로 이동) 자세한 내용은 [이슈를 에픽으로 승격](#promote-an-issue-to-an-epic)을 참조하세요.

1. **유형 변경**을 선택합니다.

이슈를 인시던트로 승격하려면 [이슈를 인시던트로 승격](#promote-an-issue-to-an-incident)을 참조하세요.

### 이슈를 에픽으로 승격 {#promote-an-issue-to-an-epic}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 이슈를 에픽으로 승격하기 위한 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

이슈를 즉시 부모 그룹의 [에픽](../../group/epics/_index.md)으로 승격할 수 있습니다.

기밀 이슈를 에픽으로 승격하면 [기밀 에픽](../../group/epics/manage_epics.md#make-an-epic-confidential)이 생성되어 기밀성이 유지됩니다.

이슈가 에픽으로 승격될 때:

- 에픽이 이슈의 프로젝트와 동일한 그룹에 생성됩니다.
- 이슈의 구독자에게 에픽이 생성되었음을 알립니다.

다음 이슈 메타데이터가 에픽으로 복사됩니다:

- 제목, 설명, 활동 및 댓글 스레드.
- 업보트 및 다운보트.
- 참여자.
- 이슈가 가진 그룹 레이블.
- 부모 항목.

사전 요구 사항:

- 이슈가 속한 프로젝트는 그룹에 있어야 합니다.
- 프로젝트의 즉시 부모 그룹에 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 다음 중 하나를 수행해야 합니다:
  - 프로젝트에 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있습니다.
  - 이슈의 작성자입니다.
  - 이슈에 할당됩니다.

이슈를 에픽으로 승격하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 위 모서리에서 **추가 작업** ({{< icon name="ellipsis_v" >}})을 선택합니다.
1. **유형 변경**을 선택합니다.
1. **유형** 드롭다운 목록에서 **에픽**을 선택합니다.
1. **유형 변경**을 선택합니다.

또는 [`/promote_to Epic` 빠른 작업](../quick_actions.md#promote_to)을 사용할 수 있습니다.

### 이슈를 인시던트로 승격 {#promote-an-issue-to-an-incident}

[`/promote_to Incident` 빠른 작업](../quick_actions.md#promote_to)을 사용하여 이슈를 [인시던트](../../../operations/incident_management/incidents.md)로 승격할 수 있습니다.

## 이슈를 반복에 추가 {#add-an-issue-to-an-iteration}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[반복](../../group/iterations/_index.md)에 이슈를 추가하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 사이드바에서 **이터레이션** 섹션 아래 **편집**을 선택합니다.
1. 드롭다운 목록에서 이 이슈를 추가할 반복을 선택합니다.
1. 드롭다운 목록 외부의 아무 영역이나 선택합니다.

이슈를 반복에 추가하려면 다음을 수행할 수도 있습니다:

- [`/iteration` 빠른 작업](../quick_actions.md#iteration)을 사용합니다.
- 보드의 반복 목록으로 이슈를 드래그합니다.
- **작업 항목** 목록에서 이슈를 대량으로 편집합니다.

## 당신에게 할당된 모든 이슈 보기 {#view-all-issues-assigned-to-you}

당신에게 할당된 모든 이슈를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
1. 드롭다운 목록에서 **나에게 할당된 이슈**를 선택합니다.

또는:

- [키보드 단축키](../../shortcuts.md)를 사용하려면 <kbd>Shift</kbd>+<kbd>i</kbd>를 누르세요.
- 오른쪽 위 모서리에서 **할당된 작업 항목** ({{< icon name="work-items" >}})을 선택합니다.

## 이슈 목록 {#issue-list}

이슈 목록에는 프로젝트 또는 그룹의 모든 이슈가 표시됩니다. 이를 사용하여 이슈를 보고, 정렬하고, 관리할 수 있습니다.

이슈 목록을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음, **유형** = **이슈**로 필터링합니다.

**작업 항목** 목록에 표시될 특성을 설정하려면 [표시 설정 구성](../../work_items/_index.md#configure-list-display-preferences)을 수행하세요.

이슈 목록에서 다음을 수행할 수 있습니다:

- 제목, 담당자, 레이블 및 마일스톤과 같은 이슈 세부 정보를 봅니다.
- 다양한 기준으로 [이슈를 정렬](sorting_issue_lists.md)합니다.
- 이슈를 필터링하여 특정 이슈를 찾습니다.
- 개별적으로 또는 대량으로 이슈를 편집합니다.
- 새로운 이슈를 생성합니다.

다음 섹션에서는 이슈 목록으로 작업하는 방법을 설명합니다.

### 이슈 목록 필터링 {#filter-the-list-of-issues}

{{< history >}}

- OR 필터링이 GitLab 17.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/296031)합니다. 기능 플래그 `or_issuable_queries`이 제거되었습니다.
- 이슈 목록을 사용자 정의 상태 또는 부모 항목별로 필터링하는 것이 GitLab 18.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/520791)되었습니다.
- 생성 날짜, 종료 날짜, 마감일 및 업데이트 날짜별로 필터링하는 것이 GitLab 19.4에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/17758)합니다. 기능 플래그 `issue_date_filter`이 제거되었습니다.

{{< /history >}}

이슈 목록을 필터링하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음, **유형** = **이슈**로 필터링합니다.
1. 필요에 따라 추가 필터, 연산자 및 값을 선택합니다. 다음 필터를 사용할 수 있습니다:
   - 담당자
   - 작성자
   - 종료 날짜
   - 기밀
   - [연락처](../../crm/_index.md)
   - 생성 날짜
   - 마감일
   - [헬스](#health-status)
   - 반복
   - 레이블
   - 마일스톤
   - 내 반응
   - [조직](../../crm/_index.md)
   - [부모](../../group/epics/_index.md)
   - 릴리스
   - 검색 위치 (제목 또는 설명)
   - 상태
   - 구독됨
   - 형식
   - 업데이트 날짜
   - 가중치
   - [사용자 정의 필드](../../work_items/custom_fields.md)
1. 특성을 필터링할 연산자를 선택하거나 입력합니다. 다음 연산자를 사용할 수 있습니다:
   - `=`: 다음과 같음
   - `!=`: 다음 중 하나가 아님
   - `||`: 다음 중 하나 (담당자, 작성자, 레이블, 유형의 경우). 포함 OR처럼 작동합니다. 예를 들어 `Assignee is one of Sidney Jones` 및 `Assignee is one of Zhang Wei`으로 필터링하면 GitLab은 `Sidney`, `Zhang` 또는 둘 다 담당자인 이슈를 표시합니다.
1. 특성을 필터링할 텍스트를 입력합니다. 일부 특성을 **없음** 또는 **Any**로 필터링할 수 있습니다.
1. 이 프로세스를 반복하여 여러 특성으로 필터링합니다. 여러 특성이 논리적 `AND`으로 결합됩니다.
1. <kbd>Enter</kbd>를 누르거나 검색 아이콘 ({{< icon name="search" >}})을 선택합니다.

#### 제목 또는 설명별로 필터링 {#filter-by-title-or-description}

제목 또는 설명의 텍스트에 대해 이슈 목록을 필터링하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음, **유형** = **이슈**로 필터링합니다.
1. 필터 막대에서 검색 문구를 입력합니다.
1. 나타나는 드롭다운 목록에서 **이 텍스트 검색**을 선택합니다.
1. <kbd>Enter</kbd>를 누르거나 검색 아이콘 ({{< icon name="search" >}})을 선택합니다.

이슈 필터링은 [PostgreSQL 전체 텍스트 검색](https://www.postgresql.org/docs/16/textsearch-intro.html)을 사용하여 의미 있고 중요한 단어를 일치시킵니다.

예를 들어 `I am securing information for M&A`을(를) 검색하면 GitLab은 제목 또는 설명에서 `securing`, `secured` 또는 `information`을(를) 포함하는 결과를 반환할 수 있습니다. 그러나 GitLab은 `I`, `am` 또는 `M&A`이라는 문장 또는 단어를 정확히 일치시키지 않습니다. 이는 어휘적으로 의미 있거나 중요하지 않기 때문입니다. PostgreSQL 전체 텍스트 검색의 제한입니다.

#### ID별로 이슈 필터링 {#filter-issues-by-id}

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음, **유형** = **이슈**로 필터링합니다.
1. 필터 막대에서 `#` 다음에 이슈 ID를 입력합니다. 예를 들어 `#362255`을(를) 입력하면 이슈 362255만 반환됩니다.
1. **이 텍스트 검색**을 선택합니다.
1. <kbd>Enter</kbd>를 누르거나 검색 아이콘 ({{< icon name="search" >}})을 선택합니다.

### 패널에서 이슈 열기 {#open-issues-in-a-panel}

{{< history >}}

- `issues_list_drawer`라는 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/464063)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.6에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/463829)되었습니다. 기능 플래그 `issues_list_drawer`이 제거되었습니다.

{{< /history >}}

목록 또는 이슈 보드에서 이슈를 선택하면 세부 정보 패널에서 열립니다.

그러면 목록 또는 보드의 컨텍스트를 잃지 않고 세부 정보를 보고 편집할 수 있습니다.

패널을 사용할 때:

- 목록에서 이슈를 선택하여 패널에서 엽니다.
- 패널은 화면의 오른쪽에 나타납니다.
- 패널에서 이슈를 직접 편집할 수 있습니다.
- 패널을 닫으려면 닫기 아이콘 ({{< icon name="close" >}}) 또는 **에스케이프**를 누릅니다.

#### 전체 페이지로 열기 {#open-an-issue-in-full-page-view}

이슈를 전체 보기로 열려면:

- 새 탭에서 이슈를 엽니다. 이슈 목록에서 다음 중 하나를 수행합니다:
  - 이슈를 마우스 오른쪽 버튼으로 클릭하고 새 브라우저 탭에서 엽니다.
  - <kbd>Command</kbd> 또는 <kbd>Control</kbd>을 누른 상태에서 이슈를 선택합니다.
- 이슈를 선택한 후 패널에서 다음 중 하나를 수행합니다:
  - 왼쪽 위 모서리에서 이슈 참조 (예: `my_project#123`)를 선택합니다.
  - 오른쪽 위 모서리에서 **전체 페이지로 열기** ({{< icon name="maximize" >}})을 선택합니다.

항상 전체 페이지 보기에서 이슈를 열려면 [표시 설정 구성](../../work_items/_index.md#configure-list-display-preferences)을 수행하세요.

### 이슈 목록의 RSS 피드 구독 {#subscribe-to-an-rss-feed-of-the-issue-list}

이슈 목록의 RSS 피드를 구독할 수 있습니다. 피드는 목록에 적용된 모든 필터를 반영합니다.

프로젝트의 이슈 목록에 대한 RSS 피드를 구독하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음, **유형** = **이슈**로 필터링합니다.
1. 선택 사항. 모든 필터를 적용합니다.
1. 오른쪽 위 모서리에서 **조치** ({{< icon name="ellipsis_v" >}}) > **RSS 피드 구독**을 선택합니다.

그룹의 이슈 목록에 대한 RSS 피드를 구독하려면 동일한 단계를 따릅니다. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 대신 그룹을 찾습니다. 개인 이슈 목록의 경우 왼쪽 사이드바에서 **귀하의 작업** > **작업 항목**을 선택한 후 동일한 **조치** > **RSS 피드 구독**을 사용합니다.

피드 URL에는 피드 판독기로 인증하는 [피드 토큰](../../../security/tokens/_index.md#feed-token)이 포함됩니다.

## 이슈 참조 복사 {#copy-issue-reference}

GitLab의 다른 곳에서 이슈를 참조하려면 전체 URL 또는 `namespace/project-name#123`처럼 보이는 짧은 참조를 사용할 수 있습니다. 여기서 `namespace`은(는) 그룹 또는 사용자 이름입니다.

이슈 참조를 클립보드에 복사하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 위 모서리에서 **추가 작업** ({{< icon name="ellipsis_v" >}}) > **참조 복사**를 선택합니다.

이제 참조를 다른 설명 또는 댓글에 붙여넣을 수 있습니다.

자세한 내용은 [GitLab 고유 참조](../../markdown.md#gitlab-specific-references)를 참조하세요.

## 이슈 이메일 주소 복사 {#copy-issue-email-address}

이메일을 보내 이슈에서 댓글을 생성할 수 있습니다. 이 주소로 이메일을 보내면 이메일 본문을 포함하는 댓글이 생성됩니다.

이메일로 댓글을 생성하는 방법 및 필요한 구성에 대한 자세한 내용은 [이메일로 댓글에 회신](../../discussions/_index.md#reply-to-a-comment-by-sending-email)을 참조하세요.

이슈의 이메일 주소를 복사하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 위 모서리에서 **추가 작업** ({{< icon name="ellipsis_v" >}}) > **이슈 이메일 주소 복사**를 선택합니다.

## 담당자 {#assignees}

이슈는 [여러 사용자](multiple_assignees_for_issues.md)에게 할당할 수 있습니다.

담당자는 필요에 따라 자주 변경할 수 있습니다. 담당자들은 이슈에 대한 책임이 있는 사람들입니다. 이슈가 누군가에게 할당되면 **할당된 작업 항목** 페이지에 표시됩니다.

사용자가 프로젝트 멤버가 아닌 경우 이슈는 본인이 생성하거나 다른 프로젝트 멤버가 할당할 때만 할당될 수 있습니다.

### 이슈의 담당자 변경 {#change-assignee-on-an-issue}

{{< history >}}

- 담당자를 변경할 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

이슈의 담당자를 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 사이드바의 **담당자** 또는 **담당자** 섹션에서 **편집**을 선택합니다.
1. 드롭다운 목록에서 할당할 사용자를 선택합니다.
1. **적용**을 선택하거나 드롭다운 목록 외부의 아무 영역이나 선택합니다.

페이지를 새로 고칠 필요 없이 담당자가 변경됩니다.

## 유사한 이슈 {#similar-issues}

같은 주제의 이슈 중복을 방지하기 위해 GitLab은 새 이슈를 생성할 때 유사한 이슈를 검색합니다.

**새 이슈** 페이지의 제목 텍스트 상자에 입력하면 GitLab이 현재 프로젝트의 모든 이슈에 걸쳐 제목과 설명을 검색합니다. 액세스할 수 있는 이슈만 반환됩니다. 최대 5개의 유사한 이슈가 가장 최근에 업데이트된 순서로 제목 텍스트 상자 아래에 표시됩니다.

## 헬스 체크 상태 {#health-status}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

계획을 충족하는 위험을 더 잘 추적하기 위해 각 이슈에 헬스 체크 상태를 할당할 수 있습니다. 헬스 체크 상태를 사용하여 이슈가 계획대로 진행되고 있는지 아니면 일정에 맞추기 위해 주의가 필요한지 조직의 다른 사람들에게 알릴 수 있습니다.

일일 스탠드업, 프로젝트 상태 보고서 또는 주간 회의에 이슈 헬스 체크 상태 검토를 포함하여 계획된 작업의 적시 제공에 대한 위험을 해결합니다.

### 이슈의 헬스 체크 상태 변경 {#change-health-status-of-an-issue}

{{< history >}}

- 헬스 체크 상태를 변경할 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

이슈의 헬스 체크 상태를 편집하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 사이드바의 **헬스 체크 상태** 섹션에서 **편집**을 선택합니다.
1. 드롭다운 목록에서 이 이슈에 추가할 상태를 선택합니다:

   - 진행 중
   - 주의 필요
   - 위험 상태

이슈의 헬스 체크 상태를 다음 위치에서 볼 수 있습니다:

- **작업 항목** 목록
- 에픽의 **하위 항목** 섹션
- 이슈 보드의 이슈 카드

이슈가 닫힌 후에는 헬스 체크 상태를 편집할 수 없으며 이슈를 다시 열 때까지 **편집**을 사용할 수 없습니다.

[`/health_status`](../quick_actions.md#health_status) 및 [`/clear_health_status`](../quick_actions.md#clear_health_status) 빠른 작업을 사용하여 헬스 체크 상태를 설정하고 지울 수도 있습니다.

## 상태 {#status}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- `work_item_status_feature_flag`라는 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)로 GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/543862)되었습니다. 기본적으로 활성화됩니다.
- GitLab 18.4에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/issues/521286). 기능 플래그 `work_item_status_feature_flag`이 제거되었습니다.

{{< /history >}}

<!-- Turn off the future tense test because of "won't do". -->
<!-- vale gitlab_base.FutureTense = NO -->

이슈에 상태를 할당하여 워크플로우를 통한 진행 상황을 추적할 수 있습니다. 상태는 기본 열림/닫힘 상태보다 더 세분화된 추적을 제공하므로 **진행중**, **완료** 또는 **안 함**과 같은 특정 단계를 사용할 수 있습니다.

사용자 정의 상태를 구성하는 방법에 대한 자세한 내용은 [상태 섹션](../../work_items/status.md)을 참조하세요.

<!-- vale gitlab_base.FutureTense = YES -->

### 상태 변경 {#change-status}

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나, 이슈의 작성자이거나, 이슈에 할당되어야 합니다.

이슈의 상태를 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 사이드바에 **상태** 섹션에서 **편집**을 선택합니다.
1. 드롭다운 목록에서 상태를 선택합니다.

이슈의 상태가 즉시 업데이트됩니다.

이슈의 상태는 다음 위치에서 볼 수 있습니다:

- **작업 항목** 목록
- 에픽의 **하위 항목** 섹션
- 이슈 보드의 카드

[`/status` 빠른 작업](../quick_actions.md#status)을 사용하여 상태를 설정할 수도 있습니다.

## 참여자 {#participants}

참여자는 이슈와 상호작용한 사용자입니다. 참여자를 보는 방법에 대한 정보는 [참여자](../../participants.md)를 참조하세요.

## 이슈 발행 {#publish-an-issue}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

상태 페이지 애플리케이션이 프로젝트와 연결되어 있으면 [`/publish` 빠른 작업](../quick_actions.md#publish)을 사용하여 이슈를 발행할 수 있습니다.

자세한 내용은 [GitLab 상태 페이지](../../../operations/incident_management/status_page.md)를 참조하세요.

## 이슈 관련 빠른 작업 {#issue-related-quick-actions}

빠른 작업을 사용하여 이슈를 관리할 수도 있습니다.

일부 작업에는 아직 해당하는 UI 버튼이 없습니다. 빠른 작업을 사용하여만 다음을 수행할 수 있습니다:

- [Zoom 회의 추가 또는 제거](associate_zoom_meeting.md) ([`/zoom` 및 `/remove_zoom`](../quick_actions.md#zoom)).
- [이슈 발행](#publish-an-issue) ([`/publish`](../quick_actions.md#publish)).
- 같은 프로젝트 또는 다른 프로젝트로 이슈 복제 ([`/clone`](../quick_actions.md#clone)).
- 이슈를 닫고 다른 이슈의 중복으로 표시 ([`/duplicate`](../quick_actions.md#duplicate)).
- 프로젝트의 다른 병합 요청 또는 이슈에서 레이블 및 마일스톤 복사 ([`/copy_metadata`](../quick_actions.md#copy_metadata)).

## 관련 항목 {#related-topics}

- [연결된 항목](../../work_items/linked_items.md)
- [하위 항목](../../work_items/child_items.md)
