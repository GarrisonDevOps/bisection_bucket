---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 미완성 머지 리퀘스트가 준비될 때까지 병합되지 않도록 초안으로 설정하여 차단합니다.
title: 초안 머지 리퀘스트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

머지 리퀘스트가 병합할 준비가 되지 않았다면 [준비됨으로 마킹](#mark-merge-requests-as-ready)할 때까지 병합되지 않도록 차단할 수 있습니다. **초안**으로 표시된 머지 리퀘스트는 **초안** 플래그를 제거할 때까지 병합할 수 없으며, 다른 모든 병합 조건을 충족하더라도 마찬가지입니다:

![준비됨으로 표시될 때까지 병합이 차단된 초안 상태를 보여주는 머지 리퀘스트입니다.](img/merge_request_draft_blocked_v16_0.png)

## 머지 리퀘스트를 초안으로 마킹 {#mark-merge-requests-as-drafts}

여러 방법으로 머지 리퀘스트에 초안 플래그를 지정할 수 있습니다:

- 머지 리퀘스트 보기: 머지 리퀘스트의 오른쪽 위 모서리에서 **머지 리퀘스트 동작**({{< icon name="ellipsis_v" >}})을 선택한 다음 **초안으로 마킹**을 선택합니다.
- 머지 리퀘스트 생성 또는 편집: 다음 중 하나를 수행할 수 있습니다.
  - 머지 리퀘스트 제목의 시작 부분에 `[Draft]`, `Draft:` 또는 `(Draft)`을 추가합니다.
  - **제목** 필드 아래에서 **초안으로 마킹**을 선택합니다.
- 기존 머지 리퀘스트에 댓글 달기: 댓글에 [`/draft` 빠른 작업](../quick_actions.md#draft)을 추가합니다. 머지 리퀘스트를 준비됨으로 표시하려면 [`/ready`](../quick_actions.md#ready) 빠른 작업을 사용합니다.
- 커밋 생성: 머지 리퀘스트의 소스 브랜치를 대상으로 하는 커밋 메시지의 시작 부분에 `draft:`, `Draft:`, `fixup!` 또는 `Fixup!`을 추가합니다. 이 방법은 토글이 아닙니다. 이후 커밋에서 이 텍스트를 다시 추가해도 머지 리퀘스트가 준비됨으로 표시되지 않습니다.

## 머지 리퀘스트를 준비됨으로 마킹 {#mark-merge-requests-as-ready}

머지 리퀘스트가 병합할 준비가 되었을 때 여러 방법으로 `Draft` 플래그를 제거할 수 있습니다:

- 머지 리퀘스트 보기: 머지 리퀘스트의 오른쪽 위 모서리에서 **준비됨으로 마킹**을 선택합니다. 개발자, 유지 관리자 또는 소유자 역할이 있는 사용자는 머지 리퀘스트 설명의 맨 아래로 스크롤하여 **준비됨으로 마킹**을 선택할 수도 있습니다.
- 기존 머지 리퀘스트 편집: 제목의 시작 부분에서 `[Draft]`, `Draft:` 또는 `(Draft)`을 제거하거나 **제목** 필드 아래에서 **초안으로 마킹**을 선택 해제합니다.
- 기존 머지 리퀘스트에 댓글 달기: 머지 리퀘스트의 댓글에 [`/ready` 빠른 작업](../quick_actions.md#ready)을 추가합니다.

머지 리퀘스트를 준비됨으로 표시하면 GitLab이 [머지 리퀘스트 참여자 및 감시자](../../profile/notifications.md#issue-merge-request-and-epic-events)에게 알립니다.

## 검색 시 초안 포함 또는 제외 {#include-or-exclude-drafts-when-searching}

프로젝트의 머지 리퀘스트 목록을 보거나 검색할 때 초안 머지 리퀘스트를 포함하거나 제외하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**을 선택합니다.
1. 머지 리퀘스트 상태별로 필터링하려면 탐색 모음에서 **열기**, **머지됨**, **닫힘** 또는 **전체**를 선택합니다.
1. 검색 상자를 선택하여 필터 목록을 표시하고 **초안**을 선택하거나 `draft`을 입력합니다.
1. `=`을 선택합니다.
1. 초안을 포함하려면 **예**를 선택하거나 제외하려면 **아니오**를 선택한 다음 **Return**을 눌러 머지 리퀘스트 목록을 업데이트합니다:

   ![선택 옵션과 함께 초안 필터 옵션을 보여주는 머지 리퀘스트 필터 드롭다운 목록입니다.](img/filter_draft_merge_requests_v16_0.png)

## 초안의 파이프라인 {#pipelines-for-drafts}

초안 머지 리퀘스트는 준비됨으로 표시된 머지 리퀘스트와 동일한 파이프라인을 실행합니다.

초안 머지 리퀘스트의 파이프라인을 건너뛰려면 [초안 머지 리퀘스트의 파이프라인 건너뛰기](../../../ci/yaml/workflow.md#skip-pipelines-for-draft-merge-requests)를 참조합니다.
