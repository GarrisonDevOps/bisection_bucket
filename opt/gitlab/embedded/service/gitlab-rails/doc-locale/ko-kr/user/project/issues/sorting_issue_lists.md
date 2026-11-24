---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 이슈 목록 정렬 및 순서 정렬
description: "마감일, 우선 순위, 인기도, 마일스톤, 헬스 상태 또는 기타 조건별로 이슈 목록을 정렬하여 작업 항목을 찾고 정렬합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

여러 방법으로 이슈 목록을 정렬할 수 있습니다. 사용 가능한 정렬 옵션은 목록의 컨텍스트에 따라 변경될 수 있습니다. 목록의 정렬 방식을 변경하려면 [작업 항목 정렬](../../work_items/_index.md#sort-work-items)을 참조하세요.

## 차단 이슈별로 정렬 {#sorting-by-blocking-issues}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

**차단**으로 정렬하면 이슈 목록이 각 이슈가 [차단](related_issues.md#blocking-issues)하는 이슈의 수로 내림차순으로 정렬됩니다.

## 생성, 업데이트 또는 닫힌 날짜별로 정렬 {#sorting-by-created-updated-or-closed-date}

**생성됨**, **업데이트됨**, 또는 **닫힌 날짜**로 정렬하면 이슈 목록이 각 날짜 및 시간 기준으로 내림차순으로 정렬됩니다. 최근에 생성, 업데이트 또는 닫힌 이슈가 먼저 표시됩니다.

## 마감일별로 정렬 {#sorting-by-due-date}

**마감일**로 정렬하면 이슈 목록이 이슈 [마감일](due_dates.md)을 기준으로 오름차순으로 정렬됩니다. 가장 빠른 마감일을 가진 이슈가 먼저 표시되고 마감일이 없는 이슈는 마지막에 표시됩니다.

## 라벨 우선 순위별로 정렬 {#sorting-by-label-priority}

**라벨 우선순위**로 정렬하면 이슈 목록이 내림차순으로 정렬됩니다. 우선 순위가 가장 높은 레이블이 있는 이슈가 먼저 표시되고 다른 모든 이슈가 뒤에 표시됩니다.

동일한 경우는 임의로 처리됩니다. 가장 높은 우선순위의 레이블만 확인되며 우선순위가 낮은 레이블은 무시됩니다. 자세한 내용은 [이슈 14523](https://gitlab.com/gitlab-org/gitlab/-/issues/14523)을 참조하세요.

자세한 내용은 [레이블 우선 순위](../labels.md#set-label-priority)를 참조하세요.

## 수동 정렬 {#manual-sorting}

**수동** 순서로 정렬하면 이슈를 끌어다 놓아 순서를 변경할 수 있습니다. 변경된 순서가 유지되고 동일한 목록을 방문하는 모든 사용자는 업데이트된 이슈 순서를 볼 수 있습니다. 일부 예외가 있습니다.

각 이슈에는 목록의 다른 이슈에 대한 상대적 순서를 나타내는 상대 순서 값이 할당됩니다. 이슈를 끌어다 놓아 순서를 변경하면 상대 순서 값이 변경됩니다.

또한 이슈가 수동으로 정렬된 목록에 나타날 때마다 업데이트된 상대 순서 값이 순서 지정에 사용됩니다. 따라서 누군가가 GitLab 인스턴스에서 이슈 `A` 위에 이슈 `B`를 끌어놓으면 목록에서 함께 나타날 때마다 이 순서가 유지됩니다.

이 순서는 [이슈 보드](../issue_board.md#ordering-issues-in-a-list)에도 영향을 줍니다. 이슈 목록의 순서를 변경하면 이슈 보드의 순서가 변경되고 그 반대도 마찬가지입니다.

## 마일스톤 마감일별로 정렬 {#sorting-by-milestone-due-date}

**마일스톤 마감일**로 정렬하면 이슈 목록이 할당된 마일스톤 마감일을 기준으로 오름차순으로 정렬됩니다. 가장 빠른 마감일이 있는 마일스톤이 있는 이슈가 먼저 표시되고 마감일이 없는 마일스톤이 있는 이슈가 뒤에 표시됩니다.

## 인기도별로 정렬 {#sorting-by-popularity}

**인기도**로 정렬하면 이슈 순서가 각 이슈의 upvote 수로 내림차순으로 정렬됩니다([이모지 반응](../../emoji_reactions.md) 중 "thumbs up"). 이를 사용하면 수요가 높은 이슈를 식별할 수 있습니다.

투표의 총 수는 합산되지 않습니다. 18개의 upvote와 5개의 downvote가 있는 이슈는 17개의 upvote와 downvote가 없는 이슈보다 더 인기가 있다고 간주됩니다.

## 우선 순위별로 정렬 {#sorting-by-priority}

**우선 순위**로 정렬하면 이슈 순서가 다음 순서로 정렬됩니다:

1. 마감일이 있는 마일스톤이 있는 이슈(가장 빠른 할당된 마일스톤이 먼저 나열됨).
1. 마감일이 없는 마일스톤이 있는 이슈.
1. 더 높은 우선순위 레이블이 있는 이슈.
1. 우선순위 레이블이 없는 이슈.

동일한 경우는 임의로 처리됩니다.

자세한 내용은 [레이블 우선 순위](../labels.md#set-label-priority)를 참조하세요.

## 제목별로 정렬 {#sorting-by-title}

**제목**으로 정렬하면 이슈 순서가 이슈 제목에 따라 다음 순서로 알파벳순으로 정렬됩니다:

- 이모지
- 특수 문자
- 숫자
- 문자: 먼저 라틴, 그 다음 악센트 (예: `ö`)

## 헬스 상태별로 정렬 {#sorting-by-health-status}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

**헬스**로 정렬하면 이슈 목록이 이슈의 [헬스 상태](managing_issues.md#health-status)별로 정렬됩니다. 내림차순으로 나타낼 때 이슈는 다음 순서로 표시됩니다:

1. **위험함** 이슈
1. **주의 필요** 이슈
1. **추적중** 이슈
1. 기타 모든 이슈

## 가중치별로 정렬 {#sorting-by-weight}

**가중치**로 정렬하면 이슈 목록이 [이슈 가중치](../../work_items/weight.md)를 기준으로 오름차순으로 정렬됩니다. 가중치가 가장 낮은 이슈가 먼저 표시되고 가중치가 없는 이슈는 마지막에 표시됩니다.

## 상태별로 정렬 {#sorting-by-status}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.5에서 `work_item_status_mvc2`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/550262)되었습니다. 기본적으로 활성화됩니다.
- GitLab 18.6에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/576610)되었습니다. 기능 플래그 `work_item_status_mvc2`이 제거되었습니다.

{{< /history >}}

**상태**로 정렬하면 이슈 목록이 [이슈 상태](../../work_items/status.md)를 기준으로 오름차순으로 정렬됩니다. 이슈는 먼저 상태 범주별로 정렬됩니다. 두 이슈가 동일한 범주를 공유하면 시스템은 이슈 ID로 정렬하도록 폴백됩니다.
