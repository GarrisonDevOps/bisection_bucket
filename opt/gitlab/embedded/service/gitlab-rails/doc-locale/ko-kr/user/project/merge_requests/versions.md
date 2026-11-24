---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 단일 병합 요청에 포함된 푸시를 비교하기 위해 diff 버전을 사용합니다.
title: 병합 요청 diff 버전
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

병합 요청을 생성할 때 비교할 두 개의 브랜치를 선택합니다. 두 브랜치 간의 차이점이 병합 요청의 diff로 표시됩니다. 병합 요청에 연결된 브랜치에 커밋을 푸시할 때마다 GitLab은 병합 요청 diff를 새 diff 버전으로 업데이트합니다.

> [!note]
> Diff 버전은 각 커밋마다가 아니라 각 푸시마다 업데이트됩니다. 푸시에 여러 커밋이 포함되어 있으면 새 diff 버전이 하나만 생성됩니다.

기본적으로 GitLab은 소스 브랜치의 최신 푸시(`feature`)를 대상 브랜치의 가장 최근 커밋(종종 `main`)과 비교합니다.

## Diff 버전 비교 {#compare-diff-versions}

브랜치에 여러 번 푸시한 경우 이전 각 푸시의 diff 버전을 비교할 수 있습니다. 병합 요청에 많은 변경 사항이 포함되어 있거나 동일한 파일에 순차적인 변경 사항이 있는 경우 더 적은 수의 변경 사항을 비교할 수 있습니다.

사전 요구 사항:

- 병합 요청 브랜치는 여러 푸시의 커밋을 포함해야 합니다. 동일한 푸시의 개별 커밋은 새 diff 버전을 생성하지 않습니다.

Diff 버전을 비교하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**을 선택합니다.
1. 병합 요청을 선택합니다.
1. 이 병합 요청의 현재 diff 버전을 보려면 **변경사항**을 선택합니다.
1. **비교** ({{< icon name="file-tree" >}}) 옆에서 비교할 푸시를 선택합니다. 이 예제는 `main`을 브랜치의 가장 최근 푸시(최신 diff 버전)와 비교합니다:

   ![병합 요청 버전 드롭다운 목록](img/versions_dropdown_v16_6.png)

   이 예제 브랜치는 4개의 커밋을 가지고 있지만 두 개의 커밋이 동시에 푸시되었기 때문에 브랜치는 3개의 diff 버전만 포함합니다.

## 시스템 노트에서 diff 버전 보기 {#view-diff-versions-from-a-system-note}

GitLab은 병합 요청 브랜치에 새 변경 사항을 푸시할 때마다 병합 요청에 시스템 노트를 추가합니다. 이 예제에서 단일 푸시가 두 개의 커밋을 추가했습니다:

![병합 요청 버전 시스템 노트](img/versions_system_note_v16_6.png)

해당 커밋의 diff를 보려면 커밋 SHA를 선택합니다.

자세한 내용은 [병합 요청에서 시스템 노트 표시 또는 필터링하는 방법](../system_notes.md#on-a-merge-request)을 참조하세요.

## 관련 항목 {#related-topics}

- [관리자를 위한 병합 요청 diff 저장소](../../../administration/merge_request_diffs.md)
