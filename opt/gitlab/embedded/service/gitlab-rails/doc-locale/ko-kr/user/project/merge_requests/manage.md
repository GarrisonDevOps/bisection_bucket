---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 병합 요청 리뷰를 사용하여 코드를 프로젝트에 병합하기 전에 논의하고 개선합니다.
title: 병합 요청 관리
---

GitLab은 프로젝트 및 그룹의 병합 요청을 관리하기 위한 도구를 제공합니다.

## 병합 요청 삭제 {#delete-a-merge-request}

대부분의 경우 병합 요청을 삭제하지 말고 종료해야 합니다. 병합 요청 삭제를 취소할 수 없습니다.

사전 요구 사항:

- 프로젝트에 대해 소유자 역할이 필요합니다.

병합 요청을 삭제하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**을 선택하고 삭제할 병합 요청을 찾습니다.
1. **편집**을 선택합니다.
1. 페이지 하단으로 스크롤한 다음 **병합 요청 삭제**를 선택합니다.

> [!note]
> 병합 요청을 삭제하면 모든 데이터가 완전히 삭제되지는 않습니다. 일부 정보는 프로젝트 기록을 유지하고 복구 프로세스를 지원하기 위해 유지됩니다. 자세한 내용은 [민감한 정보 처리](../../../topics/git/undo.md#handle-sensitive-information)를 참조하세요.

## 프로젝트에서 병합 요청 대량 편집 {#bulk-edit-merge-requests-in-a-project}

병합 요청을 대량 편집할 때 편집할 수 있는 특성은 다음과 같습니다:

- 상태(열기/닫기)
- 담당자
- 마일스톤
- 레이블
- 구독

사전 요구 사항:

- 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

다음과 같이 설정합니다.

1. 프로젝트에서 **코드** > **병합 요청**으로 이동합니다.
1. **대량 편집**을 선택합니다. 화면의 오른쪽에 편집 가능한 필드가 있는 사이드바가 나타납니다.
1. 편집할 각 병합 요청 옆의 확인란을 선택합니다.
1. 사이드바에서 적절한 필드와 해당 값을 선택합니다.
1. **선택한 업데이트**를 선택합니다.

## 그룹에서 병합 요청 대량 편집 {#bulk-edit-merge-requests-in-a-group}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹의 병합 요청을 대량 편집할 때 편집할 수 있는 특성은 다음과 같습니다:

- 마일스톤
- 레이블

사전 요구 사항:

- 프로젝트에 대해 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

여러 그룹 병합 요청을 동시에 업데이트하려면:

1. 그룹에서 **코드** > **병합 요청**으로 이동합니다.
1. **대량 편집**을 선택합니다. 화면의 오른쪽에 편집 가능한 필드가 있는 사이드바가 나타납니다.
1. 편집할 각 병합 요청 옆의 확인란을 선택합니다.
1. 사이드바에서 적절한 필드와 해당 값을 선택합니다.
1. **선택한 업데이트**를 선택합니다.

## 관련 항목 {#related-topics}

- [이슈 대량 편집](../issues/managing_issues.md#bulk-edit-issues)
