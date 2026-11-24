---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "GitLab에서 여러 사람을 단일 이슈에 할당하여 소유권을 명확히 하고, 협업을 개선하고, 큰 팀에서 공유된 책임을 추적하는 방법을 알아봅니다."
title: 이슈에 대한 여러 담당자
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Free 사용자는 하나의 이슈에 한 명의 사용자를 할당할 수 있습니다. GitLab Premium 및 Ultimate 사용자는 하나의 이슈에 여러 사용자를 할당할 수 있습니다.

공유된 소유권이 있는 큰 팀에서는 누가 이슈를 진행 중인지, 누가 이미 완료했는지, 누가 아직 시작하지 않았는지 추적하기 어려울 수 있습니다.

여러 [담당자](managing_issues.md#assignees)를 이슈에 추가하여 추적을 더 쉽게 하고, 누가 책임이 있는지 더 명확하게 할 수 있습니다.

이슈에 대한 여러 담당자는 협업을 더 원활하게 하고, 공유된 책임을 명확하게 표시할 수 있게 합니다. 모든 담당자가 팀의 워크플로우에 표시되고 알림을 받으므로(단일 담당자처럼), 통신과 소유권이 단순화됩니다.

담당자가 자신의 작업을 완료한 후 자신을 담당자에서 제거하여 작업이 완료되었음을 명확하게 합니다.

## 이슈에 여러 사용자 할당 {#assign-multiple-users-to-an-issue}

사전 요구 사항:

- 프로젝트에 대해 플래너, 보고자, 개발자, 유지보수자 또는 소유자 역할이 있어야 합니다.

여러 사용자를 이슈에 할당하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고, **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 사이드바의 **Assignees** 섹션에서 **Edit**을 선택합니다.
1. 드롭다운 목록에서 할당할 사용자를 선택합니다. 드롭다운 목록이 열린 상태로 유지되므로 둘 이상의 사용자를 선택할 수 있습니다.
1. **적용**을 선택하거나 드롭다운 목록 외부의 아무 영역이나 선택합니다.

GitLab은 드롭다운 목록을 닫을 때만 선택 항목을 저장합니다.

[`/assign` 빠른 작업](../quick_actions.md#assign)을 사용하여 담당자를 추가할 수도 있습니다.

## 담당자 제거 {#remove-an-assignee}

이슈에서 담당자를 제거하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고, **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 오른쪽 사이드바의 **Assignees** 섹션에서 **Edit**을 선택합니다.
1. 드롭다운 목록에서 사용자의 선택을 지웁니다.
1. **적용**을 선택하거나 드롭다운 목록 외부의 아무 영역이나 선택합니다.

[`/unassign` 빠른 작업](../quick_actions.md#unassign)을 사용할 수도 있습니다.

## 관련 항목 {#related-topics}

- [작업에 사용자 할당](../../tasks.md#assign-users-to-a-task)
- [이슈 API](../../../api/issues.md)
