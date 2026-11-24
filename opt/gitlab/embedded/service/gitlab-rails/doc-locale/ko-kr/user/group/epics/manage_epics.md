---
stage: Plan
group: Portfolio Planning
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 에픽 관리
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 페이지는 [에픽](_index.md)으로 수행할 수 있는 모든 작업과 관련된 지침을 수집합니다.

에픽의 하위 항목 관리에 대한 정보는 [하위 항목](../../work_items/child_items.md)을 참조하세요.

## 에픽 생성 {#create-an-epic}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.
- 에픽에 마일스톤 할당이 GitLab 18.2에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/329)되었습니다.
- 에픽에 가중치 할당이 GitLab 18.11에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/12273)되었습니다.

{{< /history >}}

사전 요구 사항:

- 에픽의 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

그룹에서 에픽을 생성하려면:

1. 새 에픽 양식으로 이동합니다:
   - 그룹으로 이동하고 왼쪽 사이드바에서 **작업 항목**을 선택합니다. 그런 다음 **새 항목**을 선택합니다.
   - 그룹의 에픽에서 오른쪽 위 모서리에서 **추가 작업**({{< icon name="ellipsis_v" >}})을 선택합니다. 그런 다음 **새 관련 항목**을 선택합니다.
   - 어디서나 상단 메뉴에서 **신규**({{< icon name="plus-square" >}})을 선택합니다. 그런 다음 **새 작업 항목**을 선택합니다.
   - 빈 [로드맵](../roadmap/_index.md)에서 **새 작업 항목**을 선택합니다.

1. **유형** 드롭다운 목록에서 아직 선택하지 않았다면 **에픽**을 선택합니다.
1. 필드를 완성하세요.
   - 제목을 입력합니다.
   - 설명을 입력합니다.
   - [에픽을 기밀로 만들기](#make-an-epic-confidential) 위해 **비공개 활성화** 옆의 확인란을 선택합니다.
   - 레이블을 선택합니다.
   - 시작 및 마감 날짜를 선택하거나 [상속](#start-and-due-date-inheritance)합니다.
   - [색상](#epic-color)을 선택합니다.
1. **에픽 생성**을 선택합니다.

새로 생성된 에픽이 열립니다.

### 시작 및 마감 날짜 상속 {#start-and-due-date-inheritance}

**상속됨**을 선택하면:

- **시작 날짜**의 경우: GitLab은 에픽에 할당된 모든 하위 에픽 및 이슈를 스캔하고 시작 날짜를 하위 에픽에서 찾은 가장 빠른 시작 날짜 또는 하위 항목에 할당된 마일스톤과 일치하도록 설정합니다.
- **마감 날짜**의 경우: GitLab은 에픽에 할당된 모든 하위 에픽 및 이슈를 스캔하고 마감 날짜를 하위 에픽에서 찾은 최신 마감 날짜 또는 하위 항목에 할당된 마일스톤과 일치하도록 설정합니다.

이 날짜는 동적이며 다음 중 하나가 발생하면 다시 계산됩니다:

- 하위 에픽의 날짜가 변경됩니다.
- 마일스톤이 이슈에 다시 할당됩니다.
- 마일스톤의 날짜가 변경됩니다.
- 이슈가 에픽에 추가되거나 제거됩니다.

에픽의 날짜는 하위 항목에서 날짜를 상속할 수 있으므로 시작 날짜와 마감 날짜는 아래에서 위로 전파됩니다. 최하위 레벨의 하위 에픽의 시작 날짜가 변경되면 이는 상위 에픽의 가장 빠른 가능한 시작 날짜가 됩니다. 상위 에픽의 시작 날짜는 이 변경을 반영하고 상단 에픽으로 위로 전파됩니다.

## 에픽 편집 {#edit-an-epic}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

에픽을 생성한 후 다음 세부 정보를 편집할 수 있습니다:

- 제목
- 설명
- 시작 날짜
- 마감일
- 레이블
- 마일스톤
- [색상](#epic-color)

사전 요구 사항:

- 에픽의 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

에픽의 제목 또는 설명을 편집하려면:

1. **편집**을 선택합니다.
1. 변경 사항을 만듭니다.
1. **변경 사항 저장**을 선택합니다.

에픽의 시작 날짜, 마감 날짜, 마일스톤 또는 레이블을 편집하려면:

1. 오른쪽 사이드바의 각 섹션 옆에서 **편집**을 선택합니다.
1. 에픽의 날짜, 마일스톤 또는 레이블을 선택합니다.

### 에픽 설명에서 목록 항목 재정렬 {#reorder-list-items-in-the-epic-description}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

설명에 목록이 있는 에픽을 볼 때 목록 항목을 재정렬할 수도 있습니다.

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있거나, 에픽의 작성자이거나, 에픽에 할당되어야 합니다.
- 에픽의 설명에는 [순서가 있는 목록, 순서 없는](../../markdown.md#lists) 또는 [작업](../../markdown.md#task-lists) 목록이 있어야 합니다.

에픽을 볼 때 목록 항목을 재정렬하려면:

1. 목록 항목 행에 마우스를 올려서 그립 아이콘 ({{< icon name="grip" >}})을 표시합니다.
1. 그립 아이콘을 선택하고 누릅니다.
1. 행을 목록의 새 위치로 드래그합니다.
1. 그립 아이콘을 놓습니다.

### 에픽 대량 편집 {#bulk-edit-epics}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.
- GitLab 18.3에서 더 많은 대량 편집 특성이 [추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200186)되었습니다.
- GitLab 18.5에서 상위 특성에 대한 대량 편집 지원이 [추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/204037)되었습니다.

{{< /history >}}

사전 요구 사항:

- 상위 에픽의 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

여러 에픽을 동시에 업데이트하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음 **유형** = **에픽**으로 필터링합니다.
1. **대량 편집**을 선택합니다. 오른쪽에 편집 가능한 필드가 있는 사이드바가 나타납니다.
1. 편집하려는 각 에픽 옆의 확인란을 선택합니다.
1. 사이드바에서 사용 가능한 필드를 편집합니다.
1. **선택한 업데이트**를 선택합니다.

그룹에서 에픽을 대량 편집할 때 다음 특성을 편집할 수 있습니다:

- 상태 (열림 또는 닫힘)
- [담당자](#assignees)
- [레이블](../../project/labels.md)
- [헬스 체크 상태](#health-status)
- [알림](../../profile/notifications.md) 구독
- [기밀성](#make-an-epic-confidential)
- [마일스톤](../../project/milestones/_index.md)
- [부모](../../work_items/child_items.md#add-a-parent-epic-to-an-epic)

## **더 읽기**로 설명 축약 방지 {#prevent-truncating-descriptions-with-read-more}

{{< history >}}

- GitLab 17.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181184)되었습니다.

{{< /history >}}

에픽 설명이 길면 GitLab은 일부만 표시합니다. 전체 설명을 보려면 **더 읽기**를 선택해야 합니다. 이 축약으로 인해 긴 텍스트를 스크롤하지 않고도 페이지의 다른 요소를 더 쉽게 찾을 수 있습니다.

설명이 축약되는지 여부를 변경하려면:

1. 에픽에서 오른쪽 위 모서리에서 **추가 작업**({{< icon name="ellipsis_v" >}})을 선택합니다.
1. **설명 축약**을 기본 설정에 따라 켜거나 끕니다.

이 설정은 기억되며 모든 이슈, 작업, 에픽, 목표 및 핵심 결과에 영향을 줍니다.

## 오른쪽 사이드바 숨기기 {#hide-the-right-sidebar}

{{< history >}}

- GitLab 17.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181184)되었습니다.

{{< /history >}}

에픽 특성은 공간이 허용할 때 설명의 오른쪽에 있는 사이드바에 표시됩니다.

사이드바를 숨기고 설명 공간을 늘리려면:

1. 에픽에서 오른쪽 위 모서리에서 **추가 작업**({{< icon name="ellipsis_v" >}})을 선택합니다.
1. **사이드바 숨기기**를 선택합니다.

이 설정은 기억되며 모든 이슈, 작업, 에픽, 목표 및 핵심 결과에 영향을 줍니다.

사이드바를 다시 표시하려면:

- 이전 단계를 반복하고 **사이드바 표시**를 선택합니다.

## 담당자 {#assignees}

{{< details >}}

- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- `work_items_beta`라는 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/groups/gitlab-org/-/epics/4231)되었습니다. 기본적으로 비활성화되었습니다. 이 기능은 [베타](../../../policy/development_stages_support.md#beta) 단계입니다.
- GitLab 18.2에서 [정식 출시](https://gitlab.com/gitlab-org/gitlab/-/issues/551805)되었습니다. 기능 플래그 `work_items_beta` 뒤에서 이동되었습니다.

{{< /history >}}

에픽은 하나 이상의 사용자에게 할당될 수 있습니다.

담당자는 필요에 따라 자주 변경할 수 있습니다. 담당자는 에픽을 담당하는 사람들입니다.

사용자가 그룹의 구성원이 아닌 경우 다른 그룹 구성원이 할당하면 에픽을 해당 사용자에게만 할당할 수 있습니다.

### 에픽의 담당자 변경 {#change-assignee-on-an-epic}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

에픽의 담당자를 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음 **유형** = **에픽**으로 필터링합니다.
1. 에픽을 선택하여 봅니다.
1. 오른쪽 사이드바의 **담당자** 섹션에서 **편집**을 선택합니다.
1. 드롭다운 목록에서 담당자로 추가할 사용자를 선택합니다.
1. 드롭다운 목록 외부의 아무 영역이나 선택합니다.

페이지를 새로 고칠 필요 없이 담당자가 변경됩니다.

## 에픽 색상 {#epic-color}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

{{< history >}}

- 사용자 지정 가능한 색상이 GitLab 17.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/394864)되었습니다.

{{< /history >}}

에픽의 색상을 설정하여 작업을 시각적으로 분류하고 우선순위를 지정할 수 있습니다. 색상을 사용하여:

- 에픽을 팀 또는 회사 이니셔티브와 연결합니다.
- 에픽 계층 구조의 레벨을 표시합니다.
- 관련 에픽을 함께 그룹화합니다.

에픽 색상은 [로드맵](../roadmap/_index.md) 및 [에픽 보드](epic_boards.md)에 표시됩니다.

로드맵에서 타임라인 막대는 에픽의 색상과 일치합니다:

![v17.0에서 색상으로 구분된 에픽](img/epic_color_roadmap_v17_0.png)

에픽 보드에서 색상은 에픽의 카드 악센트에 표시됩니다:

![v17.0에서 관련 에픽 색상으로 강조된 카드](img/epic_accent_boards_v17_0.png)

### 에픽의 색상 변경 {#change-an-epics-color}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 에픽의 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

에픽의 색상을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음 **유형** = **에픽**으로 필터링합니다.
1. 에픽을 선택합니다.
1. 오른쪽 사이드바의 **색상** 섹션에서 **편집**을 선택합니다.
1. 기존 색상을 선택하거나 RGB 또는 16진수 값을 입력합니다.
1. 대화 상자 외부의 모든 영역을 선택합니다.

에픽의 색상이 업데이트됩니다.

## 에픽 삭제 {#delete-an-epic}

{{< history >}}

- GitLab 17.7에서 계획자 역할이 에픽을 삭제하도록 [허용](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 에픽의 그룹에 대해 계획자 또는 소유자 역할이 있어야 합니다.

에픽을 삭제하려면:

1. 오른쪽 위 모서리에서 **추가 작업**({{< icon name="ellipsis_v" >}})을 선택한 다음 **에픽 삭제**를 선택합니다.
1. **삭제**를 선택합니다. 확인 대화 상자에서 **에픽 삭제**를 선택합니다.

에픽을 삭제하면 시스템의 관련 에픽에서 모든 기존 이슈가 해제됩니다.

## 에픽 종료 {#close-an-epic}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 에픽의 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

에픽을 종료하려면:

- 오른쪽 위 모서리에서 **추가 작업**({{< icon name="ellipsis_v" >}})을 선택한 다음 **에픽 종료**를 선택합니다.

[`/close` 빠른 작업](../../project/quick_actions.md#close)을 사용할 수도 있습니다.

## 종료된 에픽 다시 열기 {#reopen-a-closed-epic}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

종료된 에픽을 다시 열 수 있습니다.

사전 요구 사항:

- 에픽의 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

이렇게 하려면:

- 오른쪽 위 모서리에서 **추가 작업**({{< icon name="ellipsis_v" >}})을 선택한 다음 **에픽 다시 열기**를 선택합니다.
- [`/reopen` 빠른 작업](../../project/quick_actions.md#reopen)을 사용합니다.

[이슈 승격](../../project/issues/managing_issues.md#promote-an-issue-to-an-epic)으로 에픽을 생성할 수도 있습니다.

## 이슈에서 에픽으로 이동 {#go-to-an-epic-from-an-issue}

이슈가 에픽에 속하면 다음에서 상위 에픽으로 이동할 수 있습니다:

- 이슈 상단의 경로 표시입니다.
- 오른쪽 사이드바의 **상위** 섹션입니다.

## 에픽 목록 보기 {#view-epics-list}

사전 요구 사항:

- 다음 중 하나의 구성원이어야 합니다:
  - 그룹
  - 그룹의 프로젝트
  - 그룹의 모든 하위 그룹의 프로젝트

그룹의 에픽을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음 **유형** = **에픽**으로 필터링합니다.

에픽 목록에 표시되는 특성을 설정하려면 [표시 기본 설정 구성](../../work_items/_index.md#configure-list-display-preferences)을 참조하세요.

### 에픽을 볼 수 있는 사람 {#who-can-view-an-epic}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

에픽을 볼 수 있는지 여부는 [그룹 가시성 레벨](../../public_access.md) 및 에픽의 [기밀성 상태](#make-an-epic-confidential)에 따라 다릅니다:

- 공개 그룹 및 비기밀 에픽: 누구나 에픽을 볼 수 있습니다.
- 개인 그룹 및 비기밀 에픽: 그룹의 게스트, 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있거나 그룹의 프로젝트 구성원이거나 모든 하위 그룹의 프로젝트 구성원이어야 합니다.
- 기밀 에픽(그룹 가시성 여부 무관): 그룹에 대해 최소 계획자 역할이 있어야 합니다.

에픽을 볼 수 있는 권한은 하위 항목을 볼 수 있는 권한과 다릅니다. **하위 항목** 섹션에서는 볼 수 있는 권한이 있는 항목만 표시됩니다. 항목 수 및 진행률에는 볼 수 없는 항목이 포함됩니다. 자세한 내용은 [에픽의 이슈 수 및 가중치 보기](../../work_items/child_items.md#view-count-and-weight-of-issues-in-an-epic)를 참조하세요.

### 에픽을 드로어에서 열기 {#open-epics-in-a-drawer}

{{< history >}}

- `work_item_view_for_issues`라는 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/464698)되었습니다. 기본적으로 활성화됩니다.
- 드로어와 전체 페이지 보기 간 전환이 GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/536620)되었습니다.
- GitLab 18.6에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/500367)되었습니다. 기능 플래그 `epics_list_drawer`이 제거되었습니다.

{{< /history >}}

작업 항목 페이지 또는 에픽 보드에서 에픽을 선택하면 세부 정보 패널에서 열립니다. 그런 다음 에픽 목록이나 보드의 컨텍스트를 잃지 않고 세부 정보를 보고 편집할 수 있습니다.

드로어를 사용할 때:

- 목록에서 에픽을 선택하여 드로어에서 엽니다.
- 드로어가 화면의 오른쪽에 나타납니다.
- 드로어에서 직접 에픽을 편집할 수 있습니다.
- 드로어를 닫으려면 닫기 아이콘({{< icon name="close" >}})을 선택하거나 **에스케이프** 키를 누르세요.

#### 에픽을 전체 페이지 보기로 열기 {#open-an-epic-in-full-page-view}

에픽을 전체 페이지 보기로 열려면:

- 새 탭에서 에픽을 엽니다. 작업 항목 목록에서:
  - 에픽을 마우스 오른쪽 버튼으로 클릭하고 새 브라우저 탭에서 엽니다.
  - <kbd>Command</kbd> 또는 <kbd>Control</kbd>을 누르고 에픽을 선택합니다.
- 에픽을 선택하고 드로어에서:
  - 왼쪽 위 모서리에서 이슈 참조 (예: `my_project#123`)를 선택합니다.
  - 오른쪽 위 모서리에서 **전체 페이지로 열기** ({{< icon name="maximize" >}})을 선택합니다.

작업 항목을 항상 전체 페이지 보기에서 열려면 [항목을 드로어에서 열지 여부의 선호도 설정](../../work_items/_index.md#configure-list-display-preferences)을 참조하세요.

## 에픽 목록 필터링 {#filter-a-list-of-epics}

{{< history >}}

- 사용자 지정 필드에 의한 필터링이 GitLab 17.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/525462)되었습니다.

{{< /history >}}

다음을 기준으로 에픽 목록을 필터링할 수 있습니다:

- 제목 또는 설명(**내부 검색** 선택)
- 작성자 이름 / 사용자명
- 기밀성
- 그룹
- 헬스
- 레이블
- 마일스톤
- 반응 이모지
- 부모
- 구독됨
- 에픽에 사용 가능한 [사용자 지정 필드](../../work_items/custom_fields.md)

필터링하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음 **유형** = **에픽**으로 필터링합니다.
1. 필요에 따라 추가 필터, 연산자 및 값을 선택합니다. 제목 또는 설명으로 검색하려면 필터 표시줄에 입력합니다.
1. <kbd>Enter</kbd> 키를 누르거나 돋보기({{< icon name="search" >}})를 선택합니다.

### OR 연산자를 사용하여 필터링 {#filter-with-the-or-operator}

{{< history >}}

- 레이블 및 작성자에 대한 OR 필터링이 GitLab 15.9에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/382969)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `or_issuable_queries` 이름이 지정되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 15.9에서 [GitLab.com 및 GitLab Self-Managed에서 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/104292)합니다.
- GitLab 17.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/296031)합니다. 기능 플래그 `or_issuable_queries`이 제거되었습니다.

{{< /history >}}

다음을 기준으로 [에픽 목록 필터링](#filter-a-list-of-epics) 시 OR 연산자(**다음 중 하나: `||`**)를 사용할 수 있습니다:

- 담당자
- 작성자
- 레이블

`is one of`는 포함 OR을 나타냅니다. 예를 들어 `Label is one of Deliverable` 및 `Label is one of UX`으로 필터링하면 GitLab은 `Deliverable`, `UX` 또는 둘 다인 에픽을 표시합니다.

## 에픽 목록 정렬 {#sort-the-list-of-epics}

다음을 기준으로 에픽 목록을 정렬할 수 있습니다:

- 생성 날짜
- 업데이트 날짜
- 종료 날짜
- 마일스톤 마감 날짜
- 마감일
- 인기도
- 제목
- 시작 날짜
- 헬스
- 차단

각 옵션에는 **오름차순** 및 **내림차순** 간의 순서를 전환할 수 있는 버튼이 포함되어 있습니다. 정렬 옵션 및 순서는 저장되며 [로드맵](../roadmap/_index.md)을 포함하여 에픽을 탐색하는 모든 위치에서 사용됩니다.

## 활동 정렬 순서 변경 {#change-activity-sort-order}

기본 순서를 반대로 하고 상단의 가장 최근 항목으로 정렬된 활동 피드와 상호 작용할 수 있습니다. 선호도는 로컬 저장소에 저장되며 보는 모든 에픽 및 이슈에 자동으로 적용됩니다.

활동 정렬 순서를 변경하려면 **가장 오래된 것부터** 드롭다운 목록을 선택하고 먼저 표시할 가장 오래된 항목 또는 최신 항목을 선택합니다.

## 에픽을 기밀로 만들기 {#make-an-epic-confidential}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

개인 정보가 포함된 항목을 작업하는 경우 에픽을 기밀로 만들 수 있습니다.

> [!note]
> 기밀 에픽은 [기밀 이슈](../../project/issues/confidential_issues.md) 및 기밀 하위 에픽만 포함할 수 있습니다. 그러나 병합 요청은 공개 프로젝트에서 생성된 경우 공개입니다. 기밀 병합 요청을 생성하려면 [기밀 이슈에 대한 병합 요청](../../project/merge_requests/confidential.md)을 참조하세요.

사전 요구 사항:

- 에픽의 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

에픽을 기밀로 만들려면:

- **에픽을 생성할 때**: **비공개 활성화** 옆의 확인란을 선택합니다.
- **기존 에픽**: 오른쪽 위 모서리에서 **추가 작업** ({{< icon name="ellipsis_v" >}})을 선택합니다. 그런 다음 **비공개 활성화**를 선택합니다.

[`/confidential` 빠른 작업](../../project/quick_actions.md#confidential)을 사용할 수도 있습니다.

## 에픽에 할당된 이슈 관리 {#manage-issues-assigned-to-an-epic}

이 섹션은 에픽과 관련하여 [이슈](../../project/issues/_index.md)로 수행할 수 있는 모든 작업에 대한 지침을 수집합니다.

### 헬스 체크 상태 {#health-status}

{{< details >}}

- 티어: Ultimate

{{< /details >}}

{{< history >}}

- GitLab 17.5에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/9002)되었습니다.

{{< /history >}}

에픽에서 헬스 체크 상태를 사용하여 프로젝트 진행 상황을 신속하게 파악할 수 있습니다. 헬스 체크 상태는 잠재적 문제를 사전에 소통하고 관리하는 데 도움이 됩니다.

에픽 보기 및 **하위 항목** 및 **링크된 항목** 섹션에서 에픽의 헬스 체크 상태를 볼 수 있습니다.

헬스 체크 상태를 다음으로 설정할 수 있습니다:

- 진행 중(녹색)
- 주의 필요(황색)
- 위험(빨강색)

계획된 작업의 적시 배달 위험을 해결하려면 에픽 헬스 체크 상태 검토를 다음에 통합합니다:

- 일일 스탠드업 회의
- 프로젝트 상태 보고서
- 주간 회의

#### 에픽의 헬스 체크 상태 변경 {#change-health-status-of-an-epic}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

에픽의 헬스 체크 상태를 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음 **유형** = **에픽**으로 필터링합니다.
1. 에픽을 선택합니다.
1. 오른쪽 사이드바의 **헬스 체크 상태** 섹션에서 **편집**을 선택합니다.
1. 드롭다운 목록에서 상태를 선택합니다.

에픽의 헬스 체크 상태가 업데이트됩니다.

[`/health_status`](../../project/quick_actions.md#health_status) 및 [`/clear_health_status`](../../project/quick_actions.md#clear_health_status) 빠른 작업을 사용하여 헬스 체크 상태를 설정하고 지울 수도 있습니다.

### 참여자 {#participants}

참여자는 에픽과 상호 작용한 사용자입니다. 참여자를 보는 방법에 대한 정보는 [참여자](../../participants.md)를 참조하세요.

## 관련 항목 {#related-topics}

- [연결된 항목](../../work_items/linked_items.md)
- [하위 항목](../../work_items/child_items.md)
- [가중치](../../work_items/weight.md)
