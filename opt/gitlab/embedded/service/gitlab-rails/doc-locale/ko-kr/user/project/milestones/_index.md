---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 마일스톤
description: "번다운 차트, 목표, 진행 상황 추적 및 릴리스."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

마일스톤은 GitLab에서 작업을 추적하고 정리하는 데 도움이 됩니다. 마일스톤:

- 관련 이슈, 에픽, 머지 리퀘스트를 그룹화하여 목표를 향한 진행 상황을 추적합니다.
- 선택적 시작 날짜 및 마감 날짜를 포함한 시간 기반 계획을 지원합니다.
- 반복과 함께 작동하여 동시에 실행되는 타임박스를 추적합니다.
- 릴리스를 추적하고 릴리스 증거를 생성합니다.
- 프로젝트 및 그룹에 적용됩니다.

마일스톤은 [프로젝트](../_index.md) 또는 [그룹](../../group/_index.md)에 속할 수 있습니다. 프로젝트 마일스톤은 해당 프로젝트의 이슈 및 머지 리퀘스트에만 적용됩니다. 그룹 마일스톤은 해당 그룹의 프로젝트에서 모든 이슈, 에픽 또는 머지 리퀘스트에 적용됩니다.

프로젝트 및 그룹 마일스톤 API에 대한 정보는 다음을 참조하십시오:

- [프로젝트 마일스톤 API](../../../api/milestones.md)
- [그룹 마일스톤 API](../../../api/group_milestones.md)

## 릴리스로서의 마일스톤 {#milestones-as-releases}

마일스톤을 사용하여 릴리스를 추적할 수 있습니다. 방법은 다음과 같습니다:

1. 마일스톤 마감 날짜를 설정하여 릴리스의 릴리스 날짜를 나타냅니다. 릴리스 주기에 정의된 시작 날짜가 없으면 마일스톤 시작 날짜를 공백으로 둘 수 있습니다.
1. 마일스톤 제목을 `Version 9.4`과 같은 릴리스의 버전으로 설정합니다.
1. 이슈의 우측 사이드바에서 마일스톤을 선택하여 릴리스에 이슈를 추가합니다.

또한 릴리스를 생성할 때 릴리스 증거를 자동으로 생성하려면 마일스톤을 [릴리스 기능](../releases/_index.md#associate-milestones-with-a-release)과 통합합니다.

## 프로젝트 마일스톤 및 그룹 마일스톤 {#project-milestones-and-group-milestones}

마일스톤은 [프로젝트](../_index.md) 또는 [그룹](../../group/_index.md)에 속할 수 있습니다.

**프로젝트 마일스톤**을 해당 프로젝트의 이슈 또는 머지 리퀘스트에만 할당할 수 있습니다. **그룹 마일스톤**을 해당 그룹의 모든 프로젝트에서 모든 이슈, 에픽 또는 머지 리퀘스트에 할당할 수 있습니다.

프로젝트 및 그룹 마일스톤 API에 대한 정보는 다음을 참조하십시오:

- [프로젝트 마일스톤 API](../../../api/milestones.md)
- [그룹 마일스톤 API](../../../api/group_milestones.md)

### 프로젝트 또는 그룹 마일스톤 보기 {#view-project-or-group-milestones}

마일스톤 목록을 보려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **마일스톤**을 선택합니다.

프로젝트에서 GitLab은 프로젝트에 속하는 마일스톤을 표시합니다. 그룹에서 GitLab은 그룹 및 그룹의 모든 프로젝트와 하위 그룹에 속하는 마일스톤을 표시합니다.

### 이슈가 비활성화된 프로젝트에서 마일스톤 보기 {#view-milestones-in-a-project-with-issues-turned-off}

프로젝트에서 이슈 추적이 [비활성화](../settings/_index.md#configure-project-features-and-permissions)되어 있으면 마일스톤 페이지로 이동하려면 해당 URL을 입력합니다.

방법은 다음과 같습니다:

1. 프로젝트로 이동합니다.
1. 프로젝트 URL에 `/-/milestones`을 추가합니다. 예: `https://gitlab.com/gitlab-org/sample-data-templates/sample-gitlab-project/-/milestones`.

또는 이 프로젝트의 이슈가 그룹의 마일스톤 페이지에 표시됩니다.

이 경험을 개선하는 것은 [이슈 339009](https://gitlab.com/gitlab-org/gitlab/-/issues/339009)에서 추적됩니다.

### 모든 마일스톤 보기 {#view-all-milestones}

전체 GitLab 네임스페이스에서 액세스 권한이 있는 모든 마일스톤을 볼 수 있습니다. 자신이 속하지 않은 프로젝트 또는 그룹의 일부 마일스톤은 볼 수 없을 수 있습니다.

방법은 다음과 같습니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
1. **귀하의 작업**을 선택합니다.
1. 왼쪽 사이드바에서 **마일스톤**을 선택합니다.

### 마일스톤 상세 정보 보기 {#view-milestone-details}

**마일스톤** 페이지에서 마일스톤에 대한 자세한 정보를 보려면 보려는 마일스톤의 제목을 선택합니다.

마일스톤 보기는 제목 및 설명을 표시합니다. 제목 및 설명 아래의 탭은 다음을 표시합니다:

- **작업 항목**: 마일스톤에 할당된 모든 작업 항목을 표시합니다. 작업 항목은 세 개의 열에 표시됩니다:
  - 미시작된 이슈(열림 및 미할당)
  - 진행 중인 이슈(열림 및 할당됨)
  - 완료된 이슈(닫힘)
- **머지 리퀘스트**: 마일스톤에 할당된 모든 머지 리퀘스트를 표시합니다. 머지 리퀘스트는 네 개의 열에 표시됩니다:
  - 진행 중(열림 및 미할당)
  - 병합 대기 중(열림 및 할당됨)
  - 거부됨(닫힘)
  - 병합됨
- **참가자**: 마일스톤에 할당된 이슈의 모든 담당자를 표시합니다.
- **라벨**: 마일스톤에 할당된 이슈에서 사용되는 모든 라벨을 표시합니다.

#### 번다운 차트 {#burndown-charts}

마일스톤 보기는 [번다운 및 번업 차트](burndown_and_burnup_charts.md)를 포함하며 마일스톤 완료 진행 상황을 표시합니다.

![시간 경과에 따른 프로젝트 진행 상황을 보여주는 번다운 및 번업 차트입니다.](img/burndown_and_burnup_charts_v15_3.png)

#### 마일스톤 사이드바 {#milestone-sidebar}

마일스톤 보기의 사이드바는 다음을 표시합니다:

- 완료된 작업 항목의 수를 전체 작업 항목 수로 나눈 값으로 계산되는 완료 백분율입니다.
- 시작 날짜 및 마감 날짜입니다.
- 마일스톤에 할당된 모든 작업 항목 및 머지 리퀘스트에 소비된 총 시간입니다.
- 마일스톤에 할당된 모든 작업 항목의 총 이슈 가중치입니다.
- 총, 열림, 닫힘 및 병합된 머지 리퀘스트의 개수입니다.
- 관련된 릴리스에 대한 링크입니다.
- 클립보드에 복사할 수 있는 마일스톤의 참조입니다.

![마일스톤 목록과 진행 상황 및 마감 날짜를 표시하는 프로젝트 마일스톤 페이지입니다.](img/milestones_project_milestone_page_sidebar_v13_11.png)

## 마일스톤 생성 {#create-a-milestone}

{{< history >}}

- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) \- GitLab 17.7에서 최소 사용자 역할이 Reporter에서 Planner로 변경되었습니다.
- [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/195530)됨 - 마일스톤을 GitLab 18.2의 에픽 작업 항목에 도입했습니다.

{{< /history >}}

프로젝트 또는 그룹에서 마일스톤을 생성할 수 있습니다.

사전 요구 사항:

- 마일스톤이 속한 프로젝트 또는 그룹에 대해 플래너, Reporter, Developer, Maintainer 또는 Owner 역할이 있어야 합니다.

마일스톤을 생성하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **마일스톤**을 선택합니다.
1. **새 마일스톤**을 선택합니다.
1. 제목을 입력합니다.
1. 선택 사항. 설명, 시작 날짜 및 마감 날짜를 입력합니다.
1. **새 마일스톤**을 선택합니다.

![제목, 설명, 시작 날짜 및 마감 날짜 필드가 있는 새 마일스톤을 만드는 양식입니다.](img/milestones_new_project_milestone_v16_11.png)

### 마일스톤 제목 규칙 {#milestone-title-rules}

그룹 계층 구조에서 혼동을 피하기 위해 중복된 마일스톤 제목은 허용되지 않습니다.

- **프로젝트 마일스톤**의 경우 제목은 프로젝트의 상위 계층 구조에서 프로젝트 및 마일스톤 제목 모두에 대해 고유해야 합니다.
- **그룹 마일스톤**의 경우 제목은 상위 항목과 하위 항목을 포함하여 그룹 계층 구조 내에서 고유해야 하며 그룹 및 프로젝트 마일스톤을 포함합니다.

## 마일스톤 편집 {#edit-a-milestone}

{{< history >}}

- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) \- GitLab 17.7에서 최소 사용자 역할이 Reporter에서 Planner로 변경되었습니다.

{{< /history >}}

사전 요구 사항:

- 마일스톤이 속한 프로젝트 또는 그룹에 대해 플래너, Reporter, Developer, Maintainer 또는 Owner 역할이 있어야 합니다.

마일스톤을 편집하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **마일스톤**을 선택합니다.
1. 마일스톤의 제목을 선택합니다.
1. 우측 상단에서 **마일스톤 동작**({{< icon name="ellipsis_v" >}}) 다음 **편집**을 선택합니다.
1. 제목, 시작 날짜, 마감 날짜 또는 설명을 편집합니다.
1. **변경 사항 저장**을 선택합니다.

## 마일스톤 닫기 {#close-a-milestone}

{{< history >}}

- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) \- GitLab 17.7에서 최소 사용자 역할이 Reporter에서 Planner로 변경되었습니다.

{{< /history >}}

마일스톤은 마감 날짜 이후에 닫힙니다. 마일스톤을 수동으로 닫을 수도 있습니다.

마일스톤이 닫혀도 열린 이슈는 열린 상태로 유지됩니다.

사전 요구 사항:

- 마일스톤이 속한 프로젝트 또는 그룹에 대해 플래너, Reporter, Developer, Maintainer 또는 Owner 역할이 있어야 합니다.

마일스톤을 닫으려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **마일스톤**을 선택합니다.
1. 다음 중 하나를 선택합니다.
   - 닫으려는 마일스톤 옆에서 **마일스톤 동작**({{< icon name="ellipsis_v" >}}) > **닫기**를 선택합니다.
   - 마일스톤 제목을 선택한 다음 **닫기**를 선택합니다.

## 마일스톤 삭제 {#delete-a-milestone}

{{< history >}}

- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) \- GitLab 17.7에서 최소 사용자 역할이 Reporter에서 Planner로 변경되었습니다.

{{< /history >}}

사전 요구 사항:

- 마일스톤이 속한 프로젝트 또는 그룹에 대해 플래너, Reporter, Developer, Maintainer 또는 Owner 역할이 있어야 합니다.

마일스톤을 삭제하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **마일스톤**을 선택합니다.
1. 다음 중 하나를 선택합니다.
   - 삭제하려는 마일스톤 옆에서 **마일스톤 동작**({{< icon name="ellipsis_v" >}}) > **삭제**를 선택합니다.
   - 마일스톤 제목을 선택한 다음 **마일스톤 동작**({{< icon name="ellipsis_v" >}}) > **삭제**를 선택합니다.
1. **마일스톤 삭제**를 선택합니다.

## 프로젝트 마일스톤을 그룹 마일스톤으로 승격 {#promote-a-project-milestone-to-a-group-milestone}

{{< history >}}

- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) \- GitLab 17.7에서 최소 사용자 역할이 Reporter에서 Planner로 변경되었습니다.

{{< /history >}}

그룹의 프로젝트 수를 확장하고 있다면 이 그룹의 프로젝트 간에 동일한 마일스톤을 공유할 수 있습니다. 프로젝트 마일스톤을 상위 그룹으로 승격하여 같은 그룹의 다른 프로젝트에서 사용할 수 있게 할 수 있습니다.

마일스톤을 승격하면 이 그룹의 모든 프로젝트에서 같은 이름의 모든 프로젝트 마일스톤을 단일 그룹 마일스톤으로 병합합니다. 이전에 이러한 프로젝트 마일스톤 중 하나에 할당된 모든 이슈 및 머지 리퀘스트는 새로운 그룹 마일스톤에 할당됩니다.

> [!warning]
> 이 작업은 되돌릴 수 없으며 변경 사항은 영구적입니다.

사전 요구 사항:

- 그룹에 대해 플래너, Reporter, Developer, Maintainer 또는 Owner 역할이 있어야 합니다.

프로젝트 마일스톤을 승격하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **마일스톤**을 선택합니다.
1. 다음 중 하나를 선택합니다.
   - 승격하려는 마일스톤 옆에서 **마일스톤 동작**({{< icon name="ellipsis_v" >}}) > **승급**을 선택합니다.
   - 마일스톤 제목을 선택한 다음 **마일스톤 동작**({{< icon name="ellipsis_v" >}}) > **승급**을 선택합니다.
1. **마일스톤 승격**을 선택합니다.

## 항목에 마일스톤 할당 {#assign-a-milestone-to-an-item}

{{< history >}}

- 마일스톤을 에픽에 할당하기는 GitLab 18.2에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/329)되었습니다.

{{< /history >}}

모든 이슈, 에픽 또는 머지 리퀘스트에는 하나의 마일스톤을 할당할 수 있습니다. 마일스톤은 모든 이슈 및 머지 리퀘스트 페이지의 우측 사이드바에 표시됩니다. 작업 항목 보드에서도 볼 수 있습니다.

마일스톤을 할당하거나 할당 해제하려면:

1. 이슈, 에픽 또는 머지 리퀘스트를 봅니다.
1. 우측 사이드바에서 **마일스톤** 옆에 **편집**을 선택합니다.
1. **마일스톤 할당** 목록에서 이름을 입력하여 마일스톤을 검색합니다. 프로젝트 및 그룹 마일스톤 모두에서 선택할 수 있습니다.
1. 할당하려는 마일스톤을 선택합니다.

마일스톤을 할당하거나 할당 해제하려면 다음을 수행할 수도 있습니다:

- 주석 또는 설명에서 [`/milestone` 빠른 작업](../quick_actions.md#milestone)을 사용합니다.
- 보드의 [마일스톤 목록](../issue_board.md#milestone-lists)으로 이슈를 드래그합니다.
- 이슈 목록에서 [대량 편집 이슈](../issues/managing_issues.md#bulk-edit-issues)를 수행합니다.

## 마일스톤별 이슈 및 머지 리퀘스트 필터링 {#filter-issues-and-merge-requests-by-milestone}

### 목록 페이지의 필터 {#filters-in-list-pages}

프로젝트 및 그룹 이슈/머지 리퀘스트 목록 페이지에서 그룹 및 프로젝트 마일스톤으로 필터링할 수 있습니다.

### 이슈 보드의 필터 {#filters-in-issue-boards}

[프로젝트 이슈 보드](../issue_board.md)에서 다음 항목에서 그룹 마일스톤 및 프로젝트 마일스톤으로 필터링할 수 있습니다:

- [검색 및 필터 표시줄](../issue_board.md#filter-issues)
- [이슈 보드 구성](../issue_board.md#configurable-issue-boards)

[그룹 이슈 보드](../issue_board.md#group-issue-boards)에서만 다음 항목에서 그룹 마일스톤으로 필터링할 수 있습니다:

- [검색 및 필터 표시줄](../issue_board.md#filter-issues)
- [이슈 보드 구성](../issue_board.md#configurable-issue-boards)

### 특별한 마일스톤 필터 {#special-milestone-filters}

{{< history >}}

- **시작됨** 및 **다음** 필터에 대한 논리가 GitLab 18.0에서 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/429728)되었습니다.

{{< /history >}}

마일스톤별로 필터링할 때 특정 프로젝트 마일스톤 또는 그룹 마일스톤을 선택하는 것 외에도 특별한 마일스톤 필터를 선택할 수 있습니다.

- **없음**: 할당된 마일스톤이 없는 이슈 또는 머지 리퀘스트를 표시합니다.
- **Any**: 할당된 마일스톤이 있는 이슈 또는 머지 리퀘스트를 표시합니다.
- **다음**: 미래에 시작하는 열린 할당된 마일스톤이 있는 이슈 또는 머지 리퀘스트를 표시합니다.
- **시작됨**: 현재 날짜와 겹치는 열린 할당된 마일스톤이 있는 이슈 또는 머지 리퀘스트를 표시합니다. 목록은 정의된 시작 및 마감 날짜가 없는 마일스톤을 제외합니다.
