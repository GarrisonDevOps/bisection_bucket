---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "범위 지정 레이블과 이슈 보드를 단일 프로젝트에서 설정하여 유형, 심각도, 우선 순위별로 이슈를 분류합니다."
title: '자습서: 이슈 분류 프로젝트 설정'
---

<!-- vale gitlab_base.FutureTense = NO -->

이슈 분류는 유형 및 심각도에 따른 분류 프로세스입니다. 프로젝트가 커지고 사람들이 더 많은 이슈를 생성하면서 들어오는 이슈를 분류하는 방법에 대한 워크플로를 만드는 것이 좋습니다.

이 자습서에서는 이를 위해 GitLab 프로젝트를 설정하는 방법을 배웁니다.

프로젝트에서 이슈 분류를 위해 GitLab을 설정하려면:

1. [프로젝트 생성](#create-a-project)
1. [유형, 심각도, 우선 순위의 기준 결정](#decide-on-the-criteria-for-types-severity-and-priority)
1. [기준 문서화](#document-your-criteria)
1. [범위 지정 레이블 생성](#create-scoped-labels)
1. [새 레이블 우선 순위 지정](#prioritize-the-new-labels)
1. [이슈 분류 보드 생성](#create-an-issue-triage-board)
1. [기능 이슈 생성](#create-issues-for-features)

## 시작하기 전에 {#before-you-begin}

- 이 튜토리얼을 위해 기존 프로젝트를 사용하는 경우 프로젝트에 대해 리포터, 개발자, 유지 관리자 또는 소유자 역할을 가지고 있는지 확인하세요.
- 아래 단계를 따르다가 나중에 프로젝트에 대한 상위 그룹을 생성하기로 결정한 경우 레이블을 최대한 활용하려면 프로젝트 레이블을 그룹 레이블로 승격해야 합니다. 먼저 그룹을 만드는 것을 고려하세요.

## 프로젝트 생성 {#create-a-project}

프로젝트에는 향후 코드 변경 사항을 계획하는 데 사용되는 이슈가 포함되어 있습니다.

이미 작업 중인 프로젝트가 있으면 [유형, 심각도, 우선 순위의 기준 결정](#decide-on-the-criteria-for-types-severity-and-priority)으로 진행하세요.

빈 프로젝트를 생성하려면:

1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. 프로젝트 세부 정보를 입력합니다.
   - **프로젝트 이름**의 경우 `Issue triage tutorial`을 입력합니다.
1. **프로젝트 생성**을 선택합니다.

## 유형, 심각도, 우선 순위의 기준 결정 {#decide-on-the-criteria-for-types-severity-and-priority}

다음으로 다음을 결정해야 합니다:

- 인식하려는 이슈의 **유형**입니다. 더 세분화된 접근이 필요하면 각 유형의 하위 유형도 만들 수 있습니다. 유형은 팀에서 요청하는 작업의 종류를 이해하기 위해 작업을 분류하는 데 도움이 됩니다.
- 들어오는 작업이 최종 사용자에게 미치는 영향을 정의하고 우선 순위 결정을 지원하기 위한 **우선 순위** 및 **심각도** 수준입니다.

이 자습서에서는 다음과 같이 결정했다고 가정합니다:

- 유형: `Bug`, `Feature`, `Maintenance`
- 우선 순위: `1`, `2`, `3`, `4`
- 심각도: `1`, `2`, `3`, `4`

영감을 얻으려면 GitLab에서 이들을 정의하는 방법을 참조하세요:

- [유형 및 하위 유형](https://handbook.gitlab.com/handbook/engineering/metrics/#work-type-classification)
- [우선 순위](https://handbook.gitlab.com/handbook/product-development/how-we-work/issue-triage/#priority)
- [심각도](https://handbook.gitlab.com/handbook/product-development/how-we-work/issue-triage/#severity)

## 기준 문서화 {#document-your-criteria}

모든 기준에 동의한 후 팀원들이 항상 접근할 수 있는 어딘가에 모든 것을 적어두세요.

예를 들어 프로젝트의 [wiki](../../user/project/wiki/_index.md)에 추가하거나 [GitLab Pages](../../user/project/pages/_index.md)로 발행한 회사 핸드북에 추가하세요.

<!-- Idea for expanding this tutorial:
     Add steps for [creating a wiki page](../../user/project/wiki/_index.md#create-a-new-wiki-page). -->

## 범위 지정 레이블 생성 {#create-scoped-labels}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

다음으로 이슈를 분류하기 위해 추가할 레이블을 만듭니다.

이를 위한 최고의 도구는 [범위 지정 레이블](../../user/project/labels.md#scoped-labels)로, 이를 사용하여 서로 배타적인 특성을 설정할 수 있습니다.

[이전에](#decide-on-the-criteria-for-types-severity-and-priority) 수집한 유형, 심각도, 우선 순위 목록을 확인하면서 일치하는 범위 지정 레이블을 만들고 싶을 것입니다.

범위 지정 레이블의 이름에서 이중 콜론(`::`)은 동일한 범위의 두 레이블이 함께 사용되는 것을 방지합니다. 예를 들어, 이미 `type::bug`이(가) 있는 이슈에 `type::feature` 레이블을 추가하면 이전 레이블이 제거됩니다.

> [!note]
> 범위 지정 레이블은 GitLab Premium 및 GitLab Ultimate 티어에서 사용할 수 있습니다. Free 티어를 사용하는 경우 대신 일반 레이블을 사용할 수 있습니다. 그러나 이들은 서로 배타적이지 않습니다.

각 레이블을 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **관리** > **라벨**을 선택합니다.
1. **새 라벨**을 선택합니다.
1. **제목** 텍스트 상자에 레이블의 이름을 입력합니다. `type::bug`으로 시작하세요.
1. 선택사항. 사용 가능한 색상에서 선택하여 색상을 선택하거나 **배경 색** 텍스트 상자에 특정 색상을 위한 16진수 색상 값을 입력하세요.
1. **라벨 생성**을 선택합니다.

필요한 모든 레이블을 생성하려면 이 단계를 반복합니다:

- `type::bug`
- `type::feature`
- `type::maintenance`
- `priority::1`
- `priority::2`
- `priority::3`
- `priority::4`
- `severity::1`
- `severity::2`
- `severity::3`
- `severity::4`

## 새 레이블 우선 순위 지정 {#prioritize-the-new-labels}

이제 새 레이블을 우선 순위 레이블로 설정하여 우선 순위 또는 레이블 우선 순위로 정렬할 때 가장 중요한 이슈가 이슈 목록의 맨 위에 표시되도록 합니다.

우선 순위 또는 레이블 우선 순위로 정렬할 때 발생하는 상황을 알아보려면 [이슈 목록 정렬 및 순서 지정](../../user/project/issues/sorting_issue_lists.md)을 참조하세요.

레이블의 우선 순위를 지정하려면:

1. 레이블 페이지에서 우선 순위를 지정하려는 레이블 옆에 별({{< icon name="star-o" >}})을 선택합니다. 이 레이블은 이제 **우선 순위 라벨** 아래 레이블 목록의 맨 위에 나타납니다.
1. 이 레이블의 상대적 우선 순위를 변경하려면 목록에서 위아래로 끌어옵니다. 목록에서 높을수록 우선 순위가 높습니다.
1. 이전에 만든 모든 레이블의 우선 순위를 지정합니다. 우선 순위 및 심각도가 높은 레이블이 낮은 값보다 목록에서 더 높은지 확인하세요.

![11개의 우선 순위 범위 지정 레이블 목록입니다.](img/priority_labels_v16_3.png)

## 이슈 분류 보드 생성 {#create-an-issue-triage-board}

들어오는 이슈 백로그를 준비하려면 레이블별로 이슈를 정리하는 [이슈 보드](../../user/project/issue_board.md)를 만듭니다. 이를 사용하여 카드를 다양한 목록으로 끌어서 이슈를 빠르게 생성하고 레이블을 추가할 수 있습니다.

이슈 보드를 설정하려면:

1. 보드의 범위를 결정합니다. 예를 들어 이슈에 심각도를 지정하는 데 사용할 보드를 만듭니다.
1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 **이슈 분류 자습서** 프로젝트를 찾습니다.
1. **계획** > **이슈 보드**를 선택합니다.
1. 이슈 보드 페이지의 왼쪽 위 모서리에서 현재 보드 이름이 있는 드롭다운 목록을 선택합니다.
1. **새 보드 생성**을 선택합니다.
1. **제목** 텍스트 상자에 `Issue triage (by severity)`을(를) 입력합니다.
1. **열린 목록 표시** 확인란을 선택한 상태로 유지하고 **닫힌 목록 표시**를 선택 해제합니다.
1. **보드 생성**을 선택합니다. 빈 보드가 표시되어야 합니다.
1. `severity::1` 레이블에 대한 목록을 생성합니다:
   1. 이슈 보드 페이지의 오른쪽 위 모서리에서 **목록 생성**을 선택합니다.
   1. 나타나는 열의 **값** 드롭다운 목록에서 `severity::1` 레이블을 선택합니다.
   1. **보드에 추가**를 선택합니다.
1. 레이블 `severity::2`, `severity::3`, `severity::4`에 대해 이전 단계를 반복합니다.

현재 보드의 목록은 비어 있어야 합니다. 다음으로, 일부 이슈로 채웁니다.

## 기능 이슈 생성 {#create-issues-for-features}

향후 기능 및 버그를 추적하려면 일부 이슈를 만들어야 합니다. 이슈는 프로젝트에 속하지만 이슈 보드에서 직접 만들 수도 있습니다.

계획된 기능에 대한 일부 이슈를 만들어 시작합니다. 발견한 대로 버그에 대한 이슈를 만들 수 있습니다(바라건대 너무 많지 않기를!).

**이슈 분류(심각도별)** 보드에서 이슈를 만들려면:

1. **열기** 목록에서 **새 이슈 생성**({{< icon name="plus" >}})을 선택합니다. **열기** 목록에는 다른 보드 목록에 맞지 않는 이슈가 표시됩니다.

   이슈가 어떤 심각도 레이블을 가져야 하는지 이미 알고 있으면 해당 레이블 목록에서 직접 만들 수 있습니다. 레이블 목록에서 만든 각 이슈에는 해당 레이블이 지정됩니다.
1. 필드를 완성합니다:
   - **제목** 아래에 `User registration`를 입력합니다.
1. **이슈 만들기**를 선택합니다.
1. 이 단계를 반복하여 더 많은 이슈를 만듭니다.

   예를 들어 앱을 만드는 경우 다음 이슈를 만듭니다:

   - `User registration`
   - `Profile creation`
   - `Search functionality`
   - `Add to favorites`
   - `Push notifications`
   - `Social sharing`
   - `In-app messaging`
   - `Track progress`
   - `Feedback and ratings`
   - `Settings and preferences`

첫 번째 분류 이슈 보드가 준비되었습니다! **열기** 목록에서 일부 이슈를 레이블 목록 중 하나로 끌어 심각도 레이블 중 하나를 추가해 보세요.

![레이블이 지정되지 않은 이슈와 이슈에 레이블을 지정하기 위한 우선 순위 "심각도" 레이블이 있는 이슈 보드입니다.](img/triage_board_v16_3.png)

## 다음 단계 {#next-steps}

다음으로, 다음을 수행할 수 있습니다:

- 이슈 보드 사용 방식을 조정합니다. 옵션에는 다음이 포함됩니다:
  - 현재 이슈 보드를 편집하여 우선 순위 및 유형 레이블의 목록도 있습니다. 이렇게 하면 보드가 더 넓어지고 가로 스크롤이 필요할 수 있습니다.
  - `Issue triage (by priority)` 및 `Issue triage (by type)`이라는 이름의 별도 이슈 보드를 만듭니다. 이렇게 하면 다양한 유형의 분류 작업을 분리된 상태로 유지하지만 보드 간 전환이 필요합니다.
  - [팀 인계를 위한 이슈 보드 설정](../boards_for_teams/_index.md)입니다.
- [각 레이블별로 필터링된](../../user/project/issues/managing_issues.md#filter-the-list-of-issues) 이슈 목록에서 우선 순위 또는 심각도별로 이슈를 탐색합니다. 가능하면 ["하나는" 필터 연산자](../../user/project/issues/managing_issues.md#filter-the-list-of-issues)를 활용하세요.
- 이슈를 [작업](../../user/tasks.md)으로 분류합니다.
- [`gitlab-triage` gem](https://gitlab.com/gitlab-org/ruby/gems/gitlab-triage)을(를) 사용하여 프로젝트에서 이슈 분류를 자동화하는 데 도움이 되는 정책을 만듭니다. 다음과 같은 히트맵으로 요약 보고서를 생성합니다:

  !["우선 순위" 및 "심각도" 레이블이 있는 이슈의 대각선 히트맵입니다.](img/triage_report_v16_3.png)

GitLab의 이슈 분류에 대해 자세히 알아보려면 [이슈 분류](https://handbook.gitlab.com/handbook/product-development/how-we-work/issue-triage/) 및 [분류 작업](https://handbook.gitlab.com/handbook/engineering/infrastructure-platforms/developer-experience/triage-operations/)을 참조하세요.
