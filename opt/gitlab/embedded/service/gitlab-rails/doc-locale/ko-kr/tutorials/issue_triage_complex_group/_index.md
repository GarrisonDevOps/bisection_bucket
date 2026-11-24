---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "그룹의 하위그룹과 프로젝트 전체에서 범위 지정 레이블과 이슈 보드를 설정하여 유형, 심각도 및 우선 순위로 이슈를 분류합니다."
title: '자습서: 이슈 분류를 위한 하위그룹을 포함한 복잡한 그룹 설정'
---

<!-- vale gitlab_base.FutureTense = NO -->

이슈 분류는 유형과 심각도에 따라 분류하는 프로세스입니다. 프로젝트가 성장하고 사람들이 더 많은 이슈를 생성할수록 들어오는 이슈를 분류하는 방법에 대한 워크플로우를 만들 가치가 있습니다.

이 튜토리얼에서는 이 시나리오를 위해 하위그룹을 포함한 GitLab 그룹을 설정하는 방법을 배웁니다.

이슈 분류를 위해 하위그룹이 있는 복잡한 그룹에 대해 GitLab을 설정하려면:

1. [그룹 만들기](#create-a-group)
1. [그룹 내 하위그룹 만들기](#create-subgroups-inside-a-group)
1. [하위그룹 내 프로젝트 만들기](#create-projects-inside-subgroups)
1. [유형, 심각도, 우선 순위에 대한 기준 결정](#decide-on-the-criteria-for-types-severity-and-priority)
1. [기준 문서화](#document-your-criteria)
1. [범위 지정 레이블 만들기](#create-scoped-labels)
1. [새 라벨 우선 순위 지정](#prioritize-the-new-labels)
1. [상위 그룹 이슈 분류 보드 만들기](#create-a-parent-group-issue-triage-board)
1. [기능에 대한 이슈 만들기](#create-issues-for-features)

## 시작하기 전에 {#before-you-begin}

- 이 튜토리얼을 위해 기존 프로젝트를 사용하는 경우 프로젝트에 대해 리포터, 개발자, 유지보수자 또는 소유자 역할이 있는지 확인하세요.
  - 기존 프로젝트에 부모 그룹이 없으면 그룹을 만들고 [프로젝트 라벨을 그룹 라벨로 승격](../../user/project/labels.md#promote-a-project-label-to-a-group-label)합니다.

## 그룹 만들기 {#create-a-group}

[그룹](../../user/group/_index.md)은 본질적으로 여러 프로젝트의 컨테이너입니다. 그룹을 사용하면 여러 프로젝트를 관리하고 그룹 구성원과 한 번에 소통할 수 있습니다.

새 그룹을 만들려면:

1. 오른쪽 상단 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 를 선택한 다음 **새 그룹**을 선택하세요.
1. **그룹 생성**를 선택하세요.
1. 그룹 세부 정보를 입력하세요:
   - **그룹 이름**에 `Web App Dev`을(를) 입력하거나 다른 값을 입력하세요.
1. 페이지 하단에서 **그룹 생성**를 선택하세요.

## 그룹 내 하위그룹 만들기 {#create-subgroups-inside-a-group}

[하위그룹](../../user/group/subgroups/_index.md)은 그룹 내의 그룹입니다. 하위그룹은 대규모 프로젝트를 구성하고 권한을 관리하는 데 도움이 됩니다.

새 하위그룹을 만들려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 **Web App Dev** 그룹을 찾으세요.
1. **새로 만들기** ({{< icon name="plus" >}}) 를 선택하고 **새 하위 그룹**을 선택하세요.
1. 하위그룹 세부 정보를 입력하세요:
   - **하위 그룹 이름**에 `Frontend`을(를) 입력하거나 다른 값을 입력하세요.
1. **하위그룹 생성**을 선택하세요.
1. 이 프로세스를 반복하여 `Backend` 또는 다른 값으로 명명된 두 번째 하위그룹을 만드세요.

## 하위그룹 내 프로젝트 만들기 {#create-projects-inside-subgroups}

여러 프로젝트 간에 이슈 추적을 관리하려면 하위그룹에서 프로젝트를 만들어야 합니다.

새 프로젝트를 만들려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `Frontend` 하위그룹을 찾으세요.
1. 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 를 선택하고 **새 프로젝트/리포지토리**를 선택하세요.
1. **빈 프로젝트 생성**을 선택하세요.
1. 프로젝트 세부 정보를 입력하세요:
   - **프로젝트 이름**에 `Web UI`을 입력하세요. 자세한 내용은 프로젝트 [이름 규칙](../../user/reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs)을 참조하세요.
1. 페이지 하단에서 **프로젝트 생성**을 선택하세요.
1. 이 프로세스를 반복하여 `Accessibility Audit` 프로젝트를 `Frontend` 하위그룹에 만들고 `API` 프로젝트를 `Backend` 하위그룹에 만드세요.

## 유형, 심각도, 우선 순위에 대한 기준 결정 {#decide-on-the-criteria-for-types-severity-and-priority}

다음으로 다음을 결정해야 합니다:

- 인식하려는 이슈의 **유형**입니다. 더 세분화된 접근 방식이 필요한 경우 각 유형에 대한 하위 유형을 만들 수도 있습니다. 유형은 팀에 요청되는 작업의 종류를 이해하기 위해 작업을 분류하는 데 도움이 됩니다.
- 들어오는 작업이 최종 사용자에게 미치는 영향을 정의하고 우선 순위 지정을 지원하기 위한 **우선 순위**와 **심각도**의 수준입니다.

이 튜토리얼에서는 다음을 결정했다고 가정하세요:

- 유형: `Bug`, `Feature`, 및 `Maintenance`
- 우선 순위: `1`, `2`, `3`, 및 `4`
- 심각도: `1`, `2`, `3`, 및 `4`

영감을 얻기 위해 GitLab에서 이를 정의하는 방법을 참조하세요:

- [유형 및 하위 유형](https://handbook.gitlab.com/handbook/engineering/metrics/#work-type-classification)
- [우선 순위](https://handbook.gitlab.com/handbook/product-development/how-we-work/issue-triage/#priority)
- [심각도](https://handbook.gitlab.com/handbook/product-development/how-we-work/issue-triage/#severity)

## 기준 문서화 {#document-your-criteria}

모든 기준에 동의한 후 팀원들이 항상 접근할 수 있는 곳에 기록해 두세요.

예를 들어 프로젝트의 [위키](../../user/project/wiki/_index.md)에 추가하거나 [GitLab Pages](../../user/project/pages/_index.md)로 발행된 회사 핸드북에 추가하세요.

<!-- Idea for expanding this tutorial:
     Add steps for [creating a wiki page](../../user/project/wiki/_index.md#create-a-new-wiki-page). -->

## 범위 지정 레이블 만들기 {#create-scoped-labels}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

다음으로 이슈를 분류하기 위해 추가할 라벨을 만듭니다.

이를 위한 최고의 도구는 [범위 지정 레이블](../../user/project/labels.md#scoped-labels)이며, 이를 사용하여 상호 배타적 특성을 설정할 수 있습니다.

[이전에](#decide-on-the-criteria-for-types-severity-and-priority) 수집한 유형, 심각도 및 우선 순위 목록을 확인하면서 일치하는 범위 지정 레이블을 만들고 싶을 것입니다.

범위 지정 레이블의 이름에 있는 이중 콜론(`::`) 은 같은 범위의 두 라벨이 함께 사용되지 않도록 방지합니다. 예를 들어 이미 `type::bug`을 가지고 있는 이슈에 `type::feature` 라벨을 추가하면 이전 라벨이 제거됩니다.

> [!note]
> 범위 지정 레이블은 Premium 및 Ultimate 티어에서 사용할 수 있습니다. Free 티어를 사용하는 경우 대신 일반 라벨을 사용할 수 있습니다. 그러나 상호 배타적이지 않습니다.

모든 하위그룹의 모든 프로젝트에서 레이블을 사용할 수 있도록 하려면 먼저 하위그룹을 포함하는 상위 그룹으로 이동합니다. 특정 하위그룹의 프로젝트에만 레이블을 사용할 수 있도록 하려면 하위그룹 내에서 이 단계를 따르세요.

각 라벨을 만들려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 **Web App Dev** 그룹을 찾으세요.
1. **관리** > **라벨**을 선택하세요.
1. **새 라벨**을 선택하세요.
1. **제목** 텍스트 상자에 라벨의 이름을 입력하세요. `type::bug`부터 시작하세요.
1. 선택사항. 사용 가능한 색상에서 색상을 선택하거나 **배경 색** 텍스트 상자에 특정 색상에 대한 16진수 색상 값을 입력하세요.
1. **라벨 생성**을 선택하세요.

필요한 모든 라벨을 만들려면 3-6단계를 반복하세요. 다음은 몇 가지 예입니다:

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

## 새 라벨 우선 순위 지정 {#prioritize-the-new-labels}

이제 새 라벨을 우선 순위 라벨로 설정하세요. 이렇게 하면 우선 순위 또는 라벨 우선 순위로 정렬하는 경우 가장 중요한 이슈가 이슈 목록의 맨 위에 표시되도록 합니다.

우선 순위 또는 라벨 우선 순위로 정렬할 때 어떤 일이 발생하는지 알아보려면 [이슈 목록 정렬 및 순서 지정](../../user/project/issues/sorting_issue_lists.md)을 참조하세요.

라벨의 우선 순위를 지정하려면:

1. 라벨 페이지의 우선 순위를 지정하려는 라벨 옆에서 **우선 순위**({{< icon name="star-o" >}}) 를 선택하세요. 이 라벨은 이제 라벨 목록의 맨 위에 표시되며 **우선 순위 라벨** 아래에 표시됩니다.
1. 이 라벨의 상대적 우선 순위를 변경하려면 목록에서 위아래로 드래그하세요. 목록에서 더 높은 라벨이 더 높은 우선 순위를 얻습니다.
1. 이전에 만든 모든 라벨의 우선 순위를 지정하세요. 더 높은 우선 순위 및 심각도의 라벨이 더 낮은 값의 라벨보다 목록에서 더 높은 위치에 있는지 확인하세요.

![11개의 우선 순위 범위 지정 레이블 목록입니다.](img/priority_labels_v16_3.png)

## 상위 그룹 이슈 분류 보드 만들기 {#create-a-parent-group-issue-triage-board}

들어오는 이슈 백로그를 준비하려면 이슈를 라벨로 정리하는 [이슈 보드](../../user/project/issue_board.md)를 만드세요. 이를 사용하여 카드를 다양한 목록으로 드래그하여 이슈를 빠르게 만들고 라벨을 추가할 수 있습니다.

이슈 보드를 설정하려면:

1. 보드의 범위를 결정하세요. 예를 들어 [그룹 이슈 보드](../../user/project/issue_board.md#group-issue-boards)를 만들어 이슈에 심각도를 할당하세요.
1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 **Web App Dev** 그룹을 찾으세요.
1. **계획** > **이슈 보드**를 선택하세요.
1. 이슈 보드 페이지의 왼쪽 상단 모서리에서 현재 보드 이름이 있는 드롭다운 목록을 선택하세요.
1. **새 보드 생성**을 선택하세요.
1. **제목** 텍스트 상자에 `Issue triage (by severity)`을 입력하세요.
1. **열린 목록 표시** 확인란을 선택한 상태로 유지하고 **닫힌 목록 표시**를 선택 해제합니다.
1. **보드 생성**을 선택하세요. 빈 보드가 표시됩니다.
1. `severity::1` 라벨에 대한 목록을 만드세요:
   1. 이슈 보드 페이지의 오른쪽 상단 모서리에서 **목록 생성**을 선택하세요.
   1. 표시되는 열에서 **값** 드롭다운 목록을 선택하고 `severity::1` 라벨을 선택하세요.
   1. 목록 하단에서 **보드에 추가**를 선택하세요.
1. `severity::2`, `severity::3`, 및 `severity::4` 라벨에 대해 이전 단계를 반복하세요.

하위그룹 이슈 보드를 만들려면 하위그룹 내부에서 3-10단계를 따르세요.

지금은 보드의 목록이 비어 있어야 합니다. 다음으로 이를 몇 가지 이슈로 채우겠습니다.

## 기능에 대한 이슈 만들기 {#create-issues-for-features}

예정된 기능과 버그를 추적하려면 몇 가지 이슈를 만들어야 합니다. 이슈는 프로젝트에 속하지만 그룹 이슈 보드에서 직접 만들 수도 있습니다.

계획된 기능에 대한 몇 가지 이슈를 먼저 만드세요. 버그는 발견할 때마다 만들 수 있습니다(너무 많지 않기를 바랍니다!).

**이슈 분류(심각도별)** 보드에서 이슈를 만들려면:

1. **열기** 목록으로 이동하세요. 이 목록은 다른 보드 목록에 맞지 않는 이슈를 표시합니다. 이미 이슈가 어떤 심각도 라벨을 가져야 하는지 알고 있다면 해당 라벨의 목록에서 직접 만들 수 있습니다. 라벨 목록에서 만든 각 이슈에 해당 라벨이 지정된다는 점을 명심하세요.

   지금은 **열기** 목록을 진행하세요.
1. **열기** 목록에서 **새 이슈 생성** 아이콘({{< icon name="plus" >}}) 을 선택하세요.
1. 필드를 완성합니다:
   - **제목** 아래에 `Dark mode toggle`을 입력하세요.
   - 이 이슈가 적용되는 프로젝트를 선택하세요. 이 예제는 `Frontend / Web UI`을 사용합니다.
1. **이슈 만들기**를 선택합니다.
1. 몇 가지 이슈를 더 만들려면 이 단계를 반복하세요.

   예를 들어 Web API 앱을 빌드하는 경우 `Frontend` 및 `Backend`은(는) 다양한 엔지니어링 팀을 나타냅니다. 프로젝트는 스택 개발의 다양한 측면을 나타냅니다. 다음 이슈를 만들고 필요에 따라 프로젝트에 할당하세요:

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

> [!note]
> 한 프로젝트의 이슈 보드에 있는 이슈는 다른 프로젝트의 이슈 보드에서 볼 수 없습니다. 마찬가지로 한 하위그룹의 프로젝트에 있는 이슈는 해당 하위그룹의 이슈 보드에서만 볼 수 있습니다. 상위 그룹의 모든 프로젝트에서 모든 이슈를 보려면 상위 그룹의 이슈 보드에 있어야 합니다.

첫 번째 분류 이슈 보드가 준비되었습니다! **열기** 목록에서 일부 이슈를 라벨 목록 중 하나로 드래그하여 심각도 라벨 중 하나를 추가해 봅시다.

![레이블이 없는 이슈 및 이슈 레이블 지정을 위한 우선 순위 "심각도" 레이블이 있는 이슈 보드입니다.](img/triage_board_v16_3.png)

## 다음 단계 {#next-steps}

다음으로 다음을 할 수 있습니다:

- 이슈 보드를 사용하는 방식을 조정하세요. 일부 옵션은 다음과 같습니다:
  - 현재 이슈 보드를 편집하여 우선 순위 및 유형 라벨에 대한 목록을 추가하세요. 이렇게 하면 보드가 더 넓어지고 일부 수평 스크롤이 필요할 수 있습니다.
  - `Issue triage (by priority)` 및 `Issue triage (by type)`이라는 별도의 이슈 보드를 만드세요. 이렇게 하면 다양한 유형의 분류 작업을 분리할 수 있지만 보드 간에 전환해야 합니다.
  - [팀 전환을 위한 이슈 보드 설정](../boards_for_teams/_index.md)합니다.
- 이슈 목록에서 우선 순위 또는 심각도별로 이슈를 찾고 [각 라벨로 필터링](../../user/project/issues/managing_issues.md#filter-the-list-of-issues)하세요. 가능한 경우 ["다음 중 하나" 필터 연산자](../../user/project/issues/managing_issues.md#filter-the-list-of-issues)를 사용하세요.
- 이슈를 [작업](../../user/tasks.md)으로 분류하세요.
- [`gitlab-triage` gem](https://gitlab.com/gitlab-org/ruby/gems/gitlab-triage)을 사용하여 프로젝트에서 이슈 분류를 자동화하는 데 도움이 되는 정책을 만듭니다. 다음과 같은 히트맵으로 요약 보고서를 생성하세요:

  !["우선 순위" 및 "심각도" 라벨이 있는 이슈의 대각선 히트맵입니다.](img/triage_report_v16_3.png)

GitLab에서의 이슈 분류에 대해 자세히 알아보려면 [이슈 분류](https://handbook.gitlab.com/handbook/product-development/how-we-work/issue-triage/) 및 [분류 작업](https://handbook.gitlab.com/handbook/engineering/infrastructure-platforms/developer-experience/triage-operations/)을 참조하세요.
