---
stage: Plan
group: Planning Views
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 별도의 이슈 보드와 워크플로우 레이블을 구성하여 두 팀이 이슈를 순서대로 서로 전달할 수 있도록 하세요.
title: '자습서: 팀 핸드오프를 위한 이슈 보드 설정'
---

<!-- vale gitlab_base.FutureTense = NO -->

이 튜토리얼에서는 [이슈 보드](../../user/project/issue_board.md)와 [범위 지정 레이블](../../user/project/labels.md#scoped-labels)을 두 팀이 순서대로 이슈에서 작업하도록 설정하는 방법을 보여줍니다.

이 예제에서는 UX 팀과 Frontend 팀을 위한 두 개의 이슈 보드를 만듭니다. 다음 단계를 사용하여 Backend 또는 Quality Assurance와 같은 더 많은 하위 팀에 대한 이슈 보드와 워크플로우를 만들 수 있습니다.

여러 팀을 위한 이슈 보드를 설정하려면 다음을 수행하세요:

1. [그룹 만들기](#create-a-group)
1. [프로젝트 생성](#create-a-project)
1. [레이블 생성](#create-labels)
1. [팀 이슈 보드 생성](#create-team-issue-boards)
1. [기능 이슈 생성](#create-issues-for-features)

## 시작하기 전에 {#before-you-begin}

- 이 튜토리얼에 기존 그룹을 사용하는 경우 그룹에 대한 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 있는지 확인하세요.
- 이 튜토리얼에 기존 프로젝트를 사용하는 경우 프로젝트에 대한 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 있는지 확인하세요.

## 목표 워크플로우 {#the-goal-workflow}

모든 것을 설정한 후 두 팀은 한 보드에서 다른 보드로 이슈를 전달할 수 있습니다. 예를 들어 다음과 같이 진행됩니다:

1. 프로젝트 리드는 `Workflow::Ready for design` 및 `Frontend` 레이블을 **사용자 프로필 페이지 재설계**라는 기능 이슈에 추가합니다.
1. UX 팀의 제품 디자이너:
   1. `Workflow::Ready for design` 목록을 **UX 워크플로우** 보드에서 확인하고 프로필 페이지 재설계를 진행하기로 결정합니다.

      ![세 개의 워크플로우 열에 걸친 세 개의 이슈가 있는 "UX 워크플로우" 이슈 보드](img/ux_board_filled_v16_0.png)

   1. **사용자 프로필 페이지 재설계** 이슈에 자신을 할당합니다.
   1. 이슈 카드를 `Workflow::Design` 목록으로 드래그합니다. 이전 워크플로우 레이블이 자동으로 제거됩니다.
   1. ✨새 디자인✨을 만듭니다.
   1. [이슈에 디자인을 추가합니다](../../user/project/issues/design_management.md).
   1. 이슈 카드를 `Workflow::Ready for development` 목록으로 드래그하면 이 레이블이 추가되고 다른 모든 `Workflow::` 레이블이 제거됩니다.
   1. 이슈에서 자신을 할당 해제합니다.
1. Frontend 팀의 개발자:
   1. `Workflow::Ready for development` 목록을 **Frontend 워크플로우** 보드에서 확인하고 작업할 이슈를 선택합니다.

      !["UX 워크플로우" 보드에서 "개발 준비" 열의 "Frontend 워크플로우" 이슈 보드 두 개 이슈](img/frontend_board_filled_v16_0.png)

   1. **사용자 프로필 페이지 재설계** 이슈에 자신을 할당합니다.
   1. 이슈 카드를 `Workflow::In development` 목록으로 드래그합니다. 이전 워크플로우 레이블이 자동으로 제거됩니다.
   1. [머지 리퀘스트](../../user/project/merge_requests/_index.md)에서 프론트엔드 코드를 추가합니다.
   1. `Workflow::Complete` 레이블을 추가합니다.

## 그룹 생성 {#create-a-group}

프로젝트 성장에 대비하려면 그룹 만들기부터 시작하세요. 그룹을 사용하여 동시에 하나 이상의 관련 프로젝트를 관리합니다. 사용자를 그룹의 구성원으로 추가하고 역할을 할당합니다.

그룹을 만들려면 다음을 수행하세요:

1. 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 그룹**을 선택합니다.
1. **그룹 생성**를 선택합니다.
1. 필드를 완성합니다. 그룹 이름을 `Paperclip Software Factory`로 지정합니다.
1. **그룹 생성**를 선택합니다.

빈 그룹을 만들었습니다. 다음으로 이슈 및 코드를 저장할 프로젝트를 만듭니다.

## 프로젝트 생성 {#create-a-project}

주요 코드 개발 작업은 프로젝트 및 해당 리포지토리에서 이루어집니다. 프로젝트에는 코드 및 파이프라인뿐만 아니라 향후 코드 변경을 계획하는 데 사용되는 이슈가 포함됩니다.

빈 프로젝트를 생성하려면:

1. 그룹에서 오른쪽 위 모서리에 있는 **새로 만들기** ({{< icon name="plus" >}}) 및 **이 그룹에서** > **새 프로젝트/리포지토리**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. 프로젝트 세부 정보를 입력합니다:
   - **프로젝트 이름** 텍스트 상자에서 프로젝트 이름을 `Paperclip Assistant`로 지정합니다.
1. **프로젝트 생성**을 선택합니다.

## 레이블 생성 {#create-labels}

개발 주기에서 이슈가 어디에 있는지 표시하려면 팀 레이블과 일련의 워크플로우 레이블이 필요합니다.

`Paperclip Assistant` 프로젝트에서 이러한 레이블을 만들 수 있지만 `Paperclip Software Factory` 그룹에서 만드는 것이 더 좋습니다. 이렇게 하면 나중에 만드는 다른 모든 프로젝트에서도 이러한 레이블을 사용할 수 있습니다.

각 레이블을 생성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 **Paperclip Software Factory** 그룹을 찾습니다.
1. **관리** > **라벨**을 선택합니다.
1. **새 라벨**을 선택합니다.
1. **제목** 텍스트 상자에 레이블의 이름을 입력합니다. `Frontend`으로 시작하세요.
1. 선택사항. 사용 가능한 색상에서 선택하여 색상을 선택하거나 **배경 색** 텍스트 상자에 특정 색상을 위한 16진수 색상 값을 입력하세요.
1. **라벨 생성**을 선택합니다.

필요한 모든 레이블을 생성하려면 이 단계를 반복합니다:

- `Frontend`
- `Workflow::Ready for design`
- `Workflow::Design`
- `Workflow::Ready for development`
- `Workflow::In development`
- `Workflow::Complete`

## 팀 이슈 보드 생성 {#create-team-issue-boards}

레이블과 마찬가지로 **Paperclip Assistant** 프로젝트에서 이슈 보드를 만들 수 있지만 **Paperclip Software Factory** 그룹에 있으면 더 좋을 수 있습니다. 이렇게 하면 이 그룹에서 나중에 만들 수 있는 모든 프로젝트의 이슈를 관리할 수 있습니다.

새 그룹 이슈 보드를 만들려면 다음을 수행하세요:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 **Paperclip Software Factory** 그룹을 찾습니다.
1. **계획** > **이슈 보드**를 선택합니다.
1. UX 워크플로우 및 Frontend 워크플로우 보드를 만듭니다.

**UX 워크플로우** 이슈 보드를 만들려면 다음을 수행하세요:

1. 이슈 보드 페이지의 왼쪽 위 모서리에서 현재 보드 이름이 있는 드롭다운 목록을 선택합니다.
1. **새 보드 생성**을 선택합니다.
1. **제목 필드**에 `UX workflow`를 입력합니다.
1. **열린 목록 표시** 및 **닫힌 목록 표시** 확인란을 선택 해제합니다.
1. **보드 생성**을 선택합니다. 빈 보드가 표시되어야 합니다.
1. `Workflow::Ready for design` 레이블에 대한 목록을 생성합니다:
   1. 이슈 보드 페이지의 오른쪽 위 모서리에서 **목록 생성**을 선택합니다.
   1. 나타나는 열의 **값** 드롭다운 목록에서 `Workflow::Ready for design` 레이블을 선택합니다.
   1. **보드에 추가**를 선택합니다.
1. `Workflow::Design` 및 `Workflow::Ready for development` 레이블에 대해 이전 단계를 반복합니다.

![세 개의 워크플로우 열이 있는 빈 "UX 워크플로우" 이슈 보드](img/ux_board_empty_v16_0.png)

**Frontend 워크플로우** 보드를 만들려면 다음을 수행하세요:

1. 이슈 보드 페이지의 왼쪽 위 모서리에서 현재 보드 이름이 있는 드롭다운 목록을 선택합니다.
1. **새 보드 생성**을 선택합니다.
1. **제목 필드**에 `Frontend workflow`를 입력합니다.
1. **열린 목록 표시** 및 **닫힌 목록 표시** 확인란을 선택 해제합니다.
1. **범위**를 확장합니다.
1. **라벨** 다음에 **편집**을 선택하고 `Frontend` 레이블을 선택합니다.
1. **보드 생성**을 선택합니다.
1. `Workflow::Ready for development` 레이블에 대한 목록을 생성합니다:
   1. 이슈 보드 페이지의 오른쪽 위 모서리에서 **목록 생성**을 선택합니다.
   1. 표시되는 열의 **값** 드롭다운 목록에서 `Workflow::Ready for development` 레이블을 선택합니다.
   1. **보드에 추가**를 선택합니다.
1. `Workflow::In development` 및 `Workflow::Complete` 레이블에 대해 이전 단계를 반복합니다.

![세 개의 워크플로우 열이 있는 빈 "Frontend 워크플로우" 이슈 보드](img/frontend_board_empty_v16_0.png)

지금은 두 보드의 목록이 비어 있어야 합니다. 다음으로, 일부 이슈로 채웁니다.

## 기능 이슈 생성 {#create-issues-for-features}

향후 기능, 향상 및 버그를 추적하려면 일부 이슈를 만들어야 합니다. 이슈는 프로젝트에 속하지만 이슈 보드에서 직접 만들 수도 있습니다.

보드에서 이슈를 만들려면 다음을 수행하세요:

1. 이슈 보드 페이지의 왼쪽 위 모서리에서 현재 보드 이름이 있는 드롭다운 목록을 선택합니다.
1. **UX 워크플로우**를 선택합니다.
1. `Workflow::Ready for development` 목록에서 **새 이슈 생성** ({{< icon name="plus" >}})을 선택합니다.
1. 필드를 완성합니다:
   1. **제목** 아래에 `Redesign user profile page`를 입력합니다.
   1. **프로젝트** 아래에서 **Paperclip Software Factory / Paperclip Assistant**를 선택합니다.
1. **이슈 만들기**를 선택합니다. 레이블 목록에서 새 이슈를 만들었기 때문에 이 레이블로 만들어집니다.
1. `Frontend` 레이블을 추가합니다. 이 레이블이 있는 이슈만 Frontend 팀의 보드에 표시되기 때문입니다:
   1. 이슈 카드(제목 아님)를 선택하면 오른쪽에 사이드바가 표시됩니다.
   1. 사이드바의 **라벨** 섹션에서 **편집**을 선택합니다.
   1. **레이블 할당** 드롭다운 목록에서 `Workflow::Ready for design` 및 `Frontend` 레이블을 선택합니다. 선택한 레이블이 체크 표시로 표시됩니다.
   1. 레이블에 대한 변경사항을 적용하려면 **레이블 할당** 다음의 **X**를 선택하거나 레이블 섹션 외부의 다른 영역을 선택합니다.

이 단계를 반복하여 같은 레이블로 더 많은 이슈를 만듭니다.

이제 제품 디자이너들이 작업을 시작할 준비가 된 최소 하나의 이슈가 있어야 합니다!

축하합니다! 이제 팀이 놀라운 소프트웨어에 대해 협업을 시작할 수 있습니다. 다음 단계로 이 보드를 사용하여 [목표 워크플로우](#the-goal-workflow)를 직접 시도하고 두 팀이 상호작용하는 것을 시뮬레이션할 수 있습니다.

## GitLab의 프로젝트 관리에 대해 자세히 알아보기 {#learn-more-about-project-management-in-gitlab}

[튜토리얼 페이지](../plan_and_track.md)에서 프로젝트 관리에 관한 다른 튜토리얼을 찾습니다.
