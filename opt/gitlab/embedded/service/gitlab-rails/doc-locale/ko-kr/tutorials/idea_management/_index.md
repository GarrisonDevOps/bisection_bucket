---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "범위 지정 레이블과 이슈 보드를 사용하여 프로젝트를 설정하면 이해관계자가 아이디어를 제출하고, 투표하고, 분류할 수 있습니다."
title: '자습서: 아이디어 관리용 프로젝트 설정'
---

<!-- vale gitlab_base.FutureTense = NO -->

아이디어 관리는 조직 또는 커뮤니티에서 아이디어의 수집, 조직, 평가 및 구현을 말합니다. 아이디어는 직원, 고객 또는 파트너와 같은 다양한 이해관계자에게서 나올 수 있습니다.

별도의 아이디어 백로그를 통해 팀은 아이디어가 완전히 구체화되기 전에 잠재적 개념과 제안을 수집하고 우선순위를 지정할 수 있습니다. 이러한 별도의 백로그를 통해 원본 아이디어를 더 쉽게 관리할 수 있습니다. 이렇게 하면 정제되지 않거나 검증되지 않은 개념으로 메인 백로그가 복잡해지지 않습니다.

이 튜토리얼에서는 아이디어 관리를 위해 GitLab 프로젝트를 설정하는 방법을 배웁니다.

프로젝트에서 GitLab을 아이디어 관리용으로 설정하려면:

1. [프로젝트 생성](#create-a-project)
1. [아이디어 워크플로우 정의](#define-the-idea-workflow)
1. [기준 문서화](#document-your-criteria)
1. [범위 지정 레이블 생성](#create-scoped-labels)
1. [아이디어 상태 보드 생성](#create-an-idea-status-board)
1. [이해관계자가 아이디어 제출 및 투표](#stakeholders-submit-and-vote-on-ideas)
1. [새 아이디어 분류](#triage-new-ideas)

## 시작하기 전에 {#before-you-begin}

- 이 튜토리얼을 위해 기존 프로젝트를 사용하는 경우 프로젝트에 대해 리포터, 개발자, 유지 관리자 또는 소유자 역할을 가지고 있는지 확인하세요.
- 아래 단계를 따르다가 나중에 프로젝트에 대한 상위 그룹을 생성하기로 결정한 경우 레이블을 최대한 활용하려면 프로젝트 레이블을 그룹 레이블로 승격해야 합니다.

## 프로젝트 생성 {#create-a-project}

프로젝트에는 아이디어를 추적하는 데 사용할 이슈가 포함되어 있습니다.

빈 프로젝트를 생성하려면:

1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. 프로젝트 세부 정보를 입력합니다.
   - **프로젝트 이름**의 경우 `Idea management tutorial`을 입력합니다.
1. **프로젝트 생성**을 선택합니다.

## 아이디어 워크플로우 정의 {#define-the-idea-workflow}

다음으로, 아이디어가 따를 **상태 워크플로우**를 결정해야 합니다. 아이디어의 상태를 공지하면 이해관계자와의 올바른 기대를 설정할 수 있습니다.

이 튜토리얼을 위해 다음 상태 워크플로우를 결정했다고 가정해봅시다:

- `In Review`
- `Backlog`
- `In Progress`
- `Complete`
- `Rejected`

## 기준 문서화 {#document-your-criteria}

상태 워크플로우에 동의한 후 팀원들이 언제든지 액세스할 수 있는 곳에 모든 내용을 적어두세요.

예를 들어 프로젝트의 [wiki](../../user/project/wiki/_index.md)에 추가하거나 [GitLab Pages](../../user/project/pages/_index.md)로 발행한 회사 핸드북에 추가하세요.

<!-- Idea for expanding this tutorial:
     Add steps for [creating a wiki page](../../user/project/wiki/_index.md#create-a-new-wiki-page). -->

## 범위 지정 레이블 생성 {#create-scoped-labels}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

다음으로, 상태 워크플로우를 나타내기 위해 아이디어에 추가할 레이블을 생성합니다.

이를 위한 최고의 도구는 [범위 지정 레이블](../../user/project/labels.md#scoped-labels)로, 이를 사용하여 서로 배타적인 특성을 설정할 수 있습니다.

[이전](#define-the-idea-workflow)에 수집한 상태 목록을 확인하면 일치하는 범위 지정 레이블을 생성하려고 할 것입니다.

범위 지정 레이블의 이름에서 이중 콜론(`::`)은 동일한 범위의 두 레이블이 함께 사용되는 것을 방지합니다. 예를 들어, 이미 `status::in review`이(가) 있는 이슈에 `status::backlog` 레이블을 추가하면 이전 레이블이 제거됩니다.

> [!note]
> 범위 지정 레이블은 GitLab Premium 및 GitLab Ultimate 티어에서 사용할 수 있습니다. Free 티어를 사용하는 경우 대신 일반 레이블을 사용할 수 있습니다. 그러나 이들은 서로 배타적이지 않습니다.

각 레이블을 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **관리** > **라벨**을 선택합니다.
1. **새 라벨**을 선택합니다.
1. **제목** 텍스트 상자에 레이블의 이름을 입력합니다. `status::in review`으로 시작하세요.
1. 선택사항. 사용 가능한 색상에서 선택하여 색상을 선택하거나 **배경 색** 텍스트 상자에 특정 색상을 위한 16진수 색상 값을 입력하세요.
1. **라벨 생성**을 선택합니다.

필요한 모든 레이블을 생성하려면 이 단계를 반복합니다:

- `status::backlog`
- `status::in progress`
- `status::complete`
- `status::rejected`

## 아이디어 상태 보드 생성 {#create-an-idea-status-board}

들어오는 아이디어를 준비하려면 아이디어를 레이블별로 정리하는 [이슈 보드](../../user/project/issue_board.md)를 생성합니다. 이를 사용하여 카드를 다양한 목록으로 끌어서 이슈를 빠르게 생성하고 레이블을 추가할 수 있습니다.

이슈 보드를 설정하려면:

1. 맨 위 표시줄에서 **검색 또는 이동**을 선택하고 **아이디어 관리 튜토리얼** 프로젝트를 찾습니다.
1. **계획** > **이슈 보드**를 선택합니다.
1. 이슈 보드 페이지의 왼쪽 위 모서리에서 현재 보드 이름이 있는 드롭다운 목록을 선택합니다.
1. **새 보드 생성**을 선택합니다.
1. **제목 필드**에 `Idea status workflow`를 입력합니다.
1. **열린 목록 표시** 확인란을 선택한 상태로 유지하고 **닫힌 목록 표시**를 선택 해제합니다.
1. **보드 생성**을 선택합니다. 빈 보드가 표시되어야 합니다.
1. `status::in review` 레이블에 대한 목록을 생성합니다:
   1. 이슈 보드 페이지의 왼쪽 위 모서리에서 **목록 생성**을 선택합니다.
   1. 나타나는 열의 **값** 드롭다운 목록에서 `status::in review` 레이블을 선택합니다.
   1. **보드에 추가**를 선택합니다.
1. `status::backlog`, `status::in progress`, `status::complete` 및 `status::rejected` 레이블에 대해 이전 단계를 반복합니다.

현재 보드의 목록은 비어 있어야 합니다. 다음으로, 일부 이슈로 채웁니다.

![아이디어 상태 보드.](img/blank_idea_board_v16_10.png)

## 이해관계자가 아이디어 제출 및 투표 {#stakeholders-submit-and-vote-on-ideas}

이해관계자와 아이디어 관리 프로젝트를 공유하고 아이디어를 문서화하도록 초대하세요!

이해관계자를 초대하려면:

1. 왼쪽 사이드바에서 **관리** > **멤버**를 선택합니다.
1. **멤버 초대**를 선택합니다.
1. 이해관계자의 이메일 주소를 입력합니다.
1. **리포터** 역할을 선택합니다.

이해관계자는 이제 프로젝트에 액세스하여 새 아이디어를 생성할 수 있습니다:

1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택합니다.
1. 오른쪽 위 모서리에서 **새 항목**을 선택합니다.
1. **유형** 드롭다운 목록에서 **이슈**를 선택합니다(아직 선택되지 않은 경우).
1. 제목과 설명을 입력합니다.
1. **이슈 만들기**를 선택합니다.

이해관계자는 또한 기존 아이디어를 업보트하여 아이디어에 관심이 있음을 나타낼 수 있습니다:

1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택합니다.
1. **유형** = **이슈**로 목록을 필터링한 후 이슈를 선택합니다.
1. 이슈 설명 아래에서 **엄지손가락 위로** [이모지 반응](../../user/emoji_reactions.md)을 선택합니다.

## 새 아이디어 분류 {#triage-new-ideas}

**열기** 목록에서 일부 이슈를 끌어서 레이블 목록 중 하나로 워크플로우 상태를 설정해봅니다.

![예제 이슈가 포함된 아이디어 이슈 보드.](img/populated_idea_board_v16_10.png)

## 다음 단계 {#next-steps}

다음으로, 다음을 수행할 수 있습니다:

- 이해관계자로부터 모든 중요한 세부 정보를 수집하기 위해 [이슈 템플릿](../../user/project/description_templates.md)을 생성합니다.
- 아이디어에 대한 추가 정보를 수집하기 위해 [댓글과 스레드](../../user/discussions/_index.md)를 사용합니다.
- 팀 백로그의 이슈를 아이디어 프로젝트의 이슈와 [관계짓습니다](../../user/project/issues/related_issues.md).
