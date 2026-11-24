---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "GitLab 작업 항목으로 팀의 작업을 구성하세요. 작업, 에픽, 이슈 및 목표를 통합 보기로 추적하여 전략을 구현과 연결하고 진행 상황을 모니터링합니다."
title: 작업 항목
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

작업 항목은 GitLab에서 작업을 계획하고 추적하기 위한 핵심 요소입니다. 제품 개발을 계획하고 추적하려면 종종 작업을 더 작고 관리 가능한 부분으로 나누면서 전체 그림과의 연결을 유지해야 합니다. 작업 항목은 이 근본적인 필요를 중심으로 설계되어 전략적 이니셔티브에서 개별 작업까지 모든 수준에서 작업 단위를 나타내는 통합된 방식을 제공합니다.

작업 항목의 계층적 특성은 다양한 수준의 작업 간에 명확한 관계를 만들어 팀이 일일 작업이 더 큰 목표에 어떻게 기여하는지, 전략적 목표가 어떻게 실행 가능한 구성 요소로 분해되는지 이해하도록 도와줍니다.

이 구조는 Scrum, Kanban 및 포트폴리오 관리 방식과 같은 다양한 계획 프레임워크를 지원하면서 팀에게 모든 수준에서 진행 상황에 대한 가시성을 제공합니다.

## 작업 항목 유형 {#work-item-types}

GitLab은 다음 작업 항목 유형을 지원합니다:

- [이슈](../project/issues/_index.md): 작업, 기능 및 버그를 추적합니다.
- [에픽](../group/epics/_index.md): 여러 마일스톤과 이슈에 걸쳐 대규모 이니셔티브를 관리합니다.
- [작업](../tasks.md): 작은 작업 단위를 추적합니다.
- [목표 및 핵심 결과](../okrs.md): 전략적 목표와 측정 가능한 결과를 추적합니다.
- [테스트 사례](../../ci/test_cases/_index.md): GitLab 워크플로우에 테스트 계획을 직접 통합합니다.

[작업 항목 유형을 구성](configurable_work_item_types.md)하여 새 유형을 만들고 그룹 및 프로젝트 전체에서의 가용성을 제어할 수도 있습니다.

## 모든 작업 항목 보기 {#view-all-work-items}

{{< history >}}

- GitLab 18.7에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/11918)되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `work_item_planning_view`가 포함되어 있습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/work_items/520452)합니다. `work_item_planning_view` 기능 플래그가 제거되었습니다.

{{< /history >}}

**작업 항목** 목록은 프로젝트 또는 그룹에 대한 모든 작업 항목 유형(예: 이슈, 에픽 및 작업)을 보고 관리하기 위한 중앙 장소입니다. 이 보기를 사용하여 프로젝트 또는 그룹의 전체 작업 범위를 이해하고 효과적으로 우선 순위를 지정합니다.

이전 버전의 GitLab에서 이슈와 에픽은 **계획** > **이슈** 및 **계획** > **에픽** 아래에 별도의 목록 페이지가 있었습니다. GitLab 18.10 이상에서는 이러한 페이지가 **계획** > **작업 항목**으로 대체되어 모든 작업 항목 유형을 단일 보기에서 통합합니다. 사이드바에 **이슈** 또는 **에픽**을 고정했다면 **작업 항목**이 대신 고정됩니다. `/epics/:iid` 또는 `/issues/:iid`을 포함하는 URL은 자동으로 `/work_items/:iid`로 리디렉션됩니다.

프로젝트 또는 그룹에 대한 작업 항목을 보려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택합니다.

### 작업 항목 필터링 {#filter-work-items}

**작업 항목** 목록은 기본적으로 모든 작업 항목 유형을 표시합니다. 특정 유형(예: 이슈만 또는 에픽만)을 보려면 **유형** 필터를 사용합니다.

작업 항목 목록을 필터링하려면:

1. 페이지 상단의 필터 표시줄에서 필터, 연산자 및 해당 값을 선택합니다. 예를 들어 에픽만 보려면 **유형** 필터, **다음과 같음** 연산자를 선택하고 **에픽** 값을 선택합니다.
1. 선택 사항. 검색을 좁히기 위해 더 많은 필터를 추가합니다.
1. <kbd>Enter</kbd> 키를 누르거나 검색 아이콘({{< icon name="search" >}})을 선택합니다.

#### 사용 가능한 필터 {#available-filters}

{{< history >}}

- 설명으로 필터링은 GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/536876)되었습니다.

{{< /history >}}

작업 항목에 사용 가능한 필터:

- 담당자
  - 연산자: `is`, `is not one of`, `is one of`
- 작성자
  - 연산자: `is`, `is not one of`, `is one of`
- 기밀
  - 값: `Yes`, `No`
- 연락처
  - 연산자: `is`
- 상태
  - 연산자: `is`
- 상태
  - 연산자: `is`, `is not`
- 반복
  - 연산자: `is`, `is not`
- 레이블
  - 연산자: `is`, `is not one of`, `is one of`
- 마일스톤
  - 연산자: `is`, `is not`
- 내 반응
  - 연산자: `is`, `is not`
- 조직
  - 연산자: `is`
- 부모
  - 연산자: `is`, `is not`
  - 값: 모든 `Issue`, `Epic`, `Objective`
- 릴리스
  - 연산자: `is`, `is not`
- 내에서 검색
  - 연산자: `Titles`, `Descriptions`
- 상태
  - 값: `Any`, `Open`, `Closed`
- 형식
  - 값: `Issue`, `Incident`, `Task`, `Epic`, `Objective`, `Key Result`, `Test case`
- 가중치
  - 연산자: `is`, `is not`

최근에 사용한 필터에 액세스하려면 필터 표시줄의 왼쪽에서 **최근 검색**({{< icon name="history" >}}) 드롭다운 목록을 선택합니다.

### 작업 항목 정렬 {#sort-work-items}

{{< history >}}

- 상태별 정렬은 GitLab 18.5에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/18638)되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `work_item_status_mvc2`가 포함되어 있습니다. 기본적으로 활성화됩니다.
- 상태별 정렬은 GitLab 18.6에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/576610)합니다. `work_item_status_mvc2` 기능 플래그가 제거되었습니다.

{{< /history >}}

다음 항목으로 작업 항목 목록을 정렬합니다:

- 생성 날짜
- 업데이트된 날짜
- 시작 날짜
- 마감 날짜
- 제목
- 상태
- 가중치

정렬 기준을 변경하려면:

1. 필터 바의 오른쪽에서 **표시**({{< icon name="preferences" >}})를 선택하여 표시 기본 설정 드로어를 엽니다.
1. 서랍 상단에서 **다음으로 정렬** 드롭다운 목록을 선택합니다.

오름차순과 내림차순 사이의 정렬 순서를 변경하려면:

1. 필터 바의 오른쪽에서 **표시**({{< icon name="preferences" >}})를 선택하여 표시 기본 설정 드로어를 엽니다.
1. 서랍 상단에서 **다음으로 정렬** 드롭다운 목록 옆에 **정렬 순서**({{< icon name="sort-lowest" >}} 또는 {{< icon name="sort-highest" >}})를 선택합니다.

정렬 논리에 대한 자세한 내용은 [이슈 목록 정렬 및 순서 지정](../project/issues/sorting_issue_lists.md)을 참조하세요.

### 작업 항목 목록의 RSS 피드 구독 {#subscribe-to-an-rss-feed-of-the-work-item-list}

GitLab은 작업 항목 목록의 RSS 피드를 제공합니다.

피드를 구독하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택합니다.
1. 선택 사항. 필터를 적용하여 목록을 좁힙니다.
1. 오른쪽 위 모서리에서 **조치**({{< icon name="ellipsis_v" >}}) > **RSS 피드 구독**을 선택합니다.

기본적으로 피드에는 모든 작업 항목 유형이 포함됩니다. 필터를 적용했다면 피드는 대신 해당 필터와 일치합니다.

피드 URL에는 피드 리더로 인증하는 [피드 토큰](../../security/tokens/_index.md#feed-token)이 포함되어 있습니다.

## 목록 표시 기본 설정 구성 {#configure-list-display-preferences}

{{< history >}}

- GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/393559)되었습니다.
- 이슈에 대한 지원이 GitLab 18.7에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/520791)되었습니다.

{{< /history >}}

특정 메타데이터 필드를 표시하거나 숨기고 보기 기본 설정을 구성하여 목록 페이지에서 작업 항목이 표시되는 방식을 사용자 지정합니다.

GitLab은 다양한 수준에서 표시 기본 설정을 저장합니다:

- **필드**: 네임스페이스별로 저장됩니다. 워크플로우 요구에 따라 다양한 그룹 및 프로젝트에 대해 서로 다른 필드 가시성 설정을 가질 수 있습니다. 예를 들어 한 그룹 또는 프로젝트에서는 담당자와 레이블을 표시하지만 다른 그룹 또는 프로젝트에서는 숨길 수 있습니다.
- **당신의 사전 설정**: 모든 프로젝트 및 그룹 전체에서 전역적으로 저장됩니다. 이렇게 하면 작업 항목을 보는 방식에 대한 일관된 동작이 보장됩니다.

표시 기본 설정을 구성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택합니다.
1. 필터 바의 오른쪽에서 **표시**({{< icon name="preferences" >}})를 선택하여 표시 기본 설정 드로어를 엽니다.
1. **필드** 아래에서 표시할 메타데이터를 켜거나 끕니다:
   - 상태 (이슈의 경우)
   - 담당자
   - 레이블
   - 가중치 (이슈의 경우)
   - 마일스톤
   - 반복 (이슈의 경우)
   - 날짜: 마감일 및 날짜 범위
   - 상태: 상태 표시기
   - 차단됨/차단: 관계 차단 표시기
   - 댓글: 댓글 수
   - 인기도: 인기도 측정치

   **표시됨** 아래에 켠 필드가 나타납니다. **숨김** 아래에 끈 필드가 나타납니다.
1. 선택 사항. 특정 필드를 검색하려면 **검색 필드** 입력을 사용합니다.
1. **당신의 사전 설정** 아래에서 **사이드 패널에서 항목 열기**를 켜거나 꺼서 항목을 선택할 때 작업 항목이 열리는 방식을 선택합니다:
   - 켜짐 (기본값): 항목이 화면의 오른쪽에 있는 서랍에서 열립니다.
   - 꺼짐: 항목이 전체 페이지 보기로 열립니다.

당신의 기본 설정이 저장되며 모든 세션과 기기에서 기억됩니다.

## 작업 항목 마크다운 참조 {#work-item-markdown-reference}

{{< history >}}

- GitLab 18.1에서 `extensible_reference_filters` [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/352861)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.2에서 [정식 출시](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197052)되었습니다. `extensible_reference_filters` 기능 플래그가 제거되었습니다.

{{< /history >}}

GitLab Flavored Markdown 필드에서 `[work_item:123]`으로 작업 항목을 참조할 수 있습니다. 자세한 내용은 [GitLab 특정 참조](../markdown.md#gitlab-specific-references)를 참조하세요.

## 머지 리퀘스트의 작업 항목 {#work-items-in-merge-requests}

{{< history >}}

- `mr_related_work_items`라는 이름의 [기능 플래그](../../administration/feature_flags/_index.md)와 함께 GitLab 18.11에 [도입](https://gitlab.com/groups/gitlab-org/plan-stage/-/work_items/456)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 19.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/233554)합니다. `mr_related_work_items` 기능 플래그가 제거되었습니다.

{{< /history >}}

머지 리퀘스트 설명에서 작업 항목을 참조하면 머지 리퀘스트 사이드바의 **작업 항목** 위젯에 자동으로 나타납니다. 위젯은 작업 항목을 링크된 방식에 따라 그룹화합니다:

- **닫는중**: [종료 패턴](../project/issues/managing_issues.md#closing-issues-automatically) (예: `Closes #123`)으로 링크된 작업 항목입니다. 이러한 작업 항목은 머지 리퀘스트가 병합될 때 자동으로 종료됩니다.
- **언급됨**: 설명에서 참조되지만 종료 패턴으로 링크되지 않은 작업 항목입니다 (예: `Related to #456`). 이러한 작업 항목은 머지 리퀘스트가 병합될 때 종료되지 않습니다.

위젯에 두 개 이상의 작업 항목이 포함된 경우 기본적으로 축소됩니다. 위젯 헤더를 선택하여 확장합니다. 작업 항목을 선택하여 서랍에서 엽니다.

### 작업 항목 수동으로 링크 {#link-work-items-manually}

{{< history >}}

- GitLab 19.1에서 `explicit_mr_work_item_relations` [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/238648)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 19.5에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256281)되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

머지 리퀘스트 설명을 편집하지 않고도 머지 리퀘스트에 작업 항목을 링크할 수 있습니다. 이 방식으로 링크한 작업 항목은 **닫는중** 또는 **관련된** 그룹에 나타나며, 머지 리퀘스트는 각 링크된 작업 항목의 **개발** 섹션에 나타납니다.

사전 요구 사항:

- 프로젝트에 대해 최소한 개발자 역할이 있어야 합니다.

기존 작업 항목을 머지 리퀘스트에 링크하려면:

1. 머지 리퀘스트 페이지의 오른쪽 사이드바에서 **작업 항목** 섹션의 **작업 항목 추가**({{< icon name="plus" >}})를 선택합니다.
1. **작업 항목 링크** 대화 상자의 **관계** 드롭다운 목록에서 **닫침** 또는 **다음과 관련**을 선택합니다.
1. 검색 필드에서 작업 항목을 검색하거나 해당 URL 또는 참조 ID를 입력한 다음 선택합니다.
1. **추가**를 선택합니다.

작업 항목을 생성하고 머지 리퀘스트에 링크하려면:

1. 머지 리퀘스트 페이지의 오른쪽 사이드바에서 **작업 항목** 섹션의 **작업 항목 추가**({{< icon name="plus" >}})를 선택합니다.
1. **작업 항목 링크** 대화 상자의 **관계** 드롭다운 목록에서 **닫침** 또는 **다음과 관련**을 선택합니다.
1. **새 항목 생성**을 선택합니다.
1. **프로젝트** 드롭다운 목록에서 프로젝트를 선택합니다.
1. **유형** 드롭다운 목록에서 작업 항목 유형을 선택합니다.
1. 필드를 완성하세요.
1. 선택한 유형에 대해 **생성**를 선택합니다 (예: **이슈 생성**).

링크를 제거하려면:

1. 머지 리퀘스트 페이지의 오른쪽 사이드바에서 **작업 항목** 섹션의 작업 항목 옆에서 **삭제**({{< icon name="close" >}})를 선택합니다.

종료 패턴이나 머지 리퀘스트 설명의 언급으로 추가된 작업 항목은 제거할 수 없습니다.

다른 프로젝트의 작업 항목을 링크하려면 해당 URL 또는 전체 참조(예: `group/project#123`)를 입력합니다.

## 관련 항목 {#related-topics}

- [연결된 이슈](../project/issues/related_issues.md)
- [링크된 에픽](../group/epics/linked_epics.md)
- [이슈 보드](../project/issue_board.md)
- [레이블](../project/labels.md)
- [반복](../group/iterations/_index.md)
- [마일스톤](../project/milestones/_index.md)
- [사용자 지정 필드](custom_fields.md)
- [구성 가능한 작업 항목 유형](configurable_work_item_types.md)
- [Workplan](workplan.md)
