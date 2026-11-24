---
stage: Growth
group: Engagement
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
title: '자습서: GitLab 인터페이스 탐색'
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 인터페이스가 GitLab 18.6에서 [패널 기반 레이아웃으로 변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/208474)되었습니다.

{{< /history >}}

<!-- vale gitlab_base.FutureTense = NO -->

이 자습서를 따라 다양한 인터페이스 요소를 사용하여 GitLab을 탐색하는 방법을 알아보세요.

## 인터페이스 레이아웃 {#layout-of-the-interface}

오른쪽 상단 모서리에 여러 바로 가기가 있습니다. 이 바로 가기를 사용하여 새 항목을 만들고, 프로필, 이슈 목록, 머지 리퀘스트 및 할 일 항목을 볼 수 있습니다.

![새로운 탐색의 바로 가기입니다.](img/top_nav_v18_11.png)

왼쪽 사이드바는 보고 있는 정보에 따라 변경됩니다. 예를 들어 프로젝트를 보거나, 프로젝트 또는 그룹을 탐색하거나, 프로필을 보고 있을 수 있습니다. 왼쪽 사이드바의 다른 영역으로 전환하려면 상단 표시줄에서 **검색 또는 이동**을 사용하세요.

왼쪽 사이드바의 나머지 부분은 선택한 옵션에 따라 채워집니다. 예를 들어 프로젝트에 있으면 사이드바는 프로젝트별로 표시됩니다.

오른쪽에서 GitLab Duo 사이드바에는 GitLab Duo Chat 및 관련 세션에 액세스하는 버튼이 있습니다.

![GitLab Duo 사이드바입니다.](img/paneled_view_duo_sidebar_v18_11.png)

## 프로젝트 찾기 {#find-your-project}

이제 왼쪽 사이드바를 사용할 몇 가지 일반적인 작업을 살펴보겠습니다.

시작하려면 작업하려는 프로젝트를 찾겠습니다.

1. 사용 가능한 모든 프로젝트를 탐색하려면 상단 표시줄에서 **검색 또는 이동**을 선택하세요.
1. 자주 방문한 프로젝트 목록에서 선택하거나 콜론 `:`을 입력한 후 프로젝트 이름을 입력합니다:

   ![프로젝트를 찾고 자주 방문한 프로젝트를 검색하는 막대입니다.](img/search_projects_v18_11.png)

이제 왼쪽 사이드바에 프로젝트별 옵션이 표시됩니다.

![프로젝트별 옵션](img/sidebar_v18_11.png)

## 자주 사용하는 항목 고정 {#pin-frequently-used-items}

자주 사용하는 경우 메뉴 항목을 고정할 수 있습니다.

1. 고정하려는 항목을 볼 때까지 섹션을 확장합니다.
1. 핀 위에 마우스를 놓고 {{< icon name="thumbtack" >}}를 선택합니다.

   ![선택된 핀 아이콘입니다.](img/pin_v18_11.png)

항목이 **고정됨** 섹션에 표시됩니다:

![고정됨 섹션의 항목입니다.](img/sidebar_v18_11_pinned.png)

> [!note]
> 프로젝트를 보는 동안 고정한 항목은 그룹을 보는 동안 고정한 항목과 다릅니다.

## 더 집중된 보기 사용 {#use-a-more-focused-view}

왼쪽 사이드바에서 액세스할 수 있는 영역으로 더 집중된 보기를 선택할 수도 있습니다. **검색 또는 이동**을 선택한 다음 **귀하의 작업**을 선택합니다.

![검색 막대 및 귀하의 작업 항목입니다.](img/your_work_v18_11.png)

그런 다음 왼쪽 사이드바에 **귀하의 작업**이 표시됩니다.

## 세부 정보 패널에서 작업 항목 열기 {#open-work-items-in-the-details-panel}

이슈 같은 작업 항목을 선택하면 세부 정보 패널에서 열립니다.

전체 페이지 보기에서 항목을 열려면 다음 중 하나를 수행하세요:

- **작업 항목** 페이지에서 항목을 마우스 오른쪽 단추로 클릭하고 새 탭에서 엽니다.
- 항목을 선택하고 세부 정보 패널에서 ID를 선택합니다(예: `myproject#123456`).

충분한 화면 공간이 있으면 세부 정보 패널이 열려 있는 목록 또는 보드 옆에 열립니다. 더 작은 화면에서 세부 정보 패널이 목록 또는 보드 패널을 덮습니다.

![이슈 패널과 함께 나란히 패널에서 열린 이슈입니다.](img/paneled_view_issue_drawer_v18_11.png)

![이슈 패널의 일부를 덮는 패널에서 열린 이슈입니다.](img/paneled_view_issue_drawer_overlap_v18_11.png)

### 패널에서 작업 항목을 열기 위한 기본 설정 {#set-preference-for-opening-work-items-in-a-panel}

기본적으로 이슈 또는 에픽과 같은 작업 항목은 세부 정보 패널에서 열립니다. 끄려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택합니다.
1. 필터 표시줄의 오른쪽에서 **디스플레이 옵션** ({{< icon name="preferences" >}}) 을 선택하고 **사이드 패널에서 항목 열기** 토글을 끕니다.

기본 설정이 저장되고 GitLab 전체에 적용됩니다.

## 관리자 영역으로 이동 {#go-to-the-admin-area}

**운영자** 영역은 오른쪽 상단 모서리에서 사용할 수 있습니다:

![새로운 탐색의 운영자 영역 버튼입니다.](img/admin_area_v18_11.png)

## 새로운 기능에 액세스 {#access-whats-new}

**새로운 기능** 기능은 사용자에게 지난 10개의 GitLab 버전에서 새로운 기능의 일부 하이라이트를 보여줍니다.

로그인한 경우:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **당신을 위한 새 기능**을 선택합니다.

로그인하지 않은 경우:

1. 왼쪽 사이드바의 아래쪽에서 **도움말** ({{< icon name="question" >}}) 을 선택합니다.
1. **당신을 위한 새 기능**을 선택합니다.

**당신을 위한 새 기능** 메뉴 항목은 아직 읽지 않은 항목의 수를 표시합니다.
