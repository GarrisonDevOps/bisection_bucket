---
stage: Analytics
group: Optimize
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 기여 분석
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

기여 분석은 지난 주, 월, 3개월 동안 그룹 멤버가 수행한 [기여 이벤트](../../profile/contributions_calendar.md#user-contribution-events)의 개요를 제공합니다. 대화형 막대 차트와 상세 테이블은 그룹 멤버별 기여 이벤트(푸시 이벤트, 이슈, 머지 리퀘스트)를 보여줍니다.

![지난 주에 사용자별 푸시 횟수를 보여주는 기여 분석 막대 차트](img/contribution_analytics_push_v17_7.png)

기여 분석을 사용하여 팀 활동과 개인 성과에 대한 인사이트를 얻고, 다음을 위해 이 정보를 활용하세요:

- 업무 부하 분산: 시간 경과에 따른 그룹의 기여를 분석하고, 고성과자이거나 추가 지원이 필요한 그룹 멤버를 파악합니다.
- 팀 협업: 코드 푸시 대 리뷰 또는 승인과 같은 기여의 균형을 평가하여 협업 개발 관행을 보장합니다.
- 교육 기회: 머지 리퀘스트 승인 또는 이슈 해결률이 낮은 등 팀 멤버가 멘토링이나 교육의 이점을 얻을 수 있는 영역을 파악합니다.
- 회고 평가: 기여 분석을 회고에 포함하여 팀이 목표를 얼마나 효과적으로 달성했는지 평가하고 필요한 조정 사항을 파악합니다.

## 추적 {#tracking}

기여 분석은 푸시 이벤트를 기반으로 하며, 고유 커밋보다 더 신뢰할 수 있는 기여 보기를 제공합니다. 고유 커밋을 계산하면 여러 브랜치에 걸쳐 푸시할 때 중복이 발생할 수 있습니다. 대신 푸시 이벤트를 추적하면 GitLab은 모든 기여가 정확하게 계산되도록 보장합니다.

예를 들어 사용자가 한 번의 푸시로 브랜치 A에 3개의 커밋을 푸시합니다. 나중에 사용자는 브랜치 A에서 브랜치 B로 이 중 2개의 커밋을 푸시합니다. GitLab은 사용자가 3개의 고유 커밋을 만들었지만 5개의 커밋을 기록합니다.

## 기여 분석 보기 {#view-contribution-analytics}

기여 분석을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **분석** > **기여 분석**을 선택합니다.
1. 선택 사항. 결과를 필터링합니다:

   - 지난 주, 월, 3개월의 기여 분석을 보려면 3개 탭 중 하나를 선택합니다. 선택한 기간이 모든 차트와 테이블에 적용됩니다.
   - 막대 차트를 확대하여 그룹 멤버의 일부만 표시하려면 차트 아래의 슬라이더({{< icon name="status-paused" >}})를 선택하고 축을 따라 슬라이드합니다.
   - 기여 테이블을 열별로 정렬하려면 열 헤더 또는 셰브론을 선택합니다(내림차순의 경우 {{< icon name="chevron-lg-down" >}}, 오름차순의 경우 {{< icon name="chevron-lg-up" >}}).

1. 선택 사항. 그룹 멤버의 기여를 보려면 다음 중 하나를 수행합니다:

   - **기여 분석** 막대 차트에서 멤버 이름이 있는 막대 위로 마우스를 이동합니다.
   - **그룹 멤버별 기여** 테이블에서 멤버 이름을 선택합니다. 멤버의 GitLab 프로필이 표시되며, [기여 달력](../../profile/contributions_calendar.md)을 살펴볼 수 있습니다.

사용자 기여에 대한 메트릭을 검색하려면 [GraphQL API](../../../api/graphql/reference/_index.md#groupcontributions)를 사용할 수도 있습니다.

## ClickHouse를 사용한 기여 분석 {#contribution-analytics-with-clickhouse}

GitLab.com에서는 기여 분석이 ClickHouse Cloud 클러스터를 통해 실행됩니다. GitLab Self-Managed에서는 ClickHouse 통합을 구성하면 ClickHouse `events` 테이블이 PostgreSQL `events` 테이블에서 자동으로 채워집니다. 이 프로세스는 대규모 설치의 경우 시간이 걸릴 수 있습니다. 테이블이 완전히 동기화된 후 새로운 이벤트는 약 3분의 지연으로 ClickHouse에서 사용 가능하게 됩니다.

자세한 정보는 다음을 참조하세요.

- [ClickHouse 통합 지침](../../../integration/clickhouse.md)
- [GitLab에서의 ClickHouse 사용](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/clickhouse_usage/)
