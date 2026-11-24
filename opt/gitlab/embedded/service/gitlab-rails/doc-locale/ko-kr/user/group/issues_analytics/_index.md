---
stage: Analytics
group: Optimize
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 이슈 분석
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이슈 분석은 그룹 또는 프로젝트에서 매월 생성되는 이슈에 대한 인사이트를 제공합니다. 막대 차트는 매월 열린 이슈와 닫힌 이슈의 수를 보여줍니다. 표는 전역 페이지 필터를 기반으로 상위 100개의 이슈를 표시하며, 각 이슈에 대한 다음 세부 정보를 포함합니다:

- 이름
- 나이
- 상태
- 마일스톤
- 반복
- 가중치
- 마감 날짜
- 담당자
- 작성자

![그룹에서 생성된 이슈를 보여주는 이슈 분석 막대 차트 및 표](img/issue_analytics_v17_8.png)

## 이슈 분석 보기 {#view-issue-analytics}

이슈 분석을 보려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **분석** > **이슈 분석**을 선택합니다. 한 달의 총 이슈 수를 확인하려면 막대 위에 마우스를 가져갑니다.
1. 선택 사항. **검색 또는 결과 필터** 텍스트 상자에서 검색 기준을 입력합니다:

   - 작성자
   - 담당자
   - 마일스톤
   - 레이블
   - 내 반응
   - 가중치

1. 선택 사항. 표시되는 월의 총 개수를 변경하려면 `months_back=n` 매개변수를 URL에 추가합니다. 예를 들어 `https://gitlab.com/groups/gitlab-org/-/issues_analytics?months_back=15`는 GitLab.org 그룹의 15개월 데이터가 포함된 차트를 표시합니다.

[Value Streams Dashboard](../../analytics/value_streams_dashboard.md)에서 **새 이슈** 드릴다운 보고서를 통해 이슈 분석에 액세스할 수도 있습니다.

### 향상된 이슈 분석 {#enhanced-issue-analytics}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

향상된 이슈 분석은 추가 메트릭 `Issues closed`을(를) 표시하며, 이는 선택된 기간 동안 그룹에서 해결된 이슈의 총 수를 나타냅니다. 이 메트릭을 사용하여 전체 처리 시간을 개선하고 고객에게 제공되는 가치를 높일 수 있습니다.

![그룹에서 열린 이슈와 닫힌 이슈를 보여주는 향상된 이슈 분석 막대 차트 및 표](img/enhanced_issue_analytics_v17_8.png)
