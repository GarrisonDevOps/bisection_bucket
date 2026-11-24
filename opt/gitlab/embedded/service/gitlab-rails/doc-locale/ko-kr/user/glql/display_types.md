---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: GLQL 디스플레이 유형
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- `glql_integration`라는 이름의 [기능 플래그](../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14767)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.3에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/554870)입니다. `glql_integration` 기능 플래그가 제거되었습니다.

{{< /history >}}

디스플레이 유형은 [임베드된 뷰](_index.md#embedded-views)가 GLQL 쿼리의 결과를 렌더링하는 방식을 제어합니다. 뷰 소스에서 `display` 매개변수로 디스플레이 유형을 설정합니다.

`display` 매개변수를 설정하지 않으면 결과가 목록으로 렌더링됩니다.

일부 디스플레이 유형은 모든 쿼리에서 작동합니다. 기타는 데이터를 차원 및 메트릭으로 집계하는 [분석 모드](_index.md#analytics-mode)에서만 작동합니다.

다음 디스플레이 유형은 모든 모드에서 사용할 수 있습니다:

| 디스플레이 유형                  | `display` 값 | 설명 |
| ----------------------------- | --------------- | ----------- |
| 테이블               | `table`         | 결과당 한 행, 필드당 한 열을 가진 테이블입니다. |
| 목록                 | `list`          | 결과의 순서 없는 목록입니다. |
| 순서가 지정된 목록 | `orderedList`   | 결과의 번호가 지정된 목록입니다. |

다음 디스플레이 유형은 분석 모드에서만 사용할 수 있습니다:

| 디스플레이 유형                  | `display` 값 | 설명 |
| ----------------------------- | --------------- | ----------- |
| 단일 통계 | `stat`          | 큰 값으로 표시되는 단일 집계 메트릭입니다. |
| 열 차트 | `columnChart`   | 차원으로 정의된 카테고리 간 메트릭을 비교하는 차트입니다. |
| 막대 차트 | `barChart` | 차원으로 정의된 카테고리 간 메트릭을 비교하는 가로 차트입니다. |
| 막대 목록 | `barList` | 각 차원 값을 전체의 비율로 표시하는 가로 차트입니다. |
| 선 차트     | `lineChart`     | 차원 위에 하나 이상의 메트릭을 선으로 표시하여 추세를 보여주는 차트입니다. |
| 영역 차트     | `areaChart`     | 차원 위에 하나 이상의 메트릭을 채워진 영역으로 표시하여 추세와 볼륨을 보여주는 차트입니다. |
| 히트맵     | `heatMap`     | 차원 값 쌍마다 하나의 셀을 포함하는 음영이 있는 셀의 그리드로, 더 어두운 셀이 더 큰 값입니다. |
| 발산형 막대 차트 | `divergingBarChart` | 공유 카테고리 열 주위에 두 메트릭을 미러링하는 차트로, 각각 자신의 가장 큰 막대에 맞춰 확대/축소됩니다. |

## 테이블 {#table}

{{< history >}}

- 동적 설명 및 `hiddenMetrics`은(는) GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256879).

{{< /history >}}

테이블은 결과당 한 행, [필드](fields.md)당 한 열을 렌더링합니다.

테이블을 열별로 정렬하려면 열 헤더를 선택합니다. 이 뷰는 전체 결과 집합이 아니라 뷰에 로드된 행을 다시 정렬합니다.

테이블은 결과를 설명할 수 있습니다. 이를 위해 [분석 모드](_index.md#analytics-mode)가 필요합니다. `description`를 `displayConfig` 아래에 설정하고, 메트릭을 열에서 제외하려면 `hiddenMetrics`를 설정합니다. 자리표시자 구문 및 규칙은 [동적 설명](#dynamic-descriptions)을 참조합니다.

### 예 {#example}

현재 사용자에게 할당된 처음 5개의 미해결 이슈를 `gitlab-org/gitlab` 프로젝트에서 테이블로 표시하며, `title`, `state`, `health`, `epic`, `milestone`, `weight`, 및 `updated` 열이 포함됩니다:

````yaml
```glql
display: table
title: My open issues
fields: title, state, health, epic, milestone, weight, updated
limit: 5
query: type = Issue AND project = "gitlab-org/gitlab" AND assignee = currentUser() AND state = opened
```
````

## 목록 {#list}

목록은 결과를 순서 없는 목록으로 렌더링합니다. 목록은 기본 디스플레이 유형입니다.

### 예 {#example-1}

현재 사용자에게 할당된 처음 5개의 미해결 이슈를 `gitlab-org/gitlab` 프로젝트에서 목록으로 표시하며, 가장 빠른 날짜 순으로 정렬되고 `title`, `health`, 및 `due` 필드를 표시합니다:

````yaml
```glql
display: list
fields: title, health, due
limit: 5
sort: due asc
query: type = Issue AND project = "gitlab-org/gitlab" AND assignee = currentUser() AND state = opened
```
````

## 순서가 지정된 목록 {#ordered-list}

순서가 지정된 목록은 결과를 번호가 지정된 목록으로 렌더링합니다. 결과의 순서가 순위 매기기와 같이 의미가 있을 때 순서가 지정된 목록을 사용합니다.

### 예 {#example-2}

현재 사용자에게 할당된 처음 5개의 미해결 이슈를 `gitlab-org/gitlab` 프로젝트에서 순서가 지정된 목록으로 표시하며, 가장 빠른 날짜 순으로 정렬되고 `title`, `health`, 및 `due` 필드를 표시합니다:

````yaml
```glql
display: orderedList
fields: title, health, due
limit: 5
sort: due asc
query: type = Issue AND project = "gitlab-org/gitlab" AND assignee = currentUser() AND state = opened
```
````

## 단일 통계 {#single-stat}

{{< history >}}

- GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241395)되었습니다.
- `compact` 디스플레이 옵션은 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/groups/gitlab-org/-/work_items/23470).
- 동적 설명은 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255287).

{{< /history >}}

단일 통계는 [분석 모드](_index.md#analytics-mode)의 하나의 집계 메트릭을 큰 값으로 시각화합니다. 단일 통계를 사용하여 합계 또는 비율과 같은 주요 숫자를 강조합니다.

단일 통계에는 다음이 필요합니다:

- `mode: analytics`로 설정된 분석 모드입니다.
- `metrics` 매개변수로 설정된 하나 이상의 메트릭입니다. 통계는 첫 번째 메트릭의 값을 표시하고 설명이 이를 참조하지 않으면 나머지를 무시합니다.
- `dimensions` 없음입니다.

값은 메트릭을 기반으로 자동으로 형식이 지정됩니다. 예를 들어, 개수는 천 단위 구분 기호를 사용하고 비율은 백분율로 표시됩니다. 대신 컴팩트 표기법으로 숫자를 렌더링하려면 예를 들어 `1.45M`, `compact: true`를 `displayConfig` 아래에 설정합니다. 비율은 백분율 형식을 유지하고, 기간은 가장 큰 단위로 떨어지며, 예를 들어 `1h 1m 1s`는(는) `1h`가 됩니다.

값을 설명하려면 `description`를 `displayConfig` 아래에 설정합니다. 자리표시자 구문 및 규칙은 [동적 설명](#dynamic-descriptions)을 참조합니다.

### 예 {#example-3}

지난 30일 동안의 코드 제안 총 개수를 단일 통계로 표시하려면:

````yaml
```glql
display: stat
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
metrics: totalCount
```
````

쿼리가 선택한 다른 메트릭으로 값을 설명하려면:

````yaml
```glql
display: stat
displayConfig:
  description: "%{acceptedCount} of %{shownCount} suggestions accepted"
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
metrics: acceptanceRate, acceptedCount, shownCount
```
````

## 열 차트 {#column-chart}

{{< history >}}

- GitLab 19.1에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21212)되었습니다.
- `maxSeries` 디스플레이 옵션은 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/groups/gitlab-org/-/work_items/23470).

{{< /history >}}

열 차트는 [분석 모드](_index.md#analytics-mode)의 집계 데이터를 시각화합니다. 열 차트를 사용하여 차원으로 정의된 카테고리 간 메트릭을 비교합니다.

열 차트에는 다음이 필요합니다:

- `mode: analytics`로 설정된 분석 모드입니다.
- 결과를 그룹화할 1개 또는 2개의 `dimensions`입니다.
- 표시할 최소 1개의 메트릭(`metrics` 매개변수 사용)입니다.

차원 및 메트릭의 수는 차트 렌더링 방식을 결정합니다:

- 1개의 차원과 1개 이상의 메트릭은 각 메트릭에 대해 열을 표시합니다. 이 열을 스택하려면 `stacked: true`를 `displayConfig` 아래에 설정합니다. 단일 메트릭을 사용하면 `stacked`는 눈에 띄는 효과가 없습니다.
- 2개의 차원과 1개의 메트릭은 두 번째 차원으로 그룹화된 스택된 열 차트를 표시합니다. 2개의 차원을 사용하면, 1개의 메트릭만 사용할 수 있으며, GitLab은 `displayConfig.stacked`을(를) 무시합니다.

2개의 차원을 사용할 때, `maxSeries` 옵션은 `displayConfig` 아래에서 몇 개의 두 번째 차원 값이 자신의 세그먼트를 가지는지를 제한합니다. 가장 큰 합계를 가진 값은 자신의 값을 유지하고, 나머지는 `Other (N)` 세그먼트로 결합됩니다. 한계를 초과한 단일 값은 그대로 유지됩니다. `maxSeries` 없이 모든 값이 세그먼트를 가집니다. `maxSeries` 값이 0보다 큰 정수가 아니면 무시됩니다.

### 예 {#example-4}

지난 30일 동안 언어별 코드 제안 사용량을 열 차트로 표시하려면:

````yaml
```glql
display: columnChart
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: totalCount
```
````

메트릭을 단일 열로 스택하려면 나란히 표시하지 않습니다:

````yaml
```glql
display: columnChart
displayConfig:
  stacked: true
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: acceptedCount, rejectedCount
```
````

## 막대 차트 {#bar-chart}

{{< history >}}

- GitLab 19.2에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21212)되었습니다.
- `categoryLabels`, `colorBy`, 및 `showAxisTitles` 디스플레이 옵션은 GitLab 19.4에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/628025).

{{< /history >}}

막대 차트는 [분석 모드](_index.md#analytics-mode)의 집계 데이터를 가로 막대로 시각화합니다. 막대 차트를 사용하여 차원으로 정의된 카테고리 간 메트릭을 비교합니다. 특히 카테고리 레이블이 긴 경우에 유용합니다.

막대 차트에는 다음이 필요합니다:

- `mode: analytics`로 설정된 분석 모드입니다.
- 결과를 그룹화할 1개 또는 2개의 `dimensions`입니다.
- 표시할 최소 1개의 메트릭(`metrics` 매개변수 사용)입니다.

차원 및 메트릭의 수는 차트 렌더링 방식을 결정합니다:

- 1개의 차원과 1개 이상의 메트릭은 각 메트릭에 대해 막대를 표시합니다. 이 막대를 스택하려면 `stacked: true`를 `displayConfig` 아래에 설정합니다. 단일 메트릭을 사용하면 `stacked`는 눈에 띄는 효과가 없습니다.
- 2개의 차원과 1개의 메트릭은 두 번째 차원으로 그룹화된 스택된 막대 차트를 표시합니다. 2개의 차원을 사용하면, 1개의 메트릭만 사용할 수 있으며, GitLab은 `displayConfig.stacked`을(를) 무시합니다.

막대 차트는 첫 번째 행을 맨 아래에 그리므로, 가장 큰 값을 맨 위에 배치하려면 오름차순으로 정렬합니다. 차트 높이는 행이 필요한 만큼이며, 기본 차트 높이까지입니다.

막대 차트는 또한 `displayConfig` 아래에서 이 옵션들을 허용합니다:

- `categoryLabels: valueAndShare`은(는) 각 카테고리의 값과 전체의 비율을 카테고리 레이블에 추가합니다. 예: `Returning · 1,555 · 78%` 기본값인 `plain`은(는) 카테고리 이름만 표시합니다. 이는 `usersCount`, `totalCount`, 또는 `acceptedCount`와 같은 카운트 메트릭에만 적용되며, 1개의 차원과 1개의 메트릭을 사용하며, 그렇지 않으면 무시됩니다. 합계는 표시된 행의 합이므로 비율은 항상 표시된 항목의 100%에 합산됩니다. 비율은 각 항목이 정확히 하나의 카테고리에 속할 때만 의미가 있습니다. 예를 들어, `usersCount`을(를) 사용하면, 여러 카테고리에서 활동하는 사용자는 각 행에서 한 번 계산되므로 비율은 사용자의 비율이 아닙니다. 쿼리가 `limit`을(를) 사용할 때, 합계는 표시된 행만 포함합니다.
- `colorBy: category`은(는) 각 막대에 파란색 스케일에서 고유한 음영을 제공하며, 시리즈마다 한 가지 색상을 사용하는 대신입니다. 맨 위의 막대는 가장 진한 음영을 받으며, 밝은 모드에서는 어둡고 어두운 모드에서는 밝아서 막대가 어느 쪽이든 읽을 수 있도록 유지됩니다. 1개의 차원과 1개의 메트릭이 필요하며, 그렇지 않으면 무시됩니다.
- `showAxisTitles: false`은(는) 두 축의 제목을 모두 숨깁니다.

### 예 {#example-5}

지난 30일 동안 언어별 코드 제안 사용량을 막대 차트로 표시하려면:

````yaml
```glql
display: barChart
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: totalCount
```
````

메트릭을 단일 막대로 스택하려면 나란히 표시하지 않습니다:

````yaml
```glql
display: barChart
displayConfig:
  stacked: true
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: acceptedCount, rejectedCount
```
````

각 언어의 수락된 제안의 비율을 레이블이 지정되고 개별적으로 색상이 지정된 막대로 축 제목 없이 표시하려면:

````yaml
```glql
display: barChart
displayConfig:
  categoryLabels: valueAndShare
  colorBy: category
  showAxisTitles: false
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: acceptedCount
sort: acceptedCount asc
```
````

## 막대 목록 {#bar-list}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/623319)되었습니다.
- `valueLabels`, `color`, 및 `scale` 디스플레이 옵션은 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/628026).
- 차원이 없는 쿼리의 메트릭의 행과 `color: gray`은(는) GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/628932).
- 2차원 스택된 막대 및 `maxSeries` 디스플레이 옵션은 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/groups/gitlab-org/-/work_items/23470).
- `metricRows` 디스플레이 옵션은 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/628025).
- 동적 설명 및 `hiddenMetrics`은(는) GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256879).

{{< /history >}}

막대 목록은 [분석 모드](_index.md#analytics-mode)의 집계 데이터를 가로 막대로 시각화합니다. 기본적으로 각 막대의 길이는 해당 행의 모든 행의 합계의 백분율이며, 가장 큰 행과의 비교가 아닙니다. 막대 목록은 "전체의 어느 정도인가"에 답하는 반면, 막대 차트는 "이들을 서로 어떻게 비교하는가"에 답합니다.

막대 목록에는 다음이 필요합니다:

- `mode: analytics`로 설정된 분석 모드입니다.
- 최대 2개의 `dimensions` 값입니다.
- 최소 1개의 메트릭(`metrics` 매개변수로 설정)입니다.

1개의 차원을 사용하면 각 행은 해당 차원의 값이며 첫 번째 메트릭이 행의 값을 설정합니다. 2개 이상의 메트릭을 이름으로 지정하는 쿼리는 첫 번째를 렌더링하고 나머지를 무시합니다. 행은 값으로 내림차순으로 정렬됩니다. 2개 이상의 차원은 뷰에서 유효성 검사 오류를 발생시키며, 2개의 차원과 함께 2개 이상의 메트릭도 마찬가지입니다.

차원이 없으면 각 메트릭은 쿼리가 이름을 지정하는 순서대로 행이 됩니다. 이를 사용하여 단일 측정의 백분위수 또는 개수를 비교합니다. 예: 중앙값 및 75번째 백분위수 병합 시간입니다. 각 행의 값은 메트릭의 단위로 형식이 지정되므로 기간은 `9h 24m`로 표시되지 않고 밀리초 수로 표시됩니다. 이 행들은 순서를 유지하며, `Other` 행으로 절대로 폴딩되지 않으며, 이전 기간에 비해 변화를 표시하지 않습니다. 응답에 값이 없는 메트릭(예: 병합 요청이 없는 백분위수)은 em dash(`—`)와 빈 막대로 렌더링됩니다.

일부 메트릭은 차원을 삭제할 수 없습니다. 한 시간 버킷을 이전 시간과 비교하는 메트릭(예: `returningUsersCount`)은 날짜 차원이 필요합니다. 쿼리에서 메트릭당 한 행을 가져오려면 `metricRows: true`를 `displayConfig` 아래에 설정합니다. 값은 응답의 첫 번째 행에서 나오므로 원하는 행을 먼저 배치하도록 쿼리를 정렬합니다.

차원을 사용할 때, `maxRows` 옵션은 `displayConfig` 아래에서 각 페이지에 표시되는 행 수를 설정합니다. 기본값은 6이고 행은 값으로 순위가 매겨지며 가장 높은 값부터 시작됩니다. 쿼리가 더 많은 행을 반환할 때, **이전** 및 **다음** 컨트롤은 이미 [자동으로 가져온](#pagination-support) 행을 통해 페이징합니다. 따라서 페이지를 전환해도 새로운 항목이 가져와지지 않습니다. 해당 페치는 1,000행에서 중지되므로 페이징은 최대 처음 1,000행을 포함합니다. 페이지 크기보다 과거의 단일 행은 자신의 페이지를 시작하는 대신 첫 페이지에 유지됩니다. 공유는 모든 페이지의 전체 합계에 대해 상대적입니다. `maxRows` 값이 0보다 큰 정수가 아니면 기본값으로 돌아갑니다.

전체의 비율은 메트릭이 카운트 또는 합일 때만 의미가 있습니다. 평균 또는 중앙값과 같은 메트릭의 경우, 비율 뒤의 합계는 의미가 없습니다.

차원이 없는 막대 목록은 메트릭당 하나의 막대를 렌더링합니다. 설명만을 위해 메트릭을 선택하되 막대를 제공하지 않으려면 `hiddenMetrics` 아래의 `displayConfig`에 추가합니다. 자리표시자 구문 및 `hiddenMetrics` 규칙은 [동적 설명](#dynamic-descriptions)을 참조합니다.

### 1개의 차원 {#one-dimension}

각 행은 차원의 하나의 값입니다.

각 행의 레이블은 막대 끝을 지나서 값을 표시하며, `valueLabels`은(는) `displayConfig` 아래에서 제어됩니다:

- `valueLabels: shareAndValue`이(가) 기본값입니다. 행의 전체의 비율과 컴팩트 값을 표시합니다. 예: `89% · 85.6k`
- `valueLabels: value`은(는) 행의 값만 전체 숫자로 표시합니다. 예: `1,071` 비율보다 개수가 중요할 때 사용합니다.

막대 색상은 `color`에서 `displayConfig` 아래로 설정됩니다:

- `color: orange`이(가) 기본값입니다. 기존 모양과 일치합니다.
- `color: blue`은(는) 다른 GLQL 차트가 첫 번째 시리즈에 사용하는 파란색과 동일한 색상으로 막대를 그립니다. 차트 팔레트의 기본 색상입니다.
- `color: gray`은(는) 색상이 지정된 목록 옆에 표시되는 기준선에 대해 중립적인 회색 막대를 그립니다.

막대 길이는 스케일에 대해 측정되며, `scale`는 `displayConfig` 아래에서 설정됩니다:

- `scale: total`이(가) 기본값입니다. 막대의 길이는 모든 행의 합계 중 행의 비율이므로 트랙은 전체의 100%로 표시되고 막대 뒤의 간격은 나머지 합계입니다.
- `scale: max`은(는) 가장 큰 행이 트랙을 채우게 하고, 다른 모든 막대는 상대적으로 크기를 조정하므로 막대가 행을 서로 비교합니다. 행이 많거나 고르게 분포되어 있고 전체의 비율이 모든 막대를 짧게 남길 때 사용합니다.

레이블은 `scale`에 의해 영향을 받지 않습니다: `valueLabels: shareAndValue`을(를) 사용하면 `scale`이(가) 무엇이든 전체의 비율을 계속 표시합니다.

`valueLabels`, `color`, 또는 `scale`의 다른 값은 뷰에서 유효성 검사 오류를 발생시킵니다.

### 2개의 차원 {#two-dimensions}

각 행은 첫 번째 차원의 값이며, 해당 막대는 두 번째 차원의 값당 하나씩 스택된 세그먼트로 분할되며, 차트 아래에 범례가 있습니다. 행은 컴팩트한 합계로 레이블이 지정됩니다.

`maxSeries` 옵션은 `displayConfig` 아래에서 몇 개의 두 번째 차원 값이 자신의 세그먼트를 가지는지를 제한합니다. 나머지는 `Other (N)` 세그먼트로 결합됩니다. 한계를 초과한 단일 세그먼트는 그대로 유지됩니다. 기본값은 6입니다.

행은 1개의 차원과 동일한 `maxRows` 및 컨트롤로 페이징되며, 각 행은 해당 세그먼트를 유지합니다.

범례 항목을 선택하면 해당 세그먼트가 숨겨지고 나머지 막대와 레이블이 표시되는 합계로 다시 확대/축소됩니다.

`valueLabels`, `color`, 및 `scale` 옵션과 이전 기간 비교는 1개의 차원에만 적용됩니다.

### 예제 {#examples}

지난 30일 동안 언어별 코드 제안 사용량을 막대 목록으로 표시하려면:

````yaml
```glql
display: barList
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: totalCount
```
````

기본 6개 행보다 더 많이 표시하려면:

````yaml
```glql
display: barList
displayConfig:
  maxRows: 10
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: totalCount
```
````

지난 30일 동안 플로우 유형별 Duo 에이전트 플랫폼 세션을 파란색으로 각 레이블의 값만 사용하여 표시하고, 전체 대신 가장 큰 행에 대해 크기 조정된 막대를 사용합니다:

````yaml
```glql
display: barList
displayConfig:
  valueLabels: value
  color: blue
  scale: max
mode: analytics
query: type = AgentPlatformSession and created >= -30d
dimensions: flowType
metrics: usersCount
```
````

지난 30일 동안 병합된 병합 요청에 대한 중앙값 및 75번째 백분위수 병합 시간을 비교하고, 백분위수당 1행 및 더 긴 막대로 트랙을 채웁니다:

````yaml
```glql
display: barList
displayConfig:
  valueLabels: value
  scale: max
mode: analytics
query: type = MergeRequest and merged >= -30d
metrics: timeToMergeQuantile(0.5) as "Median", timeToMergeQuantile(0.75) as "p75"
```
````

기간 중 활성 사용자를 기간 전에 세션을 가진 사용자와 그렇지 않은 사용자로 분할합니다. 각각 1행입니다. 쿼리는 2개의 연속 30일 기간을 포함합니다. `returningUsersCount`은(는) 이전 기간 없이 비교할 것이 없기 때문이며, 가장 최신 버킷을 먼저 정렬하므로 `metricRows`이(가) 나중의 것을 읽습니다. `origin`은(는) 버킷을 범위의 시작으로 고정하므로 Unix 시간부터 계산하는 대신 이와 일치합니다:

````yaml
```glql
display: barList
displayConfig:
  metricRows: true
mode: analytics
query: type = DuoWorkflow and created >= 2026-07-16 and created < 2026-09-14
dimensions: created(granularity=30d, origin=2026-07-16)
metrics: joinedUsersCount as "New", returningUsersCount as "Returning"
sort: created desc
```
````

지난 30일 동안 각 사용자의 세션을 플로우 유형으로 분할하고, 최대 4개의 플로우 유형이 자신의 세그먼트로 사용됩니다:

````yaml
```glql
display: barList
displayConfig:
  maxSeries: 4
mode: analytics
query: type = AgentPlatformSession and created >= -30d
dimensions: user, flowType
metrics: totalCount
```
````

## 선 차트 {#line-chart}

{{< history >}}

- GitLab 19.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/240016)되었습니다.

{{< /history >}}

선 차트는 [분석 모드](_index.md#analytics-mode)의 집계 데이터를 하나 이상의 선으로 시각화합니다. 선 차트를 사용하여 메트릭이 차원(예: 시간 경과)에 따라 어떻게 변하는지 보여줍니다.

선 차트에는 다음이 필요합니다:

- `mode: analytics`로 설정된 분석 모드입니다.
- X축에 대한 정확히 1개의 `dimension`입니다.
- 표시할 최소 1개의 `metric`입니다. 각 메트릭은 별도의 선으로 렌더링됩니다.

### 예 {#example-6}

지난 30일 동안 언어별 코드 제안 사용량을 선 차트로 표시합니다. 전체 제안에 대해 1개의 선, 수락된 제안에 대해 1개의 선이 있습니다:

````yaml
```glql
display: lineChart
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: totalCount, acceptedCount
```
````

## 영역 차트 {#area-chart}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/glql/-/work_items/103)되었습니다.

{{< /history >}}

영역 차트는 [분석 모드](_index.md#analytics-mode)의 집계 데이터를 하나 이상의 채워진 영역으로 시각화합니다. 영역 차트를 사용하여 메트릭이 차원(예: 시간 경과)에 따라 어떻게 변하는지 보여주고, 추세 뒤의 볼륨을 강조합니다.

영역 차트에는 다음이 필요합니다:

- `mode: analytics`로 설정된 분석 모드입니다.
- 결과를 그룹화할 1개 또는 2개의 `dimensions`입니다.
- 표시할 최소 1개의 메트릭(`metrics` 매개변수 사용)입니다.

차원 및 메트릭의 수는 차트 렌더링 방식을 결정합니다:

- 1개의 차원과 1개 이상의 메트릭은 각 메트릭에 대해 영역을 표시합니다. 영역은 반투명 채우기와 겹칩니다. 대신 영역을 누적으로 스택하려면 `stacked: true`를 `displayConfig` 아래에 설정합니다. 단일 메트릭을 사용하면 `stacked`는 눈에 띄는 효과가 없습니다.
- 2개의 차원과 1개의 메트릭은 두 번째 차원으로 그룹화된 스택된 영역 차트를 표시합니다. 2개의 차원을 사용하면, 1개의 메트릭만 사용할 수 있으며, GitLab은 `displayConfig.stacked`을(를) 무시합니다.

### 예 {#example-7}

지난 30일 동안 표시된 및 수락된 코드 제안을 겹치는 영역으로 표시하려면:

````yaml
```glql
display: areaChart
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: timestamp
metrics: shownCount, acceptedCount
```
````

대신 메트릭을 누적으로 스택하려면:

````yaml
```glql
display: areaChart
displayConfig:
  stacked: true
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: timestamp
metrics: shownCount, acceptedCount
```
````

## 히트맵 {#heat-map}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/628031)되었습니다.
- `maxColumns` 및 `maxRows` 디스플레이 옵션은 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/628031).

{{< /history >}}

히트맵은 [분석 모드](_index.md#analytics-mode)의 집계 데이터를 차원 값 쌍마다 하나의 셀을 포함하는 음영이 있는 셀의 그리드로 시각화합니다. 히트맵을 사용하여 단일 메트릭을 두 차원에 걸쳐 비교하고 가장 큰 값이 있는 위치를 확인합니다.

히트맵에는 다음이 필요합니다:

- `mode: analytics`로 설정된 분석 모드입니다.
- 결과를 그룹화할 정확히 2개의 `dimensions`입니다. 첫 번째는 열을 따라 실행되고 두 번째는 행을 따라 실행됩니다.
- 셀에 음영을 칠할 정확히 1개의 메트릭(`metrics` 매개변수 사용)입니다.

각 셀은 값을 표시하며, 값이 올라가면 밝은색에서 어두운색으로 음영이 지정됩니다. 음영은 결과의 값에서 파생된 고정 대역을 사용하므로 더 어두운 셀은 항상 더 큰 값을 의미합니다. 값이 전혀 없는 셀은 가장 밝은 색상보다는 중립적인 회색으로 음영이 지정되어 작은 값이 없는 값으로 잘못 해석되지 않도록 합니다. 셀을 가리키면 행, 열, 정확한 값이 표시됩니다.

그리드 위의 패널을 설명하려면 `description`를 `displayConfig` 아래에 설정합니다.

그리드가 그리는 차원 값의 개수를 제한하려면 `maxColumns` 또는 `maxRows`를 `displayConfig` 아래에 설정합니다. `maxColumns`는 열을 따라 실행되는 첫 번째 차원을 제한하고, `maxRows`는 행을 따라 실행되는 두 번째 차원을 제한합니다. 유지된 값은 가장 큰 값이며, 다른 축 전체에서 메트릭으로 순위가 매겨지며, 제한된 축은 가장 크기부터 정렬되고 이름으로 동점이 깨집니다. 이 순서는 `sort`이(가) 해당 축에 제공하는 순서를 대체합니다. 다른 축은 여전히 쿼리를 따릅니다.

한계를 초과한 값은 삭제되고, 그리드의 아무것도 누락된 값을 표시하지 않으므로 패널 제목이나 설명에 한계를 명시합니다. 어느 옵션도 기본값이 없으며, 0보다 큰 정수가 아닌 값은 무시됩니다.

### 예 {#example-8}

지난 30일 동안 IDE 및 언어 전반의 코드 제안 볼륨을 비교하려면:

````yaml
```glql
display: heatMap
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: ideName, language
metrics: totalCount
```
````

그리드 위에 설명을 추가하려면:

````yaml
```glql
display: heatMap
displayConfig:
  description: Code Suggestions accepted per language, by IDE.
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: ideName, language
metrics: acceptedCount
```
````

가장 바쁜 5개의 IDE만 표시하려면:

````yaml
```glql
display: heatMap
displayConfig:
  description: Code Suggestions accepted per language, for the five busiest IDEs.
  maxColumns: 5
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: ideName, language
metrics: acceptedCount
```
````

## 발산형 막대 차트 {#diverging-bar-chart}

발산형 막대 차트는 [분석 모드](_index.md#analytics-mode)의 집계 데이터를 공유된 중앙 카테고리 열 주위에 미러링된 두 메트릭으로 시각화합니다. 첫 번째 메트릭의 막대는 중앙에서 왼쪽으로 증가하고, 두 번째 메트릭의 막대는 오른쪽으로 증가합니다. 발산형 막대 차트를 사용하여 절대적으로 한 메트릭이 다른 메트릭을 능가할 수 있는 경우 카테고리 전체의 두 메트릭을 비교합니다.

차트의 각 반쪽은 자신의 가장 큰 막대에 독립적으로 확대/축소됩니다. 이는 카테고리가 한 메트릭의 작은 비율이고 다른 메트릭의 대부분이 될 수 있으며, 두 막대가 여전히 차트의 자신의 쪽을 채울 수 있음을 의미합니다. 두 반쪽이 다른 스케일을 사용하기 때문에 막대 길이는 반쪽 내에서만 비교 가능하며, 절대로 중앙을 가로질러 비교할 수 없습니다.

발산형 막대 차트에는 다음이 필요합니다:

- `mode: analytics`로 설정된 분석 모드입니다.
- 결과를 그룹화할 `dimensions`의 정확히 1개 값입니다.
- 표시할 정확히 2개의 메트릭(`metrics` 매개변수 사용)입니다.

정확히 1개의 차원 및 정확히 2개의 메트릭 이외의 모든 것은 뷰에서 유효성 검사 오류를 발생시킵니다.

행은 쿼리가 반환하는 순서대로 렌더링됩니다. `sort`을(를) 사용하여 이 순서를 제어합니다. 발산형 막대 차트는 행을 정렬하지 않습니다. 각 메트릭의 값은 메트릭의 자신의 단위로 형식이 지정되므로 카운트와 비율을 쌍으로 만들 수 있습니다.

카테고리 열은 차트 너비의 비율이므로 맞지 않는 카테고리 레이블이 잘립니다. 좁은 패널에서는 카테고리 이름을 짧게 유지합니다.

이 디스플레이 유형에 대한 `displayConfig` 옵션이 없습니다.

### 예 {#example-9}

GitLab Duo 에이전트 플랫폼의 고유 사용자 수를 플로우 유형별로 그룹화된 세션의 총 개수와 비교하며, 지난 30일 동안:

````yaml
```glql
display: divergingBarChart
mode: analytics
query: type = AgentPlatformSession and created >= -30d
dimensions: flowType
metrics: usersCount, totalCount
sort: totalCount desc
```
````

## 동적 설명 {#dynamic-descriptions}

{{< history >}}

- 단일 통계를 위한 동적 설명은 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255287).
- 막대 목록 및 테이블를 위한 동적 설명은 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256879).
- 막대 목록 및 테이블을 위한 `hiddenMetrics`은(는) GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256879).

{{< /history >}}

`stat`, `barList`, 및 `table` 디스플레이 유형은 [분석 모드](_index.md#analytics-mode)에서 동적 설명을 지원합니다. 설명을 사용하여 시각화 옆에 있는 문장에서 결과를 요약합니다.

결과를 설명하려면 `description`를 `displayConfig` 아래에 설정합니다. 설명에는 `%{metricName}` 자리표시자가 포함될 수 있으며, 여기서 `metricName`는(는) `metrics`의 메트릭을 식별합니다. GitLab은 각 자리표시자를 메트릭의 값으로 바꾸고 해당 메트릭의 자신의 단위로 형식을 지정합니다. 쿼리가 선택하지 않은 메트릭의 이름을 지정하는 자리표시자는 유효성 검사 오류를 표시합니다. 메트릭의 값이 응답에서 누락되면 해당 자리표시자는 em dash(`—`)로 렌더링됩니다.

메트릭은 항상 키 이름으로 식별되며, 중복된 매개변수화된 메트릭인 경우 식별하려면 별칭이 필요합니다. 예를 들어, `metrics: totalCount as "count"`은(는) 여전히 `%{totalCount}`로 참조되며, 별칭은 레이블만 설정합니다. 같은 메트릭이 `metrics: durationQuantile(0.5) as "Median", durationQuantile(0.95) as "p95 duration"`와 같이 다른 매개변수로 두 번 나타날 때, 각 별칭이 키가 되므로 `%{Median}` 및 `%{p95 duration}`로 참조합니다.

막대 목록 및 테이블의 경우, 쿼리에 `dimensions`이(가) 있을 때 설명이 자리표시자를 사용할 수 없습니다. 이는 뷰에서 유효성 검사 오류를 발생시킵니다: `Description placeholders cannot be used with dimensions.` 자리표시자는 단일 행을 읽으므로 차원으로 인해 모든 그룹을 포함하는 것처럼 한 그룹의 값을 표시합니다. 자리표시자가 없는 설명은 여전히 차원에서 작동합니다.

막대 목록 및 테이블의 경우, `hiddenMetrics`를 `displayConfig` 아래에 설정하여 막대 또는 열에서 제외할 메트릭의 목록을 설정합니다. 자리표시자와 동일한 방식으로 이름을 지정합니다. 중복된 메트릭을 기본 이름(예: `durationQuantile`)으로 이름을 지정하면 이의 모든 복사본이 숨겨집니다. GitLab은 여전히 이 메트릭을 실행하므로 설명이 인용할 수 있습니다. `hiddenMetrics` 값이 목록이 아니거나 쿼리의 메트릭 중 하나가 아닌 이름은 뷰에서 유효성 검사 오류를 발생시킵니다. 막대 목록은 `hiddenMetrics`에서 최소 1개의 메트릭을 제외해야 합니다.

설명은 시각화 위에 렌더링됩니다. 쿼리가 로드되는 동안, 자리표시자를 포함하는 설명은 숨겨진 상태로 유지되므로 아직 없는 값에 대해 em dash를 깜박이지 않습니다.

### 예 {#example-10}

GitLab Duo에서 생성된 병합 요청에 대한 중앙값 및 75번째 백분위수 병합 시간을 표시하고, 세 번째 막대를 그리지 않고 몇 개가 병합되었는지 인용하려면:

````yaml
```glql
display: barList
mode: analytics
query: type = MergeRequest and createdByDuo = true and merged >= -30d
metrics: timeToMergeQuantile(0.5) as "Median", timeToMergeQuantile(0.75) as "p75", throughputCount
displayConfig:
  description: "%{throughputCount} merged merge requests"
  hiddenMetrics: [throughputCount]
```
````

## 페이지 매김 지원 {#pagination-support}

{{< history >}}

- 분석 모드 시각화를 위한 자동 페이지 매김은 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/glql/-/work_items/170).

{{< /history >}}

모든 모드에서 사용 가능한 디스플레이 유형은 결과의 첫 페이지를 표시하고 추가 페이지를 가져오기 위한 **더 보기** 작업을 제공합니다. 자세한 내용은 [페이지 매김](_index.md#pagination)을 참조합니다.

분석 모드 집계 시각화(예: 차트 및 통계)는 **더 보기** 작업을 제공하지 않습니다. 최대 1,000행까지 자동으로 집계 결과의 모든 페이지를 가져옵니다.

쿼리가 1,000개 이상의 집계 행을 반환하면 시각화는 처음 1,000행을 표시합니다. 모든 데이터를 보려면 쿼리에 필터를 추가하거나 더 적은 차원으로 그룹화합니다.

대신 단일 페이지를 표시하려면 블록에서 `limit`을(를) 설정합니다. 시각화는 최대 100까지 최대 해당 많은 행을 표시합니다.
