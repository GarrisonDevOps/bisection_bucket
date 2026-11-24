---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 병합 요청 분석
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21214)되었습니다.
- `timeToMergeQuantile` [변경됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/501)으로 GitLab 19.5에서 초 단위로 보고합니다.
- `timeToMergeMin`, `timeToMergeMax`, `timeToMergeMean`, 그리고 `timeToMergeSum` 메트릭 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/507) GitLab 19.5에서.
- `createdByDuo` 필터 및 차원, 그리고 `acceptanceRate` 메트릭 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/518) GitLab 19.5에서.
- `!=` 그리고 `not in` 연산자는 `state` 및 `targetBranch` 필터에서 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/537) GitLab 19.5에서.

{{< /history >}}

분석 모드는 병합 요청에 대한 집계된 메트릭을 반환하며, 일반적으로 10분 이내에 데이터를 사용할 수 있습니다.

개별 병합 요청 레코드를 쿼리하려면 [병합 요청](merge_requests.md)을 사용하세요.

## 허용되는 범위 {#allowed-scopes}

| 범위     | 설명                                                               |
| --------- | -------------------------------------------------------------------------- |
| `project` | 특정 프로젝트의 병합 요청을 쿼리합니다.                               |
| `group`   | 서브그룹을 포함한 그룹의 모든 프로젝트에서 병합 요청을 쿼리합니다. |

여러 그룹이나 프로젝트에서 병합 요청을 집계하려면 `in` 연산자로 목록을 사용하세요. 자세한 내용은 [여러 그룹 및 프로젝트](_index.md#multiple-groups-and-projects)를 참조하세요.

## 쿼리 필터 {#query-filters}

`query` 매개변수에서 이러한 필드를 사용하여 결과를 필터링하세요.

| 필드                              | 이름           | 연산자                 |
| ---------------------------------- | -------------- | ------------------------- |
| [생성된 날짜](#created-at)          | `created`      | `=`, `>`, `<`, `>=`, `<=` |
| [Duo로 생성됨](#created-by-duo)  | `createdByDuo` | `=`, `!=`                 |
| [병합된 날짜](#merged-at)            | `merged`       | `=`, `>`, `<`, `>=`, `<=` |
| [상태](#state)                    | `state`        | `=`, `!=`, `in`, `not in` |
| [대상 브랜치](#target-branch)    | `targetBranch` | `=`, `!=`, `in`, `not in` |

### 생성된 날짜 {#created-at}

**Description (설명)**: 생성 날짜별로 병합 요청을 필터링합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (형식 `YYYY-MM-DD`에서)
- `RelativeDate` (형식 `<sign><digit><unit>`에서, 부호가 `+`, `-`, 또는 생략되며, 숫자는 정수이고 `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (연도) 중 하나입니다)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지 간주됩니다.

### Duo로 생성됨 {#created-by-duo}

**Description (설명)**: GitLab Duo Agent Platform 세션이 생성했는지 여부별로 병합 요청을 필터링합니다.

**허용되는 값 유형**:

- `Boolean` (`true` 또는 `false`)

### 병합된 날짜 {#merged-at}

**Description (설명)**: 병합 날짜별로 병합 요청을 필터링합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (형식 `YYYY-MM-DD`에서)
- `RelativeDate` (형식 `<sign><digit><unit>`에서, 부호가 `+`, `-`, 또는 생략되며, 숫자는 정수이고 `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (연도) 중 하나입니다)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지 간주됩니다.

### 상태 {#state}

**Description (설명)**: 상태별로 병합 요청을 필터링합니다.

**허용되는 값 유형**:

- `Enum`, 즉 `opened`, `closed`, `merged`, 또는 `locked` 중 하나
- `List` (여러 값의 경우 `in` 또는 `not in` 연산자 사용)

**노트**:

- `all` 값은 지원되지 않습니다. 모든 상태의 병합 요청을 포함하려면 필터를 생략하세요.

### 대상 브랜치 {#target-branch}

**Description (설명)**: 대상 브랜치별로 병합 요청을 필터링합니다.

**허용되는 값 유형**:

- `String`
- `List` (여러 값의 경우 `in` 또는 `not in` 연산자 사용)

## 차원 {#dimensions}

| 차원     | 이름           | 설명                              |
| ------------- | -------------- | ---------------------------------------- |
| 생성된 날짜    | `created`      | 생성 날짜별로 그룹화합니다. `daily`, `weekly`, `monthly`, 또는 `30d` 같은 일 수의 [`granularity` 매개변수](../_index.md#field-parameters)를 허용합니다 (기본값: `weekly`), 그리고 선택적인 `origin`. 예를 들어 `created(monthly)` 또는 `created(granularity=30d, origin=2026-07-16)`입니다. |
| Duo로 생성됨 | `createdByDuo` | GitLab Duo Agent Platform 세션이 병합 요청을 생성했는지 여부별로 그룹화합니다. |
| 병합된 날짜     | `merged`       | 병합 날짜별로 그룹화합니다. `daily`, `weekly`, `monthly`, 또는 `30d` 같은 일 수의 [`granularity` 매개변수](../_index.md#field-parameters)를 허용합니다 (기본값: `weekly`), 그리고 선택적인 `origin`. 예를 들어 `merged(monthly)` 또는 `merged(granularity=30d, origin=2026-07-16)`입니다. |
| 상태         | `state`        | 병합 요청 상태별로 그룹화합니다.            |
| 대상 브랜치 | `targetBranch` | 대상 브랜치별로 그룹화합니다.                  |

## 메트릭 {#metrics}

| 메트릭                 | 이름                   | 설명                              |
| ---------------------- | ---------------------- | ---------------------------------------- |
| 승인 비율        | `acceptanceRate`       | 병합된 병합 요청의 비율. |
| 처리량 개수       | `throughputCount`      | 병합된 병합 요청의 개수.         |
| 병합까지의 최대 시간      | `timeToMergeMax`       | 생성에서 병합까지의 최대 시간 (초). |
| 병합까지의 평균 시간     | `timeToMergeMean`      | 생성에서 병합까지의 평균 시간 (초). |
| 병합까지의 최소 시간      | `timeToMergeMin`       | 생성에서 병합까지의 최소 시간 (초). |
| 병합까지의 백분위수 시간 | `timeToMergeQuantile`  | 생성에서 병합까지의 시간 (초), 지속 시간으로 렌더링됩니다. 예를 들어, `1d 2h`입니다. `0.01`와 `0.99` 사이의 [`quantile` 매개변수](../_index.md#field-parameters)를 허용합니다 (기본값: `0.5`, 중앙값). 예를 들어, `timeToMergeQuantile(0.95)`입니다. |
| 병합까지의 합계 시간      | `timeToMergeSum`       | 모든 병합된 병합 요청에서 생성에서 병합까지의 총 시간 (초). |
| 총 개수            | `totalCount`           | 병합 요청의 총 개수.          |

## 필드 정렬 {#sort-fields}

선택한 차원 또는 메트릭에 포함된 모든 필드별로 정렬합니다. 자세한 내용은 [분석 모드 정렬](../_index.md#sorting)을 참조하세요.

## 예제 {#examples}

- 지난 30일의 주간 병합 요청 처리량 추세:

  ````yaml
  ```glql
  title: "Weekly merge request throughput (last 30 days)"
  display: table
  mode: analytics
  query: type = MergeRequest and project = "gitlab-org/gitlab" and merged > -30d
  dimensions: merged(weekly) as "Week"
  metrics: totalCount as "Total", throughputCount as "Merged", timeToMergeQuantile(0.5) as "Median time to merge"
  sort: merged desc
  ```
  ````

- 주별 중앙값 및 p95 병합까지 시간:

  ````yaml
  ```glql
  title: "Median and p95 time to merge by week"
  display: table
  mode: analytics
  query: type = MergeRequest and project = "gitlab-org/gitlab" and merged > -90d
  dimensions: merged(weekly) as "Week"
  metrics: timeToMergeQuantile(0.5) as "Median time to merge", timeToMergeQuantile(0.95) as "p95 time to merge"
  sort: merged desc
  ```
  ````

- 상태별로 그룹화된 병합 요청

  ````yaml
  ```glql
  title: "Merge requests by state (last 30 days)"
  display: table
  mode: analytics
  query: type = MergeRequest and project = "gitlab-org/gitlab" and created > -30d
  dimensions: state as "State"
  metrics: totalCount as "Total"
  sort: totalCount desc
  ```
  ````

- 그룹 전체의 대상 브랜치별 처리량:

  ````yaml
  ```glql
  title: "Merge request throughput by target branch"
  display: table
  mode: analytics
  query: type = MergeRequest and group = "gitlab-org" and merged > -30d
  dimensions: targetBranch as "Target branch"
  metrics: totalCount as "Total", throughputCount as "Merged"
  sort: throughputCount desc
  ```
  ````

- GitLab Duo가 생성한 병합 요청과 다른 병합 요청의 승인 비율:

  ````yaml
  ```glql
  title: "Merge request acceptance rate by origin (last 30 days)"
  display: table
  mode: analytics
  query: type = MergeRequest and group = "gitlab-org" and created > -30d
  dimensions: createdByDuo as "Created by Duo"
  metrics: totalCount as "Total", throughputCount as "Merged", acceptanceRate as "Acceptance rate"
  sort: totalCount desc
  ```
  ````

- 그룹 전체의 병합 요청 개수 (그룹화 없음):

  ````yaml
  ```glql
  title: "Merge requests created in the last 7 days"
  display: table
  mode: analytics
  query: type = MergeRequest and group = "gitlab-org" and created > -7d
  metrics: totalCount as "Total"
  ```
  ````
