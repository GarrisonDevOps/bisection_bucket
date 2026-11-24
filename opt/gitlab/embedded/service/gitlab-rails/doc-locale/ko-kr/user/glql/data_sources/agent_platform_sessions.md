---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 에이전트 플랫폼 세션
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/592423)되었습니다.
- `daily` 및 고정 기간 `granularity` 값(대상: `created`) [GitLab 19.5에서 도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/528)
- `!=` 및 `not in` 연산자(대상: `flowType` 및 `user` 필터) [GitLab 19.5에서 도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/537)

{{< /history >}}

이 데이터 소스는 프로젝트 또는 그룹 전체에서 GitLab Duo 에이전트 플랫폼 세션 사용량에 대한 집계된 메트릭을 제공합니다.

## 허용된 모드 {#allowed-modes}

- [`analytics`](../_index.md#analytics-mode)

## 허용된 범위 {#allowed-scopes}

| 범위     | 설명 |
|-----------|-------------|
| `project` | 특정 프로젝트에서 GitLab Duo 에이전트 플랫폼 세션을 쿼리합니다. |
| `group`   | 하위 그룹을 포함하여 그룹의 모든 프로젝트 전체에서 GitLab Duo 에이전트 플랫폼 세션을 쿼리합니다. |

여러 그룹 또는 프로젝트 전체에서 GitLab Duo 에이전트 플랫폼 세션을 집계하려면 `in` 연산자를 포함한 목록을 사용합니다. 자세한 내용은 [여러 그룹 및 프로젝트](_index.md#multiple-groups-and-projects)를 참고하세요.

## 쿼리 필터 {#query-filters}

`query` 매개변수의 이 필드들을 사용하여 결과를 필터링합니다.

| 필드                   | 이름(및 별칭)                                | 연산자                 |
| ----------------------- | ----------------------------------------------- | ------------------------- |
| [생성됨](#created)     | `created`(`opened`, `openedAt`, `createdAt`)   | `=`, `>`, `<`, `>=`, `<=` |
| [플로우 유형](#flow-type) | `flowType`                                      | `=`, `!=`, `in`, `not in` |
| [사용자](#user)           | `user`                                          | `=`, `!=`, `in`, `not in` |

### 생성됨 {#created}

**Description (설명)**: 세션이 생성된 시기를 기준으로 필터링합니다. 범위 연산자를 사용하여 시간 창을 정의합니다.

**허용된 값 유형**:

- `AbsoluteDate`(형식: `YYYY-MM-DD`)
- `RelativeDate`(형식: `<sign><digit><unit>`, 부호는 `+`, `-` 또는 생략, 숫자는 정수, `unit`는 `d`(일), `w`(주), `m`(월) 또는 `y`(년) 중 하나)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자의 시간대에서 00:00~23:59로 간주됩니다.

### 플로우 유형 {#flow-type}

**Description (설명)**: 세션의 플로우 유형을 기준으로 필터링합니다. 예를 들어 `chat` 또는 `code_review/v1`입니다.

**허용된 값 유형**:

- `String`
- `List`(여러 값의 경우 `in` 또는 `not in` 연산자 사용)

### 사용자 {#user}

**Description (설명)**: 세션을 소유한 사용자를 기준으로 필터링합니다.

**허용된 값 유형**:

- `Number`(사용자 ID)
- `List`(여러 사용자 ID의 경우 `in` 또는 `not in` 연산자 사용)

> [!note]
> 사용자 이름 필터링에 대한 지원은 [이슈 599750](https://gitlab.com/gitlab-org/gitlab/-/work_items/599750)에서 추적 중입니다.

## 차원 {#dimensions}

| 차원 | 이름       | 설명 |
|-----------|------------|-------------|
| 생성됨   | `created`  | 날짜별로 그룹화합니다. [`granularity` 매개변수](../_index.md#field-parameters)를 `daily`, `weekly`, `monthly` 또는 `30d`과 같은 일 수(기본값: `weekly`)로 받으며, 선택 사항인 `origin`도 받습니다. 예를 들어 `created(monthly)` 또는 `created(granularity=30d, origin=2026-07-16)`입니다. |
| 플로우 유형 | `flowType` | 세션 플로우 유형별로 그룹화합니다. |
| 프로젝트   | `project`  | 프로젝트별로 그룹화합니다. 프로젝트로 범위가 지정되지 않은 세션은 프로젝트 없이 단일 행으로 그룹화됩니다. |
| 사용자      | `user`     | 사용자별로 그룹화합니다(아바타, 이름 및 사용자 이름 표시). |

## 메트릭 {#metrics}

| 메트릭            | 이름               | 설명 |
|-------------------|--------------------|-------------|
| 완료율   | `completionRate`   | 완료된 세션의 비율(0~1 범위의 값). |
| 최대 기간      | `durationMax`      | 가장 긴 완료된 세션 기간(초). |
| 평균 기간     | `durationMean`     | 완료된 세션의 평균 기간(초). |
| 최소 기간      | `durationMin`      | 가장 짧은 완료된 세션 기간(초). |
| 기간 분위수 | `durationQuantile` | 주어진 분위수의 완료된 세션의 기간(초). [`quantile` 매개변수](../_index.md#field-parameters)를 `0.01`~`0.99` 범위(기본값: `0.5`)로 받습니다. 예를 들어, `durationQuantile(0.95)`입니다. |
| 기간 합계      | `durationSum`      | 완료된 세션의 총 기간(초). |
| 완료 수    | `finishedCount`    | 완료된 세션 수. |
| 전체 수       | `totalCount`       | 총 세션 수. |
| 사용자 수       | `usersCount`       | 고유 사용자 수. |

## 정렬 필드 {#sort-fields}

모든 차원 또는 다음 메트릭 중 하나로 정렬합니다:

- `totalCount`
- `finishedCount`
- `usersCount`
- `completionRate`
- `durationQuantile`
- `durationMean`
- `durationMin`
- `durationMax`
- `durationSum`

자세한 내용은 [분석 모드 정렬](../_index.md#sorting)을 참고하세요.

## 예제 {#examples}

- 지난 30일 동안의 플로우 유형별 세션:

  ````yaml
  ```glql
  title: "Agent Platform sessions by flow (last 30 days)"
  display: table
  mode: analytics
  query: type = AgentPlatformSession and group = "gitlab-org" and created > -30d
  dimensions: flowType as "Flow"
  metrics: totalCount as "Total", finishedCount as "Finished", completionRate as "Completion rate"
  sort: totalCount desc
  ```
  ````

- 주간 세션 추세:

  ````yaml
  ```glql
  title: "Weekly Agent Platform session trend"
  display: columnChart
  mode: analytics
  query: type = AgentPlatformSession and group = "gitlab-org" and created > -90d
  dimensions: created(weekly) as "Week"
  metrics: totalCount as "Total", usersCount as "Users"
  sort: created desc
  ```
  ````

- 사용자당 세션(평균 기간 포함):

  ````yaml
  ```glql
  title: "Agent Platform sessions by user"
  display: table
  mode: analytics
  query: type = AgentPlatformSession and group = "gitlab-org" and created > -30d
  dimensions: user as "User"
  metrics: totalCount as "Total", durationMean as "Avg duration"
  sort: totalCount desc
  limit: 10
  ```
  ````

- 전체 완료율 및 중앙값 기간(그룹화 없음):

  ````yaml
  ```glql
  title: "Agent Platform session completion (last 30 days)"
  display: table
  mode: analytics
  query: type = AgentPlatformSession and group = "gitlab-org" and created > -30d
  metrics: totalCount as "Total", completionRate as "Completion rate", durationQuantile(0.5) as "Median duration"
  ```
  ````
