---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 파이프라인 분석
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.1에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21212)되었습니다.
- GitLab 19.2에서 진행 중인 파이프라인을 포함한 모든 상태의 파이프라인을 다루도록 [변경](https://gitlab.com/gitlab-org/glql/-/merge_requests/416)했습니다.
- 구성 가능한 `granularity` 및 `quantile` 매개변수가 GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/glql/-/issues/130)되었습니다.
- `durationMin`, `durationMax`, `durationMean`, `durationSum` 메트릭이 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/507)되었습니다.
- `!=` 및 `not in` 연산자가 `ref`, `source`, `status` 필터에서 GitLab 19.5에 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/537)되었습니다.

{{< /history >}}

분석 모드는 진행 중인 파이프라인을 포함한 모든 상태의 파이프라인에 대해 집계된 메트릭을 반환하며, 일반적으로 10분 이내에 데이터를 사용할 수 있습니다.

개별 파이프라인 레코드를 쿼리하려면 [파이프라인](pipelines.md)을 사용하세요.

## 허용 범위 {#allowed-scopes}

| 범위     | 설명                                                          |
| --------- | -------------------------------------------------------------------- |
| `project` | 특정 프로젝트의 파이프라인을 쿼리합니다.                               |
| `group`   | 하위 그룹을 포함한 그룹의 모든 프로젝트에서 파이프라인을 쿼리합니다. |

여러 그룹 또는 프로젝트에서 파이프라인을 집계하려면 `in` 연산자와 함께 목록을 사용하세요. 자세한 내용은 [여러 그룹 및 프로젝트](_index.md#multiple-groups-and-projects)를 참조하세요.

## 쿼리 필터 {#query-filters}

결과를 필터링하려면 `query` 매개변수에서 이 필드들을 사용하세요.

| 필드                                  | 이름       | 연산자                 |
| -------------------------------------- | ---------- | ------------------------- |
| [완료 시간](#finished-at)         | `finished` | `=`, `>`, `<`, `>=`, `<=` |
| [브랜치](#ref)                         | `ref`      | `=`, `!=`, `in`, `not in` |
| [소스](#source)                   | `source`   | `=`, `!=`, `in`, `not in` |
| [시작 시간](#started-at)           | `started`  | `=`, `>`, `<`, `>=`, `<=` |
| [상태](#status)                   | `status`   | `=`, `!=`, `in`, `not in` |

### 완료 시간 {#finished-at}

**Description (설명)**: 완료 날짜로 파이프라인을 필터링합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (형식 `YYYY-MM-DD`)
- `RelativeDate` (형식 `<sign><digit><unit>`, 부호는 `+`, `-`, 또는 생략되며, 숫자는 정수이고, `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (년) 중 하나)

**노트**:

- `=` 연산자의 경우, 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지로 간주됩니다.

### 브랜치 {#ref}

**Description (설명)**: 실행된 Git 브랜치 또는 태그 이름으로 파이프라인을 필터링합니다.

**허용되는 값 유형**:

- `String`
- `List` (여러 값에는 `in` 또는 `not in` 연산자 사용)

**노트**:

- `!=` 및 `not in`는 브랜치가 있는 파이프라인만 반환합니다. 브랜치가 없는 파이프라인은 제외되므로, `ref != "main"`는 `main`의 파이프라인을 제외한 모든 파이프라인과 동일하지 않습니다.

### 소스 {#source}

**Description (설명)**: 트리거 이벤트로 파이프라인을 필터링합니다.

**허용되는 값 유형**:

- `String`
- `List` (여러 값에는 `in` 또는 `not in` 연산자 사용)

**노트**:

- `!=` 및 `not in`는 소스가 있는 파이프라인만 반환합니다. 소스가 없는 파이프라인은 제외됩니다.
- GitLab이 인식하지 않는 소스를 제외하면 아무것도 제외되지 않습니다. 소스 값의 유효성 검사는 [이슈 629846](https://gitlab.com/gitlab-org/gitlab/-/issues/629846)에서 제안되었습니다.

### 시작 시간 {#started-at}

**Description (설명)**: 시작 날짜로 파이프라인을 필터링합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (형식 `YYYY-MM-DD`)
- `RelativeDate` (형식 `<sign><digit><unit>`, 부호는 `+`, `-`, 또는 생략되며, 숫자는 정수이고, `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (년) 중 하나)

**노트**:

- `=` 연산자의 경우, 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지로 간주됩니다.

### 상태 {#status}

**Description (설명)**: CI/CD 상태로 파이프라인을 필터링합니다.

**허용되는 값 유형**:

- `Enum`, `canceled`, `canceling`, `created`, `failed`, `manual`, `pending`, `preparing`, `running`, `scheduled`, `skipped`, `success`, `waiting_for_callback` 또는 `waiting_for_resource` 중 하나
- `List` (여러 값에는 `in` 또는 `not in` 연산자 사용)

## 차원 {#dimensions}

| 차원   | 이름       | 설명                              |
| ----------- | ---------- | ---------------------------------------- |
| 완료 시간 | `finished` | 완료 날짜로 그룹화합니다. [`granularity` 매개변수](../_index.md#field-parameters)를 수락하며, `daily`, `weekly`, `monthly`, 또는 `30d`과 같은 날짜 수 (기본값: `weekly`), 및 선택적 `origin`를 수락합니다. 예를 들어 `finished(daily)` 또는 `finished(granularity=30d, origin=2026-07-16)`입니다. |
| 프로젝트     | `project`  | 프로젝트별로 그룹화합니다.                        |
| 브랜치         | `ref`      | Git 브랜치 또는 태그별로 그룹화합니다.        |
| 소스      | `source`   | 파이프라인을 트리거한 항목으로 그룹화합니다.    |
| 시작 시간  | `started`  | 시작 날짜로 그룹화합니다. [`granularity` 매개변수](../_index.md#field-parameters)를 수락하며, `daily`, `weekly`, `monthly`, 또는 `30d`과 같은 날짜 수 (기본값: `weekly`), 및 선택적 `origin`를 수락합니다. 예를 들어 `started(daily)` 또는 `started(granularity=30d, origin=2026-07-16)`입니다. |
| 상태      | `status`   | 파이프라인 상태별로 그룹화합니다.                |

## 메트릭 {#metrics}

파이프라인은 처리를 완료하고 최종 상태(성공, 실패, 취소 또는 건너뜀)에 도달했을 때 완료된 것으로 간주됩니다.

| 메트릭            | 이름               | 설명                                            |
| ----------------- | ------------------ | ------------------------------------------------------ |
| 취소율     | `canceledRate`     | 취소된 파이프라인과 완료된 파이프라인의 비율입니다.    |
| 최대 소요 시간      | `durationMax`      | 가장 긴 파이프라인 소요 시간(초)입니다.                |
| 평균 소요 시간     | `durationMean`     | 평균 파이프라인 소요 시간(초)입니다.                |
| 최소 소요 시간      | `durationMin`      | 가장 짧은 파이프라인 소요 시간(초)입니다.               |
| 소요 시간 분위수 | `durationQuantile` | 파이프라인 소요 시간 분위수(초)입니다. [`quantile` 매개변수](../_index.md#field-parameters)를 수락하며, `0.01`에서 `0.99` 사이 (기본값: `0.95`)입니다. 예를 들어, `durationQuantile(0.5)`입니다. |
| 총 소요 시간      | `durationSum`      | 모든 파이프라인의 총 소요 시간(초)입니다.          |
| 실패율      | `failureRate`      | 실패한 파이프라인과 완료된 파이프라인의 비율입니다.      |
| 건너뜬 비율      | `skippedRate`      | 건너뜬 파이프라인과 완료된 파이프라인의 비율입니다.     |
| 성공률      | `successRate`      | 성공한 파이프라인과 완료된 파이프라인의 비율입니다.  |
| 총 개수       | `totalCount`       | 진행 중인 파이프라인을 포함한 총 파이프라인 수입니다. |

## 정렬 필드 {#sort-fields}

선택한 차원 또는 메트릭에 포함된 모든 필드로 정렬합니다. 자세한 내용은 [분석 모드 정렬](../_index.md#sorting)을 참조하세요.

## 예제 {#examples}

- 지난 30일간의 브랜치별 파이프라인 성공률 및 실패율:

  ````yaml
  ```glql
  title: "Pipeline success and failure rates by branch (last 30 days)"
  display: table
  mode: analytics
  query: type = Pipeline and project = "gitlab-org/gitlab" and finished >= -30d
  dimensions: ref as "Ref"
  metrics: totalCount as "Total", successRate as "Success rate", failureRate as "Failure rate"
  sort: totalCount desc
  ```
  ````

- `success`이 아닌 다른 상태의 파이프라인, 기본 브랜치를 벗어난 파이프라인, 지난 30일:

  ````yaml
  ```glql
  title: "Pipelines not successful, off the default branches (last 30 days)"
  display: table
  mode: analytics
  query: type = Pipeline and project = "gitlab-org/gitlab" and finished >= -30d and status != success and ref not in ("main", "master")
  dimensions: ref as "Ref"
  metrics: totalCount as "Pipelines", failureRate as "Failure rate"
  sort: totalCount desc
  limit: 10
  ```
  ````

- 특정 브랜치에 대한 주간 파이프라인 소요 시간 추이:

  ````yaml
  ```glql
  title: "Weekly pipeline duration trend for master"
  display: table
  mode: analytics
  query: type = Pipeline and project = "gitlab-org/gitlab" and ref = "master" and finished >= -90d
  dimensions: finished as "Week"
  metrics: totalCount as "Total", durationQuantile as "p95 duration (s)"
  sort: finished desc
  ```
  ````

- 주간 중앙값 및 p95 파이프라인 소요 시간:

  ````yaml
  ```glql
  title: "Median and p95 pipeline duration by week"
  display: table
  mode: analytics
  query: type = Pipeline and project = "gitlab-org/gitlab" and finished >= -90d
  dimensions: finished(weekly) as "Week", status as "Status"
  metrics: durationQuantile(0.5) as "Median", durationQuantile(0.95) as "p95", totalCount as "Total"
  sort: Median desc
  ```
  ````

- 그룹의 전체 파이프라인 메트릭, 그룹화 없음:

  ````yaml
  ```glql
  title: "Overall pipeline metrics for gitlab-org"
  display: table
  mode: analytics
  query: type = Pipeline and group = "gitlab-org" and finished >= -7d
  metrics: totalCount as "Total", successRate as "Success rate", failureRate as "Failure rate", canceledRate as "Canceled rate"
  ```
  ````

- 소스 및 상태별로 그룹화된 파이프라인, 날짜 범위로 필터링:

  ````yaml
  ```glql
  title: "Pipelines by source and status (Q1 2026)"
  display: table
  mode: analytics
  query: type = Pipeline and project = "gitlab-org/gitlab" and finished >= "2026-01-01" and finished <= "2026-03-31"
  dimensions: source as "Source", status as "Status"
  metrics: totalCount as "Total"
  sort: totalCount desc
  ```
  ````

- 그룹 전체에서 특정 브랜치 및 상태로 필터링:

  ````yaml
  ```glql
  title: "Default branch pipeline outcomes across gitlab-org"
  display: table
  mode: analytics
  query: type = Pipeline and group = "gitlab-org" and finished >= -14d and ref in ("master", "main") and status in ("success", "failed")
  dimensions: project as "Project", status as "Status"
  metrics: totalCount as "Total", successRate as "Success rate"
  sort: totalCount desc
  limit: 20
  ```
  ````
