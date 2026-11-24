---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 코드 제안
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.1에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21212)되었습니다.
- `timestamp`의 `daily`, `weekly`, 그리고 고정 일수 `granularity` 값이 [GitLab 19.5에서 도입되었습니다](https://gitlab.com/gitlab-org/glql/-/merge_requests/528).
- `!=` 및 `not in` 연산자가 `ideName`, `language`, `user` 필터에 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/537)되었습니다.

{{< /history >}}

코드 제안은 프로젝트 또는 그룹에서 [GitLab Duo 코드 제안](../../project/repository/code_suggestions/_index.md) 사용에 관한 집계된 메트릭을 제공하는 데이터 소스입니다.

## 허용된 모드 {#allowed-modes}

- [`analytics`](../_index.md#analytics-mode)

## 허용된 범위 {#allowed-scopes}

| 범위     | 설명                                                                 |
| --------- | --------------------------------------------------------------------------- |
| `project` | 특정 프로젝트에서 코드 제안을 조회합니다.                               |
| `group`   | 하위 그룹을 포함하여 그룹의 모든 프로젝트에서 코드 제안을 조회합니다. |

여러 그룹 또는 프로젝트에서 코드 제안을 집계하려면 `in` 연산자를 포함한 목록을 사용합니다. 자세한 내용은 [여러 그룹 및 프로젝트](_index.md#multiple-groups-and-projects)를 참고하세요.

## 쿼리 필터 {#query-filters}

`query` 매개변수의 이 필드들을 사용하여 결과를 필터링합니다.

| 필드                                      | 이름(및 별칭) | 연산자                 |
| ------------------------------------------ | ---------------- | ------------------------- |
| [IDE 이름](#cs-ide-name)                   | `ideName`        | `=`, `!=`, `in`, `not in` |
| [언어](#cs-language)                    | `language`       | `=`, `!=`, `in`, `not in` |
| [타임스탬프](#cs-timestamp)                 | `timestamp`      | `=`, `>`, `<`, `>=`, `<=` |
| [사용자](#cs-user)                           | `user`           | `=`, `!=`, `in`, `not in` |

### IDE 이름 {#cs-ide-name}

**Description (설명)**: 제안을 생성하는 데 사용된 IDE로 필터링합니다.

**허용된 값 유형**:

- `String`
- `List`(여러 값의 경우 `in` 또는 `not in` 연산자 사용)

### 언어 {#cs-language}

**Description (설명)**: 제안의 프로그래밍 언어로 필터링합니다.

**허용된 값 유형**:

- `String`
- `List`(여러 값의 경우 `in` 또는 `not in` 연산자 사용)

### 타임스탬프 {#cs-timestamp}

**Description (설명)**: 제안이 생성된 시간으로 필터링합니다. 범위 연산자를 사용하여 시간 창을 정의합니다.

**허용된 값 유형**:

- `AbsoluteDate`(형식: `YYYY-MM-DD`)
- `RelativeDate` (형식은 `<sign><digit><unit>`이며, 부호는 `+`, `-` 또는 생략되고, 숫자는 정수이며, `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (년) 중 하나입니다)

### 사용자 {#cs-user}

**Description (설명)**: 제안을 받은 사용자로 필터링합니다.

**허용된 값 유형**:

- `Number`(사용자 ID)
- `List`(여러 사용자 ID의 경우 `in` 또는 `not in` 연산자 사용)

> [!note]
> 사용자 이름 필터링에 대한 지원은 [이슈 599750](https://gitlab.com/gitlab-org/gitlab/-/work_items/599750)에서 추적 중입니다.

## 차원 {#dimensions}

지원되는 차원은 다음과 같습니다:

| 차원 | 이름(및 별칭) | 설명                                          |
|-----------|------------------|------------------------------------------------------|
| IDE 이름  | `ideName`        | 사용된 IDE로 그룹화합니다(예: VSCode, JetBrains).  |
| 언어  | `language`       | 프로그래밍 언어로 그룹화합니다.                       |
| 타임스탬프 | `timestamp`      | 날짜별로 그룹화합니다. [`granularity` 매개변수](../_index.md#field-parameters)를 `daily`, `weekly`, `monthly` 또는 `30d`과 같은 일 수(기본값: `monthly`)로 받으며, 선택 사항인 `origin`도 받습니다. 예를 들어 `timestamp(weekly)` 또는 `timestamp(granularity=30d, origin=2026-07-16)`입니다. |
| 사용자      | `user`           | 사용자별로 그룹화합니다(아바타, 이름 및 사용자 이름 표시). |

## 메트릭 {#metrics}

지원되는 메트릭은 다음과 같습니다:

| 메트릭              | 이름(및 별칭)    | 설명                             |
|---------------------|---------------------|-----------------------------------------|
| 수용률     | `acceptanceRate`    | 수용된 제안 대 표시된 제안의 비율입니다. |
| 수용된 개수      | `acceptedCount`     | 수용된 제안의 개수입니다.         |
| 거부된 개수      | `rejectedCount`     | 거부된 제안의 개수입니다.         |
| 표시된 개수         | `shownCount`        | 사용자에게 표시된 제안의 개수입니다.   |
| 제안 크기 합계 | `suggestionSizeSum` | 제안의 총 볼륨입니다.            |
| 전체 수         | `totalCount`        | 제안의 총 개수입니다.            |
| 사용자 수         | `usersCount`        | 고유 사용자 수.                 |

## 정렬 필드 {#sort-fields}

선택한 차원 또는 메트릭에 포함된 모든 필드별로 정렬합니다. 자세한 내용은 [분석 모드 정렬](../_index.md#sorting)을 참고하세요.

## 예제 {#examples}

- 지난 30일 동안의 언어별 수용률:

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= -30d
  dimensions: language as "Language"
  metrics: totalCount as "Total", acceptanceRate as "Acceptance Rate"
  sort: acceptanceRate desc
  ```
  ````

- IDE별 사용 현황:

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= -30d
  dimensions: ideName as "IDE"
  metrics: totalCount as "Total Suggestions", usersCount as "Active Users"
  sort: totalCount desc
  ```
  ````

- 그룹화 없는 전체 메트릭:

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= -30d
  metrics: totalCount as "Total", acceptedCount as "Accepted", rejectedCount as "Rejected", shownCount as "Shown", acceptanceRate as "Acceptance Rate"
  ```
  ````

- 특정 프로젝트의 사용자당 제안(Ruby로 필터링됨):

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= -30d and language = "ruby"
  dimensions: user as "User"
  metrics: totalCount as "Total", acceptanceRate as "Acceptance Rate"
  sort: totalCount desc
  limit: 10
  ```
  ````

- 날짜 범위에서 언어별 시간에 따른 제안:

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= "2026-01-01" and timestamp <= "2026-03-31"
  dimensions: timestamp as "Date", language as "Language"
  metrics: totalCount as "Total", acceptanceRate as "Acceptance Rate"
  sort: timestamp desc
  ```
  ````

- 특정 IDE 및 언어로 필터링:

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= -7d and ideName in ("Visual Studio Code", "RubyMine") and language in ("ruby", "python")
  dimensions: ideName as "IDE", language as "Language"
  metrics: totalCount as "Total", acceptanceRate as "Rate"
  sort: totalCount desc
  ```
  ````
