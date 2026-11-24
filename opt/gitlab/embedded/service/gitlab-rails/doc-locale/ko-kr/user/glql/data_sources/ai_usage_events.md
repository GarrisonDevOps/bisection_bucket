---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: AI 사용 이벤트
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21216)되었습니다.
- `returningUsersCount` 또는 `previousPeriodUsersCount`을 `timestamp` 차원 없이 선택하면 GitLab 19.5에서 오류를 반환하도록 [변경](https://gitlab.com/gitlab-org/glql/-/merge_requests/485)되었습니다.
- `group` 차원이 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/530)되었습니다.
- `!=` 및 `not in` 연산자가 `event`, `feature`, `user` 필터에 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/537)되었습니다.
- `event` 매개변수가 `totalCount`에 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/541)되었습니다.

{{< /history >}}

AI 사용 이벤트는 프로젝트 또는 그룹 전체에서 GitLab Duo 기능 사용에 대한 집계된 메트릭을 제공하는 데이터 소스입니다.

## 허용된 모드 {#allowed-modes}

- [`analytics`](../_index.md#analytics-mode)

## 허용된 범위 {#allowed-scopes}

| 범위     | 설명                                                                 |
| --------- | --------------------------------------------------------------------------- |
| `project` | 특정 프로젝트에서 AI 사용 이벤트를 쿼리합니다.                                |
| `group`   | 그룹의 모든 프로젝트에서 AI 사용 이벤트를 쿼리합니다(하위 그룹 포함).  |

여러 그룹 또는 프로젝트에서 AI 사용 이벤트를 집계하려면 `in` 연산자를 사용하여 목록을 만듭니다. 자세한 내용은 [여러 그룹 및 프로젝트](_index.md#multiple-groups-and-projects)를 참고하세요.

## 쿼리 필터 {#query-filters}

`query` 매개변수의 이 필드들을 사용하여 결과를 필터링합니다.

| 필드                                | 이름            | 연산자                 |
| ------------------------------------ | --------------- | ------------------------- |
| [이벤트](#event)                      | `event`         | `=`, `!=`, `in`, `not in` |
| [기능](#feature)                  | `feature`       | `=`, `!=`, `in`, `not in` |
| [기능 수](#features-count)    | `featuresCount` | `>`, `<`, `>=`, `<=`      |
| [타임스탬프](#timestamp)              | `timestamp`     | `=`, `>`, `<`, `>=`, `<=` |
| [사용자](#user)                        | `user`          | `=`, `!=`, `in`, `not in` |

### 이벤트 {#event}

**Description (설명)**: 이벤트 식별자로 필터링합니다.

**허용된 값 유형**:

- `String`
- `List`(여러 값의 경우 `in` 또는 `not in` 연산자 사용)

**노트**:

- GitLab에서 인식하지 못하는 이벤트 식별자를 제외해도 실제로 제외되는 이벤트는 없습니다. 이벤트 식별자의 유효성 검사는 [이슈 629846](https://gitlab.com/gitlab-org/gitlab/-/issues/629846)에서 제안되었습니다.

### 기능 {#feature}

**Description (설명)**: 이벤트를 생성한 GitLab Duo 기능으로 필터링합니다. 예를 들어 `code_suggestions` 또는 `chat`입니다.

**허용된 값 유형**:

- `String`
- `List`(여러 값의 경우 `in` 또는 `not in` 연산자 사용)

**노트**:

- `!=` 및 `not in`은 기능이 알려진 이벤트만 반환합니다. GitLab에서 기능으로 매핑할 수 없는 이벤트는 제외되므로 `feature != "chat"`은 채팅을 제외한 모든 이벤트와 동일하지 않습니다.

### 기능 수 {#features-count}

**Description (설명)**: 사용된 고유 기능의 수로 필터링합니다. 이 필터는 `featuresCount` 메트릭도 선택되었을 때만 유효합니다.

**허용되는 값 유형**: `Number`

### 타임스탬프 {#timestamp}

**Description (설명)**: 이벤트가 발생한 시간으로 필터링합니다. 범위 연산자를 사용하여 시간 창을 정의합니다.

**허용된 값 유형**:

- `AbsoluteDate`(형식: `YYYY-MM-DD`)
- `RelativeDate` (형식은 `<sign><digit><unit>`이며, 부호는 `+`, `-` 또는 생략되고, 숫자는 정수이며, `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (년) 중 하나입니다)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자의 시간대에서 00:00~23:59로 간주됩니다.

### 사용자 {#user}

**Description (설명)**: 이벤트를 트리거한 사용자로 필터링합니다.

**허용된 값 유형**:

- `Number`(사용자 ID)
- `List`(여러 사용자 ID의 경우 `in` 또는 `not in` 연산자 사용)

> [!note]
> 사용자 이름 필터링에 대한 지원은 [이슈 599750](https://gitlab.com/gitlab-org/gitlab/-/work_items/599750)에서 추적 중입니다.

## 차원 {#dimensions}

| 차원 | 이름        | 설명 |
| --------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 이벤트     | `event`     | 이벤트 식별자별로 그룹화합니다. |
| 기능   | `feature`   | GitLab Duo 기능별로 그룹화합니다. |
| 그룹     | `group`     | 그룹별로 그룹화합니다. 최상위 그룹부터 계산하는 `depth` 매개변수를 `1`에서 `99`까지(기본값: `1`) 받으므로, `group`은 최상위 그룹을 반환하고 `group(depth=2)`는 해당 하위 그룹을 반환합니다. 해당 깊이보다 위에 있는 이벤트나, 하위 그룹이 아니라 해당 깊이의 프로젝트에 속한 이벤트(예: `depth=2`일 때 최상위 그룹 바로 아래의 프로젝트)는 그룹이 없으며, 결과에 그룹이 없는 행이 둘 이상 포함될 수 있습니다. |
| 타임스탬프 | `timestamp` | 날짜별로 그룹화합니다. [`granularity` 매개변수](../_index.md#field-parameters)를 `daily`, `weekly`, `monthly` 또는 `30d`과 같은 일 수(기본값: `weekly`)로 받으며, 선택 사항인 `origin`도 받습니다. 예를 들어 `timestamp(daily)` 또는 `timestamp(granularity=30d, origin=2026-07-16)`입니다. |
| 사용자      | `user`      | 사용자별로 그룹화합니다(아바타, 이름 및 사용자 이름 표시). |

## 메트릭 {#metrics}

| 메트릭                      | 이름                      | 설명                                             |
| --------------------------- | ------------------------- | ------------------------------------------------------- |
| 기능 수              | `featuresCount`           | 사용된 고유 기능의 수입니다.                         |
| 이전 기간 사용자 수 | `previousPeriodUsersCount` | 이전 기간의 고유 사용자 수입니다.         |
| 반환 사용자 수       | `returningUsersCount`     | 현재 기간과 이전 기간 모두에서 활동한 사용자 수입니다. |
| 전체 수                 | `totalCount`              | 이벤트별로 선택적으로 필터링된 총 이벤트 수입니다. 선택적 `event` 매개변수를 하나 이상의 이벤트 식별자(`event` 필터와 동일한 값)와 함께 허용합니다. 예: `totalCount(event="publish_duo_code_review_comments")` 또는 `totalCount(event=["request_review_duo_code_review_on_mr_by_author", "request_review_duo_code_review_on_mr_by_non_author"])`. 매개변수 없이 또는 `event=[]`로 모든 이벤트가 계산됩니다. GitLab에서 인식하지 못하는 이벤트 식별자는 오류를 반환합니다. |
| 사용자 수                 | `usersCount`              | 고유 사용자 수.                                 |

**노트**:

- `returningUsersCount` 및 `previousPeriodUsersCount` 메트릭은 각 `timestamp` 버킷을 이전 항목과 비교하므로 `timestamp` 차원도 선택되어야 합니다. 이것이 없으면 쿼리에서 오류를 반환합니다. `timestamp` 필터만으로는 충분하지 않습니다.

## 정렬 필드 {#sort-fields}

선택한 차원 또는 메트릭에 포함된 모든 필드별로 정렬합니다. 자세한 내용은 [분석 모드 정렬](../_index.md#sorting)을 참고하세요.

## 예제 {#examples}

- 지난 30일간의 기능 채택:

  ````yaml
  ```glql
  title: "GitLab Duo feature adoption (last 30 days)"
  display: table
  mode: analytics
  query: type = AiUsageEvent and group = "gitlab-org" and timestamp > -30d
  dimensions: feature as "Feature"
  metrics: totalCount as "Total events", usersCount as "Users"
  sort: usersCount desc
  ```
  ````

- 반환 사용자와의 주간 사용 추세:

  ````yaml
  ```glql
  title: "Weekly GitLab Duo usage trend"
  display: table
  mode: analytics
  query: type = AiUsageEvent and group = "gitlab-org" and timestamp > -30d
  dimensions: timestamp(weekly) as "Week"
  metrics: usersCount as "Users", returningUsersCount as "Returning users", previousPeriodUsersCount as "Previous period users"
  sort: timestamp desc
  ```
  ````

- 주간 GitLab Duo 코드 검토 수, 이벤트 그룹당 하나:

  ````yaml
  ```glql
  title: "Weekly GitLab Duo Code Review requests and reviews"
  display: table
  mode: analytics
  query: type = AiUsageEvent and group = "gitlab-org" and timestamp > -30d
  dimensions: timestamp(weekly) as "Week"
  metrics: totalCount(event=["request_review_duo_code_review_on_mr_by_author", "request_review_duo_code_review_on_mr_by_non_author"]) as "Requested", totalCount(event="publish_duo_code_review_comments") as "With comments", totalCount(event="find_no_issues_duo_code_review_after_review") as "Without comments"
  sort: timestamp desc
  ```
  ````

- 특정 프로젝트의 사용자당 이벤트:

  ````yaml
  ```glql
  title: "GitLab Duo events by user"
  display: table
  mode: analytics
  query: type = AiUsageEvent and project = "gitlab-org/gitlab" and timestamp > -30d
  dimensions: user as "User"
  metrics: totalCount as "Total events"
  sort: totalCount desc
  limit: 10
  ```
  ````

- 그룹화 없이 고유 사용자 전체:

  ````yaml
  ```glql
  title: "Unique GitLab Duo users (last 30 days)"
  display: table
  mode: analytics
  query: type = AiUsageEvent and group = "gitlab-org" and timestamp > -30d
  metrics: usersCount as "Users"
  ```
  ````
