---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 기여도
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.2에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21212)되었습니다.
- 설정 가능한 `granularity` 매개변수가 GitLab 19.3에서 [도입되었습니다](https://gitlab.com/gitlab-org/glql/-/issues/130).
- `!=` 및 `not in` 연산자가 `user` 필터에 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/glql/-/merge_requests/537).

{{< /history >}}

기여도(Contributions)는 프로젝트 또는 그룹 전체에서 기여 활동(커밋, 이슈, 머지 리퀘스트 등)에 대한 집계 메트릭을 제공하는 데이터 소스입니다.

## 허용된 모드 {#allowed-modes}

- [`analytics`](../_index.md#analytics-mode)

## 허용된 범위 {#allowed-scopes}

| 범위     | 설명                                                              |
| --------- | ------------------------------------------------------------------------ |
| `project` | 특정 프로젝트에서 기여도를 쿼리합니다.                               |
| `group`   | 하위 그룹을 포함한 그룹의 모든 프로젝트에서 기여도를 쿼리합니다. |

여러 그룹 또는 프로젝트에서 기여도를 집계하려면 `in` 연산자와 함께 목록을 사용합니다. 더 많은 정보를 보려면 [여러 그룹 및 프로젝트](_index.md#multiple-groups-and-projects)를 참조하세요.

## 쿼리 필터 {#query-filters}

`query` 매개변수에서 이러한 필드를 사용하여 결과를 필터링합니다.

| 필드                      | 이름      | 연산자                 |
| -------------------------- | --------- | ------------------------- |
| [생성 시간](#created-at)  | `created` | `=`, `>`, `<`, `>=`, `<=` |
| [사용자](#user)              | `user`    | `=`, `!=`, `in`, `not in` |

### 생성 시간 {#created-at}

**Description (설명)**: 생성된 날짜로 기여도를 필터링합니다.

**허용된 값 타입**:

- `AbsoluteDate` (`YYYY-MM-DD` 형식)
- `RelativeDate` (`<sign><digit><unit>` 형식, 부호는 `+`, `-` 또는 생략, 숫자는 정수이며 `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (년) 중 하나)

**노트**:

- `=` 연산자의 경우 GLQL은 사용자의 시간대에서 00:00부터 23:59까지의 시간 범위를 고려합니다.

### 사용자 {#user}

**Description (설명)**: 기여도를 작성한 사용자로 필터링합니다.

**허용된 값 타입**:

- `Number` (사용자 ID)
- `List` (여러 사용자 ID의 경우 `in` 또는 `not in` 연산자 사용)

> [!note]
> 사용자명 필터링 지원은 [GLQL 이슈 143](https://gitlab.com/gitlab-org/glql/-/work_items/143)에서 추적 중입니다.

## 차원 {#dimensions}

| 차원  | 이름      | 설명                                          |
| ---------- | --------- | ----------------------------------------------------- |
| 생성 시간 | `created` | 기여도 생성 날짜별로 그룹화합니다. [`granularity` 매개변수](../_index.md#field-parameters)를 `daily`, `weekly`, `monthly` 또는 `30d`과 같은 일 수(기본값: `monthly`)로 수용하며, 선택 사항인 `origin`도 있습니다. 예를 들어 `created(weekly)` 또는 `created(granularity=30d, origin=2026-07-16)`입니다. |

## 메트릭 {#metrics}

| 메트릭      | 이름         | 설명                    |
| ----------- | ------------ | ------------------------------- |
| 전체 개수 | `totalCount` | 전체 기여도 수입니다. |
| 사용자 개수 | `usersCount` | 고유 기여자의 수입니다. |

## 정렬 필드 {#sort-fields}

선택한 차원 또는 메트릭에 포함된 모든 필드별로 정렬합니다. 더 많은 정보를 보려면 [분석 모드 정렬](../_index.md#sorting)을 참조하세요.

## 예제 {#examples}

- 프로젝트의 월별 기여도 추이:

  ````yaml
  ```glql
  title: "Monthly contributions"
  display: table
  mode: analytics
  query: type = Contribution and project = "gitlab-org/gitlab"
  dimensions: created as "Month"
  metrics: totalCount as "Total", usersCount as "Contributors"
  sort: created desc
  ```
  ````

- 사용자 집합의 기여도 추이:

  ````yaml
  ```glql
  title: "Contributions from a set of users"
  display: table
  mode: analytics
  query: type = Contribution and project = "gitlab-org/gitlab" and user in (1234567, 2345678) and created >= -90d
  dimensions: created as "Month"
  metrics: totalCount as "Total"
  sort: created desc
  ```
  ````

- 특정 사용자의 지난 연도 기여도, 월별:

  ````yaml
  ```glql
  title: "User contribution history"
  display: table
  mode: analytics
  query: type = Contribution and group = "gitlab-org" and user = 1234567 and created >= -365d
  dimensions: created as "Month"
  metrics: totalCount as "Total"
  sort: created asc
  ```
  ````

- 그룹의 전체 기여도 메트릭(그룹화 없음):

  ````yaml
  ```glql
  title: "Overall contribution metrics"
  display: table
  mode: analytics
  query: type = Contribution and group = "gitlab-org" and created >= -90d
  metrics: totalCount as "Total", usersCount as "Contributors"
  ```
  ````
