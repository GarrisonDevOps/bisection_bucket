---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 쿼리 언어(GLQL)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- `glql_integration`라는 이름의 [기능 플래그](../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14767)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.4에서 일부 그룹 및 프로젝트에 대해 GitLab.com에서 활성화되었습니다.
- [GitLab 17.10에서 실험에서 베타로 변경되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/issues/476990)
- GitLab 17.10의 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/work_items/476990)되었습니다.
- GitLab 18.3에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/554870)입니다. 기능 플래그 `glql_integration`이 제거되었습니다.

{{< /history >}}

GitLab 쿼리 언어(GLQL)는 GitLab 전체를 위한 단일 쿼리 언어입니다. 이를 사용하여 익숙한 구문을 사용하여 플랫폼 어디서나 콘텐츠를 필터링하고 임베드할 수 있습니다.

Markdown 코드 블록에 쿼리를 임베드합니다. 임베드된 뷰는 GLQL 소스 코드 블록의 렌더링된 출력입니다.

[GLQL로 지원되는 임베드된 뷰 피드백 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/509792)에서 피드백을 공유하세요.

## 쿼리 구문 {#query-syntax}

쿼리 구문은 주로 논리 표현식으로 구성됩니다. 이러한 표현식은 `<field> <operator> <value> and ...`의 구문을 따릅니다.

### 데이터 소스 {#data-sources}

GLQL은 작업 항목, 병합 요청, 파이프라인, 작업 및 프로젝트와 같은 다양한 데이터 소스를 쿼리할 수 있습니다.

지원되는 데이터 소스의 전체 목록은 [GLQL 데이터 소스](data_sources/_index.md)를 참조하세요.

### 필드 {#fields}

필드를 사용하여 결과를 필터링, 표시 및 정렬합니다.

사용할 수 있는 필드는 쿼리하는 데이터 소스에 따라 다릅니다. 각 데이터 소스에 대해 지원되는 필드, 연산자 및 값의 전체 목록은 [GLQL 필드](fields.md)를 참조하세요.

### 연산자 {#operators}

{{< history >}}

- `=`을(를) 같은 날짜 또는 범위 필드의 다른 비교와 결합하면 GitLab 19.5에서 오류를 반환하도록 [변경되었습니다.](https://gitlab.com/gitlab-org/glql/-/merge_requests/516) 이전에는 두 조건 중 하나만 적용되었습니다.
- `not in` 연산자가 GitLab 19.5에서 분석 데이터 소스의 목록 필터에 대해 [도입되었습니다.](https://gitlab.com/gitlab-org/glql/-/merge_requests/537)

{{< /history >}}

**비교 연산자**:

| GLQL 연산자 | 설명                             | 검색에서 동등한 것   |
|---------------|-----------------------------------------|------------------------|
| `=`           | 같음 / 목록의 모든 항목 포함           | `is` (같음)        |
| `!=`          | 같지 않음 / 목록에 포함되지 않음 | `is not` (같음)    |
| `in`          | 목록에 포함됨                       | `or` / `is one of`     |
| `not in`      | 목록에 포함되지 않음                   | `is not one of`        |
| `>`           | 보다 큼                            | {{< no >}} |
| `<`           | 보다 작음                               | {{< no >}} |
| `>=`          | 보다 크거나 같음                | {{< no >}} |
| `<=`          | 보다 작거나 같음                   | {{< no >}} |

**논리 연산자**: `and`만 지원됩니다. `or`는 `in` 비교 연산자를 사용하여 일부 필드에 대해 간접적으로 지원됩니다.

`not in` 연산자는 목록의 모든 값을 제외합니다(예: `flowType not in ("chat", "agentic_chat/v1")`). 이는 분석 데이터 소스 필드에서 사용 가능하며 목록에는 최소 하나의 값이 포함되어야 합니다. 단일 값을 제외하려면 `!=`을(를) 사용합니다.

> [!note]
> `=`이(가) 범위를 선택하는 필드(예: 날짜 필드의 단일 날짜 또는 `activeDays`과(와) 같은 범위 필터의 정확한 개수)에서는 `=`을(를) 같은 필드의 다른 비교와 결합할 수 없습니다. 예를 들어 `created = 2024-01-01 and created > 2023-01-01`는 오류를 반환합니다. 같음 또는 범위를 사용합니다. 이는 모든 데이터 소스 및 모드에 적용됩니다.

### 값 {#values}

값은 다음을 포함할 수 있습니다:

- 문자열
- 숫자
- 상대 날짜(`-1d`, `2w`, `-6m`, 또는 `1y`와 같은)
- `YYYY-MM-DD` 형식의 절대 날짜(`2025-01-01`와 같은)
- 함수(`currentUser()`(사용자 필드의 경우) 또는 `today()`(날짜의 경우))
- 열거형 값(`upcoming` 또는 마일스톤의 경우 `started`과(와) 같은)
- 부울(`true` 또는 `false`)
- Null 가능한 값(`null`, `none`, 또는 `any`과(와) 같은)
- GitLab 참조(`~label`(레이블의 경우), `%Backlog`(마일스톤의 경우), 또는 `@username`(사용자의 경우))
- 이전 값을 포함하는 목록(괄호로 둘러싸여 있음: `()` 및 쉼표로 구분됨: `,`)

## 임베드된 뷰 {#embedded-views}

임베드된 뷰는 Markdown의 GLQL 소스 코드 블록의 출력입니다. 소스에는 GLQL 쿼리 결과를 표시하는 방법을 설명하는 YAML 특성과 쿼리가 포함됩니다.

### 지원되는 영역 {#supported-areas}

{{< history >}}

- 저장소 Markdown 파일의 임베드된 뷰가 GitLab 18.3에서 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197950)

{{< /history >}}

임베드된 뷰는 다음 영역에 표시될 수 있습니다:

- 그룹 및 프로젝트 위키
- 다음의 설명 및 주석:
  - 에픽
  - 이슈
  - 병합 요청
  - 작업 항목(작업, OKR 또는 에픽)
- 저장소 Markdown 파일

### 구문 {#syntax}

임베드된 뷰의 소스 구문은 다음으로 구성된 YAML의 상위 집합입니다:

- `query` 매개변수: `and`와(과) 같은 논리 연산자와 함께 조인된 표현식입니다.
- `display`, `limit`, 또는 `fields`, `title` 및 `description`와 같은 프레젠테이션 레이어 관련 매개변수는 YAML로 표현됩니다.

뷰는 Markdown의 코드 블록으로 정의되며 Mermaid와 같은 다른 코드 블록과 유사합니다.

예를 들어:

- `gitlab-org/gitlab`에서 인증된 사용자에게 할당된 첫 5개의 열린 이슈 표를 표시합니다.
- `title`, `state`, `health`, `description`, `epic`, `milestone`, `weight` 및 `updated` 열을 표시합니다.

````yaml
```glql
display: table
title: GLQL table 🎉
description: This view lists my open issues
fields: title, state, health, epic, milestone, weight, updated
limit: 5
query: type = Issue AND group = "gitlab-org" AND assignee = currentUser() AND state = opened
```
````

이 소스는 다음과 같은 표를 렌더링합니다:

![현재 사용자에게 할당된 이슈를 나열하는 표](img/glql_table_v18_5.png)

#### 프레젠테이션 구문 {#presentation-syntax}

{{< history >}}

- GitLab 17.7에서 [변경되었습니다:](https://gitlab.com/gitlab-org/gitlab/-/issues/508956): YAML 전면부를 사용한 프레젠테이션 레이어 구성은 더 이상 사용되지 않습니다.
- `title` 및 `description` 매개변수가 GitLab 17.10에서 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/183709)
- 정렬 및 페이지 매김이 GitLab 18.2에서 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/issues/502701)
- `collapsed` 매개변수가 GitLab 18.3에서 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197824)

{{< /history >}}

`query` 매개변수를 제외하고 더 많은 선택적 매개변수를 사용하여 뷰의 프레젠테이션 세부 사항을 구성할 수 있습니다.

지원되는 매개변수:

| 매개 변수     | 기본값                                       | 설명 |
| ------------- | --------------------------------------------- | ----------- |
| `collapsed`   | `false`                                       | 뷰를 축소할지 확장할지 여부입니다. |
| `description` | 없음                                          | 제목 아래에 표시할 선택적 설명입니다. |
| `display`     | `list`                                        | 쿼리 결과를 표시하는 방법입니다. 사용 가능한 유형은 [표시 유형](#display-types)을(를) 참조하세요. |
| `displayConfig` | 없음                                        | 예를 들어 `stacked`(열 차트의 경우)과 같은 표시 유형별 옵션입니다. [표시 유형](display_types.md)을(를) 참조하세요. |
| `fields`      | `title`                                       | 뷰에 포함할 [필드](fields.md)의 쉼표로 구분된 목록입니다. |
| `limit`       | `100`                                         | 첫 페이지에 표시할 항목 수입니다. 최댓값은 `100`입니다. |
| `sort`        | `updated desc`                                | [데이터를 정렬할 필드](fields.md) 다음에 정렬 순서(`asc` 또는 `desc`)입니다. |
| `title`       | `Embedded table view` 또는 `Embedded list view` | 임베드된 뷰의 위쪽에 표시되는 제목입니다. |

#### 페이지 매김 {#pagination}

{{< history >}}

- GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/502701)되었습니다.

{{< /history >}}

임베드된 뷰는 기본적으로 첫 페이지의 결과를 표시합니다. `limit` 매개변수는 표시된 항목의 수를 제어합니다.

다음 페이지를 로드하려면 마지막 행에서 **더 보기**를 선택합니다.

#### 필드 함수 {#field-functions}

동적으로 생성된 열을 만들려면 뷰의 `fields` 매개변수에서 함수를 사용합니다. 전체 목록은 [임베드된 뷰의 함수](functions.md#functions-in-embedded-views)를 참조하세요.

#### 사용자 정의 필드 별칭 {#custom-field-aliases}

{{< history >}}

- GitLab 18.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/535558)되었습니다.

{{< /history >}}

표 뷰의 열을 사용자 정의 값으로 바꾸려면 `AS` 구문 키워드를 사용하여 필드를 별칭으로 지정합니다.

````yaml
```glql
display: list
fields: title, labels("workflow::*") AS "Workflow", labels("priority::*") AS "Priority"
limit: 5
query: type = Issue AND project = "gitlab-org/gitlab" AND assignee = currentUser() AND state = opened
```
````

이 소스는 `Title`, `Workflow` 및 `Priority` 열이 있는 뷰를 표시합니다.

### 표시 유형 {#display-types}

`display` 매개변수는 임베드된 뷰가 쿼리 결과를 렌더링하는 방법을 제어합니다(예: 목록, 표 또는 열 차트로). 기본적으로 결과는 목록으로 표시됩니다.

표시 유형 및 해당 구성의 전체 목록은 [GLQL 표시 유형](display_types.md)을(를) 참조하세요.

### 뷰 작업 {#view-actions}

{{< history >}}

- GitLab 17.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184788)되었습니다.
- **새로고침** 작업이 GitLab 18.0에서 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/issues/537310)

{{< /history >}}

뷰가 페이지에 나타나면 **뷰 작업**({{< icon name="ellipsis_v" >}}) 드롭다운 목록을 사용하여 작업을 수행합니다.

지원되는 작업:

| 작업        | 설명                                                    |
| ------------- | -------------------------------------------------------------- |
| 소스 보기   | 뷰의 소스를 봅니다.                                   |
| 소스 복사   | 뷰의 소스를 클립보드로 복사합니다.                      |
| 내용 복사 | 표 또는 목록 내용을 클립보드로 복사합니다. |
| 새로고침        | 이 뷰를 새로고침합니다.                                              |

## 분석 모드 {#analytics-mode}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.1에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21212)되었습니다.

{{< /history >}}

GLQL은 집계된 메트릭을 제공하는 데이터 소스에 대한 분석 모드를 지원합니다. 분석 모드 쿼리는 데이터를 그룹화하고 집계하기 위해 `fields` 대신 `dimensions` 및 `metrics`를 사용합니다.

일부 데이터 소스는 표준 모드와 분석 모드를 모두 지원합니다. 지원되는 모드는 각 [데이터 소스](data_sources/_index.md) 페이지를 참조하세요.

### 구문 {#syntax-1}

분석 모드 쿼리는 다음 구조를 사용합니다:

````yaml
```glql
mode: analytics
query: type = <DataSource> and <filters>
dimensions: <dimension fields>
metrics: <metric fields>
sort: <field> <direction>
limit: <number>
```
````

| 매개 변수 | 필수 | 설명 |
|-----------|----------|-------------|
| `mode: analytics` | 예 | 분석 모드를 사용하는 데 필요합니다. |
| `metrics` | 예 | 계산할 집계된 값입니다. 최소 하나의 메트릭이 필요합니다. |
| `dimensions` | 아니요 | 결과를 그룹화할 필드입니다. 원하는 조합을 선택하거나 단일 집계 행을 반환하려면 완전히 생략합니다. |
| `sort` | 아니요 | 정렬 필드는 선택된 차원 또는 메트릭에도 나타나야 합니다. |
| `limit` | 아니요 | 페이지당 행 수(최대 `100`). `limit`를 생략하면 차트 및 통계와 같은 분석 모드 표시 유형이 최대 1,000행까지 모든 페이지를 자동으로 가져옵니다. [페이지 매김 지원](display_types.md#pagination-support)을(를) 참조하세요. |

### 필드 매개변수 {#field-parameters}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/glql/-/issues/130)되었습니다.
- 필드 매개변수의 목록 값이 GitLab 19.5에서 [도입되었습니다.](https://gitlab.com/gitlab-org/glql/-/merge_requests/522)
- 고정 일 `granularity` 값이 GitLab 19.5에서 [도입되었습니다.](https://gitlab.com/gitlab-org/glql/-/merge_requests/528)
- `origin` 매개변수가 GitLab 19.5에서 [도입되었습니다.](https://gitlab.com/gitlab-org/glql/-/merge_requests/529)

{{< /history >}}

일부 차원 및 메트릭은 필드 이름 뒤에 괄호 안의 매개변수를 수락합니다. 매개변수를 생략하면 필드는 기본값을 사용합니다. 위치(`finished(weekly)`) 또는 이름(`finished(granularity=weekly)`)으로 매개변수를 전달할 수 있습니다.

단일 위치 인수는 필드의 첫 번째 매개변수에 바인딩됩니다(예: `created(30d)`). 두 개 이상의 매개변수를 전달할 때는 명명된 구문을 사용합니다(예: `created(granularity=30d, origin=2026-07-16)`). 두 개의 위치 인수는 오류를 반환합니다.

매개변수를 수락하는 필드 및 기본값은 [데이터 소스](data_sources/_index.md) 페이지를 참조하세요. 다양한 매개변수를 사용하여 같은 필드를 두 번 이상 포함하려면 [사용자 정의 별칭](#custom-aliases)을(를) 참조하세요.

예를 들어 다음 쿼리는 주간 버킷에서 파이프라인 기간의 중앙값을 반환합니다:

````yaml
```glql
mode: analytics
query: type = Pipeline and project = "gitlab-org/gitlab" and finished >= -90d
dimensions: finished(weekly)
metrics: durationQuantile(0.5)
sort: finished desc
```
````

#### 목록 값 {#list-values}

일부 매개변수는 목록을 사용합니다. 예를 들어 `name(key=[v1, v2])` 또는 `name([v1, v2])`과(과) 같이 대괄호로 작성하세요. `[]`는 빈 목록입니다. 숫자는 음수일 수 있습니다. 목록 매개변수에 전달된 단일 값은 한 항목 목록으로 읽히므로 `userTier(8)`는 `userTier(thresholds=[8])`과(과) 같고 `totalCount(event="request_duo_chat_response")`는 `totalCount(event=["request_duo_chat_response"])`과(과) 같습니다.

대괄호는 필드 매개변수에만 해당됩니다. `query`의 필터 목록은 여전히 괄호를 사용합니다(예: `status in (paused, failed)`).

#### 세분화 {#granularity}

모든 날짜 차원은 `granularity` 매개변수를 수락합니다. 수용된 값은 `daily`, `weekly`, `monthly` 또는 `1d`에서 `399d`까지의 고정된 일 수이며 예를 들어 `created(30d)`입니다. 일 수를 따옴표 없이(`created(30d)`), 따옴표로 묶어(`created("30d")`) 또는 이름(`created(granularity=30d)`)으로 작성할 수 있습니다.

고정 일 버킷은 `origin`으로 앵커하지 않는 한 Unix epoch(1970년 1월 1일)에서 계산되므로 자신의 날짜 필터와 거의 정렬되지 않습니다.

각 데이터 소스 페이지는 차원별 기본 세분화를 나열합니다.

#### 원점 {#origin}

`origin`는 모든 날짜 차원의 선택적 두 번째 매개변수입니다. 고정 일 버킷을 계산하는 인스턴트를 설정합니다.

값은 ISO 8601 날짜 또는 날짜-시간입니다. 날짜를 필터 날짜와 같이 따옴표 없이 작성합니다(`origin=2026-07-16`). 날짜-시간은 인용되어야 합니다(`origin="2026-07-16T00:00:00Z"`). 시간대 오프셋이 UTC로 변환됩니다. 초의 소수 부분은 허용되지 않습니다. 버킷 레이블은 달력 날짜를 사용하고 시각 경계를 표시하지 않으므로 `origin`(시간 포함)는 시작된 UTC 날짜별로 각 버킷에 레이블을 지정합니다.

`origin`는 고정 일 세분화에서만 유효합니다. `created(granularity=weekly, origin=...)` 및 `created(origin=...)`(달력 기본값을 사용하는) 모두 오류를 반환합니다.

`-60d` 또는 `today()`와 같은 상대 값은 허용되지 않습니다. 지원은 [이슈 230](https://gitlab.com/gitlab-org/glql/-/work_items/230)에서 제안됩니다.

예를 들어 이 쿼리는 연속된 두 개의 30일 기간 동안 병합된 병합 요청을 비교합니다:

````yaml
```glql
title: "Merge requests merged per 30-day period"
display: table
mode: analytics
query: type = MergeRequest and group = "gitlab-org" and merged >= 2026-07-16 and merged < 2026-09-14
dimensions: merged(granularity=30d, origin=2026-07-16) as "Period"
metrics: totalCount as "Merge requests"
sort: merged asc
```
````

`origin`는 30일 버킷을 선택된 기간의 시작으로 정렬하므로 쿼리는 기간별로 한 행을 반환합니다. 빈 버킷이 생략됩니다.

### 사용자 정의 별칭 {#custom-aliases}

{{< history >}}

- 고유 별칭을 사용한 중복 매개변수화 필드가 GitLab 19.3에서 [도입되었습니다.](https://gitlab.com/gitlab-org/glql/-/issues/153)

{{< /history >}}

`as` 키워드를 사용하여 차원 또는 메트릭 열의 이름을 바꿉니다:

```plaintext
dimensions: language as "Language", ideName as "IDE"
metrics: totalCount as "Total", acceptanceRate as "Acceptance Rate"
```

다양한 매개변수를 사용하여 같은 [매개변수화 필드](#field-parameters)를 두 번 이상 포함할 수 있습니다:

```plaintext
metrics: durationQuantile(0.5) as "Median", durationQuantile(0.95) as "p95"
```

필드를 중복할 때:

- 중복된 각 필드에는 고유한 별칭이 있어야 합니다.
- 별칭은 모든 차원 및 메트릭에서 고유해야 합니다.
- 매개변수를 허용하지 않는 필드는 중복될 수 없습니다.
- 중복된 필드는 별칭으로 정렬되어야 합니다. 예를 들어, `sort: Median desc`입니다.
- `sort`에 사용된 별칭은 단일 단어여야 합니다.

### 정렬 {#sorting}

선택한 차원 또는 메트릭에 나타나는 모든 필드로 정렬합니다. 선택한 차원 또는 메트릭에 없는 필드로는 정렬할 수 없습니다. [사용자 정의 별칭](#custom-aliases)이 있는 필드의 경우 별칭 또는 원래 필드 이름으로 정렬할 수 있습니다. 같은 필드가 다양한 매개변수로 중복되면 별칭으로 정렬해야 합니다.

```plaintext
sort: acceptanceRate desc
```

여러 정렬 필드가 지원됩니다:

```plaintext
sort: totalCount desc, acceptanceRate asc
```

### 예 {#example}

다음 쿼리는 지난 30일 동안 언어별 코드 제안 수락률을 반환합니다(수락률로 정렬):

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

자세한 내용은 특정 [데이터 소스](data_sources/_index.md)의 예제를 참조하세요.

## 고급 검색 통합 {#advanced-search-integration}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.6에서 [베타](../../policy/development_stages_support.md#beta)로 [도입되었으며](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/210854) [기능 플래그](../../administration/feature_flags/_index.md) `glql_work_items` 및 `glql_es_integration`라는 이름으로 도입되었습니다. 기본적으로 활성화됩니다.
- 기능 플래그 `glql_work_items`이(가) GitLab 18.10에서 제거되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

GLQL은 쿼리 속도를 높이기 위해 사용 가능한 경우 고급 검색을 사용합니다. 고급 검색은 대규모 데이터 세트에 대한 복잡한 쿼리에 대해 더 빠른 응답 시간을 제공합니다.

고급 검색은:

- GitLab.com 및 GitLab Dedicated 유료 구독에 대해 기본적으로 활성화됩니다.
- 관리자가 [고급 검색을 활성화](../../integration/advanced_search/elasticsearch.md#enable-advanced-search)할 때 GitLab Self-Managed에서 사용 가능합니다.

고급 검색을 사용할 수 없는 경우 GLQL은 대신 PostgreSQL을 사용합니다.
