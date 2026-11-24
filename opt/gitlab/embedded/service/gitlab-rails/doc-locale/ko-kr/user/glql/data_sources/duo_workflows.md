---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Duo 플로우
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed
- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- [GitLab 19.5에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/606576) [실험](../../../policy/development_stages_support.md#experiment)으로.
- `model` 차원은 GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/511).
- `status` 필터 및 차원과 `flowTypesCount`, `returningUsersCount`, `joinedUsersCount`, `churnedUsersCount`, `previousPeriodUsersCount`, `createdMrCount`, `mergedMrCount`, 그리고 `closedMrCount` 메트릭이 GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/514).
- `userTier` 차원과 `flowTypesUsed` 및 `activeDays` 필터가 GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/516).
- `status` 매개변수가 `totalCount`에서 GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/527).
- `group` 차원은 GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/530).
- `openMrCount` 메트릭이 GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/534).
- `creditsPerMergedMrRatio` 메트릭이 GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/533).
- `!=` 및 `not in` 연산자가 `flowType`, `status`, 그리고 `user` 필터에서 GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/537).
- `model` 차원이 GitLab 19.5에서 모델 카탈로그 이름을 표시하도록 [변경됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/539).

{{< /history >}}

> [!flag]
> 이 데이터 소스는 GitLab Duo 에이전트 플랫폼 플로우 분석 엔진에서 읽으며, 이는 [기능 플래그](../../../administration/feature_flags/_index.md) `dap_impact_v1`(으)로 제어됩니다. 이 플래그는 기본적으로 비활성화되어 있습니다. 관리자가 활성화할 때까지 쿼리에서 오류를 반환합니다.

이 데이터 소스는 프로젝트 또는 그룹 전체에서 실행되는 GitLab Duo 에이전트 플랫폼 플로우(Duo 플로우라고도 함)에 대한 집계된 메트릭을 제공하며, 사용한 크레딧 수를 포함합니다.

## 허용되는 모드 {#allowed-modes}

- [`analytics`](../_index.md#analytics-mode)

## 허용되는 범위 {#allowed-scopes}

| 범위     | 설명 |
|-----------|-------------|
| `project` | 특정 프로젝트의 GitLab Duo 에이전트 플랫폼 플로우를 쿼리합니다. |
| `group`   | 서브그룹을 포함하여 그룹의 모든 프로젝트 전체에서 GitLab Duo 에이전트 플랫폼 플로우를 쿼리합니다. |

GitLab Duo 플로우를 여러 그룹 또는 프로젝트 전체에 집계하려면 `in` 연산자와 함께 목록을 사용합니다. 자세한 내용은 [여러 그룹 및 프로젝트](_index.md#multiple-groups-and-projects)를 참조하세요.

## 쿼리 필드 {#query-fields}

`query` 매개변수에서 이 필드를 사용하여 결과를 필터링합니다.

| 필드                               | 이름(및 별칭)                              | 연산자                 |
| ----------------------------------- | --------------------------------------------- | ------------------------- |
| [활성 일수](#active-days)         | `activeDays`                                  | `=`, `>`, `<`, `>=`, `<=` |
| [생성됨](#created)                 | `created` (`opened`, `openedAt`, `createdAt`) | `=`, `>`, `<`, `>=`, `<=` |
| [플로우 유형](#flow-type)             | `flowType`                                    | `=`, `!=`, `in`, `not in` |
| [사용된 플로우 유형](#flow-types-used) | `flowTypesUsed`                               | `=`, `>`, `<`, `>=`, `<=` |
| [상태](#status)                   | `status`                                      | `=`, `!=`, `in`, `not in` |
| [사용자](#user)                       | `user`                                        | `=`, `!=`, `in`, `not in` |

### 활성 일수 {#active-days}

**Description (설명)**: 선택된 기간에 사용자가 플로우를 만든 서로 다른 일수별로 플로우를 필터링합니다. `activeDays = 1`는 정확히 1일 동안 활성이었던 사용자와 일치합니다.

**허용되는 값 유형**: `Number`

**노트**:

- 이 개수는 선택된 전체 기간을 사용자당 포함합니다.
- 범위에 대해 두 개의 범위 연산자를 결합할 수 있습니다(예: `activeDays >= 2 and activeDays <= 5`, 하지만 같은 필드의 다른 비교와 함께 `=`는 불가능).

### 생성됨 {#created}

**Description (설명)**: 생성된 날짜별로 플로우를 필터링합니다. 여러 `created` 조건을 사용하여 지정된 기간을 정의합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (`YYYY-MM-DD` 형식)
- `RelativeDate` (`<sign><digit><unit>` 형식으로, 여기서 부호는 `+`, `-`, 또는 생략되고 자릿수는 정수이며 `unit`는 `d` (일), `w` (주), `m` (개월), 또는 `y` (년) 중 하나)

**노트**:

- `=` 연산자의 경우, GLQL은 사용자 시간대의 00:00~23:59 시간 범위를 고려합니다.

### 플로우 유형 {#flow-type}

**Description (설명)**: 유형별로 플로우를 필터링합니다. 예를 들어 `software_development` 또는 `code_review/v1`입니다.

**허용되는 값 유형**:

- `String`
- `List` (여러 값에 대해 `in` 또는 `not in` 연산자 사용)

### 사용된 플로우 유형 {#flow-types-used}

**Description (설명)**: 선택된 기간에 사용자가 실행한 서로 다른 플로우 유형의 수별로 플로우를 필터링합니다. `flowTypesUsed >= 2`는 2개 이상의 플로우 유형을 사용한 사용자와 일치합니다.

**허용되는 값 유형**: `Number`

**노트**:

- 이 개수는 선택된 전체 기간을 사용자당 포함합니다.
- 동일한 조합 규칙이 적용됩니다: 범위에 대해 두 개의 범위 연산자를 사용하되, 같은 필드의 다른 비교와 함께 `=`은 불가능합니다.

### 상태 {#status}

**Description (설명)**: 수명 주기 상태별로 플로우를 필터링합니다.

**허용되는 값 유형**:

- `Enum`, 하나의 `created`, `running`, `paused`, `finished`, `failed`, `stopped`, `input_required`, `plan_approval_required`, 또는 `tool_call_approval_required`
- `List` (여러 값에 대해 `in` 또는 `not in` 연산자 사용)

**노트**:

- 세 개의 `*_required` 상태는 사용자를 기다리는 플로우이며 `paused`와는 다릅니다.
- 상태는 대소문자를 구분하지 않고 일치합니다. `completed` 또는 `aborted`와 같은 다른 철자는 허용되지 않습니다.

### 사용자 {#user}

**Description (설명)**: 플로우를 실행한 사용자별로 필터링합니다.

**허용되는 값 유형**:

- `Number` (사용자 ID)
- `List` (여러 사용자 ID에 대해 `in` 또는 `not in` 연산자 사용)

> [!note]
> 사용자 이름 필터링 지원은 [이슈 599750](https://gitlab.com/gitlab-org/gitlab/-/work_items/599750)에서 추적 중입니다.

## 차원 {#dimensions}

| 차원 | 이름       | 설명 |
| --------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 생성됨   | `created`  | 날짜별로 그룹화합니다. `daily`, `weekly`, `monthly`, 또는 `30d`과 같은 일수(기본값: `monthly`)의 [`granularity` 매개변수](../_index.md#field-parameters)를 수락하며, 선택적인 `origin`를 지원합니다. 예를 들어 `created(weekly)` 또는 `created(granularity=30d, origin=2026-07-16)`입니다. |
| 플로우 유형 | `flowType` | 플로우 유형별로 그룹화합니다. |
| 그룹     | `group`    | 그룹별로 그룹화합니다. 최상위 그룹에서 계산된 `depth` 매개변수(`1`에서 `99`, 기본값: `1`)를 수락하므로 `group`는 최상위 그룹을 반환하고 `group(depth=2)`은 해당 부분 그룹을 반환합니다. 해당 깊이보다 위에 있는 플로우 또는 부분 그룹이 아닌 해당 깊이의 프로젝트에 있는 플로우(예: `depth=2`일 때 최상위 그룹 바로 아래의 프로젝트)는 그룹이 없으며, 결과는 그룹이 없는 여러 행을 포함할 수 있습니다. |
| 모델     | `model`    | 플로우가 사용한 모델별로 그룹화합니다(모델 카탈로그 이름 표시). 카탈로그에 없는 모델은 원시 식별자를 표시합니다. 모델 속성이 없는 플로우는 이름이 없습니다. 행은 플로우가 보고한 모델 식별자별로 그룹화되므로 하나의 카탈로그 이름이 여러 행 또는 차트 막대에 나타날 수 있습니다. |
| 프로젝트   | `project`  | 프로젝트별로 그룹화합니다. 프로젝트로 범위가 지정되지 않은 플로우는 프로젝트가 없는 단일 행으로 그룹화됩니다. |
| 상태    | `status`   | 플로우 상태별로 그룹화합니다. 행은 알파벳 순서가 아닌 수명 주기 순서로 정렬됩니다. |
| 사용자      | `user`     | 사용자별로 그룹화합니다(아바타, 이름 및 사용자 이름 표시). |
| 사용자 계층 | `userTier` | `created(weekly)`과 같은 다른 차원도 선택되어 있을 때도 사용자가 선택된 전체 기간에서 실행한 플로우 수별로 사용자를 그룹화합니다. `thresholds` 매개변수가 필요합니다: 최소한 `1`의 1~9개의 엄격하게 오름차순인 정수 목록이며 기본값은 없습니다. 예를 들어 `userTier(thresholds=[4, 25, 100])`는 `tier_0` (4개 미만의 플로우), `tier_1` (4~24개), `tier_2` (25~99개), 그리고 `tier_3` (100개 이상)을 반환합니다. 단일 임계값은 괄호 없이 쓸 수 있습니다: `userTier(8)`. |

## 메트릭 {#metrics}

| 메트릭                      | 이름                       | 설명 |
|-----------------------------|----------------------------|-------------|
| 이탈한 사용자 수         | `churnedUsersCount`        | 이전 기간에는 플로우를 실행했지만 이번에는 실행하지 않은 고유 사용자의 수입니다. |
| 종료된 MR 개수 최대         | `closedMrCountMax`         | 단일 플로우에서 생성된 가장 많은 종료된 머지 리퀘스트입니다. |
| 종료된 MR 개수 평균        | `closedMrCountMean`        | 플로우당 생성된 평균 종료된 머지 리퀘스트입니다. |
| 종료된 MR 개수 최소         | `closedMrCountMin`         | 단일 플로우에서 생성된 가장 적은 종료된 머지 리퀘스트입니다. |
| 종료된 MR 개수 분위수    | `closedMrCountQuantile`    | 주어진 분위수에서 플로우당 생성된 종료된 머지 리퀘스트입니다. `0.01`과 `0.99` 사이의 [`quantile` 매개변수](../_index.md#field-parameters)를 수락합니다(기본값: `0.5`). 예를 들어, `closedMrCountQuantile(0.95)`입니다. |
| 종료된 MR 개수 합계         | `closedMrCountSum`         | 모든 플로우에서 생성된 총 종료된 머지 리퀘스트입니다. |
| 생성된 MR 개수 최대        | `createdMrCountMax`        | 단일 플로우에서 생성된 가장 많은 머지 리퀘스트입니다. |
| 생성된 MR 개수 평균       | `createdMrCountMean`       | 플로우당 생성된 평균 머지 리퀘스트입니다. |
| 생성된 MR 개수 최소        | `createdMrCountMin`        | 단일 플로우에서 생성된 가장 적은 머지 리퀘스트입니다. |
| 생성된 MR 개수 분위수   | `createdMrCountQuantile`   | 주어진 분위수에서 플로우당 생성된 머지 리퀘스트입니다. `0.01`과 `0.99` 사이의 [`quantile` 매개변수](../_index.md#field-parameters)를 수락합니다(기본값: `0.5`). 예를 들어, `createdMrCountQuantile(0.95)`입니다. |
| 생성된 MR 개수 합계        | `createdMrCountSum`        | 모든 플로우에서 생성된 총 머지 리퀘스트입니다. |
| 병합된 MR당 크레딧 비율 | `creditsPerMergedMrRatio`  | 플로우에서 생성하고 나중에 병합된 머지 리퀘스트당 사용된 크레딧입니다. 머지 리퀘스트를 생성하지 않은 플로우를 포함하여 모든 플로우의 크레딧이 계산됩니다. |
| 사용된 크레딧 최대            | `creditsUsedMax`           | 단일 플로우에서 사용된 가장 많은 크레딧입니다. |
| 사용된 크레딧 평균           | `creditsUsedMean`          | 플로우당 사용된 평균 크레딧입니다. |
| 사용된 크레딧 최소            | `creditsUsedMin`           | 단일 플로우에서 사용된 가장 적은 크레딧입니다. |
| 사용된 크레딧 분위수       | `creditsUsedQuantile`      | 주어진 분위수에서 플로우당 사용된 크레딧입니다. `0.01`과 `0.99` 사이의 [`quantile` 매개변수](../_index.md#field-parameters)를 수락합니다(기본값: `0.5`). 예를 들어, `creditsUsedQuantile(0.95)`입니다. |
| 사용된 크레딧 합계            | `creditsUsedSum`           | 모든 플로우에서 사용된 총 크레딧입니다. |
| 플로우 유형 개수            | `flowTypesCount`           | 고유한 플로우 유형의 수입니다. |
| 참여한 사용자 수          | `joinedUsersCount`         | 이번 기간에는 플로우를 실행했지만 이전 기간에는 실행하지 않은 고유 사용자의 수입니다. |
| 병합된 MR 개수 최대         | `mergedMrCountMax`         | 단일 플로우에서 생성된 가장 많은 병합된 머지 리퀘스트입니다. |
| 병합된 MR 개수 평균        | `mergedMrCountMean`        | 플로우당 생성된 평균 병합된 머지 리퀘스트입니다. |
| 병합된 MR 개수 최소         | `mergedMrCountMin`         | 단일 플로우에서 생성된 가장 적은 병합된 머지 리퀘스트입니다. |
| 병합된 MR 개수 분위수    | `mergedMrCountQuantile`    | 주어진 분위수에서 플로우당 생성된 병합된 머지 리퀘스트입니다. `0.01`과 `0.99` 사이의 [`quantile` 매개변수](../_index.md#field-parameters)를 수락합니다(기본값: `0.5`). 예를 들어, `mergedMrCountQuantile(0.95)`입니다. |
| 병합된 MR 개수 합계         | `mergedMrCountSum`         | 모든 플로우에서 생성된 총 병합된 머지 리퀘스트입니다. |
| 열린 MR 개수 최대           | `openMrCountMax`           | 단일 플로우에서 생성된 가장 많은 열린 머지 리퀘스트입니다. |
| 열린 MR 개수 평균          | `openMrCountMean`          | 플로우당 생성된 평균 열린 머지 리퀘스트입니다. |
| 열린 MR 개수 최소           | `openMrCountMin`           | 단일 플로우에서 생성된 가장 적은 열린 머지 리퀘스트입니다. |
| 열린 MR 개수 분위수      | `openMrCountQuantile`      | 주어진 분위수에서 플로우당 생성된 열린 머지 리퀘스트입니다. `0.01`과 `0.99` 사이의 [`quantile` 매개변수](../_index.md#field-parameters)를 수락합니다(기본값: `0.5`). 예를 들어, `openMrCountQuantile(0.95)`입니다. |
| 열린 MR 개수 합계           | `openMrCountSum`           | 모든 플로우에서 생성된 총 열린 머지 리퀘스트입니다. |
| 이전 기간 사용자 수 | `previousPeriodUsersCount` | 이전 기간의 고유 사용자 수입니다. |
| 프로젝트 수              | `projectsCount`            | 고유한 프로젝트의 수입니다. 프로젝트로 범위가 지정되지 않은 플로우는 계산되지 않으므로 해당 플로우의 행에는 `0`이(가) 표시됩니다. |
| 반환된 사용자 수       | `returningUsersCount`      | 이전 기간에도 플로우를 실행한 고유 사용자의 수입니다. |
| 총 개수                 | `totalCount`               | 상태별로 선택적으로 필터링된 플로우의 총 개수입니다. 선택적 `status` 매개변수를 수락하며, 하나 이상의 플로우 상태(`status` 필터와 동일한 값)를 포함합니다. 예를 들어 `totalCount(status="finished")` 또는 `totalCount(status=["paused", "input_required"])`. 매개변수가 없거나 `status=[]` 상태로 모든 플로우가 계산됩니다. |
| 사용자 수                 | `usersCount`               | 고유 사용자의 수입니다. |

> [!note]
> 크레딧 메트릭(예: `creditsPerMergedMrRatio`)은 그룹 또는 프로젝트에 대한 소유자 또는 보안 관리자 역할이거나 [사용자 지정 역할](../../custom_roles/abilities.md)(`read_agent_artifacts` 권한 포함)이 필요합니다. 다른 사용자의 경우 이 메트릭은 비어 있습니다.

**노트**:

- `returningUsersCount`, `joinedUsersCount`, `churnedUsersCount`, 그리고 `previousPeriodUsersCount` 메트릭은 각 `created` 버킷을 선행 버킷과 비교하므로, `created` 차원도 선택될 때만 유효합니다. `created` 필터만으로는 부족합니다.
- `mergedMrCount`, `closedMrCount`, 그리고 `openMrCount` 메트릭은 플로우가 생성한 머지 리퀘스트 중 나중에 병합되거나, 병합되지 않고 종료되거나, 아직 열려 있는 것을 계산합니다. 이 메트릭은 이러한 머지 리퀘스트의 현재 상태보다 뒤처질 수 있으므로, 최근에 병합된 머지 리퀘스트는 여전히 열린 상태로 계산될 수 있습니다.

## 정렬 필드 {#sort-fields}

선택한 차원 또는 메트릭에 포함된 모든 필드별로 정렬합니다. 자세한 내용은 [분석 모드 정렬](../_index.md#sorting)을 참조하세요.

## 예제 {#examples}

- 지난 30일간 플로우 유형별 플로우:

  ````yaml
  ```glql
  title: "Duo workflows by flow type (last 30 days)"
  display: table
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -30d
  dimensions: flowType as "Flow"
  metrics: totalCount as "Flows", usersCount as "Users", creditsUsedSum as "Credits"
  sort: totalCount desc
  ```
  ````

- 월별 크레딧 사용 추세:

  ````yaml
  ```glql
  title: "Monthly Duo workflow credit usage trend"
  display: columnChart
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -90d
  dimensions: created(monthly) as "Month"
  metrics: creditsUsedSum as "Credits used"
  sort: created asc
  ```
  ````

- 채팅 플로우를 제외한 월별 크레딧 사용:

  ````yaml
  ```glql
  title: "Monthly Duo workflow credits, excluding chat"
  display: columnChart
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -90d and flowType not in ("chat", "agentic_chat/v1")
  dimensions: created(monthly) as "Month", flowType as "Flow"
  metrics: creditsUsedSum as "Credits used"
  sort: created asc
  ```
  ````

- 지난 30일간 모델별 크레딧:

  ````yaml
  ```glql
  title: "Duo workflow credits by model (last 30 days)"
  display: barChart
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -30d
  dimensions: model as "Model"
  metrics: creditsUsedSum as "Credits used"
  sort: creditsUsedSum desc
  ```
  ````

- 지난 30일간 크레딧별 상위 사용자:

  ````yaml
  ```glql
  title: "Top users by Duo workflow credits (last 30 days)"
  display: table
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -30d
  dimensions: user as "User"
  metrics: totalCount as "Flows", creditsUsedSum as "Credits", creditsUsedMean as "Avg credits per flow"
  sort: creditsUsedSum desc
  limit: 10
  ```
  ````

- 지난 30일간 상태별 플로우:

  ````yaml
  ```glql
  title: "Duo workflows by status (last 30 days)"
  display: table
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -30d
  dimensions: status as "Status"
  metrics: totalCount as "Flows", createdMrCountSum as "MRs created", mergedMrCountSum as "MRs merged", openMrCountSum as "MRs open"
  sort: status asc
  ```
  ````

- 주간 사용자 유지:

  ````yaml
  ```glql
  title: "Weekly Duo workflow user retention"
  display: table
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -90d
  dimensions: created(weekly) as "Week"
  metrics: usersCount as "Users", returningUsersCount as "Returning", joinedUsersCount as "Joined", churnedUsersCount as "Churned"
  sort: created desc
  ```
  ````

- 지난 30일간 활동 계층 및 플로우 유형별 사용자:

  ````yaml
  ```glql
  title: "Duo workflow users by activity tier (last 30 days)"
  display: table
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -30d
  dimensions: userTier(thresholds=[4, 25, 100]) as "Tier", flowType as "Flow"
  metrics: totalCount as "Flows", usersCount as "Users"
  sort: userTier asc
  ```
  ````

- 지난 30일간 상태별 플로우 개수 나란히:

  ````yaml
  ```glql
  title: "Duo workflows by outcome (last 30 days)"
  display: table
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -30d
  metrics: totalCount as "All", totalCount(status="finished") as "Completed", totalCount(status=["paused", "input_required"]) as "Waiting", totalCount(status="failed") as "Failed"
  ```
  ````

- 지난 30일간 그룹 비교:

  ````yaml
  ```glql
  title: "Duo workflow usage by subgroup (last 30 days)"
  display: table
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -30d
  dimensions: group(depth=2) as "Group"
  metrics: usersCount as "Users", creditsUsedSum as "Credits"
  sort: usersCount desc
  ```
  ````

- 그룹화 없이 전체 사용:

  ````yaml
  ```glql
  title: "Duo workflow usage overview (last 30 days)"
  display: table
  mode: analytics
  query: type = DuoWorkflow and group = "gitlab-org" and created > -30d
  metrics: totalCount as "Flows", usersCount as "Users", projectsCount as "Projects", creditsUsedQuantile(0.5) as "Median credits"
  ```
  ````
