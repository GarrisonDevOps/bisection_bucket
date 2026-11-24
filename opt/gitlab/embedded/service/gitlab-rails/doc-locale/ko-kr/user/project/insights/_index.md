---
stage: Analytics
group: Optimize
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 인사이트
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

인사이트는 매월 항목 수(예: 생성된 버그)를 표시하는 대화형 막대형 차트입니다.

프로젝트 및 그룹에 대한 인사이트를 구성하고 사용자 정의 보고서를 만들어 다음과 같은 데이터를 탐색합니다:

- 지정된 기간 동안 생성 및 종료된 이슈입니다.
- 병합 요청이 병합되기까지의 평균 시간입니다.
- 심사 위생 상태입니다.

## 인사이트 보기 {#view-insights}

사전 요구 사항:

- 프로젝트 인사이트의 경우 프로젝트에 대한 액세스 권한과 병합 요청 및 이슈에 대한 정보를 볼 수 있는 권한이 있어야 합니다.
- 그룹 인사이트의 경우 그룹을 볼 수 있는 권한이 있어야 합니다.

프로젝트 또는 그룹의 인사이트를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **분석** > **인사이트**를 선택합니다.
1. **보고서 선택** 드롭다운 목록에서 보려는 보고서를 선택합니다. 주석을 보려면 차트의 각 막대 위에 마우스를 놓습니다.
1. 선택 사항. 결과를 필터링합니다:
   - 90일 범위의 하위 집합에서만 데이터를 표시하려면 일시 중지 아이콘({{< icon name="status-paused" >}})을 선택하고 가로축을 따라 드래그합니다.
   - 차트에서 차원을 제외하려면 차트 아래의 범례에서 차원 이름을 선택합니다.

### 차트 드릴다운 {#drill-down-on-charts}

`query.data_source`이 `issuables`인 모든 차트의 데이터로 드릴다운할 수 있습니다.

특정 우선순위 또는 심각도에 대한 한 달간의 드릴다운 보고서를 보려면:

- 차트에서 드릴다운하려는 막대 스택을 선택합니다.

### 보고서 딥 링크 생성 {#create-a-report-deep-link}

딥 링크된 URL을 사용하여 사용자를 인사이트의 특정 보고서로 이동시킬 수 있습니다.

딥 링크를 생성하려면 보고서 키를 인사이트 보고서 URL의 끝에 추가합니다. 예를 들어 `bugsCharts` 키가 있는 GitLab 보고서는 `https://gitlab.com/gitlab-org/gitlab/insights/#/bugsCharts` 딥 링크 URL을 갖습니다.

## 구성 {#configuration}

### 기본 파일 {#default-file}

GitLab은 [기본 구성 파일](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/fixtures/insights/default.yml)에서 인사이트를 읽습니다.

프로젝트 인사이트는 프로젝트의 [`.gitlab/insights.yml`](#configuration) 파일로 구성됩니다. 프로젝트에 구성 파일이 없으면 [그룹 구성](#for-groups)을 사용합니다.

`.gitlab/insights.yml` 파일은 다음을 정의하는 YAML 파일입니다:

- 보고서의 차트 구조 및 순서입니다.
- 프로젝트 또는 그룹의 보고서에 표시되는 차트의 스타일입니다.

`.gitlab/insights.yml` 파일에서:

- [구성 매개변수](#parameters)는 차트 동작을 정의합니다.
- 각 보고서는 고유한 키와 가져오고 표시할 차트 모음을 포함합니다.
- 각 차트 정의는 키-값 쌍으로 구성된 해시로 이루어집니다.

#### 예 {#example}

다음 예제는 차트 하나가 있는 보고서를 표시하는 단일 정의를 보여줍니다:

```yaml
bugsCharts:
  title: "Charts for bugs"
  charts:
    - title: "Monthly bugs created"
      description: "Open bugs created per month"
      type: bar
      query:
        data_source: issuables
        params:
          issuable_type: issue
          issuable_state: opened
          filter_labels:
            - bug
          group_by: month
          period_limit: 24
```

다음 예제는 3개의 차트를 표시하는 `.gitlab/insights.yml` 파일의 완전한 구성을 보여줍니다:

```yaml
.projectsOnly: &projectsOnly
  projects:
    only:
      - 3
      - groupA/projectA
      - groupA/subgroupB/projectC

bugsCharts:
  title: "Charts for bugs"
  charts:
    - title: "Monthly bugs created"
      description: "Open bugs created per month"
      type: bar
      <<: *projectsOnly
      query:
        data_source: issuables
        params:
          issuable_type: issue
          issuable_state: opened
          filter_labels:
            - bug
          group_by: month
          period_limit: 24

    - title: "Weekly bugs by severity"
      type: stacked-bar
      <<: *projectsOnly
      query:
        data_source: issuables
        params:
          issuable_type: issue
          issuable_state: opened
          filter_labels:
            - bug
          collection_labels:
            - S1
            - S2
            - S3
            - S4
          group_by: week
          period_limit: 104

    - title: "Monthly bugs by team"
      type: line
      <<: *projectsOnly
      query:
        data_source: issuables
        params:
          issuable_type: merge_request
          issuable_state: opened
          filter_labels:
            - bug
          collection_labels:
            - Manage
            - Plan
            - Create
          group_by: month
          period_limit: 24
```

### 매개변수 {#parameters}

다음 표는 차트 매개변수를 나열합니다:

| 키워드                                            | 설명 |
|:---------------------------------------------------|:------------|
| [`title`](#title)                                  | 차트의 제목입니다. 인사이트 페이지에 표시됩니다. |
| [`description`](#description)                      | 개별 차트에 대한 설명입니다. 관련 차트 위에 표시됩니다. |
| [`type`](#type)                                    | 차트 유형: `bar`, `line` 또는 `stacked-bar`입니다. |
| [`query`](#query)                                  | 차트의 데이터 소스 및 필터링 조건을 정의하는 해시입니다. |

#### `title` {#title}

`title`을 사용하여 차트 제목을 업데이트합니다. 제목이 인사이트 보고서에 표시됩니다.

**예**:

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
```

#### `description` {#description}

`description`을 사용하여 차트 설명을 추가합니다. 설명이 제목 아래 차트 위에 표시됩니다.

**예**:

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
  description: "Open bugs created per month"
```

#### `type` {#type}

`type`을 사용하여 차트 유형을 정의합니다.

**지원되는 값**:

| 이름  | 예: |
| ----- | ------- |
| `bar` | ![인사이트 예제 막대형 차트](img/insights_example_bar_chart_v11_10.png) |
| `bar`(`group_by`를 포함한 시계열) | ![인사이트 예제 막대형 시계열 차트](img/insights_example_bar_time_series_chart_v11_10.png) |
| `line` | ![인사이트 예제 누적 막대형 차트](img/insights_example_line_chart_v11_10.png) |
| `stacked-bar` | ![인사이트 예제 누적 막대형 차트](img/insights_example_stacked_bar_chart_v11_10.png) |

`dora` 데이터 소스는 `bar` 및 `line` [차트 유형](#type)을 지원합니다.

**예**:

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
  type: bar
```

#### `query` {#query}

`query`을 사용하여 차트의 데이터 소스 및 필터링 조건을 정의합니다.

**예**:

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
  description: "Open bugs created per month"
  type: bar
  query:
    data_source: issuables
    params:
      issuable_type: issue
      issuable_state: opened
      filter_labels:
        - bug
      collection_labels:
        - S1
        - S2
        - S3
        - S4
      group_by: week
      period_limit: 104
```

`data_source` 매개변수 없이 기존 형식이 여전히 지원됩니다:

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
  description: "Open bugs created per month"
  type: bar
  query:
    issuable_type: issue
    issuable_state: opened
    filter_labels:
      - bug
    collection_labels:
      - S1
      - S2
      - S3
      - S4
    group_by: week
    period_limit: 104
```

##### `query.data_source` {#querydata_source}

`data_source`을 사용하여 데이터를 노출하는 데이터 소스를 정의합니다.

**지원되는 값**:

- `issuables`: 병합 요청 또는 이슈 데이터를 노출합니다.
- `dora`: DORA 메트릭을 노출합니다.

##### `issuable` 쿼리 매개변수 {#issuable-query-parameters}

###### `query.params.issuable_type` {#queryparamsissuable_type}

`query.params.issuable_type`을 사용하여 차트를 생성할 이슈 가능 유형을 정의합니다.

**지원되는 값**:

- `issue`: 차트에 이슈 데이터가 표시됩니다.
- `merge_request`: 차트에 병합 요청 데이터가 표시됩니다.

###### `query.params.issuable_state` {#queryparamsissuable_state}

`query.params.issuable_state`을 사용하여 쿼리된 이슈 가능의 현재 상태로 필터링합니다.

기본적으로 `opened` 상태 필터가 적용됩니다.

**지원되는 값**:

- `opened`: 열린 이슈 또는 병합 요청입니다.
- `closed`: 종료된 이슈 또는 병합 요청입니다.
- `locked`: 토론이 잠긴 이슈 또는 병합 요청입니다.
- `merged`: 병합된 병합 요청입니다.
- `all`: 모든 상태의 이슈 또는 병합 요청입니다.

###### `query.params.filter_labels` {#queryparamsfilter_labels}

`query.params.filter_labels`을 사용하여 쿼리된 이슈 가능에 적용된 레이블로 필터링합니다.

기본적으로 레이블 필터가 적용되지 않습니다. 모든 정의된 레이블을 이슈 가능에 적용하여 선택해야 합니다.

**예**:

```yaml
monthlyBugsCreated:
  title: "Monthly regressions created"
  type: bar
  query:
    data_source: issuables
    params:
      issuable_type: issue
      issuable_state: opened
      filter_labels:
        - bug
        - regression
```

###### `query.params.collection_labels` {#queryparamscollection_labels}

`query.params.collection_labels`을 사용하여 구성된 레이블로 이슈 가능을 그룹화합니다. 기본적으로 그룹화가 적용되지 않습니다.

**예**:

```yaml
weeklyBugsBySeverity:
  title: "Weekly bugs by severity"
  type: stacked-bar
  query:
    data_source: issuables
    params:
      issuable_type: issue
      issuable_state: opened
      filter_labels:
        - bug
      collection_labels:
        - S1
        - S2
        - S3
        - S4
```

###### `query.group_by` {#querygroup_by}

`query.group_by`을 사용하여 차트의 X축을 정의합니다.

**지원되는 값**:

- `day`: 날짜별로 데이터를 그룹화합니다.
- `week`: 주별로 데이터를 그룹화합니다.
- `month`: 월별로 데이터를 그룹화합니다.

###### `query.period_limit` {#queryperiod_limit}

`query.period_limit`을 사용하여 이슈 가능을 쿼리할 시간을 정의합니다(`query.period_field` 사용).

단위는 `query.group_by`에서 정의된 값과 관련이 있습니다. 예를 들어 `query.group_by: 'day'`을 정의하고 `query.period_limit: 365`인 경우 차트는 지난 365일의 데이터를 표시합니다.

기본적으로 정의한 `query.group_by`에 따라 기본값이 적용됩니다.

| `query.group_by` | 기본값 |
| ---------------- | ------------- |
| `day`            | 30            |
| `week`           | 4             |
| `month`          | 12            |

##### `query.period_field` {#queryperiod_field}

`query.period_field`을 사용하여 이슈 가능을 그룹화할 타임스탬프 필드를 정의합니다.

**지원되는 값**:

- `created_at`(기본값): `created_at` 필드를 사용하여 데이터를 그룹화합니다.
- `closed_at`: `closed_at` 필드를 사용하여 데이터를 그룹화합니다(이슈만 해당).
- `merged_at`: `merged_at` 필드를 사용하여 데이터를 그룹화합니다(병합 요청만 해당).

`period_field`은 자동으로 다음으로 설정됩니다:

- `closed_at` (`query.issuable_state`이 `closed`인 경우)
- `merged_at` (`query.issuable_state`이 `merged`인 경우)
- `created_at` (그 외의 경우)

> [!note]
> [이 버그](https://gitlab.com/gitlab-org/gitlab/-/issues/26911)가 해결될 때까지 `merged_at` 대신 `created_at`이 표시될 수 있습니다. `created_at`이 대신 사용됩니다.

##### `DORA` 쿼리 매개변수 {#dora-query-parameters}

`dora` 데이터 소스와 DORA 관련 쿼리를 사용하여 DORA 차트 정의를 생성합니다.

**예**:

```yaml
dora:
  title: "DORA charts"
  charts:
    - title: "DORA deployment frequency"
      type: bar # or line
      query:
        data_source: dora
        params:
          metric: deployment_frequency
          group_by: day
          period_limit: 10
      projects:
        only:
          - 38
    - title: "DORA lead time for changes"
      description: "DORA lead time for changes"
      type: bar
      query:
        data_source: dora
        params:
          metric: lead_time_for_changes
          group_by: day
          environment_tiers:
            - staging
          period_limit: 30
```

###### `query.metric` {#querymetric}

`query.metric`을 사용하여 쿼리할 [DORA 메트릭](../../../api/dora/metrics.md#the-value-field)을 정의합니다.

**지원되는 값**:

- `deployment_frequency` (기본값)
- `lead_time_for_changes`
- `time_to_restore_service`
- `change_failure_rate`

###### `query.group_by` {#querygroup_by-1}

`query.group_by`을 사용하여 차트의 X축을 정의합니다.

**지원되는 값**:

- `day`(기본값): 날짜별로 데이터를 그룹화합니다.
- `month`: 월별로 데이터를 그룹화합니다.

###### `query.period_limit` {#queryperiod_limit-1}

`query.period_limit`을 사용하여 메트릭을 과거에 쿼리하는 범위를 정의합니다(기본값: 15). 최대 기간은 180일 또는 6개월입니다.

###### `query.environment_tiers` {#queryenvironment_tiers}

`query.environment_tiers`을 사용하여 계산을 포함할 환경의 배열을 정의합니다.

**지원되는 값**:

- `production`(기본값)
- `staging`
- `testing`
- `development`
- `other`

#### `projects` {#projects}

`projects`을 사용하여 이슈 가능을 쿼리할 위치를 제한합니다:

- `.gitlab/insights.yml`이 그룹의 인사이트에 사용되는 경우 `projects`를 사용하여 이슈 가능을 쿼리할 프로젝트를 정의합니다. 기본적으로 그룹의 모든 프로젝트가 사용됩니다.
- `.gitlab/insights.yml`이 프로젝트의 인사이트에 사용되는 경우 다른 프로젝트를 지정해도 결과가 나오지 않습니다. 기본적으로 프로젝트가 사용됩니다.

##### `projects.only` {#projectsonly}

`projects.only`을 사용하여 이슈 가능을 쿼리할 프로젝트를 지정합니다.

이 매개변수에 나열된 프로젝트는 다음의 경우 무시됩니다:

- 존재하지 않습니다.
- 현재 사용자가 이를 읽을 수 있는 충분한 권한이 없습니다.
- 그룹 외부에 있습니다.

**예**:

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
  description: "Open bugs created per month"
  type: bar
  query:
    data_source: issuables
    params:
      issuable_type: issue
      issuable_state: opened
      filter_labels:
        - bug
  projects:
    only:
      - 3                         # You can use the project ID
      - groupA/projectA           # Or full project path
      - groupA/subgroupB/projectC # Projects in subgroups can be included
      - groupB/project            # Projects outside the group will be ignored
```

### 인사이트 구성 {#configure-insights}

프로젝트 및 그룹에 대한 인사이트를 구성할 수 있습니다. 프로젝트에 `.gitlab/insights.yml` 파일을 생성한 후 프로젝트의 그룹에도 사용할 수 있습니다.

> [!note]
> 사용자 정의 `.gitlab/insights.yml` 파일은 기본 구성을 재정의합니다. 원본 구성을 유지하려면 [기본 구성 파일](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/fixtures/insights/default.yml)의 내용을 기반으로 복사합니다.

#### 프로젝트의 경우 {#for-projects}

사전 요구 사항:

- 프로젝트에 대해 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

프로젝트 인사이트를 구성하려면 `.gitlab/insights.yml` 파일을 생성합니다:

- 프로젝트의 루트 디렉터리에 로컬로 생성하고 변경 사항을 푸시합니다.
- UI에서:
  1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
  1. 파일 목록 위에서 커밋할 브랜치를 선택하고 더하기 아이콘을 선택한 다음 **새 파일**을 선택합니다.
  1. **파일명**에 `.gitlab/insights.yml`을 입력합니다.
  1. 파일 편집기에서 구성을 입력합니다. [구성 예제](#example)를 참조하세요.
  1. **변경 사항 커밋**을 선택합니다.

#### 그룹의 경우 {#for-groups}

사전 요구 사항:

- 그룹의 프로젝트는 `.gitlab/insights.yml` 파일을 포함해야 합니다.

그룹 인사이트를 구성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **분석**을 선택합니다.
1. **인사이트** 섹션에서 `.gitlab/insights.yml` 구성 파일을 포함하는 프로젝트를 선택합니다.
1. **변경 사항 저장**을 선택합니다.
