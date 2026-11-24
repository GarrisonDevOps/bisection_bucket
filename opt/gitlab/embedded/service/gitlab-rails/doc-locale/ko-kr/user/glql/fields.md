---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GLQL 필드
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- `glql_integration`라는 이름의 [기능 플래그](../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14767)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.4에서 일부 그룹 및 프로젝트를 위해 GitLab.com에서 활성화되었습니다.
- [GitLab 17.10에서 실험에서](https://gitlab.com/gitlab-org/gitlab/-/issues/476990) [베타](../../policy/development_stages_support.md#beta)로 변경되었습니다.
- GitLab 17.10의 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/work_items/476990)되었습니다.
- GitLab 18.3에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/554870)입니다. 기능 플래그 `glql_integration`이 제거되었습니다.

{{< /history >}}

GitLab Query Language(GLQL)를 사용하면 필드는 다음과 같이 사용됩니다:

- [GLQL 쿼리](_index.md#query-syntax)에서 반환된 결과를 필터링합니다.
- [임베드된 보기](_index.md#presentation-syntax)에 표시된 세부 정보를 제어합니다.
- 임베드된 보기에 표시된 결과를 정렬합니다.

세 가지 임베드된 보기 매개변수에서 필드를 사용합니다:

- **`query`** - 검색할 항목을 결정하는 조건을 설정합니다. `query` 매개변수는 `<field> <operator> <value>` 형식의 하나 이상의 표현식을 포함할 수 있습니다. 여러 표현식은 `and`으로 연결되며, 예를 들어 `group = "gitlab-org" and author = currentUser()`입니다.
- **`fields`** - 보기에 표시할 열과 세부 정보를 지정합니다. 필드 또는 [필드 함수](functions.md#functions-in-embedded-views)의 쉼표로 구분된 목록입니다(예: `fields: title, state, health, epic, milestone, weight, updated`).
- **`sort`** - 특정 기준으로 항목을 정렬합니다. 필드 이름 뒤에 정렬 순서(`asc` 또는 `desc`)가 오며, 예를 들어 `sort: updated desc`입니다.

## 데이터 소스 {#data-sources}

지원되는 데이터 원본 및 해당 필드의 목록은 [GLQL 데이터 원본](data_sources/_index.md)을 참조하세요.

## 문제 해결 {#troubleshooting}

### 쿼리 시간 초과 오류 {#query-timeout-errors}

다음 오류 메시지가 표시될 수 있습니다:

```plaintext
Embedded view timed out. Add more filters to reduce the number of results.
```

```plaintext
Query temporarily blocked due to repeated timeouts. Please try again later or try narrowing your search scope.
```

이러한 오류는 쿼리 실행이 너무 오래 걸릴 때 발생합니다. 큰 결과 집합과 광범위한 검색으로 인해 시간 초과가 발생할 수 있습니다.

이 문제를 해결하려면 검색 범위를 제한하는 필터를 추가하세요:

- `created`, `updated` 또는 `closed`와 같은 날짜 필드를 사용하여 결과를 특정 기간으로 제한하는 시간 범위 필터를 추가합니다. 예를 들어:

  ````yaml
  ```glql
  display: table
  fields: title, labels, created
  query: type = Issue and group = "gitlab-org" and label = "group::planner intelligence" and created > "2025-01-01" and created < "2025-03-01"
  ```
  ````

- 최근 업데이트로 필터링하여 활성 항목에 초점을 맞춥니다:

  ````yaml
  ```glql
  display: table
  fields: title, labels, updated
  query: type = Issue and group = "gitlab-org" and label = "group::planner intelligence" and updated > -3m
  ```
  ````

- 가능한 경우 그룹 전체 검색 대신 프로젝트별 쿼리를 사용합니다:

  ````yaml
  ```glql
  display: table
  fields: title, state, assignee
  query: type = Issue and project = "gitlab-org/gitlab" and state = opened and updated > -1m
  ```
  ````
