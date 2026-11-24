---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 파이프라인
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228521)되었습니다.
- `commit`, `commitPath`, `refPath`, `stages`, 및 `user` 필드가 GitLab 18.11에 [추가됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/361).

{{< /history >}}

## 허용되는 모드 {#allowed-modes}

- 표준 모드(기본): 파이프라인 레코드를 쿼리합니다.
- 분석 모드: 집계된 파이프라인 메트릭을 쿼리합니다. 자세한 내용은 [파이프라인 분석](pipeline_analytics.md)을 참조하세요.

> [!note]
> 표준 모드는 정렬을 지원하지 않습니다.

## 허용 범위 {#allowed-scopes}

| 범위     | 설명                              |
| --------- | ---------------------------------------- |
| `project` | 특정 프로젝트의 파이프라인을 쿼리합니다.   |

자세한 내용은 [범위](_index.md#scopes)를 참조하세요.

## 쿼리 필터 {#query-filters}

결과를 필터링하려면 `query` 매개변수에서 이 필드들을 사용하세요.

| 필드                                          | 이름(및 별칭)                             | 연산자                  |
| ---------------------------------------------- | -------------------------------------------- | -------------------------- |
| [작성자](#pipeline-author)                     | `author`                                     | `=`                        |
| [브랜치](#pipeline-ref)                           | `ref`                                        | `=`                        |
| [범위](#pipeline-scope)                       | `scope`                                      | `=`                        |
| [SHA](#pipeline-sha)                           | `sha`                                        | `=`                        |
| [소스](#pipeline-source)                     | `source`                                     | `=`                        |
| [상태](#pipeline-status)                     | `status`                                     | `=`                        |
| [업데이트 시간](#pipeline-updated-at)             | `updated`, `updatedAt`                       | `=`, `>`, `<`, `>=`, `<=`  |

### 작성자 {#pipeline-author}

**Description (설명)**: 이를 트리거한 사용자별로 파이프라인을 필터링합니다.

**허용되는 값 유형**:

- `String`
- `User` (예: `@username`)

### 브랜치 {#pipeline-ref}

**Description (설명)**: 실행된 Git 브랜치 또는 태그 이름으로 파이프라인을 필터링합니다.

**허용되는 값 유형**: `String`

### 범위 {#pipeline-scope}

**Description (설명)**: 범위별로 파이프라인을 필터링합니다.

**허용되는 값 유형**:

- `Enum`, `branches`, `tags`, `finished`, `pending`, 또는 `running` 중 하나

### SHA {#pipeline-sha}

**Description (설명)**: 커밋 SHA별로 파이프라인을 필터링합니다.

**허용되는 값 유형**: `String`

### 소스 {#pipeline-source}

**Description (설명)**: 이를 트리거한 것을 기준으로 파이프라인을 필터링합니다.

**허용되는 값 유형**: `String`

### 상태 {#pipeline-status}

**Description (설명)**: CI/CD 상태로 파이프라인을 필터링합니다.

**허용되는 값 유형**:

- `Enum`, `canceled`, `canceling`, `created`, `failed`, `manual`, `pending`, `preparing`, `running`, `scheduled`, `skipped`, `success`, `waiting_for_callback` 또는 `waiting_for_resource` 중 하나

### 업데이트 시간 {#pipeline-updated-at}

**Description (설명)**: 마지막으로 업데이트된 시간을 기준으로 파이프라인을 필터링합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (형식 `YYYY-MM-DD`)
- `RelativeDate` (형식 `<sign><digit><unit>`, 부호는 `+`, `-`, 또는 생략되며, 숫자는 정수이고, `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (년) 중 하나)

**노트**:

- `=` 연산자의 경우, 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지로 간주됩니다.

## 표시 필드 {#display-fields}

| 필드              | 이름(및 별칭)                   | 설명 |
| ------------------ | ---------------------------------- | ----------- |
| 활성             | `active`                           | 파이프라인이 활성인지 여부를 표시합니다 |
| 취소 가능         | `cancelable`                       | 파이프라인을 취소할 수 있는지 여부를 표시합니다 |
| 하위              | `child`                            | 하위 파이프라인인지 여부를 표시합니다 |
| 커밋             | `commit`                           | 커밋 세부 정보(ID, 짧은 ID, 제목, 작성자 이름, 웹 URL) 표시 |
| 커밋 경로        | `commitPath`                       | 파이프라인을 트리거한 커밋의 경로를 표시합니다 |
| 커밋 시간       | `committed`, `committedAt`         | 커밋 타임스탬프를 표시합니다 |
| 완료           | `complete`                         | 파이프라인이 완료되었는지 여부를 표시합니다 |
| 계산 시간    | `computeMinutes`                   | 사용된 계산 시간을 표시합니다 |
| 구성 소스      | `configSource`                     | 파이프라인 구성 소스를 표시합니다 |
| 범위           | `coverage`                         | 코드 범위 백분율을 표시합니다 |
| 생성 시간         | `created`, `createdAt`             | 파이프라인이 생성된 시간을 표시합니다 |
| 지속 시간           | `duration`                         | 파이프라인 지속 시간을 표시합니다 |
| 실패한 작업 수  | `failedJobsCount`                  | 실패한 작업의 수를 표시합니다 |
| 실패 이유     | `failureReason`                    | 파이프라인 실패 이유를 표시합니다 |
| 완료 시간        | `finished`, `finishedAt`           | 파이프라인이 완료된 시간을 표시합니다 |
| ID                 | `id`                               | 파이프라인 ID를 표시합니다 |
| IID                | `iid`                              | 파이프라인 내부 ID를 표시합니다 |
| 최신             | `latest`                           | 참조에 대한 최신 파이프라인인지 여부를 표시합니다 |
| 이름               | `name`                             | 파이프라인 이름을 표시합니다 |
| 경로               | `path`                             | 파이프라인 경로를 표시합니다 |
| 브랜치                | `ref`                              | Git 참조(브랜치 또는 태그)를 표시합니다 |
| 참조 경로           | `refPath`                          | 파이프라인을 트리거한 참조의 경로를 표시합니다 |
| 재시도 가능          | `retryable`                        | 파이프라인을 재시도할 수 있는지 여부를 표시합니다 |
| SHA                | `sha`                              | 커밋 SHA를 표시합니다 |
| 소스             | `source`                           | 파이프라인을 트리거한 것을 표시합니다 |
| 스테이지             | `stages`                           | 파이프라인 스테이지(이름 및 상태)를 표시합니다 |
| 시작 시간         | `started`, `startedAt`             | 파이프라인이 시작된 시간을 표시합니다 |
| 상태             | `status`                           | 파이프라인 상태를 표시합니다 |
| 정지됨              | `stuck`                            | 파이프라인이 정지되었는지 여부를 표시합니다 |
| 총 작업 수         | `totalJobs`                        | 총 작업 수를 표시합니다 |
| 업데이트 시간         | `updated`, `updatedAt`             | 파이프라인이 마지막으로 업데이트된 시간을 표시합니다 |
| 사용자               | `user`                             | 파이프라인을 트리거한 사용자를 표시합니다 |
| 경고           | `warnings`                         | 파이프라인 경고를 표시합니다 |
| YAML 오류        | `yamlErrors`                       | 파이프라인에 YAML 오류가 있는지 여부를 표시합니다 |
| YAML 오류 메시지| `yamlErrorMessages`                | YAML 오류 메시지를 표시합니다 |

## 알려진 이슈 {#known-issues}

- 큰 날짜 범위가 있는 쿼리는 시간 초과를 일으킬 수 있습니다.

## 예제 {#examples}

- `gitlab-org/gitlab` 프로젝트에서 오늘 실패한 모든 파이프라인을 나열합니다:

  ````yaml
  ```glql
  title: "Failed pipelines today"
  display: table
  fields: id, ref, status, startedAt
  query: type = Pipeline and project = "gitlab-org/gitlab" and status = failed and updated = today()
  ```
  ````

- `gitlab-org/gitlab` 프로젝트의 모든 Duo 에이전트 파이프라인을 나열합니다:

  ````yaml
  ```glql
  title: "GitLab Duo agent pipelines"
  display: table
  fields: id, ref, status, source, startedAt
  query: type = Pipeline and project = "gitlab-org/gitlab" and source = "duo_workflow"
  ```
  ````
