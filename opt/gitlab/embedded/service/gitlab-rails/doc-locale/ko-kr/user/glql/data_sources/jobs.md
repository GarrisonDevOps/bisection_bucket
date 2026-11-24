---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 작업
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228521)되었습니다.
- `browseArtifactsPath`, `canPlayJob`, `commitPath`, `createdByTag`, `exitCode`, `pipeline`, `playPath`, `queuedDuration`, `refPath`, `retryPath` 및 `scheduledAt` 필드가 [GitLab 18.11에 추가되었습니다](https://gitlab.com/gitlab-org/glql/-/merge_requests/361).

{{< /history >}}

> [!note]
> 작업은 정렬을 지원하지 않습니다.

## 허용된 범위 {#allowed-scopes}

| 범위     | 설명                           |
| --------- | ------------------------------------- |
| `project` | 특정 프로젝트의 작업을 쿼리합니다.     |

자세한 내용은 [범위](_index.md#scopes)를 참조하세요.

## 쿼리 필터 {#query-filters}

`query` 매개변수의 이 필드들을 사용하여 결과를 필터링합니다.

| 필드                                          | 이름                | 연산자  |
| ---------------------------------------------- | ------------------- | ---------- |
| [종류](#job-kind)                              | `kind`              | `=`        |
| [파이프라인](#job-pipeline)                      | `pipeline`          | `=`        |
| [상태](#job-status)                          | `status`            | `=`        |
| [아티팩트 포함](#job-with-artifacts)          | `withArtifacts`     | `=`, `!=`  |

### 종류 {#job-kind}

**Description (설명)**: 작업을 종류별로 필터링합니다.

**허용된 값 유형**:

- `Enum`, `bridge` 또는 `build` 중 하나

**노트**:

- `bridge` 작업은 다운스트림 파이프라인을 시작하는 트리거 작업입니다.
- `build` 작업은 일반적인 CI/CD 작업입니다.

### 파이프라인 {#job-pipeline}

**Description (설명)**: 파이프라인 IID를 사용하여 작업이 속한 파이프라인별로 작업을 필터링합니다.

**허용된 값 유형**: `Number` (파이프라인 IID)

### 상태 {#job-status}

**Description (설명)**: 작업을 CI/CD 상태별로 필터링합니다.

**허용된 값 유형**:

- `Enum`, `canceled`, `canceling`, `created`, `failed`, `manual`, `pending`, `preparing`, `running`, `scheduled`, `skipped`, `success`, `waiting_for_callback` 또는 `waiting_for_resource` 중 하나

### 아티팩트 포함 {#job-with-artifacts}

**Description (설명)**: 작업에 아티팩트가 있는지 여부로 작업을 필터링합니다.

**허용된 값 유형**: `Boolean` (`true` 또는 `false`)

## 표시 필드 {#display-fields}

| 필드                  | 이름 (및 별칭)                   | 설명 |
| ---------------------- | ---------------------------------- | ----------- |
| 활성                 | `active`                           | 작업이 활성 상태인지 여부 표시 |
| 실패 허용          | `allowFailure`                     | 작업이 실패하도록 허용되었는지 여부 표시 |
| 아티팩트 경로 찾아보기  | `browseArtifactsPath`              | 작업의 아티팩트 아카이브를 찾아보기 위한 URL 표시 |
| 작업 실행 가능           | `canPlayJob`                       | 현재 사용자가 작업을 실행할 수 있는지 여부 표시 |
| 취소 가능             | `cancelable`                       | 작업을 취소할 수 있는지 여부 표시 |
| 커밋 경로            | `commitPath`                       | 작업을 트리거한 커밋의 경로 표시 |
| 범위               | `coverage`                         | 코드 범위 백분율 표시 |
| 생성 시간             | `created`, `createdAt`             | 작업이 생성된 시간 표시 |
| 태그로 생성됨         | `createdByTag`                     | 작업이 태그로 생성되었는지 여부 표시 |
| 지속 시간               | `duration`                         | 작업 지속 시간 표시 |
| 삭제된 시간              | `erased`, `erasedAt`               | 작업 아티팩트가 삭제된 시간 표시 |
| 종료 코드              | `exitCode`                         | 작업의 종료 코드 표시 |
| 오류 메시지        | `failureMessage`                   | 오류 메시지 표시 |
| 완료 시간            | `finished`, `finishedAt`           | 작업이 완료된 시간 표시 |
| ID                     | `id`                               | 작업 ID 표시 |
| 종류                   | `kind`                             | 작업 종류(`bridge` 또는 `build`) 표시 |
| 수동 작업             | `manualJob`                        | 수동 작업인지 여부 표시 |
| 이름                   | `name`                             | 작업 이름 표시 |
| 파이프라인               | `pipeline`                         | 작업이 속한 파이프라인 표시 |
| 재생 경로              | `playPath`                         | 작업을 재생하기 위한 경로 표시 |
| 재생 가능               | `playable`                         | 작업을 재생할 수 있는지 여부 표시 |
| 대기 시간              | `queued`, `queuedAt`               | 작업이 대기된 시간 표시 |
| 대기 기간        | `queuedDuration`                   | 작업이 시작되기 전에 대기한 기간 표시 |
| Ref 이름               | `refName`                          | Git ref 이름 표시 |
| Ref 경로               | `refPath`                          | 작업을 트리거한 ref의 경로 표시 |
| 재시도됨                | `retried`                          | 작업이 재시도되었는지 여부 표시 |
| 재시도 경로             | `retryPath`                        | 작업을 재시도하기 위한 경로 표시 |
| 재시도 가능              | `retryable`                        | 작업을 재시도할 수 있는지 여부 표시 |
| 예약됨              | `scheduled`                        | 작업이 예약되었는지 여부 표시 |
| 예약된 시간           | `scheduledAt`                      | 작업이 실행되도록 예약된 시간 표시 |
| 예약 유형        | `schedulingType`                   | 예약 유형 표시 |
| 단축 SHA              | `shortSha`                         | 단축 커밋 SHA 표시 |
| 소스                 | `source`                           | 작업 소스 표시 |
| 스테이지                  | `stage`                            | 작업이 속한 파이프라인 스테이지 표시 |
| 시작 시간             | `started`, `startedAt`             | 작업이 시작된 시간 표시 |
| 상태                 | `status`                           | 작업 상태 표시 |
| 정지됨                  | `stuck`                            | 작업이 정지되었는지 여부 표시 |
| 태그                   | `tags`                             | 러너 태그 표시 |
| 트리거됨              | `triggered`                        | 작업이 트리거되었는지 여부 표시 |
| 웹 경로               | `webPath`                          | 작업의 웹 경로 표시 |

## 예제 {#examples}

- `gitlab-org/gitlab` 프로젝트의 모든 실패한 작업 나열:

  ````yaml
  ```glql
  display: table
  fields: name, status, stage, startedAt
  query: type = Job and project = "gitlab-org/gitlab" and status = failed
  ```
  ````

- `gitlab-org/gitlab` 프로젝트의 아티팩트가 있는 모든 작업 나열:

  ````yaml
  ```glql
  display: table
  fields: name, status, stage
  query: type = Job and project = "gitlab-org/gitlab" and withArtifacts = true
  ```
  ````
