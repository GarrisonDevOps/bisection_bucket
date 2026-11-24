---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 프로젝트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- `avatarUrl` 필드가 GitLab 18.11에서 [추가](https://gitlab.com/gitlab-org/glql/-/merge_requests/361)되었습니다.

{{< /history >}}

## 허용 범위 {#allowed-scopes}

| 범위       | 설명                                                                              |
| ----------- | ---------------------------------------------------------------------------------------- |
| `namespace` | 특정 네임스페이스에서 프로젝트를 쿼리합니다. `group`을(를) `namespace`의 별칭으로 사용할 수 있습니다. |

자세한 내용은 [범위](_index.md#scopes)를 참조하세요.

## 쿼리 필터 {#query-filters}

결과를 필터링하려면 `query` 매개변수에서 이 필드들을 사용하세요.

| 필드                                                    | 이름(및 별칭)       | 연산자  |
| -------------------------------------------------------- | ---------------------- | ---------- |
| [보관만](#project-archived-only)                  | `archivedOnly`         | `=`, `!=`  |
| [코드 커버리지 포함](#project-has-code-coverage)          | `hasCodeCoverage`      | `=`, `!=`  |
| [취약점 포함](#project-has-vulnerabilities)      | `hasVulnerabilities`   | `=`, `!=`  |
| [보관된 항목 포함](#project-include-archived)            | `includeArchived`      | `=`, `!=`  |
| [하위 그룹 포함](#project-include-subgroups)          | `includeSubgroups`     | `=`, `!=`  |
| [이슈 활성화](#project-issues-enabled)                | `issuesEnabled`        | `=`, `!=`  |
| [머지 리퀘스트 활성화](#project-merge-requests-enabled)| `mergeRequestsEnabled` | `=`, `!=`  |

### 보관만 {#project-archived-only}

**Description (설명)**: 보관된 프로젝트만 표시하도록 필터링합니다.

**허용되는 값의 유형**: `Boolean` (`true` 또는 `false` 중 하나)

**노트**:

- `includeArchived`과(와) 함께 사용할 수 없습니다.

### 코드 커버리지 포함 {#project-has-code-coverage}

**Description (설명)**: 코드 커버리지 보고서의 보유 여부에 따라 프로젝트를 필터링합니다.

**허용되는 값의 유형**: `Boolean` (`true` 또는 `false` 중 하나)

### 취약점 포함 {#project-has-vulnerabilities}

**Description (설명)**: 보안 취약점의 보유 여부에 따라 프로젝트를 필터링합니다.

**허용되는 값의 유형**: `Boolean` (`true` 또는 `false` 중 하나)

### 보관된 항목 포함 {#project-include-archived}

**Description (설명)**: 보관된 프로젝트를 결과에 포함합니다.

**허용되는 값의 유형**: `Boolean` (`true` 또는 `false` 중 하나)

**노트**:

- `archivedOnly`과(와) 함께 사용할 수 없습니다.
- 기본적으로 보관된 프로젝트는 포함되지 않습니다.

### 하위 그룹 포함 {#project-include-subgroups}

**Description (설명)**: 하위 그룹의 프로젝트를 포함할지 여부입니다.

**허용되는 값의 유형**: `Boolean` (`true` 또는 `false` 중 하나)

**노트**:

- 이 필드는 `namespace` 범위에서만 사용할 수 있습니다.
- `namespace` 범위가 지정되면 `true`로 기본 설정됩니다.

### 이슈 활성화 {#project-issues-enabled}

**Description (설명)**: 이슈 활성화 여부에 따라 프로젝트를 필터링합니다.

**허용되는 값의 유형**: `Boolean` (`true` 또는 `false` 중 하나)

### 머지 리퀘스트 활성화 {#project-merge-requests-enabled}

**Description (설명)**: 머지 리퀘스트 활성화 여부에 따라 프로젝트를 필터링합니다.

**허용되는 값의 유형**: `Boolean` (`true` 또는 `false` 중 하나)

## 표시 필드 {#display-fields}

| 필드                            | 이름(및 별칭)                 | 설명 |
| -------------------------------- | -------------------------------- | ----------- |
| Archived (아카이브됨)                         | `archived`                       | 프로젝트 보관 여부 표시 |
| 아바타 URL                       | `avatarUrl`                      | 프로젝트 아바타의 URL 표시 |
| Duo 기능 활성화             | `duoFeaturesEnabled`             | Duo 기능 활성화 여부 표시 |
| 포크됨                           | `forked`                         | 프로젝트가 포크인지 여부 표시 |
| 포크 수                      | `forksCount`                     | 포크의 수 표시 |
| 전체 경로                        | `fullPath`                       | 프로젝트의 전체 경로 표시 |
| 그룹                            | `group`                          | 프로젝트가 속한 그룹 표시 |
| ID                               | `id`                             | 프로젝트 ID 표시 |
| 이슈 활성화                   | `issuesEnabled`                  | 이슈 활성화 여부 표시 |
| 마지막 활동                    | `lastActivity`, `lastActivityAt` | 프로젝트가 마지막으로 활동한 시간 표시 |
| 머지 리퀘스트 활성화           | `mergeRequestsEnabled`           | 머지 리퀘스트 활성화 여부 표시 |
| 이름                             | `name`                           | 프로젝트 이름 표시 |
| 공개 이슈 수                | `openIssuesCount`                | 공개 이슈의 수 표시 |
| 공개 머지 리퀘스트 수        | `openMergeRequestsCount`         | 공개 머지 리퀘스트의 수 표시 |
| 경로                             | `path`                           | 프로젝트 경로 표시 |
| 시크릿 푸시 보호 활성화   | `secretPushProtectionEnabled`    | 시크릿 푸시 보호 활성화 여부 표시 |
| 별 수                       | `starCount`                      | 별의 수 표시 |
| 표시 수준                       | `visibility`                     | 프로젝트 표시 수준 표시 |
| 웹 URL                          | `webUrl`                         | 프로젝트의 웹 URL 표시 |

## 정렬 필드 {#sort-fields}

| 필드         | 이름(및 별칭)                 | 설명                    |
| ------------- | -------------------------------- | ------------------------------ |
| 전체 경로     | `fullPath`                       | 전체 경로 기준으로 정렬              |
| 마지막 활동 | `lastActivity`, `lastActivityAt` | 마지막 활동 날짜 기준으로 정렬     |
| 경로          | `path`                           | 경로 기준으로 정렬                   |

**노트**:

- `lastActivity`은(는) 내림차순(`desc`) 정렬 순서만 지원합니다.

## 예제 {#examples}

- `gitlab-org` 그룹의 모든 프로젝트를 경로 기준으로 정렬하여 나열합니다:

  ````yaml
  ```glql
  display: table
  fields: name, fullPath, starCount, openIssuesCount
  sort: path asc
  query: type = Project and group = "gitlab-org"
  ```
  ````

- `gitlab-org` 그룹의 모든 프로젝트를 최근 활동 순으로 정렬하여 나열합니다:

  ````yaml
  ```glql
  display: table
  fields: name, fullPath, lastActivity
  sort: lastActivity desc
  query: type = Project and group = "gitlab-org"
  ```
  ````
