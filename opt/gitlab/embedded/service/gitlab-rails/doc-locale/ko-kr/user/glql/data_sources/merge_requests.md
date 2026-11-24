---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 병합 요청
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [GitLab 17.8에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/491246)

{{< /history >}}

## 허용되는 모드 {#allowed-modes}

- 표준 모드(기본값): 병합 요청 레코드를 조회합니다.
- 분석 모드: 집계된 병합 요청 메트릭을 조회합니다. 자세한 내용은 [병합 요청 분석](merge_request_analytics.md)을 참조하세요.

## 허용되는 범위 {#allowed-scopes}

| 범위     | 설명                                           |
| --------- | ----------------------------------------------------- |
| `project` | 특정 프로젝트의 병합 요청을 쿼리합니다.           |
| `group`   | 서브그룹을 포함한 그룹의 모든 프로젝트에서 병합 요청을 쿼리합니다. |

자세한 내용은 [범위](_index.md#scopes)를 참조하세요.

## 쿼리 필터 {#query-filters}

`query` 매개변수에서 이러한 필드를 사용하여 결과를 필터링하세요.

| 필드                                                    | 이름 (및 별칭)                             | 연산자                  |
| -------------------------------------------------------- | -------------------------------------------- | -------------------------- |
| [사용자별 승인됨](#mr-approved-by-user)                 | `approver`, `approvedBy`, `approvers`        | `=`, `!=`                  |
| [담당자](#mr-assignees)                               | `assignee`, `assignees`                      | `=`, `!=`                  |
| [작성자](#mr-author)                                     | `author`                                     | `=`, `!=`                  |
| [종료됨](#mr-closed-at)                               | `closed`, `closedAt`                         | `=`, `>`, `<`, `>=`, `<=`  |
| [생성된 날짜](#mr-created-at)                             | `created`, `createdAt`, `opened`, `openedAt` | `=`, `>`, `<`, `>=`, `<=`  |
| [초안](#mr-draft)                                       | `draft`                                      | `=`, `!=`                  |
| [환경](#mr-environment)                           | `environment`                                | `=`                        |
| [ID](#mr-identifier)                                     | `id`                                         | `=`, `in`                  |
| [하위 그룹 포함](#mr-include-subgroups)               | `includeSubgroups`                            | `=`, `!=`                  |
| [레이블](#mr-labels)                                     | `label`, `labels`                            | `=`, `!=`                  |
| [병합된 날짜](#mr-merged-at)                               | `merged`, `mergedAt`                         | `=`, `>`, `<`, `>=`, `<=`  |
| [사용자별 병합됨](#mr-merged-by-user)                     | `merger`, `mergedBy`                         | `=`                        |
| [마일스톤](#mr-milestone)                               | `milestone`                                  | `=`, `!=`                  |
| [나의 반응 이모지](#mr-my-reaction-emoji)               | `myReaction`, `myReactionEmoji`              | `=`, `!=`                  |
| [검토 상태](#mr-review-state)                         | `reviewState`, `reviewStates`                | `=`, `!=`, `in`            |
| [검토자](#mr-reviewers)                               | `reviewer`, `reviewers`, `reviewedBy`        | `=`, `!=`                  |
| [소스 브랜치](#mr-source-branch)                       | `sourceBranch`                               | `=`, `in`, `!=`            |
| [상태](#mr-state)                                       | `state`                                      | `=`                        |
| [구독함](#mr-subscribed)                             | `subscribed`                                 | `=`, `!=`                  |
| [대상 브랜치](#mr-target-branch)                       | `targetBranch`                               | `=`, `in`, `!=`            |
| [배포됨](#mr-deployed-at)                           | `deployed`, `deployedAt`                     | `=`, `>`, `<`, `>=`, `<=`  |
| [업데이트됨](#mr-updated-at)                             | `updated`, `updatedAt`                       | `=`, `>`, `<`, `>=`, `<=`  |

### 사용자별 승인됨 {#mr-approved-by-user}

{{< history >}}

- [GitLab 17.8에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/491246)
- 별칭 `approvedBy` 및 `approvers` [GitLab 18.0에서 도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/137)
- `Nullable` 값에 대한 지원 [GitLab 18.3에서 도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/221)

{{< /history >}}

**Description (설명)**: 병합 요청을 승인한 하나 이상의 사용자별로 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `String`
- `User` (예: `@username`)
- `List` (`String` 또는 `User` 값 포함)
- `Nullable` (`null`, `none` 또는 `any` 중 하나)

### 담당자 {#mr-assignees}

**Description (설명)**: 담당자로 지정된 하나 이상의 사용자별로 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `String`
- `User` (예: `@username`)
- `Nullable` (`null`, `none` 또는 `any` 중 하나)

**노트**:

- `List` 값과 `in` 연산자는 병합 요청에서 지원되지 않습니다.

### 작성자 {#mr-author}

**Description (설명)**: 작성자별로 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `String`
- `User` (예: `@username`)

**노트**:

- `in` 연산자는 병합 요청에서 지원되지 않습니다.

### 종료됨 {#mr-closed-at}

**Description (설명)**: 병합 요청이 종료된 날짜별로 조회합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (형식 `YYYY-MM-DD`에서)
- `RelativeDate` (형식 `<sign><digit><unit>`에서, 부호가 `+`, `-`, 또는 생략되며, 숫자는 정수이고 `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (연도) 중 하나입니다)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지 간주됩니다.

### 생성된 날짜 {#mr-created-at}

**Description (설명)**: 병합 요청이 생성된 날짜별로 조회합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (형식 `YYYY-MM-DD`에서)
- `RelativeDate` (형식 `<sign><digit><unit>`에서, 부호가 `+`, `-`, 또는 생략되며, 숫자는 정수이고 `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (연도) 중 하나입니다)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지 간주됩니다.

### 초안 {#mr-draft}

{{< history >}}

- [GitLab 17.8에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/491246)

{{< /history >}}

**Description (설명)**: 초안 상태별로 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `Boolean` (`true` 또는 `false` 중 하나)

### 배포됨 {#mr-deployed-at}

**Description (설명)**: 병합 요청이 배포된 날짜별로 조회합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (형식 `YYYY-MM-DD`에서)
- `RelativeDate` (형식 `<sign><digit><unit>`에서, 부호가 `+`, `-`, 또는 생략되며, 숫자는 정수이고 `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (연도) 중 하나입니다)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지 간주됩니다.

### 환경 {#mr-environment}

{{< history >}}

- [GitLab 17.8에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/491246)

{{< /history >}}

**Description (설명)**: 배포된 환경별로 병합 요청을 조회합니다.

**허용되는 값 유형**: `String`

### ID {#mr-identifier}

**Description (설명)**: ID별로 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `Number` (양의 정수만)
- `List` (`Number` 값 포함)

### 하위 그룹 포함 {#mr-include-subgroups}

**Description (설명)**: 그룹의 전체 계층 구조에서 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `Boolean` (`true` 또는 `false` 중 하나)

**노트**:

- 이 필드는 `group` 범위에서만 사용할 수 있습니다.
- 이 필드의 기본값은 `false`입니다.

### 레이블 {#mr-labels}

**Description (설명)**: 연결된 레이블별로 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `String`
- `Label` (예: `~bug`, `~"team::planning"`)
- `Nullable` (`none` 또는 `any` 중 하나)

**노트**:

- `in` 연산자는 병합 요청에서 지원되지 않습니다.
- 범위 지정 레이블 또는 공백을 포함하는 레이블은 따옴표로 묶어야 합니다.

### 병합된 날짜 {#mr-merged-at}

{{< history >}}

- [GitLab 17.8에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/491246)
- 별칭 `mergedAt` [GitLab 18.0에서 도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/137)
- 연산자 `>=` 및 `<=` [GitLab 18.0에서 도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/work_items/58)

{{< /history >}}

**Description (설명)**: 병합 요청이 병합된 날짜별로 조회합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (형식 `YYYY-MM-DD`에서)
- `RelativeDate` (형식 `<sign><digit><unit>`에서, 부호가 `+`, `-`, 또는 생략되며, 숫자는 정수이고 `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (연도) 중 하나입니다)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지 간주됩니다.

### 사용자별 병합됨 {#mr-merged-by-user}

{{< history >}}

- [GitLab 17.8에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/491246)
- 별칭 `mergedBy` [GitLab 18.0에서 도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/137)

{{< /history >}}

**Description (설명)**: 병합 요청을 병합한 사용자별로 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `String`
- `User` (예: `@username`)

### 마일스톤 {#mr-milestone}

**Description (설명)**: 연결된 마일스톤별로 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `String`
- `Milestone` (예: `%Backlog`, `%"Awaiting Further Demand"`)
- `Nullable` (`none` 또는 `any` 중 하나)

**노트**:

- `in` 연산자는 병합 요청에서 지원되지 않습니다.
- 공백을 포함하는 마일스톤은 따옴표(`"`)로 묶어야 합니다.

### 나의 반응 이모지 {#mr-my-reaction-emoji}

**Description (설명)**: 현재 사용자의 [이모지 반응](../../emoji_reactions.md)별로 병합 요청을 조회합니다.

**허용되는 값 유형**: `String`

### 검토 상태 {#mr-review-state}

{{< history >}}

- [GitLab 19.5에서 도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/508)

{{< /history >}}

**Description (설명)**: 검토자의 검토 상태별로 병합 요청을 조회합니다. 검토 상태에 대한 자세한 내용은 [병합 요청 검토](../../project/merge_requests/reviews/_index.md)를 참조하세요.

**허용되는 값 유형**:

- `Enum`, `unreviewed`, `review_started`, `reviewed`, `requested_changes`, `approved` 또는 `unapproved` 중 하나
- `List` (`Enum` 값 포함)

**노트**:

- `List` 값은 `in` 및 `!=` 연산자에서만 지원됩니다.
- 병합 요청은 모든 검토자가 주어진 상태에 있을 때가 아니라 검토자 중 최소 하나가 주어진 상태에 있을 때 일치합니다.
- `reviewer = @username`와 함께 결합될 때 `=` 및 `in`은 해당 검토자에게만 적용됩니다. `!=`은 모든 검토자에게 적용됩니다: `reviewer = @username and reviewState != approved`은 사용자가 검토자이고 어떤 검토자도 승인하지 않은 병합 요청을 반환합니다.
- 검토자 없이 병합 요청은 일치하지 않으므로 `reviewState`은 `reviewer = any` 또는 `reviewer = none`과 결합할 수 없습니다.
- 둘 이상의 상태를 제외하려면 `List`을 사용합니다: `reviewState != (approved, unapproved)`

### 검토자 {#mr-reviewers}

{{< history >}}

- 별칭 `reviewers` 및 `reviewedBy` [GitLab 18.0에서 도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/137)

{{< /history >}}

**Description (설명)**: 하나 이상의 사용자가 검토한 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `String`
- `User` (예: `@username`)
- `Nullable` (`null`, `none` 또는 `any` 중 하나)

### 소스 브랜치 {#mr-source-branch}

{{< history >}}

- GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197407)되었습니다.

{{< /history >}}

**설명:** 소스 브랜치별로 병합 요청을 조회합니다.

**허용되는 값 유형:** `String`, `List`

**노트**:

- `List` 값은 `in` 및 `!=` 연산자에서만 지원됩니다.

### 상태 {#mr-state}

**Description (설명)**: 상태별로 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `Enum`, 즉 `opened`, `closed`, `merged`, 또는 `all` 중 하나

**노트**:

- `state` 필드는 `!=` 연산자를 지원하지 않습니다.

### 구독함 {#mr-subscribed}

**Description (설명)**: 현재 사용자가 [알림 설정](../../profile/notifications.md)을 켜거나 껐는지 여부별로 병합 요청을 조회합니다.

**허용되는 값 유형**: `Boolean`

### 대상 브랜치 {#mr-target-branch}

{{< history >}}

- GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197407)되었습니다.

{{< /history >}}

**설명:** 대상 브랜치별로 병합 요청을 조회합니다.

**허용되는 값 유형:** `String`, `List`

**노트**:

- `List` 값은 `in` 및 `!=` 연산자에서만 지원됩니다.

### 업데이트됨 {#mr-updated-at}

**Description (설명)**: 마지막으로 업데이트된 시간별로 병합 요청을 조회합니다.

**허용되는 값 유형**:

- `AbsoluteDate` (형식 `YYYY-MM-DD`에서)
- `RelativeDate` (형식 `<sign><digit><unit>`에서, 부호가 `+`, `-`, 또는 생략되며, 숫자는 정수이고 `unit`는 `d` (일), `w` (주), `m` (월) 또는 `y` (연도) 중 하나입니다)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지 간주됩니다.

## 필드 표시 {#display-fields}

{{< history >}}

- [GitLab 17.8에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/491246)
- 필드 `sourceBranch`, `targetBranch`, `sourceProject` 및 `targetProject` [GitLab 18.2에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197407)

{{< /history >}}

| 필드            | 이름 또는 별칭                         | 설명 |
| ---------------- | ------------------------------------- | ----------- |
| 승인됨         | `approved`                            | `Yes` 또는 `No`을 표시하여 병합 요청이 승인되었는지 여부를 나타냅니다 |
| 사용자별 승인됨 | `approver`, `approvers`, `approvedBy` | 병합 요청을 승인한 사용자를 표시합니다 |
| 담당자        | `assignee`, `assignees`               | 병합 요청에 담당자로 지정된 사용자를 표시합니다 |
| 작성자           | `author`                              | 병합 요청의 작성자를 표시합니다 |
| 종료됨        | `closed`, `closedAt`                  | 병합 요청이 종료된 이후 경과 시간을 표시합니다 |
| 생성된 날짜       | `created`, `createdAt`                | 병합 요청이 생성된 이후 경과 시간을 표시합니다 |
| 설명      | `description`                         | 병합 요청의 설명을 표시합니다 |
| 초안            | `draft`                               | `Yes` 또는 `No`을 표시하여 병합 요청이 초안 상태인지 여부를 나타냅니다 |
| ID               | `id`                                  | 병합 요청의 ID를 표시합니다 |
| 레이블           | `label`, `labels`                     | 병합 요청과 연결된 레이블을 표시합니다 |
| 마지막 댓글     | `lastComment`                         | 병합 요청에 작성된 마지막 댓글을 표시합니다 |
| 병합된 날짜        | `merged`, `mergedAt`                  | 병합 요청이 병합된 이후 경과 시간을 표시합니다 |
| 사용자별 병합됨   | `merger`, `mergedBy`                  | 병합 요청을 병합한 사용자를 표시합니다 |
| 마일스톤        | `milestone`                           | 병합 요청과 연결된 마일스톤을 표시합니다 |
| 프로젝트          | `project`                             | 병합 요청이 속한 프로젝트를 표시합니다 |
| 검토자        | `reviewer`, `reviewers`               | 병합 요청을 검토하도록 지정된 사용자를 표시합니다 |
| 소스 브랜치    | `sourceBranch`                        | 병합 요청의 소스 브랜치를 표시합니다 |
| 소스 프로젝트   | `sourceProject`                       | 병합 요청의 소스 프로젝트를 표시합니다 |
| 상태            | `state`                               | 상태를 나타내는 배지를 표시합니다. 값은 `Open`, `Closed` 또는 `Merged`입니다 |
| 구독함       | `subscribed`                          | `Yes` 또는 `No`을 표시하여 현재 사용자가 구독했는지 여부를 나타냅니다 |
| 대상 브랜치    | `targetBranch`                        | 병합 요청의 대상 브랜치를 표시합니다 |
| 대상 프로젝트   | `targetProject`                       | 병합 요청의 대상 프로젝트를 표시합니다 |
| 시간 추정    | `timeEstimate`                        | 병합 요청의 예상 시간을 표시합니다 |
| 제목            | `title`                               | 병합 요청의 제목을 표시합니다 |
| 소비한 총 시간 | `totalTimeSpent`                      | 병합 요청에 소비한 총 시간을 표시합니다 |
| 업데이트됨       | `updated`, `updatedAt`                | 병합 요청이 마지막으로 업데이트된 이후 경과 시간을 표시합니다 |

## 필드 정렬 {#sort-fields}

| 필드         | 이름 (및 별칭)       | 설명                                     |
|---------------|------------------------|-------------------------------------------------|
| 종료됨     | `closed`, `closedAt`   | 종료된 날짜순 정렬                             |
| 생성됨       | `created`, `createdAt` | 생성된 날짜순 정렬                            |
| 병합된 날짜     | `merged`, `mergedAt`   | 병합된 날짜순 정렬                              |
| 마일스톤     | `milestone`            | 마일스톤 기한순 정렬                      |
| 인기도    | `popularity`           | 좋아요 이모지 반응 수순 정렬 |
| 제목         | `title`                | 제목순 정렬                                   |
| 업데이트됨    | `updated`, `updatedAt` | 마지막 업데이트 날짜순 정렬                       |

## 예제 {#examples}

- `gitlab-org/gitlab` 프로젝트에서 첫 번째 검토 대기 중인 열린 병합 요청을 나열합니다:

  ````yaml
  ```glql
  display: table
  fields: title, author, reviewer, updated
  sort: updated asc
  query: project = "gitlab-org/gitlab" and type = MergeRequest and state = opened and draft = false and reviewState = unreviewed
  limit: 10
  ```
  ````

- `gitlab-org` 그룹의 모든 병합 요청을 병합 날짜(최신순)로 정렬하여 내가 만든 목록을 나열합니다:

  ````yaml
  ```glql
  display: table
  fields: title, reviewer, merged
  sort: merged desc
  query: group = "gitlab-org" and type = MergeRequest and state = merged and author = currentUser()
  limit: 10
  ```
  ````
