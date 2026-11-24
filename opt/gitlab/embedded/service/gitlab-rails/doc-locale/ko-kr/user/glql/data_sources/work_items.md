---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 작업 항목
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

작업 항목은 `Issue`, `Incident`, `TestCase`, `Requirement`, `Task`, `Ticket`, `Objective`, `KeyResult`, 및 `Epic`의 유형을 포함합니다.

> [!note]
> 에픽 쿼리는 Premium 및 Ultimate 티어에서만 사용 가능합니다.

## 허용된 범위 {#allowed-scopes}

| 범위     | 설명                                      |
| --------- | ------------------------------------------------ |
| `project` | 특정 프로젝트에서 작업 항목을 쿼리합니다.          |
| `group`   | 서브그룹을 포함한 그룹의 모든 프로젝트에서 작업 항목을 쿼리합니다. |

자세한 내용은 [범위](_index.md#scopes)를 참조하세요.

## 쿼리 필터 {#query-filters}

`query` 매개변수의 이 필드들을 사용하여 결과를 필터링합니다.

| 필드                                                          | 이름 (및 별칭)                             | 연산자                  | 유형              |
| -------------------------------------------------------------- | -------------------------------------------- | -------------------------- | ------------------ |
| [담당자](#workitem-assignees)                               | `assignee`, `assignees`                      | `=`, `in`, `!=`            | 모두                |
| [작성자](#workitem-author)                                     | `author`                                     | `=`, `in`, `!=`            | 모두                |
| [케이던스](#workitem-cadence)                                   | `cadence`                                    | `=`, `in`                  | 에픽 제외    |
| [종료 시간](#workitem-closed-at)                               | `closed`, `closedAt`                         | `=`, `>`, `<`, `>=`, `<=`  | 모두                |
| [기밀](#workitem-confidential)                         | `confidential`                               | `=`, `!=`                  | 모두                |
| [생성 시간](#workitem-created-at)                             | `created`, `createdAt`, `opened`, `openedAt` | `=`, `>`, `<`, `>=`, `<=`  | 모두                |
| [사용자 정의 필드](#workitem-custom-field)                         | `customField("Field name")`                  | `=`                        | 모두                |
| [마감일](#workitem-due-date)                                 | `due`, `dueDate`                             | `=`, `>`, `<`, `>=`, `<=`  | 모두                |
| [에픽](#workitem-epic)                                         | `epic`                                       | `=`, `!=`                  | 에픽 제외    |
| [헬스 체크 상태](#workitem-health-status)                       | `health`, `healthStatus`                     | `=`, `!=`                  | 모두                |
| [ID](#workitem-identifier)                                     | `id`                                         | `=`, `in`                  | 모두                |
| [하위 그룹 포함](#workitem-include-subgroups)               | `includeSubgroups`                           | `=`, `!=`                  | 모두                |
| [반복](#workitem-iteration)                               | `iteration`                                  | `=`, `in`, `!=`            | 에픽 제외    |
| [레이블](#workitem-labels)                                     | `label`, `labels`                            | `=`, `in`, `!=`            | 모두                |
| [마일스톤](#workitem-milestone)                               | `milestone`                                  | `=`, `in`, `!=`            | 모두                |
| [내 반응 이모지](#workitem-my-reaction-emoji)               | `myReaction`, `myReactionEmoji`              | `=`, `!=`                  | 모두                |
| [부모](#workitem-parent)                                     | `parent`                                     | `=`, `!=`                  | 에픽 제외    |
| [상태](#workitem-state)                                       | `state`                                      | `=`                        | 모두                |
| [상태](#workitem-status)                                     | `status`                                     | `=`                        | 에픽 제외    |
| [구독됨](#workitem-subscribed)                             | `subscribed`                                 | `=`, `!=`                  | 모두                |
| [업데이트 시간](#workitem-updated-at)                             | `updated`, `updatedAt`                       | `=`, `>`, `<`, `>=`, `<=`  | 모두                |
| [가중치](#workitem-weight)                                     | `weight`                                     | `=`, `!=`                  | 에픽 제외    |

### 담당자 {#workitem-assignees}

{{< history >}}

- 별칭 `assignees` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) GitLab 18.0에서.
- 에픽 쿼리 지원 담당자별 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) GitLab 18.3에서.

{{< /history >}}

**Description (설명)**: 할당된 하나 이상의 사용자별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `String`
- `User` (예: `@username`)
- `List` (`String` 또는 `User` 값 포함)
- `Nullable` (`null`, `none` 또는 `any` 중 하나)

### 작성자 {#workitem-author}

{{< history >}}

- 작성자별 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) GitLab 18.1에서.
- `in` 연산자 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/221) GitLab 18.3에서.

{{< /history >}}

**Description (설명)**: 작성자별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `String`
- `User` (예: `@username`)
- `List` (`String` 또는 `User` 값 포함)

### 케이던스 {#workitem-cadence}

{{< history >}}

- GitLab 17.6에서 [도입](https://gitlab.com/gitlab-org/gitlab-query-language/glql-haskell/-/issues/74)되었습니다.

{{< /history >}}

**Description (설명)**: 작업 항목의 반복이 속하는 [케이던스](../../group/iterations/_index.md#iteration-cadences)별로 에픽을 제외한 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `Number` (양의 정수만)
- `List` (`Number` 값 포함)
- `Nullable` (`none` 또는 `any` 중 하나)

**노트**:

- 작업 항목은 하나의 반복만 가질 수 있으므로 `=` 연산자는 `cadence` 필드에 대해 `List` 유형과 함께 사용할 수 없습니다.

### 종료 시간 {#workitem-closed-at}

{{< history >}}

- 별칭 `closedAt` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) GitLab 18.0에서.
- 연산자 `>=` 및 `<=` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/work_items/58) GitLab 18.0에서.
- 종료 날짜별 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) GitLab 18.3에서.

{{< /history >}}

**Description (설명)**: 작업 항목이 종료된 날짜별로 쿼리합니다.

**허용된 값 유형**:

- `AbsoluteDate` (`YYYY-MM-DD` 형식으로)
- `RelativeDate` (`<sign><digit><unit>` 형식으로, 부호는 `+`, `-` 또는 생략, 숫자는 정수, `unit`는 `d` (일), `w` (주), `m` (개월) 또는 `y` (년) 중 하나)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자 시간대의 00:00에서 23:59로 간주됩니다.

### 기밀 {#workitem-confidential}

{{< history >}}

- 기밀성에 따른 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) GitLab 18.1에서.

{{< /history >}}

**Description (설명)**: 프로젝트 구성원에 대한 가시성별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `Boolean` (`true` 또는 `false` 중 하나)

**노트**:

- GLQL을 사용하여 쿼리된 기밀 작업 항목은 이를 볼 수 있는 권한이 있는 사람에게만 표시됩니다.

### 생성 시간 {#workitem-created-at}

{{< history >}}

- 별칭 `createdAt`, `opened`, 및 `openedAt` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) GitLab 18.0에서.
- 연산자 `>=` 및 `<=` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/work_items/58) GitLab 18.0에서.
- 생성 날짜별 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) GitLab 18.1에서.

{{< /history >}}

**Description (설명)**: 작업 항목이 생성된 날짜별로 쿼리합니다.

**허용된 값 유형**:

- `AbsoluteDate` (`YYYY-MM-DD` 형식으로)
- `RelativeDate` (`<sign><digit><unit>` 형식으로, 부호는 `+`, `-` 또는 생략, 숫자는 정수, `unit`는 `d` (일), `w` (주), `m` (개월) 또는 `y` (년) 중 하나)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자 시간대의 00:00에서 23:59로 간주됩니다.

### 사용자 정의 필드 {#workitem-custom-field}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/233)되었습니다.

{{< /history >}}

**Description (설명)**: [사용자 정의 필드](../../work_items/custom_fields.md)별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `String` (단일 선택 사용자 정의 필드의 경우)
- `List` (`String`, 다중 선택 사용자 정의 필드의 경우)

**노트**:

- 사용자 정의 필드 이름과 값은 대소문자를 구분하지 않습니다.

### 마감일 {#workitem-due-date}

{{< history >}}

- 별칭 `dueDate` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) GitLab 18.0에서.
- 연산자 `>=` 및 `<=` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/work_items/58) GitLab 18.0에서.
- 마감일별 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) GitLab 18.3에서.

{{< /history >}}

**Description (설명)**: 작업 항목이 마감되는 날짜별로 쿼리합니다.

**허용된 값 유형**:

- `AbsoluteDate` (`YYYY-MM-DD` 형식으로)
- `RelativeDate` (`<sign><digit><unit>` 형식으로, 부호는 `+`, `-` 또는 생략, 숫자는 정수, `unit`는 `d` (일), `w` (주), `m` (개월) 또는 `y` (년) 중 하나)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자 시간대의 00:00에서 23:59로 간주됩니다.

### 에픽 {#workitem-epic}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

{{< history >}}

- GitLab 18.1에 [도입](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/issues/30)되었습니다.

{{< /history >}}

**Description (설명)**: 상위 에픽 ID 또는 참조별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `Number` (에픽 ID)
- `String` (`&123` 같은 에픽 참조 포함)
- `Epic` (예: `&123`, `gitlab-org&123`)

### 헬스 체크 상태 {#workitem-health-status}

{{< details >}}

- 티어: Ultimate

{{< /details >}}

{{< history >}}

- 별칭 `healthStatus` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) GitLab 18.0에서.
- 건강 상태별 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) GitLab 18.3에서.

{{< /history >}}

**Description (설명)**: 건강 상태별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `StringEnum` (`"needs attention"`, `"at risk"` 또는 `"on track"` 중 하나)
- `Nullable` (`null`, `none` 또는 `any` 중 하나)

### ID {#workitem-identifier}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/92) GitLab 17.8에서.
- ID별 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) GitLab 18.1에서.

{{< /history >}}

**Description (설명)**: ID별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `Number` (양의 정수만)
- `List` (`Number` 값 포함)

### 하위 그룹 포함 {#workitem-include-subgroups}

{{< history >}}

- GitLab 17.10에서 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/106)되었습니다.
- 에픽에서 사용할 필드 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) GitLab 18.1에서.

{{< /history >}}

**Description (설명)**: 그룹의 전체 계층 구조에서 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `Boolean` (`true` 또는 `false` 중 하나)

**노트**:

- 이 필드는 `group` 범위에서만 사용할 수 있습니다.
- 이 필드의 값은 기본적으로 `false`입니다.

### 반복 {#workitem-iteration}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

{{< history >}}

- GitLab 17.6에서 [도입](https://gitlab.com/gitlab-org/gitlab-query-language/glql-haskell/-/issues/74)되었습니다.
- 반복 값 유형 지원 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/79) GitLab 17.8에서.

{{< /history >}}

**Description (설명)**: 연결된 [반복](../../group/iterations/_index.md)별로 에픽을 제외한 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `Number` (양의 정수만)
- `Iteration` (예: `*iteration:123456`)
- `List` (`Number` 또는 `Iteration` 값 포함)
- `Enum` (`current`만 지원됨)
- `Nullable` (`none` 또는 `any` 중 하나)

**노트**:

- 작업 항목은 하나의 반복만 가질 수 있으므로 `=` 연산자는 `iteration` 필드에 대해 `List` 유형과 함께 사용할 수 없습니다.

### 레이블 {#workitem-labels}

{{< history >}}

- 레이블 값 유형 지원 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/79) GitLab 17.8에서.
- 별칭 `labels` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) GitLab 18.0에서.
- 레이블별 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) GitLab 18.1에서.

{{< /history >}}

**Description (설명)**: 연결된 레이블별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `String`
- `Label` (예: `~bug`, `~"team::planning"`)
- `List` (`String` 또는 `Label` 값 포함)
- `Nullable` (`none` 또는 `any` 중 하나)

**노트**:

- 범위 지정 레이블 또는 공백이 포함된 레이블은 따옴표로 감싸야 합니다.

### 마일스톤 {#workitem-milestone}

{{< history >}}

- 마일스톤 값 유형 지원 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/77) GitLab 17.8에서.
- 마일스톤별 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) GitLab 18.1에서.

{{< /history >}}

**Description (설명)**: 연결된 마일스톤별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `String`
- `Milestone` (예: `%Backlog`, `%"Awaiting Further Demand"`)
- `List` (`String` 또는 `Milestone` 값 포함)
- `Nullable` (`none` 또는 `any` 중 하나)

**노트**:

- 공백이 포함된 마일스톤은 따옴표(`"`)로 감싸야 합니다.
- 작업 항목은 하나의 마일스톤만 가질 수 있으므로 `=` 연산자는 `milestone` 필드에 대해 `List` 유형과 함께 사용할 수 없습니다.
- `Epic` 유형은 `none` 또는 `any`과 같은 와일드카드 마일스톤 필터를 지원하지 않습니다.

### 내 반응 이모지 {#workitem-my-reaction-emoji}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/223)되었습니다.

{{< /history >}}

**Description (설명)**: 현재 사용자의 [이모지 반응](../../emoji_reactions.md)별로 작업 항목을 쿼리합니다.

**허용되는 값 유형**: `String`

### 상위 항목 {#workitem-parent}

**Description (설명)**: 상위 작업 항목 또는 에픽별로 에픽을 제외한 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `Number` (상위 ID)
- `String` (`#123` 같은 참조 포함)
- `WorkItem` (예: `#123`, `gitlab-org/gitlab#123`)
- `Epic` (예: `&123`, `gitlab-org&123`)

### 상태 {#workitem-state}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/96) GitLab 17.8에서.
- 상태별 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) GitLab 18.1에서.

{{< /history >}}

**Description (설명)**: 상태별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `Enum`, `opened`, `closed` 또는 `all` 중 하나

**노트**:

- `state` 필드는 `!=` 연산자를 지원하지 않습니다.

### 상태 {#workitem-status}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

{{< history >}}

- GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197407)되었습니다.

{{< /history >}}

**설명:** 상태별로 작업 항목을 쿼리합니다.

**허용되는 값 유형:** `String`

### 구독됨 {#workitem-subscribed}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/223)되었습니다.

{{< /history >}}

**Description (설명)**: 현재 사용자가 [알림 설정](../../profile/notifications.md)을 켜거나 끄는지 여부별로 작업 항목을 쿼리합니다.

**허용되는 값 유형**: `Boolean`

### 업데이트 시간 {#workitem-updated-at}

{{< history >}}

- 별칭 `updatedAt` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) GitLab 18.0에서.
- 연산자 `>=` 및 `<=` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/work_items/58) GitLab 18.0에서.
- 마지막 업데이트별 에픽 쿼리 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) GitLab 18.1에서.

{{< /history >}}

**Description (설명)**: 마지막으로 업데이트된 시기별로 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `AbsoluteDate` (`YYYY-MM-DD` 형식으로)
- `RelativeDate` (`<sign><digit><unit>` 형식으로, 부호는 `+`, `-` 또는 생략, 숫자는 정수, `unit`는 `d` (일), `w` (주), `m` (개월) 또는 `y` (년) 중 하나)

**노트**:

- `=` 연산자의 경우 시간 범위는 사용자 시간대의 00:00에서 23:59로 간주됩니다.

### 가중치 {#workitem-weight}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

**Description (설명)**: 가중치별로 에픽을 제외한 작업 항목을 쿼리합니다.

**허용된 값 유형**:

- `Number` (양의 정수 또는 0만)
- `Nullable` (`null`, `none` 또는 `any` 중 하나)

**노트**:

- 비교 연산자 `<` 및 `>`는 사용할 수 없습니다.

## 표시 필드 {#display-fields}

{{< history >}}

- 필드 `iteration` [도입됨](https://gitlab.com/gitlab-org/gitlab-query-language/glql-haskell/-/issues/74) GitLab 17.6에서.
- 필드 `lastComment` [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/512154) GitLab 17.11에서.
- 에픽 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) GitLab 18.1에서.
- 필드 `status` [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197407) GitLab 18.2에서.
- 필드 `health` 및 `type` 에픽에서 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) GitLab 18.3에서.

{{< /history >}}

| 필드            | 이름 또는 별칭                         | 유형           | 설명 |
| ---------------- | ------------------------------------- | --------------- | ----------- |
| 담당자        | `assignee`, `assignees`               | 모두             | 개체에 할당된 사용자 표시 |
| 작성자           | `author`                              | 모두             | 개체의 작성자 표시 |
| 종료 시간        | `closed`, `closedAt`                  | 모두             | 개체가 종료된 이후 시간 표시 |
| 색상            | `color`                               | 에픽만       | 에픽과 연결된 색상 견본 표시 |
| 기밀     | `confidential`                        | 모두             | `Yes` 또는 `No`를 표시하여 개체가 기밀인지 여부를 나타냅니다 |
| 생성 시간       | `created`, `createdAt`                | 모두             | 개체가 생성된 이후 시간 표시 |
| 설명      | `description`                         | 모두             | 개체의 설명 표시 |
| 마감일         | `due`, `dueDate`                      | 모두             | 개체가 마감되기까지 남은 시간 표시 |
| 에픽             | `epic`                                | 에픽 제외 | 에픽에 대한 링크 표시. Premium 및 Ultimate 티어에서 사용 가능 |
| 헬스 체크 상태    | `health`, `healthStatus`              | 모두             | 건강 상태를 나타내는 배지 표시. Ultimate 티어에서 사용 가능 |
| ID               | `id`                                  | 모두             | 개체의 ID 표시 |
| 반복        | `iteration`                           | 에픽 제외 | 반복 표시. Premium 및 Ultimate 티어에서 사용 가능 |
| 레이블           | `label`, `labels`                     | 모두             | 레이블 표시. 특정 레이블을 필터링하는 매개변수를 허용할 수 있습니다. 예: `labels("workflow::*", "backend")` |
| 마지막 댓글     | `lastComment`                         | 모두             | 개체에 대한 마지막 댓글 표시 |
| 마일스톤        | `milestone`                           | 모두             | 개체와 연결된 마일스톤 표시 |
| 부모           | `parent`                              | 모두             | 상위 작업 항목 또는 에픽에 대한 링크 표시 |
| 진행률         | `progress`                            | 목표 및 핵심 결과만 | 작업 항목의 진행률 백분율(0-100) 표시 |
| 프로젝트          | `project`                             | 에픽 제외 | 작업 항목이 속한 프로젝트 표시 |
| 시작 날짜       | `start`, `startDate`                  | 에픽만       | 에픽의 시작 날짜 표시 |
| 상태            | `state`                               | 모두             | 상태를 나타내는 배지 표시. 값은 `Open` 또는 `Closed`입니다 |
| 상태           | `status`                              | 에픽 제외 | 상태를 나타내는 배지 표시. 예: "할 일" 또는 "완료". Premium 및 Ultimate 티어에서 사용 가능 |
| 작업 완료 상태 | `taskCompletionStatus`          | 모두             | 작업 완료를 분수(완료/전체)로 표시 |
| 시간 추정    | `timeEstimate`                        | 모두             | 작업 항목의 예상 시간 표시 |
| 제목            | `title`                               | 모두             | 개체의 제목 표시 |
| 사용된 총 시간 | `totalTimeSpent`                      | 모두             | 작업 항목에 사용된 총 시간 표시 |
| 형식             | `type`                                | 모두             | 작업 항목 유형을 표시합니다. 예: `Issue`, `Task` 또는 `Objective` |
| 업데이트 시간       | `updated`, `updatedAt`                | 모두             | 개체가 마지막으로 업데이트된 이후 시간 표시 |
| 가중치           | `weight`                              | 에픽 제외 | 가중치 표시. Premium 및 Ultimate 티어에서 사용 가능 |

## 정렬 필드 {#sort-fields}

{{< history >}}

- GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/glql/-/merge_requests/178)되었습니다.
- 건강 상태별 에픽 정렬 지원 [도입됨](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) GitLab 18.3에서.

{{< /history >}}

| 필드         | 이름 (및 별칭)         | 유형           | 설명                                     |
|---------------|--------------------------|-----------------|------------------------------------------------ |
| 종료 시간     | `closed`, `closedAt`     | 모두             | 종료 날짜로 정렬                             |
| 생성됨       | `created`, `createdAt`   | 모두             | 생성 날짜로 정렬                            |
| 마감일      | `due`, `dueDate`         | 모두             | 마감일로 정렬                                |
| 헬스 체크 상태 | `health`, `healthStatus` | 모두             | 건강 상태로 정렬                           |
| 마일스톤     | `milestone`              | 에픽 제외 | 마일스톤 마감일로 정렬                      |
| 인기도    | `popularity`             | 모두             | 엄지손가락 이모지 반응 수로 정렬 |
| 시작 날짜    | `start`, `startDate`     | 에픽만       | 시작 날짜로 정렬                              |
| 제목         | `title`                  | 모두             | 제목으로 정렬                                   |
| 업데이트 시간    | `updated`, `updatedAt`   | 모두             | 마지막 업데이트 날짜로 정렬                       |
| 가중치        | `weight`                 | 에픽 제외 | 가중치로 정렬                                  |

## 예제 {#examples}

- `gitlab-org/gitlab` 프로젝트의 모든 이슈를 제목으로 정렬된 목록:

  ````yaml
  ```glql
  display: table
  fields: state, title, updated
  sort: title asc
  query: project = "gitlab-org/gitlab" and type = Issue
  ```
  ````

- `gitlab-org` 그룹의 모든 에픽을 시작 날짜(가장 오래된 순서)로 정렬된 목록:

  ````yaml
  ```glql
  display: table
  fields: title, state, startDate
  sort: startDate asc
  query: group = "gitlab-org" and type = Epic
  ```
  ````

- `gitlab-org` 그룹에서 할당된 가중치가 있는 모든 이슈를 가중치(가장 높은 순서)로 정렬된 목록:

  ````yaml
  ```glql
  display: table
  fields: title, weight, health
  sort: weight desc
  query: type = Issue and group = "gitlab-org" and weight = any
  ```
  ````

- `gitlab-org` 그룹에서 오늘부터 일주일 이내에 마감되는 모든 이슈를 마감일(가장 빠른 순서)로 정렬된 목록:

  ````yaml
  ```glql
  display: table
  fields: title, dueDate, assignee
  sort: dueDate asc
  query: type = Issue and group = "gitlab-org" and due >= today() and due <= 1w
  ```
  ````
