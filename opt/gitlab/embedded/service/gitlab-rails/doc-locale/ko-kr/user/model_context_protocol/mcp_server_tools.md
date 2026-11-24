---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab MCP 서버를 통해 GitLab과 상호 작용할 수 있는 도구들을 사용합니다.
title: GitLab MCP 서버 도구
---

{{< details >}}

- 티어:  Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  정식 출시(GA)

{{< /details >}}

> [!warning]
> 이 기능에 대한 피드백을 제공하려면 [이슈 630189](https://gitlab.com/gitlab-org/gitlab/-/issues/630189)에 댓글을 남기세요.

GitLab MCP 서버는 기존 GitLab 워크플로우와 통합되는 도구 모음을 제공합니다. 이 도구들을 사용하여 GitLab과 직접 상호 작용하고 일반적인 GitLab 작업을 수행할 수 있습니다.

## `get_mcp_server_version` {#get_mcp_server_version}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200105)되었습니다.
- GitLab 19.5에서 [베타](../../policy/development_stages_support.md#beta)에서 [일반 공급](../../policy/development_stages_support.md#generally-available)으로 변경되었습니다.

{{< /history >}}

현재 GitLab MCP 서버의 버전을 반환합니다.

예:

```plaintext
What version of the GitLab MCP server am I connected to?
```

## `get_project` {#get_project}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250430)되었습니다.

{{< /history >}}

단일 GitLab 프로젝트의 메타데이터 반환: 숫자 ID, 전체 경로, 기본 브랜치, 가시성, 웹 URL.

| 매개 변수    | 형식   | 필수 | 설명 |
|--------------|--------|----------|-------------|
| `url`        | 문자열 | 아니요       | 프로젝트의 URL입니다. `url` 또는 `project_id` 중 정확히 하나를 제공합니다. |
| `project_id` | 문자열 | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url` 또는 `project_id` 중 정확히 하나를 제공합니다. |

`default_branch`은 프로젝트에 아직 리포지토리가 없을 때 `null`입니다. 아직 이름을 지정할 수 없는 프로젝트를 찾으려면 `search`을 `projects` 범위와 함께 사용합니다.

예:

```plaintext
What is the default branch of gitlab-org/gitlab?
```

## `add_commit` {#add_commit}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605876)되었습니다.
- `start_sha` 및 `start_project` 매개변수는 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/621972)되었습니다.

{{< /history >}}

브랜치에 하나 이상의 파일 작업이 포함된 커밋을 한 번의 호출로 추가합니다.

| 매개 변수        | 형식             | 필수 | 설명 |
|------------------|------------------|----------|-------------|
| `commit_message` | 문자열           | 예      | 커밋 메시지. |
| `actions`        | 객체의 배열 | 예      | 단일 배치로 커밋할 파일 작업입니다. |
| `branch`         | 문자열           | 예      | 커밋할 브랜치의 이름입니다. |
| `project_id`     | 문자열           | 아니요       | 프로젝트의 ID 또는 경로입니다. `url`이 제공되지 않으면 필수입니다. |
| `url`            | 문자열           | 아니요       | 프로젝트의 GitLab URL입니다. `project_id`이 제공되지 않으면 필수입니다. |
| `start_branch`   | 문자열           | 아니요       | 새 브랜치를 시작할 브랜치의 이름입니다. `branch`이 존재하지 않을 때 필수입니다. |
| `start_sha`      | 문자열           | 아니요       | 새 브랜치를 시작할 커밋의 SHA입니다. `start_branch`과 상호 배타적입니다. |
| `start_project`  | 문자열           | 아니요       | 커밋을 시작할 프로젝트의 전체 경로입니다. 프로젝트 자체이거나 해당 프로젝트의 포크 원본 프로젝트여야 합니다. |

`actions`의 각 객체는 다음 필드를 허용합니다:

| 필드              | 형식    | 필수 | 설명 |
|--------------------|---------|----------|-------------|
| `action`           | 문자열  | 예      | 수행할 작업: `create`, `update`, `delete`, `move`, 또는 `chmod`. |
| `file_path`        | 문자열  | 예      | 파일의 전체 경로입니다. |
| `content`          | 문자열  | 아니요       | 파일 콘텐츠입니다. `create`, `update`, 및 `move`에서 사용됩니다. `old_str` 및 `new_str`와 상호 배타적입니다. |
| `old_str`          | 문자열  | 아니요       | `update` 작업에서 대체할 기존 텍스트입니다. `new_str`이 필요합니다. |
| `new_str`          | 문자열  | 아니요       | `old_str` 작업에서 `update`에 대한 대체 텍스트입니다. |
| `previous_path`    | 문자열  | 아니요       | 원본 파일 경로입니다. `move`에 필수입니다. |
| `encoding`         | 문자열  | 아니요       | `content`의 인코딩: `text` 또는 `base64`. 기본값은 `text`입니다. |
| `last_commit_id`   | 문자열  | 아니요       | 낙관적 동시성에 사용되는 파일의 마지막으로 알려진 커밋 ID입니다. |
| `execute_filemode` | 부울 | 아니요       | 파일이 실행 가능한지 여부입니다. `chmod`에 필수입니다. |

부분 편집은 `old_str`의 정확히 하나의 항목을 대체합니다. 두 번 이상 나타나면 더 많은 주변 컨텍스트를 제공합니다. 부분 편집은 서버에서 전체 파일을 읽으므로 10 MiB보다 큰 파일은 지원되지 않습니다. 더 큰 파일의 경우 전체 파일 콘텐츠를 커밋합니다.

부분 편집은 바이너리 파일이나 LFS에 저장된 파일에는 지원되지 않습니다.

예:

```plaintext
In project gitlab-org/gitlab, create README.md on branch "docs-update"
with the content "# New title" and commit message "Add README"
```

## `create_issue` {#create_issue}

{{< history >}}

- GitLab 18.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203055)되었습니다.
- GitLab 19.4에서 [목록에 없음](https://gitlab.com/gitlab-org/gitlab/-/work_items/625129). [`save_work_item`](#save_work_item)로 대체되었습니다.

{{< /history >}}

[`save_work_item`](#save_work_item)로 대체되었으며, 이는 마일스톤 제목과 레이블 이름을 같은 위치(프로젝트 및 해당 상위 그룹)에서 해석하지만 찾을 수 없는 이름에 대해 더 엄격합니다. `create_issue`은 아직 존재하지 않는 레이블 이름을 만들고 알려지지 않은 마일스톤 제목을 자동으로 삭제하는 반면, `save_work_item`은 찾을 수 없는 항목의 이름을 지정하여 오류를 반환합니다. 이 도구는 더 이상 `tools/list`에 나타나지 않지만 호출자가 마이그레이션하는 동안 계속 호출할 수 있습니다.

GitLab 프로젝트에서 새 이슈를 만듭니다.

| 매개 변수      | 형식              | 필수 | 설명 |
|----------------|-------------------|----------|-------------|
| `id`           | 문자열            | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `title`        | 문자열            | 예      | 이슈의 제목입니다. |
| `description`  | 문자열            | 아니요       | 이슈의 설명입니다. |
| `assignee_ids` | 정수 배열 | 아니요       | 할당된 사용자의 ID 배열입니다. |
| `milestone_id` | 정수           | 아니요       | 마일스톤의 ID입니다. |
| `labels`       | 문자열 배열  | 아니요       | 레이블 이름 배열입니다. |
| `confidential` | 부울           | 아니요       | 이슈를 기밀로 설정합니다. 기본값은 `false`입니다. |
| `epic_id`      | 정수           | 아니요       | 연결된 에픽의 ID입니다. |

예:

```plaintext
Create a new issue titled "Fix login bug" in project 123 with description
"Users cannot log in with special characters in password"
```

## `get_issue` {#get_issue}

{{< history >}}

- GitLab 18.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/201838)되었습니다.
- GitLab 19.4에서 [목록에 없습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/628333). [`get_work_item`](#get_work_item)로 대체되었습니다.

{{< /history >}}

[`get_work_item`](#get_work_item)로 대체되었으며, 이는 이슈 및 다른 작업 항목 유형을 포함합니다. 이 도구는 더 이상 `tools/list`에 나타나지 않지만 호출자가 마이그레이션하는 동안 계속 호출할 수 있습니다.

특정 GitLab 이슈에 대한 자세한 정보를 검색합니다.

| 매개 변수   | 형식    | 필수 | 설명 |
|-------------|---------|----------|-------------|
| `id`        | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `issue_iid` | 정수 | 예      | 이슈의 내부 ID입니다. |

예:

```plaintext
Get details for issue 42 in project 123
```

## `save_merge_request` {#save_merge_request}

{{< history >}}

- GitLab 18.5에서 `create_merge_request`로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/571243)되었습니다.
- `assignee_ids`, `reviewer_ids`, `description`, `labels` 및 `milestone_id`가 GitLab 18.8에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/217458)되었습니다.
- GitLab 19.3에서 `save_merge_request`으로 이름이 바뀌고 머지 리퀘스트 업데이트로 확장되었습니다. `create_merge_request` 및 `update_merge_request` 이름은 별칭으로 유지됩니다.

{{< /history >}}

GitLab 프로젝트에서 머지 리퀘스트를 생성하거나 업데이트합니다. `merge_request_iid`의 존재 여부에 따라 작업이 선택됩니다. 머지 리퀘스트를 생성하려면 생략하고, 기존 머지 리퀘스트를 업데이트하려면 제공합니다.

| 매개 변수              | 형식              | 필수 | 설명 |
|------------------------|-------------------|----------|-------------|
| `project_id`           | 문자열            | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `merge_request_iid`    | 정수           | 아니요       | 머지 리퀘스트의 내부 ID입니다. 기존 머지 리퀘스트를 업데이트하려면 제공하고, 생성하려면 생략합니다. |
| `title`                | 문자열            | 아니요       | 머지 리퀘스트의 제목입니다. 생성할 때 필수입니다. |
| `source_branch`        | 문자열            | 아니요       | 소스 브랜치의 이름입니다. 생성할 때 필수입니다. |
| `target_branch`        | 문자열            | 아니요       | 대상 브랜치의 이름입니다. 생성할 때 필수입니다. |
| `target_project_id`    | 정수           | 아니요       | 대상 프로젝트의 ID입니다. 생성할 때 적용됩니다. |
| `description`          | 문자열            | 아니요       | 머지 리퀘스트의 설명입니다. |
| `labels`               | 문자열 배열  | 아니요       | 레이블 이름입니다. 기존 모든 레이블을 바꿉니다. 모든 레이블을 제거하려면 빈 배열을 전달합니다. |
| `add_labels`           | 문자열 배열  | 아니요       | 추가할 레이블 이름입니다. 업데이트할 때 적용됩니다. |
| `remove_labels`        | 문자열 배열  | 아니요       | 제거할 레이블 이름입니다. 업데이트할 때 적용됩니다. |
| `assignees`            | 문자열 배열  | 아니요       | 할당할 사용자 이름입니다. `assignee_ids`의 대체입니다. 둘 중 하나를 제공합니다. 모든 담당자를 제거하려면 빈 배열을 전달합니다. |
| `assignee_ids`         | 정수 배열 | 아니요       | 할당할 사용자 ID입니다. `assignees`의 대체입니다. 둘 중 하나를 제공합니다. 모든 담당자를 제거하려면 빈 배열을 전달합니다. |
| `reviewers`            | 문자열 배열  | 아니요       | 검토를 요청할 사용자 이름입니다. `reviewer_ids`의 대체입니다. 둘 중 하나를 제공합니다. 모든 검토자를 제거하려면 빈 배열을 전달합니다. |
| `reviewer_ids`         | 정수 배열 | 아니요       | 검토를 요청할 사용자 ID입니다. `reviewers`의 대체입니다. 둘 중 하나를 제공합니다. 모든 검토자를 제거하려면 빈 배열을 전달합니다. |
| `milestone_id`         | 정수           | 아니요       | 마일스톤의 ID입니다. |
| `milestone`            | 문자열            | 아니요       | 할당할 프로젝트 또는 상위 그룹 마일스톤의 제목입니다. `milestone_id`과 상호 배타적입니다. |
| `remove_source_branch` | 부울           | 아니요       | 머지 리퀘스트가 병합될 때 소스 브랜치를 제거합니다. |
| `squash`               | 부울           | 아니요       | 병합할 때 커밋을 하나의 커밋으로 스쿼시합니다. |
| `state_event`          | 문자열            | 아니요       | 수행할 상태 전환입니다. `close` 또는 `reopen` 중 하나입니다. 업데이트할 때 적용됩니다. |
| `discussion_locked`    | 부울           | 아니요       | 머지 리퀘스트 토론을 잠급니다. 업데이트할 때 적용됩니다. |
| `allow_collaboration`  | 부울           | 아니요       | 대상 브랜치로 병합할 수 있는 멤버의 커밋을 허용합니다. 업데이트할 때 적용됩니다. |

예:

```plaintext
Create a merge request in project gitlab-org/gitlab titled "Bug fix broken specs"
from branch "fix/specs-broken" into "master" and enable squash
```

```plaintext
Update merge request 42 in project gitlab-org/gitlab to add the "bug" label and close it
```

## `get_merge_request` {#get_merge_request}

{{< history >}}

- GitLab 18.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/201838)되었습니다.
- GitLab 19.3에서 `url`을 수락하고 관련 데이터 패싯을 반환하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/605878)되었습니다.

{{< /history >}}

머지 리퀘스트를 검색하고, 필요에 따라 diffs, 커밋, 메모, 파이프라인, 토론, 승인 또는 충돌을 검색합니다. `include` 매개 변수로 관련 데이터를 요청하지 않으면 기본 머지 리퀘스트만 반환됩니다.

| 매개 변수           | 형식    | 필수 | 설명 |
|---------------------|---------|----------|-------------|
| `url`               | 문자열  | 아니요       | 머지 리퀘스트의 GitLab URL입니다. 이것을 제공하거나 `project_id` 및 `merge_request_iid`를 제공합니다. |
| `project_id`        | 문자열  | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url`이 누락된 경우 필수입니다. |
| `merge_request_iid` | 정수 | 아니요       | 머지 리퀘스트의 내부 ID입니다. `url`이 누락된 경우 필수입니다. |
| `include`           | 배열   | 아니요       | 머지 리퀘스트와 함께 반환할 관련 패싯입니다. `diffs`, `commits`, `notes`, `pipelines`, `discussions`, `approvals`, 또는 `conflicts` 중 하나입니다. 호출당 하나의 패싯으로 제한됩니다. |
| `detail`            | 문자열  | 아니요       | Diff 세부 정보 수준입니다. 요약 횟수만 `none`, 파일별 추가 및 삭제를 위해 `stats`, 또는 파일별 패치 텍스트 및 파일별 통계를 위해 `full_patch` 중 하나입니다. 기본값은 `stats`입니다. `include`가 `["diffs"]`인 경우에만 적용됩니다. |
| `diffs_after`       | 문자열  | 아니요       | 파일의 정방향 페이지 매김을 위한 커서입니다. `include`이 `["diffs"]`이고 `detail`이 `full_patch`일 때만 적용됩니다. |
| `diffs_first`       | 정수 | 아니요       | 커서 뒤에 반환할 파일 수, 최대 100입니다. `include`이 `["diffs"]`이고 `detail`이 `full_patch`일 때만 적용됩니다. |
| `notes_after`       | 문자열  | 아니요       | 메모의 포워드 페이지 로드에 대한 커서입니다. `include`가 `["notes"]`인 경우에만 적용됩니다. |
| `notes_first`       | 정수 | 아니요       | 커서 뒤에 반환할 메모의 수이며 최대 100개입니다. `include`가 `["notes"]`인 경우에만 적용됩니다. |
| `notes_before`      | 문자열  | 아니요       | 메모의 역방향 페이지 매김을 위한 커서입니다. `include`가 `["notes"]`인 경우에만 적용됩니다. |
| `notes_last`        | 정수 | 아니요       | 커서 앞에 반환할 메모 수, 최대 100입니다. `include`가 `["notes"]`인 경우에만 적용됩니다. |
| `commits_after`     | 문자열  | 아니요       | 커밋의 정방향 페이지 매김을 위한 커서입니다. `include`가 `["commits"]`인 경우에만 적용됩니다. |
| `commits_first`     | 정수 | 아니요       | 커서 뒤에 반환할 커밋 수, 최대 100입니다. `include`가 `["commits"]`인 경우에만 적용됩니다. |
| `pipelines_after`   | 문자열  | 아니요       | 파이프라인의 정방향 페이지 매김을 위한 커서입니다. `include`가 `["pipelines"]`인 경우에만 적용됩니다. |
| `pipelines_first`   | 정수 | 아니요       | 커서 뒤에 반환할 파이프라인 수, 최대 100입니다. `include`가 `["pipelines"]`인 경우에만 적용됩니다. |

`diffs` 패싯은 기본적으로 변경 통계를 반환합니다: 전체 합계 및 파일별 추가 및 삭제입니다. 패치 텍스트를 얻으려면 `detail`을 `full_patch`으로 설정합니다.

`commits` 및 `pipelines` 패싯은 호출당 최대 100개 항목을 반환합니다. 각 응답에는 `pageInfo.hasNextPage` 및 `pageInfo.endCursor`가 포함됩니다. 해당 커서를 `commits_after` 또는 `pipelines_after`으로 다시 전달하여 다음 페이지를 읽습니다.

`notes` 패싯은 `notes_last` 및 `notes_before`로도 역방향 페이지 매김을 수행합니다. 최신 메모를 읽으려면 `notes_last`을 `notes_first` 또는 `notes_after` 없이 전달합니다. 한 번의 호출에서 두 방향을 모두 혼합하면 오류가 반환됩니다. 각 메모는 `position`(diff 주석의 파일 및 줄) 및 `discussion`(속하는 스레드 및 스레드 해결 여부)를 반환합니다. 응답에는 `resolvedDiscussionsCount` 및 `resolvableDiscussionsCount`도 포함됩니다.

`conflicts` 패싯은 Git 충돌 마커를 포함한 원시 충돌 파일 콘텐츠를 반환합니다. 병합 가능성이 확인될 때까지 머지 리퀘스트를 병합할 수 없고 소스 브랜치에 푸시할 수 있을 때만 사용 가능하며 `null`입니다. 기본 `conflicts` 필드를 읽어 상태를 결정합니다.

예:

```plaintext
Get merge request 15 in project gitlab-org/gitlab with its commits
```

## `list_duo_agents_and_flows` {#list_duo_agents_and_flows}

{{< history >}}

- GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/617173)되었습니다.

{{< /history >}}

프로젝트에서 활성화된 GitLab Duo 에이전트 및 플로우를 나열하므로 플로우 이름을 추측하는 대신 사용 가능한 항목을 발견할 수 있습니다. 프로젝트가 제공하는 에이전트 및 플로우는 프로젝트별로 구성되며 ID는 프로젝트 간에 다릅니다.

각 항목에는 `can_start_session`이 포함되어 있으며, 이는 실행 권한이 있는 플로우의 경우 `true`, 프로젝트에서 CI 세션을 실행할 수 있는 기본 채팅 에이전트의 경우입니다. 기본 GitLab Duo 에이전트, 기타 에이전트, 외부 에이전트는 발견용으로만 나열되며 `can_start_session`은 항상 `false`입니다. 실행할 수 없거나 버전이 미출시 또는 아직 초안인 플로우의 경우에도 `false`입니다.

GitLab Ultimate 구독이 없는 경우 필요한 기본 채팅 에이전트는 나열되지 않거나 `can_start_session`이 `false`로 설정되어 나열됩니다.

`can_start_session`이 `true`로 설정된 플로우만 `start_duo_session`에서 사용하는 `ai_catalog_item_consumer_id`을 포함합니다. 기본 채팅 에이전트를 시작하려면 `workflow_definition`을 `agent`으로 전달합니다. 설명이 잘릴 수 있습니다.

목록에는 프로젝트에 구성된 에이전트, 플로우, 외부 에이전트 및 기본 채팅 에이전트가 포함됩니다. 채팅 에이전트는 페이지가 매겨진 프로젝트 결과의 일부가 아닌 고정 목록이므로 첫 페이지에서만 반환되며 에이전트가 포함되지 않으면 생략됩니다. `first`에 추가되므로 첫 페이지에는 요청한 것보다 더 많은 항목이 포함될 수 있습니다. `ai_catalog_item_consumer_id` 대신 `workflow_definition`을 수행하며, 이는 `GitLab Duo` 표시 이름을 공유하는 두 에이전트를 구별하기도 합니다. 프로젝트에서 구성된 항목은 `workflow_definition`이 `null`로 설정됩니다.

기본 채팅 에이전트는 GitLab.com의 프로젝트 최상위 그룹에 의해 관리되고 GitLab Self-Managed의 조직에 의해 관리되며, 프로젝트에 의해 관리되지 않습니다.

| 매개 변수    | 형식    | 필수 | 설명 |
|--------------|---------|----------|-------------|
| `project_id` | 문자열  | 예      | 에이전트 및 플로우를 나열할 프로젝트의 숫자 ID 또는 전체 경로입니다. |
| `item_type`  | 문자열  | 아니요       | `agent`, `flow` 또는 `third_party_flow` 항목만 반환합니다. 생략하면 모든 종류가 반환됩니다. |
| `after`      | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. |
| `first`      | 정수 | 아니요       | 정방향 페이지 매김을 위해 반환할 에이전트 및 플로우의 수입니다. 기본값은 20이며 최대값은 100입니다. |

각 호출은 결과의 단일 페이지를 반환합니다. 더 많은 페이지가 있으면 응답에 `pageInfo.endCursor`가 포함되며 `after`로 전달할 수 있습니다.

구성되지만 비활성화된 항목은 페이지를 가져온 후 삭제되므로 페이지는 `first`보다 적은 항목을 보유하거나 아무것도 없을 수 있지만 `pageInfo.hasNextPage`은 여전히 `true`입니다. `hasNextPage`이 `false`될 때까지 페이지를 매기고 빈 페이지에서 멈추지 마십시오.

예:

```plaintext
Which Duo flows can I run in gitlab-org/gitlab?
```

## `start_duo_session` {#start_duo_session}

{{< history >}}

- GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/607619)되었습니다.

{{< /history >}}

프로젝트에서 목표를 달성하기 위한 비동기 GitLab Duo 에이전트 플랫폼 세션을 시작합니다. 즉시 `workflow_id`을 반환합니다. 진행 상황을 추적하고 최종 결과를 검색하려면 `get_duo_session`을 해당 ID와 함께 사용합니다.

이 도구는 GitLab Duo 에이전트 플랫폼을 사용할 수 있을 때만 나열됩니다. 자세한 내용은 [도구 그룹 선택](mcp_server.md#select-tool-groups-toolsets)을 참조하세요.

세션은 커밋을 푸시하고 머지 리퀘스트를 열 수 있는 CI 작업에서 실행됩니다.

`url` 또는 `project_id` 중 정확히 하나를 제공합니다. 최대 `flow`, `flow_item_id`, `ai_catalog_item_consumer_id`, 또는 `agent` 중 하나를 제공합니다.

| 매개 변수                     | 형식    | 필수 | 설명 |
|-------------------------------|---------|----------|-------------|
| `url`                         | 문자열  | 아니요       | 프로젝트의 전체 GitLab URL (예: `https://gitlab.com/group/project`). `project_id`와 함께 사용하지 마세요. |
| `project_id`                  | 문자열  | 아니요       | 프로젝트의 숫자 ID 또는 전체 경로 (예: `gitlab-org/gitlab`). `url`와 함께 사용하지 마세요. |
| `goal`                        | 문자열  | 예      | 세션의 자연어 목표 (예: `Fix the flaky spec in issue #1234 and open a merge request`). 일부 플로우는 URL을 대신 사용합니다. 예를 들어 `fix_pipeline/v1`의 실패한 파이프라인 URL입니다. |
| `flow`                        | 문자열  | 아니요       | 기본 플로우 참조 (예: `developer/v1`, `fix_pipeline/v1`). 플로우 또는 에이전트가 제공되지 않으면 `developer/v1`으로 기본값입니다. `flow_item_id`, `ai_catalog_item_consumer_id` 또는 `agent`과 함께 사용하지 마십시오. |
| `flow_item_id`                | 정수 | 아니요       | 프로젝트에서 활성화된 사용자 지정 플로우의 AI 카탈로그 항목 ID입니다. 최신 출시 버전이 실행됩니다. `flow`, `ai_catalog_item_consumer_id` 또는 `agent`과 함께 사용하지 마십시오. |
| `ai_catalog_item_consumer_id` | 정수 | 아니요       | 실행할 플로우를 구성하는 AI 카탈로그 항목 소비자의 ID입니다. `list_duo_agents_and_flows`을 사용하여 찾습니다. `flow`, `flow_item_id` 또는 `agent`과 함께 사용하지 마십시오. |
| `agent`                       | 문자열  | 아니요       | 실행할 기본 에이전트의 참조 (예: `analytics_agent/v1`). 기본 GitLab Duo 에이전트는 시작할 수 없습니다. `flow`, `flow_item_id` 또는 `ai_catalog_item_consumer_id`과 함께 사용하지 마십시오. |

플로우는 프로젝트 또는 프로젝트의 상위 그룹에서 활성화되어야 합니다. 플로우가 활성화되지 않으면 도구가 오류를 반환합니다.

기능 플래그 뒤의 플로우는 해당 플래그가 활성화될 때만 실행됩니다. 플로우가 이러한 조건을 충족하지 않으면 도구가 오류를 반환합니다.

일부 플로우는 특정 형식의 목표를 예상하며, 도구는 세션을 시작하기 전에 확인합니다:

- `fix_pipeline/v1`은 같은 프로젝트의 실패한 파이프라인 URL을 예상합니다. 세션은 파이프라인의 브랜치에서 실행됩니다. 파이프라인이 열린 머지 리퀘스트에 속하면 플로우가 해당 머지 리퀘스트에 제안된 수정 사항을 게시합니다. 그렇지 않으면 수정 사항을 포함한 새 머지 리퀘스트를 엽니다. 목표가 프로젝트의 파이프라인이 아니면 도구가 오류를 반환하고 세션을 시작하지 않습니다.
- `code_review/v1`은 머지 리퀘스트의 URL 또는 IID를 예상합니다. 세션은 머지 리퀘스트의 소스 브랜치에서 실행됩니다.

이들은 GitLab UI의 파이프라인 또는 머지 리퀘스트에서 시작할 때 플로우가 사용하는 것과 동일한 브랜치 및 머지 리퀘스트입니다.

기본 플로우를 시작하려면 `flow`을 사용합니다. 기본 플로우의 AI 카탈로그 항목 ID를 `flow_item_id`에 전달하면 도구가 대신 사용할 `flow` 값의 이름을 지정하는 오류를 반환합니다. 기본 에이전트의 참조를 `flow`에 전달하면 도구가 대신 사용할 `agent` 값의 이름을 지정하는 오류를 반환합니다.

응답에는 `get_duo_session`을 호출하기 전에 얼마나 오래 기다려야 하는지를 나타내는 힌트로 `poll_after_seconds`이 포함됩니다.

예:

```plaintext
Fix the flaky spec in issue #1234 and open an MR in gitlab-org/gitlab
```

## `list_duo_sessions` {#list_duo_sessions}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248587)되었습니다.
- GitLab 19.5에서 `statuses` 매개변수를 허용하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256101)되었습니다.

{{< /history >}}

Duo Chat 세션을 제외한 GitLab Duo Agent Platform 세션을 나열합니다. 각 세션에는 개별 상태, 목표 미리 보기, 플로우 정의 및 만들기 타임스탬프가 포함됩니다. 프로젝트 및 그룹 세션에는 세션 URL도 포함됩니다. 목표 미리 보기가 잘릴 수 있습니다.

| 매개 변수      | 형식    | 필수 | 설명 |
|----------------|---------|----------|-------------|
| `url`          | 문자열  | 아니요       | 세션을 필터링할 프로젝트의 GitLab URL입니다. `project_id`와 함께 사용하지 마세요. |
| `project_id`   | 문자열  | 아니요       | 세션을 필터링할 프로젝트의 숫자 ID 또는 전체 경로입니다. `url`와 함께 사용하지 마세요. |
| `status_group` | 문자열  | 아니요       | 세션 상태 그룹입니다. `active`, `paused`, `awaiting_input`, `completed`, `failed` 또는 `canceled` 중 하나입니다. |
| `statuses`     | 배열   | 아니요       | 세션 상태입니다. `created`, `running`, `paused`, `finished`, `failed`, `stopped`, `input_required`, `plan_approval_required` 또는 `tool_call_approval_required` 중 하나 이상입니다. `status_group`와 함께 사용하지 마세요. |
| `after`        | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. |
| `first`        | 정수 | 아니요       | 포워드 페이지 로드에 대한 반환할 세션 수입니다. 기본값은 20이며 최대값은 100입니다. |

`status_group` 필터는 여러 개별 상태를 가진 세션을 반환할 수 있습니다. 대신 정확한 상태로 필터링하려면 `statuses`을 사용합니다. 각 호출은 결과의 단일 페이지를 반환합니다. 더 많은 페이지가 있으면 응답에 `pageInfo.endCursor`가 포함되며 `after`로 전달할 수 있습니다.

예:

```plaintext
List my active Duo Agent Platform sessions in gitlab-org/gitlab
```

## `get_duo_session` {#get_duo_session}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/607634)되었습니다. `get_duo_workflow_status`도 별칭으로 허용됩니다.
- 세션이 생성한 머지 리퀘스트, 작업 항목 및 주석을 반환하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/work_items/627561)되었으며, 상태에 따라 폴링 지연을 변경하고, `status`을 밑줄로 보고(`input_required` 대신 `input required`) `list_duo_sessions`과 일치하도록 GitLab 19.5에서 변경되었습니다.
- GitLab 19.5에서 실패한 세션이 실패한 이유와 해당 CI 작업에 대한 링크를 반환하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/work_items/631690)되었습니다.

{{< /history >}}

GitLab Duo 에이전트 플랫폼 세션의 상태를 확인합니다. 실행 중인 세션에는 제안된 폴링 지연이 포함되며, 세션이 CI 작업 시작을 기다리는 동안 더 깁니다. 완료된 세션 및 완료된 채팅 턴에는 최신 에이전트 답변이 포함됩니다. 세션이 생성한 머지 리퀘스트, 작업 항목 또는 주석은 존재하면 `created_merge_requests`, `created_work_items` 및 `created_notes`로 포함됩니다. 각각은 배열이며, 세션이 해당 종류의 항목을 만들지 않으면 비어 있고 최대 20개의 가장 최근 항목을 보유합니다. 목록이 잘리면 `artifacts_truncated`는 잘린 목록의 이름을 지정하고 `artifact_limit`는 한도를 제공합니다. `get_merge_request`을 `include: ["notes"]`과 함께 사용하여 머지 리퀘스트의 모든 주석을 페이지합니다. 승인을 대기하는 세션에는 `send_duo_session_input`로 세션을 계속하기 위한 지침이 포함됩니다.

실패한 세션에는 다음도 포함됩니다:

- `failure_reason`: 실패에 기록된 이유이거나 기록된 이유가 없으면 `null`입니다.
- `job_url`: 세션을 실행한 CI 작업이거나 CI 작업이 실행되지 않았거나 로그를 읽을 수 없으면 `null`입니다.

세션이 에이전트 시작 전에 실패한 경우 응답은 변경이 없음을 나타내고 다시 시작할 수 있습니다. 30일 이상 된 세션에는 이 메시지가 포함되지 않습니다. 30일 이상 된 체크포인트는 유지되지 않으므로 도구가 에이전트가 세션을 실행했는지 식별할 수 없습니다.

| 매개 변수     | 형식    | 필수 | 설명 |
|---------------|---------|----------|-------------|
| `workflow_id` | 정수 | 예      | `start_duo_session` 또는 `list_duo_sessions`에서 반환한 Duo 세션의 ID입니다. |

예:

```plaintext
Check the status of Duo session 42
```

## `send_duo_session_input` {#send_duo_session_input}

{{< history >}}

- GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/617171)되었습니다.

{{< /history >}}

입력을 기다리는 GitLab Duo 에이전트 플랫폼 세션에 응답합니다: 보류 중인 계획 또는 도구 호출을 승인 또는 거부하거나 에이전트가 물었던 질문에 회신합니다. `ai_catalog_item_consumer_id`에서 시작된 세션 및 `agent`에서 시작된 세션에 대해 작동합니다. 세션은 마지막 CI 작업이 완료되면 입력을 허용하며 `input_required`, `plan_approval_required` 또는 `tool_call_approval_required` 상태로 대기 중입니다.

세션은 CI 작업에서 계속됩니다. 응답에는 제안된 폴링 지연이 포함됩니다. 같은 `workflow_id`으로 `get_duo_session`을 사용하여 진행 상황을 따릅니다.

| 매개 변수        | 형식    | 필수 | 설명 |
|------------------|---------|----------|-------------|
| `workflow_id`    | 정수 | 예      | `list_duo_sessions` 또는 `get_duo_session`에서 반환한 Duo 세션의 ID입니다. |
| `human_approval` | 부울 | 예      | `true`은 보류 중인 계획 또는 도구 호출을 승인합니다. `human_message`을 `true`과 포함하지 마세요. 그렇지 않으면 도구가 세션을 재개하는 대신 호출을 거부합니다. `false`은 거부합니다: 에이전트가 피드백으로 계속 진행하도록 `human_message`을 포함합니다. 없으면 에이전트는 진행하지 않도록 지시받고 세션은 계속됩니다. |
| `human_message`  | 문자열  | 아니요       | 에이전트에 대한 피드백 또는 세션이 물었던 질문에 대한 답변, 최대 2000자입니다. `human_approval=false`과 함께 제공합니다. `human_approval=true`에서 도구가 세션을 재개하는 대신 호출을 거부합니다. |

예:

```plaintext
Approve the plan for Duo session 42
```

```plaintext
Reject the plan for Duo session 42 and ask it to also add tests
```

## `list_merge_requests` {#list_merge_requests}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246413)되었습니다.
- `group_id` 매개변수 및 그룹 범위는 GitLab 19.4에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/work_items/606934)되었습니다.

{{< /history >}}

GitLab 프로젝트 또는 그룹에서 머지 리퀘스트를 나열하거나 검색하고 콤팩트 머지 리퀘스트 메타데이터를 반환합니다. 그룹 범위는 항상 그룹 및 해당 하위 그룹의 모든 프로젝트에서 머지 리퀘스트를 포함하지만 보관된 프로젝트의 머지 리퀘스트는 제외합니다. 그룹 결과에는 `get_merge_request`과 함께 사용할 각 머지 리퀘스트의 소유 프로젝트 경로도 포함됩니다.

| 매개 변수           | 형식    | 필수 | 설명 |
|---------------------|---------|----------|-------------|
| `url`               | 문자열  | 아니요       | 프로젝트 또는 그룹의 GitLab URL입니다. `url`, `project_id`, `group_id` 중 정확히 하나를 제공합니다. |
| `project_id`        | 문자열  | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url`, `project_id`, `group_id` 중 정확히 하나를 제공합니다. |
| `group_id`          | 문자열  | 아니요       | 그룹의 ID 또는 전체 경로입니다. `url`, `project_id`, `group_id` 중 정확히 하나를 제공합니다. |
| `author_username`   | 문자열  | 아니요       | 머지 리퀘스트 작성자의 사용자 이름으로 필터링합니다. |
| `assignee_username` | 문자열  | 아니요       | 담당자의 사용자 이름으로 필터링합니다. |
| `reviewer_username` | 문자열  | 아니요       | 검토자의 사용자 이름으로 필터링합니다. |
| `state`             | 문자열  | 아니요       | 상태로 필터링합니다. `opened`, `closed`, `merged`, `locked` 또는 `all` 중 하나입니다. 모든 상태를 포함하려면 생략합니다. |
| `scope`             | 문자열  | 아니요       | 인증된 사용자를 기준으로 필터링합니다. `created_by_me`, `assigned_to_me` 또는 `review_requested` 중 하나입니다. 명시적 사용자 이름이 해당 필드에서 우선합니다. |
| `milestone`         | 문자열  | 아니요       | 마일스톤 제목으로 필터링합니다. |
| `labels`            | 문자열  | 아니요       | 쉼표로 구분된 레이블 이름의 목록입니다. 이러한 모든 레이블을 가진 머지 리퀘스트만 반환됩니다. |
| `search`            | 문자열  | 아니요       | 머지 리퀘스트 제목 및 설명과 비교되는 검색 쿼리입니다. |
| `after`             | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. |
| `first`             | 정수 | 아니요       | 포워드 페이지 로드에 반환할 머지 리퀘스트 수입니다. 기본값은 20이며 최대값은 100입니다. |

단일 머지 리퀘스트를 완전히 세부적으로 검색하려면 `get_merge_request`을 사용합니다. 커밋을 가져오려면 `get_merge_request`을 `include: ["commits"]`과 함께 사용합니다. Diffs 또는 메모의 경우 `include: ["diffs"]` 또는 `include: ["notes"]`를 사용합니다. 패치 텍스트를 얻으려면 `detail`을 `full_patch`로 설정합니다. 리소스 유형 전체에 대한 전체 텍스트 검색을 위해 `search`을 사용합니다.

예:

```plaintext
List my open merge requests in gitlab-org/gitlab
```

## `get_merge_request_commits` {#get_merge_request_commits}

{{< history >}}

- GitLab 18.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203055)되었습니다.
- GitLab 19.5에서 [목록에 없음](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712). [`get_merge_request`](#get_merge_request)과 `include: ["commits"]`으로 대체되었습니다.

{{< /history >}}

[`get_merge_request`](#get_merge_request)과 `include: ["commits"]`으로 대체되었습니다. 이 도구는 더 이상 `tools/list`에 나타나지 않지만 호출자가 마이그레이션하는 동안 계속 호출할 수 있습니다.

특정 GitLab 머지 리퀘스트의 커밋 목록을 검색합니다.

| 매개 변수           | 형식    | 필수 | 설명 |
|---------------------|---------|----------|-------------|
| `id`                | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `merge_request_iid` | 정수 | 예      | 머지 리퀘스트의 내부 ID입니다. |
| `per_page`          | 정수 | 아니요       | 페이지당 커밋 수입니다. |
| `page`              | 정수 | 아니요       | 현재 페이지 번호입니다. |

예:

```plaintext
Show me all commits in merge request 42 from project 123
```

## `get_merge_request_diffs` {#get_merge_request_diffs}

{{< history >}}

- GitLab 18.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203055)되었습니다.
- GitLab 19.5에서 [목록에 없습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712). [`get_merge_request`](#get_merge_request)과 `include: ["diffs"]`으로 대체되었습니다.

{{< /history >}}

[`get_merge_request`](#get_merge_request)과 `include: ["diffs"]`으로 대체되었습니다. 원시 패치 텍스트의 경우 `detail: full_patch`도 전달합니다. 이 도구는 더 이상 `tools/list`에 나타나지 않지만 호출자가 마이그레이션하는 동안 계속 호출할 수 있습니다.

특정 GitLab 머지 리퀘스트의 diff를 검색합니다.

| 매개 변수           | 형식    | 필수 | 설명 |
|---------------------|---------|----------|-------------|
| `id`                | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `merge_request_iid` | 정수 | 예      | 머지 리퀘스트의 내부 ID입니다. |
| `per_page`          | 정수 | 아니요       | 페이지당 diff 수입니다. |
| `page`              | 정수 | 아니요       | 현재 페이지 번호입니다. |

예:

```plaintext
What files were changed in merge request 25 in the gitlab project?
```

## `get_merge_request_pipelines` {#get_merge_request_pipelines}

{{< history >}}

- GitLab 18.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203055)되었습니다.
- GitLab 19.5에서 [목록에 없습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712). [`get_merge_request`](#get_merge_request)과 `include: ["pipelines"]`으로 대체되었습니다.

{{< /history >}}

[`get_merge_request`](#get_merge_request)과 `include: ["pipelines"]`으로 대체되었습니다. 이 도구는 더 이상 `tools/list`에 나타나지 않지만 호출자가 마이그레이션하는 동안 계속 호출할 수 있습니다.

특정 GitLab 머지 리퀘스트의 파이프라인을 검색합니다.

| 매개 변수           | 형식    | 필수 | 설명 |
|---------------------|---------|----------|-------------|
| `id`                | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `merge_request_iid` | 정수 | 예      | 머지 리퀘스트의 내부 ID입니다. |

예:

```plaintext
Show me all pipelines for merge request 42 in project gitlab-org/gitlab
```

## `get_merge_request_conflicts` {#get_merge_request_conflicts}

{{< history >}}

- GitLab 18.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/221941)되었습니다.
- GitLab 19.5에서 [목록에 없습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712). [`get_merge_request`](#get_merge_request)과 `include: ["conflicts"]`으로 대체되었습니다.

{{< /history >}}

[`get_merge_request`](#get_merge_request)과 `include: ["conflicts"]`으로 대체되었으며, 이는 평문 텍스트 대신 `ourPath` 및 `theirPath` 필드를 가진 구조화된 `conflictFiles` 항목으로 동일한 충돌을 반환합니다. 이 도구는 더 이상 `tools/list`에 나타나지 않지만 호출자가 마이그레이션하는 동안 계속 호출할 수 있습니다.

병합할 수 없는 머지 리퀘스트의 머지 충돌 콘텐츠를 검색합니다. 원시 Git 충돌 마커(`<<<<<<<`, `=======`, 및 `>>>>>>>`)를 충돌된 파일에 나타나는 대로 정확히 반환합니다. 각 파일의 콘텐츠는 `# File:` 제목 아래 그룹화됩니다. 이름이 바뀐 파일의 경우 제목은 각 브랜치의 경로를 표시합니다.

| 매개 변수           | 형식    | 필수 | 설명 |
|---------------------|---------|----------|-------------|
| `project_id`        | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로 (예: `gitlab-org/gitlab`). |
| `merge_request_iid` | 정수 | 예      | 머지 리퀘스트의 내부 ID입니다. |

머지 리퀘스트의 소스 브랜치에 푸시할 권한이 있어야 합니다. 머지 리퀘스트에 충돌이 없거나 병합 가능성이 아직 확인되지 않았거나 브랜치 또는 diff ref가 누락된 경우 도구가 오류를 반환합니다.

예:

```plaintext
Show the conflicts for merge request 42 in project gitlab-org/gitlab
```

## `save_note` {#save_note}

{{< history >}}

- GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241114)되었습니다.
- GitLab 19.4에서 `create_merge_request_note` 및 `create_workitem_note` 도구를 [대체](https://gitlab.com/gitlab-org/gitlab/-/work_items/605848)했습니다. 두 원본 도구 이름은 계속 별칭으로 작동합니다.

{{< /history >}}

인증된 사용자로 GitLab 머지 리퀘스트 또는 작업 항목에 주석을 추가하거나 기존 토론 스레드에 회신합니다.

| 매개 변수           | 형식    | 필수 | 설명 |
|---------------------|---------|----------|-------------|
| `url`               | 문자열  | 아니요       | 머지 리퀘스트 또는 작업 항목의 URL입니다. URL은 대상 유형을 결정합니다. |
| `project_id`        | 문자열  | 아니요       | 프로젝트의 ID 또는 경로입니다. `merge_request_iid`과 함께 필수이며, 프로젝트 수준 작업 항목의 경우 `work_item_iid`과 함께입니다. |
| `group_id`          | 문자열  | 아니요       | 그룹의 ID 또는 경로입니다. 그룹 수준 작업 항목의 경우 `work_item_iid`과 함께 필수입니다. |
| `merge_request_iid` | 정수 | 아니요       | 머지 리퀘스트의 내부 ID입니다. `project_id`과 함께 제공합니다. `work_item_iid`과 상호 배타적입니다. |
| `work_item_iid`     | 정수 | 아니요       | 작업 항목의 내부 ID입니다. `project_id` 또는 `group_id`과 함께 제공합니다. `merge_request_iid`과 상호 배타적입니다. |
| `body`              | 문자열  | 예      | 메모의 내용입니다. 줄이 `/`로 시작할 수 없습니다. 빠른 작업 실행을 피하기 위함입니다(예: `/merge`). |
| `internal`          | 부울 | 아니요       | 메모를 내부로 표시합니다 (최소 리포터 역할을 가진 멤버에게만 표시). 기본값은 `false`입니다. |
| `discussion_id`     | 문자열  | 아니요       | 답글할 토론의 글로벌 ID입니다(`gid://gitlab/Discussion/<id>` 형식). 누락된 경우 새 최상위 수준에 메모가 만들어집니다. |

예:

- 머지 리퀘스트에 댓글 달기:

  ```plaintext
  Reply "Thanks, fixed in the latest push" to merge request 42 in project gitlab-org/gitlab
  ```

- 작업 항목에 댓글 달기:

  ```plaintext
  Add a comment "This looks good to me" to work item 42 in project gitlab-org/gitlab
  ```

## `get_merge_request_notes` {#get_merge_request_notes}

{{< history >}}

- GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/597494)되었습니다.
- GitLab 19.5에서 [목록에 없습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712). [`get_merge_request`](#get_merge_request)의 `notes` 패싯으로 대체되었습니다.

{{< /history >}}

[`get_merge_request`](#get_merge_request)과 `include: ["notes"]`으로 대체되었습니다. 이 도구는 더 이상 `tools/list`에 나타나지 않지만 호출자가 마이그레이션하는 동안 계속 호출할 수 있습니다.

특정 GitLab 머지 리퀘스트의 메모(댓글 및 시스템 메모)를 검색합니다.

| 매개 변수           | 형식    | 필수 | 설명                                                                                    |
|---------------------|---------|----------|--------------------------------------------------------------------------------------------------|
| `url`               | 문자열  | 아니요       | GitLab 머지 리퀘스트의 URL입니다. `project_id` 및 `merge_request_iid`가 누락된 경우 필수입니다.   |
| `project_id`        | 문자열  | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url`이 누락된 경우 필수입니다.                                  |
| `merge_request_iid` | 정수 | 아니요       | 머지 리퀘스트의 내부 ID입니다. `url`이 누락된 경우 필수입니다.                                |
| `after`             | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다.                                                                 |
| `before`            | 문자열  | 아니요       | 백워드 페이지 로드에 대한 커서입니다.                                                                |
| `first`             | 정수 | 아니요       | 포워드 페이지 로드에 대해 반환할 메모의 수입니다.                                              |
| `last`              | 정수 | 아니요       | 포워드 페이지 로드에 대해 반환할 메모의 수입니다.                                             |

각 반환된 메모는 토론 ID를 포함하므로 관련된 메모를 스레드로 그룹화할 수 있습니다.

예:

```plaintext
Show me all comments on merge request 5 in project gitlab-org/gitlab
```

## `save_merge_request_review` {#save_merge_request_review}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605881)되었습니다.

{{< /history >}}

인증된 사용자로서 머지 리퀘스트 검토 아티팩트를 작성합니다. 각 호출은 `method` 매개 변수로 선택된 정확히 하나의 작업을 수행합니다.

| 메서드               | 작업 |
|----------------------|--------|
| `create_note`        | 최상위 수준 댓글을 추가합니다. |
| `reply_discussion`   | 기존 토론에 회신합니다. |
| `create_diff_note`   | 특정 diff 줄에 댓글을 추가합니다. |
| `resolve_discussion` | 토론을 해결하거나 해결을 취소합니다. |
| `submit_review`      | 여러 diff 댓글 및 선택적 요약을 한 번의 호출로 게시합니다. |
| `post_duo_review`    | GitLab Duo에 머지 리퀘스트를 검토하도록 요청합니다. GitLab Duo 코드 검토가 필요합니다. |
| `approve`            | 머지 리퀘스트를 승인합니다. 이미 승인된 호출은 `already_approved` 상태로 성공합니다. |
| `unapprove`          | 승인을 제거합니다. 사전 승인 없는 호출은 `not_approved` 상태로 성공합니다. |

`post_duo_review`, `approve`, 및 `unapprove`의 응답에는 머지 리퀘스트의 현재 `diff_head_sha`이 포함되므로 기존 승인 또는 검토가 여전히 최신 커밋을 포함하는지 확인할 수 있습니다.

| 매개 변수           | 형식    | 필수 | 설명 |
|---------------------|---------|----------|-------------|
| `url`               | 문자열  | 아니요       | GitLab 머지 리퀘스트의 URL입니다. `project_id` 및 `merge_request_iid`가 누락된 경우 필수입니다. |
| `project_id`        | 문자열  | 아니요       | 프로젝트의 ID 또는 경로입니다. `url`이 누락된 경우 필수입니다. |
| `merge_request_iid` | 정수 | 아니요       | 머지 리퀘스트의 내부 ID입니다. `url`이 누락된 경우 필수입니다. |
| `method`            | 문자열  | 예      | 수행할 작업입니다. 다른 메서드에 속하는 매개 변수는 거부됩니다. |
| `body`              | 문자열  | 아니요       | 메모 텍스트입니다. `create_note`, `reply_discussion` 및 `create_diff_note`에 대해 필수입니다. 빠른 작업을 트리거하는 것을 피하기 위해(예: `/merge`) 줄은 `/`로 시작할 수 없습니다. |
| `discussion_id`     | 문자열  | 아니요       | 작업할 토론입니다. `reply_discussion` 및 `resolve_discussion`에 필수입니다. 전역 ID 또는 해당 토론 ID를 수락합니다. |
| `internal`          | 부울 | 아니요       | `create_note`의 경우 메모를 내부로 표시합니다. |
| `resolved`          | 부울 | 아니요       | `resolve_discussion`의 경우 `true`은 해결하고 `false`은 해결을 취소합니다. 해당 메서드에 필수입니다. |
| `old_path`          | 문자열  | 아니요       | `create_diff_note`의 경우 변경 전 파일 경로입니다. `old_path` 또는 `new_path` 중 하나 또는 둘 모두를 제공합니다. |
| `new_path`          | 문자열  | 아니요       | `create_diff_note`의 경우 변경 후 파일 경로입니다. |
| `old_line`          | 정수 | 아니요       | `create_diff_note`의 경우 이전 버전의 줄 번호입니다. `old_line` 또는 `new_line` 중 하나 또는 둘 모두를 제공합니다. |
| `new_line`          | 정수 | 아니요       | `create_diff_note`의 경우 새 버전에 줄 번호입니다. |
| `comments`          | 배열   | 아니요       | `submit_review`의 경우 1-20개의 diff 댓글입니다. 각 항목은 `file` 및 `body`(필수)과 `old_line`, `new_line` 및 `suggestion`(선택 사항)을 사용합니다. 해당 메서드에 필수입니다. `file`은 변경 후 경로입니다. 이름이 바뀐 파일의 경우 대신 `create_diff_note`를 사용합니다. |
| `verdict`           | 문자열  | 아니요       | `submit_review`의 경우 요약 참고에 앞서는 전체적인 판정입니다. |
| `summary`           | 문자열  | 아니요       | `submit_review`의 경우 diff 댓글 후에 게시된 요약 메모입니다. |
| `summary_internal`  | 부울 | 아니요       | `submit_review`의 경우 요약 메모를 내부로 표시합니다. |
| `sha`               | 문자열  | 아니요       | `approve`의 경우 머리 SHA 가드입니다. 주어졌을 때 머지 리퀘스트 머리와 더 이상 일치하지 않으면 승인이 거부됩니다. `get_merge_request`에서 반환한 전체 40자 `diff_head_sha`를 전달합니다. |

예:

```plaintext
Review merge request 42 in project gitlab-org/gitlab and leave your findings as diff comments with a summary
```

## `list_project_members` {#list_project_members}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251379)되었습니다.

{{< /history >}}

역할 및 액세스 수준과 함께 GitLab 프로젝트의 멤버를 나열합니다.

| 매개 변수           | 형식    | 필수 | 설명 |
|---------------------|---------|----------|-------------|
| `project_id`        | 문자열  | 예      | 프로젝트의 전체 경로 또는 숫자 ID(예: `gitlab-org/gitlab` 또는 `278964`)입니다. |
| `include_inherited` | 부울 | 아니요       | 상위 그룹 또는 프로젝트의 하위 그룹에서 역할을 상속하는 멤버도 반환합니다. 기본값은 `false`입니다. |
| `query`             | 문자열  | 아니요       | 이름 또는 사용자 이름이 이 텍스트를 포함하는 멤버만 반환합니다. |
| `first`             | 정수 | 아니요       | 정방향 페이지 매김을 위해 반환할 멤버 수 (기본값 20, 최대 100). |
| `after`             | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. |

각 멤버에 대해 응답은 사용자 ID, 사용자 이름, 이름, 숫자 `access_level`, 일치하는 `access_level_name`(예: `Maintainer`) 및 멤버십 `expires_at` 날짜를 반환합니다. 이메일로 초대되었지만 아직 초대를 수락하지 않은 멤버는 반환되지 않습니다.

각 호출은 결과의 단일 페이지를 반환합니다. 더 많은 페이지가 있으면 응답 `metadata`에는 다음 페이지를 가져오기 위해 `after`으로 전달할 수 있는 `end_cursor`가 포함됩니다.

예:

```plaintext
Who are the maintainers of gitlab-org/gitlab?
```

## `get_user` {#get_user}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253176)되었습니다.

{{< /history >}}

단일 GitLab 사용자를 가져옵니다. 이 도구를 사용하여 사용자 이름 또는 자신의 계정을 숫자 사용자 ID로 확인합니다. 예를 들어 다른 도구로 담당자 또는 검토자를 설정하기 전에 사용합니다.

`username`, `id`, `me` 중 정확히 하나를 제공합니다.

| 매개 변수  | 형식    | 필수 | 설명 |
|------------|---------|----------|-------------|
| `username` | 문자열  | 아니요       | 조회할 사용자의 사용자 이름입니다. |
| `id`       | 정수 | 아니요       | 조회할 사용자의 숫자 ID입니다. |
| `me`       | 부울 | 아니요       | `true`로 설정하여 인증된 사용자를 조회합니다. 설정되었을 때 `username` 및 `id`을 생략합니다. 이 매개변수를 사용하지 않으려면 `false`로 설정합니다. |

응답은 사용자의 숫자 `id`, `username`, `name`, `state` 및 `web_url`를 반환합니다.

예:

```plaintext
What is my GitLab user ID?
```

## `accept_merge_request` {#accept_merge_request}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/617968)되었습니다.

{{< /history >}}

머지 리퀘스트를 병합하거나 자동으로 병합하도록 예약합니다. `strategy` 없이 병합이 즉시 시작되고 비동기적으로 완료됩니다. `strategy` 사용 시 자동 병합이 활성화되고 머지 리퀘스트는 검사가 통과되면 병합됩니다. 대신 머지 리퀘스트를 승인하려면 `save_merge_request_review` 도구를 사용합니다.

이미 병합된 머지 리퀘스트에 대한 호출은 `already_merged` 상태로 성공하며, 이미 예약된 머지 리퀘스트에 대한 `strategy` 호출은 `already_scheduled` 상태로 성공합니다.

| 매개 변수                     | 형식    | 필수 | 설명 |
|-------------------------------|---------|----------|-------------|
| `url`                         | 문자열  | 아니요       | 머지 리퀘스트의 GitLab URL입니다. 이것을 제공하거나 `project_id` 및 `merge_request_iid`를 제공합니다. |
| `project_id`                  | 문자열  | 아니요       | 프로젝트의 ID 또는 경로입니다. `url`이 누락된 경우 필수입니다. |
| `merge_request_iid`           | 정수 | 아니요       | 머지 리퀘스트의 내부 ID입니다. `url`이 누락된 경우 필수입니다. |
| `sha`                         | 문자열  | 예      | 머리 SHA 가드입니다. 더 이상 머지 리퀘스트 머리와 일치하지 않으면 병합이 거부됩니다. `get_merge_request`에서 반환한 `diff_head_sha`을 전달합니다. |
| `strategy`                    | 문자열  | 아니요       | 자동 병합 전략, 예: `merge_when_checks_pass`. 주어지면 즉시 병합하는 대신 자동 병합을 활성화합니다. |
| `squash`                      | 부울 | 아니요       | 병합할 때 커밋을 하나의 커밋으로 스쿼시합니다. |
| `commit_message`              | 문자열  | 아니요       | 사용자 지정 병합 커밋 메시지입니다. |
| `squash_commit_message`       | 문자열  | 아니요       | 사용자 지정 스쿼시 커밋 메시지입니다. `squash`이 `true`일 때 적용됩니다. |
| `should_remove_source_branch` | 부울 | 아니요       | 병합 후 소스 브랜치를 제거합니다. |

예:

```plaintext
Merge merge request 42 in project gitlab-org/gitlab once its checks pass, and remove the source branch
```

## `add_branch` {#add_branch}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605877)되었습니다. `create_branch`는 별칭으로도 허용됩니다.

{{< /history >}}

원본 ref에서 GitLab 프로젝트에 브랜치를 추가합니다.

| 매개 변수    | 형식   | 필수 | 설명 |
|--------------|--------|----------|-------------|
| `url`        | 문자열 | 아니요       | 프로젝트의 GitLab URL입니다. 이를 제공하거나 `project_id`을 제공합니다. |
| `project_id` | 문자열 | 아니요       | 프로젝트의 ID 또는 경로입니다. `url`이 제공되지 않으면 필수입니다. |
| `branch`     | 문자열 | 예      | 새 브랜치의 이름입니다. |
| `ref`        | 문자열 | 예      | 새 브랜치를 만들 브랜치 이름 또는 커밋 SHA입니다. |

예:

```plaintext
Create a branch named feature/x from main in project gitlab-org/gitlab
```

## `fork_repository` {#fork_repository}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/597680)되었습니다.

{{< /history >}}

GitLab 프로젝트를 네임스페이스로 포크합니다.

포크는 비동기적으로 생성됩니다. 응답에는 새 프로젝트 속성이 포함되며, `scheduled`와 같은 `import_status` 필드는 포크 진행률을 표시합니다.

호출이 다음 상태 기반의 이유로 실패합니다:

- 네임스페이스에 이미 프로젝트의 포크가 있을 때 `409` 상태입니다.
- 프로젝트 또는 네임스페이스가 없거나 프로젝트를 포크할 권한이 없을 때 `404` 상태입니다.

| 매개 변수        | 형식    | 필수 | 설명 |
|------------------|---------|----------|-------------|
| `id`             | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `namespace_id`   | 정수 | 아니요       | 프로젝트를 포크할 네임스페이스의 ID입니다. |
| `namespace_path` | 문자열  | 아니요       | 프로젝트를 포크할 네임스페이스의 경로입니다. |
| `name`           | 문자열  | 아니요       | 포크에 할당할 이름입니다. |
| `path`           | 문자열  | 아니요       | 포크에 할당할 경로입니다. |
| `description`    | 문자열  | 아니요       | 포크에 할당할 설명입니다. |
| `visibility`     | 문자열  | 아니요       | 포크의 가시성입니다. |

예:

```plaintext
Fork gitlab-org/gitlab-test into my personal namespace
```

## `list_branches` {#list_branches}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605849)되었습니다.

{{< /history >}}

GitLab 프로젝트의 브랜치를 나열하고, 필요에 따라 이름으로 필터링합니다.

| 매개 변수  | 형식    | 필수 | 설명 |
|------------|---------|----------|-------------|
| `id`       | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `search`   | 문자열  | 아니요       | 이름별 브랜치를 필터링합니다. |
| `page`     | 정수 | 아니요       | 현재 페이지 번호입니다. 기본값은 `1`입니다. |
| `per_page` | 정수 | 아니요       | 페이지당 항목 수입니다. 기본값은 `20`입니다. |

예:

```plaintext
List branches in gitlab-org/gitlab whose names contain "release"
```

## `get_repository_file` {#get_repository_file}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248744)되었습니다.

{{< /history >}}

특정 ref에서 리포지토리의 단일 파일의 내용을 검색합니다.

내용은 로컬 파일 시스템이 아닌 리포지토리에서 제공됩니다. 파일은 `ref`에서 커밋된 것으로 반환되므로 로컬 체크아웃의 커밋되지 않은 변경 사항은 포함되지 않습니다.

| 매개 변수    | 형식    | 필수 | 설명 |
|--------------|---------|----------|-------------|
| `url`        | 문자열  | 아니요       | 파일의 URL(예: `https://gitlab.example.com/my-group/my-project/-/blob/main/app/models/user.rb`)입니다. 이를 제공하거나 `project_id`, `file_path` 및 `ref`를 제공합니다. |
| `project_id` | 문자열  | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url`이 제공되지 않으면 필수입니다. `url`도 제공되면 둘 다 같은 프로젝트를 참조해야 합니다. |
| `file_path`  | 문자열  | 아니요       | 리포지토리 루트 기준으로 파일의 경로입니다. `url`이 제공되지 않으면 필수입니다. |
| `ref`        | 문자열  | 아니요       | 브랜치 이름, 태그 이름 또는 커밋 SHA입니다. 기본 브랜치에 `HEAD`를 사용합니다. `url`이 제공되지 않으면 필수입니다. |
| `offset`     | 정수 | 아니요       | 읽기를 시작할 0부터 시작하는 줄입니다. 기본값은 `0`입니다. |
| `limit`      | 정수 | 아니요       | 반환할 최대 줄 수입니다. 기본값 및 최대값은 `2000`입니다. |

응답에는 `metadata` 개체가 포함되어 있으며 `total_lines`, `returned_lines`, `truncated` 및 `size_bytes`가 있습니다. 응답이 파일의 일부만 다루는 경우 `system_instruction`는 다음 호출에서 사용할 `offset`을 설명합니다.

이 도구는 텍스트만 반환합니다. 바이너리 파일 및 Git LFS에 저장된 파일은 오류를 반환합니다. 프로젝트가 GitLab Duo 컨텍스트에서 제외하는 파일도 오류를 반환합니다.

예:

```plaintext
Show me app/models/user.rb from the main branch of my-group/my-project
```

## `list_repository_tree` {#list_repository_tree}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605873)되었습니다.

{{< /history >}}

주어진 경로 및 ref의 GitLab 리포지토리에 있는 파일 및 디렉토리를 나열합니다. 항목 메타데이터만 반환하고 파일 콘텐츠는 절대 반환하지 않습니다. 파일의 콘텐츠를 읽으려면 [`get_repository_file`](#get_repository_file)을 사용합니다.

| 매개 변수    | 형식    | 필수 | 설명 |
|--------------|---------|----------|-------------|
| `url`        | 문자열  | 아니요       | 프로젝트의 GitLab URL입니다. `url` 또는 `project_id` 중 정확히 하나를 제공합니다. |
| `project_id` | 문자열  | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url` 또는 `project_id` 중 정확히 하나를 제공합니다. |
| `path`       | 문자열  | 아니요       | 나열할 디렉토리의 경로, 리포지토리 루트 기준입니다. 기본값은 루트입니다. |
| `ref`        | 문자열  | 아니요       | 브랜치 이름, 태그 이름 또는 커밋 SHA입니다. 기본 브랜치로 기본값입니다. |
| `recursive`  | 부울 | 아니요       | 모든 하위 디렉토리의 항목을 재귀적으로 나열합니다. 기본값은 `false`입니다. |
| `after`      | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. 이전 응답에서 `endCursor`을 사용합니다. |

각 호출은 최대 100개 항목을 반환합니다. `pageInfo.hasNextPage`이 `true`일 때 다음 페이지를 가져오려면 `pageInfo.endCursor`을 `after`으로 전달합니다.

예:

```plaintext
List the files under app/services in gitlab-org/gitlab on the default branch
```

## `get_commit` {#get_commit}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/605874)되었습니다.

{{< /history >}}

단일 커밋의 메타데이터 및 선택적으로 해당 diff 또는 메모를 검색합니다.

| 매개 변수     | 형식    | 필수 | 설명 |
|---------------|---------|----------|-------------|
| `url`         | 문자열  | 아니요       | GitLab 커밋의 URL입니다. `project_id` 및 `commit_sha`이 제공되지 않으면 필수입니다. |
| `project_id`  | 문자열  | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url`이 제공되지 않으면 필수입니다. |
| `commit_sha`  | 문자열  | 아니요       | 조회할 커밋입니다. 전체 또는 짧은 SHA, 브랜치 이름 또는 태그 이름을 수락합니다. `url`이 제공되지 않으면 필수입니다. |
| `include`     | 배열   | 아니요       | 호출당 하나(`diff` 또는 `notes`)로, 인라인으로 가져올 연결된 패싯입니다. 기본 메타데이터는 항상 반환됩니다. |
| `diff_detail` | 문자열  | 아니요       | 커밋 diff의 세부 정보 수준입니다. `include`에 `diff`가 포함된 경우에만 적용됩니다. `stats` 또는 `full_patch` 중 하나입니다. 기본값은 `stats`입니다. |
| `notes_after` | 문자열  | 아니요       | 메모의 다음 페이지를 가져올 토큰입니다. `include`에 `notes`가 포함된 경우에만 적용됩니다. |
| `notes_first` | 정수 | 아니요       | 페이지당 반환할 메모의 수(최대 100)입니다. `include`에 `notes`가 포함된 경우에만 적용됩니다. |

`diff_detail`이 `stats`로 설정된 경우 diff 패싯은 파일별 및 요약 줄 수를 반환합니다. `full_patch`의 경우 패치 텍스트를 반환합니다.

예:

```plaintext
Show me commit abc123 in gitlab-org/gitlab with its diff stats
```

## `list_commits` {#list_commits}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605875)되었습니다.

{{< /history >}}

ref, author, path 또는 date로 필요에 따라 필터링된 GitLab 프로젝트의 커밋을 나열합니다. 콤팩트 커밋 메타데이터를 반환합니다. 단일 커밋의 diff 또는 메모를 얻으려면 [`get_commit`](#get_commit)을 사용합니다.

| 매개 변수      | 형식    | 필수 | 설명 |
|----------------|---------|----------|-------------|
| `url`          | 문자열  | 아니요       | 프로젝트의 GitLab URL입니다. `url` 또는 `project_id` 중 정확히 하나를 제공합니다. |
| `project_id`   | 문자열  | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url` 또는 `project_id` 중 정확히 하나를 제공합니다. |
| `ref_name`     | 문자열  | 아니요       | 커밋을 나열할 브랜치 또는 태그입니다. 기본 브랜치로 기본값입니다. |
| `author`       | 문자열  | 아니요       | 커밋 작성자 이름 또는 이메일별로 필터링합니다. |
| `path`         | 문자열  | 아니요       | 이 파일 경로를 건드린 커밋만 반환합니다. |
| `since`        | 문자열  | 아니요       | 이 ISO 8601 날짜 또는 시간 이후에 커밋된 날짜가 있는 커밋만 반환합니다. |
| `until`        | 문자열  | 아니요       | 이 ISO 8601 날짜 또는 시간 이전에 커밋된 날짜가 있는 커밋만 반환합니다. |
| `order`        | 문자열  | 아니요       | 정렬 전략입니다. `topo` 또는 `date`일 수 있습니다. 역시간 순서로 기본값입니다. |
| `first_parent` | 부울 | 아니요       | 머지 커밋의 첫 번째 부모만 따릅니다. |
| `with_stats`   | 부울 | 아니요       | 커밋별 라인 카운트 통계 (추가, 삭제 및 파일 변경)를 포함합니다. |
| `after`        | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. 이전 응답에서 `endCursor`을 사용합니다. |
| `first`        | 정수 | 아니요       | 반환할 커밋 수입니다. 기본값은 `20`, 최대값은 `100`입니다. |

`with_stats`이 `true`일 때 각 커밋은 Gitaly 호출 비용이 소요되므로 `first`은 `10`로 기본값이며 `with_stats`이 설정될 때 `10`를 초과할 수 없습니다.

예:

```plaintext
List commits to app/models in gitlab-org/gitlab since 2026-08-01 by Alex
```

## `list_releases` {#list_releases}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/618494)되었습니다.

{{< /history >}}

GitLab 프로젝트의 릴리스를 나열하고, 가장 최근에 릴리스된 먼저 나열합니다.

| 매개 변수    | 형식    | 필수 | 설명 |
|--------------|---------|----------|-------------|
| `url`        | 문자열  | 아니요       | 프로젝트의 GitLab URL입니다. `project_id`이 제공되지 않으면 필수입니다. |
| `project_id` | 문자열  | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url`이 제공되지 않으면 필수입니다. |
| `page`       | 정수 | 아니요       | 검색할 페이지 번호입니다. 기본값은 `1`입니다. |
| `per_page`   | 정수 | 아니요       | 페이지당 반환할 릴리스 수입니다. 기본값은 `20`, 최대값은 `100`입니다. |
| `state`      | 문자열  | 아니요       | 릴리스 상태별로 필터링: `released`, `upcoming` 또는 `all`. 기본값은 `released`입니다. |

`url` 또는 `project_id` 중 정확히 하나를 제공합니다.

각 항목은 릴리스 메타데이터만 반환합니다: `tag_name`, `name`, `released_at`, `upcoming` 및 `assets`. `assets`은 릴리스의 자산 링크 `count`의 개수와 그 중 최대 5개의 `links`을 보유합니다. 릴리스에 5개 이상이 있으면 `count`이 실제 합계를 보고합니다. 소스 아카이브는 제외되어 있습니다. 태그에서 파생될 수 있기 때문입니다.

응답에는 `metadata` 객체도 포함되며 `page`, `per_page` 및 `has_more`을 포함합니다. 다음 페이지를 요청할지 여부를 결정하려면 `has_more`을 사용합니다.

릴리스 정보는 의도적으로 이 응답에서 반환되지 않습니다.

미래의 `released_at`을 가진 릴리스는 발행되기보다는 예약되며, 발행된 릴리스보다 앞에 정렬됩니다. `state`을 사용하여 어떤 것을 얻을지 제어합니다. 예약된 릴리스는 `upcoming`이 `true`로 설정됩니다.

릴리스가 빌드된 커밋을 읽으려면 `get_commit` 도구에 `tag_name`을 전달합니다. 자산을 다운로드하려면 `assets.links`에서 `url`을 사용합니다.

예:

```plaintext
List the most recent releases for project gitlab-org/gitlab
```

## `list_tags` {#list_tags}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/618493)되었습니다.

{{< /history >}}

GitLab 프로젝트의 태그를 나열하고, 가장 최근에 업데이트된 먼저 나열합니다. `search`이 태그 이름과 정확히 일치하면 GitLab이 먼저 해당 태그를 나열합니다.

| 매개 변수    | 형식    | 필수 | 설명 |
|--------------|---------|----------|-------------|
| `url`        | 문자열  | 아니요       | 프로젝트의 GitLab URL입니다. `project_id`이 제공되지 않으면 필수입니다. |
| `project_id` | 문자열  | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url`이 제공되지 않으면 필수입니다. |
| `search`     | 문자열  | 아니요       | 이름별 태그를 필터링합니다. `^`을 지원하여 시작을 고정하고 `$`을 끝에 고정하고 `*`을 와일드카드로 지원합니다. |
| `first`      | 정수 | 아니요       | 반환할 태그 수입니다. 기본값은 `20`, 최대값은 `100`입니다. |
| `after`      | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. 이전 응답에서 `metadata.end_cursor`을 사용합니다. |

`url` 또는 `project_id` 중 정확히 하나를 제공합니다.

각 항목은 `name` 및 `commit`을 반환하며, 여기서 `commit`은 태그의 팁 커밋 `sha` 및 `title`을 보유합니다. `commit`은 커밋이 아닌 항목을 가리키는 태그의 경우 `null`입니다.

태그 메시지는 의도적으로 이 응답에서 반환되지 않습니다.

응답에는 `metadata` 객체도 포함되며 `has_next_page` 및 `end_cursor`을 포함합니다. `has_next_page`이 `true`일 때 다음 페이지를 가져오려면 `end_cursor`을 `after`으로 전달합니다.

태그가 가리키는 전체 커밋을 읽으려면 `get_commit` 도구를 사용합니다.

예:

```plaintext
List the most recent tags for the gitlab-org/gitlab project
```

## `get_pipeline` {#get_pipeline}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605853)되었습니다.
- `artifacts` 패싯은 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/585022)되었습니다.

{{< /history >}}

파이프라인을 검색하고, 필요에 따라 작업, 다운스트림 파이프라인, 브릿지(트리거) 작업 또는 작업이 생산한 아티팩트를 검색합니다.

| 매개 변수     | 형식    | 필수 | 설명 |
|---------------|---------|----------|-------------|
| `id`          | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `pipeline_id` | 정수 | 예      | 파이프라인의 ID입니다. |
| `include`     | 배열   | 아니요       | 파이프라인과 함께 포함할 패싯, 호출당 하나: `jobs`, `downstream_pipelines`, `bridge_jobs` 또는 `artifacts`. |
| `job_status`  | 문자열  | 아니요       | 상태로 `jobs` 패싯을 필터링합니다(예: `failed`). `include`가 `jobs`인 경우에만 적용됩니다. |
| `first`       | 정수 | 아니요       | 선택한 `include` 패싯에 대해 반환할 항목 수입니다. `artifacts` 패싯의 경우, 이는 아티팩트가 반환되는 작업의 수입니다. 기본값은 `20`, 최대값은 `100`입니다. |
| `after`       | 문자열  | 아니요       | 선택한 `include` 패싯의 포워드 페이지 로드에 대한 커서입니다. 이전 응답에서 `page_info.end_cursor`을 사용합니다. |

브리지 작업의 `downstream_pipeline`은 트리거 작업이 다운스트림 파이프라인을 아직 트리거하지 않은 경우 및 사용자가 해당 파이프라인에 액세스 권한이 없는 경우 모두에서 생략(`null`)됩니다.

다운스트림 파이프라인이 다른 프로젝트에 속할 수 있기 때문에 각 다운스트림 파이프라인에는 `project_full_path`가 포함됩니다. 해당 값을 후속 호출의 `id`로 사용합니다.

`artifacts` 패싯은 아티팩트의 평면 목록을 반환합니다. 각 아티팩트는 `name`, `size`, `file_type`, 만료 정보 및 해당 아티팩트를 생산한 작업의 `job_id` 및 `job_name`을 가집니다. 페이지 매김은 아티팩트가 아닌 파이프라인의 작업을 페이지합니다.

예:

- 파이프라인 가져오기:

  ```plaintext
  Get the status of pipeline 12345 in project gitlab-org/gitlab
  ```

- 파이프라인의 실패한 작업 가져오기:

  ```plaintext
  Show me the failed jobs in pipeline 12345 for project gitlab-org/gitlab
  ```

- 파이프라인의 다운스트림 파이프라인 가져오기:

  ```plaintext
  Show me the downstream pipelines triggered by pipeline 12345 in project gitlab-org/gitlab
  ```

- 파이프라인이 생산한 아티팩트 가져오기:

  ```plaintext
  List the artifacts of pipeline 12345 in project gitlab-org/gitlab
  ```

## `get_pipeline_jobs` {#get_pipeline_jobs}

{{< history >}}

- GitLab 18.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203055)되었습니다.
- GitLab 19.5에서 [목록에 없습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712). [`get_pipeline`](#get_pipeline)과 `include: ["jobs"]`으로 대체되었습니다.

{{< /history >}}

[`get_pipeline`](#get_pipeline)과 `include: ["jobs"]`으로 대체되었으며, 이는 단일 호출에서 파이프라인의 나머지 데이터와 함께 작업을 반환합니다. `jobs` 패싯은 작업당 더 적은 필드를 반환합니다: `failure_reason`, `duration`, `queued_duration` 또는 타임스탐프를 포함하지 않습니다. 이 도구는 더 이상 `tools/list`에 나타나지 않지만 호출자가 마이그레이션하는 동안 계속 호출할 수 있습니다.

특정 GitLab CI/CD 파이프라인의 작업을 검색합니다.

| 매개 변수     | 형식    | 필수 | 설명 |
|---------------|---------|----------|-------------|
| `id`          | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `pipeline_id` | 정수 | 예      | 파이프라인의 ID입니다. |
| `per_page`    | 정수 | 아니요       | 페이지당 작업 수입니다. |
| `page`        | 정수 | 아니요       | 현재 페이지 번호입니다. |

예:

```plaintext
Show me all jobs in pipeline 12345 for project gitlab-org/gitlab
```

## `get_job` {#get_job}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605856)되었습니다.
- GitLab 19.3에서 `get_job_log`에서 [이름이 바뀌었습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/605856). `get_job_log`은 별칭으로 계속 작동하며 항상 `log` 패싯을 반환하며 `byte_limit`로 제한됩니다.
- `artifacts` 패싯은 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/585022)되었습니다.

{{< /history >}}

CI/CD 작업의 메타데이터를 가져오고, 필요에 따라 trace/log 또는 생산한 아티팩트를 가져옵니다.

| 매개 변수     | 형식    | 필수 | 설명 |
|---------------|---------|----------|-------------|
| `id`          | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `job_id`      | 정수 | 예      | 작업의 ID입니다. |
| `include`     | 배열   | 아니요       | 작업과 함께 포함할 패싯, 호출당 하나: `log` 또는 `artifacts`. |
| `byte_offset` | 정수 | 아니요       | 작업의 로그를 읽기 시작할 바이트 오프셋입니다. `include`가 `log`인 경우에만 적용됩니다. 기본값은 `0`입니다. |
| `byte_limit`  | 정수 | 아니요       | 반환할 작업의 로그의 최대 바이트 수입니다. `include`가 `log`인 경우에만 적용됩니다. 기본값 및 최대값은 `512000`입니다. |

로그가 `byte_limit`보다 길면 응답은 전체 크기를 보고하고 다음 기간에 사용할 `byte_offset`을 알려줍니다.

`artifacts` 패싯은 작업이 생산한 모든 아티팩트를 나열하며 `name`, `size`, `file_type` 및 만료 정보를 가집니다.

예:

- 작업의 메타데이터 가져오기:

  ```plaintext
  Get the status of job 88 in project gitlab-org/gitlab
  ```

- 작업의 로그 가져오기:

  ```plaintext
  Show me the log output for job 88 in project gitlab-org/gitlab
  ```

- 작업의 아티팩트 가져오기:

  ```plaintext
  What artifacts did job 88 in project gitlab-org/gitlab produce?
  ```

## `get_artifact_file` {#get_artifact_file}

{{< history >}}

- GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/585022)되었습니다.

{{< /history >}}

CI/CD 작업의 아티팩트 아카이브 내의 파일을 텍스트로 읽습니다. 작업 또는 파이프라인이 생산한 항목을 발견하려면 `include: artifacts`과 함께 `get_job` 또는 `get_pipeline` 도구를 사용합니다.

| 매개 변수       | 형식    | 필수 | 설명 |
|-----------------|---------|----------|-------------|
| `url`           | 문자열  | 아니요       | 작업의 URL입니다. 이것을 제공하거나 `project_id` 및 `job_id`를 제공합니다. |
| `project_id`    | 문자열  | 아니요       | 프로젝트의 ID 또는 전체 경로입니다. `url`이 제공되지 않으면 필수입니다. |
| `job_id`        | 정수 | 아니요       | 작업의 ID입니다. `url`이 제공되지 않으면 필수입니다. |
| `artifact_path` | 문자열  | 예      | 아티팩트 아카이브 내의 파일 경로, 예: `coverage/index.html`. |
| `byte_offset`   | 정수 | 아니요       | 파일 읽기를 시작할 바이트 오프셋입니다. 기본값은 `0`입니다. |
| `byte_limit`    | 정수 | 아니요       | 반환할 최대 바이트 수입니다. 기본값 및 최대값은 `1048576` (1 MB)입니다. |

도구는 아카이브 아티팩트에서만 읽습니다. `junit` 또는 `dotenv` 아티팩트와 같은 별도의 파일로 저장된 아티팩트를 보고하면 아카이브의 일부가 아니므로 이 도구로 읽을 수 없습니다.

파일이 `byte_limit`보다 길면 응답이 전체 크기를 보고하고 다음 창에 사용할 `byte_offset`를 알려줍니다. 바이너리 파일은 반환되지 않습니다. 오류는 파일, 크기 및 유형의 이름을 지정하며 브라우저에서 볼 수 있는 위치를 지정합니다.

예:

- 작업의 아티팩트에서 테스트 보고서 읽기:

  ```plaintext
  Read coverage/index.html from the artifacts of job 88 in project gitlab-org/gitlab
  ```

- 실패한 종단 간 테스트 조사:

  ```plaintext
  Find the JUnit report in the artifacts of job 88 in gitlab-org/gitlab and summarize the failures
  ```

## `list_pipelines` {#list_pipelines}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605854)되었습니다.

{{< /history >}}

GitLab 프로젝트의 파이프라인을 선택적 필터와 함께 나열합니다.

| 매개 변수        | 형식    | 필수 | 설명 |
|------------------|---------|----------|-------------|
| `id`             | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `ref`            | 문자열  | 아니요       | 브랜치 또는 태그 이름입니다. 파이프라인을 ref별로 필터링합니다. |
| `status`         | 문자열  | 아니요       | 파이프라인을 상태로 필터링합니다(예: `running`, `success`, `failed`). |
| `source`         | 문자열  | 아니요       | 파이프라인을 소스별로 필터링합니다(예: `push`, `web`, `schedule`). |
| `created_after`  | 문자열  | 아니요       | 지정된 datetime(ISO 8601 형식) 이후에 만들어진 파이프라인을 반환합니다. |
| `created_before` | 문자열  | 아니요       | 지정된 datetime(ISO 8601 형식) 이전에 만들어진 파이프라인을 반환합니다. |
| `order_by`       | 문자열  | 아니요       | 파이프라인을 `id`, `status`, `ref`, `updated_at` 또는 `user_id`로 정렬합니다. 기본값은 `id`입니다. |
| `sort`           | 문자열  | 아니요       | 정렬 방향이며 `asc` 또는 `desc`입니다. 기본값은 `desc`입니다. |
| `page`           | 정수 | 아니요       | 현재 페이지 번호입니다. 기본값은 `1`입니다. |
| `per_page`       | 정수 | 아니요       | 페이지당 항목 수입니다. 기본값은 `20`입니다. |

하위 파이프라인은 기본적으로 결과에서 제외됩니다. 파위 파이프라인만 반환하려면 `source`를 `parent_pipeline`으로 설정합니다.

기본 순서(`id`, `desc`)는 가장 높은 ID를 가진 파이프라인을 먼저 반환합니다. ID 순서는 보통 만든 순서와 일치하지만 두 항목이 일치한다고 보장할 수 없습니다. `created_after` 또는 `created_before`을 사용하여 명시적 시간 경계로 필터링합니다. 호출자는 결과 페이지를 검색하고 대상 범위 외의 첫 파이프라인에서 중지할 수 있습니다.

예:

```plaintext
List all failed pipelines on the main branch for project gitlab-org/gitlab
```

## `save_pipeline` {#save_pipeline}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605855)되었습니다.
- `update` 작업은 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/619469)되었습니다.

{{< /history >}}

GitLab 프로젝트에서 CI/CD 파이프라인을 실행, 재시도, 취소 또는 이름을 바꿉니다. 파이프라인을 나열하려면 `list_pipelines` 도구를 대신 사용합니다.

| 매개 변수     | 형식    | 필수    | 설명 |
|---------------|---------|-------------|-------------|
| `url`         | 문자열  | 아니요          | 프로젝트의 GitLab URL입니다. 파이프라인을 만들 때만 사용됩니다. 이를 제공하거나 `project_id`을 제공합니다. |
| `project_id`  | 문자열  | 아니요          | 프로젝트의 ID 또는 전체 경로입니다. 파이프라인을 만들 때만 사용됩니다. 이를 제공하거나 `url`을 제공합니다. |
| `pipeline_id` | 정수 | 아니요          | 대상으로 할 기존 파이프라인의 ID입니다. 설정된 경우 `action`이 필요합니다. 새 파이프라인을 만들려면 생략합니다. |
| `action`      | 문자열  | 아니요          | `pipeline_id`에서 수행할 수명 주기 작업: `retry`, `cancel` 또는 `update`. `pipeline_id`가 설정된 경우 필수입니다. |
| `ref`         | 문자열  | 아니요          | 브랜치 또는 태그 이름입니다. 파이프라인을 만들려면 필수입니다(`pipeline_id`가 없는 경우). |
| `name`        | 문자열  | 아니요          | 새 파이프라인 이름입니다. `action: "update"`에 필수입니다. |
| `variables`   | 배열   | 아니요          | 배열 형식(`[{key, value, variable_type}]`)의 파이프라인 변수입니다. |
| `inputs`      | 해시    | 아니요          | 키-값 쌍으로 된 파이프라인 입력 매개변수입니다. |

예:

- 파이프라인 만들기:

  ```plaintext
  Create a pipeline on the main branch for project gitlab-org/gitlab
  ```

- 파이프라인 재시도:

  ```plaintext
  Retry failed jobs in pipeline 12345 for project gitlab-org/gitlab
  ```

- 파이프라인 취소:

  ```plaintext
  Cancel pipeline 12345 in project gitlab-org/gitlab
  ```

- 파이프라인의 이름을 바꿉니다:

  ```plaintext
  Rename pipeline 12345 to "Nightly security scan" in project gitlab-org/gitlab
  ```

## `manage_pipeline` {#manage_pipeline}

{{< history >}}

- GitLab 18.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/583826)되었습니다.
- GitLab 19.3에서 `list_pipelines` 도구로 대신하여 `list` 작업을 [제거](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247806)했습니다.
- GitLab 19.3에서 `save_pipeline` 도구로 대신하여 `create`, `retry` 및 `cancel` 작업을 [제거](https://gitlab.com/gitlab-org/gitlab/-/work_items/605855)했습니다.
- GitLab 19.5에서 [목록에 없습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/631276). 파이프라인의 이름을 바꾸려면 [`save_pipeline`](#save_pipeline)을 `action: "update"`과 함께 사용합니다.

{{< /history >}}

> [!warning]
> 이 도구는 더 이상 나열되지 않지만 오래된 도구 목록을 가지고 있거나 도구 이름을 저장한 에이전트에서 계속 호출할 수 있습니다. 파이프라인의 이름을 바꾸려면 [`save_pipeline`](#save_pipeline)을 대신 `action: "update"`과 함께 사용합니다. 파이프라인 삭제는 아직 교체되지 않았습니다.

GitLab 프로젝트에서 파이프라인 메타데이터를 업데이트하거나 파이프라인을 삭제합니다. 파이프라인을 만들거나 다시 시도하거나 취소하려면 대신 `save_pipeline` 도구를 사용합니다. 파이프라인을 나열하려면 `list_pipelines` 도구를 대신 사용합니다.

| 매개 변수     | 형식    | 필수    | 설명 |
|---------------|---------|-------------|-------------|
| `id`          | 문자열  | 예         | 프로젝트의 ID 또는 전체 경로입니다. |
| `pipeline_id` | 정수 | 예         | 파이프라인의 ID입니다. 이 매개변수만 설정된 경우 파이프라인 및 모든 관련 데이터를 삭제합니다. |
| `name`        | 문자열  | 아니요          | 파이프라인의 이름입니다. 이 매개변수와 `pipeline_id`이 설정된 경우 파이프라인 메타데이터를 업데이트합니다. |

예:

- 파이프라인 업데이트:

  ```plaintext
  Rename pipeline 12345 to "My deploy pipeline" in project gitlab-org/gitlab
  ```

- 파이프라인 삭제:

  ```plaintext
  Delete pipeline 12345 in project gitlab-org/gitlab
  ```

## `get_work_item` {#get_work_item}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605882)되었습니다.
- `discussions` 패싯은 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/597686)되었습니다.

{{< /history >}}

단일 작업 항목(이슈, 에픽, 작업, 인시던트, 목표 또는 핵심 결과)을 해당 유형, 날짜, 담당자, 레이블, 마일스톤 및 부모와 함께 검색합니다. 선택적으로 해당 메모, 토론 또는 관련 머지 리퀘스트를 포함합니다. 작업 항목 유형이 지원하지 않는 위젯은 생략됩니다.

| 매개 변수                       | 형식    | 필수 | 설명 |
|---------------------------------|---------|----------|-------------|
| `url`                           | 문자열  | 아니요       | 작업 항목의 GitLab URL (`/-/work_items/`, `/-/issues/` 또는 `/-/epics/` URL). 이를 제공하거나 `work_item_iid`을 `group_id` 또는 `project_id`과 함께 제공합니다. |
| `group_id`                      | 문자열  | 아니요       | 그룹의 ID 또는 경로입니다. `url` 및 `project_id`가 누락된 경우 필수입니다. |
| `project_id`                    | 문자열  | 아니요       | 프로젝트의 ID 또는 경로입니다. `url` 및 `group_id`가 누락된 경우 필수입니다. |
| `work_item_iid`                 | 정수 | 아니요       | 작업 항목의 내부 ID입니다. `url`이 누락된 경우 필수입니다. |
| `include`                       | 배열   | 아니요       | 반환할 관련 데이터입니다. `notes`, `discussions` 또는 `related_merge_requests` 중 하나, 호출당 하나의 패싯입니다. 최신 메모의 경우 `notes_last`을 `notes_first` 또는 `notes_after` 없이 사용합니다. |
| `notes_first`                   | 정수 | 아니요       | 커서 뒤에 반환할 메모 수 (정방향 페이지 매김). 기본값 100, 최대 100. |
| `notes_after`                   | 문자열  | 아니요       | 메모의 포워드 페이지 로드에 대한 커서입니다. 이전 응답에서 `pageInfo.endCursor`을 사용합니다. |
| `notes_last`                    | 정수 | 아니요       | 커서 앞에 반환할 메모 수 (역방향 페이지 매김). 기본값 100, 최대 100. |
| `notes_before`                  | 문자열  | 아니요       | 메모의 역방향 페이지 매김을 위한 커서입니다. 이전 응답에서 `pageInfo.startCursor`을 사용합니다. |
| `discussions_first`             | 정수 | 아니요       | 커서 뒤에 반환할 토론 수입니다. 기본값 20, 최대 100. |
| `discussions_after`             | 문자열  | 아니요       | 토론의 정방향 페이지 매김을 위한 커서입니다. 이전 응답에서 `pageInfo.endCursor`을 사용합니다. |
| `discussions_filter`            | 문자열  | 아니요       | 반환할 토론: `all_notes` (기본값), 시스템 메모를 제외하려면 `only_comments` 또는 시스템 메모만 `only_activity`. |
| `related_merge_requests_first`  | 정수 | 아니요       | 반환할 관련 머지 리퀘스트 수입니다. 기본값 20, 최대 100. |
| `related_merge_requests_after`  | 문자열  | 아니요       | 관련 머지 리퀘스트의 정방향 페이지 매김을 위한 커서입니다. |
| `mr_page_size`                  | 정수 | 아니요       | 대신 `related_merge_requests_first`을 사용하십시오. |
| `mr_pagination_cursor`          | 문자열  | 아니요       | 대신 `related_merge_requests_after`을 사용하십시오. |

`notes` 패싯은 호출당 최대 100개 메모를 반환하고 `notes_*` 매개변수로 양방향 페이지 매김을 수행합니다. 각 메모에는 `discussion.id`, 속하는 스레드의 ID가 포함되어 메모를 스레드별로 그룹화할 수 있습니다.

스레드 구조 및 해결 상태의 경우 `discussions`을 사용하고, 시간 순서 히스토리의 경우 `notes`을 사용합니다.

`discussions` 패싯은 작업 항목의 스레드를 반환합니다. 각 토론은 `resolvable` 및 `resolved` 상태와 해당 메모를 포함하므로 아직 미해결된 스레드를 찾을 수 있습니다. 미해결 스레드는 `resolvable`이 `true`로 설정되고 `resolved`이 `false`로 설정됩니다. `discussions_*` 매개변수로만 정방향 페이지 매김을 수행하며, 토론은 페이지 전체에 분할되지 않습니다.

`related_merge_requests` 패싯은 에픽과 같은 그룹 작업 항목에 대해 비어 있습니다.

예:

```plaintext
Get issue 42 in project gitlab-org/gitlab with its related merge requests
```

## `get_workitem_notes` {#get_workitem_notes}

{{< history >}}

- GitLab 18.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/581892)되었습니다.
- GitLab 19.4에서 [목록에 없습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/625128). [`get_work_item`](#get_work_item)의 `notes` 패싯으로 대체되었습니다.

{{< /history >}}

[`get_work_item`](#get_work_item)과 `include: ["notes"]`으로 대체되었으며, 양방향에서 메모를 페이지합니다. 이 도구는 더 이상 `tools/list`에 나타나지 않지만 호출자가 마이그레이션하는 동안 계속 호출할 수 있습니다.

특정 GitLab 작업 항목의 모든 메모(댓글)를 검색합니다.

| 매개 변수       | 형식    | 필수 | 설명 |
|-----------------|---------|----------|-------------|
| `url`           | 문자열  | 아니요       | 작업 항목의 URL입니다. `group_id` 또는 `project_id` 및 `work_item_iid`이 누락된 경우 필수입니다. |
| `group_id`      | 문자열  | 아니요       | 그룹의 ID 또는 경로입니다. `url` 및 `project_id`가 누락된 경우 필수입니다. |
| `project_id`    | 문자열  | 아니요       | 프로젝트의 ID 또는 경로입니다. `url` 및 `group_id`가 누락된 경우 필수입니다. |
| `work_item_iid` | 정수 | 아니요       | 작업 항목의 내부 ID입니다. `url`이 누락된 경우 필수입니다. |
| `after`         | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. |
| `before`        | 문자열  | 아니요       | 백워드 페이지 로드에 대한 커서입니다. |
| `first`         | 정수 | 아니요       | 포워드 페이지 로드에 대해 반환할 메모의 수입니다. |
| `last`          | 정수 | 아니요       | 포워드 페이지 로드에 대해 반환할 메모의 수입니다. |

예:

```plaintext
Show me all comments on work item 42 in project gitlab-org/gitlab
```

## `link_work_items` {#link_work_items}

{{< history >}}

- GitLab 19.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/230221)되었습니다.
- `work_items_ids`에 대한 일반 iid는 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254551)되었습니다.

{{< /history >}}

작업 항목을 하나 이상의 다른 작업 항목과 관계 유형으로 연결합니다.

| 매개 변수        | 형식             | 필수 | 설명 |
|------------------|------------------|----------|-------------|
| `work_items_ids` | 배열            | 예      | 링크할 작업 항목: 같은 프로젝트 또는 그룹에서 해결된 일반 iid 또는 다른 프로젝트 또는 그룹의 작업 항목에 대한 전역 ID (`gid://gitlab/WorkItem/<id>`). 최대 10개 항목입니다. |
| `url`            | 문자열           | 아니요       | 소스 작업 항목의 URL입니다. `group_id` 또는 `project_id` 및 `work_item_iid`이 누락된 경우 필수입니다. |
| `group_id`       | 문자열           | 아니요       | 그룹의 ID 또는 경로입니다. `url` 및 `project_id`가 누락된 경우 필수입니다. |
| `project_id`     | 문자열           | 아니요       | 프로젝트의 ID 또는 경로입니다. `url` 및 `group_id`가 누락된 경우 필수입니다. |
| `work_item_iid`  | 정수          | 아니요       | 소스 작업 항목의 내부 ID입니다. `url`이 누락된 경우 필수입니다. |
| `link_type`      | 문자열           | 아니요       | 관계 유형입니다. `relates_to`, `blocks` 또는 `blocked_by` 중 하나입니다. 기본값은 `relates_to`입니다. `blocks` 및 `blocked_by` 유형은 GitLab Premium 또는 Ultimate이 필요합니다. |

예:

```plaintext
Mark work item 42 in project gitlab-org/gitlab as blocked by work item 40
```

## `get_saved_view_work_items` {#get_saved_view_work_items}

{{< history >}}

- GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/227911)되었습니다.

{{< /history >}}

네임스페이스에서 저장된 보기와 작업 항목 목록을 검색합니다. 도구는 저장된 보기의 필터와 정렬 순서를 반환된 작업 항목에 적용합니다.

| 매개 변수       | 형식    | 필수 | 설명 |
|-----------------|---------|----------|-------------|
| `saved_view_id` | 문자열  | 예      | 저장된 보기의 글로벌 ID입니다(`gid://gitlab/WorkItems::SavedViews::SavedView/<id>` 형식). |
| `url`           | 문자열  | 아니요       | 네임스페이스(프로젝트 또는 그룹)의 URL입니다. `group_id` 또는 `project_id`이 누락된 경우 필수입니다. |
| `group_id`      | 문자열  | 아니요       | 그룹의 ID 또는 경로입니다. `url` 및 `project_id`가 누락된 경우 필수입니다. |
| `project_id`    | 문자열  | 아니요       | 프로젝트의 ID 또는 경로입니다. `url` 및 `group_id`가 누락된 경우 필수입니다. |
| `after`         | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. |
| `first`         | 정수 | 아니요       | 반환할 작업 항목 수입니다. 최대 100입니다. |

예:

```plaintext
Show me the work items in this saved view: <URL>
```

## `list_vulnerabilities` {#list_vulnerabilities}

{{< details >}}

- 티어:  Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251243)되었습니다.

{{< /history >}}

GitLab 프로젝트의 보안 취약성을 선택적 필터 및 커서 페이지 매김과 함께 나열합니다. 페이지가 매겨진 취약성 메타데이터를 반환합니다. 단일 취약성의 전체 세부 정보를 얻으려면 [`get_vulnerability`](#get_vulnerability)을 사용합니다.

보안 대시보드 기능이 활성화되어야 합니다.

이 도구는 라이선스 기능을 사용할 수 있을 때만 나열됩니다. 자세한 내용은 [도구 그룹 선택](mcp_server.md#select-tool-groups-toolsets)을 참조하세요.

| 매개 변수            | 형식             | 필수 | 설명 |
|----------------------|------------------|----------|-------------|
| `project_full_path`  | 문자열           | 예      | 프로젝트의 전체 경로 (예: `namespace/project` 또는 `group/subgroup/project`). |
| `severity`           | 문자열 배열 | 아니요       | 심각도 수준별로 필터링합니다. 생략하여 모든 심각도의 취약성을 포함합니다. `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` 또는 `UNKNOWN` 중 하나 이상입니다. |
| `report_type`        | 문자열 배열 | 아니요       | 보안 보고서 유형별로 필터링합니다. 생략하여 모든 보고서 유형을 포함합니다. 예: `SAST`, `DAST` 또는 `DEPENDENCY_SCANNING`. |
| `state`              | 문자열 배열 | 아니요       | 취약성 상태별로 필터링합니다. 생략하여 모든 상태의 취약성을 포함합니다. `CONFIRMED`, `DETECTED`, `DISMISSED` 또는 `RESOLVED` 중 하나 이상입니다. |
| `first`              | 정수          | 아니요       | 정방향 페이지 매김을 위해 반환할 취약성 수입니다. 기본값은 `20`, 최대값은 `100`입니다. |
| `after`              | 문자열           | 아니요       | 포워드 페이지 로드에 대한 커서입니다. 이전 응답에서 `pageInfo.endCursor`을 사용합니다. |

예:

```plaintext
List critical and high severity vulnerabilities in project gitlab-org/gitlab
```

## `get_vulnerability` {#get_vulnerability}

{{< details >}}

- 티어:  Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251243)되었습니다.

{{< /history >}}

제목, 상태, 설명, 심각도 및 식별자를 포함한 단일 취약성에 대한 포괄적인 세부 정보를 반환합니다.

이 도구는 라이선스 기능을 사용할 수 있을 때만 나열됩니다. 자세한 내용은 [도구 그룹 선택](mcp_server.md#select-tool-groups-toolsets)을 참조하세요.

| 매개 변수          | 형식   | 필수 | 설명 |
|--------------------|--------|----------|-------------|
| `vulnerability_id` | 문자열 | 예      | 취약성의 숫자 ID (예: `567`). |

예:

```plaintext
Get full details for vulnerability 567
```

## `save_vulnerability` {#save_vulnerability}

{{< details >}}

- 티어:  Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/613026)되었습니다.

{{< /history >}}

GitLab 프로젝트의 취약성에 대한 쓰기 작업을 수행합니다.

이 도구는 라이선스 기능을 사용할 수 있을 때만 나열됩니다. 자세한 내용은 [도구 그룹 선택](mcp_server.md#select-tool-groups-toolsets)을 참조하세요.

| 매개 변수            | 형식   | 필수 | 설명 |
|----------------------|--------|----------|-------------|
| `action`             | 문자열 | 예      | 수행할 작업입니다. `dismiss`, `confirm`, `revert_to_detected`, `update_severity` 또는 `create_issue` 중 하나입니다. |
| `vulnerability_id`   | 문자열 | 예      | 취약성의 숫자 ID (예: `567`). |
| `comment`            | 문자열 | 아니요       | 작업에 대한 설명입니다. `action`가 `update_severity`일 때 필수입니다. |
| `dismissal_reason`   | 문자열 | 아니요       | 거부 이유입니다. `ACCEPTABLE_RISK`, `FALSE_POSITIVE`, `MITIGATING_CONTROL`, `USED_IN_TESTS` 또는 `NOT_APPLICABLE` 중 하나입니다. `action`이 `dismiss`일 때만 사용합니다. |
| `severity`           | 문자열 | 아니요       | 새로운 심각도 수준입니다. `INFO`, `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH` 또는 `CRITICAL` 중 하나입니다. `action`가 `update_severity`일 때 필수입니다. |
| `project_full_path`  | 문자열 | 아니요       | 프로젝트의 전체 경로 (예: `namespace/project`). `action`가 `create_issue`일 때 필수입니다. |

예:

- 취약성 거부:

  ```plaintext
  Dismiss vulnerability 123 with reason FALSE_POSITIVE
  ```

- 취약성 확인:

  ```plaintext
  Mark vulnerability 456 as confirmed
  ```

- 감지됨으로 되돌리기:

  ```plaintext
  Revert vulnerability 789 back to detected state
  ```

- 심각도 업데이트:

  ```plaintext
  Change severity of vulnerability 321 to CRITICAL with comment "Reassessed based on new intel"
  ```

- 문제 생성:

  ```plaintext
  Create an issue for vulnerability 654 in project gitlab-org/gitlab
  ```

## `save_work_item` {#save_work_item}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605852)되었습니다.
- `labels`, `add_labels`, `remove_labels`, `milestone_id` 및 `milestone` 매개변수는 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/622711)되었습니다.

{{< /history >}}

이슈, 작업 또는 에픽 같은 GitLab 작업 항목을 만들거나 업데이트합니다. 새 작업 항목을 만들려면 `work_item_iid`를 생략합니다. 기존 항목을 업데이트하려면 `work_item_iid` 또는 작업 항목 URL을 제공합니다. 설정하려는 필드만 보내고 나머지는 생략합니다. 도구 이름 `create_work_item` 및 `update_work_item`은 이 도구의 별칭입니다.

| 매개 변수          | 형식              | 필수 | 설명 |
|--------------------|-------------------|----------|-------------|
| `url`              | 문자열            | 아니요       | 프로젝트, 그룹 또는 작업 항목의 GitLab URL입니다. `url`, `project_id`, `group_id` 중 정확히 하나를 제공합니다. |
| `group_id`         | 문자열            | 아니요       | 그룹의 ID 또는 경로입니다. `url` 및 `project_id`가 누락된 경우 필수입니다. |
| `project_id`       | 문자열            | 아니요       | 프로젝트의 ID 또는 경로입니다. `url` 및 `group_id`가 누락된 경우 필수입니다. |
| `work_item_iid`    | 정수           | 아니요       | 업데이트할 작업 항목의 양수 내부 ID입니다. 새 작업 항목을 만들려면 생략합니다. |
| `title`            | 문자열            | 아니요       | 작업 항목의 제목입니다. 작업 항목을 만드는 경우 필수입니다. |
| `type_name`        | 문자열            | 아니요       | 작업 항목 유형 이름(예: `Issue`, `Task`, `Epic`)입니다. 작업 항목을 만드는 경우 필수입니다. 유효한 유형은 네임스페이스 및 라이선스에 따라 다릅니다. |
| `description`      | 문자열            | 아니요       | GitLab Flavored Markdown에 설명입니다. 최대 1,048,576자입니다. |
| `assignee_ids`     | 정수 배열 | 아니요       | 작업 항목에 할당할 사용자 ID입니다. 최대 100개 항목입니다. |
| `label_ids`        | 문자열 배열  | 아니요       | 레이블 ID 또는 전역 ID입니다. 만들기 전용입니다. 업데이트에서는 `add_label_ids` 또는 `remove_label_ids`를 사용합니다. 최대 100개 항목입니다. |
| `labels`           | 문자열 배열  | 아니요       | 프로젝트 또는 그룹 및 해당 상위 그룹에서 해결된 설정할 레이블의 이름입니다. 만들기 전용입니다. 업데이트에서는 `add_labels` 또는 `remove_labels`를 사용합니다. 최대 100개 항목입니다. |
| `add_label_ids`    | 문자열 배열  | 아니요       | 업데이트 전용입니다. 추가할 레이블 ID 또는 전역 ID입니다. 최대 100개 항목입니다. |
| `add_labels`       | 문자열 배열  | 아니요       | 업데이트 전용입니다. 추가할 레이블의 이름입니다. 최대 100개 항목입니다. |
| `remove_label_ids` | 문자열 배열  | 아니요       | 업데이트 전용입니다. 제거할 레이블 ID 또는 전역 ID입니다. 최대 100개 항목입니다. |
| `remove_labels`    | 문자열 배열  | 아니요       | 업데이트 전용입니다. 제거할 레이블의 이름입니다. 최대 100개 항목입니다. |
| `milestone_id`     | 문자열            | 아니요       | 할당할 마일스톤의 ID 또는 전역 ID, 프로젝트 또는 그룹 및 해당 상위 그룹에 대해 유효성이 검증됩니다. 둘 다 주어진 경우 `milestone`보다 우선합니다. |
| `milestone`        | 문자열            | 아니요       | 할당할 마일스톤의 제목, 프로젝트 또는 그룹 및 해당 상위 그룹의 마일스톤 중에서 해결됩니다. |
| `confidential`     | 부울           | 아니요       | 작업 항목 기밀성을 설정합니다. |
| `start_date`       | 문자열            | 아니요       | 시작 날짜이며 `YYYY-MM-DD` 형식입니다. |
| `due_date`         | 문자열            | 아니요       | 기한 날짜이며 `YYYY-MM-DD` 형식입니다. |
| `state`            | 문자열            | 아니요       | 업데이트 전용입니다. `closed`은 작업 항목을 닫고 `opened`은 다시 엽니다. |
| `parent_id`        | 문자열            | 아니요       | 상위 작업 항목의 전역 ID 또는 숫자 ID입니다. |
| `todo_action`      | 문자열            | 아니요       | 업데이트 전용입니다. `add`는 현재 사용자에 대해 할 일을 추가하고 `mark_as_done`은 할 일을 완료로 표시합니다. |
| `todo_id`          | 문자열            | 아니요       | 업데이트 전용입니다. 할 일의 전역 ID 또는 숫자 ID입니다. 작업 항목의 모든 할 일을 업데이트하려면 생략합니다. |
| `health_status`    | 문자열            | 아니요       | 상태입니다. `onTrack`, `needsAttention` 또는 `atRisk` 중 하나입니다. Ultimate만 해당입니다. |
| `weight`           | 정수           | 아니요       | 작업 항목의 가중치입니다. 0 이상이어야 합니다. Premium 및 Ultimate만 해당입니다. |
| `clear_weight`     | 부울           | 아니요       | 업데이트 전용입니다. 가중치를 제거합니다. `weight`보다 우선합니다. Premium 및 Ultimate만 해당입니다. |
| `status_id`        | 문자열            | 아니요       | 설정할 상태의 전역 ID입니다. Premium 및 Ultimate만 해당입니다. |
| `is_fixed`         | 부울           | 아니요       | 시작 및 기한 날짜가 고정되어 있는지 여부입니다. `false`인 경우 날짜는 하위 항목에서 롤업되고 `start_date` 및 `due_date`는 무시됩니다. Premium 및 Ultimate만 해당입니다. |
| `agent_plan`       | 문자열            | 아니요       | 에이전트 작업의 Markdown 내용입니다. Ultimate만 해당입니다. 작업 계획 기능이 필요합니다. |
| `readiness_score`  | 정수           | 아니요       | 에이전트 계획의 준비 점수, 0~100입니다. Ultimate만 해당입니다. `workplan_score` 기능 플래그이 필요합니다. 플래그가 비활성화되면 오류를 반환합니다. |

예:

```plaintext
Create a task "Update the onboarding guide" in project gitlab-org/gitlab and assign it to me
```

## `list_work_items` {#list_work_items}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/605850)되었습니다.

{{< /history >}}

그룹 또는 프로젝트에서 작업 항목(이슈, 인시던트, 테스트 케이스, 요구 사항, 작업, 티켓, 목표, 핵심 결과, 에픽)을 나열하거나 검색합니다. 그룹 범위에는 하위 프로젝트 및 하위 그룹의 작업 항목이 포함됩니다. 각 결과에는 ID, IID, 제목, 상태, 웹 URL, 전체 참조, 생성 및 업데이트된 타임스탐프, 작업 항목 유형만 포함되며 커서 페이지 매김을 포함합니다. 하나의 작업 항목을 깊이 있게 읽으려면 `get_work_item`을 사용합니다.

| 매개 변수               | 형식    | 필수 | 설명 |
|-------------------------|---------|----------|-------------|
| `url`                   | 문자열  | 아니요       | 프로젝트 또는 그룹의 GitLab URL입니다. `url`, `group_id`, `project_id` 중 정확히 하나를 제공합니다. |
| `group_id`              | 문자열  | 아니요       | 그룹의 ID 또는 경로입니다. `url` 및 `project_id`가 누락된 경우 필수입니다. |
| `project_id`            | 문자열  | 아니요       | 프로젝트의 ID 또는 경로입니다. `url` 및 `group_id`가 누락된 경우 필수입니다. |
| `state`                 | 문자열  | 아니요       | 상태별 필터링: `opened`, `closed` 또는 `all` (기본값). |
| `search`                | 문자열  | 아니요       | 제목 및 설명의 전체 텍스트 검색입니다. |
| `author_username`       | 문자열  | 아니요       | 작성자의 사용자 이름입니다. |
| `assignee_usernames`    | 배열   | 아니요       | 담당자의 사용자 이름입니다. 작업 항목은 모두 일치해야 합니다. 최대 100 값입니다. |
| `label_name`            | 배열   | 아니요       | 레이블 이름입니다. 작업 항목은 모두 가져야 합니다. 최대 100 값입니다. |
| `milestone_title`       | 배열   | 아니요       | 마일스톤 제목. `milestone_wildcard_id`과 함께 사용할 수 없습니다. 최대 100 값입니다. |
| `milestone_wildcard_id` | 문자열  | 아니요       | `NONE`, `ANY`, `STARTED`, 또는 `UPCOMING`. `milestone_title`과 함께 사용할 수 없습니다. |
| `types`                 | 배열   | 아니요       | 포함할 작업 항목 유형입니다. 예를 들어 `["ISSUE", "TASK"]`. |
| `created_after`         | 문자열  | 아니요       | 이 시간 이후에 생성되었습니다(ISO 8601; 날짜만 지정하면 하루의 시작을 의미하며 오프셋이 적용됩니다). |
| `created_before`        | 문자열  | 아니요       | 이 시간 이전에 생성되었습니다(ISO 8601; 날짜만 지정하면 하루의 시작을 의미하며 오프셋이 적용됩니다). |
| `updated_after`         | 문자열  | 아니요       | 이 시간 이후에 업데이트되었습니다(ISO 8601; 날짜만 지정하면 하루의 시작을 의미하며 오프셋이 적용됩니다). |
| `updated_before`        | 문자열  | 아니요       | 이 시간 이전에 업데이트되었습니다(ISO 8601; 날짜만 지정하면 하루의 시작을 의미하며 오프셋이 적용됩니다). |
| `due_after`             | 문자열  | 아니요       | 이 시간 이후 만료됩니다(ISO 8601; 날짜만 지정하면 하루의 시작을 의미하며 오프셋이 적용됩니다). |
| `due_before`            | 문자열  | 아니요       | 이 시간 이전 만료됩니다(ISO 8601; 날짜만 지정하면 하루의 시작을 의미하며 오프셋이 적용됩니다). |
| `sort`                  | 문자열  | 아니요       | 정렬 순서입니다. 예를 들어 `UPDATED_DESC`. 기본값은 `CREATED_DESC`입니다. |
| `first`                 | 정수 | 아니요       | 반환할 작업 항목 수입니다. 기본값 20, 최대 100. |
| `after`                 | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. |
| `health_status_filter`  | 문자열  | 아니요       | Ultimate만 해당합니다. `onTrack`, `needsAttention`, 또는 `atRisk`. |
| `status`                | 개체  | 아니요       | Ultimate만 해당입니다. 사용자 지정 상태 이름으로 필터링합니다. 예를 들어 `{"name": "In progress"}`. |

예:

```plaintext
List my open tasks in the gitlab-org group updated this month.
```

## `get_work_item_types` {#get_work_item_types}

{{< history >}}

- GitLab 19.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/237071)되었습니다.

{{< /history >}}

네임스페이스(그룹 또는 프로젝트)에서 사용 가능한 작업 항목 유형 목록을 반환합니다. 시스템 정의 유형(이슈, 에픽, 작업 등)과 사용자 지정 유형을 포함합니다. 반환되는 각 유형은 전역 ID, 이름, 아이콘 및 활성화된 위젯 유형을 포함하므로 유형이 지원하지 않는 필드를 설정하지 않을 수 있습니다.

| 매개 변수    | 형식   | 필수 | 설명 |
|--------------|--------|----------|-------------|
| `url`        | 문자열 | 아니요       | 네임스페이스(프로젝트 또는 그룹)의 GitLab URL. `group_id` 및 `project_id`가 누락된 경우 필수입니다. |
| `group_id`   | 문자열 | 아니요       | 그룹의 ID 또는 경로입니다. `url` 및 `project_id`가 누락된 경우 필수입니다. |
| `project_id` | 문자열 | 아니요       | 프로젝트의 ID 또는 경로입니다. `url` 및 `group_id`가 누락된 경우 필수입니다. |

예:

```plaintext
List the work item types available in the gitlab-org group
```

## `list_projects` {#list_projects}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250301)되었습니다.

{{< /history >}}

`group_id` 없이는 기본적으로 최소 게스트 역할이 있는 프로젝트를 나열합니다. `min_access_level`를 지정하여 임계값을 높입니다. `group_id`을 지정하면 해당 그룹과 그 하위 그룹의 모든 프로젝트를 나열합니다. 액세스 수준에 관계없이 `min_access_level` 또는 `visibility`를 추가하면 목록을 해당 그룹만으로 제한합니다. 하위 그룹이 아닙니다. GitLab은 그룹의 프로젝트를 나열할 때 하위 그룹 순회와 이러한 필터를 결합하는 것을 지원하지 않기 때문입니다.

| 매개 변수          | 형식    | 필수 | 설명 |
|--------------------|---------|----------|-------------|
| `group_id`         | 문자열  | 아니요       | 그룹의 ID 또는 전체 경로. 전체 인스턴스를 나열하려면 생략합니다. 기본적으로 최소 게스트 역할이 있는 프로젝트로 제한됩니다. |
| `min_access_level` | 문자열  | 아니요       | 포함할 프로젝트가 사용자에게 부여해야 하는 최소 액세스 수준입니다. `guest`, `planner`, `reporter`, `developer`, `maintainer` 또는 `owner` 중 하나입니다. |
| `search`           | 문자열  | 아니요       | 프로젝트를 이름, 경로 또는 설명으로 검색합니다. |
| `visibility`       | 문자열  | 아니요       | 표시 수준으로 필터링합니다: `public`, `internal`, 또는 `private`. |
| `archived`         | 문자열  | 아니요       | 보관된 상태로 필터링합니다: `only`, `include`, 또는 `exclude`(기본값). |
| `after`            | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. |
| `first`            | 정수 | 아니요       | 정방향 페이지 매김을 위해 반환할 프로젝트 수입니다. 기본값은 20이며 최대값은 100입니다. |

`group_id`을 제공하면 응답에 `subgroupsIncluded`이 포함됩니다: 목록이 그룹의 하위 그룹을 포함할 때 `true`, `min_access_level` 또는 `visibility`이 목록을 해당 그룹만으로 제한할 때 `false`.

예:

```plaintext
List my projects
```

## `list_groups` {#list_groups}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/607719)되었습니다.

{{< /history >}}

그룹 계층을 탐색하고 다른 도구와 함께 사용할 그룹 ID 및 전체 경로를 검색합니다. `group_id` 없이 이 도구는 사용자가 구성원인 최상위 그룹을 나열합니다. `group_id`를 지정하면 해당 그룹의 직접 하위 그룹을 나열합니다. 멤버십과 관계없이. `include_subgroups`을 `true`로 설정하여 모든 하위 그룹을 재귀적으로 나열합니다. `group_id` 없이는 모든 깊이에서 사용자의 그룹을 나열합니다. 보관된 그룹과 삭제 대기 중인 그룹은 제외됩니다.

| 매개 변수           | 형식    | 필수 | 설명 |
|---------------------|---------|----------|-------------|
| `group_id`         | 문자열  | 아니요       | 하위 그룹을 나열할 상위 그룹의 ID 또는 전체 경로. 사용자가 구성원인 최상위 그룹을 나열하려면 생략합니다. |
| `search`            | 문자열  | 아니요       | 그룹을 이름 또는 전체 경로로 검색합니다. |
| `visibility`        | 문자열  | 아니요       | 표시 수준으로 필터링합니다: `public`, `internal`, 또는 `private`. |
| `include_subgroups` | 부울 | 아니요       | 직접 하위 항목만이 아닌 모든 하위 그룹을 재귀적으로 포함합니다. |
| `after`             | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. |
| `first`             | 정수 | 아니요       | 정방향 페이지 매김을 위해 반환할 그룹 수입니다. 기본값은 20이며 최대값은 100입니다. |

예:

```plaintext
List the subgroups of gitlab-org
```

## `search` {#search}

{{< history >}}

- GitLab 18.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/566143)되었습니다.
- GitLab 18.6에서 그룹 및 프로젝트 검색과 결과 순서 지정 및 정렬이 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/571132)되었습니다.
- GitLab 18.8에서 `gitlab_search`에서 `search`로 [이름이 변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/214734)되었습니다.

{{< /history >}}

검색 API를 사용하여 전체 GitLab 인스턴스에서 용어를 검색합니다. 이 도구는 전역, 그룹 및 프로젝트 검색에 사용할 수 있습니다. 사용 가능한 범위는 [검색 유형](../search/_index.md)에 따라 다릅니다.

| 매개 변수      | 형식             | 필수 | 설명 |
|----------------|------------------|----------|-------------|
| `scope`        | 문자열           | 예      | 검색 범위(예: `work_items`, `merge_requests`, 또는 `projects`). |
| `search`       | 문자열           | 예      | 검색 용어입니다. |
| `group_id`     | 문자열           | 아니요       | 검색할 그룹의 ID 또는 전체 경로. |
| `project_id`   | 문자열           | 아니요       | 검색할 프로젝트의 ID 또는 전체 경로. |
| `state`        | 문자열           | 아니요       | 검색 결과의 상태입니다(`work_items` 및 `merge_requests`의 경우). |
| `confidential` | 부울          | 아니요       | 기밀성에 따라 결과를 필터링합니다(`work_items`의 경우). 기본값은 `false`입니다. |
| `fields`       | 문자열 배열 | 아니요       | 검색하려는 필드의 배열입니다(`work_items` 및 `merge_requests`의 경우). |
| `order_by`     | 문자열           | 아니요       | 결과를 정렬할 특성입니다. 기본값은 기본 검색의 경우 `created_at`, 고급 검색의 경우 관련성입니다. |
| `sort`         | 문자열           | 아니요       | 결과의 정렬 방향입니다. 기본값은 `desc`입니다. |
| `per_page`     | 정수          | 아니요       | 페이지당 결과 수입니다. 기본값은 `20`입니다. |
| `page`         | 정수          | 아니요       | 현재 페이지 번호입니다. 기본값은 `1`입니다. |

예:

```plaintext
Search issues for "flaky test" across GitLab
```

## `search_labels` {#search_labels}

{{< history >}}

- GitLab 18.9에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/218121)되었습니다.
- [GitLab 19.5에서 변경됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/621662)으로 여러 검색 용어를 허용합니다.

{{< /history >}}

GitLab 프로젝트 또는 그룹에서 레이블을 검색합니다.

| 매개 변수    | 형식                        | 필수 | 설명 |
|--------------|-----------------------------|----------|-------------|
| `full_path`  | 문자열                      | 예      | 프로젝트 또는 그룹의 전체 경로입니다(예: `group/project`). |
| `is_project` | 부울                     | 예      | 프로젝트(`true`) 또는 그룹(`false`)에서 검색할지 여부입니다. |
| `search`     | 문자열 또는 문자열 배열  | 아니요       | 제목별로 레이블을 필터링하기 위한 한 개 용어 또는 최대 10개 용어의 배열입니다. 생략하면 대신 레이블을 나열합니다. 빈 배열은 유효하지 않습니다. |

그룹 레이블을 검색할 때 결과에는 상위 그룹 및 하위 그룹의 레이블이 포함됩니다. 여러 용어의 결과는 중복 레이블 없이 하나의 목록을 형성합니다.

예:

```plaintext
Show me all labels in project gitlab-org/gitlab
```

## `list_wiki_pages` {#list_wiki_pages}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/240973)되었습니다.

{{< /history >}}

GitLab 프로젝트 또는 그룹의 wiki 페이지를 나열합니다.

| 매개 변수    | 형식    | 필수 | 설명 |
|--------------|---------|----------|-------------|
| `project_id` | 문자열  | 아니요       | 프로젝트의 전체 경로 또는 숫자 ID(예: `gitlab-org/gitlab` 또는 `278964`)입니다. |
| `group_id`   | 문자열  | 아니요       | 그룹의 전체 경로 또는 숫자 ID(예: `gitlab-org` 또는 `9970`)입니다. |
| `first`      | 정수 | 아니요       | 포워드 페이지 로드에 대해 반환할 위키 페이지 수(최대 100)입니다. |
| `after`      | 문자열  | 아니요       | 포워드 페이지 로드에 대한 커서입니다. |

`project_id` 또는 `group_id` 중 하나만 제공합니다. 각 호출은 결과의 단일 페이지를 반환합니다. 더 많은 페이지가 있으면 응답에 `end_cursor`이 포함되며 `after`로 전달하여 다음 페이지를 가져올 수 있습니다.

예:

```plaintext
List the wiki pages in gitlab-org/gitlab
```

## `semantic_search` {#semantic_search}

{{< details >}}

- 추가 기능: GitLab Duo Core, Pro 또는 Enterprise
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- GitLab 18.5에서 `code_snippet_search_graphqlapi` [기능 플래그](../../administration/feature_flags/_index.md)의 [실험적 기능](../../policy/development_stages_support.md#experiment)으로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/569624)되었습니다. 기본적으로 비활성화되었습니다.
- 프로젝트 경로로 검색이 GitLab 18.6에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/575234)되었습니다.
- GitLab 18.7에서 실험적 기능에서 [베타](../../policy/development_stages_support.md#beta)로 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/568359)되었습니다. `code_snippet_search_graphqlapi` 기능 플래그가 제거되었습니다.
- GitLab 18.7에서 GitLab UI에 `mcp_client` [기능 플래그](../../administration/feature_flags/_index.md)로 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/581105)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.11에서 [REST API](../../api/search.md#semantic-search)를 사용하도록 [업데이트](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228569)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)는 `mcp_semantic_code_search_use_rest_api`입니다. 기본적으로 비활성화되었습니다.
- GitLab 19.1에서 REST API 사용이 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/239364)하게 되었습니다. `mcp_semantic_code_search_use_rest_api` 기능 플래그가 제거되었습니다.
- GitLab 19.4에서 `semantic_code_search`에서 [이름이 변경됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/606755). `semantic_code_search`은 별칭으로 계속 작동합니다.
- `scope` 매개변수는 [GitLab 19.4에서 추가됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/606755).
- `semantic_query` 매개변수는 GitLab 19.4에서 `q`으로 [이름이 변경됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/606755).

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

키워드보다는 의미로 GitLab 프로젝트의 관련 내용을 검색합니다. 정확한 기호나 파일 이름을 모르거나 코드베이스에서 동작이 구현되는 방식을 발견하려는 경우 이 도구를 사용하세요. 설정 및 사용으로 설정을 포함한 자세한 정보는 [의미론적 코드 검색](../gitlab_duo/semantic_code_search.md)을 참조하세요.

| 매개 변수        | 형식    | 필수 | 설명 |
|------------------|---------|----------|-------------|
| `scope`          | 문자열  | 예      | 검색할 콘텐츠의 유형입니다. `code`만 지원됩니다. |
| `q`              | 문자열  | 예      | 자연언어 검색 쿼리. |
| `project_id`     | 문자열  | 예      | 프로젝트의 ID 또는 전체 경로입니다. |
| `directory_path` | 문자열  | 아니요       | 검색을 이 디렉토리 경로 아래의 파일로 제한합니다. 예를 들어 `app/services/`. 상대 경로여야 하며 선행 슬래시나 `..` 세그먼트가 없어야 합니다. `scope`가 `code`인 경우에만 적용됩니다. |
| `knn`            | 정수 | 아니요       | 내부적으로 검색된 최근접 이웃의 수입니다. 기본값은 `64`, 최대값은 `100`입니다. 값이 높을수록 지연 시간을 희생하면서 재현율이 향상됩니다. `scope`가 `code`인 경우에만 적용됩니다. |
| `limit`          | 정수 | 아니요       | 반환할 최대 결과 수입니다. 기본값은 `20`, 최대값은 `100`입니다. `scope`가 `code`인 경우에만 적용됩니다. |

결과는 파일별로 그룹화됩니다. 각 파일에는 병합된 줄 범위와 내용 및 관련성 점수가 포함됩니다. 최선의 결과를 위해 일반적인 키워드나 특정 함수 또는 변수 이름을 사용하는 것보다 관심 있는 기능이나 동작을 설명합니다.

예:

```plaintext
How are authorizations managed in this project?
```

## `attach_scan_profile` {#attach_scan_profile}

{{< details >}}

- 티어:  Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/240685)되었습니다.

{{< /history >}}

지정된 보안 검사 프로필을 지정된 프로젝트에 또는 지정된 그룹 아래의 모든 프로젝트에 연결합니다.

이 도구는 라이선스 기능을 사용할 수 있을 때만 나열됩니다. 자세한 내용은 [도구 그룹 선택](mcp_server.md#select-tool-groups-toolsets)을 참조하세요.

| 매개 변수                  | 형식             | 필수 | 설명 |
|----------------------------|------------------|----------|-------------|
| `security_scan_profile_id` | 문자열           | 예      | 보안 검사 프로필의 전역 ID입니다(예: `gid://gitlab/Security::ScanProfile/1`). |
| `project_ids`              | 문자열 배열 | 아니요       | 프로젝트의 전역 ID의 배열입니다(예: `[gid://gitlab/Project/1]`). `group_ids`가 제공되지 않으면 필수입니다. |
| `group_ids`                | 문자열 배열 | 아니요       | 그룹의 전역 ID의 배열입니다(예: `[gid://gitlab/Group/1]`). `project_ids`가 제공되지 않으면 필수입니다. |

예:

```plaintext
Attach `gid://gitlab/Security::ScanProfile/1` to all projects under `gid://gitlab/Group/1`.
```
