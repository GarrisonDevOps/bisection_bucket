---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab Duo Agent Platform 플로우를 생성하고 시작하며 관리하는 REST API입니다.
title: 플로우 API
---

{{< details >}}

- 티어:  Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 API를 사용하여 [플로우](../user/duo_agent_platform/flows/_index.md)를 [GitLab Duo Agent Platform](../user/duo_agent_platform/_index.md)에서 생성하고 관리합니다. 플로우는 버그 수정, 코드 작성 또는 취약점 해결과 같은 개발자 작업을 완료하기 위해 함께 작동하는 AI 에이전트의 조합입니다.

## 플로우 트리거 {#trigger-a-flow}

{{< history >}}

- `start_workflow`이(가) `true`일 때 복합 ID 서비스 계정 요구사항이 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/601901)되었으며, `enforce_composite_identity_for_api_started_workflows`(이)라는 [기능 플래그](../administration/feature_flags/_index.md)를 사용합니다. 기본적으로 비활성화되었습니다.
- `callback_hook_id`과(와) `client_reference` 속성이 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249147)되었으며, `duo_flow_callback_hooks`(이)라는 [기능 플래그](../administration/feature_flags/_index.md)를 사용합니다. 기본적으로 비활성화되었습니다.
- GitLab 19.5에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258242)되었습니다.

{{< /history >}}

> [!flag]
> 복합 ID 서비스 계정에 대한 요구사항은 기능 플래그에 의해 제어됩니다. `callback_hook_id`과(와) `client_reference` 속성의 가용성은 별도의 기능 플래그에 의해 제어됩니다. 자세한 내용은 기록을 참조하세요.

새 플로우를 트리거하고 시작합니다.

전제 조건:

- `enforce_composite_identity_for_api_started_workflows` 기능 플래그가 활성화되고 `start_workflow`이(가) `true`이면, 플로우는 [복합 ID](../user/duo_agent_platform/composite_identity.md) 서비스 계정이 있어야 합니다. 서비스 계정은 AI 카탈로그의 플로우에 대해 구성되거나, 요청의 복합 ID 뒤에 있는 서비스 계정입니다. 그렇지 않으면 GitLab이 `403 Forbidden`를 반환하고 플로우를 시작하지 않습니다.

```plaintext
POST /ai/duo_workflows/workflows
```

지원되는 속성:

| 속성 | 유형 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `additional_context` | 객체 배열 | 아니요 | 플로우에 대한 추가 컨텍스트입니다. 각 요소는 최소한 `Category`(문자열) 및 `Content`(문자열, 직렬화된 JSON) 키를 포함하는 객체여야 합니다. |
| `agent_privileges` | 정수 배열 | 아니요 | 에이전트가 사용할 수 있는 권한 ID입니다. 모든 권한으로 기본 설정됩니다. [모든 에이전트 권한 나열](#list-all-agent-privileges)을 참조하세요. |
| `ai_catalog_item_consumer_id` | 정수 | 아니요 | 실행할 카탈로그 항목을 구성하는 AI 카탈로그 항목 소비자의 ID입니다. `project_id`을(를) 필요로 합니다. `workflow_definition`과 함께 사용할 수 없습니다. 둘 다 제공되는 경우 `ai_catalog_item_consumer_id`이 우선합니다. [소비자 ID 조회](#look-up-the-consumer-id)를 참조하세요. |
| `ai_catalog_item_version_id` | 정수 | 아니요 | 플로우 구성의 출처인 AI 카탈로그 항목 버전의 ID입니다. |
| `allow_agent_to_request_user` | 부울 | 아니요 | `true`(기본값)일 때 에이전트가 진행하기 전에 사용자에게 질문을 할 수 있습니다. `false`일 때 에이전트는 사용자 입력 없이 완료까지 실행됩니다. |
| `callback_hook_id` | 정수 | 아니요 | [GitLab Duo 플로우 웹후크 콜백](../user/duo_agent_platform/flows/webhook_callbacks.md)이 활성화된 웹후크의 ID입니다. GitLab이 해당 웹후크에 플로우 수명 주기 이벤트를 보내므로 플로우 상태를 폴링할 필요가 없습니다. 웹후크는 플로우가 실행되는 프로젝트 또는 네임스페이스, 또는 상위 그룹 중 하나에 속해야 합니다. 이 속성은 [실험](../policy/development_stages_support.md)입니다. |
| `client_reference` | 문자열 | 아니요 | 모든 콜백 페이로드에 에코되는 불투명한 문자열로, 콜백을 플로우를 트리거한 요청과 연결합니다. 최대 255자입니다. `callback_hook_id` 없이는 효과가 없습니다. 이 속성은 [실험](../policy/development_stages_support.md)입니다. |
| `environment` | 문자열 | 아니요 | 실행 환경입니다. 다음 중 하나입니다: `ide`, `web`, `chat_partial`, `chat`, `ambient`. |
| `goal` | 문자열 | 아니요 | 에이전트가 완료해야 할 작업에 대한 설명입니다. 예: `Fix the failing pipeline`. |
| `image` | 문자열 | 아니요 | 플로우에 사용할 컨테이너 이미지입니다. 플로우가 CI 파이프라인에서 실행될 때만 적용됩니다. [사용자 지정 이미지 요구사항](../user/duo_agent_platform/flows/execution/images.md#use-a-custom-image)을 충족해야 합니다. 예: `registry.gitlab.com/gitlab-org/duo-workflow/custom-image:latest`. |
| `issue_id` | 정수 | 아니요 | 플로우와 연결할 이슈의 IID입니다. `project_id`을(를) 필요로 합니다. |
| `merge_request_id` | 정수 | 아니요 | 플로우와 연결할 머지 리퀘스트의 IID입니다. `project_id`을(를) 필요로 합니다. |
| `namespace_id` | 문자열 | 아니요 | 플로우와 연결할 네임스페이스의 ID 또는 경로입니다. |
| `pre_approved_agent_privileges` | 정수 배열 | 아니요 | 사용자 승인을 요청하지 않고 에이전트가 사용할 수 있는 권한 ID입니다. `agent_privileges`의 부분 집합이어야 합니다. |
| `project_id` | 문자열 | 아니요 | 플로우와 연결할 프로젝트의 ID 또는 경로입니다. |
| `source` | 문자열 | 아니요 | 세션이 트리거된 위치입니다. GitLab 기능 진입점 중 하나(예: `merge_request_code_conflict`) 또는 세션을 만든 클라이언트 표면(`duo_cli_interactive`, `duo_cli_run`, `duo_cli_acp`, `ide_extension`)입니다. 세션의 `source_type`로 유지됩니다. |
| `source_branch` | 문자열 | 아니요 | 플로우의 소스 브랜치입니다. 플로우가 CI 파이프라인에서 실행될 때만 적용됩니다. 지정하지 않으면, 목표가 파이프라인 또는 머지 리퀘스트(예: `fix_pipeline/v1` 또는 `code_review/v1`)인 플로우는 해당 파이프라인 또는 머지 리퀘스트의 브랜치에서 실행됩니다. `fix_pipeline/v1`의 경우, `merge_request` 및 `pipeline` 항목도 `additional_context`에서 파이프라인으로부터 입력됩니다. 다른 플로우는 프로젝트의 기본 브랜치에서 실행됩니다. |
| `start_workflow` | 부울 | 아니요 | `true`일 때 생성 후 즉시 플로우를 시작합니다. |
| `workflow_definition` | 문자열 | 아니요 | 플로우 유형 식별자입니다. 예: `developer/v1`. `ai_catalog_item_consumer_id`과 함께 사용할 수 없습니다. 둘 다 제공되는 경우 `ai_catalog_item_consumer_id`이 우선합니다. |

성공하면 [`201 Created`](rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다:

| 속성 | 유형 | 설명 |
|-----------|------|-------------|
| `agent_privileges` | 정수 배열 | 에이전트에 할당된 권한 ID입니다. |
| `agent_privileges_names` | 문자열 배열 | `agent_privileges`에 해당하는 이름입니다. |
| `ai_catalog_item_version_id` | 정수 | AI 카탈로그 항목 버전의 ID입니다. 설정되지 않으면 `null`입니다. |
| `allow_agent_to_request_user` | 부울 | `true`일 때 에이전트가 사용자 입력을 위해 일시 중지할 수 있습니다. |
| `environment` | 문자열 | 실행 환경입니다. 설정되지 않으면 `null`입니다. |
| `gitlab_url` | 문자열 | GitLab 인스턴스의 기본 URL입니다. |
| `id` | 정수 | 플로우의 ID입니다. |
| `image` | 문자열 | CI 파이프라인 실행을 위한 컨테이너 이미지입니다. 설정되지 않으면 `null`입니다. |
| `mcp_enabled` | 부울 | `MCP` (Model Context Protocol) 도구가 이 플로우에 대해 활성화되어 있는지 여부입니다. |
| `namespace_id` | 정수 | 연결된 네임스페이스의 ID입니다. 설정되지 않으면 `null`입니다. |
| `pre_approved_agent_privileges` | 정수 배열 | 승인을 요청하지 않고 에이전트가 사용할 수 있는 권한 ID입니다. |
| `pre_approved_agent_privileges_names` | 문자열 배열 | `pre_approved_agent_privileges`에 해당하는 이름입니다. |
| `project_id` | 정수 | 연결된 프로젝트의 ID입니다. 설정되지 않으면 `null`입니다. |
| `status` | 문자열 | 현재 플로우 상태입니다. 다음 중 하나입니다: `created`, `running`, `paused`, `finished`, `failed`, `stopped`, `input_required`, `plan_approval_required`, 또는 `tool_call_approval_required`. GitLab이 새로운 값을 추가할 수 있습니다. |
| `summary` | 문자열 | workflow의 간단한 텍스트 요약입니다. |
| `title` | 문자열 | 세션의 제목입니다. |
| `web_url` | 문자열 | GitLab UI의 세션 URL입니다. 세션이 프로젝트용이 아니면 `null`입니다. |
| `workflow_definition` | 문자열 | 플로우 유형 식별자입니다. |
| `workload` | 객체 | 워크로드에 대한 정보입니다. |
| `workload.id` | 정수 | 워크로드의 ID입니다. 예를 들어 `start_workflow`이(가) `true`이 아닐 때 워크로드가 만들어지지 않으면 `null`입니다. |
| `workload.message` | 문자열 | 워크로드의 상태 메시지입니다. 워크로드가 만들어지지 않으면 `null`입니다. |

사용자가 GitLab Duo Agent Platform을 사용하기 전에 [ID 확인](../security/identity_verification.md)을 완료해야 하면, GitLab이 [`403 Forbidden`](rest/troubleshooting.md#status-codes)를 반환하고 `message`를 포함합니다:

```json
{
  "message": "403 Forbidden - Identity verification is required to use GitLab Duo Agent Platform"
}
```

`callback_hook_id`이(가) 설정되어 있고 다음 중 하나가 참이면 GitLab이 [`400 Bad request`](rest/troubleshooting.md#status-codes)를 반환합니다:

- `duo_flow_callback_hooks` 기능 플래그가 플로우가 실행되는 프로젝트 또는 네임스페이스의 최상위 그룹에 대해 활성화되지 않았습니다.
- ID가 플로우가 실행되는 프로젝트 또는 네임스페이스의 GitLab Duo 플로우 콜백이 활성화된 웹후크나, 상위 그룹 중 하나를 참조하지 않습니다.

### 소비자 ID 조회 {#look-up-the-consumer-id}

`ai_catalog_item_consumer_id`을 사용하기 전에 GraphQL API를 사용하여 [AI 카탈로그](../user/duo_agent_platform/ai_catalog.md)에서 ID를 검색해야 합니다. 항목이 프로젝트에 대해 이미 활성화되어 있어야 합니다.

```graphql
query {
  aiCatalogConfiguredItems(projectId: "gid://gitlab/Project/<project_id>") {
    nodes {
      id
      item { name }
    }
  }
}
```

`id` 필드는 `gid://gitlab/AiCatalogItemConsumer/<numeric_id>` 형식의 전역 ID입니다. 숫자 접미사를 `ai_catalog_item_consumer_id` 값으로 사용합니다.

기본 제공 플로우 유형을 사용한 예 요청:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --header "Content-Type: application/json" \
  --data '{
    "project_id": "5",
    "goal": "Fix the failing pipeline by correcting the syntax error in .gitlab-ci.yml",
    "workflow_definition": "developer/v1",
    "start_workflow": true
  }' \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows"
```

카탈로그로 구성된 플로우를 사용한 예 요청:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --header "Content-Type: application/json" \
  --data '{
    "project_id": "5",
    "goal": "Fix the failing pipeline by correcting the syntax error in .gitlab-ci.yml",
    "ai_catalog_item_consumer_id": 12,
    "start_workflow": true
  }' \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows"
```

응답 예시:

```json
{
  "id": 1,
  "web_url": "https://gitlab.example.com/group/project/-/automate/agent-sessions/1",
  "project_id": 5,
  "namespace_id": null,
  "agent_privileges": [1, 2, 3, 4, 5, 6],
  "agent_privileges_names": [
    "read_write_files",
    "read_only_gitlab",
    "read_write_gitlab",
    "run_commands",
    "use_git",
    "run_mcp_tools"
  ],
  "pre_approved_agent_privileges": [],
  "pre_approved_agent_privileges_names": [],
  "workflow_definition": "developer/v1",
  "status": "running",
  "allow_agent_to_request_user": true,
  "image": null,
  "environment": null,
  "ai_catalog_item_version_id": null,
  "workload": {
    "id": "abc-123",
    "message": "Workflow started"
  },
  "mcp_enabled": false,
  "gitlab_url": "https://gitlab.example.com"
}
```

## 플로우 재시작 {#restart-a-flow}

{{< details >}}

- 상태:  실험적 기능

{{< /details >}}

같은 플로우 매개변수로 새 플로우를 시작하여 실패하거나 중지된 플로우를 재시작합니다. 새 플로우는 처음부터 실행됩니다. 원본 플로우는 수정되지 않으며 `failed` 또는 `stopped` 상태를 유지합니다.

`failed` 또는 `stopped` 상태인 프로젝트 수준 플로우만 재시작할 수 있습니다. 다른 상태의 플로우나 그룹 수준 플로우를 재시작하면 `403 Forbidden`를 반환합니다. 재시작이 진행 중인 동안 같은 플로우를 다시 재시작하면 `409 Conflict`를 반환합니다.

```plaintext
POST /ai/duo_workflows/workflows/:workflow_id/restart
```

지원되는 속성:

| 속성 | 유형 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `workflow_id` | 정수 | 예 | 재시작할 플로우의 ID입니다. |

성공하면 [`201 Created`](rest/troubleshooting.md#status-codes)를 반환하고 [플로우 트리거](#trigger-a-flow)와 같은 응답 속성을 반환합니다. 응답은 새 플로우를 설명하므로 `id`는 재시작한 플로우의 ID가 아니라 새 플로우의 ID입니다.

요청 예시:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows/42/restart"
```

## 워크플로우 추적을 JSONL로 가져오기 {#get-workflow-trace-as-jsonl}

{{< details >}}

- 상태:  실험적 기능

{{< /details >}}

워크플로우 세션의 `ui_chat_log` 항목을 [JSON Lines](https://jsonlines.org/) (JSONL)로 반환합니다. 각 줄은 `ui_chat_log` 배열의 한 항목을 나타내는 유효한 JSON 개체입니다. 이 엔드포인트를 사용하여 추적을 `jq`과(와) 같은 도구로 구문 분석하거나 파이프합니다.

기본적으로 엔드포인트는 세션의 모든 스레드 전체의 전체 대화와 컨텍스트 압축 전의 메시지를 반환합니다. `thread` 속성을 사용하여 단일 스레드만 반환합니다.

```plaintext
GET /ai/duo_workflows/workflows/:workflow_id/trace.jsonl
```

지원되는 속성:

| 속성 | 유형 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `workflow_id` | 정수 | 예 | 워크플로우의 ID입니다. |
| `thread` | 문자열 | 아니요 | 반환할 스레드입니다. 모든 스레드 전체의 전체 추적은 생략합니다. `latest`을(를) 사용하여 가장 최근 스레드만 반환하거나, 특정 스레드의 경우 스레드 ID를 사용합니다. |

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes)를 반환합니다:

- **Content-Type**: `application/x-ndjson`
- **본문**: 각 줄에 하나의 JSON 개체가 있으며, 각각은 `ui_chat_log` 항목을 나타냅니다. 워크플로우에 체크포인트나 `ui_chat_log` 항목이 없으면 빈 본문을 반환합니다.

사용자가 GitLab Duo Agent Platform을 사용하기 전에 [ID 확인](../security/identity_verification.md)을 완료해야 하면, GitLab이 [`403 Forbidden`](rest/troubleshooting.md#status-codes)를 반환하고 `message`를 포함합니다:

```json
{
  "message": "403 Forbidden - Identity verification is required to use GitLab Duo Agent Platform"
}
```

요청 예시:

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows/1/trace.jsonl"
```

예제 응답(각 줄은 별개의 JSON 개체):

```jsonl
{"status":"success","content":"Analyze the issue","message_type":"human"}
{"status":"success","content":"I'll start by reading the codebase.","message_type":"ai"}
```

출력을 `jq`로 파이프하여 유형별로 항목을 필터링할 수 있습니다:

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows/1/trace.jsonl" \
  | jq 'select(.message_type == "ai")'
```

## 모든 에이전트 권한 나열 {#list-all-agent-privileges}

모든 사용 가능한 에이전트 권한을 ID, 이름, 설명 및 각 권한이 기본적으로 활성화되어 있는지 여부를 나열합니다.

```plaintext
GET /ai/duo_workflows/workflows/agent_privileges
```

이 엔드포인트는 지원되는 특성이 없습니다.

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다:

| 속성 | 유형 | 설명 |
|-----------|------|-------------|
| `all_privileges` | 객체 배열 | 사용 가능한 모든 에이전트 권한입니다. |
| `all_privileges[].default_enabled` | 부울 | 권한이 기본적으로 활성화되어 있는지 여부입니다. |
| `all_privileges[].description` | 문자열 | 권한이 허용하는 작업에 대한 사람이 읽을 수 있는 설명입니다. |
| `all_privileges[].id` | 정수 | 권한 ID입니다. |
| `all_privileges[].name` | 문자열 | 기계가 읽을 수 있는 권한 이름입니다. |

요청 예시:

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows/agent_privileges"
```

응답 예시:

```json
{
  "all_privileges": [
    {
      "id": 1,
      "name": "read_write_files",
      "description": "Allow local filesystem read/write access",
      "default_enabled": true
    },
    {
      "id": 2,
      "name": "read_only_gitlab",
      "description": "Allow read only access to GitLab APIs",
      "default_enabled": true
    },
    {
      "id": 3,
      "name": "read_write_gitlab",
      "description": "Allow write access to GitLab APIs",
      "default_enabled": true
    },
    {
      "id": 4,
      "name": "run_commands",
      "description": "Allow running any commands",
      "default_enabled": true
    },
    {
      "id": 5,
      "name": "use_git",
      "description": "Allow git commits, push and other git commands",
      "default_enabled": true
    },
    {
      "id": 6,
      "name": "run_mcp_tools",
      "description": "Allow running MCP tools",
      "default_enabled": true
    }
  ]
}
```
