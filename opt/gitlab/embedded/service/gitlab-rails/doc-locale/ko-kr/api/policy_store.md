---
stage: Security Risk Management
group: Security Policies
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 조직 및 그룹의 정책 저장소에 저장된 보안 정책을 관리하는 REST API입니다.
title: 정책 저장소 API
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태: 실험

{{< /details >}}

{{< history >}}

- GitLab 19.3에서 `security_policies_v2`이라는 [기능 플래그](../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/606971)되었습니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../policy/development_stages_support.md)입니다.
- 카탈로그 끝점:
  - [GitLab 19.4에서 인증이 필요하도록 변경되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/work_items/598030)
  - `environment_advanced`과 `deployment_promoted` 트리거는 GitLab 19.4에 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252841)
  - `set_setting` 작업은 GitLab 19.6에 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/work_items/630210)
  - `project.before_settings_update`, `project.after_create`, 및 `project.after_transfer` 트리거와 `[].kind` 트리거 속성은 GitLab 19.6에 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/work_items/634898)
- 정책 끝점:
  - [GitLab 19.4에서 정책을 데이터베이스에 유지하도록 변경되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/work_items/604367)
  - `policy_rego` 응답 속성은 GitLab 19.4에 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/work_items/616505)
  - `scope_dimensions` 응답 속성은 GitLab 19.4에 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/work_items/623359)
- `lifecycle_state` 필터는 GitLab 19.4에 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253089)
- 정책 끝점 만들기 및 업데이트:
  - `rules` 및 `actions`의 제한 사항은 GitLab 19.4에 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/work_items/612905)
  - Rego 유효성 검사는 GitLab 19.5에 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/work_items/618556)
- 그룹 끝점은 GitLab 19.5에 [도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254842)

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트용으로 사용 가능하지만 프로덕션 사용을 위한 준비가 되어 있지 않습니다.

이 API를 사용하여 정책 저장소에서 [보안 정책](../user/application_security/policies/_index.md)을 작성합니다. 정책은 조직에 속하며, 단일 트리거에 응답하고, 동작을 구성하는 규칙 및 작업을 전달합니다.

이 끝점은 다음이 모두 참인 경우에만 사용 가능합니다:

- `security_policies_v2` 기능 플래그가 활성화되어 있습니다.
- 관리자가 **운영자** > **설정** > **보안 및 규정 준수**에서 인스턴스에 대한 정책 저장소 실험을 활성화했습니다.
- 조직 끝점의 경우 조직이 옵트인했습니다.
- 그룹 끝점의 경우 최상위 그룹이 옵트인했습니다.

기능 플래그, 인스턴스 설정 또는 조직 옵트인이 참이 아닐 때 끝점은 `404 Not Found`을 반환합니다. 인스턴스가 보안 오케스트레이션 정책에 대해 라이센스되지 않았거나 그룹이 옵트인하지 않은 경우 `403 Forbidden`을 반환합니다.

## 카탈로그 {#catalogs}

카탈로그 끝점은 정책을 구축할 수 있는 항목을 설명하고 적격 호출자에게 동일한 정적 콘텐츠를 반환합니다. 호출자는 `security_policies_v2` 기능 플래그가 활성화된 조직의 인증된 사용자여야 합니다. 이것이 참이 아닐 때 끝점은 `404 Not Found`을 반환합니다.

### 모든 트리거 나열 {#list-all-triggers}

정책이 응답할 수 있는 모든 트리거를 나열합니다.

```plaintext
GET /security/policy_store/triggers
```

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성 | 형식   | 설명 |
| --------- | ------ | ----------- |
| `[].id`   | 문자열 | 정책을 작성할 때 `trigger_type`로 사용되는 트리거의 ID입니다. |
| `[].name` | 문자열 | 트리거의 표시 이름입니다. |
| `[].kind` | 문자열 | `gate` 또는 `event`. `gate` 트리거는 변경 전에 평가되며 이를 중단할 수 있습니다. `event` 트리거는 변경 후에 평가되며 중단할 수 없습니다. |

요청 예:

```shell
curl --request GET --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/security/policy_store/triggers"
```

응답 예:

```json
[
  { "id": "deployment_requested", "name": "Deployment requested", "kind": "gate" },
  { "id": "environment_advanced", "name": "Environment advanced", "kind": "gate" },
  { "id": "deployment_promoted", "name": "Deployment promoted", "kind": "gate" },
  { "id": "project.before_settings_update", "name": "Project settings change requested", "kind": "gate" },
  { "id": "project.after_create", "name": "Project created", "kind": "event" },
  { "id": "project.after_transfer", "name": "Project transferred", "kind": "event" }
]
```

### 모든 작업 나열 {#list-all-actions}

정책이 수행할 수 있는 모든 작업을 나열합니다.

```plaintext
GET /security/policy_store/actions
```

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성 | 형식   | 설명 |
| --------- | ------ | ----------- |
| `[].id`   | 문자열 | 작업의 ID입니다. |
| `[].name` | 문자열 | 작업의 표시 이름입니다. |

요청 예:

```shell
curl --request GET --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/security/policy_store/actions"
```

응답 예:

```json
[
  { "id": "block", "name": "Block" },
  { "id": "require_approval", "name": "Require approval" },
  { "id": "set_setting", "name": "Set project setting" },
  { "id": "log_audit_trail", "name": "Log audit trail" }
]
```

### 모든 규칙 종류 나열 {#list-all-rule-kinds}

정책을 구축할 수 있는 모든 규칙 종류를 나열합니다.

```plaintext
GET /security/policy_store/rules
```

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성 | 형식   | 설명 |
| --------- | ------ | ----------- |
| `[].id`   | 문자열 | 규칙 종류의 ID입니다. |
| `[].name` | 문자열 | 규칙 종류의 표시 이름입니다. |

요청 예:

```shell
curl --request GET --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/security/policy_store/rules"
```

응답 예:

```json
[
  { "id": "custom", "name": "Custom" },
  { "id": "calendar", "name": "Calendar" },
  { "id": "environment", "name": "Environment" },
  { "id": "setting_validation", "name": "Project setting validation" }
]
```

## 정책 속성 {#policy-attributes}

조직 및 그룹 정책 끝점은 동일한 정책 범위, 규칙, 작업 및 응답 속성을 사용합니다.

### 정책 범위 속성 {#policy-scope-attributes}

`policy_scope`은 하나 이상의 기준을 보유하며, `match_mode`는 이들을 결합하는 방법을 제어합니다. 기준은 정수 또는 `id` 키를 가진 객체로 ID의 이름을 지정합니다. GitLab은 ID를 중복 제거하고 정렬하므로 작성 순서가 컴파일된 프로그램을 변경하지 않습니다.

| 속성 | 형식 | 설명 |
| --------- | ---- | ----------- |
| `application` | 개체 | 애플리케이션 보안 속성 ID의 `including` 및 `excluding` 목록입니다. |
| `business_impact` | 개체 | 비즈니스 영향 보안 속성 ID의 `including` 및 `excluding` 목록입니다. |
| `business_unit` | 개체 | 비즈니스 단위 보안 속성 ID의 `including` 및 `excluding` 목록입니다. |
| `compliance_frameworks` | 배열 | 프로젝트가 보유해야 하는 규정 준수 프레임워크의 ID입니다. `including` 및 `excluding` 대신 직접 목록을 사용합니다. |
| `exposure` | 개체 | 노출 보안 속성 ID의 `including` 및 `excluding` 목록입니다. |
| `groups` | 개체 | 그룹 ID의 `including` 및 `excluding` 목록입니다. |
| `match_mode` | 문자열 | `all` 또는 `any`. `all`인 경우 모든 기준이 일치해야 합니다. `any`인 경우 하나의 일치로 충분합니다. 다른 모든 값은 `all`로 처리됩니다. |
| `projects` | 개체 | 프로젝트 ID의 `including` 및 `excluding` 목록입니다. `excluding`은 또한 `{"type": "personal"}` 및 `{"type": "archived"}`을 수락하며, 이는 해당 종류의 모든 프로젝트를 제외합니다. |

예를 들어:

```json
{
  "match_mode": "any",
  "compliance_frameworks": [{ "id": 5 }],
  "projects": { "including": [12, 34], "excluding": [{ "type": "archived" }] },
  "groups": { "including": [{ "id": 7 }] }
}
```

GitLab이 ID로 읽을 수 없는 값은 `400 Bad Request`을 반환합니다. 이는 숫자가 아닌 값과 1에서 9223372036854775807 범위를 벗어난 숫자를 포함합니다.

수락되는 세 가지 경우가 있으며 각각 예상과 다르게 정책의 범위를 지정하므로 주목할 가치가 있습니다:

- ID의 이름을 지정하지 않는 `including` 목록은 해당 기준에 대해 아무것도 일치하지 않습니다. `match_mode: all` 아래에서 정책은 어떤 프로젝트에도 적용되지 않습니다. `match_mode: any` 아래에서 다른 기준이 여전히 일치할 수 있습니다.
- ID의 이름을 지정하지 않는 `excluding` 목록은 아무것도 제외하지 않습니다.
- GitLab이 인식하지 못하는 기준은 효과가 없습니다. 제공된 유일한 기준인 경우 정책은 모든 프로젝트에 적용됩니다.

### 규칙 및 작업 속성 {#rule-and-action-attributes}

`rules` 및 `actions`는 배열입니다. 각 항목에는 다음 속성이 있습니다:

| 속성 | 형식           | 필수 | 설명 |
| --------- | -------------- | -------- | ----------- |
| `type`    | 문자열         | 예      | 규칙의 경우 [모든 규칙 종류 나열](#list-all-rule-kinds)에서 반환되는 ID 중 하나입니다. 작업의 경우 [모든 작업 나열](#list-all-actions)에서 반환되는 ID 중 하나입니다. |
| `value`   | 문자열 또는 해시 | 아니요       | 항목이 작용하는 대상입니다. `custom` 규칙은 Rego 소스를 문자열로 사용합니다. 다른 모든 규칙은 해시를 사용하며, 모든 작업도 마찬가지입니다. `setting_validation` 규칙은 평가 컨텍스트가 명명된 설정을 포함하지 않는 프로젝트에 대해 위반을 보고하지 않습니다. |

각 배열은 최대 5개의 항목을 수락하며, 각 항목은 최대 4096바이트로 직렬화되어야 합니다. 크기가 초과된 항목에 대한 오류는 각 위치의 이름을 지정하며, 예를 들어 `rules has an entry exceeding maximum size of 4096 bytes at 0`입니다. 항목은 비어있을 수 없습니다. 빈 항목은 `400 Bad Request`를 반환하고 오류는 각 빈 위치의 이름을 지정하며, 예를 들어 `rules[0] is blank`입니다.

`custom` 규칙의 Rego와 모든 규칙이 병합되는 `policy_rego` 모듈은 구문 분석되어야 합니다. 구문 분석하지 않는 `custom` 규칙은 `400 Bad Request`를 반환합니다. 오류는 규칙의 위치의 이름을 지정하고 `value`에서 전송한 Rego의 줄과 열이 있는 엔진의 메시지를 포함하며, 예를 들어 ``rules[0] is invalid: error: expecting `}` while parsing object (at line:column)``입니다. `policy_rego` 모듈은 모든 규칙이 병합된 후에도 구문 분석됩니다. 모든 규칙이 이미 자체적으로 구문 분석되었으므로 이 단계에서의 실패는 정책 엔진의 결함으로 처리됩니다. 요청은 `500 Internal Server Error`을 반환하고, 정책은 저장되지 않으며, 결함은 오류 추적에 보고됩니다.

`rules` 및 `actions`를 `Content-Type: application/json` 헤더가 있는 JSON으로 전송합니다. 폼 인코딩 본문은 두 배열을 모두 전달할 수 있지만 하나의 모든 값은 문자열로 도착하므로 문자열이 아닌 `value`는 이런 식으로 표현할 수 없습니다.

### 응답 속성 {#response-attributes}

정책 끝점은 다음 속성을 반환합니다:

| 속성         | 형식            | 설명 |
| ----------------- | --------------- | ----------- |
| `actions`         | 배열           | 정책이 수행하는 작업입니다. |
| `created_at`      | 문자열          | 정책을 만든 날짜와 시간입니다. |
| `description`     | 문자열          | 정책의 설명입니다. |
| `id`              | 정수         | 정책의 ID입니다. |
| `lifecycle_state` | 문자열          | `active` 또는 `disabled`. |
| `mode`            | 문자열          | `audit`, `warn` 또는 `enforce` 중 하나입니다. |
| `name`            | 문자열          | 정책의 이름입니다. |
| `namespace_id`    | 정수         | 정책을 소유하는 그룹의 ID입니다. 조직 끝점을 통해 만들어진 정책의 경우 `null`, 조직이 해당 정책을 소유하거나 그룹을 볼 수 없을 때입니다. |
| `organization_id` | 정수         | 정책이 속한 조직의 ID입니다. |
| `policy_rego`     | 문자열          | 정책의 규칙을 단일 Rego 모듈로 컴파일합니다. 규칙이 없는 정책의 경우 `null`입니다. |
| `policy_scope`    | 개체          | 정책의 구조화된 범위 또는 Rego를 직접 작성한 경우 `null`입니다. |
| `rules`           | 배열           | 정책의 규칙입니다. |
| `scope_dimensions`| 배열           | 정책이 적용되는지 여부를 결정하기 위해 `scope_rego`이 읽는 점으로 분리된 컨텍스트 경로입니다. GitLab은 이 값을 파생하므로 사용자가 전송한 모든 값을 무시합니다. `scope_rego`을 직접 작성한 경우 `null`이고, 그렇지 않으면 배열이며, 정책에 범위가 없으면 비어 있습니다. |
| `scope_rego`      | 문자열          | 정책의 범위로, [Rego](https://www.openpolicyagent.org/docs/policy-language)의 프로그램, Open Policy Agent의 정책 언어입니다. `policy_scope`에서 직접 작성되거나 컴파일됩니다. 항상 존재합니다. 범위가 없는 정책은 모든 프로젝트에 적용되는 프로그램으로 컴파일되기 때문입니다. |
| `trigger_type`    | 문자열          | 정책이 응답하는 트리거입니다. |
| `updated_at`      | 문자열          | 정책을 마지막으로 변경한 날짜와 시간입니다. |
| `version`         | 정수         | 정책의 개정 판입니다. 최소한 하나의 값을 변경하는 업데이트가 1씩 증가합니다. |

## 조직 정책 {#organization-policies}

조직 끝점을 사용하여 조직의 정책을 관리합니다.

전제 조건:

- 조직의 소유자이거나 인스턴스의 관리자여야 합니다.

조직을 옵트인하려면 `organizationUpdate` GraphQL 뮤테이션을 `policyStoreExperimentEnabled`을 사용하여 `true`로 설정하여 전송합니다. 뮤테이션은 조직에서 실험을 사용할 수 없는 경우 오류를 반환합니다.

정책 끝점에 대한 모든 호출은 [인증](rest/authentication.md)되어야 합니다. 조직을 관리할 수 없는 호출자는 `403 Forbidden`을 받고, 조직을 전혀 볼 수 없는 호출자는 `404 Not Found`을 받습니다.

다른 조직에 속하는 정책은 존재하지 않는 정책과 구별할 수 없습니다. ID는 조직 간에 정책을 읽거나 변경하는 데 사용할 수 없습니다.

### 모든 조직 정책 나열 {#list-all-organization-policies}

조직에 속한 모든 정책을 나열합니다.

```plaintext
GET /organizations/:id/security/policy_store
```

지원되는 속성:

| 속성         | 형식    | 필수 | 설명 |
| ----------------- | ------- | -------- | ----------- |
| `id`              | 정수 | 예      | 조직의 ID입니다. |
| `lifecycle_state` | 문자열  | 아니요       | `active` 정책만 반환하거나, `disabled` 정책만 반환하거나, `all` 정책을 반환합니다. 기본값은 `active`입니다. |
| `namespace_ids`   | 배열   | 아니요       | 네임스페이스의 ID로, 일반적으로 그룹과 그 상위 항목입니다. 해당 정책 및 조직 전체 정책만 반환합니다. 최대 21개의 고유 ID이며, 더 많으면 `400 Bad Request`을 반환합니다. GitLab.com에서 기본 조직은 조직 전체 정책을 반환하지 않으며, `namespace_ids` 없이는 정책을 반환하지 않습니다. |
| `page`            | 정수 | 아니요       | 반환할 결과 페이지입니다. 기본값은 `1`입니다. |
| `per_page`        | 정수 | 아니요       | 페이지당 결과 수입니다. `20`로 기본값이 설정되며, `100` 위의 모든 값은 `100`으로 한정됩니다. |
| `trigger_type`    | 문자열  | 아니요       | 이 트리거에 응답하는 정책만 반환합니다. [모든 트리거 나열](#list-all-triggers)에서 반환되는 ID 중 하나입니다. |

이 끝점은 [페이지가 매겨진](rest/_index.md#offset-based-pagination) 결과를 반환합니다. 성능상의 이유로 조직이 보유한 정책의 수에 관계없이 `x-total` 또는 `x-total-pages` 헤더 또는 `rel="last"` `link`를 반환하지 않습니다. `x-next-page`을 확인하여 다른 페이지가 있는지 확인하세요.

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes) 및 [정책 속성](#response-attributes)의 배열을 반환합니다. GitLab.com에서 `namespace_ids` 없이 기본 조직에 대한 요청은 `trigger_type`이 `project.before_settings_update`, `project.after_create` 또는 `project.after_transfer`일 때 `400 Bad Request`를 반환합니다. 이러한 트리거는 그룹 계층 구조를 전달하기 때문입니다.

요청 예:

```shell
curl --request GET --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/organizations/1/security/policy_store?per_page=20"
```

응답 예:

```json
[
  {
    "id": 1,
    "organization_id": 1,
    "namespace_id": null,
    "name": "Block deployments on critical findings",
    "description": null,
    "version": 1,
    "trigger_type": "deployment_requested",
    "rules": [{ "type": "custom", "value": "package governance" }],
    "policy_rego": "package governance\n",
    "actions": [{ "type": "block" }],
    "policy_scope": null,
    "scope_dimensions": [],
    "scope_rego": "package gitlab.scope\n\napplicable := [result.policy | some result in results; result.applies]\n...",
    "mode": "enforce",
    "lifecycle_state": "active",
    "created_at": "2026-08-07T13:56:32.985Z",
    "updated_at": "2026-08-07T13:56:32.985Z"
  }
]
```

### 조직 정책 검색 {#retrieve-an-organization-policy}

조직에서 단일 정책을 검색합니다.

```plaintext
GET /organizations/:id/security/policy_store/:policy_id
```

지원되는 속성:

| 속성   | 형식    | 필수 | 설명 |
| ----------- | ------- | -------- | ----------- |
| `id`        | 정수 | 예      | 조직의 ID입니다. |
| `policy_id` | 정수 | 예      | 정책의 ID입니다. |

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes) 및 [정책 속성](#response-attributes)을 반환합니다. GitLab.com에서 기본 조직은 모든 정책에 대해 `404 Not Found`를 반환합니다. 각 고객은 자신의 그룹을 통해 정책에 접근합니다.

요청 예:

```shell
curl --request GET --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/organizations/1/security/policy_store/1"
```

응답 예:

```json
{
  "id": 1,
  "organization_id": 1,
  "namespace_id": null,
  "name": "Block deployments on critical findings",
  "description": null,
  "version": 1,
  "trigger_type": "deployment_requested",
  "rules": [{ "type": "custom", "value": "package governance" }],
  "policy_rego": "package governance\n",
  "actions": [{ "type": "block" }],
  "policy_scope": null,
  "scope_dimensions": [],
  "scope_rego": "package gitlab.scope\n\napplicable := [result.policy | some result in results; result.applies]\n...",
  "mode": "enforce",
  "lifecycle_state": "active",
  "created_at": "2026-08-07T13:56:32.985Z",
  "updated_at": "2026-08-07T13:56:32.985Z"
}
```

### 조직 정책 생성 {#create-an-organization-policy}

조직에서 정책을 생성합니다.

```plaintext
POST /organizations/:id/security/policy_store
```

지원되는 속성:

| 속성         | 형식    | 필수 | 설명 |
| ----------------- | ------- | -------- | ----------- |
| `id`              | 정수 | 예      | 조직의 ID입니다. |
| `name`            | 문자열  | 예      | 정책의 이름입니다. 최대 255자입니다. 조직에서 고유해야 합니다. |
| `rules`           | 배열   | 예      | 정책의 규칙입니다. 항목 속성의 경우 [규칙 및 작업 속성](#rule-and-action-attributes)을 참조하세요. 최소 1개 항목이 필요하며, 최대 5개입니다. 각 항목은 최대 4096바이트로 직렬화되어야 합니다. 항목이 65536바이트보다 큰 Rego 모듈로 컴파일될 때 거부됩니다. 해당 모듈은 `policy_rego`로 반환됩니다. |
| `trigger_type`    | 문자열  | 예      | 정책이 응답하는 트리거입니다. [모든 트리거 나열](#list-all-triggers)에서 반환되는 ID 중 하나입니다. |
| `actions`         | 배열   | 아니요       | 정책이 수행하는 작업입니다. 항목 속성의 경우 [규칙 및 작업 속성](#rule-and-action-attributes)을 참조하세요. 최대 5개의 항목입니다. 각 항목은 최대 4096바이트로 직렬화되어야 합니다. |
| `description`     | 문자열  | 아니요       | 정책의 설명입니다. 최대 4096자입니다. |
| `lifecycle_state` | 문자열  | 아니요       | `active` 또는 `disabled`. 기본값은 `active`입니다. |
| `mode`            | 문자열  | 아니요       | `audit`, `warn` 또는 `enforce` 중 하나입니다. 기본값은 `warn`입니다. |
| `policy_scope`    | 개체  | 아니요       | 정책의 구조화된 범위로, GitLab이 `scope_rego`로 컴파일합니다. 속성의 경우 [정책 범위 속성](#policy-scope-attributes)을 참조하세요. 비어있지 않은 `scope_rego`과 결합할 수 없습니다. Rego의 4096자 이상으로 컴파일될 때 거부됩니다. |
| `scope_rego`      | 문자열  | 아니요       | 정책의 범위로 Rego 프로그램으로 직접 작성됩니다. GitLab은 작성한 그대로 저장합니다. 최대 4096자입니다. 비어있지 않은 값은 `policy_scope`과 결합할 수 없습니다. 빈 값은 생략하는 것과 같은 효과를 가집니다. Rego로 구문 분석되지 않는 값은 `400 Bad Request`를 반환합니다. |

성공하면 [`201 Created`](rest/troubleshooting.md#status-codes) 및 [정책 속성](#response-attributes)을 반환합니다. 다음 조건은 `400 Bad Request`를 반환합니다:

- 속성이 유효하지 않습니다.
- 두 범위 형식이 모두 제공됩니다.
- 이름이 조직에서 이미 사용 중입니다.
- 컴파일된 `scope_rego`이 4096자를 초과합니다.
- `rules`이 65536바이트 이상의 Rego로 컴파일됩니다.
- `rules` 또는 `actions`이 5개 이상의 항목을 전달합니다.
- `rules` 또는 `actions`의 항목이 4096바이트 이상으로 직렬화됩니다.

GitLab.com에서 기본 조직에서 정책을 만들면 [`422 Unprocessable Entity`](rest/troubleshooting.md#status-codes)를 반환합니다. 자체 조직이 없는 그룹은 기본값을 공유하므로 조직 전체 정책이 모든 항목에 적용됩니다. 대신 그룹에서 정책을 생성합니다.

요청 예:

```shell
curl --request POST --header "PRIVATE-TOKEN: <your_access_token>" \
  --header "Content-Type: application/json" \
  --data '{
    "name": "Block deployments on critical findings",
    "trigger_type": "deployment_requested",
    "rules": [{ "type": "custom", "value": "package governance" }],
    "actions": [{ "type": "block" }],
    "policy_scope": { "compliance_frameworks": [{ "id": 5 }] }
  }' \
  --url "https://gitlab.example.com/api/v4/organizations/1/security/policy_store"
```

응답 예:

```json
{
  "id": 1,
  "organization_id": 1,
  "namespace_id": null,
  "name": "Block deployments on critical findings",
  "description": null,
  "version": 1,
  "trigger_type": "deployment_requested",
  "rules": [{ "type": "custom", "value": "package governance" }],
  "policy_rego": "package governance\n",
  "actions": [{ "type": "block" }],
  "policy_scope": { "compliance_frameworks": [{ "id": 5 }] },
  "scope_dimensions": ["compliance_frameworks"],
  "scope_rego": "package gitlab.scope\n\napplicable := [result.policy | some result in results; result.applies]\n...",
  "mode": "warn",
  "lifecycle_state": "active",
  "created_at": "2026-08-07T13:56:32.985Z",
  "updated_at": "2026-08-07T13:56:32.985Z"
}
```

### 조직 정책 업데이트 {#update-an-organization-policy}

조직에서 정책을 업데이트합니다. 경로 매개변수를 제외한 모든 속성은 선택 사항이지만 요청은 최소 하나를 명시해야 합니다. 전송되지 않는 속성은 그대로 유지되며, 최소한 하나의 값을 변경하는 업데이트는 `version`을 1씩 증가시킵니다. 저장된 값을 다시 진술하는 요청은 아무것도 변경하지 않으며 `version`을 그대로 둡니다.

```plaintext
PATCH /organizations/:id/security/policy_store/:policy_id
```

지원되는 속성:

| 속성         | 형식    | 필수 | 설명 |
| ----------------- | ------- | -------- | ----------- |
| `id`              | 정수 | 예      | 조직의 ID입니다. |
| `policy_id`       | 정수 | 예      | 정책의 ID입니다. |
| `actions`         | 배열   | 아니요       | 정책이 수행하는 작업입니다. 항목 속성의 경우 [규칙 및 작업 속성](#rule-and-action-attributes)을 참조하세요. 저장된 작업을 대체하며, 최대 5개의 항목입니다. 각 항목은 최대 4096바이트로 직렬화되어야 합니다. |
| `description`     | 문자열  | 아니요       | 정책의 설명입니다. 최대 4096자입니다. |
| `lifecycle_state` | 문자열  | 아니요       | `active` 또는 `disabled`. |
| `mode`            | 문자열  | 아니요       | `audit`, `warn` 또는 `enforce` 중 하나입니다. |
| `name`            | 문자열  | 아니요       | 정책의 이름입니다. 최대 255자입니다. 조직에서 고유해야 합니다. |
| `policy_scope`    | 개체  | 아니요       | 정책의 구조화된 범위로, GitLab이 `scope_rego`로 컴파일합니다. 속성의 경우 [정책 범위 속성](#policy-scope-attributes)을 참조하세요. 비어있지 않은 `scope_rego`과 결합할 수 없습니다. Rego의 4096자 이상으로 컴파일될 때 거부됩니다. |
| `rules`           | 배열   | 아니요       | 정책의 규칙입니다. 항목 속성의 경우 [규칙 및 작업 속성](#rule-and-action-attributes)을 참조하세요. 저장된 규칙을 대체하며, 최대 5개의 항목입니다. 각 항목은 최대 4096바이트로 직렬화되어야 합니다. 항목이 65536바이트보다 큰 Rego 모듈로 컴파일될 때 거부됩니다. 해당 모듈은 `policy_rego`로 반환됩니다. |
| `scope_rego`      | 문자열  | 아니요       | 정책의 범위로 Rego 프로그램으로 직접 작성됩니다. GitLab은 작성한 그대로 저장합니다. 최대 4096자입니다. 작성된 프로그램을 폐지하고 `policy_scope`에서 다시 컴파일하려면 빈 값을 전송합니다. Rego로 구문 분석되지 않는 값은 `400 Bad Request`를 반환합니다. |
| `trigger_type`    | 문자열  | 아니요       | 정책이 응답하는 트리거입니다. [모든 트리거 나열](#list-all-triggers)에서 반환되는 ID 중 하나입니다. 그룹에 속하는 정책의 경우 `project.before_settings_update`, `project.after_create`, 또는 `project.after_transfer`여야 합니다. 이러한 트리거만 그룹 계층 구조를 전달하기 때문입니다. |

정책의 이름을 바꾸면 GitLab은 생성된 `scope_rego`을 다시 컴파일해야 합니다. 정책 이름이 생성된 프로그램에 나타나기 때문입니다. 직접 작성된 `scope_rego`은 그대로 유지됩니다.

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes) 및 [정책 속성](#response-attributes)을 반환합니다. GitLab.com에서 요청이 유효할 때 기본 조직은 모든 정책에 대해 `404 Not Found`를 반환합니다. 각 고객은 자신의 그룹을 통해 정책에 접근합니다. 다음 조건은 `400 Bad Request`를 반환합니다:

- 변경할 속성이 없습니다.
- 속성이 유효하지 않습니다.
- 두 범위 형식이 모두 제공됩니다.
- 새 이름이 조직에서 이미 사용 중입니다.
- 다시 컴파일된 `scope_rego`이 4096자를 초과합니다.
- 대체 `rules`이 65536바이트 이상의 Rego로 컴파일됩니다.
- 대체 `rules` 또는 `actions`이 5개 이상의 항목을 전달합니다.
- 대체 `rules` 또는 `actions`의 항목이 4096바이트 이상으로 직렬화됩니다.
- 정책이 그룹에 속하며 새 `trigger_type`이 그룹 정책이 사용할 수 없는 항목입니다.

요청 예:

```shell
curl --request PATCH --header "PRIVATE-TOKEN: <your_access_token>" \
  --data-urlencode "name=Renamed policy" \
  --url "https://gitlab.example.com/api/v4/organizations/1/security/policy_store/1"
```

응답 예:

```json
{
  "id": 1,
  "organization_id": 1,
  "namespace_id": null,
  "name": "Renamed policy",
  "description": null,
  "version": 2,
  "trigger_type": "deployment_requested",
  "rules": [{ "type": "custom", "value": "package governance" }],
  "policy_rego": "package governance\n",
  "actions": [{ "type": "block" }],
  "policy_scope": null,
  "scope_dimensions": [],
  "scope_rego": "package gitlab.scope\n\napplicable := [result.policy | some result in results; result.applies]\n...",
  "mode": "enforce",
  "lifecycle_state": "active",
  "created_at": "2026-08-07T13:56:32.985Z",
  "updated_at": "2026-08-07T14:02:47.198Z"
}
```

### 조직 정책 삭제 {#delete-an-organization-policy}

조직에서 정책을 삭제합니다.

```plaintext
DELETE /organizations/:id/security/policy_store/:policy_id
```

지원되는 속성:

| 속성   | 형식    | 필수 | 설명 |
| ----------- | ------- | -------- | ----------- |
| `id`        | 정수 | 예      | 조직의 ID입니다. |
| `policy_id` | 정수 | 예      | 정책의 ID입니다. |

성공하면 [`204 No Content`](rest/troubleshooting.md#status-codes)를 반환합니다. GitLab.com에서 기본 조직은 모든 정책에 대해 `404 Not Found`를 반환합니다. 각 고객은 자신의 그룹을 통해 정책에 접근합니다.

요청 예:

```shell
curl --request DELETE --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/organizations/1/security/policy_store/1"
```

## 그룹 정책 {#group-policies}

그룹 끝점을 사용하여 그룹의 정책을 관리합니다. 이 끝점에서 `id`은 그룹의 ID 또는 [URL 인코딩 경로](rest/_index.md#namespaced-paths)입니다.

전제 조건:

- 그룹이 정책 저장소 실험을 옵트인했어야 합니다. 하위 그룹은 최상위 그룹의 옵트인을 따릅니다.
- 정책을 나열하거나 검색하려면 그룹의 소유자 역할이 있거나, 감사자이거나, 인스턴스의 관리자여야 합니다.
- 정책을 만들거나, 업데이트하거나, 삭제하려면 그룹의 소유자 역할이 있거나 인스턴스의 관리자여야 합니다.

그룹은 `policy_store_experiment_enabled` 설정을 통해 옵트인합니다. 보안 정책 프로젝트를 통해 이미 보안 정책이 구성된 그룹은 옵트인할 수 없습니다.

### 모든 그룹 정책 나열 {#list-all-group-policies}

그룹에 속한 모든 정책을 나열합니다.

```plaintext
GET /groups/:id/security/policy_store
```

지원되는 속성:

| 속성         | 형식              | 필수 | 설명 |
| ----------------- | ----------------- | -------- | ----------- |
| `id`              | 정수 또는 문자열 | 예      | 그룹의 ID 또는 [URL 인코딩 경로](rest/_index.md#namespaced-paths)입니다. |
| `lifecycle_state` | 문자열            | 아니요       | `active` 정책만 반환하거나, `disabled` 정책만 반환하거나, `all` 정책을 반환합니다. 기본값은 `active`입니다. |
| `page`            | 정수           | 아니요       | 반환할 결과 페이지입니다. 기본값은 `1`입니다. |
| `per_page`        | 정수           | 아니요       | 페이지당 결과 수입니다. `20`로 기본값이 설정되며, `100` 위의 모든 값은 `100`으로 한정됩니다. |
| `trigger_type`    | 문자열            | 아니요       | 이 트리거에 응답하는 정책만 반환합니다. [모든 트리거 나열](#list-all-triggers)에서 반환되는 ID 중 하나입니다. |

이 끝점은 페이지가 매겨진 결과를 반환합니다. 성능상의 이유로 그룹이 보유한 정책의 수에 관계없이 `x-total` 또는 `x-total-pages` 헤더 또는 `rel="last"` `link`를 반환하지 않습니다. `x-next-page`을 확인하여 다른 페이지가 있는지 확인하세요.

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes) 및 [정책 속성](#response-attributes)의 배열을 반환합니다.

요청 예:

```shell
curl --request GET --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/groups/5/security/policy_store?per_page=20"
```

응답 예:

```json
[
  {
    "id": 1,
    "organization_id": 1,
    "namespace_id": 5,
    "name": "Block settings changes on critical findings",
    "description": null,
    "version": 1,
    "trigger_type": "project.before_settings_update",
    "rules": [{ "type": "custom", "value": "package governance" }],
    "policy_rego": "package governance\n",
    "actions": [{ "type": "block" }],
    "policy_scope": null,
    "scope_dimensions": [],
    "scope_rego": "package gitlab.scope\n\napplicable := [result.policy | some result in results; result.applies]\n...",
    "mode": "enforce",
    "lifecycle_state": "active",
    "created_at": "2026-08-07T13:56:32.985Z",
    "updated_at": "2026-08-07T13:56:32.985Z"
  }
]
```

### 그룹 정책 검색 {#retrieve-a-group-policy}

그룹에서 단일 정책을 검색합니다.

```plaintext
GET /groups/:id/security/policy_store/:policy_id
```

지원되는 속성:

| 속성   | 형식              | 필수 | 설명 |
| ----------- | ----------------- | -------- | ----------- |
| `id`        | 정수 또는 문자열 | 예      | 그룹의 ID 또는 [URL 인코딩 경로](rest/_index.md#namespaced-paths)입니다. |
| `policy_id` | 정수           | 예      | 정책의 ID입니다. |

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes) 및 [정책 속성](#response-attributes)을 반환합니다.

요청 예:

```shell
curl --request GET --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/groups/5/security/policy_store/1"
```

응답 예:

```json
{
  "id": 1,
  "organization_id": 1,
  "namespace_id": 5,
  "name": "Block settings changes on critical findings",
  "description": null,
  "version": 1,
  "trigger_type": "project.before_settings_update",
  "rules": [{ "type": "custom", "value": "package governance" }],
  "policy_rego": "package governance\n",
  "actions": [{ "type": "block" }],
  "policy_scope": null,
  "scope_dimensions": [],
  "scope_rego": "package gitlab.scope\n\napplicable := [result.policy | some result in results; result.applies]\n...",
  "mode": "enforce",
  "lifecycle_state": "active",
  "created_at": "2026-08-07T13:56:32.985Z",
  "updated_at": "2026-08-07T13:56:32.985Z"
}
```

### 그룹 정책 생성 {#create-a-group-policy}

그룹에서 정책을 생성합니다.

```plaintext
POST /groups/:id/security/policy_store
```

지원되는 속성:

| 속성         | 형식              | 필수 | 설명 |
| ----------------- | ----------------- | -------- | ----------- |
| `id`              | 정수 또는 문자열 | 예      | 그룹의 ID 또는 [URL 인코딩 경로](rest/_index.md#namespaced-paths)입니다. |
| `name`            | 문자열            | 예      | 정책의 이름입니다. 최대 255자입니다. 조직에서 고유해야 합니다. |
| `rules`           | 배열             | 예      | 정책의 규칙입니다. 항목 속성의 경우 [규칙 및 작업 속성](#rule-and-action-attributes)을 참조하세요. 최소 1개 항목이 필요하며, 최대 5개입니다. 각 항목은 최대 4096바이트로 직렬화되어야 합니다. 항목이 65536바이트보다 큰 Rego 모듈로 컴파일될 때 거부됩니다. 해당 모듈은 `policy_rego`로 반환됩니다. |
| `trigger_type`    | 문자열            | 예      | 정책이 응답하는 트리거입니다. [모든 트리거 나열](#list-all-triggers)에서 반환되는 ID 중 하나입니다. `project.before_settings_update`, `project.after_create` 또는 `project.after_transfer`여야 하는 이유는 이러한 트리거만 그룹 계층 구조를 전달합니다. |
| `actions`         | 배열             | 아니요       | 정책이 수행하는 작업입니다. 항목 속성의 경우 [규칙 및 작업 속성](#rule-and-action-attributes)을 참조하세요. 최대 5개의 항목입니다. 각 항목은 최대 4096바이트로 직렬화되어야 합니다. |
| `description`     | 문자열            | 아니요       | 정책의 설명입니다. 최대 4096자입니다. |
| `lifecycle_state` | 문자열            | 아니요       | `active` 또는 `disabled`. 기본값은 `active`입니다. |
| `mode`            | 문자열            | 아니요       | `audit`, `warn` 또는 `enforce` 중 하나입니다. 기본값은 `warn`입니다. |
| `policy_scope`    | 개체            | 아니요       | 정책의 구조화된 범위로, GitLab이 `scope_rego`로 컴파일합니다. 속성의 경우 [정책 범위 속성](#policy-scope-attributes)을 참조하세요. 비어있지 않은 `scope_rego`과 결합할 수 없습니다. Rego의 4096자 이상으로 컴파일될 때 거부됩니다. |
| `scope_rego`      | 문자열            | 아니요       | 정책의 범위로 Rego 프로그램으로 직접 작성됩니다. GitLab은 작성한 그대로 저장합니다. 최대 4096자입니다. 비어있지 않은 값은 `policy_scope`과 결합할 수 없습니다. 빈 값은 생략하는 것과 같은 효과를 가집니다. Rego로 구문 분석되지 않는 값은 `400 Bad Request`를 반환합니다. |

성공하면 [`201 Created`](rest/troubleshooting.md#status-codes) 및 [정책 속성](#response-attributes)을 반환합니다. 다음 조건은 `400 Bad Request`를 반환합니다:

- 속성이 유효하지 않습니다.
- 두 범위 형식이 모두 제공됩니다.
- 이름이 조직에서 이미 사용 중입니다.
- 컴파일된 `scope_rego`이 4096자를 초과합니다.
- `rules`이 65536바이트 이상의 Rego로 컴파일됩니다.
- `rules` 또는 `actions`이 5개 이상의 항목을 전달합니다.
- `rules` 또는 `actions`의 항목이 4096바이트 이상으로 직렬화됩니다.
- `trigger_type`이 그룹 정책이 사용할 수 없는 항목입니다.

요청 예:

```shell
curl --request POST --header "PRIVATE-TOKEN: <your_access_token>" \
  --header "Content-Type: application/json" \
  --data '{
    "name": "Block settings changes on critical findings",
    "trigger_type": "project.before_settings_update",
    "rules": [{ "type": "custom", "value": "package governance" }],
    "actions": [{ "type": "block" }],
    "policy_scope": { "compliance_frameworks": [{ "id": 5 }] }
  }' \
  --url "https://gitlab.example.com/api/v4/groups/5/security/policy_store"
```

응답 예:

```json
{
  "id": 1,
  "organization_id": 1,
  "namespace_id": 5,
  "name": "Block settings changes on critical findings",
  "description": null,
  "version": 1,
  "trigger_type": "project.before_settings_update",
  "rules": [{ "type": "custom", "value": "package governance" }],
  "policy_rego": "package governance\n",
  "actions": [{ "type": "block" }],
  "policy_scope": { "compliance_frameworks": [{ "id": 5 }] },
  "scope_dimensions": ["compliance_frameworks"],
  "scope_rego": "package gitlab.scope\n\napplicable := [result.policy | some result in results; result.applies]\n...",
  "mode": "warn",
  "lifecycle_state": "active",
  "created_at": "2026-08-07T13:56:32.985Z",
  "updated_at": "2026-08-07T13:56:32.985Z"
}
```

### 그룹 정책 업데이트 {#update-a-group-policy}

그룹에서 정책을 업데이트합니다. 경로 매개변수를 제외한 모든 속성은 선택 사항이지만 요청은 최소 하나를 명시해야 합니다. 전송되지 않는 속성은 그대로 유지되며, 최소한 하나의 값을 변경하는 업데이트는 `version`을 1씩 증가시킵니다. 저장된 값을 다시 진술하는 요청은 아무것도 변경하지 않으며 `version`을 그대로 둡니다.

```plaintext
PATCH /groups/:id/security/policy_store/:policy_id
```

지원되는 속성:

| 속성         | 형식              | 필수 | 설명 |
| ----------------- | ----------------- | -------- | ----------- |
| `id`              | 정수 또는 문자열 | 예      | 그룹의 ID 또는 [URL 인코딩 경로](rest/_index.md#namespaced-paths)입니다. |
| `policy_id`       | 정수           | 예      | 정책의 ID입니다. |
| `actions`         | 배열             | 아니요       | 정책이 수행하는 작업입니다. 항목 속성의 경우 [규칙 및 작업 속성](#rule-and-action-attributes)을 참조하세요. 저장된 작업을 대체하며, 최대 5개의 항목입니다. 각 항목은 최대 4096바이트로 직렬화되어야 합니다. |
| `description`     | 문자열            | 아니요       | 정책의 설명입니다. 최대 4096자입니다. |
| `lifecycle_state` | 문자열            | 아니요       | `active` 또는 `disabled`. |
| `mode`            | 문자열            | 아니요       | `audit`, `warn` 또는 `enforce` 중 하나입니다. |
| `name`            | 문자열            | 아니요       | 정책의 이름입니다. 최대 255자입니다. 조직에서 고유해야 합니다. |
| `policy_scope`    | 개체            | 아니요       | 정책의 구조화된 범위로, GitLab이 `scope_rego`로 컴파일합니다. 속성의 경우 [정책 범위 속성](#policy-scope-attributes)을 참조하세요. 비어있지 않은 `scope_rego`과 결합할 수 없습니다. Rego의 4096자 이상으로 컴파일될 때 거부됩니다. |
| `rules`           | 배열             | 아니요       | 정책의 규칙입니다. 항목 속성의 경우 [규칙 및 작업 속성](#rule-and-action-attributes)을 참조하세요. 저장된 규칙을 대체하며, 최대 5개의 항목입니다. 각 항목은 최대 4096바이트로 직렬화되어야 합니다. 항목이 65536바이트보다 큰 Rego 모듈로 컴파일될 때 거부됩니다. 해당 모듈은 `policy_rego`로 반환됩니다. |
| `scope_rego`      | 문자열            | 아니요       | 정책의 범위로 Rego 프로그램으로 직접 작성됩니다. GitLab은 작성한 그대로 저장합니다. 최대 4096자입니다. 작성된 프로그램을 폐지하고 `policy_scope`에서 다시 컴파일하려면 빈 값을 전송합니다. Rego로 구문 분석되지 않는 값은 `400 Bad Request`를 반환합니다. |
| `trigger_type`    | 문자열            | 아니요       | 정책이 응답하는 트리거입니다. [모든 트리거 나열](#list-all-triggers)에서 반환되는 ID 중 하나입니다. `project.before_settings_update`, `project.after_create` 또는 `project.after_transfer`여야 하는 이유는 이러한 트리거만 그룹 계층 구조를 전달합니다. |

정책의 이름을 바꾸면 GitLab은 생성된 `scope_rego`을 다시 컴파일해야 합니다. 정책 이름이 생성된 프로그램에 나타나기 때문입니다. 직접 작성된 `scope_rego`은 그대로 유지됩니다.

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes) 및 [정책 속성](#response-attributes)을 반환합니다. 다음 조건은 `400 Bad Request`를 반환합니다:

- 변경할 속성이 없습니다.
- 속성이 유효하지 않습니다.
- 두 범위 형식이 모두 제공됩니다.
- 새 이름이 조직에서 이미 사용 중입니다.
- 다시 컴파일된 `scope_rego`이 4096자를 초과합니다.
- 대체 `rules`이 65536바이트 이상의 Rego로 컴파일됩니다.
- 대체 `rules` 또는 `actions`이 5개 이상의 항목을 전달합니다.
- 대체 `rules` 또는 `actions`의 항목이 4096바이트 이상으로 직렬화됩니다.
- 새 `trigger_type`이 그룹 정책이 사용할 수 없는 항목입니다.

요청 예:

```shell
curl --request PATCH --header "PRIVATE-TOKEN: <your_access_token>" \
  --data-urlencode "name=Renamed policy" \
  --url "https://gitlab.example.com/api/v4/groups/5/security/policy_store/1"
```

응답 예:

```json
{
  "id": 1,
  "organization_id": 1,
  "namespace_id": 5,
  "name": "Renamed policy",
  "description": null,
  "version": 2,
  "trigger_type": "project.before_settings_update",
  "rules": [{ "type": "custom", "value": "package governance" }],
  "policy_rego": "package governance\n",
  "actions": [{ "type": "block" }],
  "policy_scope": null,
  "scope_dimensions": [],
  "scope_rego": "package gitlab.scope\n\napplicable := [result.policy | some result in results; result.applies]\n...",
  "mode": "enforce",
  "lifecycle_state": "active",
  "created_at": "2026-08-07T13:56:32.985Z",
  "updated_at": "2026-08-07T14:02:47.198Z"
}
```

### 그룹 정책 삭제 {#delete-a-group-policy}

그룹에서 정책을 삭제합니다.

```plaintext
DELETE /groups/:id/security/policy_store/:policy_id
```

지원되는 속성:

| 속성   | 형식              | 필수 | 설명 |
| ----------- | ----------------- | -------- | ----------- |
| `id`        | 정수 또는 문자열 | 예      | 그룹의 ID 또는 [URL 인코딩 경로](rest/_index.md#namespaced-paths)입니다. |
| `policy_id` | 정수           | 예      | 정책의 ID입니다. |

성공하면 [`204 No Content`](rest/troubleshooting.md#status-codes)를 반환합니다.

요청 예:

```shell
curl --request DELETE --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/groups/5/security/policy_store/1"
```
