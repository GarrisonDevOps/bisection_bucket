---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 감사 이벤트 스키마 및 예제
---

## 감사 이벤트 스키마 {#audit-event-schema}

감사 이벤트는 응답 본문에 예측 가능한 스키마를 가집니다.

| 필드            | 설명                                                | 참고                                                                             | 스트리밍 전용 필드 |
|------------------|------------------------------------------------------------|-----------------------------------------------------------------------------------|----------------------|
| `author_id`      | 이벤트를 트리거한 사용자의 사용자 ID                |                                                                                   | {{< no >}}           |
| `author_name`    | 이벤트를 트리거한 작성자의 읽을 수 있는 이름 | 작성자가 더 이상 존재하지 않을 때 도움이 됩니다                                          | {{< yes >}}          |
| `created_at`     | 이벤트가 트리거된 타임스탬프                         |                                                                                   | {{< no >}}           |
| `details`        | 추가 메타데이터가 포함된 JSON 객체                 | 정의된 스키마는 없지만 이벤트에 대한 추가 정보가 포함되는 경우가 많습니다    | {{< no >}}           |
| `entity_id`      | 감사 이벤트의 엔티티 ID                             |                                                                                   | {{< no >}}           |
| `entity_path`    | 감사 가능한 이벤트의 영향을 받는 엔티티의 전체 경로    |                                                                                   | {{< yes >}}          |
| `entity_type`    | 엔티티 유형의 문자열 표현                | 허용되는 값에는 `User`, `Group`, `Key`가 포함됩니다. 이 목록은 완전하지 않습니다 | {{< no >}}           |
| `event_type`     | 감사 이벤트 유형의 문자열 표현           |                                                                                   | {{< yes >}}          |
| `id`             | 감사 이벤트의 고유 식별자                      | 필요한 경우 중복 제거에 사용할 수 있습니다                                         | {{< no >}}           |
| `ip_address`     | 이벤트를 트리거하는 데 사용된 호스트의 IP 주소           |                                                                                   | {{< yes >}}          |
| `target_details` | 대상에 대한 추가 세부 정보                        |                                                                                   | {{< yes >}}          |
| `target_id`      | 감사 이벤트의 대상 ID                             |                                                                                   | {{< yes >}}          |
| `target_type`    | 대상 유형의 문자열 표현                 |                                                                                   | {{< yes >}}          |

### 감사 이벤트 JSON 스키마 {#audit-event-json-schema}

```json
{
  "properties": {
    "id": {
      "type": "string"
    },
    "author_id": {
      "type": "integer"
    },
    "author_name": {
      "type": "string"
    },
    "details": {},
    "ip_address": {
      "type": "string"
    },
    "entity_id": {
      "type": "integer"
    },
    "entity_path": {
      "type": "string"
    },
    "entity_type": {
      "type": "string"
    },
    "event_type": {
      "type": "string"
    },
    "target_id": {
      "type": "integer"
    },
    "target_type": {
      "type": "string"
    },
    "target_details": {
      "type": "string"
    },
  },
  "type": "object"
}
```

### GitLab Duo 관련 이벤트 {#gitlab-duo-related-events}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/239648)되었습니다.

{{< /history >}}

감사 이벤트가 GitLab Duo 에이전트 플랫폼과 관련되면 `details` 객체는 `duo_related` 필드가 `true`로 설정된 상태입니다.

다음 이벤트는 이 필드를 포함할 수 있습니다:

| 이벤트 유형                    | 설명                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| `application_setting_updated` | GitLab Duo 에이전트 플랫폼과 관련된 애플리케이션 설정이 업데이트됩니다. |
| `member_destroyed`            | GitLab Duo 에이전트 플랫폼 서비스 계정의 멤버십이 제거됩니다.   |

이 필드를 사용하여 서비스 계정 명명 패턴 대신 SIEM(Security Information and Event Management) 도구 또는 기타 외부 도구에서 GitLab Duo 에이전트 플랫폼 활동을 식별합니다.

### 복합 ID로 생성된 이벤트 {#events-created-with-a-composite-identity}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/240418)되었습니다.

{{< /history >}}

서비스 계정이 [복합 ID](../duo_agent_platform/composite_identity.md)를 사용하는 사람 사용자를 대신하여 작업을 수행하면 감사 이벤트는 서비스 계정에 속합니다:

- `author_id`은(는) 서비스 계정의 사용자 ID를 포함합니다.
- `author_name`은(는) `<service account name> on behalf of @<human username>`을(를) 포함하며 255자로 잘립니다. 이 값은 감사 이벤트 페이지 및 CSV 내보내기의 **작성자** 열에 나타납니다.

`details` 객체는 작업을 승인한 사람 사용자를 기록합니다:

| 필드                   | 설명                     |
|-------------------------|---------------------------------|
| `human_author_id`       | 사람 사용자의 사용자 ID       |
| `human_author_name`     | 사람 사용자의 이름          |
| `human_author_username` | 사람 사용자의 사용자 이름      |

이 필드는 스트리밍된 감사 이벤트에 포함되며 [감사 이벤트 API](../../api/audit_events.md)에서 반환하는 `details` 객체에 포함됩니다.

이 이벤트의 경우 `details` 객체의 `author_class` 필드는 `Gitlab::Audit::CompositeIdentityAuthor`를 포함합니다. 이 값을 사용하여 SIEM 또는 기타 외부 도구에서 복합 ID 이벤트를 식별합니다.

`ai_agent_session_started` 및 `ai_tool_invoked`와 같은 AI 에이전트 세션 이벤트는 또한 `human_author_*` 필드를 기록하지만 이 `author_class` 값을 사용하지 않습니다. 두 가지 종류의 이벤트를 일치시키려면 대신 `human_author_id`의 존재 여부를 필터링합니다.

사람 사용자가 작업을 수행하고 서비스 계정만 작업에 참여하는 경우(예: 사람 사용자가 서비스 계정을 머지 리퀘스트 검토자로 할당할 때) 감사 이벤트는 사람 사용자에게 속하며 `human_author_*` 필드는 추가되지 않습니다.

### 헤더 {#headers}

헤더는 다음과 같이 서식이 지정됩니다:

```plaintext
POST /logs HTTP/1.1
Host: <DESTINATION_HOST>
Content-Type: application/x-www-form-urlencoded
X-Gitlab-Event-Streaming-Token: <DESTINATION_TOKEN>
X-Gitlab-Audit-Event-Type: repository_git_operation
```

## 예: Git 작업 시 감사 이벤트 스트리밍 {#example-audit-event-streaming-on-git-operations}

인증된 사용자가 프로젝트의 원격 Git 리포지토리를 푸시, 풀 또는 클론할 때 스트리밍 감사 이벤트가 전송될 수 있습니다:

- [SSH 사용](../ssh.md).
- HTTP 또는 HTTPS 사용
- GitLab UI에서 **다운로드**({{< icon name="download" >}}) 사용

감사 이벤트는 로그인하지 않은 사용자에 대해 캡처되지 않습니다. 예를 들어 공개 프로젝트를 다운로드할 때입니다.

### 예: 배포 키를 사용한 Git over SSH 이벤트에 대한 감사 이벤트 페이로드 {#example-audit-event-payloads-for-git-over-ssh-events-with-deploy-key}

{{< history >}}

- `gl_key_type` 및 `gl_key_id` 필드는 `custom_message`에서 GitLab 19.3에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/244603)되었습니다.

{{< /history >}}

가져오기:

```json
{
  "id": "1",
  "author_id": -3,
  "entity_id": 29,
  "entity_type": "Project",
  "details": {
    "author_name": "deploy-key-name",
    "author_class": "DeployKey",
    "target_id": 29,
    "target_type": "Project",
    "target_details": "example-project",
    "custom_message": {
      "protocol": "ssh",
      "action": "git-upload-pack",
      "written_bytes": 1048576,
      "received_bytes": 2048,
      "gl_key_type": "deploy_key",
      "gl_key_id": 24
    },
    "ip_address": "127.0.0.1",
    "entity_path": "example-group/example-project"
  },
  "ip_address": "127.0.0.1",
  "author_name": "deploy-key-name",
  "entity_path": "example-group/example-project",
  "target_details": "example-project",
  "created_at": "2022-07-26T05:43:53.662Z",
  "target_type": "Project",
  "target_id": 29,
  "event_type": "repository_git_operation"
}
```

`custom_message` 객체는 Git 작업에 대한 데이터 전송 크기 필드를 포함합니다:

- `written_bytes`: Git 작업 중에 클라이언트에 전송된 바이트 수(예: 클론, 가져오기 또는 풀 중).
- `received_bytes`: Git 작업 중에 클라이언트로부터 수신된 바이트 수(예: 푸시 중).

바이트가 전송되지 않을 때(예: 데이터를 교환하기 전에 요청이 실패할 때) 이 필드는 생략됩니다.

`custom_message` 객체는 SSH 키 또는 배포 키로 인증된 Git 작업에 대한 주요 정보를 포함합니다:

- `gl_key_type`: 인증에 사용되는 키의 유형. 사용자 SSH 키의 경우 `key`이거나 배포 키의 경우 `deploy_key`입니다.
- `gl_key_id`: 인증에 사용되는 키의 ID.

작업이 키로 인증되지 않은 경우(예: 사용자 이름 및 암호가 있는 HTTP(S) 또는 배포 토큰) 이 필드는 생략됩니다.
