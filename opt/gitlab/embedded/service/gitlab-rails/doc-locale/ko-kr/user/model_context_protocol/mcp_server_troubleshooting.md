---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab MCP 서버의 일반적인 문제를 해결합니다.
title: GitLab MCP 서버 문제 해결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태: 정식 출시(GA)

{{< /details >}}

GitLab MCP 서버로 작업할 때 다음과 같은 문제가 발생할 수 있습니다.

## 오류: `403 Forbidden` {#error-403-forbidden}

GitLab MCP 서버를 시작할 때 이 오류가 발생할 수 있습니다. `POST /api/v4/mcp` 또는 `GET /api/v4/mcp`에서 OAuth 흐름이 완료된 후 `403 Forbidden`이(가) 반환될 때도 이 오류가 발생할 수 있습니다.

GitLab 19.4 이하 버전에서는 같은 문제가 대신 `404 Not Found`을(를) 반환합니다. 두 상태 코드의 원인은 같습니다.

이 문제를 해결하려면 [GitLab MCP 서버의 필수 조건](mcp_server.md#prerequisites)을(를) 충족하는지 확인하세요.

원인을 찾으려면 응답 본문의 메시지를 읽으세요. 관리자는 [`mcp.log`](../../administration/logs/_index.md#mcplog) 파일의 `denial_reason` 필드도 확인할 수 있습니다:

- `MCP server disabled for this instance` (`denial_reason`: `instance_setting_disabled`): GitLab Self-Managed에서 관리자가 인스턴스의 MCP 서버를 [해제](../../administration/settings/visibility_and_access_controls.md#allow-access-to-the-mcp-server)했습니다.
- `MCP server not enabled for any of your groups` (`denial_reason`: `no_enabled_namespace`): GitLab.com에서 사용자가 속한 최상위 그룹에 MCP 서버가 [활성화](../group/access_and_permissions.md#allow-access-to-the-mcp-server)되어 있지 않습니다.

> [!note]
> `404` 오류는 REST 기반 도구 호출(예: `404 Project Not Found`)에서 반환되며 JSON-RPC 응답 본문에 `isError: true`(으)로 나타나고 `mcp.log`의 `tool_status`에 `not_found`(으)로 설정됩니다. 기타 도구 호출 실패도 응답 본문에 `isError: true`(으)로 나타나고 `mcp.log`의 상황을 설명하는 `tool_status`(으)로 표시됩니다.

## 오류: `Server's protocol version is not supported: 2025-06-18` {#error-servers-protocol-version-is-not-supported-2025-06-18}

GitLab 18.6 이하 버전에서 MCP 클라이언트 라이브러리가 GitLab MCP 서버 프로토콜 사양을 지원하지 않을 때 이 오류가 발생할 수 있습니다.

이 문제를 해결하려면 AI 도구 공급자에게 클라이언트 구현을 업데이트하도록 요청하세요.

## 오류: `429 Too Many Requests` {#error-429-too-many-requests}

MCP 클라이언트가 작동을 멈추고 일반적인 HTTP 또는 연결 오류를 보고할 수 있으며, 속도 제한 기간이 재설정될 때까지 모든 요청이 실패합니다. 이는 속도 제한이 초과될 때 발생합니다(MCP 서버 속도 제한 또는 인증된 API 속도 제한). MCP 서버 요청이 두 제한에 모두 적용되기 때문입니다. GitLab이 요청이 MCP 서버에 도달하기 전에 거부하므로 도구가 실행되지 않습니다. [`rate_limited` 도구 결과](#error-rate_limited-tool-result)와 달리, 이것은 오류 결과를 전달하는 `200 OK`이 아닙니다.

응답은 HTTP `429`이며 콘텐츠 유형은 `text/plain`이고 기본적으로 본문은 `Retry later`입니다. JSON-RPC 메시지가 아니므로 MCP 클라이언트는 이를 MCP 응답으로 읽을 수 없습니다.

원인을 확인하려면 응답 헤더를 확인하세요:

- `RateLimit-Name`은 도달한 제한을 나타냅니다. GitLab Self-Managed에서 MCP 서버 제한은 `throttle_authenticated_mcp`입니다. 다른 모든 값은 일반 인증된 API 제한과 같은 다른 제한을 의미합니다.
- `Retry-After`은 다시 시도하기 전에 대기할 시간(초)입니다. 현재 기간의 남은 시간이며 전체 기간이 아닙니다. 클라이언트는 즉시 다시 시도하지 않고 이를 우선시해야 합니다.

응답은 또한 다른 [속도 제한 헤더](../../administration/settings/user_and_ip_rate_limits.md#response-headers)를 포함합니다.

제한에 도달하기 전에 성공적인 `200 OK` 응답에는 이미 `RateLimit-Remaining`이 포함되므로 헤더를 읽는 클라이언트나 프록시는 제한에 접근하는 것을 볼 수 있습니다.

관리자는 로그를 확인할 수도 있습니다:

- 거부된 요청은 [Workhorse 로그](../../administration/logs/_index.md#workhorse-logs)에 `status` `429` 및 `uri` `/api/v4/mcp`로 나타납니다. 항목에는 사용자나 제한 이름이 없습니다.
- 거부된 요청은 API에 도달하지 않으므로 `api_json.log` 또는 [`mcp.log`](../../administration/logs/_index.md#mcplog)에 나타나지 않습니다. 또한 다른 일부 GitLab 속도 제한과 달리 `auth.log`에 나타나지 않습니다.
- 계산되었지만 허용된 요청은 [`api_json.log`](../../administration/logs/_index.md#api_jsonlog)에 나타나며 `rate_limit_state` 필드에 `rack_request_mcp:authenticated_mcp:allow`이 포함됩니다. 이를 사용하여 제한을 소비하는 사용자를 파악합니다.

이 문제를 해결하려면 `Retry-After`에 표시된 시간(초) 동안 대기한 후 다시 시도하세요.

- GitLab.com에서는 MCP 요청에 요금제별 제한이 적용됩니다. 게시된 값은 [속도 제한](mcp_server.md#rate-limits)을 참조하세요.
- GitLab Self-Managed에서는 제한이 기본적으로 비활성화되어 있습니다. 활성화된 경우 관리자는 [제한을 상향하거나 비활성화](../../administration/settings/user_and_ip_rate_limits.md#enable-authenticated-mcp-server-request-rate-limit)할 수 있습니다.

## 오류: `rate_limited` 도구 결과 {#error-rate_limited-tool-result}

대신 HTTP `429 Too Many Requests` 응답을 받은 경우 [`429 Too Many Requests`](#error-429-too-many-requests)를 참조하세요.

MCP 서버 자체가 `200 OK`을(를) 반환했지만 도구 결과가 `isError: true`일 수 있습니다. 이는 도구 호출이 기본 GitLab API 엔드포인트(예: 검색 도구가 실행될 때의 검색 속도 제한)의 속도 제한을 초과할 때 발생합니다.

MCP 서버는 이 경우 `429 Too Many Requests`을(를) 반환하지 않습니다. 대신, 클라이언트 또는 언어 모델이 도구 실행 오류를 읽고 자체 수정할 수 있도록 결과에 보고된 도구 실행 오류로 API 실패를 분류하는 Model Context Protocol 사양을 따릅니다.

`content` 필드에는 다음과 같은 사람이 읽을 수 있는 메시지가 포함되어 있습니다:

```plaintext
Rate limited by search_rate_limit. Retry after 60 seconds.
```

`structuredContent` 필드에는 머신이 읽을 수 있는 재시도 세부 정보가 포함되어 있습니다:

```json
{
  "error": {
    "type": "rate_limited",
    "retry_after_seconds": 60,
    "limit": "search_rate_limit",
    "message": "This endpoint has been requested too many times. Try again later."
  }
}
```

이 문제를 해결하려면 기다린 후 도구 호출을 다시 시도하세요. MCP 클라이언트를 빌드할 때 메시지 텍스트와 일치하지 않으려면 `error.type == "rate_limited"`을(를) 확인하세요(표현이 변경될 수 있음). 단일 도구 호출이 두 개 이상을 소비할 수 있으므로 `limit`을(를) 사용하여 속도 제한을 식별하세요. 정확한 대기 시간이 아니라 안전한 상한으로 `retry_after_seconds`을(를) 취급하세요(전체 속도 제한 기간이지 현재 창에서 남은 시간이 아니기 때문).

> [!note]
> `retry_after_seconds` 및 `limit`은(는) GitLab에서 호출한 엔드포인트가 제공할 때만 표시됩니다. 항상 이러한 필드가 없는 응답을 처리하세요. 관리자는 개별 엔드포인트의 속도 제한을 변경할 수 있으므로 실제 값은 인스턴스마다 다릅니다.

## 오류: `403 Forbidden` 도구 결과(출처: `start_duo_session`) {#error-403-forbidden-tool-result-from-start_duo_session}

`start_duo_session` 도구를 호출할 때 `403 Forbidden`이라는 오류가 발생할 수 있습니다. MCP 서버는 `200 OK`을 반환하고 도구 결과는 `isError: true`이며 다음 메시지가 `content` 필드에 포함됩니다:

```plaintext
403 Forbidden
```

이 문제는 프로젝트에서 플로우를 실행할 수 없을 때 발생합니다. `start_duo_session`은 항상 CI 작업에서 실행되는 세션으로 플로우를 시작하며, 프로젝트에서 해당 플로우를 실행할 수 있는 권한이 있어야 합니다.

이 이슈를 해결하려면 다음 중 하나를 수행하세요.

- GitLab Duo Agent Platform에 액세스할 수 없는 경우 [GitLab Duo Agent Platform의 전제 조건](../duo_agent_platform/_index.md#prerequisites)을 충족하세요.
- 프로젝트에서 Reporter 역할 이하인 경우 프로젝트 Owner 또는 Maintainer에게 최소 Developer 역할을 요청하세요.
- 기본 플로우가 비활성화된 경우 프로젝트 Maintainer 또는 Owner 또는 최상위 그룹 Owner에게 [기본 플로우 활성화](../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off)를 요청하세요.
- 플로우가 베타 버전인 경우 최상위 그룹 Owner에게 [베타 및 실험 기능 활성화](../duo_agent_platform/turn_on_off.md#turn-on-beta-and-experimental-features)를 요청하세요.

GitLab Duo Agent Platform을 사용하지 않는 경우 MCP 클라이언트에서 해당 도구를 숨길 수 있습니다. 클라이언트가 사용자 지정 헤더를 지원하는 경우 `X-Gitlab-Enabled-Mcp-Server-Toolsets` 헤더를 `duo_agent_platform`을 포함하지 않는 목록으로 보내세요. 자세한 내용은 [도구 그룹 선택(도구 세트)](mcp_server.md#select-tool-groups-toolsets)을 참조하세요.

## Cursor에서 GitLab MCP 서버 문제 해결 {#troubleshoot-the-gitlab-mcp-server-in-cursor}

1. Cursor에서 출력 보기를 열려면 다음 중 하나를 수행합니다:
   - **보기** > **출력**(으)로 이동합니다.
   - macOS에서 <kbd>Command</kbd>+<kbd>Shift</kbd>+<kbd>U</kbd> 키를 누르세요.
   - Windows 또는 Linux에서 <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>U</kbd> 키를 누르세요.
1. 출력 보기에서 **MCP:SERVERNAME**(을)를 선택합니다. 이름은 MCP 구성 값에 따라 다릅니다. `GitLab`(의) 예제는 `MCP: user-GitLab`(으)로 나타납니다.
1. 버그를 보고할 때 출력을 이슈 템플릿의 로그 섹션에 복사하세요.

## CLI에서 mcp-remote를 사용하여 GitLab MCP 서버 문제 해결 {#troubleshoot-the-gitlab-mcp-server-on-the-cli-with-mcp-remote}

1. [Node.js](https://nodejs.org/en/download) 버전 20 이상을 설치합니다.
1. IDE 및 데스크톱 클라이언트와 정확히 같은 명령을 테스트하려면:
   1. MCP 구성을 추출합니다.
   1. `npx` 명령 문자열을 한 줄로 조합합니다.
   1. 명령 문자열을 실행합니다.

   ```shell
   rm -rf ~/.mcp-auth/mcp-remote*

   npx -y mcp-remote@latest https://gitlab.example.com/api/v4/mcp --static-oauth-client-metadata '{"scope": "mcp"}'
   ```

1. `--debug` 매개변수를 추가하여 더 자세한 출력을 기록합니다:

   ```shell
   rm -rf ~/.mcp-auth/mcp-remote*

   npx -y mcp-remote@latest https://gitlab.example.com/api/v4/mcp --static-oauth-client-metadata '{"scope": "mcp"}' --debug
   ```

1. 선택사항. `mcp-remote-client` 실행 파일을 직접 실행합니다.

   ```shell
   rm -rf ~/.mcp-auth/mcp-remote*

   npx -p mcp-remote@latest mcp-remote-client https://gitlab.example.com/api/v4/mcp --static-oauth-client-metadata '{"scope": "mcp"}'
   ```

1. 선택사항. 버전별 버그가 발생하면 `mcp-remote` 모듈의 버전을 특정 버전으로 고정합니다. 예를 들어, `mcp-remote@0.1.26`을(를) 사용하여 버전을 `0.1.26`으(로) 고정합니다.

   > [!note]
   > 보안상의 이유로 가능하면 버전을 고정하지 않아야 합니다.

## Claude Desktop에서 GitLab MCP 서버 문제 해결 {#troubleshoot-gitlab-mcp-server-with-claude-desktop}

설치된 [Node.js](https://nodejs.org/en/download) 버전을 확인합니다. Claude Desktop에는 Node.js 버전 20 이상이 필요합니다.

```shell
for n in $(which -a node); do echo "$n" && $n -v; done
```

## MCP 인증 캐시 삭제 {#delete-mcp-authentication-caches}

MCP 인증은 로컬에 많이 캐시됩니다. 문제를 해결하는 동안 거짓 양성이 발생할 수 있습니다. 이를 방지하려면 문제 해결 중에 캐시 디렉토리를 삭제하세요:

```shell
rm -rf ~/.mcp-auth/mcp-remote*
```

## 디버깅 및 개발 도구 {#debugging-and-development-tools}

[MCP Inspector](https://modelcontextprotocol.io/legacy/tools/inspector)는 MCP 서버를 테스트하고 디버깅하기 위한 대화형 개발자 도구입니다. 이 도구를 실행하려면 명령줄을 사용하고 웹 인터페이스에 액세스하여 GitLab MCP 서버를 검사합니다.

```shell
npx -y @modelcontextprotocol/inspector npx
```
