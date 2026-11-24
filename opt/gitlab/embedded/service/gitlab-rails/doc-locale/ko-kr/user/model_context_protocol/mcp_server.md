---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab MCP 서버를 사용하여 AI 도구를 GitLab 인스턴스에 연결합니다.
title: GitLab MCP 서버
---

{{< details >}}

- 티어:  Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  정식 출시(GA)

{{< /details >}}

{{< history >}}

- `mcp_server` 및 `oauth_dynamic_client_registration`라는 [기능 플래그](../../administration/feature_flags/_index.md)로 GitLab 18.3에서 [실험적](../../policy/development_stages_support.md#experiment)으로 도입되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.6에서 실험적에서 [베타](../../policy/development_stages_support.md#beta)로 변경되었습니다. 기능 플래그 [`mcp_server`](https://gitlab.com/gitlab-org/gitlab/-/issues/556448) 및 [`oauth_dynamic_client_registration`](https://gitlab.com/gitlab-org/gitlab/-/issues/555942)이 제거되었습니다.
- `2025-03-26` 및 `2025-06-18` MCP 프로토콜 사양에 대한 지원이 GitLab 18.7에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/581459)되었습니다.
- `2025-11-25` MCP 프로토콜 사양에 대한 지원이 GitLab 18.7에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/216219)되었습니다.
- GitLab 19.2에서 별도 설정으로 [변경](https://gitlab.com/gitlab-org/gitlab/-/work_items/590729)되었으며 GitLab Premium에서 GitLab Free로 [이동](https://gitlab.com/groups/gitlab-org/-/work_items/21183)되었습니다.
- 도구 집합 선택 기능이 GitLab 19.5에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/work_items/607755)되었습니다.
- `duo_agent_platform` 도구 집합이 GitLab 19.5에서 [기본적으로 포함](https://gitlab.com/gitlab-org/gitlab/-/work_items/630992)되어 있습니다.
- GitLab 19.5에서 [베타](../../policy/development_stages_support.md#beta)에서 [일반 공급](../../policy/development_stages_support.md#generally-available)으로 변경되었습니다.
- `duo_agent_platform` 도구 집합은 GitLab 19.5에서 GitLab Duo Agent Platform을 사용할 수 있을 때만 [나열](https://gitlab.com/gitlab-org/gitlab/-/work_items/631747)됩니다.
- `code_security` 도구는 GitLab 19.5에서 각 도구 뒤의 라이선스 기능을 사용할 수 있을 때만 [나열](https://gitlab.com/gitlab-org/gitlab/-/work_items/629267)됩니다.
- `orbit` 도구 집합이 GitLab 19.6에서 [추가](https://gitlab.com/gitlab-org/orbit/knowledge-graph/-/work_items/1294)되었습니다.

{{< /history >}}

> [!warning]
> 이 기능에 대한 피드백을 제공하려면 [이슈 630189](https://gitlab.com/gitlab-org/gitlab/-/issues/630189)에 댓글을 남기세요.

GitLab [Model Context Protocol](https://modelcontextprotocol.io/)(MCP) 서버를 사용하면 AI 도구 및 애플리케이션을 GitLab 인스턴스에 안전하게 연결할 수 있습니다. Claude Desktop, Claude Code, Cursor 및 기타 MCP 호환 도구와 같은 AI 어시스턴트는 GitLab 데이터에 액세스하고 사용자를 대신하여 작업을 수행합니다.

GitLab MCP 서버는 AI 도구를 위한 표준화된 방법을 제공합니다.

- GitLab 프로젝트 정보에 액세스합니다.
- 이슈 및 머지 리퀘스트 데이터를 검색합니다.
- GitLab API와 안전하게 상호 작용합니다.
- AI 어시스턴트를 통해 GitLab에 특정된 작업을 수행합니다.

GitLab MCP 서버는 [OAuth 2.0 Dynamic Client Registration](https://tools.ietf.org/html/rfc7591)을 지원하므로 AI 도구가 GitLab 인스턴스에 등록할 수 있습니다. AI 도구가 처음으로 GitLab MCP 서버에 연결할 때 도구는 다음을 수행합니다.

1. OAuth 애플리케이션으로 등록합니다.
1. GitLab 데이터에 액세스하는 권한을 요청합니다.
1. 안전한 API 액세스를 위한 액세스 토큰을 수신합니다.

단계별 데모는 [GitLab Duo Agent Platform - GitLab MCP 서버](https://gitlab.navattic.com/gitlab-mcp-server)를 참조하세요.
<!-- Demo published on 2025-09-11 -->

## 사전 요구 사항 {#prerequisites}

- MCP 서버에 대한 액세스를 허용합니다.
  - GitLab.com에서 [최상위 그룹에 대해](../group/access_and_permissions.md#allow-access-to-the-mcp-server) 설정합니다.
  - GitLab Self-Managed 및 GitLab Dedicated에서 [인스턴스에 대해](../../administration/settings/visibility_and_access_controls.md#allow-access-to-the-mcp-server) 설정합니다.

## 인증 {#authentication}

GitLab MCP 서버는 다음 토큰을 허용합니다:

- `mcp` 범위가 있는 OAuth 액세스 토큰입니다. MCP 클라이언트는 OAuth 흐름을 통해 이 토큰을 얻으며, 동적 클라이언트 등록 또는 [사전 등록된 OAuth 애플리케이션](#reuse-a-single-oauth-application)을 사용하여 연결합니다.
- [세분화된 개인 액세스 토큰](../../auth/tokens/fine_grained_access_tokens.md)([MCP 도구 리소스 및 실행 권한](../../auth/tokens/fine_grained_access_tokens_rest.md#mcp-tool) 포함)입니다.

이 토큰들은 `mcp` 범위를 가질 수 없으므로 GitLab MCP 서버가 이들을 거부합니다. `api` 같은 범위가 있어도 마찬가지입니다:

- 레거시 개인 액세스 토큰
- 프로젝트 액세스 토큰
- 그룹 액세스 토큰

이 토큰 중 하나를 사용하는 경우 GitLab MCP 서버는 `403 Forbidden` 오류와 함께 `insufficient_scope`를 반환합니다. 응답은 `mcp` 범위를 이름으로 지정하며, 이 범위는 이 토큰들에 추가할 수 없습니다. 이 인증 방법에 대한 지원은 [이슈 586184](https://gitlab.com/gitlab-org/gitlab/-/work_items/586184)에서 제안되었습니다.

## 클라이언트를 GitLab MCP 서버에 연결 {#connect-a-client-to-the-gitlab-mcp-server}

GitLab MCP 서버는 두 가지 전송 유형을 지원합니다.

- **HTTP 전송 (권장)**: 추가 종속성 없이 직접 연결합니다.
- **`mcp-remote`를 사용한 stdio 전송**: 프록시를 통한 연결(Node.js 필수)입니다.

일반적인 AI 도구는 `mcpServers` 키에 대한 JSON 구성 형식을 지원하며 GitLab MCP 서버 설정을 구성하는 다양한 방법을 제공합니다.

서버에서 반환하는 도구를 제한하려면 [도구 그룹 선택(도구 집합)](#select-tool-groups-toolsets)을 참조하세요.

### HTTP 전송 (권장) {#http-transport-recommended}

{{< history >}}

- GitLab 18.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/577575)되었습니다.
- 도구 접두사가 GitLab 18.11에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/230406)되었습니다.

{{< /history >}}

HTTP 전송을 사용하여 GitLab MCP 서버를 구성하려면 다음 형식을 사용합니다.

- `<gitlab.example.com>`을 다음으로 바꿉니다.
  - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
  - GitLab.com에서는 `gitlab.com`입니다.

```json
{
  "mcpServers": {
    "GitLab": {
      "type": "http",
      "url": "https://<gitlab.example.com>/api/v4/mcp"
    }
  }
}
```

`X-Gitlab-Mcp-Server-Tool-Name-Prefix` HTTP 헤더를 구성하여 도구 이름에 접두사를 추가할 수 있습니다. 접두사를 지정하면 다른 MCP 서버 또는 구성의 여러 GitLab 인스턴스와 도구 이름 충돌을 방지할 수 있습니다.

접두사가 이 제한을 초과하면 처음 32자로 잘립니다.

```json
{
  "mcpServers": {
    "GitLab": {
      "type": "http",
      "url": "https://<gitlab.example.com>/api/v4/mcp",
      "headers": {
        "X-Gitlab-Mcp-Server-Tool-Name-Prefix": "gitlab_"
      }
    }
  }
}
```

### 도구 그룹 선택(도구 집합) {#select-tool-groups-toolsets}

GitLab MCP 서버에서 반환하는 도구를 특정 그룹으로 제한하려면 `X-Gitlab-Enabled-Mcp-Server-Toolsets` HTTP 헤더를 쉼표로 구분된 도구 집합 이름 목록으로 구성합니다.

사용 가능한 도구 집합:

| 도구 집합 | 기본적으로 포함됨 |
|---------|----------------------|
| `meta` | 항상 |
| `core` | 예 |
| `merge_requests` | 예 |
| `work_items` | 예 |
| `repository` | 예 |
| `ci` | 예 |
| `duo_agent_platform` | GitLab Duo Agent Platform을 사용할 수 있는 경우 |
| `wikis` | 아니요(옵트인) |
| `code_security` | 아니요(옵트인) |
| `orbit` | 아니요(옵트인) |

`duo_agent_platform` 도구는 GitLab Duo Agent Platform을 사용할 수 있을 때만 나열됩니다. 이는 헤더에서 도구 집합을 요청하거나 헤더를 `all`로 설정한 경우에도 적용됩니다.

GitLab.com에서는 다음이 모두 참이어야 합니다:

- GitLab Duo Agent Platform이 켜져 있는 Premium 또는 Ultimate 플랜의 최상위 그룹에 속하거나, GitLab Credits를 통해 GitLab Duo Agent Platform을 사용할 수 있어야 합니다.
- GitLab Duo Agent Platform을 사용할 권한이 있어야 합니다. 예를 들어, 필요한 사용자 자격이 있어야 합니다.

GitLab Self-Managed 및 GitLab Dedicated에서는 다음이 모두 참이어야 합니다:

- GitLab Duo가 인스턴스에 대해 **항상 꺼짐**으로 설정되어 있지 않아야 합니다. **기본적으로 꺼짐** 설정으로, GitLab Duo를 켜는 그룹이 도구를 사용할 수 있도록 도구가 나열됩니다.
- 인스턴스에 GitLab Duo Agent Platform이 포함된 라이선스가 있거나 GitLab Credits가 있어야 합니다.
- GitLab Duo Agent Platform이 조직에 대해 켜져 있어야 합니다.
- GitLab Duo Agent Platform을 사용할 권한이 있어야 합니다. 예를 들어, 필요한 사용자 자격이 있어야 합니다.

자세한 내용은 [GitLab Duo Agent Platform 사전 요구 사항](../duo_agent_platform/_index.md#prerequisites) 및 [GitLab Duo Agent Platform을 켜고 끄는 방법](../duo_agent_platform/turn_on_off.md)을 참조하세요.

`code_security` 도구는 각 도구 뒤의 기능을 사용할 수 있을 때만 나열됩니다. 이는 헤더에서 도구 집합을 요청하거나 헤더를 `all`로 설정한 경우에도 적용됩니다.

- `list_vulnerabilities`, `get_vulnerability`, `save_vulnerability`은 보안 대시보드가 필요합니다.
- `attach_scan_profile`은 보안 검사 프로필이 필요합니다.

둘 다 Ultimate 기능입니다. GitLab.com에서는 Ultimate 플랜이 있는 최상위 그룹에 속한 경우 도구가 나열되며, Ultimate 평가판도 포함됩니다. 해당 그룹의 프로젝트에 대한 액세스도 계산됩니다. GitLab Self-Managed 및 GitLab Dedicated에서는 인스턴스 라이선스에 기능이 포함되어 있으면 도구가 나열됩니다.

`orbit` 도구 집합은 각 Orbit 명령에 대한 도구가 하나씩 있으며, 예를 들어 `query_graph`입니다. Orbit 서버는 도구 이름, 설명 및 입력 스키마를 설정합니다. 도구는 [Orbit 요구 사항](https://docs.gitlab.com/orbit/)을 충족할 때만 나열되고 실행됩니다.

Orbit 도구는 `orbit` 도구 집합을 요청하거나 헤더를 `all`로 설정할 때만 나열됩니다. `X-Gitlab-Enabled-Mcp-Server-Tools`에서 Orbit 도구 이름을 지정해도 나열되지 않습니다.

도구를 나열하는 것이 액세스 권한을 부여하지는 않습니다. 각 도구는 호출할 때 여전히 프로젝트 및 네임스페이스 권한을 확인합니다.

옵트인 도구 집합을 포함하려면 헤더 값에 명시적으로 추가합니다. 모든 도구 집합을 요청하려면(모든 옵트인 도구 집합 포함) 헤더를 `all`로 설정합니다.

두 헤더를 모두 생략하면 서버는 기본 도구 집합을 반환합니다. 도구 집합 헤더는 생략하지만 `X-Gitlab-Enabled-Mcp-Server-Tools`을 설정하는 경우 서버는 이름을 지정한 도구만 반환하며 기본 도구 집합이나 `meta` 도구는 반환하지 않습니다.

`X-Gitlab-Enabled-Mcp-Server-Toolsets` 헤더의 도구 집합 이름은 대소문자를 구분하지 않으므로 `ci`, `CI`, `Ci` 모두 허용됩니다.

헤더에 인식할 수 없는 도구 집합 이름이 있으면 `400` 오류가 반환됩니다.

`X-Gitlab-Enabled-Mcp-Server-Tools`도 설정하는 경우 서버는 두 목록의 합집합을 반환하며, 교집합은 아닙니다. 두 헤더를 모두 설정하면 어느 헤더 하나보다 더 적은 도구가 반환되지 않습니다.

```json
{
  "mcpServers": {
    "GitLab": {
      "type": "http",
      "url": "https://<gitlab.example.com>/api/v4/mcp",
      "headers": {
        "X-Gitlab-Enabled-Mcp-Server-Toolsets": "core,work_items"
      }
    }
  }
}
```

이 헤더를 설정하는 방식은 클라이언트가 어떻게 구성되어 있는지에 따라 다릅니다. 이 페이지의 클라이언트 섹션에서 구성 형식을 확인하세요.

- `headers` 키를 허용하는 JSON 객체로 구성된 클라이언트(Cursor 및 Kiro 포함): 이전 예제를 사용합니다.
- opencode는 최상위 `mcp` 키와 `"type": "remote"`를 사용하므로, [OpenCode를 GitLab MCP 서버에 연결](#connect-opencode-to-the-gitlab-mcp-server)하는 서버 정의에 `headers` 키를 추가합니다.
- Claude Code(명령줄에서 구성됨): `--header`을 전달합니다.

  ```shell
  claude mcp add -s user --transport http GitLab https://<gitlab.example.com>/api/v4/mcp \
    --header "X-Gitlab-Enabled-Mcp-Server-Toolsets: core,work_items"
  ```

- `mcp-remote`을 통해 연결하는 클라이언트(Claude Desktop 및 Zed 포함): `--header`을 인수로 전달합니다.

  ```json
  {
    "mcpServers": {
      "GitLab": {
        "command": "npx",
        "args": [
          "-y", "mcp-remote", "https://<gitlab.example.com>/api/v4/mcp",
          "--header", "X-Gitlab-Enabled-Mcp-Server-Toolsets: core,work_items"
        ]
      }
    }
  }
  ```

  Windows에서 `args` 내부의 공백은 `npx`가 호출될 때 이스케이프되지 않으므로 헤더 값이 손상됩니다. 값을 환경 변수에 넣고 콜론 뒤의 공백을 생략합니다:

  ```json
  {
    "mcpServers": {
      "GitLab": {
        "command": "npx",
        "args": [
          "-y", "mcp-remote", "https://<gitlab.example.com>/api/v4/mcp",
          "--header", "X-Gitlab-Enabled-Mcp-Server-Toolsets:${GITLAB_TOOLSETS}"
        ],
        "env": {
          "GITLAB_TOOLSETS": "core,work_items"
        }
      }
    }
  }
  ```

Gemini Code Assist, Gemini CLI, GitHub Copilot in VS Code, OpenAI Codex를 포함한 다른 클라이언트는 자체 구성 형식을 사용합니다. 사용자 정의 HTTP 헤더를 보내는 방법에 대한 클라이언트 설명서를 확인하세요.

### `mcp-remote`를 사용한 stdio 전송 {#stdio-transport-with-mcp-remote}

전제 조건:

- Node.js 버전 20 이상을 설치합니다.

stdio 전송을 사용하여 GitLab MCP 서버를 구성하려면 다음 형식을 사용합니다.

- `"command":` 매개 변수의 경우 `npx`가 전역 대신 로컬로 설치된 경우 `npx`에 대한 전체 경로를 제공합니다.
- `<gitlab.example.com>`을 다음으로 바꿉니다.
  - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
  - GitLab.com에서는 `gitlab.com`입니다.

```json
{
  "mcpServers": {
    "GitLab": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://<gitlab.example.com>/api/v4/mcp"
      ]
    }
  }
}
```

## Cursor를 GitLab MCP 서버에 연결 {#connect-cursor-to-the-gitlab-mcp-server}

Cursor는 HTTP 전송을 사용하여 추가 종속성 없이 직접 연결합니다. Cursor에서 GitLab MCP 서버를 구성하려면 다음을 수행합니다.

1. Cursor에서 **설정** > **Cursor 설정** > **도구 및 MCP**로 이동합니다.
1. **MCP 서버 설치** 아래에서 **새 MCP 서버**를 선택합니다.
1. 열린 `mcp.json` 파일의 `mcpServers` 키에 다음 정의를 추가합니다.
   - `<gitlab.example.com>`을 다음으로 바꿉니다.
     - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
     - GitLab.com에서는 `gitlab.com`입니다.

   ```json
   {
     "mcpServers": {
       "GitLab": {
          "type": "http",
          "url": "https://<gitlab.example.com>/api/v4/mcp"
       }
     }
   }
   ```

1. 파일을 저장하고 브라우저에서 OAuth 권한 부여 페이지가 열 때까지 기다립니다.

   이 작업이 수행되지 않으면 Cursor를 닫고 다시 시작합니다.
1. 브라우저에서 권한 부여 요청을 검토하고 승인합니다.

이제 새 채팅을 시작하고 [사용 가능한 도구](mcp_server_tools.md)에 따라 질문할 수 있습니다.

> [!warning]
> 이러한 도구를 사용하면 프롬프트 인젝션에서 보호할 책임이 있습니다. 극도의 주의를 기울이거나 신뢰할 수 있는 GitLab 개체에만 MCP 도구를 사용합니다.

## Amazon Q Developer를 GitLab MCP 서버에 연결 {#connect-amazon-q-developer-to-the-gitlab-mcp-server}

Amazon Q Developer는 `mcp-remote` 프록시를 통해 stdio 전송을 사용합니다. JSON 파일이 아니라 양식에서 서버를 구성합니다.

전제 조건:

- Node.js 버전 20 이상을 설치합니다.

Amazon Q Developer에서 GitLab MCP 서버를 구성하려면:

1. Amazon Q 패널에서 MCP 서버 설정으로 이동하여 서버를 추가합니다.
1. 양식을 작성합니다:
   - **범위**의 경우 **전역**을 선택하여 서버를 어디서나 사용하거나, **이 워크스페이스**를 선택하여 한 워크스페이스로 제한합니다.
   - **이름**의 경우 `gitlab`을 입력합니다.
   - **전송**의 경우 `stdio`을 선택합니다.
   - **명령**의 경우 `npx`을 입력합니다. `npx`이 전역이 아닌 로컬에 설치된 경우 `npx`의 전체 경로를 제공합니다.
   - **인수**의 경우 세 개의 개별 인수를 추가합니다: `-y`, `mcp-remote`, `https://<gitlab.example.com>/api/v4/mcp`. `<gitlab.example.com>`을 다음으로 바꿉니다.
     - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
     - GitLab.com에서는 `gitlab.com`입니다.
   - **시간 초과**의 경우 `60`을 입력합니다.
1. 구성을 저장합니다.
1. 브라우저에서 권한 부여 요청을 검토하고 승인합니다.

`mcp-remote`을 특정 버전으로 고정하지 마세요. 고정은 OAuth 범위가 요청된 방식의 해결 방법이었으며, 서버는 이제 동적 클라이언트 등록 중에 해당 범위를 기본값으로 지정합니다. 고정된 프록시는 업스트림 수정 사항을 놓칩니다.

이제 새 채팅을 시작하고 [사용 가능한 도구](mcp_server_tools.md)에 따라 질문할 수 있습니다.

> [!warning]
> 이러한 도구를 사용하면 프롬프트 인젝션에서 보호할 책임이 있습니다. 극도의 주의를 기울이거나 신뢰할 수 있는 GitLab 개체에만 MCP 도구를 사용합니다.

## Claude Code를 GitLab MCP 서버에 연결 {#connect-claude-code-to-the-gitlab-mcp-server}

Claude Code는 HTTP 전송을 사용하여 추가 종속성 없이 직접 연결합니다. Claude Code에서 GitLab MCP 서버를 구성하려면 다음을 수행합니다.

1. 터미널에서 CLI를 사용하여 GitLab MCP 서버를 추가합니다.
   - `<gitlab.example.com>`을 다음으로 바꿉니다.
     - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
     - GitLab.com에서는 `gitlab.com`입니다.

   ```shell
   claude mcp add -s user --transport http GitLab https://<gitlab.example.com>/api/v4/mcp
   ```

   `-s user` 범위는 모든 프로젝트에서 서버를 사용할 수 있게 합니다. 이것이 없으면 서버가 `local` 범위에서 추가되며 명령을 실행한 디렉터리에서만 사용할 수 있습니다.

   GitLab MCP 서버를 이미 구성한 경우 `claude mcp add`은 덮어쓰지 않습니다. 기존 서버를 나열하고 GitLab 항목이 사용하는 범위를 확인합니다:

   ```shell
   claude mcp list
   ```

   해당 범위에서 기존 항목을 제거한 다음 다시 추가합니다. 이전 버전의 지침을 따라 추가된 항목은 `local` 범위에 있으며, `-s` 플래그가 지정되지 않았으므로 `local` 항목은 같은 이름의 `user` 항목보다 우선합니다.

   ```shell
   claude mcp remove GitLab -s local
   ```

1. Claude Code를 시작합니다.

   ```shell
   claude
   ```

1. GitLab MCP 서버로 인증합니다.
   - 채팅에서 `/mcp`를 입력합니다.
   - 목록에서 GitLab 서버를 선택합니다.
   - 브라우저에서 권한 부여 요청을 검토하고 승인합니다.

1. 선택 사항입니다. 연결을 확인하려면 `/mcp`를 다시 입력합니다. GitLab 서버가 연결됨으로 표시되어야 합니다.

이제 새 채팅을 시작하고 [사용 가능한 도구](mcp_server_tools.md)에 따라 질문할 수 있습니다.

> [!warning]
> 이러한 도구를 사용하면 프롬프트 인젝션에서 보호할 책임이 있습니다. 극도의 주의를 기울이거나 신뢰할 수 있는 GitLab 개체에만 MCP 도구를 사용합니다.

## Claude Desktop을 GitLab MCP 서버에 연결 {#connect-claude-desktop-to-the-gitlab-mcp-server}

전제 조건:

- Node.js 버전 20 이상을 설치합니다.
- `PATH` 환경 변수에서 Node.js를 전역으로 사용할 수 있습니다(`which -a node`).

Claude Desktop에서 GitLab MCP 서버를 구성하려면 다음을 수행합니다.

1. Claude Desktop을 엽니다.
1. 구성 파일을 편집합니다. 다음 중 하나를 수행할 수 있습니다.
   - Claude Desktop에서 **설정** > **개발자** > **구성 편집**으로 이동합니다.
   - macOS에서 `~/Library/Application Support/Claude/claude_desktop_config.json` 파일을 엽니다.
1. GitLab MCP 서버에 대해 이 항목을 추가하고 필요에 따라 편집합니다.
   - `"command":` 매개 변수의 경우 `npx`가 전역 대신 로컬로 설치된 경우 `npx`에 대한 전체 경로를 제공합니다.
   - `<gitlab.example.com>`을 다음으로 바꿉니다.
     - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
     - GitLab.com에서는 `GitLab.com`입니다.

   ```json
   {
     "mcpServers": {
       "GitLab": {
         "command": "npx",
         "args": [
           "-y",
           "mcp-remote",
           "https://<gitlab.example.com>/api/v4/mcp"
         ]
       }
     }
   }
   ```

1. 구성을 저장하고 Claude Desktop을 다시 시작합니다.
1. 처음 연결할 때 Claude Desktop은 OAuth를 위해 브라우저 창을 엽니다. 요청을 검토하고 승인합니다.
1. **설정** > **개발자**로 이동하여 새 GitLab MCP 구성을 확인합니다.
1. **설정** > **커넥터**로 이동하여 연결된 GitLab MCP 서버를 검사합니다.

이제 새 채팅을 시작하고 [사용 가능한 도구](mcp_server_tools.md)에 따라 질문할 수 있습니다.

> [!warning]
> 이러한 도구를 사용하면 프롬프트 인젝션에서 보호할 책임이 있습니다. 극도의 주의를 기울이거나 신뢰할 수 있는 GitLab 개체에만 MCP 도구를 사용합니다.

## Gemini Code Assist 및 Gemini CLI를 GitLab MCP 서버에 연결 {#connect-gemini-code-assist-and-gemini-cli-to-the-gitlab-mcp-server}

Gemini Code Assist 및 Gemini CLI는 HTTP 전송을 사용하여 추가 종속성 없이 직접 연결합니다. Gemini Code Assist 또는 Gemini CLI에서 GitLab MCP 서버를 구성하려면 다음을 수행합니다.

1. `~/.gemini/settings.json`을 편집하고 GitLab MCP 서버를 추가합니다.
   - `<gitlab.example.com>`을 다음으로 바꿉니다.
     - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
     - GitLab.com에서는 `gitlab.com`입니다.

   ```json
   {
     "mcpServers": {
       "GitLab": {
         "httpUrl": "https://<gitlab.example.com>/api/v4/mcp"
       }
     }
   }
   ```

1. Gemini Code Assist 또는 Gemini CLI에서 `/mcp auth GitLab` 명령을 실행합니다.

   OAuth 권한 부여 페이지가 표시되어야 합니다. 그렇지 않으면 Gemini Code Assist 또는 Gemini CLI를 다시 시작합니다.

1. 브라우저에서 권한 부여 요청을 검토하고 승인합니다.

이제 새 채팅을 시작하고 [사용 가능한 도구](mcp_server_tools.md)에 따라 질문할 수 있습니다.

> [!warning]
> 이러한 도구를 사용하면 프롬프트 인젝션에서 보호할 책임이 있습니다. 극도의 주의를 기울이거나 신뢰할 수 있는 GitLab 개체에만 MCP 도구를 사용합니다.

## GitHub Copilot in VS Code를 GitLab MCP 서버에 연결 {#connect-github-copilot-in-vs-code-to-the-gitlab-mcp-server}

GitHub Copilot은 HTTP 전송을 사용하여 추가 종속성 없이 직접 연결합니다. GitHub Copilot in VS Code에서 GitLab MCP 서버를 구성하려면 다음을 수행합니다.

1. VS Code에서 Command Palette를 엽니다.
   - macOS에서 <kbd>Command</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>를 누릅니다.
   - Windows 또는 Linux에서 <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>를 누릅니다.
1. `MCP: Add Server`를 입력하고 <kbd>Enter</kbd>를 누릅니다.
1. 서버 유형으로 **HTTP**를 선택합니다.
1. 서버 URL로 `https://<gitlab.example.com>/api/v4/mcp`를 입력합니다.
   - `<gitlab.example.com>`을 다음으로 바꿉니다.
     - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
     - GitLab.com에서는 `gitlab.com`입니다.
1. 서버 ID로 `GitLab`을 입력합니다.
1. 구성을 전역으로 또는 `vscode/mcp.json` 워크스페이스에 저장합니다.

   OAuth 권한 부여 페이지가 표시되어야 합니다. 그렇지 않으면 명령 팔렛트를 열고 **MCP: List Servers**(서버 나열)을 검색하여 상태를 확인하거나 서버를 다시 시작합니다.

1. 브라우저에서 권한 부여 요청을 검토하고 승인합니다.

이제 새 채팅을 시작하고 [사용 가능한 도구](mcp_server_tools.md)에 따라 질문할 수 있습니다.

> [!warning]
> 이러한 도구를 사용하면 프롬프트 인젝션에서 보호할 책임이 있습니다. 극도의 주의를 기울이거나 신뢰할 수 있는 GitLab 개체에만 MCP 도구를 사용합니다.

## Kiro IDE 및 CLI를 GitLab MCP 서버에 연결 {#connect-kiro-ide-and-cli-to-the-gitlab-mcp-server}

Kiro IDE 및 CLI는 HTTP 전송을 사용하여 추가 종속성 없이 직접 연결합니다. Kiro IDE 또는 CLI에서 GitLab MCP 서버를 구성하려면 다음을 수행합니다.

1. `~/.kiro/settings/mcp.json`을 편집하고 GitLab MCP 서버를 추가합니다.
   - `<gitlab.example.com>`을 다음으로 바꿉니다.
     - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
     - GitLab.com에서는 `gitlab.com`입니다.

   ```json
   {
     "mcpServers": {
       "GitLab": {
         "type": "http",
         "url": "https://<gitlab.example.com>/api/v4/mcp"
       }
     }
   }
   ```

1. 구성을 저장합니다.

   OAuth 권한 부여 페이지가 표시되어야 합니다. 그렇지 않으면 Kiro CLI를 열고 `/mcp` 명령을 실행합니다.

1. 브라우저에서 권한 부여 요청을 검토하고 승인합니다.

이제 새 채팅을 시작하고 [사용 가능한 도구](mcp_server_tools.md)에 따라 질문할 수 있습니다.

> [!warning]
> 이러한 도구를 사용하면 프롬프트 인젝션에서 보호할 책임이 있습니다. 극도의 주의를 기울이거나 신뢰할 수 있는 GitLab 개체에만 MCP 도구를 사용합니다.

## OpenCode를 GitLab MCP 서버에 연결 {#connect-opencode-to-the-gitlab-mcp-server}

OpenCode는 추가 종속성 없이 직접 연결을 위해 HTTP 전송을 사용합니다. OpenCode에서 GitLab MCP 서버를 구성하려면:

1. 이 정의를 `~/.config/opencode/opencode.json` 파일의 `mcp` 키에 추가합니다:
   - `<gitlab.example.com>`을 다음으로 바꿉니다.
     - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
     - GitLab.com에서는 `gitlab.com`입니다.

   ```json
   {
     "mcp": {
       "gitlab-mcp": {
         "type": "remote",
         "url": "https://<gitlab.example.com>/api/v4/mcp",
         "enabled": true
       }
     }
   }
   ```

1. 파일을 저장합니다.
1. GitLab MCP 서버로 인증합니다.

   ```shell
   opencode mcp auth gitlab-mcp
   ```

1. 브라우저에서 권한 부여 요청을 검토하고 승인합니다.

이제 새 채팅을 시작하고 [사용 가능한 도구](mcp_server_tools.md)에 따라 질문할 수 있습니다.

> [!warning]
> 이러한 도구를 사용하면 프롬프트 인젝션에서 보호할 책임이 있습니다. 극도의 주의를 기울이거나 신뢰할 수 있는 GitLab 개체에만 MCP 도구를 사용합니다.

## OpenAI Codex를 GitLab MCP 서버에 연결 {#connect-openai-codex-to-the-gitlab-mcp-server}

OpenAI Codex는 HTTP 전송을 사용하여 추가 종속성 없이 직접 연결합니다. OpenAI Codex에서 GitLab MCP 서버를 구성하려면 다음을 수행합니다.

1. 터미널에서 CLI를 사용하여 GitLab MCP 서버를 추가합니다.
   - `<gitlab.example.com>`을 다음으로 바꿉니다.
     - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
     - GitLab.com에서는 `gitlab.com`입니다.

   ```shell
   codex mcp add GitLab --url "https://<gitlab.example.com>/api/v4/mcp"
   ```

1. `~/.codex/config.toml`을 편집하고 `[features]` 섹션에서 `rmcp_client` 기능 플래그를 사용으로 설정합니다.

   ```toml
   [features]
   "rmcp_client" = true

   [mcp_servers.GitLab]
   url = "https://<gitlab.example.com>/api/v4/mcp"
   ```

1. 로그인 플로우을 실행하고 GitLab 인스턴스로 인증합니다.

   ```shell
   codex mcp login GitLab
   ```

1. 브라우저에서 권한 부여 요청을 검토하고 승인합니다.

이제 새 채팅을 시작하고 [사용 가능한 도구](mcp_server_tools.md)에 따라 질문할 수 있습니다.

> [!warning]
> 이러한 도구를 사용하면 프롬프트 인젝션에서 보호할 책임이 있습니다. 극도의 주의를 기울이거나 신뢰할 수 있는 GitLab 개체에만 MCP 도구를 사용합니다.

## Zed를 GitLab MCP 서버에 연결 {#connect-zed-to-the-gitlab-mcp-server}

전제 조건:

- Node.js 버전 20 이상을 설치합니다.
- `PATH` 환경 변수에서 Node.js를 전역으로 사용할 수 있습니다(`which -a node`).

Zed에서 GitLab MCP 서버를 구성하려면 다음을 수행합니다.

1. Zed에서 명령 팔렛트를 엽니다.
   - macOS에서 <kbd>Command</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>를 누릅니다.
   - Windows 또는 Linux에서 <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>를 누릅니다.
1. `agent: open settings`를 입력하고 <kbd>Enter</kbd>를 누릅니다.
1. **Model Context Protocol(MCP) 서버** 섹션에서 **서버 추가**를 선택합니다.
1. `args`에 서버 URL로 `https://<gitlab.example.com>/api/v4/mcp`를 사용합니다.
   - `<gitlab.example.com>`을 다음으로 바꿉니다.
     - GitLab Self-Managed에서는 GitLab 인스턴스 URL입니다.
     - GitLab.com에서는 `gitlab.com`입니다.

   ```json
   {
     /// The name of your MCP server
     "GitLab": {
       /// The command which runs the MCP server
       "command": "npx",
       /// The arguments to pass to the MCP server
       "args": ["-y","mcp-remote@latest","https://<gitlab.example.com>/api/v4/mcp"],
       /// The environment variables to set
       "env": {}
     }
   }
   ```

1. 구성을 저장합니다.

   OAuth 권한 부여 페이지가 표시되어야 합니다. 그렇지 않으면 **GitLab** 토글을 껐다가 다시 켭니다.

1. 브라우저에서 권한 부여 요청을 검토하고 승인합니다.

이제 새 채팅을 시작하고 [사용 가능한 도구](mcp_server_tools.md)에 따라 질문할 수 있습니다.

> [!warning]
> 이러한 도구를 사용하면 프롬프트 인젝션에서 보호할 책임이 있습니다. 극도의 주의를 기울이거나 신뢰할 수 있는 GitLab 개체에만 MCP 도구를 사용합니다.

## 단일 OAuth 애플리케이션 다시 사용 {#reuse-a-single-oauth-application}

{{< history >}}

- 관리자 UI를 통한 OAuth 애플리케이션 만들기는 GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245979)되었습니다.
- 그룹 및 사용자 UI를 통한 OAuth 애플리케이션 만들기는 GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247698)되었습니다.

{{< /history >}}

MCP 클라이언트가 GitLab MCP 서버에 연결할 때 OAuth 2.0 Dynamic Client Registration(DCR)을 사용하여 GitLab 인스턴스에 새 OAuth 애플리케이션을 만듭니다.

단일 사전 등록 OAuth 애플리케이션을 재사용해야 하는지 여부는 인스턴스에 따라 다릅니다:

- 관리자가 DCR을 끄는 인스턴스에서는 MCP 클라이언트가 애플리케이션을 자동으로 등록할 수 없으므로 사전 등록 OAuth 애플리케이션을 재사용해야 합니다. 자세한 내용은 [OAuth 동적 클라이언트 등록 끄기](../../administration/settings/account_and_limit_settings.md#turn-off-oauth-dynamic-client-registration)를 참조하세요.
- 다른 모든 인스턴스에서는 사전 등록 OAuth 애플리케이션을 재사용하는 것이 선택 사항입니다. 다음 DCR 문제를 피하기 위해 하나를 재사용합니다:
  - GitLab Self-Managed 및 GitLab Dedicated에서 많은 사용자 또는 반복적으로 연결하는 클라이언트는 인스턴스에 많은 수의 OAuth 애플리케이션을 만들 수 있습니다.
  - IP 주소는 DCR 요청을 시간당 10개 등록으로 속도 제한합니다. 회사 네트워크 또는 VPN과 같이 송신 IP 주소를 공유하는 사용자는 이 제한을 초과하고 MCP 서버에 대한 인증에 실패할 수 있습니다.

모든 사용자는 여전히 OAuth로 권한을 부여하고 자신의 액세스 토큰을 받습니다. 공유된 애플리케이션은 OAuth 클라이언트 ID이지만 공유 자격 증명이 아닙니다.

누가 다시 사용하는지에 따라 다음 범위 중 하나에 대한 OAuth 애플리케이션을 만듭니다.

- 인스턴스: 인스턴스의 모든 사용자가 공유합니다.
- 그룹: 그룹의 구성원이 공유합니다.
- 사용자: 사용자 자신의 계정입니다.

전제 조건:

- 다음을 지원하는 MCP 클라이언트:
  - 사전 구성된 OAuth 자격 증명
  - 구성에 `clientId` 필드
- 인스턴스에 대해 애플리케이션을 만드는 경우 관리자 액세스 권한을 보유합니다.
- 그룹에 대해 애플리케이션을 만드는 경우 그룹의 소유자 역할을 보유합니다.

OAuth 애플리케이션을 만들려면 다음을 수행합니다.

1. [인스턴스](../../integration/oauth_provider.md#create-an-instance-wide-application), [그룹](../../integration/oauth_provider.md#create-a-group-owned-application) 또는 [사용자](../../integration/oauth_provider.md#create-a-user-owned-application)에 대한 OAuth 애플리케이션을 만듭니다.
1. 범위의 경우 **mcp**를 선택하고 **기밀** 확인란을 선택 해제합니다.
1. 애플리케이션을 저장합니다.
1. 애플리케이션 ID로 MCP 클라이언트를 구성하거나 애플리케이션을 재사용하는 사용자에게 애플리케이션 ID를 제공합니다. 애플리케이션 ID는 `clientId`입니다. 구성 키는 클라이언트에 따라 다르지만 일반적으로 GitLab MCP 서버의 OAuth 구성에서 이름이 `clientId` 또는 `client_id`이며 일반적으로 `mcp.json` 파일에 있습니다.

인스턴스 및 사용자 애플리케이션의 경우 [REST API](../../api/applications.md#create-an-application)를 사용하여 애플리케이션을 만들 수도 있습니다. 그룹 소유 애플리케이션에는 REST API가 없으므로 그룹 UI를 사용해야 합니다.

> [!note]
> OAuth 애플리케이션에 등록된 리디렉션 URI는 OAuth 플로우 중에 MCP 클라이언트가 보내는 리디렉션 URI와 정확히 일치해야 합니다. 사용하는 리디렉션 URI에 대해서는 클라이언트의 설명서를 확인합니다. 단일 공유 OAuth 애플리케이션은 다른 리디렉션 URI를 사용하는 MCP 클라이언트를 제공할 수 없습니다. 사용자가 다른 리디렉션 URI를 사용하는 MCP 클라이언트를 사용하는 경우 각 클라이언트 유형에 대해 별도의 공유 OAuth 애플리케이션을 만듭니다.

### 보안 고려 사항 {#security-considerations}

클라이언트 ID로 인증하는 사용자는 여전히 자신의 GitLab 자격 증명으로 OAuth 권한 부여를 완료해야 합니다. 자신에게 허용된 데이터에만 액세스할 수 있습니다.

GitLab은 `clientId`를 제시하는 MCP 클라이언트 애플리케이션을 확인하지 않습니다. 특정 MCP 클라이언트에 대한 OAuth 애플리케이션을 만들려면 사전 등록을 지원하는 다른 MCP 클라이언트도 동일한 `clientId`를 사용하여 인증할 수 있습니다. `clientId`은 어떤 클라이언트 소프트웨어를 허용하는지가 아닌 어떤 OAuth 애플리케이션을 사용하는지를 제어합니다.

REST API로 만든 미리 등록된 애플리케이션은 PKCE(Proof Key for Code Exchange)를 적용하지 않습니다. PKCE는 공개 클라이언트에 대해 권한 부여 코드 도용으로부터 방어합니다.

PKCE를 적용하려면 MCP 클라이언트가 OAuth 플로우 중에 `code_challenge` 및 `code_challenge_method` 매개 변수를 보내는지 확인합니다. GitLab은 사전 등록된 애플리케이션에 대한 PKCE 매개 변수를 수락하지만 필수는 아닙니다.

## 속도 제한 {#rate-limits}

{{< details >}}

- 티어:  Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/629883)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)가 있습니다: `rate_limiter_mcp_limits_free_info`, `rate_limiter_mcp_limits_free_enforce`, `rate_limiter_mcp_limits_premium_info`, `rate_limiter_mcp_limits_premium_enforce`, `rate_limiter_mcp_limits_ultimate_info`, `rate_limiter_mcp_limits_ultimate_enforce`. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

MCP 서버 엔드포인트(`POST /api/v4/mcp`)에 대한 요청은 각 사용자의 네임스페이스 플랜별로 제한됩니다:

| 플랜     | 한도            |
| -------- | ---------------- |
| Free     | 분당 60회   |
| Premium  | 분당 600회  |
| Ultimate | 분당 600회  |

이러한 제한은 각 클라이언트나 토큰별이 아니라 각 사용자별로 적용됩니다. 여러 MCP 클라이언트를 연결하는 사용자는 모두에 대해 하나의 허용량을 공유합니다.

MCP 서버 요청은 또한 모든 트래픽에 적용되는 [GitLab.com 속도 제한](../gitlab_com/rate_limits.md)으로 계산되므로 요청이 어느 제한에도 도달할 수 있습니다. MCP 서버 제한은 모든 플랜에 대해 두 가지 중 더 낮은 제한입니다.

제한을 초과하면 GitLab은 `429 Too Many Requests`을 [표준 속도 제한 헤더](../../administration/settings/user_and_ip_rate_limits.md#response-headers)(`Retry-After` 및 `RateLimit-Reset` 포함)와 함께 반환합니다. `RateLimit-Name`은 도달한 제한을 식별합니다.

도구 뒤의 GitLab API 엔드포인트에 대한 속도 제한은 다르게 보고됩니다. 이 경우 [`rate_limited` 도구 결과](mcp_server_troubleshooting.md#error-rate_limited-tool-result)를 참조하세요.

GitLab Self-Managed 및 GitLab Dedicated에서 관리자는 인스턴스에 대한 단일 MCP 서버 제한을 설정합니다. 자세한 내용은 [인증된 MCP 서버 요청 속도 제한](../../administration/settings/user_and_ip_rate_limits.md#enable-authenticated-mcp-server-request-rate-limit)을 참조하세요.

## 지원되는 MCP 프로토콜 버전 {#supported-mcp-protocol-versions}

GitLab MCP 서버는 `initialize` 요청에서 프로토콜 버전을 협상합니다. 클라이언트가 서버에서 지원하지 않는 버전을 요청하면 서버는 지원되는 버전을 나열하는 JSON-RPC 오류를 반환합니다.

| 프로토콜 버전 | 지원 |
|------------------|---------|
| `2025-11-25`     | 지원됩니다. 클라이언트가 더 최신 버전을 요청할 때 서버도 이 버전으로 답변합니다. |
| `2025-06-18`     | 지원됩니다. |
| `2025-03-26`     | 지원됩니다. |
| `2026-07-28`     | `initialize` 요청에서만 허용됩니다. 서버는 이 버전의 상태 비저장 기능을 아직 구현하지 않았으므로 `2025-11-25`로 답변합니다. 진행 상황은 [이슈 627825](https://gitlab.com/gitlab-org/gitlab/-/work_items/627825)를 참조하세요. |

GitLab은 MCP 사양이 프로토콜 버전을 더 이상 사용하지 않은 후에도 계속 지원합니다. 프로토콜 버전의 제거는 주요 변경입니다. GitLab은 버전이 제거되기 전에 [더 이상 사용되지 않음 및 제거](../../update/deprecations.md) 페이지에 제거 사항을 공지합니다.

## 관련 항목 {#related-topics}

- [AI 카탈로그의 MCP 서버](../gitlab_duo/model_context_protocol/ai_catalog_mcp_servers.md)
