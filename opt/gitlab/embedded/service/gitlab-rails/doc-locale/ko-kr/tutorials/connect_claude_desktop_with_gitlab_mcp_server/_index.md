---
stage: Tutorials
group: Tutorials
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Claude Desktop를 GitLab MCP 서버에 연결하고 이슈를 생성합니다.
title: "자습서: Claude Desktop를 GitLab MCP 서버에 연결"
---

[GitLab Model Context Protocol(MCP) 서버](../../user/model_context_protocol/mcp_server.md)를 사용하면 외부 AI 도구 및 애플리케이션을 GitLab 인스턴스에 연결할 수 있습니다. 이 자습서에서는 Claude Desktop에 연결하도록 GitLab MCP 서버를 구성합니다. Claude Desktop를 MCP 서버와 성공적으로 통합한 후 Claude에 지시하여 GitLab 인스턴스에서 이슈를 생성합니다.

## 시작하기 전에 {#before-you-begin}

- MCP 서버에 대한 액세스를 허용합니다.
  - GitLab.com에서 [최상위 그룹에 대해](../../user/group/access_and_permissions.md#allow-access-to-the-mcp-server) 설정합니다.
  - GitLab Self-Managed 및 GitLab Dedicated에서 [인스턴스에 대해](../../administration/settings/visibility_and_access_controls.md#allow-access-to-the-mcp-server) 설정합니다.
- 운영 체제에 맞게 [Claude Desktop](https://support.claude.com/en/articles/10065433-install-claude-desktop)을 설치합니다.
- Node.js 버전 20 이상을 설치합니다. `PATH` 환경 변수에서 Node.js를 전역으로 사용할 수 있습니다(`which -a node`).
- 이슈를 생성할 수 있는 활성 프로젝트가 최소 1개 이상 있어야 합니다.

## Claude Desktop을 GitLab MCP 서버에 연결 {#connect-claude-desktop-to-the-gitlab-mcp-server}

1. Claude Desktop을 엽니다.
1. 구성 파일을 편집합니다. 다음 중 하나를 수행할 수 있습니다.
   - Claude Desktop에서 **설정** > **개발자** > **Edit Config**를 선택합니다.
   - 파일 시스템에서 `claude_desktop_config.json`로 이동하여 파일을 엽니다. 예를 들어:
     - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`.
     - Windows: `%APPDATA%\Claude\claude_desktop_config.json`.
1. 필요에 따라 편집하여 GitLab MCP 서버에 대한 다음 항목을 추가합니다:
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
1. 처음 연결할 때 Claude Desktop은 OAuth 인증을 위한 브라우저 창을 엽니다. 요청을 검토하고 승인합니다.
1. **설정** > **개발자**로 이동하여 새 GitLab MCP 구성을 확인합니다.

![Claude Desktop에서 연결된 로컬 MCP 서버 보기](img/view_local_mcp_servers_v18_10.png)

## 도구 권한 사용자 정의 {#customize-tool-permissions}

MCP 서버를 성공적으로 연결한 후 Claude가 GitLab 인스턴스와 상호 작용할 때 사용할 수 있는 도구를 사용자 정의할 수 있습니다. 예를 들어 이슈 생성이나 CI/CD 파이프라인 관리와 같은 특정 작업을 실행하기 전에 승인을 요청하도록 Claude를 구성할 수 있습니다.

Claude에서 도구 권한을 보려면:

1. 왼쪽 사이드바에서 **Customize** > **Connectors**를 선택합니다.
1. **Desktop** 아래에서 **GitLab**을 선택합니다.
1. `create_issue`을 **승인 필요** 또는 **항상 허용** 중 하나로 설정합니다.

![Claude Desktop에서 커넥터의 도구 권한 보기](img/view_connectors_v18_10.png)

## 연결 테스트 {#test-the-connection}

Claude Desktop을 MCP 서버에 성공적으로 연결한 후 프롬프트로 연결을 테스트합니다:

1. 채팅 텍스트 상자에 입력합니다:

   ```plaintext
   Which MCP server version are you using?
   ```

1. <kbd>Enter</kbd>를 누르거나 **전송**을 선택합니다.

Claude는 서버 버전과 함께 통합 및 프롬프트에 답하는 데 사용된 도구에 대한 세부 정보로 응답해야 합니다.

![프롬프트로 MCP 서버 버전을 확인하고 Claude가 사용한 도구 보기](img/verify_mcp_server_version_v18_10.png)

## 프로젝트에서 이슈 생성 {#create-an-issue-in-a-project}

이제 Claude에 특정 프로젝트를 찾도록 요청하여 테스트 이슈를 생성할 수 있습니다.

1. 채팅 텍스트 상자에 입력합니다:

   ```plaintext
   Can you find my project <project_name>?
   ```

   `<project_name>`을 프로젝트로 바꿉니다.
1. <kbd>Enter</kbd>를 누르거나 **전송**을 선택합니다.
1. Claude가 프로젝트를 찾은 후 Claude에 프로젝트에서 이슈를 생성하도록 요청합니다. 채팅 텍스트 상자에 입력합니다:

   ```plaintext
   Can you create an issue in the project called "Test issue from MCP server", and give it the following description: "This is a test issue created by Claude Desktop and the GitLab MCP server."
   ```

1. <kbd>Enter</kbd>를 누르거나 **전송**을 선택합니다.
1. `create_issue`을 **승인 필요**로 설정한 경우 Claude는 이슈를 생성할 수 있는 권한을 요청합니다. **항상 허용**을 선택하거나 드롭다운 목록에서 **한 번만 허용**을 선택합니다.

   ![Claude에 프로젝트에서 이슈를 생성할 수 있는 권한 부여](img/grant_permission_to_create_issue_v18_10.png)

Claude가 이슈를 생성한 후 브라우저에서 이슈에 액세스할 수 있는 URL을 포함한 이슈 세부 정보를 제공합니다.
