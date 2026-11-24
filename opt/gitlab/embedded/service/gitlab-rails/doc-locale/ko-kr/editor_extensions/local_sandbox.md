---
stage: AI Clients
group: Duo Client SDK
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 컴퓨터의 프로세스 샌드박스에서 GitLab Duo 에이전트 작업 및 로컬 MCP 서버를 실행합니다.
title: 로컬 샌드박스
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  실험

{{< /details >}}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.80.0) \- GitLab for VS Code 6.80.0에서 [실험](../policy/development_stages_support.md#experiment)으로 GitLab 19.0 릴리스 중에 도입됨.
- [도입됨](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.94.0) \- GitLab Duo CLI 8.94.0에서 [실험](../policy/development_stages_support.md#experiment)으로 GitLab 19.1 릴리스 중에 도입됨.
- 샌드박스 구성 파일은 GitLab Language Server 9.4.0 및 GitLab Duo CLI 9.4.0에서 [도입됨](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.4.0) \- GitLab 19.3 릴리스 중에 도입됨.

{{< /history >}}

로컬 샌드박스는 컴퓨터에서 실행될 때 GitLab Duo 에이전트가 읽고 쓰고 네트워크에 도달할 수 있는 것을 제한합니다. 편집기 및 GitLab Duo CLI의 에이전트에 적용됩니다.

샌드박스는 기본적으로 꺼져 있습니다. 활성화할 때까지 [편집기 확장 및 CLI 도구의 보안 고려 사항](security_considerations.md)에 설명된 위험이 적용됩니다.

GitLab Runner에서 실행되는 플로우의 경우 [원격 실행 환경 샌드박스](../user/duo_agent_platform/environment_sandbox.md)를 참조하세요.

## 샌드박스 작동 방식 {#how-the-sandbox-works}

샌드박스가 켜져 있으면 GitLab Duo는 운영 체제가 제한하는 별도의 워커 프로세스에서 에이전트 작업을 실행합니다. 에이전트 작업에는 셸 명령, 파일 읽기 및 쓰기, 파일 검색 및 디렉토리 목록이 포함됩니다.

`stdio` 전송을 사용하는 로컬 MCP 서버는 동일한 종류의 샌드박스에서 실행됩니다.

샌드박스는 `GITLAB_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `SSH_AUTH_SOCK`와 같은 알려진 자격 증명 환경 변수를 샌드박스의 프로세스 환경에서 제거합니다. 다른 환경 변수는 제거되지 않습니다.

기본적으로 샌드박스는 다음도 차단합니다:

- 일반적인 자격 증명 및 개인 디렉토리에서 읽기.
- 워크스페이스 및 임시 디렉토리 외부로 쓰기.
- GitLab 인스턴스를 제외한 모든 호스트에 대한 네트워크 액세스.

전체 목록은 [기본 샌드박스 규칙](#default-sandbox-rules)을 참조하세요.

샌드박스는 프로세스 샌드박스이며 컨테이너 또는 가상 머신이 아닙니다. 다음은 샌드박스 외부에서 실행됩니다:

- 편집기 및 GitLab Duo 자체.
- `http` 또는 `sse` 전송을 사용하는 MCP 서버에 연결.
- `"sandboxEnabled": false`이 있는 MCP 서버.
- [GitLab Duo CLI 훅](../user/gitlab_duo_cli/customize.md#hooks).

샌드박스는 로컬에서 에이전트를 실행하는 위험을 줄이지만 완전히 제거하지는 않습니다. 에이전트는 여전히 워크스페이스의 파일을 읽고 변경할 수 있으며 샌드박스가 허용하는 호스트로 데이터를 보낼 수 있습니다.

샌드박스가 켜져 있지만 시작할 수 없으면(예: 종속성이 누락된 경우) 에이전트 작업 및 로컬 MCP 서버가 오류로 실패합니다. 샌드박스 없이 실행되지 않습니다. 이 동작은 샌드박스 없이 플로우를 실행하고 경고를 표시하는 원격 실행 환경 샌드박스와 다릅니다.

## 지원되는 플랫폼 {#supported-platforms}

| 운영 체제 | 지원됨 |
|------------------|-----------|
| macOS            | 예       |
| Linux            | [필수 구성 요소](#prerequisites)와 함께 예 |
| Windows          | 아니요        |

## 전제 조건 {#prerequisites}

Linux에서 `bubblewrap` 및 `socat`를 설치합니다. 예를 들어:

- Debian 또는 Ubuntu에서:

  ```shell
  sudo apt-get install bubblewrap socat
  ```

- Fedora에서:

  ```shell
  sudo dnf install bubblewrap socat
  ```

macOS에서는 추가 소프트웨어가 필요하지 않습니다.

## 샌드박스 켜기 {#turn-on-the-sandbox}

샌드박스를 켜려면:

{{< tabs >}}

{{< tab title="VS Code" >}}

1. VS Code에서 설정을 엽니다:
   - macOS의 경우 <kbd>Command</kbd>+<kbd>,</kbd>를 누릅니다.
   - Windows 또는 Linux의 경우 <kbd>Control</kbd>+<kbd>,</kbd>를 누릅니다.
1. `gitlab.duoAgentPlatform.sandbox.enabled`을(를) 검색합니다.
1. **샌드박싱 활성화** 확인란을 선택합니다.

또는 아래쪽 상태 표시줄에서 **Duo**({{< icon name="tanuki-ai" >}})를 선택한 다음 **에이전트 샌드박싱 활성화**를 선택합니다.

{{< /tab >}}

{{< tab title="JetBrains IDE" >}}

샌드박스 설정은 JetBrains IDE용 GitLab Duo 플러그인의 알파 빌드에서만 사용할 수 있습니다.

1. IDE에서 상단 막대에서 IDE 이름을 선택한 다음 **설정**을 선택합니다.
1. 왼쪽 사이드바에서 **도구** > **GitLab Duo**를 선택합니다.
1. **GitLab Duo 에이전트 플랫폼** 아래에서 **샌드박싱 활성화** 확인란을 선택합니다.
1. **확인** 또는 **저장**을 선택합니다.

{{< /tab >}}

{{< tab title="GitLab Duo CLI" >}}

`--sandbox` 옵션을 `true`로 설정하여 GitLab Duo CLI를 시작합니다:

```shell
duo --sandbox true
```

또는 `DUO_SANDBOX_ENABLED` 환경 변수를 설정합니다:

```shell
export DUO_SANDBOX_ENABLED=true
```

{{< /tab >}}

{{< /tabs >}}

## 샌드박스 상태 확인 {#check-sandbox-status}

샌드박스가 켜져 있고 사용 가능한지 확인하려면:

{{< tabs >}}

{{< tab title="VS Code" >}}

- 아래쪽 상태 표시줄에서 **Duo**({{< icon name="tanuki-ai" >}})를 선택합니다. 메뉴에는 샌드박스 상태가 표시됩니다(예: **에이전트 샌드박싱: 활성화** 또는 **에이전트 샌드박싱: 누락된 종속성**).

자세한 내용은 명령 팔레트를 열고 **GitLab을 실행합니다: 진단**, 그리고 **GitLab Duo 에이전트 샌드박싱** 섹션으로 이동합니다.

{{< /tab >}}

{{< tab title="JetBrains IDE" >}}

- 상태 표시줄에서 **Duo**({{< icon name="tanuki-ai" >}})를 선택합니다. 메뉴에는 샌드박스 상태가 표시됩니다(예: **에이전트 샌드박싱: 활성화** 또는 **에이전트 샌드박싱: 누락된 종속성**).

{{< /tab >}}

{{< tab title="GitLab Duo CLI" >}}

1. 샌드박스를 켠 상태로 GitLab Duo CLI를 시작합니다:

   ```shell
   duo --sandbox true
   ```

1. `/doctor` 명령을 실행합니다.
1. **샌드박스** 섹션으로 이동합니다.

**샌드박스** 섹션은 현재 세션에만 보고합니다. `--sandbox true` 또는 `DUO_SANDBOX_ENABLED=true` 없이 CLI를 시작하면 섹션에는 샌드박스가 꺼져 있는 것으로 표시됩니다.

{{< /tab >}}

{{< /tabs >}}

각 상태 확인은 다음 여부를 보고합니다:

- 프로세스 샌드박싱이 설정에서 활성화되어 있습니다.
- 프로세스 샌드박싱이 이 플랫폼에서 지원됩니다.
- 프로세스 샌드박싱에 필요한 시스템 종속성이 설치되어 있습니다.

## 기본 샌드박스 규칙 {#default-sandbox-rules}

이 규칙은 샌드박스가 켜져 있을 때 에이전트 작업 및 로컬 MCP 서버에 적용됩니다.

### 네트워크 {#network}

샌드박스의 프로세스는 GitLab 인스턴스 URL의 호스트 및 포트에만 연결할 수 있습니다. 인스턴스 URL에 포트가 포함되지 않으면 샌드박스는 `https`의 경우 `443`, `http`의 경우 `80`을 사용합니다.

다른 모든 호스트는 패키지 레지스트리를 포함하여 차단됩니다. 더 많은 호스트를 허용하려면 [샌드박스 규칙을 사용자 지정](#customize-sandbox-rules)하세요.

샌드박스는 각 연결의 호스트 및 포트만 확인합니다. 요청을 검사하지 않습니다. 에이전트는 샌드박스가 허용하는 호스트의 모든 프로젝트 또는 계정으로 데이터를 보낼 수 있습니다.

### 파일 시스템 읽기 {#file-system-read}

샌드박스의 프로세스는 다음을 읽을 수 없습니다:

- `~/.ssh/`, `~/.gnupg/`, `~/.aws/`, `~/.azure/`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc` 및 `~/.pypirc`과 같은 자격 증명 파일 및 디렉토리.
- `~/.config/`, `~/.config/git/` 제외.
- 개인 디렉토리: `~/Documents/`, `~/Downloads/`, `~/Desktop/`, `~/Pictures/`, `~/Movies/` 및 `~/Music/`.
- 셸 기록: `~/.bash_history` 및 `~/.zsh_history`.
- macOS에서 `~/Library/Application Support/`, `~/Library/Containers/`, `~/Library/Group Containers/` 및 `~/Library/Keychains/`.

Linux 및 VS Code의 macOS에서 샌드박스의 프로세스는 허용된 경로 집합만 읽을 수 있습니다. 허용된 경로에는 워크스페이스, `/usr/`, `/bin/`, `/etc/`과 같은 시스템 디렉토리, 임시 디렉토리, GitLab Duo 구성 디렉토리, Git 구성 및 일반적인 Node.js 버전 관리자 디렉토리가 포함됩니다.

JetBrains IDE 및 GitLab Duo CLI의 macOS에서 샌드박스의 프로세스는 차단 목록에 없는 모든 경로를 읽을 수 있습니다.

허용된 경로는 포함된 차단된 경로보다 우선합니다. 예를 들어 워크스페이스가 `~/Documents/`에 있으면 샌드박스의 프로세스는 워크스페이스를 읽을 수 있습니다.

### 파일 시스템 쓰기 {#file-system-write}

샌드박스의 프로세스는 워크스페이스, 임시 디렉토리 및 샌드박스 런타임이 사용하는 몇 개의 로그 디렉토리에만 쓸 수 있습니다.

워크스페이스에서 샌드박스의 프로세스는 다음에 쓸 수 없습니다:

- `.git/hooks/` 및 `.git/config`
- `.gitlab-ci.yml` 및 `.gitlab/`
- `.gitconfig` 및 `.gitmodules`
- 셸 시작 파일(예: `.bashrc`, `.zshrc` 및 `.profile`)
- 편집기 구성 디렉토리: `.vscode` 및 `.idea`

GitLab Duo CLI에서 `--cwd` 옵션을 사용하여 다른 디렉토리에서 워크스페이스를 열면 `.git/config`, `.gitmodules`, 셸 시작 파일 및 편집기 구성 디렉토리에 대한 규칙이 워크스페이스가 아닌 CLI를 시작한 디렉토리에 적용됩니다. 이러한 규칙을 워크스페이스에 유지하려면 워크스페이스 디렉토리에서 CLI를 시작합니다.

## 샌드박스 규칙 사용자 지정 {#customize-sandbox-rules}

샌드박스 구성 파일에서 기본값에 규칙을 추가할 수 있습니다. 규칙은 모든 워크스페이스에 적용됩니다.

샌드박스 규칙을 사용자 지정하려면:

1. `sandbox.json` 파일을 [파일 위치](#file-location)에 만듭니다.
1. 필요한 규칙을 추가합니다. 예를 들어 에이전트가 npm 레지스트리에서 패키지를 설치하고 홈 디렉토리의 디렉토리를 읽을 수 있도록 하려면:

   ```json
   {
     "network": {
       "allowedDomains": ["registry.npmjs.org"]
     },
     "filesystem": {
       "allowRead": ["~/reference-docs/"],
       "allowWrite": ["~/.npm/"]
     }
   }
   ```

   npm은 다운로드한 패키지를 `~/.npm/`에 저장하므로 이 예제는 거기에 쓰기도 허용합니다.

1. 파일을 저장합니다.
1. IDE 또는 GitLab Duo CLI를 다시 시작합니다.

GitLab Duo CLI에서 `--sandbox-config` 옵션 또는 `DUO_SANDBOX_CONFIG` 환경 변수를 사용하여 다른 파일을 사용할 수 있습니다. 절대 경로 또는 `~/`으로 시작하는 경로를 사용합니다. 샌드박스도 켜져 있어야 합니다:

```shell
duo --sandbox true --sandbox-config ~/sandbox-strict.json
```

### 파일 위치 {#file-location}

파일은 `~/.gitlab/duo/sandbox.json`에 있습니다.

`XDG_CONFIG_HOME` 환경 변수를 설정하면 파일이 `$XDG_CONFIG_HOME/gitlab/duo/sandbox.json`에 있습니다.

### 구성 파일 참조 {#configuration-file-reference}

파일은 다음 키를 지원합니다. 달리 명시되지 않는 한 각 키는 문자열 목록을 사용합니다.

| 키 | 설명 |
|-----|-------------|
| `filesystem.allowRead` | 샌드박스의 프로세스가 읽을 수 있는 경로. |
| `filesystem.denyRead` | 샌드박스의 프로세스가 읽을 수 없는 경로. |
| `filesystem.allowWrite` | 샌드박스의 프로세스가 쓸 수 있는 경로. |
| `filesystem.denyWrite` | 샌드박스의 프로세스가 쓸 수 없는 경로. |
| `network.allowedDomains` | 샌드박스의 프로세스가 연결할 수 있는 호스트. 특정 포트를 허용하려면 `host:port`을 사용합니다. |
| `network.deniedDomains` | 샌드박스의 프로세스가 연결할 수 없는 호스트. |
| `srt.enableWeakerNestedSandbox` | 부울. Linux에서 `true`로 설정하여 전체 샌드박스를 지원하지 않는 컨테이너에서 실행합니다. 이 설정은 샌드박스를 약화시킵니다. |
| `srt.ignoreViolations` | 명령 패턴을 경로 목록에 매핑하는 개체. 이 경로에 대한 차단된 액세스는 보고되지 않습니다. |

규칙은 기본 규칙에 추가됩니다. 제거할 수 없습니다:

- 워크스페이스 및 임시 디렉토리에 대한 쓰기 액세스.
- GitLab 인스턴스에 대한 네트워크 액세스.
- 워크스페이스의 차단된 쓰기 경로.

파일이 유효한 JSON이 아니거나 이 표에 없는 키를 포함하면 GitLab Duo는 전체 파일을 무시하고 기본 규칙을 사용합니다. 오류는 GitLab Duo 로그에 기록됩니다.

## MCP 서버용 샌드박스 구성 {#configure-the-sandbox-for-an-mcp-server}

일부 로컬 MCP 서버는 기본 규칙이 차단하는 액세스가 필요합니다. 예를 들어 `~/.config/`에서 자체 구성을 읽는 MCP 서버는 시작할 수 없습니다.

한 MCP 서버의 샌드박스 규칙을 변경하려면:

1. [사용자 MCP 구성 파일](../user/gitlab_duo/model_context_protocol/mcp_clients.md#create-user-configuration)을 엽니다.
1. 서버 구성에서 `sandbox` 개체를 추가합니다. 예를 들어:

   ```json
   {
     "mcpServers": {
       "gitlab": {
         "type": "stdio",
         "command": "glab",
         "args": ["mcp", "serve"],
         "sandbox": {
           "allowRead": ["~/.config/glab-cli/"]
         }
       }
     }
   }
   ```

   이 예제는 Linux의 `glab` 구성 디렉토리를 사용합니다. macOS에서는 `~/Library/Application Support/glab-cli/`를 사용합니다.

1. 파일을 저장합니다.
1. IDE 또는 GitLab Duo CLI를 다시 시작합니다.

샌드박스는 서버의 `env` 개체에서 설정한 경우에도 MCP 서버에서 자격 증명 환경 변수를 제거합니다.

### MCP 서버 샌드박스 설정 {#mcp-server-sandbox-settings}

`sandbox` 개체는 `stdio` 전송을 사용하는 MCP 서버에만 적용됩니다. 다음 키를 지원합니다:

| 키 | 형식 | 설명 |
|-----|------|-------------|
| `sandboxEnabled` | 부울 | 샌드박스 없이 이 서버를 실행하려면 `false`로 설정합니다. 샌드박스가 꺼져 있으면 `true`로 설정하는 것은 효과가 없습니다. |
| `allowRead` | 문자열 목록 | 이 서버가 읽을 수 있는 경로(기본값 외). |
| `allowWrite` | 문자열 목록 | 이 서버가 쓸 수 있는 경로(기본값 외). |
| `denyRead` | 문자열 목록 | 이 서버가 읽을 수 없는 경로(기본값 외). |

`sandbox` 개체를 설정하는 위치는 어떤 키가 적용되는지에 영향을 줍니다:

- 사용자 구성: 모든 키가 적용됩니다.
- 워크스페이스 구성(`.gitlab/duo/mcp.json`): `denyRead`만 적용됩니다. 프로젝트는 서버를 제한할 수 있지만 더 많은 액세스를 제공할 수 없습니다. GitLab Duo는 다른 키를 무시하고 경고를 기록합니다.
- 플러그인: `sandbox` 개체는 무시됩니다.

> [!warning]
> `"sandboxEnabled": false`을(를) 설정하면 MCP 서버는 사용자 계정과 동일한 액세스로 실행됩니다. 이 설정은 신뢰하는 서버에만 사용하세요.

## 문제 해결 {#troubleshooting}

로컬 샌드박스로 작업할 때 다음 문제가 발생할 수 있습니다.

### 오류: `Sandbox is enabled but sandbox provider is not available (missing_dependencies)` {#error-sandbox-is-enabled-but-sandbox-provider-is-not-available-missing_dependencies}

샌드박스가 켜져 있고 필요한 소프트웨어가 설치되지 않았을 때 이 오류가 발생할 수 있습니다. VS Code에서 경고는 누락된 종속성도 나열합니다.

이 문제를 해결하려면 [필수 구성 요소](#prerequisites)를 설치한 다음 IDE 또는 GitLab Duo CLI를 다시 시작하세요.

### 오류: `Sandbox is enabled but sandbox provider is not available (unsupported_platform)` {#error-sandbox-is-enabled-but-sandbox-provider-is-not-available-unsupported_platform}

샌드박스가 켜져 있고 운영 체제가 [지원되지 않음](#supported-platforms)일 때 이 오류가 발생할 수 있습니다.

이 문제를 해결하려면 샌드박스를 끕니다:

- VS Code의 설정에서 `gitlab.duoAgentPlatform.sandbox.enabled`을 검색한 다음 **샌드박싱 활성화** 확인란을 선택 해제합니다.
- GitLab Duo CLI에서 `DUO_SANDBOX_ENABLED` 및 `DUO_SANDBOX_CONFIG` 환경 변수를 설정 해제한 다음 `--sandbox` 및 `--sandbox-config` 옵션 없이 CLI를 시작합니다.

### 오류: `Operation is blocked by sandbox.` {#error-operation-is-blocked-by-sandbox}

에이전트 작업이 샌드박스 규칙이 차단하는 항목을 읽거나 쓰거나 연결하려고 할 때 이 오류가 발생할 수 있습니다.

이 문제를 해결하려면 에이전트에 액세스가 필요한 경우 [샌드박스 구성 파일](#customize-sandbox-rules)에 규칙을 추가합니다.

### MCP 서버 시작 실패 {#mcp-server-fails-to-start}

샌드박스가 켜져 있으면 로컬 MCP 서버가 다음과 같은 이유로 시작하지 못할 수 있습니다:

- 샌드박스를 시작할 수 없습니다. 오류에 `Sandbox is enabled but sandbox provider is not available`이(가) 포함됩니다. 이 문제를 해결하려면 [필수 구성 요소](#prerequisites)를 설치합니다.
- 서버가 샌드박스가 차단하는 파일을 읽거나 호스트에 연결합니다. 이 문제를 해결하려면 [MCP 서버용 샌드박스를 구성](#configure-the-sandbox-for-an-mcp-server)합니다.
- 서버는 `GITHUB_TOKEN`과 같이 샌드박스가 제거하는 자격 증명 환경 변수가 필요합니다. 이 문제를 해결하려면 서버를 신뢰하는 경우 `sandbox` 개체에서 `"sandboxEnabled": false`를 설정합니다.

### 프로젝트 MCP 샌드박스 설정이 무시됨 {#project-mcp-sandbox-settings-are-ignored}

`sandbox settings from this project's committed config can only narrow, not widen`이(가) 포함된 경고가 표시될 수 있습니다.

워크스페이스 `.gitlab/duo/mcp.json` 파일이 `denyRead` 외에 `sandbox` 키를 설정할 때 이 경고가 발생합니다.

이 문제를 해결하려면 키를 [사용자 MCP 구성 파일](../user/gitlab_duo/model_context_protocol/mcp_clients.md#create-user-configuration)로 이동합니다.

### GitLab 인스턴스에 대한 요청이 차단됨 {#requests-to-the-gitlab-instance-are-blocked}

샌드박스의 프로세스는 인스턴스 URL의 호스트 및 포트에서만 GitLab 인스턴스에 연결할 수 있습니다. 다른 포트에 대한 요청이 차단됩니다. 예를 들어 인스턴스 URL이 `https://gitlab.example.com`이면 허용된 포트는 `443`이므로 `http://gitlab.example.com`에 대한 요청이 포트 `80`에서 차단됩니다.

이 문제를 해결하려면 인스턴스 URL과 동일한 포트를 사용하거나 `network.allowedDomains`을(를) [샌드박스 구성 파일](#customize-sandbox-rules)에 추가합니다. 예를 들어, `gitlab.example.com:8080`입니다.
