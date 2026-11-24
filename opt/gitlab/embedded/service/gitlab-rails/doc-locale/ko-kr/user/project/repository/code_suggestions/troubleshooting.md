---
stage: AI Coding
group: DAP Repository Flows
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 코드 제안의 일반적인 문제에 대한 문제 해결 팁입니다.
title: Code Suggestions 문제 해결
---

GitLab Duo 코드 제안을 사용할 때 다음 문제가 발생할 수 있습니다.

[상태 확인](../../../gitlab_duo/turn_on_off.md)을 실행하여 인스턴스가 코드 제안을 실행하기 위한 요구 사항을 충족하는지 테스트할 수 있습니다.

GitLab Duo 문제 해결에 대한 자세한 내용을 보려면 다음을 참조하세요:

- [GitLab Duo 문제 해결](../../../gitlab_duo/troubleshooting.md)
- [GitLab Duo Chat 문제 해결](../../../gitlab_duo_chat/troubleshooting.md).
- [GitLab Duo 자체 호스팅 문제 해결](../../../../administration/gitlab_duo_self_hosted/troubleshooting.md).

## 제안이 표시되지 않음 {#suggestions-are-not-displayed}

제안이 표시되지 않으면 다음을 확인하세요:

- [GitLab Duo가 올바르게 구성](../../../gitlab_duo/turn_on_off.md)되었는지 확인합니다.
- [지원되는 언어](supported_extensions.md#supported-languages-by-ide) 및 [편집기 확장](supported_extensions.md#supported-editor-extensions)을 사용 중인지 확인합니다.
- [편집기 확장이 올바르게 구성](set_up.md#configure-an-editor-extension)되었는지 확인합니다.

제안이 여전히 표시되지 않으면 다양한 IDE에 대해 다음 문제 해결 단계를 수행해 보세요:

- [VS Code 또는 GitLab Web IDE](#suggestions-not-displayed-in-vs-code-or-gitlab-web-ide)
- [JetBrains IDE](#suggestions-not-displayed-in-jetbrains-ides)
- [Microsoft Visual Studio](#suggestions-not-displayed-in-microsoft-visual-studio)

## 코드 제안에서 401 오류 반환 {#code-suggestions-returns-a-401-error}

코드 제안은 [구독을 동기화](../../../../administration/license.md)하는 라이선스 토큰에 따라 달라집니다.

토큰이 만료되면 코드 제안에서 상태 `401`인 다음 오류가 반환됩니다:

```plaintext
Token validation failed in Language Server:
(Failed to check token: Error: Fetching Information about personal access token
```

GitLab이 클라우드 서버에 액세스할 수 있으면 [수동으로 라이선스를 동기화](../../../../subscriptions/manage_subscription.md#manually-synchronize-subscription-data)해 보세요.

## 인증 문제 해결 {#authentication-troubleshooting}

문제는 최근 인증 변경, 특히 토큰 시스템에 의해 발생할 수 있습니다. 이 문제를 해결하려면:

1. GitLab 계정 설정에서 기존 개인 액세스 토큰을 제거합니다.
1. OAuth를 사용하여 GitLab 계정을 다시 인증합니다.
1. 다양한 파일 확장자로 코드 제안 기능을 테스트하여 문제가 해결되었는지 확인합니다.

## 오류 422: 기본 GitLab Duo 네임스페이스 없음 {#error-422-no-default-gitlab-duo-namespace}

`Code Suggestions cannot detect a namespace for this project. To continue, please set a default GitLab Duo namespace in your user preferences.`를 나타내는 오류가 발생할 수 있습니다.

이 이슈는 여러 GitLab Duo 네임스페이스에 속해 있거나, GitLab 원격이 구성되지 않은 프로젝트에서 로컬로 작업할 때 발생합니다.

이 문제를 해결하려면 [기본 GitLab Duo 네임스페이스를 설정](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace)하세요.

## VS Code 문제 해결 {#vs-code-troubleshooting}

다음 문서는 VS Code의 코드 제안 관련 문제 해결에 대한 것입니다.

VS Code용 GitLab의 다른 모든 문제 해결에 대해서는 [GitLab for VS Code 확장 문제 해결](../../../../editor_extensions/visual_studio_code/troubleshooting.md)을 참조하세요.

### VS Code 또는 GitLab Web IDE에 제안이 표시되지 않음 {#suggestions-not-displayed-in-vs-code-or-gitlab-web-ide}

GitLab Self-Managed를 사용 중인 경우 [GitLab Web IDE](../../web_ide/_index.md)에 대해 코드 제안이 활성화되어 있는지 확인합니다. VS Code에도 로컬 IDE와 동일한 설정이 적용됩니다.

1. IDE에서 설정 편집기를 엽니다:
   - macOS의 경우 <kbd>Command</kbd>+<kbd>,</kbd>를 누릅니다.
   - Windows 또는 Linux의 경우 <kbd>Control</kbd>+<kbd>,</kbd>를 누릅니다.
1. **GitLab Duo** 설정으로 이동합니다:
   - VS Code에서 **확장** > **GitLab** > **GitLab Duo**를 선택합니다.
   - GitLab Web IDE에서 **확장** > **GitLab Workflow** > **GitLab Duo**를 선택합니다.
1. **GitLab › Duo Code Suggestions: 활성화** 아래에서 체크박스를 선택합니다.

#### 코드 제안 로그 보기 {#view-code-suggestions-logs}

IDE에 대해 코드 제안이 활성화되어 있지만 제안이 여전히 표시되지 않으면:

1. IDE에서 설정 편집기를 엽니다:
   - macOS의 경우 <kbd>Command</kbd>+<kbd>,</kbd>를 누릅니다.
   - Windows 또는 Linux의 경우 <kbd>Control</kbd>+<kbd>,</kbd>를 누릅니다.
1. **기타** 설정으로 이동합니다:
   - VS Code에서 **확장** > **GitLab** > **기타**를 선택합니다.
   - GitLab Web IDE에서 **확장** > **GitLab Workflow** > **기타**를 선택합니다.
1. **GitLab: 디버그** 아래에서 체크박스를 선택합니다.
   - Web IDE의 경우 [마켓플레이스 확장](../../web_ide/_index.md#manage-extensions)이 활성화되어 있어야 합니다.
1. 상단 메뉴에서 **보기** > **출력**을 선택하여 하단 패널을 열고 다음 중 하나를 수행합니다:
   - 명령 팔레트에서 `GitLab: Show Extension Logs`을 선택합니다.
   - 하단 패널의 오른쪽에서 드롭다운 목록을 선택하여 로그를 필터링합니다. **GitLab**을 선택합니다.
1. 설정 편집기에서 **GitLab Duo** 설정으로 이동합니다.
1. **GitLab Duo 코드 제안** 체크박스를 선택 해제했다가 다시 선택합니다.

### 코드 생성 결과의 스트리밍 비활성화 {#disable-streaming-of-code-generation-results}

기본적으로 코드 생성은 AI 생성 코드를 스트리밍합니다. 스트리밍은 전체 코드 스니펫이 생성될 때까지 기다리지 않고 생성된 코드를 편집기에 점진적으로 전송합니다. 이는 더 인터랙티브하고 반응성이 좋은 환경을 제공합니다.

코드 생성 결과를 완료된 후에만 보려면 스트리밍을 끌 수 있습니다. 스트리밍을 비활성화하면 코드 생성 요청이 더 오래 걸리는 것으로 인식될 수 있습니다. 스트리밍을 비활성화하려면:

1. VS Code에서 설정 편집기를 엽니다.
   - macOS의 경우 <kbd>Command</kbd>+<kbd>,</kbd>를 누릅니다.
   - Windows 또는 Linux의 경우 <kbd>Control</kbd>+<kbd>,</kbd>를 누릅니다.
1. 오른쪽 위 모서리에서 **설정 열기(JSON)**를 선택하여 `settings.json` 파일을 편집합니다:

   !['설정 열기'를 포함한 VS Code의 오른쪽 위 모서리의 아이콘입니다.](img/open_settings_v17_5.png)
1. `settings.json` 파일에서 이 줄을 추가하거나 이미 존재하는 경우 `false`로 설정합니다:

   ```json
   "gitlab.featureFlags.streamCodeGenerations": false,
   ```

1. 변경 사항을 저장합니다.

### 오류: 직접 연결 실패 {#error-direct-connection-fails}

{{< history >}}

- 직접 연결이 GitLab 17.2에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/13252)되었습니다.

{{< /history >}}

지연 시간을 줄이기 위해 VS Code용 GitLab 확장은 GitLab 인스턴스를 우회하여 제안 완성 요청을 GitLab Cloud Connector로 직접 보내려고 시도합니다. 이 네트워크 연결은 VS Code 확장의 프록시 및 인증서 설정을 사용하지 않습니다.

GitLab 인스턴스가 직접 연결을 지원하지 않거나 네트워크가 확장을 GitLab Cloud Connector에 연결하는 것을 방지하면 로그에서 다음 경고를 볼 수 있습니다:

```plaintext
Failed to fetch direct connection details from GitLab instance.
Code suggestion requests will be sent to GitLab instance.
```

이 오류는 인스턴스가 직접 연결을 지원하지 않거나 잘못 구성되었음을 의미합니다.

이 오류가 표시되면 확장이 GitLab Cloud Connector에 연결할 수 없으며 GitLab 인스턴스를 사용하도록 되돌아갑니다:

```plaintext
Direct connection for code suggestions failed.
Code suggestion requests will be sent to your GitLab instance.
```

GitLab 인스턴스를 통한 간접 연결은 약 100ms 느리지만 그 외에는 동일하게 작동합니다. 이 문제는 LAN 방화벽 또는 프록시 설정과 같은 네트워크 연결 문제로 인해 발생하는 경우가 많습니다.

## JetBrains IDE 문제 해결 {#jetbrains-ides-troubleshooting}

다음 문서는 JetBrains IDE의 코드 제안 관련 문제 해결에 대한 것입니다.

JetBrains IDE의 비코드 제안 문제 해결에 대해서는 [JetBrains 문제 해결](../../../../editor_extensions/jetbrains_ide/jetbrains_troubleshooting.md)을 참조하세요.

### JetBrains IDE에 제안이 표시되지 않음 {#suggestions-not-displayed-in-jetbrains-ides}

1. **도구** > **GitLab Duo** 메뉴에서 **설정 확인**을 선택합니다. 상태 확인이 통과하는지 확인합니다.
1. JetBrains IDE가 작업 중인 파일의 언어를 기본적으로 지원하는지 확인합니다. **설정** > **언어 및 프레임워크**로 이동하여 JetBrains IDE에서 지원하는 전체 언어 및 프레임워크 목록을 확인합니다.

### 오류: `unable to find valid certification path to requested target` {#error-unable-to-find-valid-certification-path-to-requested-target}

GitLab Duo 플러그인은 GitLab 인스턴스에 연결하기 전에 TLS 인증서 정보를 확인합니다. [사용자 정의 SSL 인증서를 추가](../../../../editor_extensions/jetbrains_ide/setup.md#add-a-custom-certificate-for-code-suggestions)할 수 있습니다.

### 오류: `Failed to check token` {#error-failed-to-check-token}

이 오류는 제공된 연결 인스턴스 URL 및 GitLab 언어 서버 프로세스에 전달된 인증 토큰이 유효하지 않을 때 발생합니다. 코드 제안을 다시 활성화하려면:

1. IDE의 상단 표시줄에서 IDE 이름을 선택한 다음 **설정**을 선택합니다.
1. 왼쪽 사이드바에서 **도구** > **GitLab Duo**를 선택합니다.
1. **연결** 아래에서 **설정 확인**을 선택합니다.
1. 필요에 따라 **연결** 세부 정보를 업데이트합니다.
1. **설정 확인**을 선택하고 인증이 성공하는지 확인합니다.
1. **확인** 또는 **저장**을 선택합니다.

## Microsoft Visual Studio 문제 해결 {#microsoft-visual-studio-troubleshooting}

다음 문서는 Microsoft Visual Studio의 코드 제안 관련 문제 해결에 대한 것입니다.

Microsoft Visual Studio의 비코드 제안 문제 해결에 대해서는 [Visual Studio 문제 해결](../../../../editor_extensions/visual_studio/visual_studio_troubleshooting.md)을 참조하세요.

### IntelliCode가 없습니다 {#intellicode-is-missing}

코드 제안에는 Visual Studio의 IntelliCode 구성 요소가 필요합니다. 구성 요소가 없으면 Visual Studio를 시작할 때 다음과 같은 오류가 표시될 수 있습니다:

```plaintext
SetSite failed for package [VisualStudioPackage]Source: 'Microsoft.VisualStudio.Composition'
Description: Expected 1 export(s) with contract name "Microsoft.VisualStudio.Language.Suggestions.SuggestionServiceBase"
but found 0 after applying applicable constraints.

Microsoft.VisualStudio.Composition.CompositionFailedException:
Expected 1 export(s) with contract name "Microsoft.VisualStudio.Language.Suggestions.SuggestionServiceBase"
but found 0 after applying applicable constraints.

  at Microsoft.VisualStudio.Composition.ExportProvider.GetExports(ImportDefinition importDefinition)
  at Microsoft.VisualStudio.Composition.ExportProvider.GetExports[T,TMetadataView](String contractName, ImportCardinality cardinality)
  at Microsoft.VisualStudio.Composition.ExportProvider.GetExport[T,TMetadataView](String contractName)
  at Microsoft.VisualStudio.Composition.ExportProvider.GetExportedValue[T]()
  at Microsoft.VisualStudio.ComponentModelHost.ComponentModel.GetService[T]()
[...]
```

이 문제를 해결하려면 IntelliCode 구성 요소를 설치하세요:

1. Windows 시작 메뉴에서 **Visual Studio Installer**를 검색하고 엽니다.
1. Visual Studio 인스턴스를 선택한 다음 **수정**을 선택합니다.
1. **개별 구성 요소** 탭에서 **IntelliCode**를 검색합니다.
1. 구성 요소의 체크박스를 선택한 다음 오른쪽 하단에서 **수정**을 선택합니다.
1. Visual Studio Installer가 설치를 마칠 때까지 기다립니다.

### Microsoft Visual Studio에 제안이 표시되지 않음 {#suggestions-not-displayed-in-microsoft-visual-studio}

1. 확장을 올바르게 [설정](../../../../editor_extensions/visual_studio/setup.md)했는지 확인합니다.
1. **도구** > **옵션** 메뉴에서 **GitLab** 옵션을 찾습니다. **로그 수준**이 **디버그**로 설정되어 있는지 확인합니다.
1. **보기** > **출력**에서 확장 로그를 엽니다. 드롭다운 목록을 **GitLab 확장**으로 변경하면 로그 필터가 됩니다.
1. 디버그 로그에 유사한 출력이 있는지 확인합니다:

```shell
14:48:21:344 GitlabProposalSource.GetCodeSuggestionAsync
14:48:21:344 LsClient.SendTextDocumentCompletionAsync("GitLab.Extension.Test\TestData.cs", 34, 0)
14:48:21:346 LS(55096): time="2023-07-17T14:48:21-05:00" level=info msg="update context"
```

다른 확장이 유사한 제안 또는 완성 기능을 제공하면 확장이 제안을 반환하지 않을 수 있습니다. 이 문제를 해결하려면:

1. 다른 모든 Visual Studio 확장을 비활성화합니다.
1. 이제 코드 제안을 받는지 확인합니다.
1. 확장을 한 번에 하나씩 다시 활성화하고 매번 코드 제안을 테스트하여 충돌하는 확장을 찾습니다.

## Neovim 문제 해결 {#neovim-troubleshooting}

다음 문서는 Neovim의 코드 제안 관련 문제 해결에 대한 것입니다.

Neovim의 비코드 제안 문제 해결에 대해서는 [Neovim 문제 해결](../../../../editor_extensions/neovim/neovim_troubleshooting.md)을 참조하세요.

### 코드 완성 실패 {#code-completions-fails}

1. Neovim에서 `omnifunc`이 설정되어 있는지 확인합니다:

   ```lua
   :verbose set omnifunc?
   ```

1. Neovim에서 이 명령을 실행하여 언어 서버가 활성화되어 있는지 확인합니다:

   ```lua
   :lua =vim.lsp.get_active_clients()
   ```

1. `~/.local/state/nvim/lsp.log`의 언어 서버 로그를 확인합니다.
1. Neovim에서 이 명령을 실행하여 `vim.lsp` 로그 경로에 오류가 있는지 검사합니다:

   ```lua
   :lua =vim.cmd('view ' .. vim.lsp.get_log_path())
   ```

## 코드 완성의 지연 시간 문제 {#latency-issues-with-code-completion}

코드 완성을 위해 특정 모델이 선택된 프로젝트에서 좌석이 할당된 경우:

- IDE 확장이 [AI Gateway로의 직접 연결](_index.md#direct-and-indirect-connections)을 비활성화합니다.
- 코드 완성 요청은 GitLab 모놀리스를 통해 이동하며, 이는 이러한 요청에 응답하도록 지정된 모델을 선택합니다.

이로 인해 코드 완성 요청의 지연 시간이 증가할 수 있습니다.
