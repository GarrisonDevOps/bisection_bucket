---
stage: AI Coding
group: DAP Repository Flows
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Code Suggestions는 여러 편집기와 언어를 지원합니다.
title: 지원되는 확장 프로그램 및 언어
---

Code Suggestions는 다음 편집기 확장 프로그램 및 언어에서 사용할 수 있습니다.

## 지원되는 편집기 확장 {#supported-editor-extensions}

Code Suggestions를 사용하려면 다음 편집기 확장 중 하나를 사용하세요:

| IDE                                                             | 확장 |
|-----------------------------------------------------------------|-----------|
| Visual Studio Code(VS Code)                                    | [GitLab for VS Code](https://marketplace.visualstudio.com/items?itemName=GitLab.gitlab-workflow) |
| [GitLab Web IDE(Cloud의 VS Code)](../../web_ide/_index.md) | 설정이 필요 없습니다. |
| Microsoft Visual Studio(Windows용 2022)                      | [Visual Studio GitLab 확장](https://marketplace.visualstudio.com/items?itemName=GitLab.GitLabExtensionForVisualStudio) |
| JetBrains IDE                                                  | [GitLab Duo Plugin for JetBrains](https://plugins.jetbrains.com/plugin/22325-gitlab-duo) |
| Neovim                                                          | [`gitlab.vim` 플러그인](https://gitlab.com/gitlab-org/editor-extensions/gitlab.vim) |
| Eclipse                                                          | [GitLab for Eclipse](../../../../editor_extensions/eclipse/setup.md) |

[GitLab Language Server](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp)는 VS Code, JetBrains IDE, Visual Studio, Eclipse 및 Neovim에서 사용됩니다. Language Server는 더 많은 플랫폼에서 더 빠른 반복을 지원합니다. GitLab이 공식 지원을 제공하지 않는 IDE에서 Code Suggestions를 지원하도록 구성할 수도 있습니다.

다른 IDE 확장 지원에 관심을 표시할 수 있습니다 [이 이슈에서](https://gitlab.com/gitlab-org/editor-extensions/meta/-/issues/78).

## IDE별 지원 언어 {#supported-languages-by-ide}

VS Code에서 Code Suggestions는 IDE가 지원하는 모든 언어(일반 텍스트 제외)에서 작동합니다. Kotlin, Scala 또는 Terraform과 같은 일부 언어의 경우 VS Code에 언어 지원을 추가하려면 타사 확장을 설치해야 합니다. [특정 언어에 대해 Code Suggestions을 끌 수](#manage-languages-for-code-suggestions) 있습니다.

다른 IDE의 경우 다음 표에는 Code Suggestions이 기본적으로 지원하는 언어가 나열되어 있습니다. Code Suggestions은 다른 언어에서도 작동하지만 [수동으로 지원을 추가해야](#add-support-for-more-languages) 합니다.

| 언어                            | Web IDE     | JetBrains IDE | Visual Studio 2022 for Windows | Neovim                   | Eclipse |
|-------------------------------------|-------------|----------------|--------------------------------|--------------------------|---------|
| C                                   | {{< yes >}} | {{< no >}}     | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| C++                                 | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| C#                                  | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| CSS                                 | {{< yes >}} | {{< no >}}     | {{< no >}}                     | {{< no >}}               | {{< no >}} |
| Go                                  | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| Google SQL                          | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< no >}} |
| HAML                                | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| HTML                                | {{< yes >}} | {{< no >}}     | {{< no >}}                     | {{< no >}}               | {{< no >}} |
| Java                                | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| JavaScript                          | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| Kotlin                              | {{< no >}}  | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| 마크다운                            | {{< yes >}} | {{< no >}}     | {{< no >}}                     | {{< no >}}               | {{< no >}} |
| PHP                                 | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| Python                              | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| Ruby                                | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| Rust                                | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| Scala                               | {{< no >}}  | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| 셸 스크립트(`bash` 전용)         | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| Svelte                              | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| Swift                               | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| TypeScript(`.ts` 및 `.tsx` 파일) | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |
| Terraform                           | {{< no >}}  | {{< yes >}}    | {{< no >}}                     | {{< yes >}}[^requires-third-party] | {{< yes >}} |
| Vue                                 | {{< yes >}} | {{< yes >}}    | {{< yes >}}                    | {{< yes >}}              | {{< yes >}} |

[^requires-third-party]: Neovim에는 `terraform` 파일 형식을 제공하는 타사 확장이 필요합니다.

> [!note]
> 일부 언어는 모든 JetBrains IDE에서 지원되지 않거나 추가 플러그인 지원이 필요할 수 있습니다. IDE의 구체적인 사항은 JetBrains 설명서를 참조하세요.

## IaC(코드 기반 인프라) 지원 {#support-for-infrastructure-as-code-iac}

Code Suggestions는 다음을 포함한 코드 기반 인프라 인터페이스에서 작동합니다:

- Kubernetes Resource Model(KRM)
- Google Cloud CLI
- Terraform

## Code Suggestions에 대한 언어 관리 {#manage-languages-for-code-suggestions}

{{< history >}}

- GitLab for VS Code 4.21.0에서 [도입됨](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/blob/main/CHANGELOG.md#4210-2024-07-16)
- GitLab 19.5 릴리스 중 GitLab for VS Code 6.92.0에서 모든 언어에 대한 제안이 기본적으로 [켜짐](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.92.0).

{{< /history >}}

VS Code에서 Code Suggestions는 기본적으로 모든 언어에 대해 켜져 있습니다. 특정 언어에 대해 끌 수 있습니다.

현재 파일의 언어에 대해 Code Suggestions을 끄거나 켜려면:

1. VS Code에서 해당 언어로 파일을 엽니다.
1. 명령 팔레트를 엽니다:
   - macOS의 경우 <kbd>Command</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>를 누르세요.
   - Windows 또는 Linux의 경우 <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>를 누르세요.
1. **GitLab: 현재 언어에 대해 Code Suggestions 전환**을 선택합니다.

상태 표시줄에서 GitLab Duo 아이콘을 선택한 다음 현재 언어에 대해 Code Suggestions을 끄거나 켜는 옵션을 선택할 수도 있습니다.

둘 이상의 언어에 대해 Code Suggestions을 끄려면:

1. VS Code에서 설정 편집기를 엽니다.
   - macOS의 경우 <kbd>Command</kbd>+<kbd>,</kbd>를 누릅니다.
   - Windows 또는 Linux의 경우 <kbd>Control</kbd>+<kbd>,</kbd>를 누릅니다.
1. **확장** > **GitLab** > **GitLab Duo**를 선택합니다.
1. **GitLab › Duo Code Suggestions: 비활성화된 언어**, **항목 추가**를 선택합니다.
1. [언어 식별자](https://code.visualstudio.com/docs/languages/identifiers#_known-language-identifiers)를 입력합니다. 예를 들어 `python` 또는 `markdown`.
1. **확인**을 선택합니다.

변경 사항이 자동으로 저장되고 즉시 적용됩니다.

언어에 대해 Code Suggestions을 끄면 GitLab Duo 아이콘이 변경되어 이 언어에 대해 제안을 사용할 수 없음을 보여줍니다.

이전 버전의 확장에서 **지원 언어 활성화** 설정에서 언어를 끈 경우 업데이트할 때 **비활성화된 언어**에 추가됩니다.

## 더 많은 언어에 대한 지원 추가 {#add-support-for-more-languages}

VS Code에서는 언어를 추가할 필요가 없습니다. Code Suggestions은 일반 텍스트를 제외한 모든 언어에서 작동합니다.

다른 IDE에서 원하는 언어에 Code Suggestions을 기본적으로 사용할 수 없으면 로컬에서 언어에 대한 지원을 추가할 수 있습니다. 그러나 Code Suggestions이 예상대로 작동하지 않을 수 있습니다.

{{< tabs >}}

{{< tab title="JetBrains IDE" >}}

사전 요구 사항:

- [JetBrains IDE용 GitLab Duo 플러그인](../../../../editor_extensions/jetbrains_ide/_index.md)을 설치하고 활성화했습니다.
- [JetBrains 확장 설정](../../../../editor_extensions/jetbrains_ide/setup.md) 지침을 완료했으며 확장이 GitLab 계정에 액세스하도록 허가했습니다.

다음과 같이 설정합니다.

1. [언어 식별자](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocumentItem) 목록에서 원하는 언어를 찾습니다. 나중에 사용할 언어의 식별자가 필요합니다.
1. IDE의 상단 표시줄에서 IDE 이름을 선택한 후 **설정**을 선택합니다.
1. 왼쪽 사이드바에서 **도구** > **GitLab Duo**를 선택합니다.
1. **Code Suggestions 활성화된 언어** > **추가 언어** 아래에서 지원할 각 언어의 식별자를 추가합니다. 식별자는 소문자여야 하며 `html`과(와) 같아야 합니다. 여러 식별자를 쉼표로 구분하고 `html,powershell,latex`과(와) 같이 각 식별자에 선행 마침표를 추가하지 마세요.
1. **확인**을 선택합니다.

{{< /tab >}}

{{< tab title="Eclipse" >}}

사전 요구 사항:

- [GitLab for Eclipse 플러그인](../../../../editor_extensions/eclipse/_index.md)을 설치하고 활성화했습니다.
- [Eclipse 설정](../../../../editor_extensions/eclipse/setup.md) 지침을 완료했으며 확장이 GitLab 계정에 액세스하도록 허가했습니다.

다음과 같이 설정합니다.

1. Eclipse 하단 도구 모음에서 GitLab 아이콘을 선택합니다.
1. **설정 표시**를 선택합니다.
1. **Code Suggestions 활성화된 언어** 섹션으로 스크롤합니다.
1. **추가 언어**에서 쉼표로 구분된 언어 식별자 목록을 추가합니다. 식별자에 선행 마침표를 추가하지 마세요. 예를 들어 `html`, `md` 및 `powershell`을(를) 사용합니다.

{{< /tab >}}

{{< /tabs >}}
