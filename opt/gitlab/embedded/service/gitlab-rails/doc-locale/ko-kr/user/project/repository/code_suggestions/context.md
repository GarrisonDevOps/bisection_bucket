---
stage: AI Coding
group: DAP Repository Flows
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Code Suggestions 상황별 인식
---

GitLab Duo가 결정을 내리고 제안을 제공하는 데 도움이 되는 다양한 정보를 사용할 수 있습니다.

정보는 다음과 같이 제공될 수 있습니다:

- 항상.
- 사용자의 위치를 기반으로(탐색할 때 컨텍스트가 변경됨).

Code Suggestions에 다음 컨텍스트를 사용할 수 있습니다.

## 항상 사용 가능 {#always-available}

- 일반적인 프로그래밍 지식, 모범 사례 및 언어별 특성.
- 보고 있거나 편집 중인 파일의 이름, 확장자, 콘텐츠(커서 앞뒤의 콘텐츠 포함).

## 위치 기반 {#based-on-location}

- IDE에서 탭으로 열려 있는 파일. 선택 사항이지만 기본적으로 활성화됩니다.
  - 사전 요구 사항:
    - 최적의 컨텍스트 가중치를 위해 GitLab 17.2 이상이 필요합니다.
    - 지원되는 IDE 확장. 버전 요구 사항을 보려면 [열린 파일을 컨텍스트로 사용](#using-open-files-as-context)을 참조하세요.
  - 이러한 파일은 GitLab Duo에 프로젝트의 표준 및 사례에 대한 정보를 제공합니다.
  - 컨텍스트로 사용하지 않을 파일을 닫으세요.
  - 가장 최근에 열거나 변경한 파일이 컨텍스트에 우선 순위를 매깁니다.
  - 코드 완성은 Code Suggestions가 지원하는 모든 언어를 인식합니다.
  - 코드 생성은 다음 언어의 파일만 인식합니다: Go, Java, JavaScript, Kotlin, Python, Ruby, Rust, TypeScript(`.ts` 및 `.tsx` 파일), Vue, YAML.
- 보고 있거나 편집 중인 파일에서 가져온 파일. 선택 사항이며 기본적으로 비활성화됩니다.
  - 이러한 파일은 GitLab Duo에 파일의 클래스 및 메서드에 대한 정보를 제공합니다.
  - `.js`, `.jsx`, `.ts`, `.tsx`, `.vue` 파일 형식을 포함한 JavaScript 및 TypeScript 파일에서 지원됩니다.
- 편집기에서 선택한 코드.
- Code Suggestions의 Repository X-Ray 파일.

> [!note]
> 알려진 형식과 일치하는 비밀번호 및 민감한 값은 코드 생성에 사용되기 전에 편집됩니다. 이는 `/include`을 사용하여 추가된 파일에 적용됩니다.

Code Suggestions가 IDE에서 컨텍스트를 사용하는 방법에 대한 자세한 내용은 [GitLab Language Server 설명서](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp#use-open-tabs-as-context)를 참조하세요.

### Code Suggestions가 컨텍스트에 사용하는 것 변경 {#change-what-code-suggestions-uses-for-context}

Code Suggestions가 다른 파일을 컨텍스트로 사용하는지 여부를 변경할 수 있습니다.

#### 열린 파일을 컨텍스트로 사용 {#using-open-files-as-context}

{{< history >}}

- GitLab 17.1에서 `advanced_context_resolver`이라는 [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/464767)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.1에서 `code_suggestions_context`이라는 [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/462750)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab for VS Code 4.20.0에서 [도입됨](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/issues/276).
- GitLab Duo for JetBrains 2.7.0에서 [도입됨](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/issues/462).
- 2024년 7월 16일에 GitLab Neovim 플러그인에 [추가됨](https://gitlab.com/gitlab-org/editor-extensions/gitlab.vim/-/merge_requests/152).
- 기능 플래그 `advanced_context_resolver` 및 `code_suggestions_context`는 GitLab 17.2에서 GitLab.com에서 활성화되고 GitLab 17.4에서 GitLab Self-Managed에서 활성화됩니다.
- GitLab 18.6에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/462750)되었습니다. `code_suggestions_context` 기능 플래그가 제거되었습니다.

{{< /history >}}

기본적으로 Code Suggestions는 제안을 할 때 IDE에서 열린 파일을 컨텍스트로 사용합니다. 하지만 이 설정을 해제할 수 있습니다.

사전 요구 사항:

- GitLab 17.2 이상. Code Suggestions를 지원하는 이전 GitLab 버전은 열린 탭의 콘텐츠를 프로젝트의 다른 파일보다 더 높게 가중치를 부여할 수 없습니다.
- 지원되는 확장:
  - GitLab for VS Code 확장 6.2.2 이상.
  - GitLab Duo plugin for JetBrains IDEs 3.6.5 이상.
  - GitLab plugin for Neovim 1.1.0 이상.
  - GitLab for Visual Studio 확장 0.51.0 이상.

열린 파일을 컨텍스트로 사용하도록 변경하려면:

{{< tabs >}}

{{< tab title="Visual Studio Code" >}}

1. VS Code에서 설정 편집기를 엽니다.
   - macOS의 경우 <kbd>Command</kbd>+<kbd>,</kbd>를 누릅니다.
   - Windows 또는 Linux의 경우 <kbd>Control</kbd>+<kbd>,</kbd>를 누릅니다.
1. **확장** > **GitLab** > **GitLab Duo**를 선택합니다.
1. **GitLab › Duo Code Suggestions: Open Tabs Context**, **열린 탭의 콘텐츠를 컨텍스트로 사용**을 선택하거나 선택을 해제합니다.

{{< /tab >}}

{{< tab title="JetBrains IDEs" >}}

1. IDE의 상단 메뉴 모음으로 이동하여 **설정**을 선택합니다.
1. 왼쪽 사이드바에서 **도구**를 확장한 다음 **GitLab Duo**를 선택합니다.
1. **추가 언어** 아래에서 **열린 탭을 컨텍스트로 전송**을 선택하거나 선택을 해제합니다.
1. **적용** 또는 **저장**을 선택합니다.

{{< /tab >}}

{{< /tabs >}}

#### 가져온 파일을 컨텍스트로 사용 {#using-imported-files-as-context}

{{< history >}}

- GitLab 17.9에서 `code_suggestions_include_context_imports` [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/514124)되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab.com, GitLab Self-Managed, GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/514124) \- GitLab 17.11.
- 기능 플래그 `code_suggestions_include_context_imports`이 GitLab 18.0에서 [제거됨](https://gitlab.com/gitlab-org/gitlab/-/issues/536129).

{{< /history >}}

IDE에서 가져온 파일을 사용하여 코드 프로젝트에 대한 컨텍스트를 제공합니다. 가져온 파일 컨텍스트는 `.js`, `.jsx`, `.ts`, `.tsx`, `.vue` 파일 형식을 포함한 JavaScript 및 TypeScript 파일에서 지원됩니다.
