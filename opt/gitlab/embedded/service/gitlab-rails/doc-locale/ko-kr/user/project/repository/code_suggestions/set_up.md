---
stage: AI Coding
group: DAP Repository Flows
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: IDE에서 Code Suggestions를 설정합니다.
title: Code Suggestions 설정
---

GitLab Duo Code Suggestions는 IDE의 편집기 확장을 통해 사용할 수 있습니다.

## 사전 요구 사항 {#prerequisites}

- GitLab Duo Core [켜짐](../../../gitlab_duo/turn_on_off.md#turn-gitlab-duo-core-on-or-off).
- [지원되는 언어 및 IDE](supported_extensions.md).
- [기본 GitLab Duo 네임스페이스](../../../profile/preferences.md#namespace-resolution-in-your-local-environment) 설정, 또는 GitLab Duo 액세스 권한이 있는 프로젝트 열기.

## 편집기 확장 구성 {#configure-an-editor-extension}

Code Suggestions를 사용하려면 IDE용 확장을 설치한 후 GitLab Duo에 대해 인증하고 구성합니다. Code Suggestions는 기본적으로 켜져 있습니다.

- [Visual Studio Code](../../../../editor_extensions/visual_studio_code/setup.md)
- [GitLab Duo plugin for JetBrains IDEs](../../../../editor_extensions/jetbrains_ide/setup.md)
- [Visual Studio](../../../../editor_extensions/visual_studio/setup.md)
- [`gitlab.vim` Neovim용 플러그인](../../../../editor_extensions/neovim/setup.md)
- [GitLab for Eclipse](../../../../editor_extensions/eclipse/setup.md)

GitLab Web IDE에서 Code Suggestions는 추가 구성이 필요하지 않습니다. [Code Suggestions 사용](_index.md#use-code-suggestions)을 바로 시작할 수 있습니다.

## Code Suggestions가 켜져 있는지 확인 {#verify-that-code-suggestions-is-on}

Neovim을 제외한 GitLab의 모든 편집기 확장이 IDE의 상태 표시줄에 아이콘을 추가합니다. 아이콘을 확인하여 제안이 작동하는지 확인합니다.

예를 들어 Visual Studio에서:

![Visual Studio의 상태 표시줄입니다.](img/visual_studio_status_bar_v17_4.png)

| 아이콘 | 상태 | 의미 |
| :--- | :----- | :------ |
| {{< icon name="tanuki-ai" >}} | **준비** | GitLab Duo를 구성 및 활성화했으며, Code Suggestions를 지원하는 언어를 사용 중입니다. |
| {{< icon name="tanuki-ai-off" >}} | **구성되지 않음** | 개인 액세스 토큰을 입력하지 않았거나 Code Suggestions를 지원하지 않는 언어를 사용 중입니다. |
| ![Code Suggestions 가져오기에 대한 상태 아이콘입니다.](img/code_suggestions_loading_v17_4.svg) | **제안 로딩 중** | GitLab Duo가 Code Suggestions를 가져오고 있습니다. |
| ![Code Suggestions 오류에 대한 상태 아이콘입니다.](img/code_suggestions_error_v17_4.svg) | **오류** | GitLab Duo에서 오류가 발생했습니다. |
