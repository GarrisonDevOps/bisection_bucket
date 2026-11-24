---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 사용자 지정 규칙
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 사용자 지정 규칙이 GitLab 18.2에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/550743)되었습니다.
  - GitLab for VS Code 6.32.2에서 [도입](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.32.2)되었습니다.
  - JetBrains IDE용 GitLab Duo 플러그인 3.12.2에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.12.2)되었습니다.
  - GitLab for Visual Studio 0.60.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-visual-studio-extension/-/releases/v0.60.0)되었습니다.
  - GitLab Duo CLI 8.43.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.43.0)되었습니다.
- 사용자 수준의 사용자 지정 규칙이 GitLab 18.7에서 [추가](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/2452)되었습니다.
- GitLab 18.8에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273)되었습니다.
- GitLab UI에 대한 지원이 GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/593279)되었습니다.

{{< /history >}}

GitLab Duo Agent Platform에서 사용자 지정 규칙을 사용하여 생성된 출력(예: 코드 또는 설명서)이 특정 지침이나 개발 스타일 가이드와 같은 기타 요구사항과 일치하는지 확인할 수 있습니다.

다음 Agent Platform 기능은 사용자 지정 규칙을 지원합니다:

- GitLab UI 및 로컬 환경에서 [GitLab Duo Agentic Chat](../../gitlab_duo_chat/agentic_chat.md)을 사용합니다.
- [기본 및 사용자 지정 에이전트](../agents/_index.md).
- [기본 및 사용자 지정 플로우](../flows/_index.md)(Code Review Flow 제외).

## 사용자 지정 규칙 생성 {#create-custom-rules}

GitLab Duo를 사용하는 방식에 따라 두 가지 수준에서 사용자 지정 규칙을 생성할 수 있습니다:

| 수준                                                           | GitLab UI | 편집기 확장 | GitLab Duo CLI |
|-----------------------------------------------------------------|--------------------------|------------------|--------------|
| 사용자 수준: 모든 프로젝트에 적용        | {{< no >}}  |  {{< yes >}}    | {{< yes >}} |
| 프로젝트 수준: 특정 프로젝트에만 적용  | {{< yes >}} | {{< yes >}}         | {{< yes >}} |

IDE에서 다중 루트 워크스페이스를 사용하는 경우 워크스페이스의 각 프로젝트에 대한 프로젝트 수준의 사용자 지정 규칙을 생성할 수 있습니다.

사용자 수준 및 프로젝트 수준의 규칙이 모두 존재하면 GitLab Duo Chat은 두 규칙을 대화에 모두 적용합니다.

사전 요구 사항:

- [Agent Platform 사전 요구사항](../_index.md#prerequisites)을 충족하세요.
- 로컬 환경에서 GitLab Duo를 사용하려면 다음 중 하나를 설치하고 구성하세요:
  - [GitLab for VS Code](../../../editor_extensions/visual_studio_code/setup.md) 6.32.2 이상.
  - [JetBrains IDE용 GitLab Duo 플러그인](../../../editor_extensions/jetbrains_ide/setup.md) 3.12.2 이상.
  - [GitLab for Visual Studio](../../../editor_extensions/visual_studio/setup.md) 0.60.0 이상.
  - [GitLab Duo CLI](../../gitlab_duo_cli/set_up.md) 8.43.0 이상.

> [!note]
> 사용자 지정 규칙을 생성하기 전에 존재했던 대화는 해당 규칙을 따르지 않습니다.

### 사용자 수준의 사용자 지정 규칙 생성 {#create-user-level-custom-rules}

사용자 수준의 사용자 지정 규칙은 로컬 환경의 모든 프로젝트에 적용됩니다.

1. 홈 디렉터리에 사용자 지정 규칙 파일을 생성하세요:
   - Linux 또는 macOS에서 파일을 `~/.gitlab/duo/chat-rules.md`에 만듭니다.
   - Windows에서 파일을 `%APPDATA%\GitLab\duo\chat-rules.md`에 만듭니다.
1. 파일에 사용자 지정 규칙을 추가합니다. 예를 들어:

   ```markdown
   - Don't put comments in the generated code
   - Be brief in your explanations
   - Always use single quotes for JavaScript strings
   ```

1. 파일을 저장합니다.
1. 새 사용자 지정 규칙을 적용하려면 다음 중 하나를 수행하세요:
   - 새 GitLab Duo Chat 대화를 시작합니다.
   - Chat 대화, 토론, 이슈 또는 머지 리퀘스트에서 에이전트를 사용합니다.
   - 플로우를 트리거합니다.

특정 환경 변수를 설정한 경우 다른 위치에 사용자 지정 규칙 파일을 생성합니다:

- `GLAB_CONFIG_DIR` 환경 변수를 설정한 경우 `$GLAB_CONFIG_DIR/chat-rules.md`에서 파일을 생성합니다.
- `XDG_CONFIG_HOME` 환경 변수를 설정한 경우 `$XDG_CONFIG_HOME/gitlab/duo/chat-rules.md`에서 파일을 생성합니다.

### 프로젝트 수준의 사용자 지정 규칙 생성 {#create-project-level-custom-rules}

프로젝트 수준의 사용자 지정 규칙은 특정 프로젝트에만 적용됩니다. 이 방법을 사용하여 프로젝트의 사용자 지정 규칙 집합을 팀에 적용할 수 있습니다. 예를 들어 팀에서 사용하는 개발 스타일 가이드 집합을 적용할 수 있습니다.

1. 프로젝트의 루트에 사용자 지정 규칙 파일을 생성합니다: `.gitlab/duo/chat-rules.md`.
1. 파일에 사용자 지정 규칙을 추가합니다. 예를 들어:

   ```markdown
   - Don't put comments in the generated code
   - Be brief in your explanations
   - Always use single quotes for JavaScript strings
   ```

1. 파일을 저장합니다.
1. 프로젝트의 경우: `.gitlab/duo/chat-rules.md` 파일을 Git 리포지토리에 추가합니다. 그러면 Chat, 에이전트 및 플로우가 자동으로 리포지토리에서 컨텍스트로 사용자 지정 규칙을 읽습니다.
1. 새 사용자 지정 규칙을 적용하려면 새 GitLab Duo 대화를 시작합니다.

   사용자 지정 규칙을 변경할 때마다 이를 수행해야 합니다.

자세한 내용은 [GitLab Duo Chat 사용자 지정 규칙 튜토리얼 블로그](https://about.gitlab.com/blog/custom-rules-duo-agentic-chat-deep-dive/)를 참조하세요.

## 사용자 지정 규칙 업데이트 {#update-custom-rules}

사용자 지정 규칙을 업데이트하려면 사용자 지정 규칙 파일을 편집하고 저장합니다. 그런 다음 새 GitLab Duo 대화를 시작하여 업데이트된 규칙을 적용합니다.

Chat을 사용하여 사용자 지정 규칙 파일을 직접 편집할 수 없습니다.

사용자 지정 규칙 변경을 승인해야 하는 사람을 관리하려면 [코드 소유자](../../project/codeowners/_index.md)를 사용합니다.

## 관련 항목 {#related-topics}

- [AGENTS.md 사용자 지정 파일](agents_md.md)
- [에이전트 스킬](agent_skills.md)
