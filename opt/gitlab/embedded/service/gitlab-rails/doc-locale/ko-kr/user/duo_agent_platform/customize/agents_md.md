---
stage: Agent Foundations
group: Agent Developer
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: AGENTS.md 사용자 지정 파일
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab Duo Chat에서 `AGENTS.md`에 대한 지원이 [도입되었습니다](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/2597) (GitLab 18.7).
  - GitLab for VS Code 6.60.0에서 [도입](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.60.0)되었습니다.
  - JetBrains IDE용 GitLab Duo 플러그인 3.26.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.26.0)되었습니다.
  - GitLab Duo CLI 8.47.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.47.0)되었습니다.
- 에이전트 플로우에서 `AGENTS.md`에 대한 지원이 [도입되었습니다](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/issues/1509) (GitLab 18.8).
- GitLab 18.8에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273)되었습니다.
- GitLab UI에 대한 지원이 GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/593279)되었습니다.

{{< /history >}}

GitLab Duo는 [`AGENTS.md` 사양](https://agents.md/)을 지원하며, 이는 AI 코딩 어시스턴트에 컨텍스트와 지시사항을 제공하기 위한 새로운 표준입니다.

`AGENTS.md` 파일을 사용하여 리포지토리 구조, 코딩 규칙, 스타일 가이드라인, 빌드 및 테스트 지시사항, 프로젝트 컨텍스트를 문서화합니다. `AGENTS.md` 파일을 지정하면, 이러한 세부사항은 GitLab Duo Agent Platform 및 이 사양을 지원하는 다른 AI 도구에서 사용할 수 있습니다.

GitLab Duo에서 사용할 `AGENTS.md` 파일을 지정합니다:

- GitLab UI 및 로컬 환경에 GitLab Duo Chat입니다.
- Code Review Flow를 제외한 기본 및 사용자 지정 플로우입니다.

## GitLab Duo가 `AGENTS.md` 파일을 사용하는 방법 {#how-gitlab-duo-uses-agentsmd-files}

GitLab Duo 사용 방식에 따라 여러 수준에서 `AGENTS.md` 파일을 만들 수 있습니다:

| 수준                                                           | GitLab UI | 편집기 확장 프로그램 | GitLab Duo CLI |
|-----------------------------------------------------------------|--------------------------|------------------|--------------|
| 사용자 수준: 모든 프로젝트에 적용        | {{< no >}}  |  {{< yes >}}    | {{< yes >}} |
| 프로젝트 수준: 특정 프로젝트에만 적용  | {{< yes >}} | {{< yes >}}         | {{< yes >}} |
| 하위 디렉터리 수준: 모노리포지토리 내 또는 구분되는 구성 요소가 있는 프로젝트 내의 특정 프로젝트에만 적용 | {{< no >}} | {{< yes >}} | {{< yes >}} |

IDE에서 다중 루트 워크스페이스를 사용하는 경우, 워크스페이스의 각 프로젝트에 대해 프로젝트 수준 `AGENTS.md` 파일을 만들 수 있습니다.

GitLab Duo는 모든 대화에서 사용자 수준 및 프로젝트 수준 `AGENTS.md` 파일의 사용 가능한 지시사항을 결합합니다. 작업에서 추가 `AGENTS.md` 파일이 포함된 디렉터리의 파일로 작업해야 하는 경우, Chat은 해당 지시사항도 적용합니다.

## GitLab Duo에서 `AGENTS.md`를 사용합니다 {#use-agentsmd-with-gitlab-duo}

> [!note]
> 새로운 대화 및 `AGENTS.md` 파일을 추가하거나 업데이트한 후에 생성된 플로우만 새로운 지시사항을 따릅니다. 이전에 있던 대화는 따르지 않습니다.

### 사전 요구 사항 {#prerequisites}

- [Agent Platform 필수 구성 요소](../_index.md#prerequisites)를 충족합니다.
- 로컬 환경의 GitLab Duo Chat을 위해 다음 중 하나를 설치하고 구성해야 합니다.
  - [GitLab for VS Code](../../../editor_extensions/visual_studio_code/setup.md) 6.60 이상.
  - [JetBrains IDE용 GitLab Duo 플러그인](../../../editor_extensions/jetbrains_ide/setup.md) 3.26.0 이상.
  - [GitLab Duo CLI](../../gitlab_duo_cli/set_up.md) 8.47.0 이상.
- 사용자 지정 플로우의 경우, 플로우의 구성 파일을 업데이트하여 실행기에서 전달된 `user_rule` 컨텍스트에 액세스합니다:

  ```yaml
  components:
  - name: "my_agent"
     type: AgentComponent
     prompt_id: "my_prompt"
     inputs:
     - from: "context:inputs.user_rule"
        as: "agents_dot_md"
      optional: true
  ```

  `optional: true`를 설정하면, 플로우가 `AGENTS.md` 파일이 없는 경우를 우아하게 처리합니다. 에이전트는 추가 컨텍스트를 포함하여 또는 포함하지 않고 작동합니다.

### 사용자 수준 `AGENTS.md` 파일 만들기 {#create-user-level-agentsmd-files}

사용자 수준 `AGENTS.md` 파일은 모든 프로젝트에 적용됩니다.

1. 홈 디렉터리에 `AGENTS.md` 파일을 만듭니다:
   - Linux 또는 macOS에서 파일을 `~/.gitlab/duo/AGENTS.md`에 만듭니다.
   - Windows에서 파일을 `%APPDATA%\GitLab\duo\AGENTS.md`에 만듭니다.
1. 파일에 지시 사항을 추가합니다. 예를 들어:

   {{< tabs >}}

   {{< tab title="개인 설정" >}}

   ```markdown
   # My personal coding preferences

   - Always explain code changes in simple terms for beginners
   - Use descriptive variable names
   - Add comments for complex logic
   - Prefer functional programming patterns when appropriate
   ```

   {{< /tab >}}

   {{< tab title="팀 표준" >}}

   ```markdown
   # Team coding standards

   - Follow our company's style guide for all code
   - Use TypeScript strict mode
   - Write unit tests for all new functions
   - Document all public APIs with JSDoc
   ```

   {{< /tab >}}

   {{< tab title="모노레포 컨텍스트" >}}

   ```markdown
   # Monorepo context

   - This is a monorepo with multiple services
   - Frontend code is in /apps/web
   - Backend services are in /services
   - Shared libraries are in /packages
   - Follow the architecture decision records in /docs/adr
   ```

   {{< /tab >}}

   {{< tab title="보안 가이드라인" >}}

   ```markdown
   # Security review guidelines

   - Always validate user input
   - Use parameterized queries for database operations
   - Implement proper authentication and authorization
   - Follow OWASP security best practices
   - Never log sensitive information
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. 파일을 저장합니다.
1. 지시 사항을 저장하려면 새 대화 또는 플로우를 시작합니다. `AGENTS.md` 파일을 변경할 때마다 이를 수행해야 합니다.

특정 환경 변수를 설정한 경우, `AGENTS.md` 파일을 다른 위치에서 만듭니다:

- `GLAB_CONFIG_DIR` 환경 변수를 설정한 경우, `$GLAB_CONFIG_DIR/AGENTS.md`에 파일을 만듭니다.
- `XDG_CONFIG_HOME` 환경 변수를 설정한 경우, `$XDG_CONFIG_HOME/gitlab/duo/AGENTS.md`에 파일을 만듭니다.

### 프로젝트 수준 `AGENTS.md` 파일 만들기 {#create-project-level-agentsmd-files}

프로젝트 수준 `AGENTS.md` 파일은 특정 프로젝트에만 적용됩니다.

1. 프로젝트의 루트에서 `AGENTS.md` 파일을 만듭니다.
1. 파일에 지시 사항을 추가합니다. 예를 들어:

   {{< tabs >}}

   {{< tab title="프로젝트 가이드라인" >}}

   ```markdown
   # Project-specific guidelines

   - This project uses React with TypeScript
   - Follow the component structure in /src/components
   - Use our custom hooks from /src/hooks
   - State management uses Redux Toolkit
   ```

   {{< /tab >}}

   {{< tab title="데이터베이스 마이그레이션" >}}

   ```markdown
   # Database migrations

   - To run database migrations, use `bin/rails db:migrate` from the project root
   - Do not run `rake db:migrate` directly
   - If a migration fails with a lock timeout, wait and retry once. Do not attempt
     a schema workaround
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. 파일을 저장합니다.
1. 지시 사항을 저장하려면 새 대화 또는 플로우를 시작합니다. `AGENTS.md` 파일을 변경할 때마다 이를 수행해야 합니다.

### 모노레포 및 하위 디렉터리에서 `AGENTS.md` 파일 만들기 {#create-agentsmd-files-in-monorepos-and-subdirectories}

모노레포 또는 개별 구성 요소가 있는 프로젝트의 경우, 하위 디렉터리에 `AGENTS.md` 파일을 배치하여 코드베이스의 여러 부분에 대한 컨텍스트 특정 지시사항을 제공할 수 있습니다.

GitLab Duo Chat이 하위 디렉터리에서 추가 `AGENTS.md` 파일을 발견하면, 해당 디렉터리의 파일을 편집하기 전에 관련 파일을 읽습니다. 예를 들어:

```plaintext
/my-project
  AGENTS.md              # Root instructions (included in all conversations)
  /frontend
    AGENTS.md            # Frontend-specific instructions
  /backend
    AGENTS.md            # Backend-specific instructions
```

이 예에서:

- 루트 `AGENTS.md`는 항상 대화에 포함됩니다.
- GitLab Duo가 `/frontend`의 파일을 편집할 때, `/frontend/AGENTS.md`를 먼저 읽습니다.
- GitLab Duo가 `/backend`의 파일을 편집할 때, `/backend/AGENTS.md`를 먼저 읽습니다.

이 접근 방식은 GitLab Duo가 제품의 각 부분에 대한 적합한 규칙을 따르도록 합니다.

하위 디렉터리에서 `AGENTS.md`를 사용합니다:

1. 프로젝트의 하위 디렉터리에서 `AGENTS.md` 파일을 만듭니다.
1. 해당 디렉터리에 특정한 지시 사항을 추가합니다. 예를 들어, 백엔드 서비스의 경우:

   ```markdown
   # Backend service guidelines

   - This service uses Node.js with Express
   - Follow RESTful API conventions
   - Use async/await for asynchronous operations
   - Validate all inputs with Joi schemas
   ```

1. 파일을 저장합니다.
1. 지시 사항을 적용하려면 해당 디렉터리에 파일이 관련되는 새 대화를 시작합니다. `AGENTS.md` 파일을 변경할 때마다 이를 수행해야 합니다.

## 관련 항목 {#related-topics}

- [사용자 지정 규칙](custom_rules.md)
