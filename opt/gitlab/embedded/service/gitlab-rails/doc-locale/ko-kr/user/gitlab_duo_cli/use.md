---
stage: AI Clients
group: Developer Clients
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab Duo CLI를 대화형 및 헤드리스 모드에서 사용합니다.
title: GitLab Duo CLI 사용
---

{{< details >}}

- 티어:  Premium, Ultimate
- 제공 서비스:  GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Duo CLI는 두 가지 모드에서 사용할 수 있습니다.

- 대화형 모드:  GitLab UI 또는 편집기 확장 프로그램의 GitLab Duo Chat과 유사한 채팅 환경을 제공합니다. 빌드, 계획 및 자동 모드를 지원합니다.
- 헤드리스 모드: 러너, 스크립트 및 기타 자동화된 워크플로우에서 비대화형 사용을 활성화합니다.

## 전제 조건 {#prerequisites}

- GitLab Duo CLI가 설치되고 [설정되어](set_up.md) 있습니다.
- [기본 GitLab Duo 네임스페이스](../profile/preferences.md#namespace-resolution-in-your-local-environment)가 설정되어 있거나 GitLab Duo에 액세스할 수 있는 열린 프로젝트가 있습니다.

## 대화형 모드 {#interactive-mode}

GitLab Duo CLI를 대화형 모드로 사용하려면:

1. 설정을 기준으로 대화형 모드를 시작하는 명령을 입력합니다.

   {{< tabs >}}

   {{< tab title="glab" >}}

   ```shell
   glab duo cli
   ```

   {{< /tab >}}

   {{< tab title="duo" >}}

   ```shell
   duo
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. 프롬프트 `>`이 터미널 창에 나타납니다. 프롬프트 뒤에 질문이나 요청을 입력한 다음 <kbd>Enter</kbd>를 누릅니다.

   예를 들어:

   ```plaintext
   What is this repository about?

   Which issues need my attention?

   Help me implement issue 15.

   The pipelines in MR 23 are failing. Please help me fix them.
   ```

GitLab Duo CLI가 작동 중일 때 응답을 취소하려면 <kbd>Escape</kbd>를 누릅니다. GitLab Duo CLI는 현재 작업을 중지하고 프롬프트로 돌아갑니다.

<kbd>↑</kbd> 키를 사용하여 프롬프트 기록을 보거나 <kbd>Control</kbd>+<kbd>R</kbd>을 사용하여 검색합니다.

새로운 세션을 시작할 때 프롬프트 자리 표시자에 GitLab Duo CLI 기능에 대한 팁이 표시될 수 있습니다.

### 시작 카드 {#startup-cards}

{{< history >}}

- 시작 카드가 GitLab Duo CLI 9.11.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.11.0)되었으며, GitLab 19.4 릴리스 중입니다.
- `--startup-cards` 옵션과 `STARTUP_CARDS` 환경 변수가 GitLab Duo CLI 9.17.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.17.0)되었으며, GitLab 19.4 릴리스 중입니다.
- 온보딩 카드가 GitLab Duo CLI 9.28.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.28.0)되었으며, GitLab 19.5 릴리스 중입니다.

{{< /history >}}

시작 카드는 대화형 모드에서 새로운 세션을 시작할 때 터미널에 나타납니다. 첫 실행 시에는 온보딩 카드가, 이후 실행 시에는 시작 카드가 표시됩니다. 기존 세션을 재개할 때는 카드가 나타나지 않습니다.

시작 카드는 기본적으로 활성화되어 있지만 끌 수 있습니다.

#### 온보딩 카드 {#onboarding-card}

머신에서 GitLab Duo CLI를 처음 실행할 때 온보딩 카드를 사용하여 [MCP 서버를 연결](#model-context-protocol-mcp-connections)하고 GitLab 마켓플레이스에서 [플러그인](customize.md#plugins)을 설치할 수 있습니다.

카드는 단계를 선택하고 실행하기 위한 탐색 힌트를 표시합니다. 완료된 단계는 연결된 MCP 서버 수 또는 설치된 플러그인 수와 함께 체크마크를 표시합니다.

두 단계를 모두 완료한 후에도 첫 번째 프롬프트를 보낼 때까지 카드가 표시됩니다. 이후 실행 시 다시 나타나지 않습니다.

#### 시작 카드 {#welcome-card}

새로운 세션을 시작할 때마다 기본적으로 시작 카드가 나타납니다. [**세션 시작 시 작업 항목 표시**](#settings) 설정으로 카드를 끌 수 있습니다.

카드는 일반적인 작업을 시작하기 위한 프롬프트를 제시하고 프롬프트를 검색하고 실행하기 위한 탐색 힌트를 표시합니다. 예를 들어 GitLab 프로젝트에서 작업할 때 제안된 프롬프트는 열려 있는 머지 리퀘스트 및 이슈에서 빌드됩니다. 그렇지 않으면 카드에 일반적인 예제가 표시됩니다.

머지 리퀘스트 중 하나에 대한 프롬프트를 선택하고 해당 소스 브랜치가 존재하는 경우 프롬프트는 GitLab Duo에 먼저 해당 브랜치를 체크아웃하도록 지시합니다.

[**제안된 프롬프트를 /goal 세션으로 실행**](#settings) 설정이 활성화되어 있고 인스턴스가 GitLab 19.3 이상인 경우 검토 피드백을 처리하는 프롬프트는 `/goal` 세션으로 실행됩니다.

#### 시작 카드 숨기기 {#hide-the-startup-cards}

시작 카드는 기본적으로 활성화되어 있습니다. `--startup-cards`을(를) `false`으로 설정하여 끕니다:

{{< tabs >}}

{{< tab title="glab" >}}

```shell
glab duo cli --startup-cards false
```

{{< /tab >}}

{{< tab title="duo" >}}

```shell
duo --startup-cards false
```

{{< /tab >}}

{{< /tabs >}}

또는 `STARTUP_CARDS` 환경 변수를 `false`으로 설정합니다. 둘 다 설정하면 `--startup-cards` 옵션이 환경 변수보다 우선합니다.

### 상태 표시줄 {#status-bar}

화면 하단에는 다음이 있는 상태 표시줄이 표시됩니다:

- 현재 작업 디렉토리 및 Git 브랜치입니다.
- 감지된 GitLab 프로젝트 및 존재하는 경우 현재 브랜치에 대한 열린 머지 리퀘스트 및 파이프라인 상태입니다.
- 실행 중인 `/goal` 세션의 진행 상황입니다.
- 구성된 MCP 서버의 상태입니다.

### 모드 전환 {#switch-modes}

대화형 모드에서 작업하면서 GitLab Duo CLI 모드 간에 전환할 수 있습니다:

| 모드                 | 권한 | 작동 방식                                                                  |
|----------------------|-------------|-------------------------------------------------------------------------------|
| 빌드 모드(기본값) | 읽기-쓰기  | GitLab Duo는 작업을 실행하고 프로젝트를 변경할 수 있습니다.               |
| 플랜 모드            | 읽기 전용   | GitLab Duo는 프로젝트를 분석하고 변경 사항을 만들지 않고 플랜을 생성할 수 있습니다. |
| 자동 모드            | 읽기-쓰기  | GitLab Duo는 승인을 요청하지 않고 도구를 사용할 수 있습니다. 자세한 내용은 [자동 모드](#auto-mode)를 참조하세요. |

예를 들어, 플랜 모드에서 GitLab Duo와 함께 문제를 논의하면서 시작합니다. 준비되면 빌드 모드로 전환하고 GitLab Duo에 플랜을 구현하도록 지시합니다.

GitLab Duo CLI는 `>` 프롬프트 아래의 현재 모드를 표시합니다. 모드 간 전환하려면 <kbd>Tab</kbd>을 누릅니다.

### 슬래시 명령 {#slash-commands}

{{< history >}}

- GitLab 19.0 릴리스 중 `/exit` 슬래시 명령이 GitLab Duo CLI 8.88.0에 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.88.0)되었습니다.
- GitLab 19.0 릴리스 중 `/doctor` 슬래시 명령이 GitLab Duo CLI 8.94.0에 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.94.0)되었습니다.
- GitLab 19.0 릴리스 중 `/skills` 슬래시 명령이 GitLab Duo CLI 8.81.0에 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.81.0)되었습니다.
- GitLab 19.0 릴리스 중 `/mcp` 슬래시 명령이 GitLab Duo CLI 8.95.0에 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.95.0)되었습니다.
- `/goal` 슬래시 명령이 GitLab Duo CLI 9.17.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.17.0)되었으며, GitLab 19.4 릴리스 중에 [베타](../../policy/development_stages_support.md#beta)로 제공됩니다.
- `/goal` 슬래시 명령이 GitLab Duo CLI 9.27.0에서 [일반 공개](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.27.0)되었으며, GitLab 19.5 릴리스 중입니다.
- `/compact` 슬래시 명령이 GitLab Duo CLI 8.109.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.109.0)되었으며, GitLab 19.2 릴리스 중입니다.
- `/export` 슬래시 명령이 GitLab Duo CLI 9.11.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.11.0)되었으며, GitLab 19.4 릴리스 중입니다.
- `/review` 슬래시 명령이 GitLab Duo CLI 9.14.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.14.0)되었으며, GitLab 19.4 릴리스 중입니다.
- `/whatsnew` 슬래시 명령이 GitLab Duo CLI 9.20.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.20.0)되었으며, GitLab 19.4 릴리스 중입니다.

{{< /history >}}

대화형 모드에서는 슬래시 명령을 사용하여 GitLab Duo CLI를 구성하고 작업을 수행합니다. 프롬프트에서 슬래시 명령을 입력한 다음 <kbd>Enter</kbd>를 누릅니다.

다음 슬래시 명령을 사용할 수 있습니다.

| 명령     | 설명                                          |
|-------------|------------------------------------------------------|
| `/compact`  | 컨텍스트 공간을 절약하기 위해 대화 기록을 압축합니다. |
| `/copy`     | 마지막 GitLab Duo 응답을 클립보드에 복사합니다.  |
| `/doctor`   | GitLab Duo CLI 환경에 대한 진단을 표시합니다. |
| `/exit`     | GitLab Duo CLI를 종료합니다.                             |
| `/export`   | 세션을 휴대 가능한 JSON 번들로 내보냅니다.        |
| `/feedback` | 버그 보고서 또는 기능 요청을 제출합니다.              |
| `/goal`     | 목표를 향해 작동하는 세션을 시작합니다. GitLab 19.3 이상이 필요합니다. |
| `/help`     | 사용 가능한 바로 가기, 모드 및 슬래시 명령을 표시합니다. |
| `/mcp`      | 구성된 MCP 서버 및 상태를 확인합니다.        |
| `/model`    | 현재 세션에 대한 AI 모델을 전환합니다.         |
| `/new`      | 새 채팅 세션을 시작합니다.                            |
| `/review`   | 코드 검토 서브에이전트로 변경 사항을 검토합니다.   |
| `/sessions` | 세션을 찾고, 검색 및 전환합니다.                 |
| `/settings` | 설정 패널을 엽니다.                             |
| `/skills`   | 현재 프로젝트에서 사용 가능한 Agent Skills를 나열합니다.  |
| `/whatsnew` | GitLab Duo CLI의 최근 변경 사항을 표시합니다.           |

슬래시 명령이 열어주는 패널이나 대화를 닫으려면 <kbd>Escape</kbd> 키를 누르세요.

또한 고유한 슬래시 명령을 생성할 수 있습니다. 자세한 내용은 [사용자 정의 슬래시 명령](customize.md#custom-slash-commands)을 참조하세요.

### 설정 {#settings}

설정을 보고 변경하려면 대화형 모드에서 `/settings`을(를) 입력합니다. 자세한 내용은 [GitLab Duo CLI 설정](settings.md)을 참조하세요.

### 시스템 알림 {#system-notifications}

{{< history >}}

- GitLab 19.1 릴리스 중 시스템 알림이 GitLab Duo CLI 8.105.0에 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.105.0)되었습니다.

{{< /history >}}

GitLab Duo CLI는 세션에 주의가 필요한 경우(예: 작업을 완료했거나 도구 승인이 필요한 경우) 터미널 창이 포커스되지 않은 상태에서 시스템 알림을 보낼 수 있습니다.

**알림**은 [설정 패널](settings.md#settings-panel)의 설정으로 제어됩니다.

- `auto`(기본값): 터미널이 포커스되지 않으면 시스템 알림을 보냅니다.
- `disabled`: 시스템 알림을 보내지 않습니다.

### 도구 승인 {#tool-approvals}

{{< history >}}

- GitLab 19.0에서 세션에 대한 도구 승인 옵션이 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/work_items/2129)되었습니다.
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.80.0) 8.80.0에 도입되었습니다.
- 패턴 기반 도구 승인이 GitLab 19.1에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21850)되었습니다.
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.101.0) 8.101.0에서 도입되었습니다.
- 패턴 기반 도구 승인이 2026년 7월 10일에 [제거](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/3699)되었습니다.
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.3.0) 9.3.0에서 제거되었습니다.

{{< /history >}}

GitLab Duo가 도구를 사용해야 할 때 시작하기 전에 승인을 위해 프롬프트합니다. 예를 들어 파일을 읽거나 명령을 실행해야 할 때입니다.

옵션은 다음과 같습니다.

- **승인**: GitLab Duo는 도구를 한 번 사용할 수 있습니다.
- **세션에 대해 승인**: GitLab Duo는 세션의 나머지 기간 동안 이러한 인수로 도구를 사용할 수 있습니다. 다른 인수는 추가 승인이 필요합니다.
- **거부**: GitLab Duo는 도구를 사용할 수 없습니다.

> [!note]
> **세션에 대해 승인** 옵션을 사용하려면 관리자가 그룹 또는 인스턴스에 대해 이를 활성화해야 합니다. 자세한 내용은 [도구 승인](../gitlab_duo_chat/agentic_chat.md#tool-approvals)을 참조하세요.

### 자동 모드 {#auto-mode}

{{< details >}}

- 티어:  Premium, Ultimate
- 제공 서비스:  GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [GitLab 19.5에서 도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/618088)되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `duo_auto_mode`가 있습니다. 기본적으로 활성화되어 있습니다.
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.22.0) 9.22.0에서 도입되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

자동 모드에서 GitLab Duo는 승인을 요청하지 않고 도구를 사용합니다. 설정에서 허용하는 경우 GitLab Duo는 다음 작업을 수행할 수 있습니다:

- 파일을 삭제하거나 시스템을 변경하는 명령을 포함한 모든 셸 명령을 실행합니다.
- `git` 명령을 실행하며, 커밋 및 푸시를 포함합니다.
- 이슈, 머지 리퀘스트 및 기타 GitLab 리소스를 생성하거나 업데이트합니다.
- MCP 도구를 실행하고 플로우를 시작합니다.

자동 모드는 [에이전트 도구 거버넌스](../ai-governance/tool-governance.md)를 무시하지 않습니다. **항상 거부**로 설정된 도구는 차단된 상태로 유지됩니다.

> [!warning]
> GitLab Duo는 실수를 할 수 있습니다. GitLab Duo가 읽는 파일, 이슈, 머지 리퀘스트 또는 웹 페이지 등의 콘텐츠에는 프롬프트 인젝션에 사용되는 악의적인 지시 사항이 포함될 수 있습니다. 위험을 제한하려면:
>
> - 신뢰할 수 있는 리포지토리에서만, 버릴 수 있는 브랜치에서만 자동 모드를 사용합니다.
> - 민감한 자격 증명이 있는 기기나 셸에서는 자동 모드를 사용하지 않습니다.
> - 세션에 머물러 있으며 병합하기 전에 모든 변경 사항을 검토합니다.
> - 자동 모드가 필요 없을 때 빌드 모드로 다시 전환합니다.
>
> 자세한 내용은 [편집기 확장의 보안 고려 사항](../../editor_extensions/security_considerations.md)을 참조하세요.

#### 자동 모드 켜기 {#turn-on-auto-mode}

**자동 모드** 설정은 기본적으로 꺼져 있습니다. 자동 모드는 사용하기 전에 인스턴스, 그룹 또는 프로젝트에 대해 켜져 있어야 합니다. 그룹은 인스턴스에서 설정을 상속하고, 서브그룹 및 프로젝트는 상위 그룹에서 설정을 상속합니다.

{{< tabs >}}

{{< tab title="인스턴스" >}}

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

인스턴스에 대해 자동 모드를 켜려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **자동 모드** 드롭다운 목록에서 다음 옵션 중 하나를 선택합니다:
   - **기본적으로 켜짐**:  자동 모드를 사용할 수 있습니다. 그룹 및 서브그룹은 끌 수 있습니다.
   - **기본적으로 꺼짐**: 자동 모드를 사용할 수 없습니다. 그룹 및 서브그룹은 켤 수 있습니다.
   - **항상 꺼짐**:  자동 모드를 사용할 수 없습니다. 그룹 및 서브그룹은 켤 수 없습니다.
1. **변경 사항 저장**을 선택합니다.

{{< /tab >}}

{{< tab title="그룹" >}}

전제 조건:

- 그룹의 Owner 역할.

그룹에 대해 자동 모드를 켜려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. **설정** > **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **자동 모드** 드롭다운 목록에서 다음 옵션 중 하나를 선택합니다:
   - **기본적으로 켜짐**:  자동 모드를 사용할 수 있습니다. 서브그룹 및 프로젝트는 끌 수 있습니다.
   - **기본적으로 꺼짐**: 자동 모드를 사용할 수 없습니다. 서브그룹 및 프로젝트는 켤 수 있습니다.
   - **항상 꺼짐**:  자동 모드를 사용할 수 없습니다. 서브그룹 및 프로젝트는 켤 수 없습니다.
1. **변경 사항 저장**을 선택합니다.

{{< /tab >}}

{{< tab title="프로젝트" >}}

상위 그룹에서 자동 모드를 **항상 꺼짐**으로 설정한 경우 프로젝트 설정이 잠기고 켤 수 없습니다.

전제 조건:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.

프로젝트에 대해 자동 모드를 켜려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **설정** > **일반**을 선택합니다.
1. **GitLab Duo**를 확장합니다.
1. **자동 모드** 토글을 켭니다.
1. **변경 사항 저장**을 선택합니다.

{{< /tab >}}

{{< /tabs >}}

#### 자동 모드 사용 {#use-auto-mode}

전제 조건:

- GitLab Duo CLI 9.22.0 이상입니다.
- 프로젝트에 대해 자동 모드가 켜져 있습니다.

자동 모드를 사용하려면:

1. 설정을 선택하기 위해 프로젝트에서 GitLab Duo CLI를 시작하거나 다시 시작합니다.
1. <kbd>Tab</kbd> 키를 누르면 `>` 프롬프트 아래의 모드가 `auto`을(를) 표시할 때까지 누릅니다.
1. 프롬프트를 입력합니다. 자동 모드는 해당 프롬프트부터 적용됩니다.

자동 모드 사용을 중지하려면 <kbd>Tab</kbd> 키를 눌러 다른 모드로 전환합니다. 변경 사항은 다음 프롬프트에 적용됩니다.

자동 모드는 세션 간에 지속되지 않습니다. `/new`로 시작하는 세션을 포함한 각각의 새로운 또는 재개된 세션은 빌드 모드에서 시작됩니다.

#### 자동 모드 문제 해결 {#troubleshooting-auto-mode}

`auto`이(가) <kbd>Tab</kbd> 키를 누를 때 나타나지 않으면:

1. **자동 모드** 설정이 프로젝트에 대해 켜져 있는지 확인하세요.
1. 상위 그룹이 **항상 꺼짐**으로 설정되지 않았는지 확인하세요.
1. GitLab Duo CLI를 다시 시작합니다.

## 헤드리스 모드 {#headless-mode}

> [!caution]
> 헤드리스 모드는 신중하게 사용하고 제어된 [샌드박스 환경](../../editor_extensions/security_considerations.md#use-development-containers-for-isolation)에서 사용하십시오.

비대화형 모드에서 워크플로우를 실행하려면 설정에 맞는 명령을 사용합니다.

{{< tabs >}}

{{< tab title="glab" >}}

`glab duo cli run`을 사용합니다.

```shell
glab duo cli run --goal "Your goal or prompt here"
```

예를 들어 ESLint 명령을 실행하고 오류를 GitLab Duo CLI로 파이프하여 해결할 수 있습니다.

```shell
glab duo cli run --goal "Fix these errors: $eslint_output"
```

{{< /tab >}}

{{< tab title="duo" >}}

`duo run`을 사용합니다.

```shell
duo run --goal "Your goal or prompt here"
```

예를 들어 ESLint 명령을 실행하고 오류를 GitLab Duo CLI로 파이프하여 해결할 수 있습니다.

```shell
duo run --goal "Fix these errors: $eslint_output"
```

{{< /tab >}}

{{< /tabs >}}

헤드리스 모드를 사용할 때 GitLab Duo CLI:

- GitLab 19.4 이상에서는 [Developer 플로우](../project/merge_requests/developer.md#use-the-flow-in-the-gitlab-duo-cli)를 실행합니다.
- 수동 도구 승인을 우회하고 모든 도구를 사용하도록 자동으로 승인합니다.
- 이전 대화의 컨텍스트를 유지하지 않습니다. `run` 명령을 실행할 때마다 새 워크플로우가 시작됩니다.

## 이미지를 컨텍스트로 제공 {#provide-images-as-context}

{{< history >}}

- GitLab Duo CLI 9.27.0에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.27.0)되었으며, GitLab 19.5 릴리스 중에 [기능 플래그](../../administration/feature_flags/_index.md) `dap_tool_image_input`가 있습니다. 기본적으로 활성화되어 있습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

전제 조건:

- GitLab Duo CLI 9.27.0 이상입니다.
- GitLab에서 관리하는 모델을 사용합니다. 직접 호스팅하는 모델은 지원되지 않습니다.

GitLab Duo CLI를 로컬에서 대화형 또는 헤드리스 모드로 실행할 때 GitLab Duo는 이미지를 읽고 컨텍스트로 사용할 수 있습니다. CLI는 다음을 읽을 수 있습니다:

- 리포지토리의 이미지 파일입니다.
- 동일한 프로젝트의 이슈, 머지 리퀘스트 또는 댓글에 첨부된 이미지입니다.

프롬프트에 이미지를 직접 업로드할 수 없습니다. 대신 이미 존재하는 이미지의 이름을 지정합니다:

- 리포지토리의 파일의 경우 파일 경로를 지정합니다. 예를 들어, `docs/architecture.png`입니다.
- 첨부의 경우 Markdown에 표시되는 대로 업로드 참조를 지정합니다. 예를 들어, `/uploads/<secret>/screenshot.png`입니다.

### 이미지 요구 사항 {#image-requirements}

이미지를 컨텍스트로 사용하려면 이미지가 다음 요구 사항을 충족해야 합니다:

- 형식: PNG, JPEG 또는 WebP 파일
- 크기: 10MB 이하
- 치수: 8,000픽셀보다 넓거나 크지 않습니다

### 프롬프트 예시 {#example-prompts}

GitLab Duo CLI에 이슈에 첨부된 스크린샷에 표시된 UI 버그를 수정하도록 요청할 수 있습니다:

```plaintext
Look at the screenshot attached to issue 1234 and fix the alignment bug it shows.
```

GitLab Duo CLI에 아키텍처 다이어그램을 설명하도록 요청할 수 있습니다:

```plaintext
Read docs/architecture.png, explain the data flow, and identify any single points of failure.
```

GitLab Duo CLI에 화이트보드 사진을 설계 문서로 변환하도록 요청할 수 있습니다:

```plaintext
Read whiteboard.jpg and turn it into a design document in docs/design.md.
```

## 모델 선택 {#select-a-model}

{{< history >}}

- GitLab 18.10 릴리스 중 GitLab Duo CLI 8.68.0에서 모델 선택 옵션 및 환경 변수가 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.68.0)되었습니다.
- GitLab 18.10 릴리스 중 GitLab Duo CLI 8.76.0에서 모델 선택 슬래시 명령이 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.76.0)되었습니다.

{{< /history >}}

대화형 모드 또는 헤드리스 모드에 대해 모델을 선택할 수 있습니다.

### 대화형 모드의 경우 {#for-interactive-mode}

선택한 모델은 세션 전체에 유지되며 컨텍스트를 잃지 않고 대화 중에 모델을 전환할 수 있습니다.

전제 조건:

- GitLab Duo CLI 8.76.0 이상.

대화형 모드에 대해 모델을 선택하려면:

1. 대화형 모드에서 `/model`을 입력하고 <kbd>Enter</kbd>를 누릅니다.
1. 화살표 키를 사용하여 사용 가능한 모델 목록을 스크롤하거나 모델 이름을 입력하여 목록을 필터링합니다.
1. 모델을 선택하고 <kbd>Enter</kbd>를 눌러 전환합니다.

### 헤드리스 모드의 경우 {#for-headless-mode}

선택한 모델은 세션 전체에 유지되지 않습니다.

전제 조건:

- GitLab Duo CLI 8.68.0 이상.

헤드리스 모드에 대해 모델을 선택하려면:

1. [모델에 대한 `gitlab_identifier`](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/HEAD/ai_gateway/model_selection/models.yml)를 찾습니다.
1. GitLab Duo CLI를 실행할 때 `--model` 옵션 또는 `GITLAB_DUO_MODEL` 환경 변수를 `gitlab_identifier` 값으로 설정합니다.

   {{< tabs >}}

   {{< tab title="glab" >}}

   `--model` 옵션을 사용합니다.

   ```shell
   glab duo cli --model <gitlab_identifier_for_the_model>
   ```

   `GITLAB_DUO_MODEL` 환경 변수를 사용합니다.

   ```shell
   GITLAB_DUO_MODEL=<gitlab_identifier_for_the_model> glab duo cli
   ```

   예를 들어 [`GPT-5-Codex - OpenAI`](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/HEAD/ai_gateway/model_selection/models.yml#L448)를 사용하려면:

   ```shell
   glab duo cli --model gpt_5_codex
   ```

   ```shell
   GITLAB_DUO_MODEL=gpt_5_codex glab duo cli
   ```

   {{< /tab >}}

   {{< tab title="duo" >}}

   `--model` 옵션을 사용합니다.

   ```shell
   duo --model <gitlab_identifier_for_the_model>
   ```

   `GITLAB_DUO_MODEL` 환경 변수를 사용합니다.

   ```shell
   GITLAB_DUO_MODEL=<gitlab_identifier_for_the_model> duo
   ```

   예를 들어 [`GPT-5-Codex - OpenAI`](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/HEAD/ai_gateway/model_selection/models.yml#L448)를 사용하려면:

   ```shell
   duo --model gpt_5_codex
   ```

   ```shell
   GITLAB_DUO_MODEL=gpt_5_codex duo
   ```

   {{< /tab >}}

   {{< /tabs >}}

## 세션 전환 {#switch-sessions}

GitLab Duo Chat 세션은 대화 기록과 워크플로우 데이터를 저장하며 GitLab Duo CLI, GitLab UI 및 편집기 확장 프로그램 전체에서 공유됩니다.

예를 들어, 브라우저에서 대화를 시작하고 터미널에서 계속할 수 있습니다.

세션을 찾고 전환하려면:

1. 대화형 모드에서 `/sessions`를 입력하고 <kbd>Enter</kbd>를 누릅니다.
1. 화살표 키를 사용하여 사용 가능한 세션 목록을 스크롤하거나 텍스트를 입력하여 목록을 필터링합니다.
1. 세션을 선택하고 <kbd>Enter</kbd>를 누릅니다.

헤드리스 모드에서 세션으로 전환하려면 `--existing-session-id` 옵션을 사용합니다.

## 모델 컨텍스트 프로토콜(MCP) 연결 {#model-context-protocol-mcp-connections}

GitLab Duo CLI를 로컬 또는 원격 MCP 서버에 연결하려면 GitLab IDE 확장 프로그램과 동일한 MCP 구성을 사용합니다. 지침은 [MCP 서버 구성](../gitlab_duo/model_context_protocol/mcp_clients.md#configure-mcp-servers)을 참조하세요.

## 관련 항목 {#related-topics}

- [GitLab Duo CLI 완전 참조](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/blob/main/packages/cli/app/docs/cli-reference.md)
- [편집기 확장 프로그램의 보안 고려 사항](../../editor_extensions/security_considerations.md)
- [GitLab CLI](https://docs.gitlab.com/cli/)
- [GitLab Duo Agent Platform 사용자 정의](../duo_agent_platform/customize/_index.md)
- [GitLab Duo Agent Platform 세션](../duo_agent_platform/sessions/_index.md)

## 문제 해결 {#troubleshooting}

GitLab Duo CLI로 작업할 때 다음과 같은 문제가 발생할 수 있습니다.

### 인증서 오류 {#certificate-errors}

인증서 오류가 발생할 수 있습니다.

```plaintext
Error: unable to verify the first certificate
Error: self-signed certificate in certificate chain
```

조직에서 HTTPS 가로채기 프록시 또는 유사한 용도로 사용자 지정 CA(인증 기관)를 사용하는 경우 이러한 오류가 발생합니다.

인증서 오류를 해결하려면 다음 방법 중 하나를 사용합니다.

- 시스템 인증서 저장소를 사용합니다(권장).
  1. CA 인증서가 운영 체제의 인증서 저장소에 설치되어 있으면 Node.js를 구성하여 사용합니다. Node.js 22.15.0, 23.9.0, 24.0.0 이상이 필요합니다.
  1. GitLab Duo CLI를 컨테이너에서 실행하는 경우 호스트 시스템 저장소가 아닌 컨테이너의 시스템 저장소에 CA 인증서를 설치합니다.

     ```shell
     export NODE_OPTIONS="--use-system-ca"
     ```

- CA 인증서 파일을 지정합니다.
  1. 이전 Node.js 버전이거나 CA 인증서가 시스템 저장소에 없는 경우 Node.js를 인증서 파일로 직접 가리킵니다. 파일은 PEM 형식이어야 합니다.
  1. GitLab Duo CLI를 컨테이너에서 실행하는 경우 경로를 컨테이너의 위치로 설정합니다. 볼륨 마운트를 사용하여 인증서 파일을 제공합니다.

     ```shell
     export NODE_EXTRA_CA_CERTS=/path/to/custom-ca.pem
     ```

### 인증서 오류 무시 {#ignore-certificate-errors}

여전히 인증서 오류가 발생하면 인증서 검증을 비활성화할 수 있습니다.

> [!warning]
> 인증서 검증을 비활성화하는 것은 보안 위험입니다. 프로덕션 환경에서 검증을 비활성화하면 안 됩니다.

인증서 오류는 잠재적 보안 침해를 경고하므로, 인증서 검증을 비활성화하는 것이 안전하다고 확신할 때만 인증서 검증을 비활성화해야 합니다.

전제 조건:

- 브라우저에서 인증서 체인을 확인했거나 관리자가 이 오류를 무시해도 안전하다고 확인했습니다.

인증서 검증을 비활성화하려면:

```shell
export NODE_TLS_REJECT_UNAUTHORIZED=0
```
