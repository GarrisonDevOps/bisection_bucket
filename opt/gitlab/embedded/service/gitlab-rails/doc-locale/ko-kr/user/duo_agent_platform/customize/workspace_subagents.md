---
stage: Agent Foundations
group: Agent Developer
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 리포지토리에서 Developer 플로우가 작업을 위임할 수 있도록 특화된 하위 에이전트를 정의합니다.
title: 워크스페이스 하위 에이전트
---

{{< details >}}

- 티어: [Free](../../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태: 실험

{{< /details >}}

{{< history >}}

- [GitLab 19.5에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259664), [실험](../../../policy/development_stages_support.md#experiment) 단계로 [기능 플래그](../../../administration/feature_flags/_index.md) `dap_workspace_agents`(으)로 도입되었습니다. 기본적으로 활성화되어 있습니다.

{{< /history >}}

워크스페이스 하위 에이전트는 프로젝트 리포지토리에서 Markdown 파일로 정의하는 특화된 에이전트입니다. 이 기능은 Developer 플로우 전용이며 GitLab UI와 GitLab Duo CLI 모두에서 사용할 수 있습니다.

Developer 플로우는 하위 에이전트의 `description`을(를) 기반으로 하위 에이전트에 작업을 위임할 시기를 결정합니다. 이름으로 하위 에이전트를 사용하도록 Developer 플로우에 요청할 수도 있습니다. 예를 들어, 이슈 또는 머지 리퀘스트 의견에서 [Developer 플로우를 멘션](../../project/merge_requests/developer.md#mention-duo-developer-in-a-discussion)하고 하위 에이전트의 이름을 지정합니다:

```plaintext
@duo-developer-<namespace> delegate the review of these changes to the reviewer subagent.
```

`<namespace>`을(를) GitLab 네임스페이스 경로로 바꿉니다. 하위 에이전트의 이름을 지정하면 위임 가능성이 높아지지만 Developer 플로우는 작업을 위임할지 여부를 결정합니다.

워크스페이스 하위 에이전트는 다른 GitLab Duo Agent Platform 기능처럼 GitLab Credits를 소비합니다.

## 워크스페이스 하위 에이전트를 사용할 때 {#when-to-use-workspace-subagents}

워크스페이스 하위 에이전트는 Developer 플로우와 문맥을 공유하지 않습니다. 작업이 Developer 플로우에 필요하지 않은 세부 정보를 생성할 때 하위 에이전트를 사용하여 세부 정보가 Developer 플로우의 주요 문맥에서 벗어나도록 합니다.

예를 들어 `run_command` 및 `edit_file` 도구가 있는 linter 하위 에이전트는 프로젝트 linter를 실행하고 lint 오류를 수정할 수 있습니다. linter 출력과 개별 수정 사항은 하위 에이전트의 대화에 남습니다. Developer 플로우는 수정 사항 요약과 같은 결과만 받습니다. 하위 에이전트의 프롬프트가 요청하면 결과에는 다음번에 피할 일반적인 linter 문제도 나열할 수 있습니다. 기타 예시에는 변경 사항 검토, 접근 방식 조사 또는 보안과 같은 특정 영역 확인이 포함됩니다.

Developer 플로우가 하위 에이전트에 작업을 위임하면 하위 에이전트는:

- Developer 플로우가 제공하는 작업으로 시작하는 자체 대화에서 작동합니다. 결과만 Developer 플로우로 반환됩니다.
- Developer 플로우의 지침 대신 자체 프롬프트를 따릅니다.
- `tools` 필드에 나열된 도구만 사용할 수 있습니다. 예를 들어 `read_file` 및 `grep`만 있는 검토 하위 에이전트는 파일을 변경할 수 없습니다.

다음 표에서는 워크스페이스 하위 에이전트를 GitLab Duo Developer를 사용자 지정하는 다른 방법과 비교합니다.

| 사용자 지정 | 수행 작업 | 사용 시기 |
|---------------|--------------|-------------|
| `AGENTS.md` | 구조, 코딩 규칙, 빌드 및 테스트 지침과 같은 프로젝트 문맥 및 규칙을 작업을 수행하는 에이전트의 문맥에 추가합니다. 리포지토리의 모든 작업에 적용됩니다. | 리포지토리의 모든 작업이 동일한 규칙을 따르도록 하려고 할 때. |
| 에이전트 스킬 | 작업이 기술 설명과 일치할 때 에이전트가 자동으로 로드하는 지식 또는 워크플로우를 제공합니다. 기술을 로드하는 에이전트는 동일한 대화 및 동일한 도구로 작업을 직접 수행합니다. | 작업이 일치할 때 에이전트가 특정 워크플로우를 따르거나 특정 지식을 사용하기를 원할 때. |
| 워크스페이스 하위 에이전트 | 자체 프롬프트 및 도구가 있는 별도의 에이전트에서 작업을 실행하고 결과만 반환합니다. | linter 출력과 같은 작업의 세부 정보를 Developer 플로우의 문맥에서 벗어나도록 유지하거나 자체 지침 및 제한된 도구가 있는 별도의 에이전트를 원할 때. |

## 하위 에이전트 정의 {#subagent-definitions}

각 워크스페이스 하위 에이전트는 리포지토리 루트의 `.agents/agents/` 디렉토리에 있는 Markdown 파일입니다. 파일은 `---` 라인 사이의 YAML front matter로 시작하고 그 뒤에 프롬프트가 옵니다. 프롬프트는 파일의 Markdown 본문입니다.

다음 표에서는 front matter 필드와 프롬프트에 대해 설명합니다.

| 필드 | 필수 | 설명 |
|-------|----------|-------------|
| `name` | 아니요 | Developer 플로우가 하위 에이전트를 식별하는 데 사용하는 이름입니다. `.md` 확장자 없이 파일 이름으로 기본값이 설정됩니다. 프로젝트 내에서 고유해야 합니다. 최대 64자입니다. |
| `description` | 예 | 하위 에이전트가 수행하는 작업입니다. Developer 플로우는 이를 사용하여 하위 에이전트에 위임할 시기를 결정합니다. 최대 1,024자입니다. |
| `tools` | 아니요 | 하위 에이전트가 사용할 수 있는 도구(쉼표로 구분된 목록 또는 YAML 목록)입니다. [사용 가능한 도구 목록](../agents/tools.md)에서 도구 이름을 사용합니다. `tools`를 생략하면 하위 에이전트는 도구를 사용할 수 없습니다. 제공된 정보로 작업을 추론할 수만 있습니다. |
| 프롬프트 | 예 | front matter 이후의 하위 에이전트에 대한 지침입니다. 최대 10,000자입니다. |

### 파일 요구 사항 {#file-requirements}

워크스페이스 하위 에이전트는 파일이 다음의 모든 요구 사항을 충족할 때만 사용됩니다:

- 파일이 `.agents/agents/` 디렉토리에 직접 있습니다. 하위 디렉토리의 파일은 무시됩니다.
- 파일 이름이 `.md`로 끝납니다.
- 파일은 UTF-8 텍스트입니다.
- 파일은 `---` 라인 사이의 YAML front matter로 시작합니다.
- front matter에 `description`가 있습니다.
- 파일에 front matter 이후의 프롬프트가 있습니다.
- 파일은 64KB 이하입니다.

파일이 이러한 요구 사항을 충족하지 않으면 파일이 건너뜁니다.

### 숫자 및 크기 제한 {#number-and-size-limits}

다음 제한 사항은 프로젝트의 모든 하위 에이전트에 적용됩니다.

| 한도 | GitLab의 세션 | GitLab Duo CLI 세션 |
|-------|--------------------|-------------------------|
| 하위 에이전트의 수 | 첫 번째 10개의 `.md` 파일이 파일 이름으로 읽힙니다. | 최대 10개의 하위 에이전트입니다. 요구 사항을 충족하는 모든 하위 에이전트가 전송됩니다. |
| 전체 크기 | 최대 112KB입니다. 크기는 각 하위 에이전트의 이름, 설명, 도구 및 프롬프트를 계산합니다. 전체가 더 크면 일부 하위 에이전트를 Developer 플로우에서 사용할 수 없습니다. | 최대 gRPC 메시지 크기로 제한됩니다. |

### 세션 시작을 방지하는 오류 {#errors-that-prevent-a-session-from-starting}

Developer 플로우 세션이 시작되지 않는 경우:

- 두 개의 하위 에이전트가 동일한 이름을 가지고 있습니다.
- 하위 에이전트가 Developer 플로우에서 사용할 수 없는 도구를 나열합니다.
- `name`, `description` 또는 프롬프트가 최대값보다 깁니다.
- GitLab Duo CLI 세션에서 10개 이상의 하위 에이전트가 요구 사항을 충족합니다.

## 워크스페이스 하위 에이전트 생성 {#create-a-workspace-subagent}

Developer 플로우에 작업을 위임할 특화된 에이전트를 제공하려면 워크스페이스 하위 에이전트를 생성합니다.

전제 조건:

- [베타 및 실험 기능을 켜기](../turn_on_off.md#turn-on-beta-and-experimental-features). 단일 프로젝트에 대해서는 이 설정을 켤 수 없습니다:
  - GitLab.com에서 Owner 역할이 있는 사용자가 최상위 그룹에서 이 설정을 변경합니다. 최상위 그룹의 모든 하위 그룹 및 프로젝트가 이 설정을 상속합니다.
  - GitLab Self-Managed 및 GitLab Dedicated에서 관리자가 인스턴스에 대해 이 설정을 변경합니다. 인스턴스의 모든 그룹 및 프로젝트가 이 설정을 상속합니다.
- [Developer 플로우 전제 조건](../../project/merge_requests/developer.md#prerequisites)을(를) 충족합니다.
- 하위 에이전트를 병합하기 전에 테스트하려면 [GitLab Duo CLI](../../gitlab_duo_cli/_index.md) 9.21.0 이상을 설치합니다.

워크스페이스 하위 에이전트를 생성하려면:

1. 프로젝트의 브랜치에서 `.agents/agents/` 디렉토리에 Markdown 파일을 생성합니다. 예를 들어, `.agents/agents/reviewer.md`입니다.
1. front matter 및 프롬프트를 추가합니다. 예를 들어:

   ```markdown
   ---
   name: reviewer
   description: Reviews code changes and reports a short list of findings.
   tools: read_file, grep
   ---

   You are a meticulous code reviewer. When delegated a task, read the files it
   names and report a short list of findings. Do not modify any file.
   ```

1. 하위 에이전트를 병합하기 전에 테스트합니다. GitLab의 세션은 기본 브랜치에서만 하위 에이전트를 읽지만 GitLab Duo CLI는 로컬 작업 디렉토리에서 파일을 읽습니다.
   1. 프로젝트의 루트 디렉토리에서 GitLab Duo CLI로 Developer 플로우 세션을 시작합니다.
   1. Developer 플로우에 작업을 하위 에이전트에 위임하도록 요청하거나 하위 에이전트의 설명과 일치하는 작업을 제공합니다.
   1. 세션에 `Delegated to workspace/agents/<subagent-name>`이(가) 표시되는지 확인하고 그 뒤에 하위 에이전트의 결과가 표시됩니다. 하위 에이전트가 수행한 작업을 보려면 <kbd>Control</kbd>+<kbd>T</kbd>를 누르세요.

1. 파일을 기본 브랜치에 커밋하거나 병합합니다.
1. GitLab에서 새 Developer 플로우 세션을 시작하여 하위 에이전트를 사용합니다. 결과를 보려면 Developer 플로우가 게시한 링크에서 세션을 열거나 왼쪽 사이드바에서 **AI** > **세션**을(를) 선택합니다. Developer 플로우가 작업을 위임하면 세션에 **하위 에이전트에 위임됨**이 표시되고 그 뒤에 **에이전트로 돌아감**과 하위 에이전트의 결과가 표시됩니다.

GitLab에서는 새 세션만 하위 에이전트 구성의 변경 사항을 적용합니다. 기존 세션은 변경 사항을 적용하지 않습니다(다시 시작하더라도).

## 프로젝트에서 워크스페이스 하위 에이전트 방지 {#prevent-workspace-subagents-in-a-project}

단일 프로젝트에 대해서는 워크스페이스 하위 에이전트를 끌 수 없습니다. 하위 에이전트 정의를 리포지토리에서 제외하려면 다음 방법 중 하나 또는 모두를 사용합니다:

- `.agents/agents/`을(를) 프로젝트의 `.gitignore` 파일에 추가하여 파일이 실수로 커밋되지 않도록 합니다.
- [이름으로 파일을 금지하는 푸시 규칙](../../project/repository/push_rules.md#prohibit-files-by-name)을(를) 정규 표현식 `^\.agents\/agents\/`(으)로 생성합니다. GitLab은 파일을 포함하는 푸시를 거부합니다.

## 관련 항목 {#related-topics}

- [AGENTS.md 사용자 지정 파일](agents_md.md)
- [에이전트 스킬](agent_skills.md)
- [사용자 지정 규칙](custom_rules.md)

## 문제 해결 {#troubleshooting}

워크스페이스 하위 에이전트가 예상대로 작동하지 않는 경우:

1. 베타 및 실험 기능이 켜졌는지 확인합니다.
1. [파일 요구 사항](#file-requirements)에 대해 파일을 확인합니다. 요구 사항을 충족하지 않는 파일은 건너뜁니다.
1. GitLab의 세션의 경우 파일이 기본 브랜치에 있는지 확인합니다.
1. 세션이 시작되지 않으면 [세션 시작을 방지하는 오류](#errors-that-prevent-a-session-from-starting)를 확인합니다.
