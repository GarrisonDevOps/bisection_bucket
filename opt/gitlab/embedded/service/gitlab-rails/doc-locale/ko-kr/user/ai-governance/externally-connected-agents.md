---
stage: Software Supply Chain Security
group: AI Governance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "GitLab CLI를 사용하여 Claude Code, Cursor, Codex 세션을 기록하면 AI Governance 대시보드에 외부 연결 에이전트(ECA)로 표시됩니다."
title: 외부 연결 에이전트(ECA)를 AI Governance 대시보드에 연결
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태: 제한적 출시

{{< /details >}}

{{< history >}}

- 코딩 에이전트용 세션 캡처가 GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245529)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)의 이름은 `ai_agent_session_tracking`(이)었습니다. 기본적으로 비활성화되었습니다.
- Cursor 및 Codex 세션이 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/260978)되었습니다.
- GitLab 19.5에서 [기본적으로 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261046)되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

Claude Code, Cursor, Codex 같은 코딩 에이전트가 개발자의 컴퓨터에서 실행되면, AI Governance 대시보드는 GitLab CLI(`glab`)를 통해 이들을 외부 연결 에이전트(ECA)로 표시할 수 있습니다.

GitLab CLI(`glab`)는 각 에이전트의 로컬 트랜스크립트를 읽고 세션과 해당 이벤트를 에이전트가 작업한 GitLab 프로젝트로 전송합니다. 세션은 다음 위치에 나타납니다:

- [AI Governance 대시보드](governance-dashboard.md)에서
- AI 감사 이벤트 보고서에서

> [!warning]
> 이 기능은 [베타](../../policy/development_stages_support.md) 상태입니다. 예고 없이 변경될 수 있습니다. 자세한 내용은 [GitLab 테스팅 계약](https://handbook.gitlab.com/handbook/legal/testing-agreement/)을 참조하세요.

`glab`은(는) 에이전트가 실행된 폴더의 Git 원격에서 프로젝트를 찾습니다:

- Claude Code의 경우 `glab`은(는) 다른 명령과 같은 방식으로 원격을 선택합니다. 즉, `glab`은(는) `glab repo set-default`으로 설정된 원격을 사용하고, 그 다음 `upstream`, 그 다음 `gitlab`, 그 다음 `origin`을 사용합니다. 포크 체크아웃에서 Claude Code 세션은 업스트림 프로젝트로 이동합니다.
- Codex의 경우 `glab`은(는) Codex가 기록한 리포지토리 URL을 사용하고, 그렇지 않으면 `origin`을 사용합니다.
- Cursor의 경우 `glab`은(는) `origin`을 사용합니다.

원격은 `glab`이 로그인한 GitLab 인스턴스를 가리켜야 합니다. 그러한 원격이 없는 폴더의 세션은 전송되지 않습니다.

## 전제 조건 {#prerequisites}

- 최상위 그룹을 위해 GitLab Duo Agent Platform이 포함된 GitLab Premium 또는 Ultimate
- [`glab`](../../editor_extensions/gitlab_cli/_index.md) 1.122.0 이상, GitLab 인스턴스에 로그인된 상태
- 프로젝트에 대한 최소 개발자 역할
- **외부 에이전트 허용**이 최상위 그룹에 대해 켜져 있습니다. 기본적으로 켜져 있습니다. 이 설정은 AI 카탈로그 [외부 에이전트](../duo_agent_platform/agents/external.md#turn-external-agents-on-or-off)에 속하며 CI/CD 파이프라인에서 실행되고 세션 캡처도 제어합니다. 이를 끄면 로컬 코딩 에이전트의 세션도 중지됩니다.
- [**AI 감사 이벤트**](ai-audit-events.md#enable-ai-audit-event-storage)가 그룹 또는 프로젝트에 대해 켜져 있습니다. 이를 사용하지 않으면 세션만 기록되고 이벤트와 도구 호출은 기록되지 않습니다. 설정은 기본적으로 꺼져 있습니다. 이를 변경하려면 소유자 또는 보안 관리자 역할이 필요합니다.
- macOS 또는 Linux를 실행하는 컴퓨터

## 세션 캡처 설정 {#set-up-session-capture}

에이전트를 실행하는 각 컴퓨터의 각 사용자 계정에 대해 한 번씩 세션 캡처를 설정합니다. 이 섹션의 명령은 [`glab govern` 참고서](https://docs.gitlab.com/cli/govern/)에 문서화되어 있습니다.

`glab govern setup`은(는) 항상 Claude Code 후크를 설치합니다. `glab`은(는) `--agents` 옵션을 전달할 때 Claude Code 후크를 설치하기도 하는데, 이때 확인을 요청합니다. 스크립트에서 `glab`을(를) 호출하는 경우 `--yes`을(를) 전달하세요.

### Claude Code 세션 캡처 {#capture-claude-code-sessions}

Claude Code 세션은 후크를 통해 캡처되며, `glab`이(가) 후크에서 로그인할 수 있을 때 각 회신 후 세션을 전송합니다. 백그라운드 작업이 후크가 놓친 모든 것을 전송합니다.

Claude Code 세션을 캡처하려면 다음을 실행하세요:

```shell
glab govern setup
```

이 명령은 다음을 설치합니다:

- `~/.claude/settings.json`에 Stop 후크와 SessionEnd 후크 후크는 모든 회신 후 세션을 전송하고 세션이 끝날 때 완료로 표시합니다.
- 30분마다 실행되는 백그라운드 작업 작업은 후크가 놓친 모든 것을 전송하고 활동이 없는 24시간 후 세션을 완료로 표시합니다. macOS에서 작업은 `launchd` 에이전트이고, Linux에서는 `systemd` 사용자 타이머입니다.

명령을 실행하기 전에 종료된 세션은 전송되지 않습니다.

### Cursor 및 Codex 세션 캡처 {#capture-cursor-and-codex-sessions}

`glab`은(는) Cursor 및 Codex용 후크를 설치하지 않습니다. 백그라운드 작업은 30분마다 `~/.cursor/projects` 및 `~/.codex/sessions`을(를) 검사하여 해당 세션을 찾습니다.

Cursor 및 Codex 세션을 캡처하려면 다음을 실행하세요:

```shell
glab govern setup --agents codex,cursor
```

작업은 또한 명령을 실행하기 전의 세션을 전송합니다. 만약 세션이 지난 89일 이내에 활동했으며 `glab`이(가) 로그인한 GitLab 인스턴스의 프로젝트에 속하면 전송됩니다. 세션은 활동이 없는 24시간 후 완료로 표시됩니다. 사용자 지정 `CODEX_HOME` 폴더에 저장된 Codex 세션은 발견되지 않습니다.

캡처된 에이전트를 변경하려면 다른 `--agents` 목록으로 명령을 다시 실행하세요. Cursor 및 Codex 세션 캡처를 중지하려면 `--agents ""`을(를) 사용하여 실행하세요.

### 설정 확인 {#verify-the-setup}

세션 캡처가 올바르게 구성되었는지 확인하려면 다음을 실행하세요:

```shell
glab govern doctor
```

명령:

- `glab`이(가) 기본 GitLab 호스트에 로그인되어 있으며 `PATH`에 있는지 확인합니다.
- Claude Code 후크가 `~/.claude/settings.json`에 있고 GitLab API에 도달할 수 있는지 확인합니다.
- 백그라운드 작업이 설치되었는지 그리고 마지막 실행이 어떻게 진행되었는지 보고합니다.
- 실패한 각 확인에 대해 수정 방법을 설명합니다.

마지막 실행 라인에 나열:

- 세션 캡처가 활성화되지 않은 프로젝트
- GitLab에서 거부한 에이전트 유형
- `glab`이(가) 건너뛴 Cursor 세션

명령은 전역 `~/.claude/settings.json`만 읽습니다. 프로젝트의 `.claude` 폴더의 후크는 누락된 것으로 보고되고, 백그라운드 작업은 전역 Stop 후크가 누락된 동안 Claude Code 세션을 건너뜁니다.

백그라운드 작업을 기다리지 않고 지금 세션을 전송하려면 다음을 실행하세요:

```shell
glab govern audit sync --all
```

## 전송된 데이터 {#data-that-is-sent}

각 세션에 대해 `glab`은(는) 다음을 전송합니다:

- 사용자가 입력한 프롬프트 8KB보다 큰 프롬프트는 잘립니다. 첫 번째 프롬프트는 세션의 목표가 됩니다.
- 명령, 파일 경로, 편집 같은 인수와 함께 각 도구 호출 8KB보다 큰 인수는 마커로 바뀝니다.
- 각 도구 호출의 결과, 소요 시간, 오류 메시지 오류 메시지는 255자에서 잘립니다.
- 각 응답의 모델 및 토큰 사용량
- 세션이 완료되면 트랜스크립트 파일의 체크섬

도구 출력 및 응답의 텍스트는 전송되지 않으나, 실패한 도구 호출의 출력의 처음 255자는 오류 메시지로 전송됩니다. 컴퓨터를 식별하기 위해 `glab`은(는) 해시된 기계 ID를 전송합니다.

다양한 에이전트가 다양한 세부 정보를 기록합니다:

| 에이전트 | Claude Code와의 차이점 |
|-------|---------------------------|
| Codex | 모든 도구 호출의 결과는 완료된 것으로 기록되며, Codex는 성공 여부를 기록하지 않으므로 오류 메시지가 없습니다. |
| Cursor | Cursor는 결과, 토큰 사용량, 타임스탐프를 기록하지 않으므로 프롬프트와 도구 호출만 전송됩니다. 이벤트는 트랜스크립트의 마지막 수정으로 시간이 정해집니다. |

## ECA 세션 보기 {#view-eca-sessions}

외부 연결 에이전트(ECA)의 세션은 **표시** 컨트롤이 **모든 에이전트**(기본값) 또는 **연결됨**으로 설정되면 AI Governance 대시보드에 나타납니다:

- **최근 세션** 카드는 각 세션의 이름을 에이전트 이름으로 지정합니다. 예를 들어 **Cursor (glab)** 또는 **Claude Code (glab)**
- **가장 많이 사용된 에이전트** 카드는 각 연결된 에이전트를 이를 실행한 컴퓨터 및 사용자 수와 함께 나열합니다. 예를 들어 **2개 컴퓨터 · 2명 사용자**
- KPI 타일 및 다른 카드는 GitLab Duo Agent Platform 세션과 함께 세션 및 도구 호출을 계산합니다.

세션 및 해당 이벤트는 AI 감사 이벤트 보고서에도 나열됩니다:

- Claude Code 세션은 첫 번째 회신 직후에 나타나고 에이전트를 종료할 때 완료로 표시됩니다. 종료 후크가 실행되지 않으면 백그라운드 작업이 활동이 없는 24시간 후 세션을 완료로 표시합니다.
- Cursor 및 Codex 세션은 일반적으로 에이전트를 사용한 지 30분 이내에 나타나며, 컴퓨터가 켜져 있고 사용자가 로그인된 상태입니다. macOS에서 백그라운드 작업의 첫 번째 실행은 설정 후 30분입니다. 이러한 세션은 활동이 없는 24시간 후 완료로 표시됩니다.
- 대시보드 숫자는 짧은 지연 후 업데이트됩니다.

## 세션 캡처 중지 {#stop-capturing-sessions}

백그라운드 작업을 제거하고 Cursor 및 Codex 세션 캡처를 중지하려면 다음을 실행하세요:

```shell
glab govern setup --uninstall
```

Claude Code 후크는 제자리에 유지됩니다. Claude Code 세션 캡처를 중지하려면 `~/.claude/settings.json`의 `hooks` 섹션에서 두 `glab govern audit sync` 항목을 제거하세요. Stop 후크 없이 백그라운드 작업도 Claude Code 세션을 건너뜁니다.

이미 GitLab으로 전송된 세션은 대시보드에 유지됩니다.

## 문제 해결 {#troubleshooting}

| 문제 | 원인 | 해결 |
|---------|-------|------------|
| `glab govern doctor`이(가) 실패한 확인을 보고합니다. | 이 컴퓨터의 설정이 불완전합니다. | 확인이 인쇄하는 수정사항을 따르세요. |
| `glab govern doctor`의 마지막 실행 라인이 프로젝트에 대해 세션 캡처가 활성화되지 않았다고 표시합니다. | 세션 캡처가 해당 프로젝트에 대해 꺼져 있습니다. | GitLab 지원팀에 문의하세요. |
| `glab govern audit sync --all`이(가) `403 Forbidden` 경고를 인쇄하거나 `glab govern doctor`이(가) 마지막 실행의 오류로 표시합니다. | 프로젝트의 역할이 개발자 아래이거나, 그룹에 GitLab Duo Agent Platform이 없거나, **외부 에이전트 허용**이 최상위 그룹에 대해 꺼져 있거나, 그룹 소유자가 이 컴퓨터의 에이전트 ID를 취소했습니다. 포크 체크아웃에서 Claude Code의 경우 세션이 업스트림 프로젝트로 이동했습니다. | 역할 및 설정을 그룹 소유자와 확인하세요. 포크 체크아웃에서 `glab repo set-default`을(를) 실행하고 세션이 이동해야 할 프로젝트를 선택하세요. |
| 세션이 나타나지만 이벤트나 도구 호출이 없습니다. | **AI 감사 이벤트**가 그룹 또는 프로젝트에 대해 꺼져 있습니다. | 설정을 켜세요. 소유자 또는 보안 관리자 역할이 필요합니다. 변경 전의 이벤트는 기록되지 않습니다. |
| 세션이 전송되었지만 대시보드에 없습니다. | 대시보드는 백그라운드에서 처리된 데이터를 읽거나 필터가 세션을 제외합니다. | **표시**를 **모든 에이전트** 또는 **연결됨**으로 설정하고, 날짜 범위를 확인한 후, 몇 분 동안 기다렸다가 페이지를 새로 고치세요. |
| Cursor 세션이 절대 전송되지 않습니다. | `glab`이(가) 세션이 실행된 폴더를 확인할 수 없습니다. 이는 폴더가 이동했을 때, 다른 폴더의 경로가 구두점만 다를 때(예: `code/cli-docs` 및 `code/cli/docs`), 또는 세션이 터치한 모든 파일이 폴더 외부에 있을 때 발생합니다. 폴더에 `origin` 원격이 없을 때도 발생합니다. | `glab govern doctor`을(를) 실행하고 "동기화되지 않음" 이유를 읽으세요. 세션이 실행되었을 때 폴더를 원래 위치에 유지하고, 경로가 구두점만 다른 폴더의 이름을 바꾸고, 폴더에 `origin` 원격이 있는지 확인하세요. |
| `glab govern doctor`이(가) 에이전트 유형이 아직 GitLab에서 지원되지 않는다고 표시합니다. | GitLab이 `glab`이(가) 처음 세션을 발견했을 때 그 에이전트 유형을 받아들이지 않았습니다. 그러한 세션은 절대 전송되지 않습니다. | GitLab이 에이전트 유형을 받아들인 후 `glab`이(가) 찾는 세션은 전송됩니다. 메시지가 계속되면 GitLab 지원팀에 문의하세요. |

## 관련 항목 {#related-topics}

- [AI Governance 대시보드](governance-dashboard.md)
- [AI 이벤트 감사](ai-audit-events.md)
- [GitLab CLI](../../editor_extensions/gitlab_cli/_index.md)
