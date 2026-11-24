---
stage: AI Clients
group: Developer Clients
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "설정 패널 또는 설정 파일에서 GitLab Duo CLI 설정을 변경하고, 관리되는 설정 파일로 설정을 적용합니다."
title: GitLab Duo CLI 설정
---

{{< details >}}

- 티어:  Premium, Ultimate
- 제공 서비스:  GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Duo CLI의 동작을 다음과 같은 방식으로 변경할 수 있습니다:

- 대화형 모드에서 [설정 패널](#settings-panel)을 통해 변경합니다.
- 설정 패널 선택 사항을 저장하는 [설정 파일](#settings-file)을 통해 변경합니다. 파일을 직접 편집할 수도 있습니다.
- 시스템 관리자가 설정을 적용하기 위해 배포하는 [관리되는 설정 파일](#managed-settings-file)을 통해 변경합니다.

## 설정 패널 {#settings-panel}

{{< history >}}

- GitLab 19.0 릴리스 중 설정 패널이 GitLab Duo CLI 8.90.0에 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.90.0)되었습니다.
- 새 세션에 작업 항목을 표시하는 설정이 GitLab Duo CLI 9.11.0(GitLab 19.4 릴리스)에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.11.0)되었습니다.
- 테마를 조정하는 설정이 GitLab Duo CLI 9.11.0(GitLab 19.4 릴리스)에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.11.0)되었습니다.
- 제안된 프롬프트를 `/goal` 세션으로 실행하는 설정이 GitLab Duo CLI 9.24.0(GitLab 19.5 릴리스)에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.24.0)되었습니다.

{{< /history >}}

설정을 변경하려면:

1. 대화형 모드에서 `/settings`을 입력하고 <kbd>Enter</kbd>를 누릅니다.
1. 화살표 키를 사용하여 설정 목록을 탐색합니다.
1. 선택한 설정을 변경하려면 <kbd>Enter</kbd> 또는 <kbd>Space</kbd>를 누릅니다.
1. 패널을 닫으려면 <kbd>Escape</kbd>를 누릅니다.

변경 사항은 설정 파일에 세션 간에 유지됩니다. 조직에서 설정을 적용하면 패널에 **조직에서 설정함**이 표시되며 변경할 수 없습니다.

다음 설정을 사용할 수 있습니다.

| 설정                  | 설명                                                                                       |
|--------------------------|---------------------------------------------------------------------------------------------------|
| **원격 분석**            | GitLab Duo를 개선하기 위해 익명의 사용 데이터를 보냅니다.                                                  |
| **알림**        | [시스템 알림](use.md#system-notifications)을 제어합니다(`auto` 또는 `disabled`).                     |
| **세션 시작 시 작업 항목 표시** | 새 세션을 시작할 때 열려 있는 작업 항목을 표시합니다. |
| **제안된 프롬프트를 /goal 세션으로 실행** | 제안된 프롬프트를 일반 채팅 메시지 대신 `/goal` 세션으로 실행합니다. 변경 사항이 적용되려면 다시 시작이 필요합니다. |
| **테마**        | 테마 설정을 변경합니다. 옵션에는 `auto`, `dark`, `light`, `dark high contrast` 및 `light high contrast`가 포함됩니다. |

## 설정 파일 {#settings-file}

{{< history >}}

- GitLab Duo CLI 9.26.0(GitLab 19.5 릴리스)에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.26.0)되었습니다.

{{< /history >}}

GitLab Duo CLI는 `/settings` 패널에서 변경한 설정을 설정 파일에 저장합니다. 파일을 직접 편집하거나 미리 생성할 수도 있습니다. 예를 들어 컨테이너 이미지에서 생성할 수 있습니다.

GitLab Duo CLI는 시작할 때 파일을 읽습니다. 파일에 대한 변경 사항은 다음에 GitLab Duo CLI를 시작할 때 적용됩니다.

### 파일 위치 {#file-location}

파일 위치는 운영 체제에 따라 다릅니다:

| 운영 체제 | 경로                                 |
|------------------|--------------------------------------|
| Linux 및 macOS  | `~/.gitlab/duo/settings.json`        |
| Windows          | `%APPDATA%\GitLab\duo\settings.json` |

`XDG_CONFIG_HOME`을 설정한 경우 파일은 `$XDG_CONFIG_HOME/gitlab/duo/settings.json`입니다.

GitLab Duo CLI는 `/settings` 패널에서 처음으로 설정을 변경할 때 파일을 생성합니다.

### 파일 형식 {#file-format}

파일은 JSON 객체를 포함해야 하며 주석(`//` 및 `/* */`)과 후행 쉼표를 포함할 수 있습니다. `/settings` 패널에서 설정을 변경하면 GitLab Duo CLI는 주석, 형식 지정 및 인식하지 못하는 모든 키를 유지합니다.

다음 예에서는 모든 설정을 기본값으로 설정합니다:

```json
{
  "telemetry": {
    "enabled": true
  },
  "showWorkItemsInNewSessions": true,
  "goalFlowInWelcomePrompts": true,
  "notifications": {
    "channel": "auto" // or "disabled"
  },
  "theme": "auto" // or "dark", "light", "dark-high-contrast", "light-high-contrast"
}
```

### 잘못된 파일 및 값 {#invalid-files-and-values}

GitLab Duo CLI는 파일을 수정하기 위해 절대 삭제하거나 다시 작성하지 않습니다:

- 파일이 유효한 JSON이 아니면 GitLab Duo CLI는 전체 파일을 무시하고 경고를 기록합니다.
- 설정에 유효하지 않은 값이 있으면 GitLab Duo CLI는 해당 설정을 무시하고 경고를 기록합니다.
- GitLab Duo CLI가 설정을 인식하지 못하면(예: 최신 버전의 설정) 해당 설정을 무시합니다.

파일이 읽기 전용이면 `/settings` 패널에서 변경한 사항은 현재 세션에만 적용됩니다.

## 관리되는 설정 파일 {#managed-settings-file}

{{< history >}}

- GitLab Duo CLI 9.27.0(GitLab 19.5 릴리스)에서 [도입](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.27.0)되었습니다.

{{< /history >}}

설정을 적용하기 위해 시스템 관리자는 각 머신에 관리되는 설정 파일을 배포합니다. 예를 들어 모바일 디바이스 관리 도구 또는 그룹 정책을 사용할 수 있습니다.

관리되는 설정 파일의 설정은 명령줄 옵션, 환경 변수 및 설정 파일(사용자가 설정 패널에서 변경한 사항 포함)보다 우선합니다.

적용된 설정은 사용자가 변경할 수 없습니다. 파일에 없는 설정은 사용자 제어 상태로 유지됩니다.

### 파일 위치 {#file-location-1}

GitLab Duo CLI는 변경할 수 없는 고정 위치에서 파일을 읽습니다:

| 운영 체제                  | 경로                                                            |
|-----------------------------------|-----------------------------------------------------------------|
| Linux 및 기타 운영 체제 | `/etc/gitlab/duo/settings.managed.json`                         |
| macOS                             | `/Library/Application Support/GitLab/duo/settings.managed.json` |
| Windows                           | `C:\Program Files\GitLab\duo\settings.managed.json`             |

시스템 관리자에게 쓰기 액세스를 제한하고 다른 모든 사용자에게 읽기 전용 액세스 권한을 부여합니다.

GitLab Duo CLI는 시작할 때 파일을 읽습니다. 파일에 대한 변경 사항은 다음에 사용자가 GitLab Duo CLI를 시작할 때 적용됩니다.

Windows Subsystem for Linux(WSL)에서 GitLab Duo CLI는 배포 내부의 Linux 경로를 읽으며 Windows 그룹 정책이 적용되지 않습니다.

### 파일 형식 {#file-format-1}

파일은 JSON 객체를 포함해야 하며 주석(`//` 및 `/* */`)과 후행 쉼표를 포함할 수 있습니다.

다음 예에서는 적용할 수 있는 모든 설정을 설정합니다:

```json
{
  "telemetry": {
    "enabled": false
  },
  "showWorkItemsInNewSessions": true,
  "goalFlowInWelcomePrompts": true,
  "notifications": {
    "channel": "auto" // or "disabled"
  },
}
```

## 설정 우선순위 {#settings-precedence}

각 설정에 대해 GitLab Duo CLI는 다음 순서로 처음으로 찾은 값을 사용합니다:

1. 조직에서 설정을 적용하는 경우 관리되는 설정 파일입니다.
1. 현재 세션에만 적용되는 명령줄 옵션 및 환경 변수입니다.
1. 설정 파일입니다.
1. 기본값입니다.
