---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Slack 앱용 GitLab
description: "슬래시 명령, 알림 수신, Slack 워크스페이스에서 GitLab Duo와 상호 작용할 수 있도록 Slack 앱용 GitLab을 구성합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> 관리자 문서는 [Slack 앱용 GitLab 관리](../../../administration/settings/slack_app.md)를 참조하세요.

Slack 앱용 GitLab은 Slack 워크스페이스에서 [슬래시 명령](#slash-commands), [알림](#slack-notifications), [GitLab Duo 통합](#gitlab-duo)을 제공하는 기본 Slack 앱입니다. GitLab은 Slack 사용자를 GitLab 사용자와 연결하므로 Slack에서 실행하는 모든 명령이 연결된 GitLab 사용자로 실행됩니다.

## Slack 앱용 GitLab 설치 {#install-the-gitlab-for-slack-app}

사전 요구 사항:

- Slack 워크스페이스에 앱을 추가할 수 있는 [적절한 권한](https://slack.com/help/articles/202035138-Add-apps-to-your-Slack-workspace)이 필요합니다.
- GitLab Self-Managed에서는 관리자가 [통합을 활성화](../../../administration/settings/slack_app.md)해야 합니다.

Slack 앱용 GitLab은 [세분화된 권한](https://medium.com/slack-developer-blog/more-precision-less-restrictions-a3550006f9c3)을 사용합니다. 기능이 변경되지 않았지만 [앱을 다시 설치](#reinstall-the-gitlab-for-slack-app)해야 합니다.

### 프로젝트 또는 그룹 설정에서 {#from-the-project-or-group-settings}

{{< history >}}

- [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/175803) GitLab 17.8에서. 기능 플래그 `gitlab_for_slack_app_instance_and_group_level`이 제거되었습니다.

{{< /history >}}

프로젝트 또는 그룹 설정에서 Slack 앱용 GitLab을 설치하려면 다음을 수행합니다:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Slack 앱용 GitLab**을 선택하세요.
1. **Slack 앱용 GitLab 설치**를 선택하세요. Slack 확인 페이지로 리디렉션됩니다.
1. Slack 확인 페이지에서:
   1. 선택 사항. 2개 이상의 Slack 워크스페이스에 로그인한 경우 오른쪽 상단의 드롭다운 목록에서 앱을 설치할 워크스페이스를 선택합니다. GitLab Self-Managed 및 GitLab Dedicated에서는 관리자가 먼저 [여러 워크스페이스에 대한 지원 활성화](../../../administration/settings/slack_app.md#enable-support-for-multiple-workspaces)를 해야 드롭다운 목록이 나타납니다.
   1. **허용**을 선택하세요.

그룹에 대해 앱을 설치하면 통합이 이미 통합이 구성되지 않은 그룹의 모든 하위 그룹 및 프로젝트에도 활성화됩니다. 이미 통합이 구성된 하위 그룹 및 프로젝트는 영향을 받지 않지만 언제든지 상속된 설정을 사용할 수 있습니다. 자세한 내용은 [프로젝트 통합을 위한 그룹 기본 설정 관리](_index.md#manage-group-default-settings-for-a-project-integration)를 참조하세요. 각 프로젝트는 프로젝트 경로를 기반으로 하는 프로젝트별 별칭을 받으며, 이를 [슬래시 명령](#slash-commands)에서 사용할 수 있습니다.

### Slack 앱 디렉토리에서 {#from-the-slack-app-directory}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

GitLab.com에서 [Slack 앱 디렉토리](https://slack-platform.slack.com/apps/A676ADMV5-gitlab)에서 Slack 앱용 GitLab을 설치할 수도 있습니다.

Slack 앱 디렉토리에서 Slack 앱용 GitLab을 설치하려면 다음을 수행합니다:

1. [Slack용 GitLab 페이지](https://gitlab.com/-/profile/slack/edit)로 이동합니다.
1. Slack 워크스페이스와 연결할 GitLab 프로젝트를 선택합니다.

## Slack 앱용 GitLab 다시 설치 {#reinstall-the-gitlab-for-slack-app}

GitLab에서 Slack 앱용 GitLab에 대한 새로운 기능을 릴리스하면 이 기능을 사용하기 위해 앱을 다시 설치해야 할 수도 있습니다.

Slack 앱용 GitLab을 다시 설치하려면 다음을 수행합니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Slack 앱용 GitLab**을 선택하세요.
1. **Slack 앱용 GitLab 설치**를 선택하세요. Slack 확인 페이지로 리디렉션됩니다.
1. Slack 확인 페이지에서:
   1. 선택 사항. 2개 이상의 Slack 워크스페이스에 로그인한 경우 오른쪽 상단의 드롭다운 목록에서 앱을 다시 설치할 워크스페이스를 선택합니다. GitLab Self-Managed 및 GitLab Dedicated에서는 관리자가 먼저 [여러 워크스페이스에 대한 지원 활성화](../../../administration/settings/slack_app.md#enable-support-for-multiple-workspaces)를 해야 드롭다운 목록이 나타납니다.
   1. **허용**을 선택하세요.

Slack 앱용 GitLab은 통합을 사용하는 모든 프로젝트에 대해 업데이트됩니다.

또는 [통합을 다시 구성](https://about.gitlab.com/solutions/slack/)할 수 있습니다.

## GitLab Duo {#gitlab-duo}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- GitLab 19.1에서 `slack_duo_agent` [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/590434)되었습니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md)입니다.
- GitLab 19.4에서 [GitLab.com 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/work_items/592185)되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트 가능하지만 프로덕션 사용은 준비되지 않았습니다.

<!-- Two distinct notes, so the blank line between them is intentional. -->

> [!note]
> Slack Enterprise Grid 없이 여러 Slack 설치를 사용하면 Slack에서 GitLab Duo를 분당 15개의 대화 개체로 속도 제한합니다. 단일 호출이 컨텍스트로 사용할 채널 기록에서 50개의 메시지를 요청하므로 이로 인해 통합이 작동하지 않습니다. Slack에서 GitLab Duo의 속도 제한을 피하려면 모든 Slack 워크스페이스를 단일 Enterprise Grid 조직에 유지하세요.

[GitLab Duo](../../gitlab_duo/_index.md)와 직접 상호 작용할 수 있으며, 봇이 있는 모든 채널이나 스레드에서 GitLab 봇을 언급하면 됩니다. GitLab Duo는 전체 대화 스레드와 최근 채널 기록을 컨텍스트로 읽고, CI/CD 러너에서 플로우를 실행하고, 결과를 Slack 스레드에 다시 게시합니다.

예를 들어 GitLab Duo에 다음을 요청할 수 있습니다:

- 대화를 GitLab 이슈로 변환합니다.
- 기존 이슈 또는 머지 리퀘스트를 검색합니다.
- 토론 스레드를 요약합니다.
- 프로젝트에 대한 질문에 답변합니다.

각 상호 작용은 GitLab Duo Agent 세션을 실행하고 GitLab Credits를 소비합니다. 세션은 호출 사용자의 기본 Duo 네임스페이스의 CI/CD 러너에서 실행되며, `duo-workspace` 프로젝트가 처음 사용 시 자동으로 생성됩니다. 다른 최상위 그룹의 프로젝트에 대해 물어보면 Slack의 GitLab Duo가 실패합니다.

채널에서 언급될 때 에이전트는 해당 채널의 최근 메시지를 응답의 컨텍스트로 읽습니다. 응답 중인 메시지 이후에 게시된 메시지는 포함되지 않습니다. 사용자가 GitLab Duo와 상호 작용한 후에는 호출한 사람에게만 표시되는 에이전트 세션을 만들며, `duo-workspace` 프로젝트에 대한 액세스 권한이 있는 모든 사람에게는 표시되지 않습니다.

> [!note]
> GitLab 봇을 스레드에서 언급할 때 전체 대화 내용(모든 참여자의 메시지 포함)이 응답을 생성하기 위해 대규모 언어 모델(LLM)로 전송됩니다. GitLab Duo를 언급하는 스레드에서는 민감한 정보를 공유하지 마세요.

### 사전 요구 사항 {#prerequisites}

- [GitLab Duo Agent Platform 켜기](../../duo_agent_platform/turn_on_off.md#turn-gitlab-duo-agent-platform-on-or-off).
- [베타 및 실험 기능 활성화](../../gitlab_duo/turn_on_off.md#turn-on-beta-and-experimental-features).
- Slack 계정을 GitLab 계정과 연결합니다. 계정이 연결되지 않으면 GitLab에서 첫 언급 시 연결을 승인할 수 있는 링크가 포함된 메시지를 보냅니다.
- [기본 GitLab Duo 네임스페이스 설정](../../profile/preferences.md#set-a-default-gitlab-duo-namespace).
- 최상위 그룹에 대해 [Developer 플로우](../merge_requests/developer.md)를 켭니다.
- 사용하려는 Slack 채널에 GitLab 봇을 추가합니다.
- 기존 설치의 경우 GitLab Duo에 필요한 추가 권한을 부여하려면 [Slack 앱용 GitLab을 다시 설치](#reinstall-the-gitlab-for-slack-app)하세요.

### Slack에서 GitLab Duo 사용 {#use-gitlab-duo-in-slack}

Slack에서 GitLab Duo를 사용하려면 다음을 수행합니다:

1. `/invite @GitLab`를 사용하여 채널에 앱을 초대합니다.
1. Slack 채널 또는 채널의 스레드에서 `@GitLab`를 입력한 후 요청을 입력합니다(예: `@GitLab create an issue to track this bug`).
1. `@GitLab`를 처음 입력할 때 GitLab에서 Slack과 GitLab 계정을 연결할 수 있는 링크가 포함된 메시지를 보냅니다.
1. GitLab Duo가 요청을 승인하고 작업을 시작합니다.
1. 작업이 완료되면 GitLab Duo가 결과와 함께 스레드 회신을 게시합니다.

오류가 발생하면 GitLab Duo가 메시지에 잠긴 자물쇠 이모지로 반응하고 문제에 대한 세부 정보가 포함된 메시지를 보냅니다. 이 메시지는 사용자에게만 표시됩니다.

이 기능의 성능에 대한 피드백을 남기려면 모든 응답에 대해 좋아요 또는 싫어요를 사용합니다.

Slack의 GitLab Duo는 다음 채널 및 스레드에서 작동합니다:

- 에이전트가 채널의 구성원인 공개 및 비공개 채널입니다.
- 2명 이상의 사람 간의 그룹 직접 메시지입니다. GitLab Duo는 언급된 메시지만 보고 이전 대화는 보지 않습니다.

GitLab Duo는 다음 스레드에서 작동하지 않습니다:

- 에이전트와의 일대일 직접 메시지입니다.
- Slack 상단 표시줄의 에이전트 패널입니다.

### 워크스페이스 프로젝트 {#workspace-project}

Slack에서 처음 GitLab Duo를 사용할 때 `duo-workspace`라는 워크스페이스 프로젝트가 기본 GitLab Duo 네임스페이스에 자동으로 생성됩니다. 이 프로젝트는 Slack에서 트리거된 모든 플로우의 실행 환경으로 사용됩니다.

워크스페이스 프로젝트에서 에이전트 동작을 사용자 정의할 수 있습니다. 자세한 내용은 [Developer 플로우](../merge_requests/developer.md)를 참조하세요.

### Slack 앱용 GitLab 권한 {#gitlab-for-slack-app-permissions}

GitLab Duo에는 다음과 같은 추가 Slack 앱용 GitLab 권한이 필요합니다:

| 범위               | 목적 |
|---------------------|---------|
| `app_mentions:read` | 사용자가 채널에서 봇을 언급할 때 이벤트를 수신합니다. |
| `channels:history`  | 공개 채널의 대화 기록을 읽어 에이전트에 스레드 및 채널 컨텍스트를 제공합니다. |
| `groups:history`    | 비공개 채널의 대화 기록을 읽어 에이전트에 스레드 및 채널 컨텍스트를 제공합니다. |
| `reactions:write`   | 에이전트 수명 주기 상태를 나타내기 위해 메시지에 이모지 반응을 추가합니다. |

새로운 설치는 이러한 권한을 자동으로 받습니다. 기존 설치는 [Slack 앱용 GitLab을 다시 설치](#reinstall-the-gitlab-for-slack-app)한 후에만 이러한 권한을 받습니다.

## 슬래시 명령 {#slash-commands}

슬래시 명령을 사용하여 일반적인 GitLab 작업을 실행할 수 있습니다.

Slack 앱용 GitLab의 경우:

- 첫 슬래시 명령을 실행할 때 Slack 사용자를 승인해야 합니다.
- `<project>`를 프로젝트 전체 경로로 바꾸거나 슬래시 명령에 대해 [프로젝트 별칭을 만들](#create-a-project-alias) 수 있습니다.

대신 [Mattermost 슬래시 명령](mattermost_slash_commands.md)을 사용하는 경우:

- `/gitlab`을(를) 이러한 통합에 대해 구성한 트리거 이름으로 바꿉니다.
- `<project>`을(를) 제거합니다.

다음 슬래시 명령은 GitLab에서 사용할 수 있습니다:

| 명령 | 설명 |
| ------- | ----------- |
| `/gitlab help` | 사용 가능한 모든 슬래시 명령을 표시합니다. |
| `/gitlab <project> issue show <id>` | ID `<id>`인 이슈를 표시합니다. |
| `/gitlab <project> issue new <title>` <kbd>Shift</kbd>+<kbd>Enter</kbd> `<description>` | 제목 `<title>` 및 설명 `<description>`으로 이슈를 만듭니다. |
| `/gitlab <project> issue search <query>` | `<query>`와(과) 일치하는 최대 5개의 이슈를 표시합니다. |
| `/gitlab <project> issue move <id> to <project>` | ID `<id>`인 이슈를 `<project>`로 이동합니다. |
| `/gitlab <project> issue close <id>` | ID `<id>`인 이슈를 닫습니다. |
| `/gitlab <project> issue comment <id>` <kbd>Shift</kbd>+<kbd>Enter</kbd> `<comment>` | ID `<id>`인 이슈에 주석 본문 `<comment>`이(가) 포함된 주석을 추가합니다. |
| `/gitlab <project> deploy <from> to <to>` | `<from>` 환경에서 `<to>` 환경으로 [배포](#deploy-command)합니다. |
| `/gitlab <project> run <job name> <arguments>` | 기본 브랜치에서 [ChatOps](../../../ci/chatops/_index.md) 작업 `<job name>`을(를) 실행합니다. |
| `/gitlab incident declare` | Slack에서 [인시던트를 만들](../../../operations/incident_management/slack.md)기 위한 대화 상자를 엽니다. |

### `deploy` 명령 {#deploy-command}

환경에 배포하기 위해 GitLab은 파이프라인에서 수동 배포 작업을 찾으려고 합니다.

환경에 대해 배포 작업이 하나만 정의된 경우 해당 작업이 트리거됩니다. 둘 이상의 배포 작업이 정의된 경우 GitLab은 환경 이름과 일치하는 작업 이름을 찾으려고 합니다.

GitLab에서 일치하는 배포 작업을 찾을 수 없으면 명령에서 오류를 반환합니다.

### 프로젝트 별칭 만들기 {#create-a-project-alias}

Slack 앱용 GitLab에서 슬래시 명령은 기본적으로 프로젝트 전체 경로를 사용합니다. 대신 프로젝트 별칭을 사용할 수 있습니다.

Slack 앱용 GitLab에서 슬래시 명령에 대한 프로젝트 별칭을 만들려면 다음을 수행합니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Slack 앱용 GitLab**을 선택하세요.
1. 프로젝트 경로 또는 별칭 옆에 **편집**을 선택합니다.
1. 새 별칭을 입력하고 **변경사항 저장**을 선택합니다.

Slack 워크스페이스에서 별칭 충돌이 발생하면(예: 여러 프로젝트 또는 그룹이 동일한 별칭을 사용하려고 시도함), GitLab에서 자동으로 다음 형식으로 폴백 별칭을 할당합니다:

- 프로젝트의 경우: `p-<project_id>` (예: `p-12345`)
- 그룹의 경우: `g-<group_id>` (예: `g-67890`)

기본 별칭을 사용할 수 없을 때 슬래시 명령에서 이 폴백 별칭을 사용할 수 있습니다.

## Slack 알림 {#slack-notifications}

특정 GitLab [이벤트](#notification-events)에 대해 Slack 채널로 알림을 받을 수 있습니다.

### 알림 구성 {#configure-notifications}

Slack 알림을 구성하려면 다음을 수행합니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Slack 앱용 GitLab**을 선택하세요.
1. **트리거** 섹션에서:
   - Slack에서 알림을 받으려는 각 GitLab [이벤트](#notification-events)의 확인란을 선택합니다.
   - 선택하는 각 확인란에 대해 알림을 받을 Slack 채널의 이름을 입력합니다. 최대 10개의 채널 이름을 쉼표로 구분하여 입력할 수 있습니다(예: `#channel-one, #channel-two`).

     > [!note]
     > Slack 채널이 비공개이면 [채널에 Slack 앱용 GitLab을 추가](#receive-notifications-to-a-private-channel)해야 합니다.

1. 선택 사항. **알림 설정** 섹션에서:
   - **잘못된 파이프라인만 알림 받기** 확인란을 선택하여 실패한 파이프라인에 대한 알림만 받습니다.
   - **상태 변경 시에만 알림 받기** 확인란을 선택하여 ref의 파이프라인 상태가 변경될 때만 알림을 받습니다.
   - **알림을 보내야 할 브랜치** 드롭다운 목록에서 알림을 받을 브랜치를 선택합니다.

     알림은 또한 이 브랜치에서 만든 태그로 트리거되는 파이프라인에 대해서도 전송됩니다.

     취약성에 대한 알림은 선택한 브랜치와 관계없이 기본 브랜치에서만 트리거됩니다. 자세한 내용은 [이슈 469373](https://gitlab.com/gitlab-org/gitlab/-/issues/469373)을(를) 참조하세요.
   - **알릴 레이블**의 경우 알림을 받기 위해 GitLab 이슈, 머지 리퀘스트 또는 주석이 가져야 하는 레이블을 입력합니다. 모든 이벤트에 대한 알림을 받으려면 공백으로 두세요.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 비공개 채널로 알림 수신 {#receive-notifications-to-a-private-channel}

비공개 Slack 채널로 알림을 받으려면 채널에 Slack 앱용 GitLab을 추가해야 합니다:

1. `@GitLab`을(를) 입력하여 채널에서 앱을 언급합니다.
1. **채널에 추가**를 선택하세요.

### 알림 이벤트 {#notification-events}

다음 GitLab 이벤트는 Slack에서 알림을 트리거할 수 있습니다:

| 이벤트                                                                 | 설명 |
| --------------------------------------------------------------------- | ----------- |
| 푸시                                                                  | 리포지토리에 대해 푸시가 수행됩니다. |
| 이슈                                                                 | 작업 항목이 생성, 닫혀 있거나 다시 열립니다. |
| 기밀 이슈                                                    | 기밀 작업 항목이 생성, 닫혀 있거나 다시 열립니다. |
| 머지 리퀘스트                                                         | 머지 리퀘스트가 생성, 병합, 승인, 닫혀 있거나 다시 열립니다. |
| 주석                                                                  | 주석이 추가됩니다. |
| 기밀 주석                                                     | 기밀 작업 항목에 대한 내부 주석 또는 주석이 추가됩니다. |
| 태그 푸시                                                              | 태그가 리포지토리에 푸시되거나 제거됩니다. |
| 파이프라인                                                              | 파이프라인 상태가 변경됩니다. |
| 위키 페이지                                                             | 위키 페이지가 생성되거나 업데이트됩니다. |
| 배포                                                            | 배포가 시작되거나 완료됩니다. |
| 공개에서 [그룹 언급](#trigger-notifications-for-group-mentions)  | 그룹이 공개 채널에서 언급됩니다. |
| 비공개에서 [그룹 언급](#trigger-notifications-for-group-mentions) | 그룹이 비공개 채널에서 언급됩니다. |
| [인시던트](../../../operations/incident_management/slack.md)          | 인시던트가 생성, 닫혀 있거나 다시 열립니다. |
| [취약성](../../application_security/vulnerabilities/_index.md) | 새로운 고유 취약성이 기본 브랜치에 기록됩니다. |
| 경고                                                                 | 새로운 고유 알림이 기록됩니다. |

### 그룹 언급에 대한 알림 트리거 {#trigger-notifications-for-group-mentions}

{{< history >}}

- [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/175803) GitLab 17.8에서. 기능 플래그 `gitlab_for_slack_app_instance_and_group_level`이 제거되었습니다.

{{< /history >}}

그룹 언급에 대해 [알림 이벤트](#notification-events)를 트리거하려면 `@<group_name>`을(를) 다음에서 사용합니다:

- 이슈 및 머지 리퀘스트 설명
- 이슈, 머지 리퀘스트 및 커밋에 대한 주석
