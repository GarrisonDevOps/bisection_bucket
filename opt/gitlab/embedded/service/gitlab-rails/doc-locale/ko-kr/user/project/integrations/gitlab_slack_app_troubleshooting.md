---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab for Slack 앱 문제 해결
description: "GitLab for Slack 앱을 위한 문제 해결 가이드입니다. 누락된 프로젝트 및 알림 문제와 같은 일반적인 문제를 다룹니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab for Slack 앱으로 작업할 때 다음과 같은 문제가 발생할 수 있습니다.

## 앱이 통합 목록에 표시되지 않음 {#app-does-not-appear-in-the-list-of-integrations}

GitLab for Slack 앱이 통합 목록에 표시되지 않을 수 있습니다. GitLab Self-Managed 인스턴스에 GitLab for Slack 앱을 포함하려면 관리자가 [통합을 켜야](../../../administration/settings/slack_app.md) 합니다. GitLab.com에서는 GitLab for Slack 앱을 기본적으로 사용할 수 있습니다.

## 오류: `Project or alias not found` {#error-project-or-alias-not-found}

일부 Slack 명령은 프로젝트 전체 경로 또는 별칭이 필요하며, 프로젝트를 찾을 수 없으면 다음 오류로 실패합니다:

```plaintext
GitLab error: project or alias not found
```

이 문제를 해결하려면 다음을 확인하세요:

- 프로젝트 전체 경로가 올바릅니다.
- [프로젝트 별칭](gitlab_slack_application.md#create-a-project-alias)을 사용하는 경우 별칭이 올바릅니다.
- GitLab for Slack 앱이 [프로젝트에 대해 켜져](gitlab_slack_application.md#from-the-project-or-group-settings) 있습니다.

## 슬래시 명령이 `dispatch_failed` Slack에서 반환됨 {#slash-commands-return-dispatch_failed-in-slack}

슬래시 명령이 Slack에서 `/gitlab failed with the error "dispatch_failed"`을 반환할 수 있습니다.

이 문제를 해결하려면 관리자가 GitLab Self-Managed 인스턴스에서 [GitLab for Slack 앱 설정](../../../administration/settings/slack_app.md)을 올바르게 구성했는지 확인하세요.

## 채널에 알림이 수신되지 않음 {#notifications-not-received-to-a-channel}

Slack 채널에 알림을 받지 못하는 경우 다음을 확인하세요:

- 구성한 채널 이름이 올바릅니다.
- 채널이 비공개인 경우 [GitLab for Slack 앱을 채널에 추가](gitlab_slack_application.md#receive-notifications-to-a-private-channel)했습니다.

## 앱 홈이 제대로 표시되지 않음 {#app-home-does-not-display-properly}

[앱 홈](https://api.slack.com/start/overview#app_home)이 제대로 표시되지 않으면 [앱이 최신 상태](gitlab_slack_application.md#reinstall-the-gitlab-for-slack-app)인지 확인하세요.

## 오류: `This alias has already been taken` {#error-this-alias-has-already-been-taken}

새 프로젝트에서 설정하려고 할 때 오류 `422: The change you requested was rejected`이 발생할 수 있습니다. 반환된 Rails 오류는 다음과 같을 수 있습니다:

```plaintext
"exception.message": "Validation failed: Alias This alias has already been taken"
```

이 이슈를 해결하려면:

1. GitLab for Slack 앱이 켜져 있는 유사한 이름의 프로젝트에 대해 네임스페이스를 검색합니다.
1. 이러한 프로젝트 중에서 실패한 프로젝트와 동일한 별칭 이름을 가진 프로젝트를 확인합니다.
1. 별칭을 편집하여 다르게 만든 다음 실패한 프로젝트에 대해 GitLab for Slack 앱을 다시 켜세요.

## GitLab Duo `@mention` 실패 {#gitlab-duo-mention-failures}

Slack에서 GitLab 앱에 `@mention`하여 GitLab Duo를 트리거하면 문제가 발생할 때 앱이 스레드에 메시지를 게시합니다. 메시지 텍스트를 사용하여 원인을 파악하고 해결책을 적용하세요.

| Slack 메시지 | 원인 | 해결책 |
|---|---|---|
| 잠금 이모지(🔒) 및 인증 프롬프트 | Slack 계정이 GitLab 계정에 연결되지 않습니다. | 인증 흐름을 완료하여 Slack 및 GitLab 계정을 연결합니다. |
| `"You do not have access to this feature yet"` | `slack_duo_agent` 기능 플래그가 계정에 대해 활성화되지 않았습니다. | 관리자에게 사용자에 대한 기능 플래그를 활성화하도록 요청합니다. |
| `"This feature requires experiment and beta GitLab Duo features to be turned on"` | 베타 및 실험 GitLab Duo 기능이 꺼져 있습니다. | [베타 및 실험 기능](../../gitlab_duo/turn_on_off.md#turn-on-beta-and-experimental-features)을 켜세요. GitLab.com에서 이 설정은 최상위 그룹용입니다. GitLab Self-Managed 및 GitLab Dedicated에서는 인스턴스용입니다. |
| `"This feature requires GitLab Duo Agent Platform"` | 계정에 GitLab Duo Agent Platform 라이선스가 없습니다. | 관리자와 함께 GitLab Duo 자격을 확인합니다. |
| `"Set your default Duo namespace in your preferences"` | GitLab 계정에 기본 GitLab Duo 네임스페이스가 구성되지 않았습니다. | GitLab 기본 설정에서 기본 GitLab Duo 네임스페이스를 설정합니다. GitLab.com에서 네임스페이스에서 활성 GitLab Duo 추가 기능 사용자 할당량이 있어야 합니다. |
| `"The <flow_name> flow is not turned on for your namespace"` | GitLab Duo in Slack가 사용하는 기본 GitLab Duo 플로우가 네임스페이스에 대해 켜져 있지 않습니다. | 그룹 소유자에게 GitLab Duo Agent Platform 설정에서 메시지에 명시된 플로우를 켜달라고 요청합니다. |
| `"Could not set up the service account…"` | 네임스페이스의 서비스 계정을 프로비저닝할 수 없습니다. | 네임스페이스 GitLab Duo 구성 및 서비스 계정 프로비저닝을 확인합니다. |
| `"Could not set up the workspace project…"` | GitLab이 네임스페이스에서 `duo-workspace` 프로젝트를 찾거나 생성할 수 없습니다. | 네임스페이스에서 프로젝트를 만들 수 있는지 확인합니다. 네임스페이스 `project_creation_level` 설정은 프로젝트 생성을 허용해야 합니다. |
| `"Failed to start the GitLab Duo session"` 또는 `"Something went wrong…"` | GitLab Duo 플로우 트리거 또는 실행이 실패했습니다. | CI 작업 로그 및 GitLab 통합 로그에서 세부 정보를 확인합니다. |

### GitLab Duo `@mention` 디버깅 팁 {#debugging-tips-for-gitlab-duo-mention}

- 통합 로그는 `integrations_json.log`에 기록됩니다. 각 항목은 `slack_workspace_id` 필드를 포함하며, 종종 `slack_user_id` 및 `channel_id`도 포함합니다. `slack_workspace_id`로 필터링하여 워크스페이스와 관련된 항목을 찾습니다.
- Sidekiq 워커 로그(`sidekiq.log`)도 `Integrations::SlackEventWorker` 작업에 대해 `slack_workspace_id` 및 `slack_user_id`을 포함합니다. 이를 사용하여 이벤트가 수신되고 처리되었는지 추적합니다.
- 봇이 전혀 반응하거나 응답할 수 없으면 문제는 Slack 통합 구성 또는 봇 토큰과 관련이 있을 가능성이 높습니다. `integrations_json.log`을 확인하여 `"message": "SlackInstallation record has no bot token"`항목을 찾습니다. 봇이 반응하지만 오류를 게시하면 문제는 사용자 쪽 인증 게이트 또는 네임스페이스 해결과 관련이 있습니다.
- `duo-workspace` 프로젝트는 플로우가 처음 실행될 때 자동으로 생성되고 그 이후에 다시 사용됩니다. 프로젝트 생성이 실패하면 최소한 유지 관리자 역할이 있는 네임스페이스를 사용하거나 그룹 소유자에게 `project_creation_level` 설정을 조정하도록 요청합니다.
