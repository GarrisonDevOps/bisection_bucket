---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 프로젝트 통합
description: "프로젝트 및 그룹 통합에 대한 사용자 설명서입니다. 사용 가능한 통합 목록을 포함합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> 관리자 설명서는 [프로젝트 통합 관리](../../../administration/settings/project_integration_management.md)를 참조하세요.

외부 애플리케이션과 통합하여 GitLab에 기능을 추가할 수 있습니다.

다음에 대한 통합을 보고 관리할 수 있습니다:

- [인스턴스](../../../administration/settings/project_integration_management.md#configure-default-settings-for-an-integration) (GitLab Self-Managed)
- [그룹](#manage-group-default-settings-for-a-project-integration)

다음을 사용할 수 있습니다.

- [프로젝트 통합을 위한 인스턴스 또는 그룹 기본 설정](#use-instance-or-group-default-settings-for-a-project-integration)
- [프로젝트 또는 그룹 통합을 위한 커스텀 설정](#use-custom-settings-for-a-project-or-group-integration)

## 프로젝트 통합을 위한 그룹 기본 설정 관리 {#manage-group-default-settings-for-a-project-integration}

사전 요구 사항:

- 그룹의 소유자 역할이 있어야 합니다.

프로젝트 통합을 위한 그룹 기본 설정을 관리하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. 통합을 선택합니다.
1. 필드를 완성하세요.
1. **변경 사항 저장**을 선택합니다.

> [!warning]
> 이렇게 하면 그룹에 속한 모든 또는 대부분의 서브그룹 및 프로젝트가 영향을 받을 수 있습니다. 아래 세부 정보를 검토하세요.

통합에 대한 그룹 설정을 처음 설정하는 경우:

- 그룹 설정에서 **통합 활성화** 토글을 켜면 아직 이 통합이 구성되지 않은 그룹에 속한 모든 서브그룹 및 프로젝트에 대해 통합이 활성화됩니다.
- 이미 통합이 구성된 서브그룹 및 프로젝트는 영향을 받지 않지만 언제든지 상속된 설정을 사용하도록 선택할 수 있습니다.

그룹 기본 설정을 추가로 변경할 때:

- 통합이 기본 설정을 사용하도록 설정된 그룹에 속한 모든 서브그룹 및 프로젝트에 즉시 적용됩니다.
- 마지막으로 통합의 기본값을 저장한 후 생성된 프로젝트를 포함하여 더 최신의 서브그룹 및 프로젝트에도 즉시 적용됩니다. 그룹 기본 설정에서 **통합 활성화** 토글을 켜면 이러한 모든 서브그룹 및 프로젝트에 대해 통합이 자동으로 활성화됩니다.
- 통합에 대한 커스텀 설정이 선택된 서브그룹 및 프로젝트는 즉시 영향을 받지 않으며 언제든지 최신 기본값을 사용하도록 선택할 수 있습니다.

동일한 통합에 대해 [인스턴스 설정](../../../administration/settings/project_integration_management.md#configure-default-settings-for-an-integration)도 구성된 경우 그룹의 프로젝트는 그룹에서 설정을 상속받습니다.

통합에 대한 전체 설정만 상속할 수 있습니다. 필드별 상속은 [에픽 2137](https://gitlab.com/groups/gitlab-org/-/work_items/2137)에서 제안됩니다.

### 그룹 기본 설정 제거 {#remove-a-group-default-setting}

사전 요구 사항:

- 그룹의 소유자 역할이 있어야 합니다.

그룹 기본 설정을 제거하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. 통합을 선택합니다.
1. **리셋**를 선택하고 확인합니다.

그룹 기본 설정을 초기화하면 기본 설정을 사용하고 그룹의 프로젝트 또는 서브그룹에 속하는 통합이 제거됩니다.

## 프로젝트 통합을 위한 인스턴스 또는 그룹 기본 설정 사용 {#use-instance-or-group-default-settings-for-a-project-integration}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

프로젝트 통합을 위한 인스턴스 또는 그룹 기본 설정을 사용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. 통합을 선택합니다.
1. 오른쪽의 드롭다운 목록에서 **기본 설정 사용**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스가 선택되어 있는지 확인합니다.
1. 필드를 완성하세요.
1. **변경 사항 저장**을 선택합니다.

## 프로젝트 또는 그룹 통합을 위한 커스텀 설정 사용 {#use-custom-settings-for-a-project-or-group-integration}

사전 요구 사항:

- 프로젝트 통합에 대한 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 그룹 통합에 대한 소유자 역할이 있어야 합니다.

프로젝트 또는 그룹 통합을 위한 커스텀 설정을 사용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. 통합을 선택합니다.
1. 오른쪽의 드롭다운 목록에서 **커스텀 설정 사용**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스가 선택되어 있는지 확인합니다.
1. 필드를 완성하세요.
1. **변경 사항 저장**을 선택합니다.

## 사용 가능한 통합 {#available-integrations}

다음 통합은 GitLab 인스턴스에서 사용할 수 있습니다. 인스턴스 관리자가 [통합 허용 목록](../../../administration/settings/project_integration_management.md#integration-allowlist)을 구성한 경우 해당 통합만 사용할 수 있습니다.

### CI/CD {#cicd}

| 통합                                | 설명                                | 통합 훅 |
|--------------------------------------------|--------------------------------------------|-------------------|
| [Atlassian Bamboo](bamboo.md)              | Atlassian Bamboo로 CI/CD 파이프라인을 실행합니다. | {{< yes >}}       |
| Buildkite                                  | Buildkite로 CI/CD 파이프라인을 실행합니다.        | {{< yes >}}       |
| Drone                                      | Drone으로 CI/CD 파이프라인을 실행합니다.            | {{< yes >}}       |
| [Jenkins](../../../integration/jenkins.md) | Jenkins로 CI/CD 파이프라인을 실행합니다.          | {{< yes >}}       |
| JetBrains TeamCity                         | TeamCity로 CI/CD 파이프라인을 실행합니다.         | {{< yes >}}       |

### 이벤트 알림 {#event-notifications}

이러한 통합에는 통합 훅이 없습니다.

| 통합                                         | 설명                                                            |
|-----------------------------------------------------|------------------------------------------------------------------------|
| Campfire                                            | Campfire를 채팅에 연결합니다.                                              |
| [Discord 알림](discord_notifications.md)   | 프로젝트 이벤트에 대한 알림을 Discord 채널로 보냅니다.          |
| [Google Chat](hangouts_chat.md)                     | GitLab 프로젝트의 알림을 Google Chat의 공간으로 보냅니다. |
| [irker (IRC 게이트웨이)](irker.md)                     | 이벤트 알림을 IRC 채널로 보냅니다.                              |
| [Matrix 알림](matrix.md)                   | 프로젝트 이벤트에 대한 알림을 Matrix로 보냅니다.                     |
| [Mattermost 알림](mattermost.md)           | 프로젝트 이벤트에 대한 알림을 Mattermost 채널로 보냅니다.        |
| [Microsoft Teams 알림](microsoft_teams.md) | 이벤트 알림을 Microsoft Teams로 보냅니다.                           |
| [Pumble](pumble.md)                                 | 이벤트 알림을 Pumble 채널로 보냅니다.                          |
| Pushover                                            | 이벤트 알림을 기기로 보냅니다.                               |
| [텔레그램](telegram.md)                             | 프로젝트 이벤트에 대한 알림을 Telegram으로 보냅니다.                   |
| [Unify Circuit](unify_circuit.md)                   | 프로젝트 이벤트에 대한 알림을 Unify Circuit으로 보냅니다.              |
| [Webex Teams](webex_teams.md)                       | 이벤트 알림을 Webex Teams로 보냅니다.                               |

### 저장소 {#stores}

| 통합                                   | 설명                                                    | 통합 훅 |
|-----------------------------------------------|----------------------------------------------------------------|-------------------|
| [Apple App Store Connect](apple_app_store.md) | GitLab을 사용하여 Apple App Store에서 앱을 빌드하고 릴리스합니다. | {{< no >}}        |
| [Google Play](google_play.md)                 | GitLab을 사용하여 Google Play에서 앱을 빌드하고 릴리스합니다.         | {{< no >}}        |
| [Harbor](harbor.md)                           | Harbor를 GitLab의 컨테이너 레지스트리로 사용합니다.               | {{< no >}}        |
| Packagist                                     | Packagist에서 PHP 종속 요소를 업데이트합니다.                     | {{< yes >}}       |

### 외부 이슈 추적기 {#external-issue-trackers}

다음 통합은 프로젝트의 왼쪽 사이드바에 [외부 이슈 추적기](../../../integration/external-issue-tracker.md)에 대한 링크를 추가합니다. 이러한 통합에는 통합 훅이 없습니다.

| 통합                                     | 설명                                             | 이슈 동기화  | 새 이슈를 만들 수 있음 |
|-------------------------------------------------|---------------------------------------------------------|-------------|-----------------------|
| [Bugzilla](bugzilla.md)                         | Bugzilla를 이슈 추적기로 사용합니다.                       | {{< no >}}  | {{< yes >}}           |
| [ClickUp](clickup.md)                           | ClickUp을 이슈 추적기로 사용합니다.                        | {{< no >}}  | {{< no >}}            |
| [커스텀 이슈 추적기](custom_issue_tracker.md) | 커스텀 이슈 추적기를 사용합니다.                             | {{< no >}}  | {{< no >}}            |
| [Engineering Workflow Management (EWM)](ewm.md) | EWM을 이슈 추적기로 사용합니다.                            | {{< no >}}  | {{< yes >}}           |
| [Linear](linear.md)                             | Linear를 이슈 추적기로 사용합니다.                         | {{< no >}}  | {{< no >}}            |
| [Phorge](phorge.md)                             | Phorge를 이슈 추적기로 사용합니다.                         | {{< no >}}  | {{< yes >}}           |
| [Redmine](redmine.md)                           | Redmine을 이슈 추적기로 사용합니다.                        | {{< no >}}  | {{< yes >}}           |
| [YouTrack](youtrack.md)                         | JetBrains YouTrack을 프로젝트의 이슈 추적기로 사용합니다. | {{< yes >}} | {{< no >}}            |

### 외부 위키 {#external-wikis}

다음 통합은 프로젝트의 왼쪽 사이드바에 외부 위키에 대한 링크를 추가합니다. 이러한 통합에는 통합 훅이 없습니다.

| 통합                                              | 설명                                         |
|----------------------------------------------------------|-----------------------------------------------------|
| [Confluence Workspace](confluence.md)                    | Confluence Cloud Workspace를 내부 위키로 사용합니다. |
| [외부 위키](../wiki/_index.md#link-an-external-wiki) | 외부 위키를 연결합니다.                              |

### 기타 {#other}

| 통합                                                  | 설명                                                                              | 통합 훅 |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------- | ----------------- |
| [Asana](asana.md)                                            | 커밋 메시지를 Asana 작업에 댓글로 추가합니다.                                          | {{< no >}} |
| Assembla                                                     | Assembla로 프로젝트를 관리합니다.                                                           | {{< no >}} |
| [Beyond Identity](beyond_identity.md)                        | GPG 키가 Beyond Identity Authenticator로 승인되었는지 확인합니다.                    | {{< no >}} |
| [Datadog](../../../integration/datadog.md)                   | Datadog으로 GitLab 파이프라인을 추적합니다.                                                | {{< yes >}} |
| [Diffblue Cover](../../../integration/diffblue_cover.md)     | 자동으로 포괄적이고 사람 같은 Java 단위 테스트를 작성합니다.                           | {{< yes >}} |
| [푸시 시 이메일](emails_on_push.md)                          | 푸시 시 커밋 및 diff를 이메일로 보냅니다.                                                 | {{< no >}} |
| [GitGuardian](git_guardian.md)                               | GitGuardian 정책을 기반으로 커밋을 거부합니다.                                            | {{< no >}} |
| [GitHub](github.md)                                          | 커밋 및 풀 요청의 상태를 수신합니다.                                          | {{< no >}} |
| [GitLab for Slack 앱](gitlab_slack_application.md)          | 네이티브 Slack 앱을 사용하여 알림을 수신하고 명령을 실행합니다.                      | {{< no >}} |
| [Google Artifact Management](google_artifact_management.md)  | Google Artifact Registry에서 아티팩트를 관리합니다.                                       | {{< no >}} |
| [Google Cloud IAM](../../../integration/google_cloud_iam.md) | Identity and Access Management (IAM)로 Google Cloud 리소스에 대한 권한을 관리합니다. | {{< no >}} |
| [Jira](../../../integration/jira/_index.md)                  | Jira를 이슈 추적기로 사용합니다.                                                            | {{< no >}} |
| [Mattermost 슬래시 명령](mattermost_slash_commands.md)    | Mattermost 채팅 환경에서 슬래시 명령을 실행합니다.                                   | {{< no >}} |
| [파이프라인 상태 이메일](pipeline_status_emails.md)          | 파이프라인 상태를 받는 사람 목록에 이메일로 보냅니다.                               | {{< no >}} |
| [Pivotal Tracker](pivotal_tracker.md)                        | 커밋 메시지를 Pivotal Tracker 스토리에 댓글로 추가합니다.                              | {{< no >}} |
| [Squash TM](squash_tm.md)                                    | GitLab 이슈가 수정될 때 Squash TM 요구사항을 업데이트합니다.                           | {{< yes >}} |

## 프로젝트 웹후크 {#project-webhooks}

일부 통합은 외부 애플리케이션에 [웹후크](webhooks.md)를 사용합니다.

프로젝트 웹후크를 구성하여 푸시, 이슈 또는 병합 요청과 같은 특정 이벤트를 수신 대기할 수 있습니다. 웹후크가 트리거되면 GitLab은 지정된 웹후크 URL로 데이터와 함께 POST 요청을 보냅니다.

웹후크를 사용하는 통합 목록은 [사용 가능한 통합](#available-integrations)을 참조하세요.

## 푸시 훅 제한 {#push-hook-limit}

단일 푸시에 3개를 초과하는 브랜치 또는 태그에 대한 변경사항이 포함된 경우 `push_hooks` 및 `tag_push_hooks` 이벤트로 지원되는 통합은 실행되지 않습니다.

지원되는 브랜치 또는 태그의 수를 변경하려면 [`push_event_hooks_limit` 설정](../../../api/settings.md#available-settings)을 구성합니다.

## SSL 검증 {#ssl-verification}

기본적으로 나가는 HTTP 요청의 SSL 인증서는 내부 인증 기관 목록을 기반으로 검증됩니다. SSL 인증서는 자체 서명될 수 없습니다.

[웹후크](webhooks.md#configure-webhooks)를 구성할 때 SSL 검증을 비활성화할 수 있으며 일부 통합도 가능합니다.

## 관련 항목 {#related-topics}

- [통합 API](../../../api/project_integrations.md)
- [GitLab Developer Portal](https://developer.gitlab.com)
