---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Mattermost 슬래시 명령
description: "Mattermost 슬래시 명령을 구성하여 Mattermost 채팅 환경에서 일반적인 GitLab 작업을 실행합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[슬래시 명령](gitlab_slack_application.md#slash-commands)을 사용하여 [Mattermost](https://mattermost.com/) 채팅 환경에서 이슈 생성과 같은 일반적인 GitLab 작업을 실행할 수 있습니다.

GitLab은 별도로 구성된 [Mattermost 알림](mattermost.md)의 일부로 `issue created` 같은 이벤트를 Mattermost로 전송할 수도 있습니다.

사용 가능한 슬래시 명령 목록은 [슬래시 명령](gitlab_slack_application.md#slash-commands)을 참조하세요.

## 슬래시 명령 구성 {#configure-slash-commands}

Mattermost에서 슬래시 명령을 구성하려면 다음 단계를 수행해야 합니다.

### Mattermost에서 사용자 지정 슬래시 명령 활성화 {#enable-custom-slash-commands-in-mattermost}

Mattermost 관리자 콘솔에서 사용자 지정 슬래시 명령을 켜려면:

1. 관리자 권한이 있는 사용자로 Mattermost에 로그인합니다.
1. 왼쪽 위 모서리에서 Mattermost 로고를 선택하고 **System Console**을 선택합니다.
1. **Integration Management**을 선택하고 이 값들을 `True`으로 설정합니다:
   - **Enable Custom Slash Commands**
   - **Enable integrations to override usernames**
   - **Enable integrations to override profile picture icons**
1. **저장**을 선택하되 이 브라우저 탭을 닫지 마세요. 나중에 필요합니다.

### GitLab에서 구성 값 가져오기 {#get-configuration-values-from-gitlab}

GitLab에서 구성 값을 가져오려면:

1. 다른 브라우저 탭에서 관리자 액세스 권한이 있는 사용자로 GitLab에 로그인합니다.
1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Mattermost 슬래시 명령**을 선택합니다. GitLab은 Mattermost 설정에 대한 가능한 값을 표시합니다.
1. **요청 URL** 값을 복사합니다. 다른 모든 값은 제안입니다.
1. 이 브라우저 탭을 닫지 마세요. 나중에 필요합니다.

### Mattermost에서 슬래시 명령 생성 {#create-a-slash-command-in-mattermost}

Mattermost에서 슬래시 명령을 생성하려면:

1. [Mattermost 브라우저 탭에서](#enable-custom-slash-commands-in-mattermost) 팀 페이지로 이동합니다.
1. 왼쪽 위 모서리에서 Mattermost 로고를 선택하고 **연동**을 선택합니다.
1. 왼쪽 사이드바에서 **슬래시 명령**을 선택합니다.
1. **슬래시 명령 추가**를 선택합니다.
1. 새 명령에 대해 **표시 이름**과 **설명**을 입력합니다.
1. 애플리케이션의 구성을 기반으로 **명령 트리거 단어**를 입력합니다:

   - Mattermost 팀에 하나의 프로젝트만 연결하려는 경우 트리거 단어로 `/gitlab`을 사용합니다.
   - 여러 프로젝트를 연결하려는 경우 프로젝트와 관련된 트리거 단어(예: `/project-name` 또는 `/gitlab-project-name`)를 사용합니다.
1. **요청 URL**의 경우 [GitLab에서 복사한 값을 붙여넣습니다](#get-configuration-values-from-gitlab).
1. 다른 모든 값의 경우 GitLab의 제안이나 원하는 값을 사용할 수 있습니다.
1. **토큰** 값을 복사하고 **완료**를 선택합니다.

### Mattermost 토큰을 GitLab에 제공 {#provide-the-mattermost-token-to-gitlab}

Mattermost에서 슬래시 명령을 생성하면 GitLab에 제공해야 하는 토큰이 생성됩니다:

1. [GitLab 브라우저 탭에서](#get-configuration-values-from-gitlab) **활성** 확인란을 선택합니다.
1. **토큰** 텍스트 상자에 [Mattermost에서 복사한 토큰을 붙여넣습니다](#create-a-slash-command-in-mattermost).
1. **변경 사항 저장**을 선택합니다.

이제 슬래시 명령이 GitLab 프로젝트와 통신할 수 있습니다.

## GitLab 계정을 Mattermost에 연결 {#connect-your-gitlab-account-to-mattermost}

사전 요구 사항:

- [슬래시 명령](gitlab_slack_application.md#slash-commands)을 실행하려면 GitLab 프로젝트에서 작업을 수행할 [권한](../../permissions.md#project-permissions)이 있어야 합니다.

Mattermost 슬래시 명령을 사용하여 GitLab과 상호 작용하려면:

1. Mattermost 채팅 환경에서 새 슬래시 명령을 실행합니다.
1. **GitLab 계정 연결**을 선택하여 액세스를 승인합니다.

Mattermost 프로필 페이지의 **채팅** 아래에서 모든 승인된 채팅 계정을 볼 수 있습니다.

## 관련 항목 {#related-topics}

- [Mattermost의 슬래시 명령](https://developers.mattermost.com/integrate/slash-commands/)

## 문제 해결 {#troubleshooting}

Mattermost 슬래시 명령이 GitLab에서 이벤트를 트리거하지 않을 때:

- 공개 채널을 사용하고 있는지 확인합니다. Mattermost 웹후크는 비공개 채널에 액세스할 수 없습니다.
- 비공개 채널이 필요한 경우 웹후크 채널을 편집하고 비공개 채널을 선택합니다. 모든 이벤트가 지정된 채널로 전송됩니다.
