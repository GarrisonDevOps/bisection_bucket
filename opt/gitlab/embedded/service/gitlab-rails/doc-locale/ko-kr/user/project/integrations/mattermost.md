---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Mattermost 알림
description: "Mattermost 알림을 구성하여 GitLab에서 Mattermost 채널로 알림을 받습니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Mattermost 알림 연동을 사용하여 GitLab 이벤트(예: `issue created`)에 대한 알림을 Mattermost로 보냅니다. [Mattermost](#configure-mattermost-to-receive-gitlab-notifications) 및 [GitLab](#configure-gitlab-to-send-notifications-to-mattermost)을 모두 구성해야 합니다.

[Mattermost 슬래시 명령어](mattermost_slash_commands.md)를 사용하여 Mattermost 내에서 GitLab을 제어할 수 있습니다.

## Mattermost를 구성하여 GitLab 알림 수신 {#configure-mattermost-to-receive-gitlab-notifications}

Mattermost 연동을 사용하려면 Mattermost에서 수신 웹후크 연동을 생성해야 합니다:

1. Mattermost 인스턴스에 로그인합니다.
1. [수신 웹후크 활성화](https://docs.mattermost.com/configure/integrations-configuration-settings.html#enable-incoming-webhooks)합니다.
1. [수신 웹후크 추가](https://developers.mattermost.com/integrate/webhooks/incoming/#create-an-incoming-webhook)합니다.
1. 표시 이름, 설명 및 채널을 선택합니다. 이를 GitLab에서 재정의할 수 있습니다.
1. 저장하고 GitLab에 필요한 **Webhook URL**을 복사합니다.

수신 웹후크가 Mattermost 인스턴스에서 차단될 수 있습니다. Mattermost 관리자에게 다음 위치에서 이를 활성화해달라고 요청합니다:

- **Mattermost 시스템 콘솔** > **연동** > **연동 관리**(Mattermost 5.12 이상 버전)
- **Mattermost 시스템 콘솔** > **연동** > **사용자 정의 연동**(Mattermost 5.11 이하 버전)

표시 이름 재정의는 기본적으로 해제되어 있습니다. 관리자에게 해당 섹션에서 이를 활성화해달라고 요청합니다.

## GitLab을 구성하여 Mattermost로 알림 전송 {#configure-gitlab-to-send-notifications-to-mattermost}

Mattermost 인스턴스에 수신 웹후크가 설정되면 GitLab을 구성하여 알림을 보낼 수 있습니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Mattermost 알림**을 선택합니다.
1. 알림을 생성할 GitLab 이벤트를 선택합니다. 선택한 각 이벤트에 대해 알림을 받을 최대 10개의 Mattermost 채널을 입력합니다. 해시 기호(`#`)를 추가할 필요가 없습니다.
1. 연동 구성을 입력합니다:

   - **Webhook**: Mattermost의 수신 웹후크 URL(예: `http://mattermost.example/hooks/5xo…`)입니다.
   - **사용자명**: 선택 사항. Mattermost로 전송된 메시지에 표시되는 사용자명입니다. 봇의 사용자명을 변경하려면 값을 제공합니다.
   - **잘못된 파이프라인만 알림 받기**: **파이프라인** 이벤트를 선택하고 실패한 파이프라인에 대한 알림만 원하는 경우입니다.
   - **상태 변경 시에만 알림 받기**: **파이프라인** 이벤트를 선택하고 파이프라인 상태가 ref에 대해 변경될 때만 알림을 원하는 경우입니다.
   - **알림을 보내야 할 브랜치**: 알림을 보낼 브랜치입니다.
   - **알림을 받을 레이블**: 선택 사항. 알림을 트리거하기 위해 이슈 또는 병합 요청에 필요한 레이블입니다. 모든 이슈 및 병합 요청에 대해 알림을 받으려면 빈 칸으로 둡니다.
   - **알림을 받을 레이블 동작**: **알림을 받을 레이블** 필터를 사용할 때 필터에 지정된 레이블 중 하나를 포함하는 이슈 또는 병합 요청에 메시지가 전송됩니다. 필터에 정의된 모든 레이블을 포함하는 경우에만 이슈 또는 병합 요청에 메시지를 트리거하도록 선택할 수도 있습니다.
