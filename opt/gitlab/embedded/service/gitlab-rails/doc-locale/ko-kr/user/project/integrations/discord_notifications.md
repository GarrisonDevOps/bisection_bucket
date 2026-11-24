---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Discord 알림
description: "Discord 알림 연동을 구성하여 Discord 채널에서 GitLab의 알림을 받습니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Discord 알림 연동은 GitLab의 이벤트 알림을 웹후크가 생성된 채널로 전송합니다.

GitLab 이벤트 알림을 Discord 채널로 전송하려면 [Discord에서 웹후크 생성](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks)을 한 후 GitLab에서 구성합니다.

## 웹후크 생성 {#create-webhook}

1. GitLab 이벤트 알림을 받을 Discord 채널을 엽니다.
1. 채널 메뉴에서 **채널 편집**을 선택합니다.
1. **연동**을 선택합니다.
1. 기존 웹후크가 없으면 **웹후크 생성**을 선택합니다. 그렇지 않으면 **웹후크 보기**를 선택한 후 **새 웹후크**를 선택합니다.
1. 메시지를 게시할 봇의 이름을 입력합니다.
1. 선택 사항. 아바타를 편집합니다.
1. **WEBHOOK URL** 텍스트 상자에서 URL을 복사합니다.
1. **저장**을 선택합니다.

## GitLab에서 생성된 웹후크 구성 {#configure-created-webhook-in-gitlab}

{{< history >}}

- 웹후크 URL 유효성 검사는 GitLab 18.0에서 도입되었습니다.

{{< /history >}}

사전 요구 사항:

- Discord URL(`https://discord.com/api/webhooks/webhook-snowflake/webhook-token`)을 사용해야 합니다.

Discord 채널에서 생성된 웹후크 URL을 사용하면 GitLab에서 Discord 알림 연동을 설정할 수 있습니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Discord 알림**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. **Webhook** 텍스트 상자에 [이전에 생성한](#create-webhook) 웹후크 URL을 붙여넣습니다.
1. Discord로 알림을 보낼 GitLab 이벤트에 해당하는 체크박스를 선택합니다.
1. 선택 사항. 선택한 각 체크박스에 대해 [구성한](#create-webhook) 다른 Discord 웹후크 URL을 입력하여 **Webhook** 텍스트 상자의 URL을 재정의합니다.
1. 나머지 옵션을 구성하고 **변경사항 저장**을 선택합니다.

웹후크를 생성한 Discord 채널은 이제 구성된 GitLab 이벤트의 알림을 받습니다.
