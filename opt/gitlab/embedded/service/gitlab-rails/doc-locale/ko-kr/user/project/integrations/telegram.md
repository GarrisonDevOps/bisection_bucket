---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 텔레그램
description: "Telegram 통합을 구성하여 GitLab에서 Telegram 채팅이나 채널로 알림을 받습니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab을 구성하여 Telegram 채팅이나 채널로 알림을 보낼 수 있습니다. Telegram 통합을 설정하려면 다음을 수행해야 합니다:

1. [Telegram 봇 만들기](#create-a-telegram-bot).
1. [Telegram 봇 구성](#configure-the-telegram-bot).
1. [GitLab에서 Telegram 통합 설정](#set-up-the-telegram-integration-in-gitlab).

## Telegram 봇 만들기 {#create-a-telegram-bot}

Telegram에서 봇을 만들려면:

1. `@BotFather`과 새 채팅을 시작합니다.
1. [새 봇 만들기](https://core.telegram.org/bots/features#creating-a-new-bot) \- Telegram 문서에 설명된 대로 진행합니다.

봇을 만들 때 `BotFather`에서 API 토큰을 제공합니다. Telegram에서 봇을 인증할 때 필요하므로 이 토큰을 안전하게 보관합니다.

## Telegram 봇 구성 {#configure-the-telegram-bot}

Telegram에서 봇을 구성하려면:

1. 봇을 새로운 채널이나 기존 채널에 관리자로 추가합니다.
1. 봇에 `Post Messages` 권한을 할당하여 이벤트를 받습니다.
1. 채널에 대한 식별자를 만듭니다.
   - 공개 채널의 경우 공개 링크를 입력하고 채널 식별자를 복사합니다(예: `https://t.me/MY_IDENTIFIER`).
   - 비공개 채널의 경우 API 토큰으로 [`getUpdates`](https://telegram-bot-sdk.readme.io/reference/getupdates) 메서드를 사용하고 채널 식별자를 복사합니다(예: `-2241293890657`).

## GitLab에서 Telegram 통합 설정 {#set-up-the-telegram-integration-in-gitlab}

{{< history >}}

- **호스트 이름** [GitLab 17.1에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/461313).

{{< /history >}}

사전 요구 사항:

- 인스턴스에 대한 통합을 활성화하려면 관리자 액세스 권한이 필요합니다.
- 그룹에 대한 통합을 활성화하려면 소유자 역할이 필요합니다.
- 프로젝트에 대한 통합을 활성화하려면 유지 관리자 또는 소유자 역할이 필요합니다.

봇을 Telegram 채널에 초대한 후 GitLab을 구성하여 알림을 보낼 수 있습니다:

1. 통합을 활성화하려면:
   - 그룹이나 프로젝트의 경우:
     1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
     1. **설정** > **연동**을 선택합니다.
   - 인스턴스의 경우:
     1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
     1. **설정** > **연동**을 선택합니다.
1. **텔레그램**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 선택 사항. **호스트 이름**에 [로컬 봇 API 서버](https://core.telegram.org/bots/api#using-a-local-bot-api-server)의 호스트 이름을 입력합니다.
1. **토큰**에 [Telegram 봇의 토큰 값을 붙여넣습니다](#create-a-telegram-bot).
1. **트리거** 섹션에서 Telegram에서 받을 GitLab 이벤트의 확인란을 선택합니다.
1. **알림 설정** 섹션에서:
   - **채널 식별자**에 [Telegram 채널 식별자를 붙여넣습니다](#configure-the-telegram-bot).
   - 선택 사항. **메시지 스레드 ID**에 대상 메시지 스레드(포럼 슈퍼그룹의 주제)에 대한 고유 식별자를 붙여넣습니다.
   - 선택 사항. **잘못된 파이프라인만 알림 받기** 확인란을 선택하여 실패한 파이프라인만 알림을 받습니다.
   - 선택 사항. **Notify only when status changes** 확인란을 선택하여 파이프라인 상태가 변경될 때만 알림을 받습니다.
   - 선택 사항. **알림을 보내야 할 브랜치** 드롭다운 목록에서 알림을 받을 브랜치를 선택합니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

Telegram 채널은 이제 선택한 모든 GitLab 이벤트를 받을 수 있습니다.
