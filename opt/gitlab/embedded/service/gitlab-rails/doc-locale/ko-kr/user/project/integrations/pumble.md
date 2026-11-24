---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Pumble
description: "GitLab을 구성하여 Pumble 채널에 알림을 전송합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab을 구성하여 Pumble 채널에 알림을 전송할 수 있습니다:

1. 채널에 대한 웹후크를 생성합니다.
1. 웹후크를 GitLab에 추가합니다.

## Pumble 채널의 웹후크 생성 {#create-a-webhook-for-your-pumble-channel}

1. Pumble 설명서의 [Pumble의 수신 웹후크](https://pumble.com/help/integrations/add-pumble-apps/incoming-webhooks-for-pumble/) 단계를 따릅니다.
1. 웹후크 URL을 복사합니다.

## GitLab에서 설정 구성 {#configure-settings-in-gitlab}

사전 요구 사항:

- 인스턴스의 통합을 활성화하기 위한 관리자 액세스 권한
- 그룹의 통합을 활성화하기 위한 소유자 역할
- 프로젝트의 통합을 활성화하기 위한 유지 관리자 또는 소유자 역할

Pumble 채널의 웹후크 URL이 있으면 GitLab을 설정하여 알림을 보냅니다:

1. 그룹 또는 프로젝트에서 통합을 활성화하려면:
   1. 그룹 또는 프로젝트의 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. 인스턴스의 통합을 활성화하려면:
   1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
   1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Pumble** 통합을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. Pumble에서 받으려는 GitLab 이벤트에 해당하는 확인란을 선택합니다.
1. Pumble 채널의 **Webhook** URL을 붙여넣습니다.
1. 나머지 옵션을 구성합니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

Pumble 채널이 해당하는 모든 GitLab 이벤트를 수신하기 시작합니다.
