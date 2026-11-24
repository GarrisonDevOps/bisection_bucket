---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Webex Teams
description: "웹후크를 사용하여 GitLab에서 Webex Teams 공간으로 이벤트 알림을 보냅니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab을 구성하여 Webex Teams 공간으로 알림을 보낼 수 있습니다:

1. 공간에 대한 웹후크를 생성합니다.
1. GitLab에 웹후크를 추가합니다.

## 공간에 대한 웹후크 생성 {#create-a-webhook-for-the-space}

1. [수신 Webhooks 앱 페이지](https://apphub.webex.com/applications/incoming-webhooks-cisco-systems-38054-23307-75252)로 이동합니다.
1. **연결**을 선택하고 필요한 경우 Webex Teams에 로그인합니다.
1. 웹후크의 이름을 입력하고 알림을 받을 공간을 선택합니다.
1. **추가**를 선택합니다.
1. **Webhook URL**을 복사합니다.

## GitLab에서 설정 구성 {#configure-settings-in-gitlab}

사전 요구 사항:

- 인스턴스에 대한 통합을 활성화하려면 관리자 액세스 권한이 필요합니다.
- 그룹에 대한 통합을 활성화하려면 소유자 역할이 필요합니다.
- 프로젝트에 대한 통합을 활성화하려면 유지 관리자 또는 소유자 역할이 필요합니다.

Webex Teams 공간에 대한 웹후크 URL이 있으면 GitLab을 구성하여 알림을 보낼 수 있습니다:

1. 통합을 활성화하려면:
   - 그룹이나 프로젝트의 경우:
     1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
     1. **설정** > **연동**을 선택합니다.
   - 인스턴스의 경우:
     1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
     1. **설정** > **연동**을 선택합니다.
1. **Webex Teams** 통합을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. Webex Teams에서 받으려는 GitLab 이벤트에 해당하는 체크박스를 선택합니다.
1. Webex Teams 공간에 대한 **Webhook** URL을 붙여넣습니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

Webex Teams 공간이 모든 해당 GitLab 이벤트를 받기 시작합니다.
