---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Google Chat
description: "Google Chat 통합을 구성하여 Google Chat 공간에서 GitLab의 알림을 받습니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab에서 프로젝트를 구성하여 [Google Chat](https://chat.google.com/)의 원하는 공간으로 알림을 보낼 수 있습니다.

스레드 알림은 기본적으로 Google Chat에서 같은 GitLab 객체(예: 이슈 또는 머지 리퀘스트)에 대해 켜져 있습니다. 자세한 내용은 [이슈 438452](https://gitlab.com/gitlab-org/gitlab/-/issues/438452)를 참고하세요.

## 통합 구성 {#configure-the-integration}

### Google Chat에서 {#in-google-chat}

Google Chat에서 통합을 구성하려면:

1. GitLab에서 알림을 받을 공간으로 이동합니다.
1. 왼쪽 위에서 공간 이름 옆에 있는 아래쪽 화살표({{< icon name="chevron-down" >}}) > **앱 및 통합**을 선택합니다.
1. **Webhooks** 섹션에서 **Add webhooks**를 선택합니다.
1. **Incoming webhooks** 대화 상자에서:
   - **이름**에 웹후크의 이름을 입력합니다(예: `GitLab integration`).
   - 선택 사항. **Avatar URL**에 봇의 아바타를 입력합니다.
1. **저장**을 선택합니다.
1. 웹후크 URL 옆에서 세로 줄임표({{< icon name="ellipsis_v" >}}) > **링크 복사**를 선택합니다.

웹후크에 대한 자세한 내용은 [Google Chat 문서](https://developers.google.com/workspace/chat/quickstart/webhooks)를 참고하세요.

### GitLab에서 {#in-gitlab}

GitLab에서 통합을 구성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Google Chat**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. **Webhook**에 [Google Chat에서 복사한 URL을 붙여넣습니다](#in-google-chat).
1. **트리거** 섹션에서 Google Chat 공간에서 알림을 받을 각 GitLab 이벤트의 확인란을 선택합니다.
1. 선택 사항. **알림 설정** 섹션에서:
   - **잘못된 파이프라인만 알림 받기** 확인란을 선택하여 실패한 파이프라인에 대한 알림만 받습니다.
   - **상태 변경 시에만 알림 받기** 확인란을 선택하여 ref의 파이프라인 상태가 변경될 때만 알림을 받습니다.
   - **알림을 보내야 할 브랜치** 드롭다운 목록에서 알림을 받을 브랜치를 선택합니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.
