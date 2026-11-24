---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Microsoft Teams 알림
description: "Microsoft Teams 통합을 구성하여 GitLab에서 Microsoft Teams로 알림을 받습니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Microsoft Teams 알림을 GitLab과 통합하고 Microsoft Teams에 GitLab 프로젝트에 대한 알림을 표시할 수 있습니다. 서비스를 통합하려면 다음을 수행해야 합니다:

1. [Microsoft Teams 구성](#configure-microsoft-teams)하여 변경 사항을 감시하는 웹후크를 추가합니다.
1. [GitLab 프로젝트 구성](#configure-your-gitlab-project)하여 알림을 Microsoft Teams 웹후크로 푸시합니다.

## Microsoft Teams 구성 {#configure-microsoft-teams}

> [!warning]
> Microsoft가 [Office 365 Connectors의 사용 중단을 공지](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/)했습니다. 새로운 통합은 Power Automate 워크플로를 사용해야 합니다. 기존 커넥터 기반 통합은 2025년 12월까지 전환되어야 합니다.

Microsoft Teams가 GitLab에서 알림을 받도록 구성하려면 GitLab 웹후크 페이로드를 받아들이고 메시지를 채널에 게시하는 워크플로가 필요합니다. 다음을 생성할 수 있습니다:

- 템플릿을 사용하는 Power Automate 워크플로
- 사용자 정의 워크플로

### Power Automate 워크플로 생성 {#create-a-power-automate-workflow}

1. Microsoft Teams에서 알림을 받을 채팅 옆에 **추가 채팅 옵션** ({{< icon name="ellipsis_h" >}})을 선택합니다.
1. **워크플로**를 선택합니다.
1. **채널로 웹후크 알림 보내기** 워크플로 템플릿을 검색하고 선택합니다.
1. **파라매터** 아래에서 팀 및 채널을 입력하고 **저장**을 선택합니다.
1. 워크플로가 생성된 후 워크플로 대화 상자에서 **웹후크 링크 복사**를 선택합니다.
1. 제공된 웹후크 URL을 복사합니다. 이 웹후크 URL을 사용하여 GitLab을 구성합니다.
1. 워크플로 대화 상자를 닫습니다.

#### GitLab 페이로드를 수락하도록 워크플로 수정 {#modify-the-workflow-to-accept-gitlab-payloads}

기본 워크플로 템플릿은 Adaptive Card 형식을 예상하지만 GitLab은 Office 365 Connector Card 형식을 보냅니다. 워크플로를 수정하려면:

1. Power Automate로 이동하고 Microsoft 계정으로 로그인합니다.
1. **내 플로우**를 선택하고 생성한 워크플로를 찾습니다.
1. **편집**을 선택하여 워크플로를 수정합니다.
1. 기존 **채팅 또는 채널에 카드 게시** 작업을 선택하고 삭제합니다.
1. **작업 추가**를 선택하고 **채팅 또는 채널에 메시지 게시**를 검색합니다.
1. 작업을 구성합니다:
   - **다음 사용자로 게시**: Flow 봇
   - **게시 위치**: 채널
   - **팀**: 팀을 선택합니다
   - **채널**: 채널을 선택합니다
   - **메시지**: 텍스트 상자의 오른쪽에서 **식 삽입**을 선택하고 `triggerOutputs()?['body']?['attachments'][0]?['content']`을 입력합니다. **추가**를 선택합니다.
1. **저장**을 선택합니다.

### 사용자 정의 워크플로 생성 {#create-a-custom-workflow}

메시지 형식을 더 잘 제어하려면 사용자 정의 워크플로를 생성합니다:

1. Power Automate로 이동하고 **생성** > **즉시 클라우드 플로우**를 선택합니다.
1. 워크플로의 이름을 지정하고 **HTTP 요청이 수신될 때**를 트리거로 선택한 다음 **생성**를 선택합니다.
1. **작업 추가**를 선택하고 **채팅 또는 채널에 메시지 게시** (Microsoft Teams)를 검색합니다.
1. 트리거 구성에서 JSON 스키마를 비워둔 채로 두어 모든 페이로드를 받습니다.
1. 작업을 구성합니다:
   - **다음 사용자로 게시**: Flow 봇
   - **게시 위치**: 채널
   - **팀**: 팀을 선택합니다
   - **채널**: 채널을 선택합니다
   - **메시지**: 텍스트 상자의 오른쪽에서 **식 삽입**을 선택하고 `triggerOutputs()?['body']?['attachments'][0]?['content']`을 입력합니다. **추가**를 선택합니다.
1. **저장**을 선택합니다.
1. 워크플로에서 **수동** 트리거를 선택합니다. 트리거에서 **HTTP URL**을 복사합니다. 이 URL을 사용하여 GitLab을 구성합니다.

## GitLab 프로젝트 구성 {#configure-your-gitlab-project}

Microsoft Teams가 알림을 받도록 구성한 후 GitLab을 구성하여 알림을 보내야 합니다:

1. 관리자로 GitLab에 로그인합니다.
1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Microsoft Teams 알림**을 선택합니다.
1. 통합을 켜려면 **활성**을 선택합니다.
1. **트리거** 섹션에서 원하는 각 이벤트 옆의 확인란을 선택합니다:
   - 푸시
   - 이슈
   - 기밀 이슈
   - 병합 요청
   - 참고
   - 기밀 참고
   - 태그 푸시
   - 파이프라인
   - 위키 페이지
1. **Webhook**에 Power Automate 또는 사용자 정의 워크플로를 생성할 때 복사한 URL을 붙여넣습니다.
1. 선택 사항. 파이프라인 트리거를 선택하면 **잘못된 파이프라인만 알림 받기** 확인란을 선택하여 파이프라인이 실패할 때만 알림을 푸시합니다.
1. 선택 사항. 파이프라인 트리거를 선택하면 **상태 변경 시에만 알림 받기** 확인란을 선택하여 ref의 파이프라인 상태가 변경될 때만 알림을 보냅니다.
1. 알림을 보낼 분기를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 관련 항목 {#related-topics}

- [Microsoft Power Automate 설명서](https://learn.microsoft.com/en-us/power-automate/)
- [Microsoft Teams 수신 웹후크 생성 설명서](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
