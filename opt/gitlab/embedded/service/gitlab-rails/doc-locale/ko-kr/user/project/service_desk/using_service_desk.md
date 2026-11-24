---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 서비스 데스크 사용
description: 이메일 또는 GitLab UI에서 서비스 데스크 티켓을 생성하고 티켓 추적기에서 티켓에 응답합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

서비스 데스크를 사용하여 [티켓을 생성](#as-an-end-user-ticket-creator)하거나 [응답](#as-a-responder-to-the-ticket)할 수 있습니다. 이러한 티켓에서 [Support Bot](configure.md#support-bot-user)을 볼 수 있습니다.

## 서비스 데스크 이메일 주소 보기 {#view-service-desk-email-address}

프로젝트의 서비스 데스크 이메일 주소를 확인하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **모니터링** > **서비스 데스크**를 선택합니다.

이메일 주소는 티켓 목록의 상단에 표시됩니다.

## 최종 사용자(티켓 작성자) {#as-an-end-user-ticket-creator}

서비스 데스크 티켓을 생성하려면 최종 사용자는 GitLab 인스턴스에 대해 아무것도 알 필요가 없습니다. 주어진 주소로 이메일을 보내고 GitLab Support Bot으로부터 수신 확인 이메일을 받습니다:

```plaintext
Thank you for your support request! We are tracking your request as ticket `#%{issue_iid}`, and will respond as soon as we can.
```

이 이메일은 최종 사용자에게 구독 취소 옵션도 제공합니다.

구독을 취소하지 않으면 티켓에 추가된 새 댓글이 이메일로 전송됩니다.

이메일로 보낸 모든 응답은 티켓 자체에 표시됩니다.

자세한 내용은 [외부 참여자](external_participants.md) 및 [이메일 처리에 사용되는 헤더](../../../administration/incoming_email.md#accepted-headers)를 참조하세요.

### GitLab UI에서 서비스 데스크 티켓 생성 {#create-a-service-desk-ticket-in-gitlab-ui}

사전 요구 사항:

- 서비스 데스크는 [프로젝트에 설정](configure.md)되어야 합니다. GitLab Self-Managed에서는 이메일 서브 주소 지정 또는 catch-all 메일함으로 구성된 [수신 이메일](../../../administration/incoming_email.md#set-it-up)이 포함됩니다. 수신 이메일이 없으면 `/convert_to_ticket` 빠른 작업을 사용할 수 없습니다.

UI에서 서비스 데스크 티켓을 생성하려면:

1. [이슈 생성](../issues/create_issues.md)합니다.
1. `/convert_to_ticket user@example.com`만 포함하는 댓글을 추가합니다. [GitLab Support Bot](configure.md#support-bot-user)의 댓글이 표시되어야 합니다.
1. 페이지를 다시 로드하여 UI에 유형 변경이 반영되도록 합니다.
1. 선택 사항. 티켓에 댓글을 추가하여 외부 참여자에게 초기 서비스 데스크 이메일을 보냅니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 개요를 보려면 [UI 및 API에서 서비스 데스크 티켓 생성](https://www.youtube.com/watch?v=ibUGNc2wifQ)을 참조하세요.
<!-- Video published on 2024-03-05 -->

## 티켓에 대한 응답자 {#as-a-responder-to-the-ticket}

티켓에 응답하는 사람의 경우 모든 것이 GitLab 이슈와 마찬가지로 작동합니다. GitLab은 응답자가 고객 지원 요청을 통해 생성된 티켓을 볼 수 있고 필터링하거나 상호 작용할 수 있는 친숙한 티켓 추적기를 표시합니다.

![서비스 데스크 티켓 추적기.](img/service_desk_issue_tracker_v16_10.png)

최종 사용자의 메시지는 특수 [Support Bot 사용자](../../../subscriptions/manage_seats.md#criteria-for-non-billable-users)로부터 오는 것으로 표시됩니다. GitLab에서 일반적으로 하는 것처럼 댓글을 읽고 쓸 수 있습니다:

- 프로젝트의 가시성(비공개, 내부, 공개)은 서비스 데스크에 영향을 주지 않습니다.
- 그룹 또는 네임스페이스를 포함한 프로젝트의 경로가 이메일에 표시됩니다.

### 서비스 데스크 티켓 보기 {#view-service-desk-tickets}

사전 요구 사항:

- 프로젝트의 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

서비스 데스크 티켓을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **모니터링** > **서비스 데스크**를 선택합니다.

#### 재설계된 티켓 목록 {#redesigned-ticket-list}

서비스 데스크 티켓 목록이 일반 이슈 목록과 더 유사합니다. 사용 가능한 기능은 다음을 포함합니다:

- [이슈 목록](../issues/sorting_issue_lists.md)과 동일한 정렬 및 순서 옵션
- [OR 연산자](#filter-the-list-of-tickets) 및 [티켓 ID로 필터링](#filter-tickets-by-id)을 포함한 동일한 필터입니다.

서비스 데스크 티켓 목록에서 새 티켓을 생성하는 옵션이 더 이상 없습니다. 이 결정은 새 티켓이 전용 이메일 주소로 이메일을 보내서 생성되는 서비스 데스크의 특성을 더 잘 반영합니다.

##### 티켓 목록 필터링 {#filter-the-list-of-tickets}

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **모니터링** > **서비스 데스크**를 선택합니다.
1. 티켓 목록 위에서 **검색 또는 결과 필터**를 선택합니다.
1. 나타나는 드롭다운 목록에서 필터링할 특성을 선택합니다.
1. 특성을 필터링할 연산자를 선택하거나 입력합니다. 다음 연산자를 사용할 수 있습니다:
   - `=`: 다음과 같음
   - `!=`: 다음 중 하나가 아님
1. 특성을 필터링할 텍스트를 입력합니다. 일부 특성을 **없음** 또는 **Any**으로 필터링할 수 있습니다.
1. 이 프로세스를 반복하여 여러 특성으로 필터링합니다. 여러 특성이 논리적 `AND`으로 결합됩니다.

##### OR 연산자를 사용하여 필터링 {#filter-with-the-or-operator}

[OR 연산자로 필터링](../issues/managing_issues.md#filter-the-list-of-issues)이 켜져 있으면 **하나 해당: `||`**를 사용할 수 있으며 [티켓 목록을 필터링](#filter-the-list-of-tickets)할 때:

- 담당자
- 레이블

`is one of`는 포함 OR을 나타냅니다. 예를 들어 `Assignee is one of Sidney Jones` 및 `Assignee is one of Zhang Wei`로 필터링하면 GitLab에서 `Sidney`, `Zhang` 또는 둘 다 할당자인 티켓을 표시합니다.

##### ID별 티켓 필터링 {#filter-tickets-by-id}

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **모니터링** > **서비스 데스크**를 선택합니다.
1. **검색** 텍스트 상자에 티켓 ID를 입력합니다. 예를 들어 `#10`를 입력하여 티켓 10만 반환합니다.

## 이메일 내용 및 형식 {#email-contents-and-formatting}

### HTML 이메일의 특수 HTML 형식 {#special-html-formatting-in-html-emails}

서비스 데스크 티켓에서 보낸 HTML 이메일은 다음과 같은 HTML 형식을 표시합니다:

- 표
- 인용문
- 이미지
- 축소 가능한 섹션

### 댓글에 첨부된 파일 {#files-attached-to-comments}

댓글에 첨부 파일이 포함되어 있고 총 크기가 10MB 이하인 경우 이러한 첨부 파일이 이메일의 일부로 전송됩니다. 다른 경우에는 이메일에 첨부 파일에 대한 링크가 포함됩니다.

## 일반 이슈를 서비스 데스크 티켓으로 변환 {#convert-a-regular-issue-to-a-service-desk-ticket}

사전 요구 사항:

- 서비스 데스크는 [프로젝트에 설정](configure.md)되어야 합니다.

`/convert_to_ticket external-ticket-author@example.com` 빠른 작업을 사용하여 일반 이슈를 서비스 데스크 티켓으로 변환합니다. 이는 제공된 이메일 주소를 티켓의 외부 작성자로 할당하고 외부 참여자 목록에 추가합니다. 그들은 티켓의 공개 댓글에 대한 서비스 데스크 이메일을 받고 이러한 이메일에 회신할 수 있습니다. 회신은 티켓에 새 댓글을 추가합니다.

GitLab은 기본 [`thank_you` 이메일](configure.md#customize-emails-sent-to-external-participants)을 보내지 않습니다. 티켓에 공개 댓글을 추가하여 최종 사용자에게 티켓이 생성되었음을 알릴 수 있습니다.

## 개인정보 보호 고려 사항 {#privacy-considerations}

서비스 데스크 티켓은 [기밀](../issues/confidential_issues.md)이므로 프로젝트 멤버에게만 표시됩니다. 프로젝트 소유자는 [티켓을 공개할](../issues/confidential_issues.md#in-an-existing-issue) 수 있습니다. 서비스 데스크 티켓이 공개되면 티켓 작성자 및 참여자의 이메일 주소가 프로젝트에 대해 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있는 로그인한 사용자에게 표시됩니다.

프로젝트의 모든 사용자는 프로젝트의 역할에 관계없이 서비스 데스크 이메일 주소를 사용하여 이 프로젝트에 티켓을 생성할 수 있습니다.

고유한 내부 이메일 주소는 GitLab 인스턴스에서 최소한 계획자 역할이 있는 프로젝트 멤버에게 표시됩니다. 외부 사용자(티켓 작성자)는 정보 메모에 표시된 내부 이메일 주소를 볼 수 없습니다.

### 서비스 데스크 티켓 이동 {#moving-a-service-desk-ticket}

GitLab에서 [일반 이슈를 이동](../issues/managing_issues.md#move-an-issue)하는 것과 동일한 방식으로 서비스 데스크 티켓을 이동할 수 있습니다.

서비스 데스크 티켓이 서비스 데스크가 켜진 다른 프로젝트로 이동되면 티켓을 생성한 고객은 계속 이메일 알림을 받습니다. 이동된 티켓이 먼저 닫혀 있고 복사되기 때문에 고객은 두 티켓 모두의 참여자로 간주됩니다. 그들은 계속해서 이전 티켓과 새 티켓의 모든 알림을 받습니다.
