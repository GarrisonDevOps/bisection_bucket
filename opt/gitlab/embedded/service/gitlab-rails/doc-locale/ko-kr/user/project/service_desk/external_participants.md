---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 외부 참여자
description: 이슈 또는 서비스 데스크 티켓과 상호작용하는 외부 참여자를 추가하고 이메일 회신 및 구독 취소 방법을 관리합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- GitLab 17.0에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/3758)되었습니다.

{{< /history >}}

외부 참여자는 GitLab 계정이 없지만 이슈 또는 서비스 데스크 티켓과 이메일을 통해서만 상호작용할 수 있는 사용자입니다. 이슈 또는 티켓의 공개 댓글에 대한 알림을 [서비스 데스크 이메일](configure.md#customize-emails-sent-to-external-participants)로 받습니다.

이슈 또는 티켓의 최대 외부 참여자 수는 10명입니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 개요를 보려면 [GitLab 서비스 데스크의 여러 외부 참여자](https://www.youtube.com/watch?v=eKNe7fYQCLc)를 참조하세요.
<!-- Video published on 2024-05-13 -->

## 서비스 데스크 티켓 {#service-desk-tickets}

GitLab은 서비스 데스크 티켓의 외부 작성자를 외부 참여자로 추가합니다. 이는 일반적으로 티켓을 만든 초기 이메일의 `From` 헤더의 이메일 주소입니다.

### `Cc` 헤더에서 외부 참여자 추가 {#add-external-participants-from-the-cc-header}

기본적으로 GitLab은 서비스 데스크 티켓을 만드는 이메일의 발신자만 외부 참여자로 추가합니다.

GitLab을 구성하여 `Cc` 헤더의 모든 이메일 주소를 서비스 데스크 티켓에 추가할 수 있습니다. 이는 초기 이메일과 [`thank_you` 이메일](configure.md#customize-emails-sent-to-external-participants)에 대한 모든 회신에 적용됩니다.

`Cc` 헤더에서 추가된 외부 참여자는 `new_participant` 이메일을 받으며, 티켓에 추가되었음을 알리기 위해 `thank_you` 이메일 대신 이를 받습니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

프로젝트의 설정을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. **`Cc` 헤더에서 외부 참여자 추가**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 외부 참여자로서 {#as-an-external-participant}

외부 참여자는 [서비스 데스크 이메일](configure.md#customize-emails-sent-to-external-participants)을 사용하여 이슈 또는 티켓의 각 공개 댓글에 대한 알림을 받습니다.

### 알림 이메일에 회신하기 {#replying-to-notification-emails}

외부 참여자는 [수신한 알림 이메일에 회신](../../../administration/reply_by_email.md#you-reply-to-the-notification-email)할 수 있습니다. 이슈 또는 티켓에 새 댓글을 생성하고 GitLab 사용자명 대신 외부 참여자의 이메일 주소를 표시합니다. 이메일 주소 뒤에 `(external participant)`가 붙습니다.

![이슈 또는 티켓에서 외부 참여자의 댓글입니다.](img/service_desk_external_participants_comment_v17_0.png)

### 알림 이메일 구독 취소하기 {#unsubscribing-from-notification-emails}

외부 참여자는 기본 서비스 데스크 이메일 템플릿의 구독 취소 링크를 사용하여 이슈 또는 티켓에서 구독을 취소할 수 있습니다.

[`thank_you`, `new_participant`, `new_note` 이메일 템플릿을 사용자 정의](configure.md#customize-emails-sent-to-external-participants)하는 경우 `%{UNSUBSCRIBE_URL}` 자리 표시자를 사용하여 템플릿에 구독 취소 링크를 추가할 수 있습니다.

외부 참여자가 성공적으로 구독을 취소하려면 GitLab 인스턴스가 도달 가능해야 합니다(예: 공개 인터넷에서). 그렇지 않은 경우 템플릿에서 구독 취소 링크를 제거하는 것을 고려하세요.

GitLab의 이메일에는 또한 지원되는 이메일 클라이언트 및 다른 소프트웨어가 [외부 참여자를 자동으로 구독 취소](../../profile/notifications.md#using-an-email-client-or-other-software)할 수 있도록 하는 특수 헤더가 포함되어 있습니다.

## GitLab 사용자로서 {#as-a-gitlab-user}

외부 참여자의 이메일 주소를 보려면 프로젝트에 대해 리포터, 개발자, 유지보수자 또는 소유자 역할이 있어야 합니다.

외부 참여자의 이메일 주소는 다음 두 조건이 모두 참인 경우 난독화됩니다:

- 프로젝트의 구성원이 아니거나 게스트 역할이 있습니다.
- 이슈 또는 티켓이 공개([비밀이 아닌](../issues/confidential_issues.md))입니다.

외부 참여자의 이메일 주소는 다음에서 난독화됩니다:

- 서비스 데스크 티켓의 작성자 필드입니다.
- 외부 참여자를 언급하는 모든 [시스템 노트](../system_notes.md)입니다.
- [REST](../../../api/notes.md) 및 [GraphQL](../../../api/graphql/_index.md) API입니다.
- 댓글 편집기 아래의 경고 메시지입니다.

예를 들어:

![시스템 노트의 외부 참여자의 난독화된 이메일 주소입니다.](img/service_desk_external_participants_email_obfuscation_v17_0.png)

### 외부 참여자에게 전송된 알림 {#notifications-sent-to-external-participants}

외부 참여자는 이슈의 모든 공개 댓글에 대한 알림을 받습니다. 비공개 통신의 경우 [내부 노트](../../discussions/_index.md#add-an-internal-note)를 사용하세요.

외부 참여자는 다른 이슈 또는 티켓 이벤트에 대한 알림을 받지 않습니다.

### 모든 외부 참여자 보기 {#view-all-external-participants}

새 댓글에 대한 서비스 데스크 이메일을 받는 모든 외부 참여자의 개요를 가져옵니다.

사전 요구 사항:

- 프로젝트에 대해 리포터, 개발자, 유지보수자 또는 소유자 역할이 있어야 합니다.

모든 외부 참여자의 목록을 보려면:

1. 이슈 또는 티켓으로 이동합니다.
1. 댓글 편집기까지 아래로 스크롤합니다.
1. 이슈 또는 티켓에 외부 참여자가 있는 경우 댓글 편집기 아래에 모든 외부 참여자를 나열하는 경고가 표시됩니다.

![모든 외부 참여자를 나열하는 댓글 편집기 아래의 경고입니다.](img/service_desk_external_participants_comment_editor_warning_v17_0.png)

### 외부 참여자 추가 {#add-an-external-participant}

{{< history >}}

- GitLab 18.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/350460)합니다. 기능 플래그 `issue_email_participants`이 제거되었습니다.

{{< /history >}}

[`/add_email` 빠른 동작](../quick_actions.md#add_email)을 사용하여 외부 참여자를 추가하여 언제든지 대화에 포함시킬 수 있습니다.

추가되면 외부 참여자는 서비스 데스크 이메일을 사용하여 알림을 받기 시작합니다.

새 외부 참여자는 `new_participant` 이메일을 받아 티켓에 추가되었음을 알립니다. GitLab은 수동으로 추가된 외부 참여자에 대해 `thank_you` 이메일을 보내지 않습니다.

외부 참여자는 `/add_email` 빠른 동작이 포함된 댓글에 대한 알림 이메일을 받지 않으므로 전용 댓글에 외부 참여자를 추가해야 합니다.

사전 요구 사항:

- 프로젝트에 대해 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 있어야 합니다.

이슈 또는 티켓에 외부 참여자를 추가하려면:

1. 이슈 또는 티켓으로 이동합니다.
1. 빠른 동작 `/add_email user@example.com`만 포함하는 댓글을 추가합니다. 최대 6개의 이메일 주소를 연결할 수 있습니다. 예를 들어, `/add_email user@example.com user2@example.com`

성공 메시지와 이메일 주소가 있는 새 시스템 노트가 표시됩니다.

### 외부 참여자 제거 {#remove-an-external-participant}

{{< history >}}

- GitLab 18.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/350460)합니다. 기능 플래그 `issue_email_participants`이 제거되었습니다.

{{< /history >}}

[`/remove_email` 빠른 동작](../quick_actions.md#remove_email)을 사용하여 이슈 또는 서비스 데스크 티켓에서 외부 참여자를 제거하여 알림을 받을 수 없도록 합니다.

이슈 또는 티켓에서 제거한 후 새로운 알림을 받지 않습니다. 하지만 이전에 받은 이메일에 회신하고 이슈 또는 티켓에 새 댓글을 만들 수 있습니다.

사전 요구 사항:

- 프로젝트에 대해 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 있어야 합니다.
- 이슈 또는 티켓에 최소한 하나의 외부 참여자가 있어야 합니다.

이슈 또는 티켓에서 기존 외부 참여자를 제거하려면:

1. 이슈 또는 티켓으로 이동합니다.
1. 빠른 동작 `/remove_email user@example.com`만 포함하는 댓글을 추가합니다. 최대 6개의 이메일 주소를 연결할 수 있습니다. 예를 들어, `/remove_email user@example.com user2@example.com`

성공 메시지와 이메일 주소가 있는 새 시스템 노트가 표시됩니다.
