---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Service Desk 구성
description: "프로젝트에서 Service Desk를 활성화하고, 티켓 표시 여부, 이메일 템플릿, 커스텀 이메일 주소 및 다중 노드 이메일 수집을 구성합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

기본적으로 Service Desk는 새 프로젝트에서 활성 상태입니다. 활성 상태가 아닌 경우 프로젝트 설정에서 활성화할 수 있습니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.
- GitLab Self-Managed에서는 GitLab 인스턴스에 대해 [수신 이메일을 설정](../../../administration/incoming_email.md#set-it-up)해야 합니다. [이메일 부분 주소 지정](../../../administration/incoming_email.md#email-sub-addressing)을 사용해야 하지만 [전체 메일박스](../../../administration/incoming_email.md#catch-all-mailbox)도 사용할 수 있습니다. 이를 위해서는 관리자 액세스 권한이 있어야 합니다. 이메일 부분 주소 지정 또는 전체 메일박스를 지원하는 수신 이메일이 없으면 프로젝트 설정에 **서비스 데스크** 섹션이 표시되지 않습니다.
- 프로젝트에 대해 [이슈](../settings/_index.md#configure-project-features-and-permissions) 추적기를 활성화했어야 합니다.

프로젝트에서 Service Desk를 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. **서비스 데스크 활성화** 토글을 활성화합니다.
1. 선택 사항. 필드를 완성하세요.
   - Service Desk 이메일 주소에 [접미사 추가](#configure-a-suffix-for-service-desk-alias-email)합니다.
   - **모든 서비스 데스크 이슈에 추가할 템플릿** 아래의 목록이 비어 있으면 리포지토리에서 [설명 템플릿](../description_templates.md)을 생성합니다.
1. **변경 사항 저장**을 선택합니다.

이제 이 프로젝트에서 Service Desk가 활성화되었습니다. **Service Desk에 사용할 이메일 주소** 아래에 표시된 주소로 이메일을 보내면 GitLab이 이메일 내용이 포함된 비공개 티켓을 생성합니다.

## Service Desk 용어집 {#service-desk-glossary}

이 용어집은 Service Desk와 관련된 용어의 정의를 제공합니다.

| 용어                                             | 정의 |
|--------------------------------------------------|------------|
| [외부 참가자](external_participants.md) | GitLab 계정이 없지만 이메일을 통해서만 이슈 또는 Service Desk 티켓과 상호작용할 수 있는 사용자입니다. |
| 요청자                                        | Service Desk 티켓을 생성했거나 [`/convert_to_ticket` 빠른 작업](using_service_desk.md#create-a-service-desk-ticket-in-gitlab-ui)을 사용하여 요청자로 추가된 외부 참가자입니다. |

## 프로젝트의 보안 개선 {#improve-your-projects-security}

Service Desk 프로젝트의 보안을 개선하려면 다음을 수행해야 합니다:

- Service Desk 이메일 주소를 이메일 시스템의 별칭 뒤에 두어 나중에 변경할 수 있도록 합니다.
- GitLab 인스턴스에서 [Akismet 활성화](../../../integration/akismet.md)하여 이 서비스에 스팸 확인을 추가합니다. 차단되지 않은 이메일 스팸으로 인해 많은 스팸 이슈가 생성될 수 있습니다.

## 외부 참가자에게 전송되는 이메일 커스터마이징 {#customize-emails-sent-to-external-participants}

{{< history >}}

- 무료 및 평가판 플랜의 새로운 GitLab.com 네임스페이스에 대한 커스텀 템플릿 제한이 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254265)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `service_desk_restrict_custom_templates`로 지정됩니다. 기본적으로 비활성화되었습니다. 2026년 9월 10일 이후에 생성된 네임스페이스에 적용됩니다.

{{< /history >}}

다음의 경우 외부 참가자에게 이메일이 전송됩니다:

- 요청자가 Service Desk에 이메일을 보내 새 티켓을 제출합니다.
- 외부 참가자가 Service Desk 티켓에 추가됩니다.
- Service Desk 티켓에 새 공개 댓글이 추가됩니다.
  - 댓글을 편집해도 새 이메일이 전송되지 않습니다.

Service Desk 이메일 템플릿을 사용하여 이러한 이메일 메시지의 본문을 커스터마이징할 수 있습니다. 템플릿에는 [GitLab Flavored Markdown](../../markdown.md) 및 [일부 HTML 태그](../../markdown.md#inline-html)가 포함될 수 있습니다. 예를 들어 조직의 브랜드 가이드라인에 따라 헤더와 바닥글을 포함하도록 이메일을 형식화할 수 있습니다. 또한 다음 자리 표시자를 포함하여 Service Desk 티켓 또는 GitLab 인스턴스에 특정한 동적 콘텐츠를 표시할 수 있습니다.

> [!note]
> GitLab.com에서 2026년 9월 10일 이후에 생성된 최상위 네임스페이스는 네임스페이스가 무료 플랜 또는 평가판 플랜에 있는 동안 커스텀 Service Desk 이메일 템플릿을 사용할 수 없습니다. 이러한 네임스페이스는 대신 기본 GitLab 이메일 템플릿을 사용합니다. 이메일은 계속 전송되며 티켓, 댓글 및 참가자는 평소대로 작동합니다. 2026년 9월 10일 이전에 생성된 네임스페이스는 모든 플랜에서 영향을 받지 않습니다. 그룹의 경우 유료 비평가판 플랜(Premium, Ultimate 또는 Open Source)을 구매한 후 커스텀 템플릿을 사용할 수 있습니다. 개인 네임스페이스는 GitLab.com에서 구독을 보유할 수 없으므로 해당 날짜 이후에 생성된 개인 네임스페이스는 커스텀 템플릿을 사용할 수 없습니다. GitLab Self-Managed는 영향을 받지 않습니다.

| 자리 표시자            | `thank_you.md` 및 `new_participant` | `new_note.md`          | 설명 |
|------------------------|--------------------------------------|------------------------|-------------|
| `%{ISSUE_ID}`          | {{< yes >}}               | {{< yes >}} | 티켓 IID입니다. |
| `%{ISSUE_PATH}`        | {{< yes >}}               | {{< yes >}} | 티켓 IID가 추가된 프로젝트 경로입니다. |
| `%{ISSUE_URL}`         | {{< yes >}}               | {{< yes >}} | 티켓의 URL입니다. 외부 참가자는 프로젝트가 공개이고 티켓이 비공개가 아닌 경우에만 티켓을 볼 수 있습니다(Service Desk 티켓은 기본적으로 비공개입니다). |
| `%{ISSUE_DESCRIPTION}` | {{< yes >}}               | {{< yes >}} | 티켓 설명입니다. 사용자가 설명을 편집한 경우 외부 참가자에게 전달되지 않는 민감한 정보가 포함될 수 있습니다. 이 자리 표시자를 주의해서 사용하고, 티켓 설명을 수정하지 않거나 팀이 템플릿 디자인을 인식하는 경우에만 사용하십시오. |
| `%{UNSUBSCRIBE_URL}`   | {{< yes >}}               | {{< yes >}} | 구독 취소 URL입니다. [외부 참가자로 구독 취소하는 방법](external_participants.md#unsubscribing-from-notification-emails) 및 [GitLab의 알림 이메일에서 구독 취소 헤더를 사용하는 방법](../../profile/notifications.md#using-an-email-client-or-other-software)을 알아보세요. |
| `%{NOTE_TEXT}`         | {{< no >}}                | {{< yes >}} | 사용자가 티켓에 추가한 새 댓글입니다. `new_note.md`에 이 자리 표시자를 포함하도록 주의하세요. 그렇지 않으면 외부 참가자가 Service Desk 티켓의 업데이트를 절대 볼 수 없습니다. |

### 감사 이메일 {#thank-you-email}

요청자가 Service Desk를 통해 이슈를 제출하면 GitLab이 **감사 이메일**을 전송합니다. 추가 구성 없이 GitLab은 기본 감사 이메일을 전송합니다.

커스텀 감사 이메일 템플릿을 생성하려면:

1. 리포지토리의 `.gitlab/service_desk_templates/` 디렉터리에서 `thank_you.md`라는 파일을 생성합니다.
1. Markdown 파일을 텍스트, [GitLab Flavored Markdown](../../markdown.md), [선택된 일부 HTML 태그](../../markdown.md#inline-html) 및 자리 표시자로 채워 Service Desk 요청자에게 회신을 커스터마이징합니다.

### 새 참가자 이메일 {#new-participant-email}

{{< history >}}

- `new_participant` 이메일이 GitLab 17.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/299261)되었습니다.

{{< /history >}}

[외부 참가자](external_participants.md)가 티켓에 추가되면 GitLab이 **새 참가자 이메일**을 전송하여 대화의 일부임을 알립니다. 추가 구성 없이 GitLab은 기본 새 참가자 이메일을 전송합니다.

커스텀 새 참가자 이메일 템플릿을 생성하려면:

1. 리포지토리의 `.gitlab/service_desk_templates/` 디렉터리에서 `new_participant.md`라는 파일을 생성합니다.
1. Markdown 파일을 텍스트, [GitLab Flavored Markdown](../../markdown.md), [선택된 일부 HTML 태그](../../markdown.md#inline-html) 및 자리 표시자로 채워 Service Desk 요청자에게 회신을 커스터마이징합니다.

### 새 메모 이메일 {#new-note-email}

Service Desk 티켓에 새 공개 댓글이 있으면 GitLab이 **새 메모 이메일**을 전송합니다. 추가 구성 없이 GitLab은 댓글의 내용을 전송합니다.

이메일을 브랜드에 맞게 유지하려면 커스텀 새 메모 이메일 템플릿을 생성할 수 있습니다. 이렇게 하려면:

1. 리포지토리의 `.gitlab/service_desk_templates/` 디렉터리에서 `new_note.md`라는 파일을 생성합니다.
1. Markdown 파일을 텍스트, [GitLab Flavored Markdown](../../markdown.md), [선택된 일부 HTML 태그](../../markdown.md#inline-html) 및 자리 표시자로 채워 새 메모 이메일을 커스터마이징합니다. `%{NOTE_TEXT}`를 템플릿에 포함하여 이메일 수신자가 댓글의 내용을 읽을 수 있도록 하십시오.

### 인스턴스 전체 이메일 헤더, 바닥글 및 추가 텍스트 {#instance-wide-email-header-footer-and-additional-text}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

인스턴스 관리자는 GitLab 인스턴스에 헤더, 바닥글 또는 추가 텍스트를 추가하고 GitLab에서 전송하는 모든 이메일에 적용할 수 있습니다. 커스텀 `thank_you.md`, `new_participant.md` 또는 `new_note.md`을 사용 중인 경우 이 콘텐츠를 포함하려면 템플릿에 `%{SYSTEM_HEADER}`, `%{SYSTEM_FOOTER}` 또는 `%{ADDITIONAL_TEXT}`을 추가합니다.

자세한 내용은 [시스템 헤더 및 바닥글 메시지](../../../administration/appearance.md#add-system-header-and-footer-messages) 및 [커스텀 추가 텍스트](../../../administration/settings/email.md#custom-additional-text)를 참조하세요.

## Service Desk 티켓에 커스텀 템플릿 사용 {#use-a-custom-template-for-service-desk-tickets}

프로젝트당 하나의 [설명 템플릿](../description_templates.md#create-a-description-template)을 선택하여 모든 새로운 Service Desk 티켓 설명에 추가할 수 있습니다.

다양한 수준에서 설명 템플릿을 설정할 수 있습니다:

- 전체 [인스턴스](../description_templates.md#set-instance-level-description-templates).
- 특정 [그룹 또는 하위 그룹](../description_templates.md#set-group-level-description-templates).
- 특정 [프로젝트](../description_templates.md#set-a-default-template-for-merge-requests-and-issues).

템플릿은 상속됩니다. 예를 들어 프로젝트에서 인스턴스에 대해 설정된 템플릿이나 프로젝트의 상위 그룹에 대해 설정된 템플릿에도 액세스할 수 있습니다.

사전 요구 사항:

- [설명 템플릿을 생성](../description_templates.md#create-a-description-template)했어야 합니다.

Service Desk에 커스텀 설명 템플릿을 사용하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. 드롭다운 목록 **모든 서비스 데스크 이슈에 추가할 템플릿**에서 템플릿을 검색하거나 선택합니다.

## 지원 봇 사용자 {#support-bot-user}

내부적으로 Service Desk는 특수 Support Bot 사용자가 티켓을 생성함으로써 작동합니다. 이 사용자는 [청구 가능한 사용자](../../../subscriptions/manage_seats.md#criteria-for-non-billable-users)가 아니므로 라이선스 제한에 포함되지 않습니다.

Service Desk 이메일에서 생성된 댓글은 이메일을 보낸 사용자의 이메일을 표시합니다.

### Support Bot의 표시 이름 변경 {#change-the-support-bots-display-name}

Support Bot 사용자의 표시 이름을 변경할 수 있습니다. Service Desk 티켓에서 전송된 이메일은 `From` 헤더에 이 이름을 포함합니다. 기본 표시 이름은 `GitLab Support Bot`입니다.

커스텀 이메일 표시 이름을 편집하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. **이메일 표시 이름** 아래에 새 이름을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

## 기본 티켓 표시 여부 {#default-ticket-visibility}

{{< history >}}

- GitLab 17.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/33091)되었습니다.

{{< /history >}}

새 티켓은 기본적으로 비공개이므로 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할을 가진 프로젝트 멤버만 볼 수 있습니다.

개인 및 내부 프로젝트에서는 새 티켓이 기본적으로 비공개가 아니도록 GitLab을 구성할 수 있으며 모든 프로젝트 멤버가 볼 수 있습니다.

공개 프로젝트에서는 새 티켓이 항상 기본적으로 비공개이므로 이 설정을 사용할 수 없습니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

이 설정을 비활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. **새 티켓은 기본적으로 비공개입니다.** 확인란을 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

## 외부 참가자가 댓글을 달 때 티켓 다시 열기 {#reopen-tickets-when-an-external-participant-comments}

외부 참가자가 이메일로 티켓에 새 댓글을 추가할 때 닫힌 티켓을 다시 열도록 GitLab을 구성할 수 있습니다. 이는 또한 티켓의 담당자를 언급하는 내부 댓글을 추가하고 할 일 항목을 생성합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 연습을 보려면 [짧은 쇼케이스 비디오](https://youtu.be/163wDM1e43o)를 참조하세요.
<!-- Video published on 2023-12-12 -->

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

이 설정을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. **외부 참가자의 새 메모에서 이슈 다시 열기** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 커스텀 이메일 주소 {#custom-email-address}

{{< details >}}

- 상태:  베타

{{< /details >}}

커스텀 이메일 주소를 구성하여 지원 통신의 발신인으로 표시합니다. 지원 요청자들이 알아볼 수 있는 도메인으로 브랜드 정체성을 유지하고 신뢰를 형성합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 개요를 보려면 [짧은 쇼케이스 비디오](https://youtu.be/_moD5U3xcQs)를 참조하세요.
<!-- Video published on 2023-09-12 -->

이 기능은 [베타](../../../policy/development_stages_support.md#beta) 단계입니다. 베타 기능은 프로덕션 준비가 되지 않았지만 릴리스 전에 대폭 변경될 가능성은 낮습니다. 베타 기능을 시도하고 [피드백 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/416637)에서 피드백을 제공합니다.

### 사전 요구 사항 {#prerequisites}

프로젝트당 하나의 커스텀 이메일 주소를 Service Desk에 사용할 수 있으며 인스턴스 전체에서 고유해야 합니다.

사용하려는 커스텀 이메일 주소는 다음의 모든 요구사항을 충족해야 합니다:

- 이메일 전달을 설정할 수 있습니다.
- 전달된 이메일은 원래 `From` 헤더를 유지합니다.
- 서비스 제공업체가 부분 주소 지정을 지원해야 합니다. 이메일 주소는 로컬 부분(모든 `@` 앞) 및 도메인 부분으로 구성됩니다.

  이메일 부분 주소 지정을 사용하면 로컬 부분에 `+` 기호와 그 뒤에 텍스트를 추가하여 이메일 주소의 고유한 변형을 생성할 수 있습니다. 이메일 주소 `support@example.com`가 주어지면 `support+1@example.com`로 이메일을 보내 부분 주소 지정이 지원되는지 확인합니다. 이 이메일은 메일박스에 나타나야 합니다.
- SMTP 자격 증명이 있습니다(이상적으로 앱 비밀번호를 사용해야 합니다). 사용자 이름과 비밀번호는 256비트 키를 사용하는 Advanced Encryption Standard(AES)를 사용하여 데이터베이스에 저장됩니다.
- **SMTP 호스트**는 GitLab 인스턴스(GitLab Self-Managed에서) 또는 공개 인터넷(GitLab.com에서)의 네트워크에서 확인 가능해야 합니다.
- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 프로젝트에 대해 Service Desk를 구성해야 합니다.

### 커스텀 이메일 주소 구성 {#configure-a-custom-email-address}

자신의 이메일 주소를 사용하여 Service Desk 이메일을 보내려는 경우 커스텀 이메일 주소를 구성하고 확인합니다.

> [!warning]
> 이메일 전달을 설정할 때 커스텀 이메일 형식의 **이메일을 전달할 서비스 데스크 이메일 주소**에서 주소를 사용합니다(`incoming+...` 주소). Service Desk 설정 페이지의 맨 위에 있는 별칭 주소(`contact-project+...`)로 전달하지 마세요. 별칭 주소로 전달하면 `Incorrect forwarding target` 확인 오류가 발생합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장하고 **커스텀 이메일 주소 구성** 섹션을 찾습니다.
1. **이메일을 전달할 서비스 데스크 이메일 주소**에서 이메일 주소를 복사합니다. 이는 전달 대상으로 사용해야 하는 `incoming+...` 주소입니다.
1. 이메일 제공업체(예: Gmail 또는 Microsoft 365)에서 커스텀 이메일 주소에서 이전 단계에서 복사한 주소로의 이메일 전달을 설정합니다.
1. GitLab으로 돌아가서 나머지 필드를 완료합니다.
1. **저장 및 연결 테스트**를 선택합니다.

구성이 저장되었으며 커스텀 이메일 주소의 확인이 트리거되었습니다.

#### 확인 {#verification}

1. 구성 완료 후 모든 프로젝트 소유자와 커스텀 이메일 구성을 저장한 관리자는 알림 이메일을 수신합니다.
1. 제공된 SMTP 자격 증명을 사용하여 커스텀 이메일 주소(부분 주소 지정 부분 포함)로 확인 이메일이 전송됩니다. 이메일에는 확인 토큰이 포함되어 있습니다. 이메일 전달이 올바르게 설정되고 모든 전제 조건이 충족되면 이메일이 Service Desk 주소로 전달되고 GitLab에 의해 수집됩니다. GitLab은 다음 조건을 확인합니다:
   1. GitLab이 SMTP 자격 증명을 사용하여 이메일을 보낼 수 있습니다.
   1. 부분 주소 지정이 지원됩니다(`+verify` 부분 주소 지정 부분 포함).
   1. `From` 헤더는 전달 후에 유지됩니다.
   1. 확인 토큰이 올바릅니다.
   1. 이메일은 30분 이내에 수신됩니다.

일반적으로 프로세스는 몇 분만 소요됩니다.

언제든지 확인을 취소하거나 실패하면 **커스텀 이메일 재설정**을 선택합니다. 설정 페이지가 그에 따라 업데이트되고 확인의 현재 상태를 반영합니다. SMTP 자격 증명이 삭제되고 구성을 다시 시작할 수 있습니다.

실패 및 성공 시 모든 프로젝트 소유자와 확인 프로세스를 트리거한 사용자는 확인 결과가 포함된 알림 이메일을 수신합니다. 확인이 실패한 경우 이메일에는 이유에 대한 세부 정보도 포함됩니다.

확인이 성공한 경우 커스텀 이메일 주소를 사용할 준비가 되었습니다. 이제 커스텀 이메일 주소로 Service Desk 이메일 전송을 활성화할 수 있습니다.

#### 구성 문제 해결 {#troubleshooting-your-configuration}

커스텀 이메일을 구성할 때 다음 문제가 발생할 수 있습니다.

##### 유효하지 않은 자격 증명 {#invalid-credentials}

다음과 같은 오류가 표시될 수 있습니다:

```plaintext
The given credentials (username and password) were rejected by the SMTP server,
or you need to explicitly set an authentication method.
```

이 문제는 SMTP 서버가 인증 자격 증명을 거부할 때 발생합니다.

이 이슈를 해결하려면:

1. 사용자 이름과 비밀번호가 올바른지 확인합니다.
1. GitLab이 지원되는 인증 방법을 자동으로 선택할 수 없으면 다음 중 하나를 수행합니다:
   - 사용 가능한 인증 방법을 테스트합니다: **일반**, **로그인** 및 **CRAM-MD5**.
   - GitLab 서버에서 이 명령을 실행하여 SMTP 서버가 지원하는 인증 방법을 확인합니다:

     ```shell
          swaks --to user@example.com \
                --from support@example.com \
                --auth-user support@example.com \
                --server smtp@example.com:587 \
                -tls-optional \
                --auth-password your-app-password
     ```

     출력에서 `250-AUTH`로 시작하는 줄을 찾은 다음 커스텀 이메일 설정 형식에서 지원되는 인증 방법 중 하나를 선택합니다.

1. Microsoft 365를 사용 중이고 오류가 지속되면 조건부 액세스를 비활성화하고 이전 단계를 반복합니다.

##### 잘못된 전달 대상 {#incorrect-forwarding-target}

잘못된 전달 대상이 사용되었다는 오류가 표시될 수 있습니다.

이는 확인 이메일이 커스텀 이메일 구성 형식에 표시되는 프로젝트별 Service Desk 주소와 다른 이메일 주소로 전달되었을 때 발생합니다.

`incoming_email`에서 생성된 Service Desk 주소를 사용해야 합니다. `service_desk_email`에서 생성된 추가 Service Desk 별칭 주소로의 전달은 모든 이메일 회신 기능을 지원하지 않으므로 지원되지 않습니다.

이를 해결하려면:

1. 이메일을 전달할 올바른 이메일 주소를 찾습니다. 다음 중 하나를 선택합니다.
   - 모든 프로젝트 소유자와 확인 프로세스를 트리거한 사용자가 수신한 확인 결과 이메일에서 주소를 메모합니다.
   - 커스텀 이메일 설정 형식의 **이메일을 전달할 서비스 데스크 이메일 주소** 입력에서 주소를 복사합니다.
1. 커스텀 이메일 주소에 대한 모든 이메일을 올바른 대상 이메일 주소로 전달합니다.

### 커스텀 이메일 주소 활성화 또는 비활성화 {#enable-or-disable-the-custom-email-address}

커스텀 이메일 주소가 확인된 후 관리자는 커스텀 이메일 주소로 Service Desk 이메일 전송을 활성화하거나 비활성화할 수 있습니다.

커스텀 이메일 주소를 **활성화**하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. **커스텀 이메일 주소 활성화** 토글을 활성화합니다. Service Desk 이메일은 SMTP 자격 증명을 사용하여 외부 참가자에게 전송됩니다.

커스텀 이메일 주소를 **비활성화**하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. **커스텀 이메일 주소 활성화** 토글을 비활성화합니다. 이메일 전달을 설정했으므로 커스텀 이메일 주소로 보낸 이메일은 계속 처리되어 프로젝트에 Service Desk 티켓으로 표시됩니다.

   Service Desk 이메일은 이제 GitLab 인스턴스의 기본 발신 이메일 구성을 사용하여 외부 참가자에게 전송됩니다.

### 커스텀 이메일 구성 변경 또는 제거 {#change-or-remove-custom-email-configuration}

커스텀 이메일 구성을 변경하려면 이를 재설정하고 제거한 다음 커스텀 이메일을 다시 구성해야 합니다.

프로세스의 모든 단계에서 구성을 재설정하려면 **커스텀 이메일 재설정**을 선택합니다. 그러면 자격 증명이 데이터베이스에서 제거됩니다.

### 커스텀 이메일 회신 주소 {#custom-email-reply-address}

외부 참가자는 Service Desk 티켓에 [이메일로 회신](../../../administration/reply_by_email.md)할 수 있습니다. GitLab은 티켓에 해당하는 32자 회신 키가 있는 이메일 회신 주소를 사용합니다. 커스텀 이메일이 구성되면 GitLab은 해당 이메일에서 회신 주소를 생성합니다.

### 자신의 도메인으로 Google Workspace 사용 {#use-google-workspace-with-your-own-domain}

자신의 도메인으로 Google Workspace를 사용할 때 Service Desk에 대한 커스텀 이메일 주소를 설정합니다.

사전 요구 사항:

- 이미 Google Workspace 계정이 있습니다.
- 테넌트에 대한 새 계정을 생성할 수 있습니다.

Google Workspace로 커스텀 Service Desk 이메일 주소를 구성하려면:

1. [Google Workspace 계정 구성](#configure-a-google-workspace-account).
1. [Google Workspace에서 이메일 전달 구성](#configure-email-forwarding-in-google-workspace).
1. [Google Workspace 계정을 사용한 커스텀 이메일 주소 구성](#configure-custom-email-address-using-a-google-workspace-account).

#### Google Workspace 계정 구성 {#configure-a-google-workspace-account}

먼저 Google Workspace 계정을 생성하고 구성해야 합니다.

Google Workspace에서:

1. 사용할 커스텀 이메일 주소에 대한 새 계정을 만듭니다(예: `support@example.com`).
1. 해당 계정에 로그인하고 2단계 인증을 활성화합니다: `https://myaccount.google.com/u/3/signinoptions/two-step-verification`
1. SMTP 비밀번호로 사용할 수 있는 앱 비밀번호를 만듭니다: `https://myaccount.google.com/u/3/apppasswords` 안전한 장소에 저장하고 문자 사이의 공백을 제거합니다.

다음으로 [Google Workspace에서 이메일 전달을 구성](#configure-email-forwarding-in-google-workspace)해야 합니다.

#### Google Workspace에서 이메일 전달 구성 {#configure-email-forwarding-in-google-workspace}

다음 단계에서는 GitLab과 Google Workspace 간에 이동해야 합니다.

GitLab에서:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. **이메일을 전달할 서비스 데스크 이메일 주소** 아래의 이메일 주소를 메모합니다.

Google Workspace에서:

1. 커스텀 이메일 계정에 로그인하고 [**전달 및 POP/IMAP**](https://mail.google.com/mail/u/0/#settings/fwdandpop) 설정을 엽니다.
1. **전달 주소 추가**를 선택합니다.
1. 커스텀 이메일 형식에서 Service Desk 주소를 입력합니다.
1. **다음**을 선택합니다.
1. 입력을 확인하고 **진행**을 선택합니다. Google이 Service Desk 주소로 이메일을 보내고 확인 코드를 요청합니다.

GitLab에서:

1. **계획** > **작업 항목**을 선택한 다음 **유형** = **이슈**로 필터링합니다. Google의 확인 이메일에서 생성된 새 이슈를 기다립니다.
1. 이슈를 선택하고 확인 코드를 메모합니다.
1. 선택 사항. 이슈를 삭제합니다.

Google Workspace에서:

1. 확인 코드를 입력하고 **확인**을 선택합니다.
1. **수신 이메일 사본 전달**을 선택하고 Service Desk 주소가 드롭다운 목록에서 선택되었는지 확인합니다.
1. 페이지의 맨 아래에서 **변경 사항 저장**을 선택합니다.

다음으로 Service Desk와 함께 사용할 [Google Workspace 계정을 사용한 커스텀 이메일 주소 구성](#configure-custom-email-address-using-a-google-workspace-account)을 수행합니다.

#### Google Workspace 계정을 사용한 커스텀 이메일 주소 구성 {#configure-custom-email-address-using-a-google-workspace-account}

GitLab에서:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장하고 커스텀 이메일 설정을 찾습니다.
1. 필드를 완성합니다:
   - **커스텀 이메일 주소**: 커스텀 이메일 주소입니다.
   - **SMTP 호스트**: `smtp.gmail.com`.
   - **SMTP 포트**: `587`.
   - **SMTP username**: 커스텀 이메일 주소로 미리 채워집니다.
   - **SMTP 비밀번호**: 커스텀 이메일 계정에 대해 이전에 생성한 앱 비밀번호입니다.
   - **SMTP 인증 방법**: GitLab이 서버 지원 방법을 선택하도록 합니다(권장).
1. **저장 및 연결 테스트**를 선택합니다.
1. [확인 프로세스](#verification) 후 [커스텀 이메일 주소를 활성화](#enable-or-disable-the-custom-email-address)할 수 있습니다.

### 자신의 도메인으로 Microsoft 365(Exchange online) 사용 {#use-microsoft-365-exchange-online-with-your-own-domain}

{{< history >}}

- GitLab 17.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/496396)되었습니다.

{{< /history >}}

자신의 도메인으로 Microsoft 365(Exchange)를 사용할 때 Service Desk에 대한 커스텀 이메일 주소를 설정합니다.

사전 요구 사항:

- 이미 Microsoft 365 계정이 있습니다.
- 테넌트에 대한 새 계정을 생성할 수 있습니다.

Microsoft 365로 커스텀 Service Desk 이메일 주소를 구성하려면:

1. [Microsoft 365 계정 구성](#configure-a-microsoft-365-account).
1. [Microsoft 365에서 이메일 전달 구성](#configure-email-forwarding-in-microsoft-365).
1. [Microsoft 365 계정을 사용한 커스텀 이메일 주소 구성](#configure-custom-email-address-using-a-microsoft-365-account).

#### Microsoft 365 계정 구성 {#configure-a-microsoft-365-account}

먼저 Microsoft 365 계정을 생성하고 구성해야 합니다. 이 가이드에서는 커스텀 이메일 메일박스에 라이선스가 있는 사용자를 사용합니다. 다른 구성 옵션으로도 실험할 수 있습니다.

[Microsoft 365 관리 센터](https://admin.microsoft.com/Adminportal/Home#/homepage)에서:

1. 사용할 커스텀 이메일 주소에 대한 새 계정을 만듭니다(예: `support@example.com`).
   1. **사용자**를 확장하고 메뉴에서 **활성 사용자**를 선택합니다.
   1. **사용자 추가**를 선택하고 화면의 지침을 따릅니다.
1. Microsoft Entra(이전에 Active Directory라고 함)에서 계정에 대해 2단계 인증을 활성화합니다.
1. [사용자가 앱 비밀번호를 만들 수 있도록 허용](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-app-passwords).
1. 계정에 대해 **인증된 SMTP**를 활성화합니다.
   1. 목록에서 계정을 선택합니다.
   1. 서랍에서 **메일**을 선택합니다.
   1. **이메일 앱** 아래에서 **이메일 앱 관리**를 선택합니다.
   1. **인증된 SMTP**를 확인하고 **변경사항 저장**을 선택합니다.
1. 전체 Exchange online 구성에 따라 다음을 구성해야 할 수 있습니다:
   1. Azure Cloud Shell을 사용하여 SMTP 클라이언트 인증을 허용합니다:

      ```powershell
      Set-TransportConfig -SmtpClientAuthenticationDisabled $false
      ```

   1. Azure Cloud Shell을 사용하여 [SMTP AUTH를 사용하는 레거시 TLS 클라이언트](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/opt-in-exchange-online-endpoint-for-legacy-tls-using-smtp-auth)를 허용합니다:

      ```powershell
      Set-TransportConfig -AllowLegacyTLSClients $true
      ```

   1. 외부 수신자에게 전달하려는 경우 [외부 이메일 전달](https://learn.microsoft.com/en-gb/defender-office-365/outbound-spam-policies-external-email-forwarding)을 활성화하는 방법에 대한 이 가이드를 참조하세요. [아웃바운드 스팸 정책을 생성](https://security.microsoft.com/antispam)하여 필요한 사용자만 외부 수신자에게 전달할 수 있도록 허용할 수도 있습니다.
1. 해당 계정에 로그인하고 2단계 인증을 활성화합니다.
   <!-- vale gitlab_base.SubstitutionWarning = NO -->
   1. 오른쪽 위 메뉴에서 **계정 보기**를 선택하고 [**보안 정보**로 이동](https://mysignins.microsoft.com/security-info)합니다.
   <!-- vale gitlab_base.SubstitutionWarning = YES -->
   1. **로그인 방법 추가**를 선택하고 작동하는 방법을 선택합니다(인증자 앱, 전화 또는 이메일).
   1. 화면의 지침을 따릅니다.
<!-- vale gitlab_base.SubstitutionWarning = NO -->
1. [**보안 정보**](https://mysignins.microsoft.com/security-info) 페이지에서 SMTP 비밀번호로 사용할 수 있는 앱 비밀번호를 만듭니다.
<!-- vale gitlab_base.SubstitutionWarning = YES -->
   1. **로그인 방법 추가**를 선택하고 드롭다운 목록에서 **앱 비밀번호**를 선택합니다.
   1. `GitLab SD`과 같은 앱 비밀번호에 대해 설명적인 이름을 설정합니다.
   1. **다음**을 선택합니다.
   1. 표시된 비밀번호를 복사하고 안전한 장소에 저장합니다.
   1. 선택 사항. [`swaks` 명령줄 도구](https://www.jetmore.org/john/code/swaks/)를 사용하여 SMTP를 사용하여 이메일을 보낼 수 있는지 확인합니다.
   1. 자격 증명으로 다음 명령을 실행하고 앱 비밀번호를 `auth-password`로 사용합니다:

      ```shell
      swaks --to your-email@example.com \
            --from custom-email@example.com \
            --auth-user custom-email@example.com \
            --server smtp.office365.com:587 \
            -tls-optional \
            --auth-password <your_app_password>
      ```

다음으로 [Microsoft 365에서 이메일 전달을 구성](#configure-email-forwarding-in-microsoft-365)해야 합니다.

#### Microsoft 365에서 이메일 전달 구성 {#configure-email-forwarding-in-microsoft-365}

다음 단계에서는 GitLab과 Microsoft 365 관리 센터 간에 이동해야 합니다.

GitLab에서:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. **이메일을 전달할 서비스 데스크 이메일 주소** 아래의 이메일 주소를 메모합니다(부분 주소 부분 제외).

   수신자 주소에 부분 주소(예: GitLab에서 생성한 회신 주소)가 포함되고 전달 이메일 주소에 부분 주소(**이메일을 전달할 서비스 데스크 이메일 주소**)가 포함되면 이메일이 전달되지 않습니다.

   예를 들어, `incoming+group-project-12346426-issue-@incoming.gitlab.com`은 `incoming@incoming.gitlab.com`이 됩니다. Exchange online이 전달 후 커스텀 이메일 주소를 `To` 헤더에 유지하고 GitLab이 커스텀 이메일 주소에 따라 올바른 프로젝트를 할당할 수 있으므로 괜찮습니다.

[Microsoft 365 관리 센터](https://admin.microsoft.com/Adminportal/Home#/homepage)에서:

<!-- vale gitlab_base.SubstitutionWarning = NO -->
1. **사용자**를 확장하고 메뉴에서 **활성 사용자**를 선택합니다.
<!-- vale gitlab_base.SubstitutionWarning = YES -->
1. 목록에서 커스텀 이메일에 사용할 계정을 선택합니다.
1. 서랍에서 **메일**을 선택합니다.
1. **이메일 전달** 아래에서 **이메일 전달 관리**를 선택합니다.
1. **이 메일박스로 전송된 모든 이메일 전달**을 확인합니다.
1. **이메일 전달 주소**에서 커스텀 이메일 형식의 Service Desk 주소를 입력합니다(부분 주소 부분 제외).
1. **변경 사항 저장**을 선택합니다.

다음으로 Service Desk와 함께 사용할 [Microsoft 365 계정을 사용한 커스텀 이메일 주소 구성](#configure-custom-email-address-using-a-microsoft-365-account)을 수행합니다.

#### Microsoft 365 계정을 사용한 커스텀 이메일 주소 구성 {#configure-custom-email-address-using-a-microsoft-365-account}

GitLab에서:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장하고 커스텀 이메일 설정을 찾습니다.
1. 필드를 완성합니다:
   - **커스텀 이메일 주소**: 커스텀 이메일 주소입니다.
   - **SMTP 호스트**: `smtp.office365.com`.
   - **SMTP 포트**: `587`.
   - **SMTP username**: 커스텀 이메일 주소로 미리 채워집니다.
   - **SMTP 비밀번호**: 커스텀 이메일 계정에 대해 이전에 생성한 앱 비밀번호입니다.
   - **SMTP 인증 방법**: 로그인.
1. **저장 및 연결 테스트**를 선택합니다.
1. [확인 프로세스](#verification) 후 [커스텀 이메일 주소를 활성화](#enable-or-disable-the-custom-email-address)할 수 있습니다.

### 알려진 이슈 {#known-issues}

- 일부 서비스 제공업체는 더 이상 SMTP 연결을 허용하지 않습니다. 각 사용자에 대해 활성화하고 앱 비밀번호를 만들 수 있는 경우가 많습니다.

## 추가 Service Desk 별칭 이메일 사용 {#use-an-additional-service-desk-alias-email}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

인스턴스에 대해 추가 별칭 이메일 주소를 Service Desk에 사용할 수 있습니다.

이를 위해서는 인스턴스 구성에서 [`service_desk_email`](#configure-service-desk-alias-email)를 구성해야 합니다. 또한 부분 주소 지정 부분에서 기본 `-issue-` 부분을 대체하는 [커스텀 접미사](#configure-a-suffix-for-service-desk-alias-email)를 구성할 수도 있습니다.

### Service Desk 별칭 이메일 구성 {#configure-service-desk-alias-email}

> [!note]
> GitLab.com에서는 이메일 주소로 `contact-project+%{key}@incoming.gitlab.com`가 이미 구성된 커스텀 메일박스가 있습니다. 프로젝트 설정에서 [커스텀 접미사](#configure-a-suffix-for-service-desk-alias-email)를 계속 구성할 수 있습니다.

Service Desk는 기본적으로 [수신 이메일](../../../administration/incoming_email.md) 구성을 사용합니다. 그러나 Service Desk에 대한 별도의 이메일 주소를 가지려면 프로젝트 설정에서 `service_desk_email`을 [커스텀 접미사](#configure-a-suffix-for-service-desk-alias-email)와 함께 구성합니다.

사전 요구 사항:

- `address`은 주소의 `user` 부분에서 `@` 앞에 `+%{key}` 자리 표시자를 포함해야 합니다. 자리 표시자는 이슈를 생성해야 하는 프로젝트를 식별하는 데 사용됩니다.
- `service_desk_email` 및 `incoming_email` 구성은 Service Desk 이메일이 올바르게 처리되도록 항상 별도의 메일박스를 사용해야 합니다.

IMAP을 사용하여 Service Desk용 커스텀 메일박스를 구성하려면 다음 코드 조각을 구성 파일에 완전히 추가합니다:

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

```ruby
gitlab_rails['service_desk_email_enabled'] = true
gitlab_rails['service_desk_email_address'] = "project_contact+%{key}@gmail.com"
gitlab_rails['service_desk_email_email'] = "project_contact@gmail.com"
gitlab_rails['service_desk_email_password'] = "[REDACTED]"
gitlab_rails['service_desk_email_mailbox_name'] = "inbox"
gitlab_rails['service_desk_email_idle_timeout'] = 60
gitlab_rails['service_desk_email_log_file'] = "/var/log/gitlab/mailroom/mail_room_json.log"
gitlab_rails['service_desk_email_host'] = "imap.gmail.com"
gitlab_rails['service_desk_email_port'] = 993
gitlab_rails['service_desk_email_ssl'] = true
gitlab_rails['service_desk_email_start_tls'] = false
```

{{< /tab >}}

{{< tab title="Self-compiled(source)" >}}

```yaml
service_desk_email:
  enabled: true
  address: "project_contact+%{key}@example.com"
  user: "project_contact@example.com"
  password: "[REDACTED]"
  host: "imap.gmail.com"
  delivery_method: webhook
  secret_file: .gitlab-mailroom-secret
  port: 993
  ssl: true
  start_tls: false
  log_path: "log/mailroom.log"
  mailbox: "inbox"
  idle_timeout: 60
  expunge_deleted: true
```

{{< /tab >}}

{{< /tabs >}}

구성 옵션은 [수신 이메일](../../../administration/incoming_email.md#set-it-up) 구성과 동일합니다.

#### 암호화된 자격 증명 사용 {#use-encrypted-credentials}

Service Desk 이메일 자격 증명을 구성 파일에 평문으로 저장하는 대신 수신 이메일 자격 증명에 대해 암호화된 파일을 선택적으로 사용할 수 있습니다.

사전 요구 사항:

- 암호화된 자격 증명을 사용하려면 먼저 [암호화된 구성](../../../administration/encrypted_configuration.md)을 활성화해야 합니다.

암호화된 파일에 대해 지원되는 구성 항목은:

- `user`
- `password`

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

1. `/etc/gitlab/gitlab.rb`의 Service Desk 구성이 처음에 다음과 같았다면:

   ```ruby
   gitlab_rails['service_desk_email_email'] = "service-desk-email@mail.example.com"
   gitlab_rails['service_desk_email_password'] = "examplepassword"
   ```

1. 암호화된 비밀을 편집합니다:

   ```shell
   sudo gitlab-rake gitlab:service_desk_email:secret:edit EDITOR=vim
   ```

1. Service Desk 이메일 비밀의 암호화되지 않은 콘텐츠를 입력합니다:

   ```yaml
   user: 'service-desk-email@mail.example.com'
   password: 'examplepassword'
   ```

1. `/etc/gitlab/gitlab.rb`을 편집하고 `email` 및 `password`에 대한 `service_desk` 설정을 제거합니다.
1. 파일을 저장하고 GitLab을 다시 구성합니다.

   ```shell
   sudo gitlab-ctl reconfigure
   ```

{{< /tab >}}

{{< tab title="Helm 차트(Kubernetes)" >}}

Service Desk 이메일 비밀번호를 저장하기 위해 Kubernetes 비밀을 사용합니다. 자세한 내용은 [Helm IMAP 비밀](https://docs.gitlab.com/charts/installation/secrets/#imap-password-for-service-desk-emails)을 참조하세요.

{{< /tab >}}

{{< tab title="Docker" >}}

1. `docker-compose.yml`의 Service Desk 구성이 처음에 다음과 같았다면:

   ```yaml
   version: "3.6"
   services:
     gitlab:
       image: 'gitlab/gitlab-ee:latest'
       restart: always
       hostname: 'gitlab.example.com'
       environment:
         GITLAB_OMNIBUS_CONFIG: |
           gitlab_rails['service_desk_email_email'] = "service-desk-email@mail.example.com"
           gitlab_rails['service_desk_email_password'] = "examplepassword"
   ```

1. 컨테이너 내부로 이동하고 암호화된 비밀을 편집합니다:

   ```shell
   sudo docker exec -t <container_name> bash
   gitlab-rake gitlab:service_desk_email:secret:edit EDITOR=editor
   ```

1. Service Desk 비밀의 암호화되지 않은 콘텐츠를 입력합니다:

   ```yaml
   user: 'service-desk-email@mail.example.com'
   password: 'examplepassword'
   ```

1. `docker-compose.yml`을 편집하고 `email` 및 `password`에 대한 `service_desk` 설정을 제거합니다.
1. 파일을 저장하고 GitLab을 다시 시작합니다.

   ```shell
   docker compose up -d
   ```

{{< /tab >}}

{{< tab title="Self-compiled(source)" >}}

1. `/home/git/gitlab/config/gitlab.yml`의 Service Desk 구성이 처음에 다음과 같았다면:

   ```yaml
   production:
     service_desk_email:
       user: 'service-desk-email@mail.example.com'
       password: 'examplepassword'
   ```

1. 암호화된 비밀을 편집합니다:

   ```shell
   bundle exec rake gitlab:service_desk_email:secret:edit EDITOR=vim RAILS_ENVIRONMENT=production
   ```

1. Service Desk 비밀의 암호화되지 않은 콘텐츠를 입력합니다:

   ```yaml
   user: 'service-desk-email@mail.example.com'
   password: 'examplepassword'
   ```

1. `/home/git/gitlab/config/gitlab.yml`을 편집하고 `user` 및 `password`에 대한 `service_desk_email:` 설정을 제거합니다.
1. 파일을 저장하고 GitLab 및 Mailroom을 다시 시작합니다.

   ```shell
   # For systems running systemd
   sudo systemctl restart gitlab.target

   # For systems running SysV init
   sudo service gitlab restart
   ```

{{< /tab >}}

{{< /tabs >}}

#### Microsoft Graph {#microsoft-graph}

`service_desk_email`은 IMAP 대신 Microsoft Graph API를 사용하여 Microsoft Exchange Online 메일박스를 읽도록 구성할 수 있습니다. [수신 이메일과 동일한 방식](../../../administration/incoming_email.md#microsoft-graph)으로 Microsoft Graph에 대한 OAuth 2.0 애플리케이션을 설정합니다.

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

1. `/etc/gitlab/gitlab.rb`을 편집하고 다음 줄을 추가하여 원하는 값을 대체합니다:

   ```ruby
   gitlab_rails['service_desk_email_enabled'] = true
   gitlab_rails['service_desk_email_address'] = "project_contact+%{key}@example.onmicrosoft.com"
   gitlab_rails['service_desk_email_email'] = "project_contact@example.onmicrosoft.com"
   gitlab_rails['service_desk_email_mailbox_name'] = "inbox"
   gitlab_rails['service_desk_email_log_file'] = "/var/log/gitlab/mailroom/mail_room_json.log"
   gitlab_rails['service_desk_email_inbox_method'] = 'microsoft_graph'
   gitlab_rails['service_desk_email_inbox_options'] = {
      'tenant_id': '<YOUR-TENANT-ID>',
      'client_id': '<YOUR-CLIENT-ID>',
      'client_secret': '<YOUR-CLIENT-SECRET>',
      'poll_interval': 60  # Optional
   }
   ```

   Microsoft Cloud for US Government 또는 [다른 Azure 배포](https://learn.microsoft.com/en-us/graph/deployments)의 경우 `azure_ad_endpoint` 및 `graph_endpoint` 설정을 구성합니다. 예를 들어:

   ```ruby
   gitlab_rails['service_desk_email_inbox_options'] = {
      'azure_ad_endpoint': 'https://login.microsoftonline.us',
      'graph_endpoint': 'https://graph.microsoft.us',
      'tenant_id': '<YOUR-TENANT-ID>',
      'client_id': '<YOUR-CLIENT-ID>',
      'client_secret': '<YOUR-CLIENT-SECRET>',
      'poll_interval': 60  # Optional
   }
   ```

{{< /tab >}}

{{< tab title="Helm 차트(Kubernetes)" >}}

1. [OAuth 2.0 애플리케이션 클라이언트 비밀을 포함하는 Kubernetes 비밀](https://docs.gitlab.com/charts/installation/secrets/#microsoft-graph-client-secret-for-service-desk-emails)을 만듭니다:

   ```shell
   kubectl create secret generic service-desk-email-client-secret --from-literal=secret=<YOUR-CLIENT_SECRET>
   ```

1. [GitLab Service Desk 이메일 인증 토큰을 위한 Kubernetes 비밀](https://docs.gitlab.com/charts/installation/secrets/#gitlab-service-desk-email-auth-token)을 만듭니다. `<name>`을 GitLab 설치를 위한 [Helm 릴리스 이름](https://helm.sh/docs/intro/using_helm/)으로 바꿉니다:

   ```shell
   kubectl create secret generic <name>-service-desk-email-auth-token --from-literal=authToken=$(head -c 512 /dev/urandom | LC_CTYPE=C tr -cd 'a-zA-Z0-9' | head -c 32 | base64)
   ```

1. Helm 값을 내보냅니다:

   ```shell
   helm get values gitlab > gitlab_values.yaml
   ```

1. `gitlab_values.yaml`을 편집합니다.

   ```yaml
   global:
     appConfig:
     serviceDeskEmail:
       enabled: true
       address: "project_contact+%{key}@example.onmicrosoft.com"
       user: "project_contact@example.onmicrosoft.com"
       mailbox: inbox
       inboxMethod: microsoft_graph
       azureAdEndpoint: https://login.microsoftonline.com
       graphEndpoint: https://graph.microsoft.com
       tenantId: "YOUR-TENANT-ID"
       clientId: "YOUR-CLIENT-ID"
       clientSecret:
         secret: service-desk-email-client-secret
         key: secret
       deliveryMethod: webhook
       authToken:
         secret: <name>-service-desk-email-auth-token
         key: authToken
   ```

   Microsoft Cloud for US Government 또는 [다른 Azure 배포](https://learn.microsoft.com/en-us/graph/deployments)의 경우 `azureAdEndpoint` 및 `graphEndpoint` 설정을 구성합니다. 이 필드는 대소문자를 구분합니다:

   ```yaml
   global:
     appConfig:
     serviceDeskEmail:
       [..]
       azureAdEndpoint: https://login.microsoftonline.us
       graphEndpoint: https://graph.microsoft.us
       [..]
   ```

1. 파일을 저장하고 새 값을 적용합니다:

   ```shell
   helm upgrade -f gitlab_values.yaml gitlab gitlab/gitlab
   ```

{{< /tab >}}

{{< tab title="Docker" >}}

1. `docker-compose.yml`을 편집합니다.

   ```yaml
   version: "3.6"
   services:
     gitlab:
       environment:
         GITLAB_OMNIBUS_CONFIG: |
           gitlab_rails['service_desk_email_enabled'] = true
           gitlab_rails['service_desk_email_address'] = "project_contact+%{key}@example.onmicrosoft.com"
           gitlab_rails['service_desk_email_email'] = "project_contact@example.onmicrosoft.com"
           gitlab_rails['service_desk_email_mailbox_name'] = "inbox"
           gitlab_rails['service_desk_email_log_file'] = "/var/log/gitlab/mailroom/mail_room_json.log"
           gitlab_rails['service_desk_email_inbox_method'] = 'microsoft_graph'
           gitlab_rails['service_desk_email_inbox_options'] = {
             'tenant_id': '<YOUR-TENANT-ID>',
             'client_id': '<YOUR-CLIENT-ID>',
             'client_secret': '<YOUR-CLIENT-SECRET>',
             'poll_interval': 60  # Optional
           }
   ```

1. 파일을 저장하고 GitLab을 다시 시작합니다.

   ```shell
   docker compose up -d
   ```

Microsoft Cloud for US Government 또는 [다른 Azure 배포](https://learn.microsoft.com/en-us/graph/deployments)의 경우 `azure_ad_endpoint` 및 `graph_endpoint` 설정을 구성합니다:

1. `docker-compose.yml`을 편집합니다.

   ```yaml
   version: "3.6"
   services:
     gitlab:
       environment:
         GITLAB_OMNIBUS_CONFIG: |
           gitlab_rails['service_desk_email_enabled'] = true
           gitlab_rails['service_desk_email_address'] = "project_contact+%{key}@example.onmicrosoft.com"
           gitlab_rails['service_desk_email_email'] = "project_contact@example.onmicrosoft.com"
           gitlab_rails['service_desk_email_mailbox_name'] = "inbox"
           gitlab_rails['service_desk_email_log_file'] = "/var/log/gitlab/mailroom/mail_room_json.log"
           gitlab_rails['service_desk_email_inbox_method'] = 'microsoft_graph'
           gitlab_rails['service_desk_email_inbox_options'] = {
             'azure_ad_endpoint': 'https://login.microsoftonline.us',
             'graph_endpoint': 'https://graph.microsoft.us',
             'tenant_id': '<YOUR-TENANT-ID>',
             'client_id': '<YOUR-CLIENT-ID>',
             'client_secret': '<YOUR-CLIENT-SECRET>',
             'poll_interval': 60  # Optional
           }
   ```

1. 파일을 저장하고 GitLab을 다시 시작합니다.

   ```shell
   docker compose up -d
   ```

{{< /tab >}}

{{< tab title="Self-compiled(source)" >}}

1. `/home/git/gitlab/config/gitlab.yml`을 편집합니다.

   ```yaml
     service_desk_email:
       enabled: true
       address: "project_contact+%{key}@example.onmicrosoft.com"
       user: "project_contact@example.onmicrosoft.com"
       mailbox: "inbox"
       delivery_method: webhook
       log_path: "log/mailroom.log"
       secret_file: .gitlab-mailroom-secret
       inbox_method: "microsoft_graph"
       inbox_options:
         tenant_id: "<YOUR-TENANT-ID>"
         client_id: "<YOUR-CLIENT-ID>"
         client_secret: "<YOUR-CLIENT-SECRET>"
         poll_interval: 60  # Optional
   ```

   Microsoft Cloud for US Government 또는 [다른 Azure 배포](https://learn.microsoft.com/en-us/graph/deployments)의 경우 `azure_ad_endpoint` 및 `graph_endpoint` 설정을 구성합니다. 예를 들어:

   ```yaml
     service_desk_email:
       enabled: true
       address: "project_contact+%{key}@example.onmicrosoft.com"
       user: "project_contact@example.onmicrosoft.com"
       mailbox: "inbox"
       delivery_method: webhook
       log_path: "log/mailroom.log"
       secret_file: .gitlab-mailroom-secret
       inbox_method: "microsoft_graph"
       inbox_options:
         azure_ad_endpoint: "https://login.microsoftonline.us"
         graph_endpoint: "https://graph.microsoft.us"
         tenant_id: "<YOUR-TENANT-ID>"
         client_id: "<YOUR-CLIENT-ID>"
         client_secret: "<YOUR-CLIENT-SECRET>"
         poll_interval: 60  # Optional
   ```

{{< /tab >}}

{{< /tabs >}}

### Service Desk 별칭 이메일에 대한 접미사 구성 {#configure-a-suffix-for-service-desk-alias-email}

프로젝트의 Service Desk 설정에서 커스텀 접미사를 설정할 수 있습니다.

접미사는 소문자(`a-z`), 숫자(`0-9`) 또는 밑줄(`_`)만 포함할 수 있습니다.

구성할 때 커스텀 접미사는 `service_desk_email_address` 설정 및 형식의 키로 구성된 새로운 Service Desk 이메일 주소를 생성합니다: `<project_full_path>-<custom_suffix>`

사전 요구 사항:

- [Service Desk 별칭 이메일](#configure-service-desk-alias-email)을 구성했어야 합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **서비스 데스크**를 확장합니다.
1. **이메일 도메인 주소** 아래에 사용할 접미사를 입력합니다.
1. **변경 사항 저장**을 선택합니다.

예를 들어 `mygroup/myproject` 프로젝트 Service Desk 설정에 다음이 구성되어 있다고 가정합니다:

- 이메일 도메인 주소가 `support`로 설정됩니다.
- Service Desk 이메일 주소가 `contact+%{key}@example.com`로 구성됩니다.

이 프로젝트의 Service Desk 이메일 주소는: `contact+mygroup-myproject-support@example.com`. [수신 이메일](../../../administration/incoming_email.md) 주소도 계속 작동합니다.

커스텀 접미사를 구성하지 않으면 기본 프로젝트 식별이 프로젝트를 식별하는 데 사용됩니다.

## 다중 노드 환경에서 이메일 수집 구성 {#configure-email-ingestion-in-multi-node-environments}

다중 노드 환경은 확장성, 내결함성 및 성능상의 이유로 GitLab이 여러 서버에 걸쳐 실행되는 설정입니다.

GitLab은 `mail_room`라는 별도의 프로세스를 사용하여 `incoming_email` 및 `service_desk_email` 메일박스에서 새로운 읽지 않은 이메일을 수집합니다.

### Helm 차트(Kubernetes) {#helm-chart-kubernetes}

[GitLab Helm 차트](https://docs.gitlab.com/charts/)는 여러 하위 차트로 구성되어 있으며 그 중 하나는 [Mailroom 하위 차트](https://docs.gitlab.com/charts/charts/gitlab/mailroom/)입니다. [`incoming_email`에 대한 일반 설정](https://docs.gitlab.com/charts/installation/command-line-options/#incoming-email-configuration)을 구성하고 [`service_desk_email`에 대한 일반 설정](https://docs.gitlab.com/charts/installation/command-line-options/#service-desk-email-configuration)을 구성합니다.

### Linux 패키지(Omnibus) {#linux-package-omnibus}

다중 노드 Linux 패키지 설치 환경에서 `mail_room`을 한 노드에서만 실행합니다. 단일 `rails` 노드(예: `application_role`) 또는 완전히 별도로 실행합니다.

#### 모든 노드 설정 {#set-up-all-nodes}

1. 웹 UI 및 생성된 이메일에서 이메일 주소를 렌더링하기 위해 모든 노드에서 `incoming_email` 및 `service_desk_email`에 대한 기본 구성을 추가합니다.

   `incoming_email` 또는 `service_desk_email` 섹션을 `/etc/gitlab/gitlab.rb`에서 찾습니다:

   {{< tabs >}}

   {{< tab title="`incoming_email`" >}}

   ```ruby
   gitlab_rails['incoming_email_enabled'] = true
   gitlab_rails['incoming_email_address'] = "incoming+%{key}@example.com"
   ```

   {{< /tab >}}

   {{< tab title="`service_desk_email`" >}}

   ```ruby
   gitlab_rails['service_desk_email_enabled'] = true
   gitlab_rails['service_desk_email_address'] = "project_contact+%{key}@example.com"
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. GitLab은 `mail_room`에서 GitLab 애플리케이션으로 이메일을 전송하는 두 가지 방법을 제공합니다. 각 이메일 설정에 대해 `delivery_method`를 구성할 수 있습니다:
   1. 권장 사항(기본): `webhook`은 GitLab 애플리케이션에 API POST 요청으로 이메일 페이로드를 전송합니다. 공유 토큰을 사용하여 인증합니다. 이 방법을 선택하면 `mail_room` 프로세스가 API 엔드포인트에 액세스할 수 있고 모든 애플리케이션 노드에 공유 토큰을 배포할 수 있는지 확인합니다.

      {{< tabs >}}

      {{< tab title="`incoming_email`" >}}

      ```ruby
      gitlab_rails['incoming_email_delivery_method'] = "webhook"

      # The URL that mail_room can contact. You can also use an internal URL or IP,
      # just make sure mail_room can access the GitLab API with that address.
      # Do not end with "/".
      gitlab_rails['incoming_email_gitlab_url'] = "https://gitlab.example.com"

      # The shared secret file that should contain a random token. Make sure it's the same on every node.
      gitlab_rails['incoming_email_secret_file'] = ".gitlab_mailroom_secret"
      ```

      {{< /tab >}}

      {{< tab title="`service_desk_email`" >}}

      ```ruby
      gitlab_rails['service_desk_email_delivery_method'] = "webhook"

      # The URL that mail_room can contact. You can also use an internal URL or IP,
      # just make sure mail_room can access the GitLab API with that address.
      # Do not end with "/".

      gitlab_rails['service_desk_email_gitlab_url'] = "https://gitlab.example.com"

      # The shared secret file that should contain a random token. Make sure it's the same on every node.
      gitlab_rails['service_desk_email_secret_file'] = ".gitlab_mailroom_secret"
      ```

      {{< /tab >}}

      {{< /tabs >}}

   1. `webhook` 설정에 문제가 발생하면 `sidekiq`을 사용하여 이메일 페이로드를 Redis를 사용하여 GitLab Sidekiq에 직접 전달합니다.

      {{< tabs >}}

      {{< tab title="`incoming_email`" >}}

      ```ruby
      # It uses the Redis configuration to directly add Sidekiq jobs
      gitlab_rails['incoming_email_delivery_method'] = "sidekiq"
      ```

      {{< /tab >}}

      {{< tab title="`service_desk_email`" >}}

      ```ruby
      # It uses the Redis configuration to directly add Sidekiq jobs
      gitlab_rails['service_desk_email_delivery_method'] = "sidekiq"
      ```

      {{< /tab >}}

      {{< /tabs >}}

1. 이메일 수집을 실행하지 않아야 하는 모든 노드에서 `mail_room`을 비활성화합니다. 예를 들어 `/etc/gitlab/gitlab.rb`에서:

   ```ruby
   mailroom['enable'] = false
   ```

1. 변경 사항이 적용되도록 [GitLab 재구성](../../../administration/restart_gitlab.md)합니다.

#### 단일 이메일 수집 노드 설정 {#set-up-a-single-email-ingestion-node}

모든 노드를 설정하고 `mail_room` 프로세스를 비활성화한 후 `mail_room`를 단일 노드에서 활성화합니다. 이 노드는 `incoming_email` 및 `service_desk_email` 메일박스를 정기적으로 폴링하고 새로운 읽지 않은 이메일을 GitLab으로 이동합니다.

1. 이메일 수집을 추가로 처리하는 기존 노드를 선택합니다.
1. `incoming_email` 및 `service_desk_email`에 대한 [전체 구성 및 자격 증명](../../../administration/incoming_email.md#configuration-examples)을 추가합니다.
1. 이 노드에서 `mail_room`를 활성화합니다. 예를 들어 `/etc/gitlab/gitlab.rb`에서:

   ```ruby
   mailroom['enable'] = true
   ```

1. 변경 사항이 적용되도록 이 노드에서 [GitLab 재구성](../../../administration/restart_gitlab.md)합니다.

## 여러 프로젝트에 대해 Service Desk 비활성화 {#turn-off-service-desk-for-multiple-projects}

네임스페이스의 많은 프로젝트에서 Service Desk를 비활성화하려면 [API](../../../api/projects.md#turn-off-service-desk-for-multiple-projects)를 사용하거나 GitLab Self-Managed의 경우 [Rails 콘솔](../../../administration/operations/rails_console.md#starting-a-rails-console-session)을 사용합니다.

그룹 또는 네임스페이스의 프로젝트에 대해 Service Desk를 비활성화한 후 다음이 적용됩니다:

- 프로젝트 멤버는 Service Desk를 다시 활성화할 수 있습니다.
- 나중에 생성하는 프로젝트는 기본적으로 Service Desk가 활성 상태로 설정됩니다.

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 잘못된 조건에서 실행되면 손상을 일으킬 수 있습니다. 항상 먼저 테스트 환경에서 명령을 실행하고 복원할 준비가 된 백업 인스턴스를 준비합니다.

네임스페이스의 모든 프로젝트에 대해 Service Desk를 비활성화하려면 다음 명령을 실행합니다. `my-namespace`을 그룹 또는 개인 네임스페이스의 전체 경로로 바꿉니다.

```ruby
namespace = Namespace.find_by_full_path!('my-namespace')
scope = namespace.is_a?(Group) ? namespace.all_projects : namespace.projects

scope.where(service_desk_enabled: true).each_batch(of: 100) do |batch|
  batch.update_all(service_desk_enabled: false)
end
```

일부 프로젝트에 대해 Service Desk를 활성 상태로 유지하려면 프로젝트 ID를 제외합니다:

```ruby
keep_ids = [42, 1337]
namespace = Namespace.find_by_full_path!('my-namespace')
scope = namespace.is_a?(Group) ? namespace.all_projects : namespace.projects

scope.where(service_desk_enabled: true).where.not(id: keep_ids).each_batch(of: 100) do |batch|
  batch.update_all(service_desk_enabled: false)
end
```
