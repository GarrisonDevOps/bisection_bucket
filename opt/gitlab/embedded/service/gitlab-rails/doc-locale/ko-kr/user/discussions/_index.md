---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 댓글 및 스레드
description: 댓글과 스레드를 사용하여 작업 항목 대화를 논의하고 관리합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Wiki 페이지의 댓글과 스레드가 GitLab 17.7에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/14461)되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `wiki_comments`를 사용합니다. 기본적으로 비활성화되었습니다.
- Wiki 페이지의 댓글과 스레드가 GitLab 17.9에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/502847)해졌습니다. 기능 플래그 `wiki_comments`이 제거되었습니다.

{{< /history >}}

GitLab은 댓글, 스레드 및 [코드 변경 제안](../project/merge_requests/reviews/suggestions.md)을 통한 소통을 권장합니다. 댓글은 [Markdown](../markdown.md) 및 [빠른 작업](../project/quick_actions.md)을 지원합니다.

두 가지 유형의 댓글을 사용할 수 있습니다:

- 표준 댓글입니다.
- [해결](../project/merge_requests/_index.md#manage-comment-threads)할 수 있는 스레드의 댓글입니다.

커밋 diff 댓글에서 [코드 변경을 제안](../project/merge_requests/reviews/suggestions.md)할 수 있으며, 사용자는 사용자 인터페이스를 통해 이를 수락할 수 있습니다.

## 댓글을 추가할 수 있는 위치 {#places-you-can-add-comments}

다음과 같은 위치에서 댓글을 만들 수 있습니다:

- 커밋 diff입니다.
- 커밋입니다.
- 디자인입니다.
- 에픽.
- 이슈.
- 병합 요청.
- 스니펫입니다.
- 작업입니다.
- OKR입니다.
- 위키 페이지.

각 객체는 최대 5,000개의 댓글을 가질 수 있습니다.

## 멘션 {#mentions}

GitLab 인스턴스에서 `@username` 또는 `@groupname`을(를) 사용하여 사용자 또는 그룹([서브그룹](../group/subgroups/_index.md#mention-subgroups) 포함)을 멘션할 수 있습니다. GitLab은 언급된 모든 사용자에게 할 일 항목 및 이메일로 알립니다. 사용자는 [알림 설정](../profile/notifications.md)에서 이 설정을 변경할 수 있습니다.

GitLab이 자신의 멘션(현재 인증된 사용자)을 다른 색상으로 강조 표시하므로 어떤 댓글이 자신을 포함하는지 빠르게 확인할 수 있습니다.

작업 항목 또는 병합 요청에서 누군가를 멘션하면, 그들은 [참여자](../participants.md)가 됩니다.

### 모든 멤버 멘션 {#mentioning-all-members}

{{< history >}}

- [플래그](../../administration/feature_flags/_index.md) `disable_all_mention`가 GitLab 16.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110586)되었습니다. GitLab.com에서 사용으로 설정되었습니다. GitLab Self-Managed 및 GitLab Dedicated에서는 비활성화됩니다.
- GitLab 18.8.5에서 [GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/work_items/415280)되었습니다.
- GitLab 19.0에서 기능 플래그 `disable_all_mention`가 [제거](https://gitlab.com/gitlab-org/gitlab/-/work_items/415280)되었습니다.

{{< /history >}}

댓글과 설명에서 `@all` 멘션을 피하세요. `@all`는 프로젝트, 이슈 또는 병합 요청의 참여자뿐만 아니라 해당 프로젝트의 상위 그룹의 모든 멤버를 멘션합니다. 이러한 모든 사용자는 이메일 알림과 할 일 항목을 받으며, 스팸으로 해석할 수 있습니다.

댓글과 설명에서 `@all`을(를) 입력하면 모든 사용자를 멘션하는 대신 일반 텍스트가 됩니다. 이 변경 전의 Markdown 텍스트의 기존 `@all` 멘션은 변경되지 않으며 링크로 유지됩니다.

[그룹 설정](../group/manage.md#disable-email-notifications)에서 알림 및 멘션을 비활성화할 수 있습니다.

### 이슈 또는 병합 요청에서 그룹 멘션 {#mention-a-group-in-an-issue-or-merge-request}

댓글에서 그룹을 멘션하면, 그룹의 모든 멤버가 할 일 목록에 할 일 항목을 추가받습니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 병합 요청 또는 이슈로 이동합니다:
   - 병합 요청의 경우 **코드** > **병합 요청**을 선택하고 병합 요청을 찾습니다.
   - 이슈의 경우 **계획** > **작업 항목**을 선택하고 이슈를 찾습니다.
1. 댓글에서 `@`을(를) 입력한 후 사용자, 그룹 또는 서브그룹 네임스페이스를 입력합니다. 예를 들어 `@alex`, `@alex-team` 또는 `@alex-team/marketing`입니다.
1. **댓글**을 선택합니다.

GitLab은 모든 그룹 및 서브그룹 멤버에 대한 할 일 항목을 만듭니다.

자세한 내용은 [서브그룹 멘션](../group/subgroups/_index.md#mention-subgroups)을 참조하세요.

## 병합 요청 diff에 댓글 추가 {#add-a-comment-to-a-merge-request-diff}

병합 요청 diff에 댓글을 추가하면 다음과 같은 경우에도 이러한 댓글이 유지됩니다:

- 리베이스 후 강제 푸시입니다.
- 커밋을 수정합니다.

커밋 diff 댓글을 추가하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**을 선택하고 병합 요청을 찾습니다.
1. **커밋** 탭을 선택한 다음 커밋 메시지를 선택합니다.
1. 댓글을 시작합니다:
   - 전체 파일에 댓글을 달려면 댓글을 달고자 하는 파일을 찾고 파일 헤더에서 **이 파일에 댓글 달기** ({{< icon name="comment" >}})를 선택합니다.
   - 댓글을 달고자 하는 특정 줄의 줄 번호를 찾습니다. 줄 번호 위로 마우스를 이동한 다음 **댓글** ({{< icon name="comment" >}})를 선택합니다. 더 많은 줄을 선택하려면 **댓글** ({{< icon name="comment" >}}) 아이콘을 드래그합니다.
     - 댓글 양식이 나타나면 [선택된 줄의 범위를 변경](#edit-the-comment-line-range)할 수 있습니다.
1. 댓글을 입력합니다.
1. 댓글을 제출합니다:
   - 댓글을 즉시 추가하려면 **댓글 추가**를 선택하거나 다음 키보드 단축키를 사용합니다:
     - macOS: <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>Enter</kbd>
     - 기타 OS: <kbd>Shift</kbd>+<kbd>Control</kbd>+<kbd>Enter</kbd>
   - 리뷰를 마칠 때까지 댓글을 게시하지 않으려면 **리뷰 시작**을 선택하거나 키보드 바로 가기를 사용합니다:
     - macOS: <kbd>Command</kbd>+<kbd>Enter</kbd>
     - 기타 OS: <kbd>Control</kbd>+<kbd>Enter</kbd>

댓글이 병합 요청의 **개요** 탭에 표시됩니다.

댓글이 프로젝트의 **코드** > **커밋** 페이지에 표시되지 않습니다.

> [!note]
> 댓글에 병합 요청에 포함된 커밋에 대한 참조가 포함되어 있으면 병합 요청의 컨텍스트에서 링크로 변환됩니다. 예를 들어 `28719b171a056960dfdc0012b625d0b47b123196`는 `https://gitlab.example.com/example-group/example-project/-/merge_requests/12345/diffs?commit_id=28719b171a056960dfdc0012b625d0b47b123196`에 대한 링크인 `28719b17`가 됩니다.

### 댓글 줄 범위 수정 {#edit-the-comment-line-range}

{{< history >}}

- GitLab 19.3에서 [플래그](../../administration/feature_flags/_index.md) `rapid_diffs_on_mr_show`과(와) 함께 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/242736)되었습니다. 기본적으로 활성화됩니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

[빠른 diff](../project/merge_requests/changes.md#rapid-diffs)가 켜져 있는 병합 요청에서 댓글 양식이 열려 있으면 댓글이 적용되는 줄을 변경할 수 있습니다.

첫 번째 댓글을 만들 때만 줄 범위를 변경할 수 있습니다. 저장 후에는 옵션을 사용할 수 없습니다.

댓글 양식을 연 후 댓글 줄 범위를 조정하려면:

1. **라인 범위 수정** ({{< icon name="pencil" >}})을(를) 선택하여 편집을 시작합니다. 범위의 첫 번째 줄에 핸들과 취소 버튼이 나타나고, 포커스를 받는 다른 핸들이 마지막 줄에 나타납니다.
1. 마우스 또는 키보드를 사용하여 범위를 조정합니다.
   - 마우스를 사용하여 핸들 중 하나를 새 줄로 드래그합니다.
   - 키보드를 사용하여 다음 키를 사용합니다:

     | 키 | 작업 |
     |-----|--------|
     | <kbd>왼쪽</kbd> | 포커스를 첫 번째 줄 핸들로 이동합니다. |
     | <kbd>오른쪽</kbd> | 포커스를 마지막 줄 핸들로 이동합니다. |
     | <kbd>위</kbd> | 포커스된 핸들을 위로 이동하여 댓글을 달 수 있는 이전 줄로 이동합니다. |
     | <kbd>아래</kbd> | 포커스된 핸들을 아래로 이동하여 댓글을 달 수 있는 다음 줄로 이동합니다. |
     | <kbd>Enter</kbd> | 새 범위를 확인합니다. |
     | <kbd>Escape</kbd> | 편집을 취소하고 이전 범위를 유지합니다. |

핸들은 `@@` 구문으로 표시되는 diff의 섹션 구분을 지나 이동할 수 없습니다. 섹션을 넘어 댓글을 달려면 각 섹션에 별도의 댓글을 추가합니다.

## 이메일을 보내 댓글에 응답 {#reply-to-a-comment-by-sending-email}

["이메일로 응답"](../../administration/reply_by_email.md)을 구성한 경우, 이메일을 보내 댓글에 응답할 수 있습니다.

- 표준 댓글에 응답하면 다른 표준 댓글이 생성됩니다.
- 스레드된 댓글에 응답하면 스레드의 응답이 생성됩니다.
- [이슈 이메일 주소로 이메일을 보내면](../project/issues/managing_issues.md#copy-issue-email-address) 표준 댓글이 생성됩니다.

이메일 응답에서 [Markdown](../markdown.md) 및 [빠른 작업](../project/quick_actions.md)을 사용할 수 있습니다.

### 댓글 답장 만료 {#comment-reply-expiration}

표준 또는 스레드된 댓글을 만드는 이메일 응답은 2년 [보관 정책](../../administration/reply_by_email.md#retention-policy-for-notifications)을 준수합니다.

## 댓글 편집 {#edit-a-comment}

언제든지 자신의 댓글을 편집할 수 있습니다. 유지 관리자 또는 소유자 역할을 가진 사람은 다른 사람이 작성한 댓글을 편집할 수도 있습니다.

댓글을 편집하려면:

1. 댓글에서 **댓글 편집** ({{< icon name="pencil" >}})을(를) 선택합니다.
1. 편집을 수행합니다.
1. **변경 사항 저장**을 선택합니다.

### 댓글을 편집하여 멘션 추가 {#edit-a-comment-to-add-a-mention}

{{< history >}}

- 알림 이메일 전송이 GitLab 18.10에서 [기능 플래그](../../administration/feature_flags/_index.md) `email_on_added_mentions`과(와) 함께 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224837)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.11에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/591869)되었습니다. 기능 플래그 `email_on_added_mentions`이 제거되었습니다.

{{< /history >}}

기본적으로 사용자를 멘션하면 GitLab은 해당 사용자에 대한 [할 일 항목을 만들고](../todos.md#actions-that-create-to-do-items) [알림 이메일](../profile/notifications.md)을 보냅니다.

기존 댓글을 편집하여 이전에 없었던 사용자 멘션을 추가하면 GitLab은 다음을 수행합니다:

- 언급된 사용자에 대한 할 일 항목을 만듭니다.
- 언급된 사용자에게 알림 이메일을 보냅니다.

## 토론을 잠금으로써 댓글 방지 {#prevent-comments-by-locking-the-discussion}

이슈 또는 병합 요청에서 공개 댓글을 방지할 수 있습니다. 이렇게 하면 프로젝트 멤버만 댓글을 추가하고 편집할 수 있습니다.

사전 요구 사항:

- 병합 요청에서는 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 이슈에서는 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

이슈 또는 병합 요청을 잠그려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 병합 요청 또는 이슈로 이동합니다:
   - 병합 요청의 경우 **코드** > **병합 요청**을 선택하고 병합 요청을 찾습니다.
   - 이슈의 경우 **계획** > **작업 항목**을 선택하고 이슈를 찾습니다.
1. 오른쪽 위 모서리에서 **병합 요청 동작** 또는 **이슈 동작** ({{< icon name="ellipsis_v" >}})을(를) 선택한 다음 **토론 잠금**을 선택합니다.

GitLab은 페이지 세부 정보에 시스템 노트를 추가합니다.

이슈 또는 병합 요청을 다시 열기 전에 닫힌 이슈 또는 병합 요청의 모든 잠긴 토론을 잠금 해제해야 합니다.

## 기밀 항목의 댓글 {#comments-on-confidential-items}

기밀 항목에 액세스할 권한이 있는 사용자만 항목의 댓글에 대한 알림을 받습니다. 항목이 이전에 기밀이 아니었다면 액세스 권한이 없는 사용자가 참여자로 나타날 수 있습니다. 이 사용자는 항목이 기밀일 때 알림을 받지 않습니다.

알림을 받을 수 있는 사람:

- 역할에 관계없이 항목에 할당된 사용자입니다.
- 게스트, 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있는 경우 항목을 작성한 사용자입니다.
- 항목이 속한 그룹 또는 프로젝트에서 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할을 가진 사용자입니다.

## 내부 노트 추가 {#add-an-internal-note}

{{< history >}}

- GitLab 18.2에서 GitLab Wiki에 대해 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/538003)되었습니다.

{{< /history >}}

내부 노트를 사용하여 공개 이슈, 에픽, wiki 페이지 또는 병합 요청에 추가된 정보를 보호합니다. 내부 노트는 공개 댓글과 다릅니다:

- 최소한 보고자 역할을 가진 프로젝트 멤버만 내부 노트를 볼 수 있습니다.
- 내부 노트를 일반 댓글로 변환할 수 없습니다.
- 내부 노트에 대한 모든 응답도 내부입니다.
- 내부 노트는 **내부 노트** 배지를 표시하고 공개 댓글과 다른 색상으로 표시됩니다:

![내부 노트](img/add_internal_note_v16_9.png)

사전 요구 사항:

- 프로젝트의 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

내부 노트를 추가하려면:

1. 이슈, 에픽, wiki 페이지 또는 병합 요청의 **댓글** 텍스트 상자에 댓글을 입력합니다.
1. 댓글 아래에서 **내부 메모로 만들기**를 선택합니다.
1. **내부 노트 추가**를 선택합니다.

전체 [이슈를 기밀로 표시](../project/issues/confidential_issues.md)하거나 [기밀 병합 요청](../project/merge_requests/confidential.md)을 만들 수도 있습니다.

## 댓글만 보기 {#show-only-comments}

많은 댓글이 있는 논의에서 댓글만 표시하거나 변경 이력([시스템 노트](../project/system_notes.md))을 필터링합니다. 시스템 노트에는 설명, 다른 GitLab 객체의 멘션 또는 레이블, 할당자 및 마일스톤의 변경이 포함됩니다. GitLab은 사용자의 기본 설정을 저장하고 보는 모든 이슈, 병합 요청 또는 에픽에 적용합니다.

1. 병합 요청, 이슈 또는 에픽에서 **개요** 탭을 선택합니다.
1. 페이지의 오른쪽에서 **정렬 또는 필터링** 드롭다운 목록에서 필터를 선택합니다:
   - **모든 활동 보기**: 모든 사용자 댓글 및 시스템 노트를 표시합니다.
   - **댓글만 보기**: 사용자 댓글만 표시합니다.
   - **이력만 표시**: 활동 노트만 표시합니다.

## 활동 정렬 순서 변경 {#change-activity-sort-order}

기본 순서를 반대로 하고 맨 위에 가장 최근 항목이 정렬된 활동 피드와 상호 작용합니다. GitLab은 사용자의 기본 설정을 로컬 스토리지에 저장하고 보는 모든 이슈, 병합 요청 또는 에픽에 적용합니다. 이슈와 에픽은 동일한 정렬 기본 설정을 공유하지만 병합 요청은 자신의 별도 기본 설정을 유지합니다.

활동 정렬 순서를 변경하려면:

1. 이슈를 열거나 병합 요청 또는 에픽에서 **개요** 탭을 엽니다.
1. **활동** 제목까지 아래로 스크롤합니다.
1. 페이지의 오른쪽에서 정렬 순서를 변경합니다:
   - **이슈 및 에픽**: **정렬 또는 필터링** 드롭다운 목록에서 **최신순** 또는 **가장 오래된 것부터** (기본값)를 선택합니다.
   - **병합 요청**: 정렬 방향 화살표 버튼을 사용하여 **정렬 방향: 오름차순** (가장 오래된 것부터, 기본값) 또는 **정렬 방향: 내림차순** (최신순) 간을 전환합니다.

## 설명 변경 이력 보기 {#view-description-change-history}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이력에 나열된 설명 변경 사항을 볼 수 있습니다.

변경 사항을 비교하려면 **이전 버전과 비교**를 선택합니다.

## 이슈를 댓글 작성자에게 지정 {#assign-an-issue-to-the-commenting-user}

댓글을 작성한 사용자에게 이슈를 할당할 수 있습니다.

1. 댓글에서 **추가 작업** ({{< icon name="ellipsis_v" >}}) 메뉴를 선택합니다.
1. **댓글 작성자 지정**을 선택합니다.
1. 댓글 작성자를 할당 해제하려면 버튼을 다시 선택합니다.

## 표준 댓글에 응답하여 스레드 생성 {#create-a-thread-by-replying-to-a-standard-comment}

표준 댓글에 응답하면 스레드를 만듭니다.

사전 요구 사항:

- 게스트, 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 이슈, 병합 요청 또는 에픽에 있어야 합니다. 커밋 및 스니펫의 스레드는 지원되지 않습니다.

댓글에 응답하여 스레드를 만들려면:

1. 댓글의 오른쪽 위 모서리에서 **댓글에 답글** ({{< icon name="reply" >}})을(를) 선택하여 응답 섹션을 표시합니다.
1. 응답을 입력합니다.
1. **답장** 또는 **댓글 추가** (UI의 응답 위치에 따라 다름)을 선택합니다.

GitLab은 상위 댓글을 스레드로 변환합니다.

## 댓글에 응답하지 않고 스레드 생성 {#create-a-thread-without-replying-to-a-comment}

표준 댓글에 응답하지 않고도 스레드를 만들 수 있습니다.

사전 요구 사항:

- 게스트, 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 이슈, 병합 요청, 커밋 또는 스니펫에 있어야 합니다.

스레드를 만들려면:

1. 댓글을 입력합니다.
1. 댓글 아래에서 **댓글**의 오른쪽에 있는 아래쪽 화살표 ({{< icon name="chevron-down" >}})를 선택합니다.
1. 목록에서 **스레드 시작**을 선택합니다.
1. **스레드 시작**을 다시 선택합니다.

![스레드 생성](img/create_thread_v16_6.png)

## 스레드 해결 {#resolve-a-thread}

{{< history >}}

- 작업, 목표 및 핵심 결과에 대한 해결 가능한 스레드가 GitLab 17.3에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/458818)해졌습니다.
- 에픽을 위한 해결 가능한 스레드:
  - GitLab 17.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/458818)되었습니다. [에픽의 새로운 모양](../group/epics/_index.md#epics-as-work-items)을 활성화해야 합니다.
  - GitLab 18.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/468310)하게 되었습니다.

{{< /history >}}

대화가 완료되면 스레드를 해결할 수 있습니다. 해결된 스레드는 축소되지만 사용자는 여전히 댓글을 추가할 수 있습니다.

스레드를 해결할 수 있는 권한이 있는 모든 사용자가 해결된 스레드를 나중에 다시 열 수 있습니다. 해결된 스레드를 다시 열려면 스레드를 확장하고 **스레드 다시 열기**를 선택합니다.

사전 요구 사항:

- 에픽, 이슈, 작업, 목표, 핵심 결과 또는 병합 요청에 있어야 합니다.
- 개발자, 유지 관리자 또는 소유자 역할이 있거나 이슈 또는 병합 요청의 작성자여야 합니다.

스레드를 해결하려면:

1. 스레드로 이동합니다.
1. 다음 중 하나를 수행합니다:
   - 원본 댓글의 오른쪽 위 모서리에서 **스레드 해결** ({{< icon name="check-circle" >}})을(를) 선택합니다.
   - 마지막 응답 아래의 **답장** 필드에서 **스레드 해결**을 선택합니다.
   - 마지막 응답 아래의 **답장** 필드에서 텍스트를 입력하고 **스레드 해결** 확인란을 선택한 다음 **댓글 추가**를 선택합니다.

동일한 작업을 수행하여 스레드를 다시 열 수 있습니다.

병합 요청은 더 유연한 [스레드 관리 옵션](../project/merge_requests/_index.md#manage-comment-threads)을 제공합니다:

- 열린 스레드를 새 이슈로 이동합니다.
- 모든 스레드가 해결될 때까지 병합을 방지합니다.

## GitLab Duo Chat으로 이슈 논의 요약 {#summarize-issue-discussions-with-gitlab-duo-chat}

{{< details >}}

- 티어: Premium, Ultimate
- 추가 기능: GitLab Duo Enterprise, GitLab Duo with Amazon Q
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="모델 정보" >}}

- [기본 LLM](../gitlab_duo/model_selection.md#default-models)
- Amazon Q용 LLM: Amazon Q Developer
- [자체 호스팅 모델이 포함된 GitLab Duo](../../administration/gitlab_duo_self_hosted/_index.md)에서 사용 가능

{{< /collapsible >}}

{{< history >}}

- GitLab 17.3에서 GitLab Duo로 [베타](../../policy/development_stages_support.md#beta)로 [이동](https://gitlab.com/gitlab-org/gitlab/-/issues/454550)되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `summarize_notes_with_duo`가 있습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.4에서 [기본적으로 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/162122)되었습니다.
- GitLab 17.6 이상에서 GitLab Duo 애드온을 요구하도록 변경되었습니다.
- GitLab 18.0에서 Premium 계층을 포함하도록 변경되었습니다.

{{< /history >}}

이슈에 대한 논의 요약을 생성합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> [개요 보기](https://www.youtube.com/watch?v=IcdxLfTIUgc)
<!-- Video published on 2024-03-28 -->

사전 요구 사항:

- 이슈를 볼 수 있는 권한이 있어야 합니다.

이슈 논의 요약을 생성하려면:

1. 이슈에서 **활동** 섹션까지 스크롤합니다.
1. **요약 보기**를 선택합니다.

이슈의 댓글이 최대 10개의 목록 항목으로 요약됩니다. 응답을 기반으로 후속 질문을 할 수 있습니다.

데이터 사용: 이 기능을 사용하면 이슈의 모든 댓글 텍스트가 대규모 언어 모델로 전송됩니다.
