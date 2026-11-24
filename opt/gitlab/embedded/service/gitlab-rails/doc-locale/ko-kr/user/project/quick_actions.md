---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 빠른 작업
description: "명령어, 단축키 및 인라인 작업입니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

빠른 작업은 GitLab의 일반적인 작업을 위한 텍스트 기반 단축키를 제공합니다. 빠른 작업:

- 사용자 인터페이스를 사용하지 않고 일반적인 작업을 실행합니다.
- 이슈, 머지 리퀘스트, 에픽 및 커밋 작업을 지원합니다.
- 설명 또는 댓글을 저장할 때 자동으로 실행됩니다.
- 특정 컨텍스트 및 조건에 응답합니다.
- 여러 명령어를 별도의 줄에 입력할 때 처리합니다.

예를 들어 빠른 작업을 사용하여 다음을 수행할 수 있습니다:

- 사용자를 할당합니다.
- 레이블을 추가합니다.
- 기한을 설정합니다.
- 상태를 변경합니다.
- 다른 속성을 설정합니다.

각 명령어는 슬래시(`/`)로 시작하고 별도의 줄에 입력해야 합니다. 많은 빠른 작업은 따옴표(`"`) 또는 특정 형식으로 입력할 수 있는 매개변수를 허용합니다.

## 매개변수 {#parameters}

많은 빠른 작업에는 매개변수가 필요합니다. 예를 들어 `/assign` 빠른 작업에는 사용자 이름이 필요합니다. GitLab은 [자동완성 문자](autocomplete_characters.md)를 빠른 작업과 함께 사용하여 사용자가 매개변수를 입력할 때 사용 가능한 값 목록을 제공합니다.

매개변수를 수동으로 입력하는 경우 큰따옴표(`"`)로 묶어야 합니다. 다음 문자만 포함하지 않는 한:

- ASCII 문자
- 숫자(0-9)
- 밑줄(`_`), 하이픈(`-`), 물음표(`?`), 마침표(`.`), 앰퍼샌드(`&`) 또는 at(`@`)

매개변수는 대소문자를 구분합니다. 자동완성은 이를 자동으로 처리하고 따옴표를 삽입합니다.

## 빠른 작업 {#quick-actions}

{{< history >}}

- 에픽을 작업 항목으로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/468310)했습니다(GitLab 18.1).
- `/cc` 빠른 작업을 GitLab 18.3에서 [제거](https://gitlab.com/gitlab-org/gitlab/-/issues/369571)했습니다.

{{< /history >}}

다음 빠른 작업은 설명, 토론 및 스레드에 적용됩니다. 일부 빠른 작업은 모든 구독 티어에서 사용할 수 없을 수 있습니다.

### `add_child` {#add_child}

하나 이상의 항목을 하위 항목으로 추가합니다.

가용성:

- 에픽 (이슈, 작업, 목표 또는 핵심 결과 추가)
- 이슈 (작업, 목표 또는 핵심 결과 추가)
- 목표 (목표 또는 핵심 결과 추가)

매개변수:

- `<item>`: 하위 항목으로 추가할 항목입니다. 값은 `#item`, `group/project#item` 또는 항목의 URL 형식이어야 합니다. 여러 작업 항목을 동시에 하위 항목으로 추가할 수 있습니다.

예:

- 단일 하위 항목 추가:

  ```plaintext
  /add_child #123
  ```

- 여러 하위 항목 추가:

  ```plaintext
  /add_child #123 #456 group/project#789
  ```

- URL을 사용하여 하위 항목 추가:

  ```plaintext
  /add_child https://gitlab.com/group/project/-/work_items/123
  ```

### `add_contacts` {#add_contacts}

하나 이상의 활성 CRM 연락처를 추가합니다.

가용성:

- 이슈

매개변수:

- `[contact:email1@example.com]`: `contact:email@example.com` 형식의 하나 이상의 연락처 이메일입니다.

예:

- 단일 연락처 추가:

  ```plaintext
  /add_contacts [contact:alex@example.com]
  ```

- 여러 연락처 추가:

  ```plaintext
  /add_contacts [contact:alex@example.com] [contact:sam@example.com]
  ```

추가 세부정보:

- 자세한 내용은 [CRM 연락처](../crm/_index.md)를 참조하세요.

### `add_email` {#add_email}

{{< history >}}

- GitLab 18.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/350460)합니다. 기능 플래그 `issue_email_participants`이 제거되었습니다.

{{< /history >}}

최대 6개의 이메일 참여자를 추가합니다.

가용성:

- 인시던트
- 이슈

매개변수:

- `email1 email2`: 공백으로 구분된 하나 이상의 이메일 주소입니다.

예:

- 단일 이메일 참여자 추가:

  ```plaintext
  /add_email alex@example.com
  ```

- 여러 이메일 참여자 추가:

  ```plaintext
  /add_email alex@example.com sam@example.com
  ```

추가 세부정보:

- [이슈 템플릿](description_templates.md)에서는 지원되지 않습니다.
- 자세한 내용은 [이메일 참여자](service_desk/external_participants.md)를 참조하세요.

### `approve` {#approve}

머지 리퀘스트를 승인합니다.

가용성:

- 머지 리퀘스트

예:

- 머지 리퀘스트 승인:

  ```plaintext
  /approve
  ```

추가 세부정보:

- 머지 리퀘스트를 승인 취소하려면 [`/unapprove`](#unapprove)를 사용하세요.

### `assign` {#assign}

{{< history >}}

- GitLab 18.2에서 에픽에 대해 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/551805)되었습니다.

{{< /history >}}

작업 항목에 하나 이상의 사용자를 할당합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

매개변수:

- `@user1 @user2`: 할당할 하나 이상의 사용자 이름입니다. 사용자 이름 앞에 `@`를 붙여야 합니다.
- `me`: 작업 항목에 자신을 할당합니다.

예:

- 단일 사용자 할당:

  ```plaintext
  /assign @alex
  ```

- 여러 사용자 할당:

  ```plaintext
  /assign @alex @sam
  ```

- 자신 할당:

  ```plaintext
  /assign me
  ```

추가 세부정보:

- GitLab Premium 및 Ultimate에서는 사용자 이름을 공백으로 구분하여 단일 명령어로 여러 사용자를 할당할 수 있습니다. GitLab Free에서는 지정된 사용자 중 하나만 할당됩니다. 자세한 내용은 [여러 할당자](issues/multiple_assignees_for_issues.md)를 참조하세요.
- 할당자를 제거하려면 [`/unassign`](#unassign)를 사용하세요.
- 할당자를 바꾸려면 [`/reassign`](#reassign)를 사용하세요.

### `assign_reviewer` {#assign_reviewer}

하나 이상의 사용자를 검토자로 할당하거나 기존 검토자에게 새로운 검토를 요청합니다.

[`/request_review`](#request_review)의 별칭입니다.

가용성:

- 머지 리퀘스트

매개변수:

- `@user1 @user2`: 검토자로 할당할 하나 이상의 사용자 이름입니다. 사용자 이름 앞에 `@`를 붙여야 합니다.
- `me`: 자신을 검토자로 할당합니다.

예:

- 단일 검토자 할당:

  ```plaintext
  /assign_reviewer @alex
  ```

- 여러 검토자 할당:

  ```plaintext
  /assign_reviewer @alex @sam
  ```

- 자신을 검토자로 할당:

  ```plaintext
  /assign_reviewer me
  ```

추가 세부정보:

- 사용자가 아직 검토자가 아니면 검토자로 할당합니다.
- 사용자가 이미 검토자인 경우 새로운 검토를 요청합니다(검토 상태를 재설정하고 알림을 보냅니다).
- 사용자 이름을 공백으로 구분하여 단일 명령어로 여러 사용자를 할당할 수 있습니다.
- `/reviewer`도 이 명령어의 별칭입니다.
- 검토자를 바꾸려면 [`/reassign_reviewer`](#reassign_reviewer)를 사용하세요.
- 검토자를 제거하려면 [`/unassign_reviewer`](#unassign_reviewer)를 사용하세요.
- 자세한 내용은 [`/request_review`](#request_review)를 참조하세요.

### `award` {#award}

이모지 반응을 전환합니다.

가용성:

- 작업
- 목표
- 핵심 결과

매개변수:

- `:emoji:`: 전환할 이모지입니다. `:emoji_name:` 형식이어야 합니다.

예:

- 엄지손가락 올림 반응 전환:

  ```plaintext
  /award :thumbsup:
  ```

- 하트 반응 전환:

  ```plaintext
  /award :heart:
  ```

추가 세부정보:

- `/award`은 `/react`의 별칭입니다.
- 자세한 내용은 [이모지 반응](../emoji_reactions.md)을 참조하세요.

### `blocked_by` {#blocked_by}

항목을 다른 항목으로 차단된 것으로 표시합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트

매개변수:

- `<item1> <item2>`: 이 항목을 차단하는 하나 이상의 항목입니다. 값은 `#item`, `group/project#item` 또는 전체 URL 형식이어야 합니다. 머지 리퀘스트의 경우 `!merge_request`, `group/project!merge_request` 또는 머지 리퀘스트 URL을 사용하세요.

예:

- 단일 항목으로 차단된 것으로 표시:

  ```plaintext
  /blocked_by #123
  ```

- 여러 항목으로 차단된 것으로 표시:

  ```plaintext
  /blocked_by #123 group/project#456
  ```

- URL을 사용하여 차단된 항목으로 표시:

  ```plaintext
  /blocked_by https://gitlab.com/group/project/-/work_items/123
  ```

- 머지 리퀘스트를 다른 머지 리퀘스트로 차단된 것으로 표시:

  ```plaintext
  /blocked_by !456
  ```

추가 세부정보:

- 차단 관계를 제거하려면 [`/unlink`](#unlink)를 사용하세요.
- 항목을 서로 관련된 것으로 표시하되 서로 차단되지 않도록 하려면 [`/relate`](#relate)를 사용하세요.

### `blocks` {#blocks}

항목을 다른 항목을 차단하는 것으로 표시합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트

매개변수:

- `<item1> <item2>`: 이 항목이 차단하는 하나 이상의 항목입니다. 값은 `#item`, `group/project#item` 또는 전체 URL 형식이어야 합니다. 머지 리퀘스트의 경우 `!merge_request`, `group/project!merge_request` 또는 머지 리퀘스트 URL을 사용하세요.

예:

- 단일 항목을 차단하는 것으로 표시:

  ```plaintext
  /blocks #123
  ```

- 여러 항목을 차단하는 것으로 표시:

  ```plaintext
  /blocks #123 group/project#456
  ```

- URL을 사용하여 차단하는 항목으로 표시:

  ```plaintext
  /blocks https://gitlab.com/group/project/-/work_items/123
  ```

- 머지 리퀘스트를 다른 머지 리퀘스트를 차단하는 것으로 표시:

  ```plaintext
  /blocks !456
  ```

추가 세부정보:

- 차단 관계를 제거하려면 [`/unlink`](#unlink)를 사용하세요.
- 항목을 서로 관련된 것으로 표시하되 서로 차단되지 않도록 하려면 [`/relate`](#relate)를 사용하세요.

### `board_move` {#board_move}

보드의 열로 이슈를 이동합니다.

가용성:

- 이슈

매개변수:

- `~column`: 이슈를 이동할 보드 열의 레이블 이름입니다. `~`로 시작해야 합니다.

예:

- 열로 이동:

  ```plaintext
  /board_move ~"In Progress"
  ```

추가 세부정보:

- 프로젝트에는 하나의 이슈 보드만 있어야 합니다.

### `checkin_reminder` {#checkin_reminder}

{{< history >}}

- GitLab 16.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/422761)되었으며 `okrs_mvc` 및 `okr_checkin_reminders` 플래그를 사용합니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

목표에 대한 체크인 미리 알림을 예약합니다.

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

가용성:

- 목표

매개변수:

- `<cadence>`: 미리 알림 주기입니다. 옵션은:
  - `weekly`
  - `twice-monthly`
  - `monthly`
  - `never` (기본값)

예:

- 주간 미리 알림 설정:

  ```plaintext
  /checkin_reminder weekly
  ```

- 미리 알림 끄기:

  ```plaintext
  /checkin_reminder never
  ```

추가 세부정보:

- 자세한 내용은 [OKR 체크인 미리 알림 예약](../okrs.md#schedule-okr-check-in-reminders)을 참조하세요.

### `clear_health_status` {#clear_health_status}

건강 상태를 지웁니다.

가용성:

- 에픽
- 이슈
- 작업
- 목표
- 핵심 결과

예:

- 건강 상태 지우기:

  ```plaintext
  /clear_health_status
  ```

추가 세부정보:

- 자세한 내용은 [건강 상태](issues/managing_issues.md#health-status)를 참조하세요.

### `clear_weight` {#clear_weight}

가중치를 지웁니다.

가용성:

- 이슈
- 작업

예:

- 가중치 지우기:

  ```plaintext
  /clear_weight
  ```

### `clone` {#clone}

작업 항목을 주어진 그룹 또는 프로젝트에 복제합니다.

가용성:

- 에픽
- 인시던트
- 이슈

매개변수:

- `<path/to/group_or_project>`: 대상 그룹 또는 프로젝트의 경로입니다. 제공되지 않으면 현재 프로젝트에 복제합니다.
- `--with_notes`: 복제본에 댓글 및 시스템 메모를 포함하는 선택적 플래그입니다.
- `[type:<work item type>]`(선택 사항): 대상 네임스페이스에서 사용할 작업 항목 유형입니다. 생략하면 소스 작업 항목 유형이 유지됩니다. 다중 단어 유형 이름(예: `Key Result`)은 `]`이 값을 종료하므로 따옴표를 붙이지 않아도 됩니다.

예:

- 다른 프로젝트에 복제:

  ```plaintext
  /clone group/project
  ```

- 현재 프로젝트에 복제:

  ```plaintext
  /clone
  ```

- 메모와 함께 복제:

  ```plaintext
  /clone group/project --with_notes
  ```

- 다른 프로젝트에 복제하고 특정 작업 항목 유형으로 변환:

  ```plaintext
  /clone group/project [type:Issue]
  ```

- 다중 단어 유형 이름으로 복제:

  ```plaintext
  /clone group/project [type:Key Result]
  ```

추가 세부정보:

- 대상에 레이블, 마일스톤 또는 에픽과 같은 동등한 객체가 포함되어 있는 한 최대한 많은 데이터를 복사합니다.
- `--with_notes`이 인수로 제공되지 않는 한 댓글이나 시스템 메모를 복사하지 않습니다.
- 유형이 제공되지 않으면 소스 작업 항목 유형이 유지됩니다. 해당 유형을 대상 네임스페이스에서 사용할 수 없으면 복제에 실패합니다.
- 유형이 제공되면 작업 항목이 해당 유형으로 변환됩니다. 유형을 대상 네임스페이스에서 사용할 수 없으면 복제에 실패합니다.
- `[type:...]` 값이 대상 네임스페이스에서 사용 가능한 작업 항목 유형의 이름과 대소문자를 구분하지 않고 일치합니다.
- 해결된 유형이 대상 네임스페이스에서 꺼져 있으면(보관됨, 관리자가 끔 또는 대상 컨텍스트에서 표시되지 않음) 복제에 실패합니다.
- 동일한 네임스페이스에 복제할 때 `[type:...]` 인수가 유효성 검사되지만 변환이 수행되지 않습니다. 복제본이 소스 작업 항목 유형을 유지합니다.
- 기본 제공 유형(예: `Issue`, `Task`, `Incident`) 간의 기본 유형 변환을 모든 티어에서 사용할 수 있습니다.
- 사용자 지정 작업 항목 유형 및 네임스페이스별 유형 가시성은 GitLab.com의 Premium 및 Ultimate 기능입니다. 구독에서 대상 네임스페이스의 유형을 사용할 수 없으면 복제에 실패하고 오류 메시지에 사용할 수 있는 유형이 나열됩니다.

### `close` {#close}

작업 항목을 닫습니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

예:

- 작업 항목 닫기:

  ```plaintext
  /close
  ```

추가 세부정보:

- 작업 항목을 다시 열려면 [`/reopen`](#reopen)를 사용하세요.

### `confidential` {#confidential}

작업 항목을 비공개로 표시합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 작업
- 목표
- 핵심 결과

예:

- 비공개로 표시:

  ```plaintext
  /confidential
  ```

추가 세부정보:

- 자세한 내용은 [기밀 이슈를 볼 수 있는 사람](issues/confidential_issues.md#who-can-see-confidential-issues), [OKR](../okrs.md#who-can-see-confidential-okrs) 또는 [작업](../tasks.md#who-can-see-confidential-tasks)을 참조하세요.
- 항목을 비공개로 설정하지 않으려면 오른쪽 위 모서리에서 **추가 작업**({{< icon name="ellipsis_v" >}}) 을 선택한 다음 **비공개 해제**를 선택하세요.

### `convert_to_ticket` {#convert_to_ticket}

이슈를 Service Desk 티켓으로 변환합니다.

가용성:

- 인시던트
- 이슈

매개변수:

- `<email address>`: 티켓과 연결할 이메일 주소입니다.

예:

- 티켓으로 변환:

  ```plaintext
  /convert_to_ticket user@example.com
  ```

추가 세부정보:

- 이 빠른 작업은 [Service Desk가 설정](service_desk/configure.md)된 경우에만 프로젝트에서 사용할 수 있습니다. GitLab Self-Managed에서 인스턴스에는 이메일 서브 어드레싱 또는 catch-all 사서함으로 구성된 [수신 이메일](../../administration/incoming_email.md)도 있어야 합니다.
- 자세한 내용은 [일반 이슈를 Service Desk 티켓으로 변환](service_desk/using_service_desk.md#convert-a-regular-issue-to-a-service-desk-ticket)을 참조하세요.

### `copy_metadata` {#copy_metadata}

{{< history >}}

- GitLab 17.9에서 작업, 목표 및 핵심 결과에 대해 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/509076)되었습니다.

{{< /history >}}

다른 항목에서 레이블 및 마일스톤을 복사합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

매개변수:

- `<#item>`: 메타데이터를 복사할 항목입니다. 머지 리퀘스트의 경우 `!MR_IID` 형식을 사용하세요. 다른 항목의 경우 `#item` 또는 URL을 사용하세요.

예:

- 이슈에서 메타데이터 복사:

  ```plaintext
  /copy_metadata #123
  ```

- 머지 리퀘스트에서 메타데이터 복사:

  ```plaintext
  /copy_metadata !456
  ```

- URL을 사용하여 작업 항목에서 메타데이터 복사:

  ```plaintext
  /copy_metadata https://gitlab.com/group/project/-/work_items/123
  ```

추가 세부정보:

- 메타데이터를 복사할 항목은 동일한 네임스페이스에 있어야 합니다.

### `create_merge_request` {#create_merge_request}

현재 이슈에서 시작하여 새 머지 리퀘스트를 만듭니다.

가용성:

- 인시던트
- 이슈
- 작업

매개변수:

- `<branch name>`: 머지 리퀘스트에 대해 만들 브랜치의 이름입니다.

예:

- 머지 리퀘스트 만들기:

  ```plaintext
  /create_merge_request fix-bug-123
  ```

### `done` {#done}

할 일 항목을 완료로 표시합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

예:

- 할 일을 완료로 표시:

  ```plaintext
  /done
  ```

### `draft` {#draft}

머지 리퀘스트의 초안 상태를 설정합니다.

가용성:

- 머지 리퀘스트

예:

- 초안으로 표시:

  ```plaintext
  /draft
  ```

추가 세부정보:

- 자세한 내용은 [초안 상태](merge_requests/drafts.md)를 참조하세요.

### `due` {#due}

기한을 설정합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 작업
- 핵심 결과

매개변수:

- `<date>`: 기한입니다. 유효한 날짜의 예로는 `in 2 days`, `this Friday` 및 `December 31st`가 있습니다.

예:

- 특정 날짜로 기한 설정:

  ```plaintext
  /due December 31st
  ```

- 오늘을 기준으로 상대적으로 기한 설정:

  ```plaintext
  /due in 2 days
  ```

- 다음 금요일로 기한 설정:

  ```plaintext
  /due this Friday
  ```

추가 세부정보:

- 더 많은 날짜 형식 예제는 [Chronic 예제](https://gitlab.com/gitlab-org/ruby/gems/gitlab-chronic#examples)를 참조하세요.
- 기한을 제거하려면 [`/remove_due_date`](#remove_due_date)를 사용하세요.

### `duplicate` {#duplicate}

이 항목을 닫고 다른 항목과 관련된 것으로 표시하고 중복된 것으로 표시합니다.

가용성:

- 에픽
- 인시던트
- 이슈

매개변수:

- `<item>`: 이것이 중복된 항목입니다. 값은 `#item`, `group/project#item` 또는 URL 형식이어야 합니다.

예:

- 중복으로 표시:

  ```plaintext
  /duplicate #123
  ```

- URL을 사용하여 중복으로 표시:

  ```plaintext
  /duplicate https://gitlab.com/group/project/-/work_items/123
  ```

### `epic` {#epic}

에픽에 하위 항목으로 추가합니다.

가용성:

- 에픽
- 이슈

매개변수:

- `<epic>`: 이 항목을 추가할 에픽입니다. 값은 `&epic`, `#epic`, `group&epic`, `group#epic` 또는 에픽의 URL 형식이어야 합니다.

예:

- 참조로 에픽에 추가:

  ```plaintext
  /epic &123
  ```

- 그룹 및 참조로 에픽에 추가:

  ```plaintext
  /epic group&456
  ```

- URL을 사용하여 에픽에 추가:

  ```plaintext
  /epic https://gitlab.com/groups/group/-/epics/123
  ```

추가 세부정보:

- `/set_parent`은 동일하게 작동하지만 더 많은 작업 항목 유형에 사용할 수 있습니다.

### `estimate` {#estimate}

시간 추정을 설정합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트

매개변수:

- `<time>`: 시간 추정입니다. 예를 들어, `1mo 2w 3d 4h 5m`입니다.

예:

- 시간 추정 설정:

  ```plaintext
  /estimate 1mo 2w 3d 4h 5m
  ```

- 시간 단위로 시간 추정 설정:

  ```plaintext
  /estimate 8h
  ```

추가 세부정보:

- `/estimate_time`은 `/estimate`의 별칭입니다.
- 추정을 제거하려면 [`/remove_estimate`](#remove_estimate)를 사용하세요.
- 자세한 내용은 [시간 추적](time_tracking.md)을 참조하세요.

### `health_status` {#health_status}

건강 상태를 설정합니다.

가용성:

- 에픽
- 이슈
- 작업
- 목표
- 핵심 결과

매개변수:

- `<value>`: 건강 상태 값입니다. 유효한 옵션은 `on_track`, `needs_attention` 및 `at_risk`입니다.

예:

- 건강 상태를 정상으로 설정:

  ```plaintext
  /health_status on_track
  ```

- 건강 상태를 주의 필요로 설정:

  ```plaintext
  /health_status needs_attention
  ```

- 건강 상태를 위험으로 설정:

  ```plaintext
  /health_status at_risk
  ```

추가 세부정보:

- 자세한 내용은 [건강 상태](issues/managing_issues.md#health-status)를 참조하세요.

### `internal_note` {#internal_note}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/553068)되었습니다.

{{< /history >}}

댓글을 내부 메모로 만듭니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 티켓
- 목표
- 핵심 결과

예:

- 댓글을 내부 메모로 만들기:

  ```plaintext
  This is an internal comment.
  /internal_note
  ```

추가 세부정보:

- 플래너, 리포터, 개발자, 관리자 또는 소유자 역할이 있어야 합니다.
- `/internal_note`을 설명, 비공개가 아닌 토론의 답글 또는 기존 댓글을 편집할 때 사용할 수 없습니다.
- 내부 메모를 일반 댓글로 변환할 수 없습니다.
- 자세한 내용은 [내부 메모](../discussions/_index.md#add-an-internal-note)를 참조하세요.

### `iteration` {#iteration}

반복을 설정합니다.

가용성:

- 인시던트
- 이슈

매개변수:

- `*iteration:<iteration ID> or <iteration name>`: ID 또는 이름으로 특정 반복을 설정합니다.
- `[cadence:<iteration cadence ID> or <iteration cadence name>] <--current or --next>`: 특정 주기의 현재 또는 다음 반복을 설정합니다.
- `--current` 또는 `--next`: 그룹에 반복 주기가 하나인 경우 현재 또는 다음 반복을 설정합니다.

예:

- 이름으로 특정 반복을 설정:

  ```plaintext
  /iteration *iteration:"Late in July"
  ```

- 주기의 현재 반복을 설정:

  ```plaintext
  /iteration [cadence:"Team cadence"] --current
  ```

- 그룹에 반복 주기가 하나인 경우 다음 반복 설정:

  ```plaintext
  /iteration --next
  ```

추가 세부정보:

- 반복을 제거하려면 [`/remove_iteration`](#remove_iteration)를 사용하세요.

### `label` {#label}

하나 이상의 레이블을 추가합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

매개변수:

- `~label1 ~label2`: 하나 이상의 레이블 이름입니다. 레이블 이름은 틸데(`~`) 없이도 시작할 수 있지만 혼합 구문은 지원되지 않습니다.

예:

- 단일 레이블 추가:

  ```plaintext
  /label ~bug
  ```

- 여러 레이블 추가:

  ```plaintext
  /label ~bug ~"high priority"
  ```

- 틸데 없이 레이블 추가:

  ```plaintext
  /label bug "high priority"
  ```

추가 세부정보:

- 이름에 공백이 있는 레이블은 큰따옴표로 묶어야 합니다.
- `/labels`은 `/label`의 별칭입니다.
- 레이블을 제거하려면 [`/unlabel`](#unlabel)를 사용하세요.
- 레이블을 바꾸려면 [`/relabel`](#relabel)를 사용하세요.

### `link` {#link}

인시던트의 연결된 리소스에 링크 및 설명을 추가합니다.

가용성:

- 인시던트

예:

- 연결된 리소스 추가:

  ```plaintext
  /link
  ```

추가 세부정보:

- 자세한 내용은 [연결된 리소스](../../operations/incident_management/linked_resources.md)를 참조하세요.

### `lock` {#lock}

토론을 잠급니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트

예:

- 토론 잠금:

  ```plaintext
  /lock
  ```

추가 세부정보:

- 토론의 잠금을 해제하려면 [`/unlock`](#unlock)를 사용하세요.

### `merge` {#merge}

변경 사항을 병합합니다.

가용성:

- 머지 리퀘스트

예:

- 머지 리퀘스트 병합:

  ```plaintext
  /merge
  ```

추가 세부정보:

- 프로젝트 설정에 따라 이는 [파이프라인이 성공할 때](merge_requests/auto_merge.md) 또는 [머지 트레인](../../ci/pipelines/merge_trains.md)에 추가될 수 있습니다.

### `milestone` {#milestone}

{{< history >}}

- GitLab 18.2에서 에픽에 대해 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/329)되었습니다.

{{< /history >}}

마일스톤을 설정합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트

매개변수:

- `%milestone`: 마일스톤 이름입니다. `%`로 시작해야 합니다.

예:

- 마일스톤 설정:

  ```plaintext
  /milestone %"Sprint 1"
  ```

추가 세부정보:

- 마일스톤을 제거하려면 [`/remove_milestone`](#remove_milestone)를 사용하세요.

### `move` {#move}

작업 항목을 다른 그룹 또는 프로젝트로 이동합니다.

가용성:

- 에픽
- 인시던트
- 이슈

매개변수:

- `<path/to/group_or_project>`: 대상 그룹 또는 프로젝트의 경로입니다.
- `[type:<work item type>]`(선택 사항): 대상 네임스페이스에서 사용할 작업 항목 유형입니다. 생략하면 소스 작업 항목 유형이 유지됩니다. 다중 단어 유형 이름(예: `Key Result`)은 `]`이 값을 종료하므로 따옴표를 붙이지 않아도 됩니다.

예:

- 다른 프로젝트로 이동:

  ```plaintext
  /move group/project
  ```

- 다른 프로젝트로 이동하고 특정 작업 항목 유형으로 변환:

  ```plaintext
  /move group/project [type:Issue]
  ```

- 다중 단어 유형 이름으로 이동:

  ```plaintext
  /move group/project [type:Key Result]
  ```

추가 세부정보:

- 작업 항목을 다른 액세스 규칙이 있는 위치로 이동할 때 주의하세요. 작업 항목을 이동하기 전에 민감한 데이터가 포함되지 않도록 하세요.
- 유형이 제공되지 않으면 소스 작업 항목 유형이 유지됩니다. 해당 유형을 대상 네임스페이스에서 사용할 수 없으면 이동에 실패합니다.
- 유형이 제공되면 작업 항목이 해당 유형으로 변환됩니다. 유형을 대상 네임스페이스에서 사용할 수 없으면 이동에 실패합니다.
- `[type:...]` 값이 대상 네임스페이스에서 사용 가능한 작업 항목 유형의 이름과 대소문자를 구분하지 않고 일치합니다.
- 해결된 유형이 대상 네임스페이스에서 꺼져 있으면(보관됨, 관리자가 끔 또는 대상 컨텍스트에서 표시되지 않음) 이동에 실패합니다.
- 동일한 네임스페이스로 이동할 때 `[type:...]` 인수가 유효성 검사되지만 변환이 수행되지 않습니다. 작업 항목이 기존 유형을 유지합니다.
- 기본 제공 유형(예: `Issue`, `Task`, `Incident`) 간의 기본 유형 변환을 모든 티어에서 사용할 수 있습니다.
- 사용자 지정 작업 항목 유형 및 네임스페이스별 유형 가시성은 GitLab.com의 Premium 및 Ultimate 기능입니다. 구독에서 대상 네임스페이스의 유형을 사용할 수 없으면 이동에 실패하고 오류 메시지에 사용할 수 있는 유형이 나열됩니다.

### `page` {#page}

인시던트에 대한 에스컬레이션을 시작합니다.

가용성:

- 인시던트

매개변수:

- `<policy name>`: 에스컬레이션 정책 이름입니다.

예:

- 에스컬레이션 시작:

  ```plaintext
  /page "On-call policy"
  ```

### `promote_to` {#promote_to}

작업 항목을 지정된 유형으로 승격합니다.

가용성:

- 이슈
- 작업
- 핵심 결과

매개변수:

- `<type>`: 승격할 유형입니다. 사용 가능한 옵션:
  - `Epic` (이슈의 경우)
  - `Incident` (이슈의 경우)
  - `issue` (작업의 경우)
  - `objective` (핵심 결과의 경우)

예:

- 이슈를 에픽으로 승격:

  ```plaintext
  /promote_to Epic
  ```

- 작업을 이슈로 승격:

  ```plaintext
  /promote_to issue
  ```

- 핵심 결과를 목표로 승격:

  ```plaintext
  /promote_to objective
  ```

추가 세부정보:

- 이슈의 경우 `/promote_to_incident`은 `/promote_to Incident`의 단축키입니다.
- 작업 항목의 유형을 변경하려면 [`/type`](#type)를 사용하세요.

### `promote_to_incident` {#promote_to_incident}

이슈를 인시던트로 승격합니다.

가용성:

- 이슈

예:

- 인시던트로 승격:

  ```plaintext
  /promote_to_incident
  ```

추가 세부정보:

- 새 이슈를 만들 때도 이 빠른 작업을 사용할 수 있습니다.

### `publish` {#publish}

이슈를 관련 상태 페이지에 게시합니다.

가용성:

- 이슈

예:

- 상태 페이지에 게시:

  ```plaintext
  /publish
  ```

추가 세부정보:

- 자세한 내용은 [상태 페이지](../../operations/incident_management/status_page.md)를 참조하세요.

### `react` {#react}

이모지 반응을 전환합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트

매개변수:

- `:emoji:`: 전환할 이모지입니다. `:emoji_name:` 형식이어야 합니다.

예:

- 엄지손가락 올림 반응 전환:

  ```plaintext
  /react :thumbsup:
  ```

- 하트 반응 전환:

  ```plaintext
  /react :heart:
  ```

추가 세부정보:

- `/award`은 `/react`의 별칭입니다.

### `ready` {#ready}

머지 리퀘스트의 준비 상태를 설정합니다.

가용성:

- 머지 리퀘스트

예:

- 준비 완료로 표시:

  ```plaintext
  /ready
  ```

추가 세부정보:

- 자세한 내용은 [머지 리퀘스트를 준비 완료로 표시](merge_requests/drafts.md#mark-merge-requests-as-ready)를 참조하세요.

### `reassign` {#reassign}

{{< history >}}

- GitLab 18.2에서 에픽에 대해 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/551805)되었습니다.

{{< /history >}}

현재 할당자를 지정된 할당자로 바꿉니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

매개변수:

- `@user1 @user2`: 할당할 하나 이상의 사용자 이름입니다. 사용자 이름 앞에 `@`를 붙여야 합니다.

예:

- 단일 사용자로 재할당:

  ```plaintext
  /reassign @alex
  ```

- 여러 사용자로 재할당:

  ```plaintext
  /reassign @alex @sam
  ```

추가 세부정보:

- 이전 할당자를 바꾸지 않고 할당자를 추가하려면 [`/assign`](#assign)를 사용하세요.
- 할당자를 제거하려면 [`/unassign`](#unassign)를 사용하세요.
- 할당자를 바꾸려면 [`/reassign`](#reassign)를 사용하세요.

### `reassign_reviewer` {#reassign_reviewer}

현재 검토자를 지정된 검토자로 바꿉니다.

가용성:

- 머지 리퀘스트

매개변수:

- `@user1 @user2`: 검토자로 할당할 하나 이상의 사용자 이름입니다. 사용자 이름 앞에 `@`를 붙여야 합니다.

예:

- 단일 검토자로 재할당:

  ```plaintext
  /reassign_reviewer @alex
  ```

- 여러 검토자로 재할당:

  ```plaintext
  /reassign_reviewer @alex @sam
  ```

추가 세부정보:

- 이전 검토자를 바꾸지 않고 검토자를 할당하려면 [`/assign_reviewer`](#assign_reviewer)를 사용하세요.
- 검토자를 제거하려면 [`/unassign_reviewer`](#unassign_reviewer)를 사용하세요.

### `rebase` {#rebase}

소스 브랜치를 대상 브랜치의 최신 커밋으로 리베이스합니다. 충돌이 있으면 아무 일도 발생하지 않습니다.

가용성:

- 머지 리퀘스트

예:

- 머지 리퀘스트를 리베이스합니다:

  ```plaintext
  /rebase
  ```

추가 세부정보:

- 도움말은 [Git 문제 해결](../../topics/git/troubleshooting_git.md)을 참조하세요.

### `relabel` {#relabel}

현재 레이블을 지정된 레이블로 바꿉니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

매개변수:

- `~label1 ~label2`: 하나 이상의 레이블 이름입니다. 레이블 이름은 틸데(`~`) 없이도 시작할 수 있지만 혼합 구문은 지원되지 않습니다.

예:

- 단일 레이블로 바꾸기:

  ```plaintext
  /relabel ~bug
  ```

- 여러 레이블로 바꾸기:

  ```plaintext
  /relabel ~bug ~"high priority"
  ```

추가 세부정보:

- 이름에 공백이 있는 레이블은 큰따옴표로 묶어야 합니다.
- 이전 레이블을 바꾸지 않고 레이블을 추가하려면 [`/label`](#label)를 사용하세요.
- 레이블을 제거하려면 [`/unlabel`](#unlabel)를 사용하세요.

### `relate` {#relate}

항목을 관련된 것으로 표시합니다.

가용성:

- 에픽
- 인시던트
- 이슈

매개변수:

- `<item1> <item2>`: 관련시킬 하나 이상의 항목입니다. 값은 `#item`, `group/project#item` 또는 전체 URL 형식이어야 합니다.

예:

- 단일 항목과 관련:

  ```plaintext
  /relate #123
  ```

- 여러 항목과 관련:

  ```plaintext
  /relate #123 group/project#456
  ```

추가 세부정보:

- 관계를 제거하려면 [`/unlink`](#unlink)를 사용하세요.
- 항목을 서로 차단하는 것으로 표시하려면 [`/blocked_by`](#blocked_by) 또는 [`/blocks`](#blocks)를 사용하세요.

### `remove_child` {#remove_child}

하위 항목으로 항목을 제거합니다.

가용성:

- 에픽
- 이슈
- 목표

매개변수:

- `<item>`: 하위 항목으로 제거할 항목입니다. 값은 `#item`, `group/project#item` 또는 항목의 URL 형식이어야 합니다.

예:

- 하위 항목 제거:

  ```plaintext
  /remove_child #123
  ```

- URL을 사용하여 하위 항목 제거:

  ```plaintext
  /remove_child https://gitlab.com/group/project/-/work_items/123
  ```

### `remove_contacts` {#remove_contacts}

하나 이상의 CRM 연락처를 제거합니다.

가용성:

- 이슈

매개변수:

- `[contact:email1@example.com]`: `contact:email@example.com` 형식의 하나 이상의 연락처 이메일입니다.

예:

- 단일 연락처 제거:

  ```plaintext
  /remove_contacts [contact:alex@example.com]
  ```

- 여러 연락처 제거:

  ```plaintext
  /remove_contacts [contact:alex@example.com] [contact:sam@example.com]
  ```

추가 세부정보:

- 자세한 내용은 [CRM 연락처](../crm/_index.md)를 참조하세요.

### `remove_due_date` {#remove_due_date}

기한을 제거합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 작업
- 핵심 결과

예:

- 기한 제거:

  ```plaintext
  /remove_due_date
  ```

추가 세부정보:

- 기한을 추가하거나 바꾸려면 [`/due`](#due)를 사용하세요.

### `remove_email` {#remove_email}

{{< history >}}

- GitLab 18.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/350460)합니다. 기능 플래그 `issue_email_participants`이 제거되었습니다.

{{< /history >}}

최대 6개의 이메일 참여자를 제거합니다.

가용성:

- 인시던트
- 이슈

매개변수:

- `email1 email2`: 공백으로 구분된 하나 이상의 이메일 주소입니다.

예:

- 단일 이메일 참여자 제거:

  ```plaintext
  /remove_email alex@example.com
  ```

- 여러 이메일 참여자 제거:

  ```plaintext
  /remove_email alex@example.com sam@example.com
  ```

추가 세부정보:

- 이슈 템플릿, 머지 리퀘스트 또는 에픽에서는 지원되지 않습니다.
- 자세한 내용은 [이메일 참여자](service_desk/external_participants.md)를 참조하세요.

### `remove_estimate` {#remove_estimate}

시간 추정을 제거합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트

예:

- 시간 추정 제거:

  ```plaintext
  /remove_estimate
  ```

추가 세부정보:

- `/remove_time_estimate`은 `/remove_estimate`의 별칭입니다.
- 추정을 추가하거나 바꾸려면 [`/estimate`](#estimate)를 사용하세요.

### `remove_iteration` {#remove_iteration}

반복을 제거합니다.

가용성:

- 인시던트
- 이슈

예:

- 반복 제거:

  ```plaintext
  /remove_iteration
  ```

추가 세부정보:

- 반복을 설정하려면 [`/iteration`](#iteration)를 사용하세요.

### `remove_milestone` {#remove_milestone}

{{< history >}}

- GitLab 18.2에서 에픽에 대해 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/329)되었습니다.

{{< /history >}}

마일스톤을 제거합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트

예:

- 마일스톤 제거:

  ```plaintext
  /remove_milestone
  ```

추가 세부정보:

- 마일스톤을 설정하려면 [`/milestone`](#milestone)을 사용하세요.

### `remove_parent` {#remove_parent}

항목에서 상위 항목을 제거합니다.

가용성:

- 에픽
- 이슈
- 작업
- 핵심 결과

예:

- 상위 항목 제거:

  ```plaintext
  /remove_parent
  ```

추가 세부정보:

- 상위 항목을 설정하려면 [`/set_parent`](#set_parent)을 사용하세요.

### `remove_time_spent` {#remove_time_spent}

소요 시간을 제거합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트

예:

- 소요 시간 제거:

  ```plaintext
  /remove_time_spent
  ```

추가 세부정보:

- 소요 시간을 추가하려면 [`/spend`](#spend)을 사용하세요.

### `remove_zoom` {#remove_zoom}

이슈에서 Zoom 회의를 제거합니다.

가용성:

- 이슈

예:

- Zoom 회의 제거:

  ```plaintext
  /remove_zoom
  ```

추가 세부정보:

- Zoom 회의를 추가하려면 [`/zoom`](#zoom)을 사용하세요.

### `reopen` {#reopen}

작업 항목을 다시 엽니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

예:

- 작업 항목 다시 열기:

  ```plaintext
  /reopen
  ```

추가 세부정보:

- 작업 항목을 닫으려면 [`/close`](#close)을 사용하세요.

### `request_review` {#request_review}

검토자를 할당하거나 한 명 이상의 사용자에게 새로운 검토를 요청합니다.

가용성:

- 머지 리퀘스트

매개변수:

- `@user1 @user2`: 검토를 요청할 한 명 이상의 사용자명입니다. 사용자 이름 앞에 `@`를 붙여야 합니다.
- `me`: 자신에게 검토를 요청합니다.

예:

- 한 명의 사용자에게 검토 요청:

  ```plaintext
  /request_review @alex
  ```

- 여러 사용자에게 검토 요청:

  ```plaintext
  /request_review @alex @sam
  ```

- 자신에게 검토 요청:

  ```plaintext
  /request_review me
  ```

추가 세부정보:

- [`/assign_reviewer`](#assign_reviewer) 또는 `/reviewer`을 사용하여 호출할 수도 있습니다.
- 사용자가 아직 검토자가 아니면 검토자로 할당합니다.
- 사용자가 이미 검토자인 경우 새로운 검토를 요청합니다(검토 상태를 재설정하고 알림을 보냅니다).
- 자세한 내용은 [검토 요청](merge_requests/reviews/_index.md#request-a-review)을 참조하세요.

### `run_pipeline` {#run_pipeline}

{{< history >}}

- GitLab 18.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/212811)되었습니다.

{{< /history >}}

머지 리퀘스트를 위한 새로운 파이프라인을 실행합니다.

가용성:

- 머지 리퀘스트

예:

- 새로운 파이프라인 실행:

  ```plaintext
    /run_pipeline
  ```

추가 세부정보:

- 파이프라인은 비동기적으로 트리거되며 명령 실행 직후에 나타납니다.
- 머지 리퀘스트에 대한 파이프라인을 생성할 권한이 있어야 합니다.
- 다른 빠른 작업과 함께 사용할 수 있습니다. 예를 들어 파이프라인을 실행하고 자동 병합을 설정하려면:

  ```plaintext
    /run_pipeline
    /merge
  ```

### `set_parent` {#set_parent}

{{< history >}}

- 이슈의 `/epic` 별칭이 GitLab 17.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/514942)되었습니다.

{{< /history >}}

상위 항목을 설정합니다.

가용성:

- 에픽
- 이슈
- 작업
- 핵심 결과

매개변수:

- `<item>`: 상위 항목입니다. 값은 `#IID`, 참조 또는 항목의 URL 형식이어야 합니다.

예:

- 참조로 상위 항목 설정:

  ```plaintext
  /set_parent #123
  ```

- URL을 사용하여 상위 항목 설정:

  ```plaintext
  /set_parent https://gitlab.com/group/project/-/work_items/123
  ```

추가 세부정보:

- 이슈의 경우 `/epic`은 `/set_parent`의 별칭입니다.
- 상위 항목을 제거하려면 [`/remove_parent`](#remove_parent)을 사용하세요.

### `severity` {#severity}

사건의 심각도를 설정합니다.

가용성:

- 인시던트

매개변수:

- `<severity>`: 심각도 수준입니다. 사용 가능한 옵션:
  - `S1`
  - `S2`
  - `S3`
  - `S4`
  - `critical`
  - `high`
  - `medium`
  - `low`
  - `unknown`

예:

- 심각도를 중요로 설정:

  ```plaintext
  /severity critical
  ```

- S 표기법을 사용하여 심각도 설정:

  ```plaintext
  /severity S1
  ```

### `shrug` {#shrug}

`¯\_(ツ)_/¯`을 댓글에 추가합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

예:

- 어깨 으쓱 추가:

  ```plaintext
  /shrug
  ```

### `spend` {#spend}

소요 시간을 추가하거나 뺍니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트

매개변수:

- `<time>`: 추가하거나 뺄 시간입니다. 예를 들어, `1mo 2w 3d 4h 5m`입니다. 음수 값을 사용하여 시간을 뺍니다.
- `[<date>]`: 선택 사항. 시간을 소요한 날짜입니다.

예:

- 소요 시간 추가:

  ```plaintext
  /spend 1mo 2w 3d 4h 5m
  ```

- 소요 시간 빼기:

  ```plaintext
  /spend -1h 30m
  ```

- 특정 날짜에 소요 시간 추가:

  ```plaintext
  /spend 1mo 2w 3d 4h 5m 2018-08-26
  ```

추가 세부정보:

- `/spend_time`은 `/spend`의 별칭입니다.
- 소요 시간을 제거하려면 [`/remove_time_spent`](#remove_time_spent)을 사용하세요.
- 자세한 내용은 [시간 추적](time_tracking.md)을 참조하세요.

### `status` {#status}

상태를 설정합니다.

가용성:

- 이슈
- 작업

매개변수:

- `<value>`: 상태 값입니다. 사용 가능한 옵션에는 네임스페이스에 설정된 상태 옵션이 포함됩니다.

예:

- 상태 설정:

  ```plaintext
  /status "In Progress"
  ```

추가 세부정보:

- 자세한 내용은 [상태](../work_items/status.md)를 참조하세요.

### `submit_review` {#submit_review}

대기 중인 [검토](merge_requests/reviews/_index.md#submit-a-review)를 제출합니다.

가용성:

- 머지 리퀘스트

예:

- 검토 제출:

  ```plaintext
  /submit_review
  ```

  ```plaintext
  /submit_review reviewed
  ```

- 검토를 제출하고 승인:

  ```plaintext
  /submit_review approve
  ```

- 검토를 제출하고 [변경 요청](merge_requests/reviews/_index.md#prevent-merge-when-you-request-changes):

  ```plaintext
  /submit_review requested_changes
  ```

### `subscribe` {#subscribe}

작업 항목에 대한 알림을 구독합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

예:

- 알림 구독:

  ```plaintext
  /subscribe
  ```

추가 세부정보:

- 알림 구독을 취소하려면 [`/unsubscribe`](#unsubscribe)을 사용하세요.

### `tableflip` {#tableflip}

`(╯°□°)╯︵ ┻━┻`을 댓글에 추가합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

예:

- 테이블 뒤집기 추가:

  ```plaintext
  /tableflip
  ```

### `target_branch` {#target_branch}

머지 리퀘스트의 대상 브랜치를 설정합니다.

가용성:

- 머지 리퀘스트

매개변수:

- `<local branch name>`: 대상 브랜치의 이름입니다.

예:

- 대상 브랜치 설정:

  ```plaintext
  /target_branch main
  ```

### `timeline` {#timeline}

사건에 타임라인 이벤트를 추가합니다.

가용성:

- 인시던트

매개변수:

- `<timeline comment> | <date(YYYY-MM-DD)> <time(HH:MM)>`: 타임라인 설명, 날짜 및 시간을 `|`로 구분합니다.

예:

- 타임라인 이벤트 추가:

  ```plaintext
  /timeline DB load spiked | 2022-09-07 09:30
  ```

### `title` {#title}

제목을 변경합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

매개변수:

- `<new title>`: 작업 항목의 새 제목입니다.

예:

- 제목 변경:

  ```plaintext
  /title New title for this item
  ```

### `todo` {#todo}

자신을 위해 할 일 항목을 추가합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

예:

- 할 일 추가:

  ```plaintext
  /todo
  ```

### `type` {#type}

작업 항목을 지정된 유형으로 변환합니다.

가용성:

- 이슈
- 핵심 결과
- 목표
- 작업

매개변수:

- `<type>`: 변환할 유형입니다. 사용 가능한 옵션:
  - `issue`
  - `task`
  - `objective`
  - `key result`

예:

- 이슈로 변환:

  ```plaintext
  /type issue
  ```

- 작업으로 변환:

  ```plaintext
  /type task
  ```

추가 세부정보:

- 이슈를 에픽 또는 사건으로 변환하려면 [`/promote_to`](#promote_to)을 사용하세요.
- `/type Epic`은 `/promote_to Epic`와 동일한 방식으로 이슈를 에픽으로 변환합니다.

### `unapprove` {#unapprove}

머지 리퀘스트를 승인 취소합니다.

가용성:

- 머지 리퀘스트

예:

- 머지 리퀘스트 승인 취소:

  ```plaintext
  /unapprove
  ```

추가 세부정보:

- 머지 리퀘스트를 승인하려면 [`/approve`](#approve)을 사용하세요.

### `unassign` {#unassign}

{{< history >}}

- GitLab 18.2에서 에픽에 대해 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/551805)되었습니다.

{{< /history >}}

담당자를 제거합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

매개변수:

- `@user1 @user2`: 선택 사항. 할당을 제거할 한 명 이상의 사용자명입니다. 제공되지 않으면 모든 담당자를 제거합니다.

예:

- 특정 담당자 제거:

  ```plaintext
  /unassign @alex @sam
  ```

- 모든 담당자 제거:

  ```plaintext
  /unassign
  ```

추가 세부정보:

- 담당자를 추가하려면 [`/assign`](#assign)을 사용하세요.
- 할당자를 바꾸려면 [`/reassign`](#reassign)를 사용하세요.

### `unassign_reviewer` {#unassign_reviewer}

검토자를 제거합니다.

가용성:

- 머지 리퀘스트

매개변수:

- `@user1 @user2`: 선택 사항. 검토자로 제거할 한 명 이상의 사용자명입니다. 제공되지 않으면 모든 검토자를 제거합니다.
- `me`: 검토자로 자신을 제거합니다.

예:

- 특정 검토자 제거:

  ```plaintext
  /unassign_reviewer @alex @sam
  ```

- 검토자로 자신 제거:

  ```plaintext
  /unassign_reviewer me
  ```

- 모든 검토자 제거:

  ```plaintext
  /unassign_reviewer
  ```

추가 세부정보:

- `/remove_reviewer`은 `/unassign_reviewer`의 별칭입니다.
- 검토자를 할당하려면 [`/assign_reviewer`](#assign_reviewer)을 사용하세요.
- 검토자를 바꾸려면 [`/reassign_reviewer`](#reassign_reviewer)를 사용하세요.

### `unlabel` {#unlabel}

레이블을 제거합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

매개변수:

- `~label1 ~label2`: 선택 사항. 제거할 한 명 이상의 레이블 이름입니다. 제공되지 않으면 모든 레이블을 제거합니다.

예:

- 특정 레이블 제거:

  ```plaintext
  /unlabel ~bug ~"high priority"
  ```

- 모든 레이블 제거:

  ```plaintext
  /unlabel
  ```

추가 세부정보:

- 이름에 공백이 있는 레이블은 큰따옴표로 묶어야 합니다.
- `/remove_label`은 `/unlabel`의 별칭입니다.
- 레이블을 추가하려면 [`/label`](#label)을 사용하세요.
- 레이블을 바꾸려면 [`/relabel`](#relabel)를 사용하세요.

### `unlink` {#unlink}

{{< history >}}

- GitLab 17.8에서 작업, 목표 및 핵심 결과를 위해 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/481851)되었습니다.

{{< /history >}}

다른 항목으로의 링크를 제거합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

매개변수:

- `<item>`: 링크 해제할 항목입니다. 값은 `#item`, `group/project#item` 또는 전체 URL 형식이어야 합니다. 머지 리퀘스트의 경우 `!merge_request`, `group/project!merge_request` 또는 머지 리퀘스트 URL을 사용하세요.

예:

- 항목 링크 해제:

  ```plaintext
  /unlink #123
  ```

- URL을 사용하여 항목 링크 해제:

  ```plaintext
  /unlink https://gitlab.com/group/project/-/work_items/123
  ```

- 머지 리퀘스트 간 차단 관계 제거:

  ```plaintext
  /unlink !456
  ```

추가 세부정보:

- 항목 간의 관계를 설정하려면 [`/relate`](#relate), [`/blocks`](#blocks) 또는 [`/blocked_by`](#blocked_by)을 사용합니다.

### `unlock` {#unlock}

스레드를 잠금 해제합니다.

가용성:

- 에픽
- 이슈
- 머지 리퀘스트

예:

- 스레드 잠금 해제:

  ```plaintext
  /unlock
  ```

추가 세부정보:

- 스레드를 잠그려면 [`/lock`](#lock)을 사용하세요.

### `unsubscribe` {#unsubscribe}

작업 항목에 대한 알림 구독을 취소합니다.

가용성:

- 에픽
- 인시던트
- 이슈
- 머지 리퀘스트
- 작업
- 목표
- 핵심 결과

예:

- 알림 구독 취소:

  ```plaintext
  /unsubscribe
  ```

추가 세부정보:

- 알림을 구독하려면 [`/subscribe`](#subscribe)을 사용하세요.

### `weight` {#weight}

가중치를 설정합니다.

가용성:

- 이슈
- 작업

매개변수:

- `<value>`: 가중치 값입니다. 유효한 값은 `0`, `1` 또는 `2`와 같은 정수입니다.

예:

- 가중치 설정:

  ```plaintext
  /weight 3
  ```

### `zoom` {#zoom}

이슈 또는 사건에 Zoom 회의를 추가합니다.

가용성:

- 인시던트
- 이슈

매개변수:

- `<Zoom URL>`: Zoom 회의의 URL입니다.

예:

- Zoom 회의 추가:

  ```plaintext
  /zoom https://zoom.us/j/123456789
  ```

추가 세부정보:

- GitLab Premium을 사용하는 사용자는 [사건에 Zoom 링크 추가](../../operations/incident_management/linked_resources.md#link-zoom-meetings-from-an-incident)할 때 짧은 설명을 추가할 수 있습니다.
- Zoom 회의를 제거하려면 [`/remove_zoom`](#remove_zoom)을 사용하세요.

## 커밋 댓글 {#commit-comments}

개별 커밋에 댓글을 달 때 빠른 작업을 사용할 수 있습니다. 이러한 빠른 작업은 커밋 댓글 스레드에서만 작동하며 커밋 메시지 또는 다른 GitLab 컨텍스트에서는 작동하지 않습니다.

커밋 댓글에서 빠른 작업을 사용하려면:

1. 커밋 목록, 머지 리퀘스트 또는 다른 커밋 링크에서 커밋을 선택하여 커밋 페이지로 이동합니다.
1. 커밋 페이지 하단의 댓글 양식에 빠른 작업을 입력합니다.
1. **댓글**를 선택합니다.

다음 빠른 작업은 커밋 댓글에 적용됩니다:

### `tag` {#tag}

댓글이 달린 커밋을 가리키는 Git 태그를 만듭니다.

매개변수:

- `v1.2.3`: 태그 이름입니다.
- `<message>`: 선택 사항. 태그의 메시지입니다.

예:

- 메시지가 있는 태그 만들기:

  ```plaintext
  Ready for release after security fix.
  /tag v2.1.1 Security patch release
  ```

  이 댓글은 `v2.1.1`이라는 Git 태그를 커밋에 생성하며 "Security patch release" 메시지와 함께 생성됩니다.

추가 세부정보:

- 태그 생성은 각 프로젝트에 대해 속도 제한되며 기본값은 30분마다 100개 요청입니다. 관리자는 `tags_create_limit` [애플리케이션 설정](../../api/settings.md#available-settings)으로 제한을 변경할 수 있습니다.
- 제한은 [REST API](../../api/tags.md#create-a-new-tag), GraphQL `tagCreate` 변형, UI의 태그 생성 및 이 빠른 작업 간에 공유됩니다.
- 제한을 초과하면 댓글이 여전히 추가되지만 태그는 생성되지 않습니다.

## 문제 해결 {#troubleshooting}

### 빠른 작업이 실행되지 않음 {#quick-action-isnt-executed}

빠른 작업을 실행했지만 아무것도 실행되지 않으면 빠른 작업이 입력하는 동안 자동 완성 상자에 나타나는지 확인하세요. 그렇지 않은 경우 다음과 같은 경우가 있을 수 있습니다:

- 빠른 작업과 관련된 기능은 구독 티어 또는 그룹이나 프로젝트에 대한 사용자 역할을 기반으로 사용할 수 없습니다.
- 빠른 작업에 필요한 조건이 충족되지 않습니다. 예를 들어 레이블이 없는 이슈에서 `/unlabel`을 실행하고 있습니다.
