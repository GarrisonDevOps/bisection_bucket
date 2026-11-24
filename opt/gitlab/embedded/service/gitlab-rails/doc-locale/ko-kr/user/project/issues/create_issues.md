---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 이슈 만들기
description: "프로젝트, 그룹, 다른 이슈, 이슈 보드, 이메일, 미리 채워진 URL 또는 Service Desk에서 이슈를 만듭니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이슈를 만들 때 이슈의 필드를 입력하라는 메시지가 표시됩니다. 이슈에 할당하려는 값을 알고 있으면 [빠른 작업](../quick_actions.md)을 사용하여 입력할 수 있습니다.

GitLab에서 여러 방법으로 이슈를 만들 수 있습니다:

- [프로젝트에서](#from-a-project)
- [그룹에서](#from-a-group)
- [다른 이슈 또는 인시던트에서](#from-another-issue-or-incident)
- [이슈 보드에서](#from-an-issue-board)
- [이메일 발송으로](#by-sending-an-email)
- [미리 채워진 값으로 URL 사용](#using-a-url-with-prefilled-values)
- [Service Desk 사용](#using-service-desk)

## 프로젝트에서 {#from-a-project}

사전 요구 사항:

- 프로젝트의 게스트, 플래너, 리포터, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

이슈를 만들려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 다음 중 하나를 선택합니다.

   - 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택한 다음 오른쪽 위 모서리에서 **새 항목**을 선택합니다.
   - 오른쪽 위 모서리에서 더하기 기호({{< icon name="plus" >}})를 선택한 다음 **이 프로젝트에서** **새 작업 항목**을 선택합니다.

1. **유형** 드롭다운 목록에서 **이슈**를 선택합니다(아직 선택되지 않은 경우).
1. [필드](#fields-in-the-new-issue-form)를 완성합니다.
1. **이슈 만들기**를 선택합니다.

새로 만들어진 이슈가 열립니다.

## 그룹에서 {#from-a-group}

이슈는 프로젝트에 속하지만 그룹에 있을 때 그룹의 프로젝트에 속하는 이슈에 액세스하고 만들 수 있습니다.

사전 요구 사항:

- 그룹의 프로젝트의 게스트, 플래너, 리포터, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

그룹에서 이슈를 만들려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택합니다.
1. 오른쪽 위 모서리에서 **이슈를 만들 프로젝트 선택**을 선택합니다.
1. 이슈를 만들 프로젝트를 선택합니다. 버튼이 선택된 프로젝트를 반영합니다.
1. **`<project name>`에 새 이슈**를 선택합니다.
1. [필드](#fields-in-the-new-issue-form)를 완성합니다.
1. **이슈 만들기**를 선택합니다.

새로 만들어진 이슈가 열립니다.

가장 최근에 선택한 프로젝트가 다음 방문을 위한 기본값이 됩니다. 주로 같은 프로젝트에 대한 이슈를 만드는 경우 시간을 많이 절약할 수 있습니다.

## 다른 이슈 또는 인시던트에서 {#from-another-issue-or-incident}

기존 이슈에서 새 이슈를 만들 수 있습니다. 두 이슈를 관련으로 표시할 수 있습니다.

사전 요구 사항:

- 프로젝트의 게스트, 플래너, 리포터, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

다른 이슈에서 이슈를 만들려면:

1. 기존 이슈에서 **이슈 작업**({{< icon name="ellipsis_v" >}})을 선택합니다.
1. **새로 관련된 이슈**를 선택합니다.
1. [필드](#fields-in-the-new-issue-form)를 완성합니다. 새 이슈 양식에 **이슈 #123과 관련** 확인란이 있습니다. 여기서 `123`은 원본 이슈의 ID입니다. 이 확인란을 선택한 상태로 유지하면 두 이슈가 [연결됩니다](related_issues.md).
1. **이슈 만들기**를 선택합니다.

새로 만들어진 이슈가 열립니다.

## 이슈 보드에서 {#from-an-issue-board}

[이슈 보드](../issue_board.md)에서 새 이슈를 만들 수 있습니다.

사전 요구 사항:

- 프로젝트의 게스트, 플래너, 리포터, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

프로젝트 이슈 보드에서 이슈를 만들려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **이슈 보드**를 선택합니다.
1. 보드 목록의 맨 위에서 **새 이슈 생성**({{< icon name="plus-square" >}})을 선택합니다.
1. 이슈의 제목을 입력합니다.
1. **이슈 만들기**를 선택합니다.

그룹 이슈 보드에서 이슈를 만들려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **이슈 보드**를 선택합니다.
1. 보드 목록의 맨 위에서 **새 이슈 생성**({{< icon name="plus-square" >}})을 선택합니다.
1. 이슈의 제목을 입력합니다.
1. **프로젝트** 아래에서 이슈가 속해야 할 그룹의 프로젝트를 선택합니다.
1. **이슈 만들기**를 선택합니다.

이슈가 생성되고 보드 목록에 표시됩니다. 목록의 특성을 공유하므로, 예를 들어 목록이 레이블 `Frontend`로 범위가 지정된 경우 새 이슈도 이 레이블을 갖습니다.

## 이메일 발송으로 {#by-sending-an-email}

{{< history >}}

- **이 프로젝트에 새 이슈 이메일 보내기** [이름이 변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/560277) **이 프로젝트로 이슈 이메일 보내기** GitLab 18.6에서.

{{< /history >}}

프로젝트의 **이슈** 페이지에서 이메일을 보내 프로젝트에 이슈를 만들 수 있습니다.

사전 요구 사항:

- GitLab 인스턴스에 [수신 이메일](../../../administration/incoming_email.md)이 [이메일 서브-주소 지정 또는 catch-all 사서함](../../../administration/incoming_email.md#requirements)으로 구성되어 있어야 합니다.
- 이슈 목록에 최소 하나의 이슈가 있어야 합니다.
- 프로젝트의 게스트, 플래너, 리포터, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

프로젝트에 이슈를 이메일로 보내려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택합니다.
1. 오른쪽 위 모서리에서 **추가 작업**({{< icon name="ellipsis_v" >}})을 선택한 다음 **이 프로젝트로 이 작업항목 이메일 보내기**를 선택합니다.
1. 이메일 주소를 복사하려면 **복사**({{< icon name="copy-to-clipboard" >}})를 선택합니다.
1. 이메일 클라이언트에서 이 주소로 이메일을 보냅니다. 제목은 새 이슈의 제목으로 사용되고 이메일 본문은 설명이 됩니다. [Markdown](../../markdown.md) 및 [빠른 작업](../quick_actions.md)을 사용할 수 있습니다.

새 이슈가 생성되고 사용자가 작성자입니다. 이 주소를 이메일 클라이언트의 연락처로 저장하여 다시 사용할 수 있습니다.

> [!warning]
> 표시되는 이메일 주소는 귀하만을 위해 생성된 비공개 이메일 주소입니다. 마치 당신인 것처럼 이슈나 머지 리퀘스트를 만들 수 있으므로 이를 자신만 알고 있어야 합니다. 이 비공개 이메일 주소가 유출되었다고 의심되면 토큰을 즉시 재설정하세요.

이메일 주소를 재설정하려면:

1. **이슈** 페이지에서 **이 프로젝트로 이슈 이메일 보내기**를 선택합니다.
1. **이 토큰 재설정**을 선택합니다.

## 미리 채워진 값으로 URL 사용 {#using-a-url-with-prefilled-values}

미리 채워진 필드가 있는 새 이슈 페이지에 직접 연결하려면 URL에서 쿼리 문자열 매개변수를 사용합니다. 특정 필드가 미리 채워진 URL을 외부 HTML 페이지에 포함할 수 있습니다.

미리 채워진 값으로 이슈를 만들 URL을 작성하려면 다음을 조합합니다:

1. 프로젝트 또는 그룹의 이슈 페이지 URL, 다음 `/new`. 예를 들어: `https://gitlab.com/gitlab-org/gitlab/-/work_items/new`

1. `?` 매개변수 나열을 시작합니다.
1. URL 매개변수, 다음 `=` 및 값. 예: `issue[title]=My%20test%20issue`.
1. 선택 사항. `&` 더 많은 매개변수에 참여합니다.

| 필드                                                                                          | URL 매개변수          | 참고 |
| ---------------------------------------------------------------------------------------------- | ---------------------- | ----- |
| 제목                                                                                          | `issue[title]`         | [URL 인코딩](../../../api/rest/_index.md#namespaced-paths)되어야 합니다. |
| 이슈 유형                                                                                     | `issue[issue_type]`    | `incident` 또는 `issue` 중 하나입니다. |
| 설명 템플릿(이슈, 인시던트 및 머지 리퀘스트)                                   | `issuable_template`    | [URL 인코딩](../../../api/rest/_index.md#namespaced-paths)되어야 합니다. |
| 설명 템플릿(작업, OKR, 이슈 및 에픽) | `description_template` | [URL 인코딩](../../../api/rest/_index.md#namespaced-paths)되어야 합니다. GitLab 17.9에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/513095)되었습니다. |
| 설명 | `issue[description]` | [URL 인코딩](../../../api/rest/_index.md#namespaced-paths)되어야 합니다. `issuable_template` 또는 [기본 이슈 템플릿](../description_templates.md#set-a-default-template-for-merge-requests-and-issues)과 함께 사용할 경우 `issue[description]` 값이 템플릿을 덮어씁니다. |
| 기밀                                                                                   | `issue[confidential]`  | `true`이면 이슈가 기밀로 표시됩니다. |
| ...과 관련됨                                                                                     | `add_related_issue`    | 숫자 이슈 ID입니다. 있는 경우 이슈 양식에 [**관련** 확인란](#from-another-issue-or-incident)이 표시되어 새 이슈를 지정된 기존 이슈에 선택적으로 연결할 수 있습니다. |

[GitLab 17.8 이상](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/177215)에서 이슈 템플릿을 선택하면 URL이 변경되어 사용된 템플릿을 표시합니다.

이 예제를 조정하여 미리 채워진 필드가 있는 새 이슈 URL을 형성합니다. GitLab 프로젝트에서 이슈를 만들려면:

- 미리 채워진 제목 및 설명이 있는 경우:

  ```plaintext
  https://gitlab.com/gitlab-org/gitlab/-/work_items/new?issue[title]=Whoa%2C%20we%27re%20half-way%20there&issue[description]=Whoa%2C%20livin%27%20in%20a%20URL
  ```

- 미리 채워진 제목 및 설명 템플릿이 있는 경우:

  ```plaintext
  https://gitlab.com/gitlab-org/gitlab/-/work_items/new?issue[title]=Validate%20new%20concept&issuable_template=Feature%20Proposal%20-%20basic
  ```

- 미리 채워진 제목, 설명이 있고 기밀로 표시되는 경우:

  ```plaintext
  https://gitlab.com/gitlab-org/gitlab/-/work_items/new?issue[title]=Validate%20new%20concept&issue[description]=Research%20idea&issue[confidential]=true
  ```

## Service Desk 사용 {#using-service-desk}

이메일 지원을 제공하려면 프로젝트에 대해 [Service Desk](../service_desk/_index.md)를 켭니다.

이제 고객이 새 이메일을 보내면 적절한 프로젝트에서 새 이슈를 만들고 거기서 후속 조치를 할 수 있습니다.

## 새 이슈 양식의 필드 {#fields-in-the-new-issue-form}

새 이슈를 만들 때 다음 필드를 완성할 수 있습니다:

- 제목: [제한된 서식 지원](../../markdown.md#work-item-and-merge-request-titles)
- 프로젝트: 현재 프로젝트로 기본값
- 유형: 이슈(기본값) 또는 인시던트
- [설명 템플릿](../description_templates.md): 설명 텍스트 상자의 모든 항목을 덮어씁니다
- 설명: [Markdown](../../markdown.md) 및 [빠른 작업](../quick_actions.md)을 사용할 수 있습니다
- 이슈를 [기밀](confidential_issues.md)로 만들 확인란
- [담당자](managing_issues.md#assignees)
- [가중치](../../work_items/weight.md)
- [부모](../../group/epics/_index.md)
- [날짜](due_dates.md)
- [마일스톤](../milestones/_index.md)
- [레이블](../labels.md)
- [반복](../../group/iterations/_index.md)
- [상태](managing_issues.md#health-status)
- [연락처](../../crm/_index.md)
