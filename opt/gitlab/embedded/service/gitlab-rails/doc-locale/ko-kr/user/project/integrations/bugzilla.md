---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Bugzilla
description: Bugzilla 통합을 구성하여 GitLab 프로젝트를 Bugzilla 이슈 추적기에 연결하고 GitLab에서 Bugzilla 이슈를 참조합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Bugzilla](https://www.bugzilla.org/)는 웹 기반의 범용 버그 추적 시스템이자 테스트 도구입니다.

Bugzilla를 GitLab의 [외부 이슈 추적기](../../../integration/external-issue-tracker.md)로 구성할 수 있습니다.

프로젝트에서 Bugzilla 통합을 켜려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Bugzilla**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 필수 필드를 입력합니다:

   - **프로젝트 URL**: Bugzilla의 프로젝트에 대한 URL입니다. 예를 들어, "Fire Tanuki"라는 제품의 경우: `https://bugzilla.example.org/describecomponents.cgi?product=Fire+Tanuki`.
   - **이슈 URL**: Bugzilla 프로젝트에서 이슈를 보기 위한 URL입니다. URL에는 `:id`가 포함되어야 합니다. GitLab은 `:id`을 이슈 번호로 바꿉니다(예: `https://bugzilla.example.org/show_bug.cgi?id=:id`, 이는 `https://bugzilla.example.org/show_bug.cgi?id=123`가 됩니다).
   - **새 이슈 URL**: 연결된 Bugzilla 프로젝트에서 새 이슈를 생성하기 위한 URL입니다. 예를 들어, "My Cool App"이라는 프로젝트의 경우: `https://bugzilla.example.org/enter_bug.cgi#h=dupes%7CMy+Cool+App`.

1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

Bugzilla를 구성하고 켜면 GitLab 프로젝트 페이지에 링크가 표시됩니다. 이 링크를 통해 적절한 Bugzilla 프로젝트로 이동합니다.

이 프로젝트에서 [GitLab 내부 이슈 추적](../issues/_index.md)을 끌 수도 있습니다. GitLab 이슈를 끄는 단계 및 결과에 대한 자세한 내용은 다음을 참조하세요:

- [프로젝트 가시성 변경](../../public_access.md#change-project-visibility).
- [프로젝트 기능 및 권한 구성](../settings/_index.md#configure-project-features-and-permissions).

## GitLab에서 Bugzilla 이슈 참조 {#reference-bugzilla-issues-in-gitlab}

다음을 사용하여 Bugzilla의 이슈를 참조할 수 있습니다:

- `#<ID>`, 여기서 `<ID>`는 숫자입니다(예: `#143`).
- `<PROJECT>-<ID>` (예: `API_32-143`) 여기서:
  - `<PROJECT>`은 대문자로 시작하고 그 뒤에 대문자, 숫자 또는 밑줄이 따릅니다.
  - `<ID>`은 숫자입니다.

`<PROJECT>` 부분은 링크에서 무시되며, 항상 **이슈 URL**에 지정된 주소를 가리킵니다.

내부 및 외부 이슈 추적기를 모두 켜서 있는 경우 더 긴 형식(`<PROJECT>-<ID>`)을 사용합니다. 더 짧은 형식을 사용하고 내부 이슈 추적기에 같은 ID를 가진 이슈가 있으면 내부 이슈가 연결됩니다.

## 문제 해결 {#troubleshooting}

최근 통합 웹후크 전달에 대해서는 통합 웹후크 로그를 확인합니다.
