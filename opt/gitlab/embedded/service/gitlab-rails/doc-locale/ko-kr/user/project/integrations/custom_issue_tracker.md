---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 커스텀 이슈 트래커
description: GitLab 프로젝트를 기본 제공되지 않는 이슈 트래커에 연결하려면 커스텀 이슈 트래커 통합을 구성합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[외부 이슈 트래커](../../../integration/external-issue-tracker.md)를 GitLab과 통합할 수 있습니다. 선호하는 이슈 트래커가 [통합 목록](../../../integration/external-issue-tracker.md#configure-an-external-issue-tracker)에 없으면 커스텀 이슈 트래커를 켤 수 있습니다.

커스텀 이슈 트래커를 켠 후 프로젝트의 왼쪽 사이드바에 이슈 트래커 링크가 나타납니다.

![프로젝트의 왼쪽 사이드바에 있는 커스텀 이슈 트래커 링크](img/custom_issue_tracker_v18_3.png)

## 커스텀 이슈 트래커 활성화 {#enable-a-custom-issue-tracker}

프로젝트에서 커스텀 이슈 트래커를 켜려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **커스텀 이슈 트래커**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 필수 필드를 입력합니다:
   - **프로젝트 URL**: 커스텀 이슈 트래커의 모든 이슈를 보는 URL입니다.
   - **이슈 URL**: 커스텀 이슈 트래커에서 이슈를 보는 URL입니다. URL에는 `:id`가 포함되어야 합니다. GitLab은 `:id`을 이슈 번호로 바꿉니다(예: `https://customissuetracker.com/project-name/:id`, 이는 `https://customissuetracker.com/project-name/123`가 됩니다).
   - **새 이슈 URL**: 모든 URL을 입력합니다. 이 URL은 사용되지 않으며 제거하려면 [이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/327503)가 있습니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 커스텀 이슈 트래커의 이슈 참조 {#reference-issues-in-a-custom-issue-tracker}

다음을 사용하여 커스텀 이슈 트래커에서 이슈를 참조할 수 있습니다:

- `#<ID>`, 여기서 `<ID>`는 숫자입니다(예: `#143`).
- `<PROJECT>-<ID>` (예: `API_32-143`) 여기서:
  - `<PROJECT>`은 대문자로 시작하고 그 뒤에 대문자, 숫자 또는 밑줄이 따릅니다.
  - `<ID>`은 숫자입니다.

`<PROJECT>` 부분은 링크에서 무시되며, 항상 **이슈 URL**에 지정된 주소를 가리킵니다.

내부 및 외부 이슈 추적기를 모두 켜서 있는 경우 더 긴 형식(`<PROJECT>-<ID>`)을 사용합니다. 더 짧은 형식을 사용하고 내부 이슈 추적기에 같은 ID를 가진 이슈가 있으면 내부 이슈가 연결됩니다.
