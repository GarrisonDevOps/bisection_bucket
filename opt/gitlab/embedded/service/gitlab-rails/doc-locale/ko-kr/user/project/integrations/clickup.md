---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: ClickUp
description: GitLab 프로젝트를 ClickUp에 연결하고 머지 리퀘스트 및 커밋에서 ClickUp 이슈를 참조하도록 ClickUp 통합을 구성합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[ClickUp](https://clickup.com/)을 [외부 이슈 추적 도구](../../../integration/external-issue-tracker.md)로 사용할 수 있습니다. 프로젝트에서 ClickUp 통합을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **ClickUp**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 필수 필드를 입력합니다:

   - **프로젝트 URL**: 이 GitLab 프로젝트에 연결할 ClickUp 프로젝트의 URL입니다.
   - **이슈 URL**: 이 GitLab 프로젝트에 연결할 ClickUp 프로젝트 이슈의 URL입니다. URL에는 `:id`이 포함되어야 합니다. GitLab은 이 ID를 이슈 번호로 바꿉니다.

1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

ClickUp을 구성하고 활성화한 후 GitLab 프로젝트 페이지에 링크가 나타납니다. 링크는 ClickUp 프로젝트로 이동합니다.

예를 들어 `gitlab-ci`이라는 프로젝트의 구성입니다:

- 프로젝트 URL: `https://app.clickup.com/1234567`
- 이슈 URL: `https://app.clickup.com/t/1234567/:id`

이 프로젝트에서 [GitLab 내부 이슈 추적](../issues/_index.md)을 비활성화할 수도 있습니다. GitLab 이슈를 비활성화하는 단계 및 결과에 대한 자세한 내용은 다음을 참조하세요:

- [프로젝트 가시성 변경](../../public_access.md#change-project-visibility)
- [프로젝트 기능 및 권한 구성](../settings/_index.md#configure-project-features-and-permissions)

## GitLab에서 ClickUp 이슈 참조 {#reference-clickup-issues-in-gitlab}

다음을 사용하여 ClickUp 이슈를 참조할 수 있습니다:

- `#<ID>`, 여기서 `<ID>`은 영숫자 문자열입니다 (예: `#8wrtcd932`).
- `CU-<ID>`, 여기서 `<ID>`은 영숫자 문자열입니다 (예: `CU-8wrtcd932`).
- `<PROJECT>-<ID>`, 예를 들어 `API_32-143`, 다음 항목:
  - `<PROJECT>`은 ClickUp 목록 사용자 지정 접두사 ID입니다.
  - `<ID>`은 숫자입니다.
- [사용자 지정 작업 ID](https://help.clickup.com/hc/en-us/sections/17044579323671-Custom-Task-IDs)를 사용하는 경우 전체 사용자 지정 작업 ID도 작동합니다. 예: `SOP-1234`.

링크에서 `CU-` 부분은 무시되며 이슈의 전역 URL로 연결됩니다. ClickUp 목록에서 사용자 지정 접두사를 사용하면 접두사 부분이 링크의 일부입니다.

내부 및 외부 이슈 추적 도구를 모두 활성화한 경우 `CU-` 형식 (`CU-<ID>`)을 사용합니다. 짧은 형식을 사용하는 경우 내부 이슈 추적 도구에 동일한 ID를 가진 이슈가 있으면 내부 이슈가 연결됩니다.

[사용자 지정 작업 ID](https://help.clickup.com/hc/en-us/sections/17044579323671-Custom-Task-IDs)의 경우 사용자 지정 접두사를 포함하여 전체 ID를 포함해야 합니다. 예를 들어, `SOP-1432`입니다.
