---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Pivotal Tracker
description: 커밋 메시지를 Pivotal Tracker 스토리에 주석으로 추가하고 커밋에서 스토리를 종료하도록 Pivotal Tracker 통합을 구성합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pivotal Tracker 통합은 커밋 메시지를 Pivotal Tracker 스토리에 주석으로 추가합니다.

통합을 활성화한 후 커밋 메시지는 해시 기호 뒤에 스토리 ID가 포함된 대괄호가 있는지 확인됩니다(예: `[#555]`). 발견된 모든 스토리 ID에 커밋 주석이 추가됩니다.

`fix [#555]`가 포함된 메시지로 스토리를 종료할 수 있습니다. 다음 단어 중 하나를 사용할 수 있습니다:

- `fix`
- `fixed`
- `fixes`
- `complete`
- `completes`
- `completed`
- `finish`
- `finished`
- `finishes`
- `delivers`

소스 커밋 엔드포인트에 대한 자세한 내용은 [Pivotal Tracker API](https://www.pivotaltracker.com/help/api/rest/v5#Source_Commits)를 참고합니다.

Pivotal Tracker 통합에 대한 자세한 내용은 [프로젝트 통합 API](../../../api/project_integrations.md#pivotal-tracker)를 참고합니다.

## Pivotal Tracker 설정 {#set-up-pivotal-tracker}

Pivotal Tracker에서 [API 토큰을 생성](https://www.pivotaltracker.com/help/articles/api_token/)합니다.

GitLab에서 다음 단계를 완료합니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Pivotal Tracker**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. Pivotal Tracker에서 생성한 토큰을 붙여넣습니다.
1. 선택 사항. 이 설정을 특정 브랜치로 제한하려면 **브랜치로 제한** 필드에 쉼표로 구분하여 나열합니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.
