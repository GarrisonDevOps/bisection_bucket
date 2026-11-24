---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Asana
description: Asana 통합을 구성하여 커밋 메시지를 Asana 작업에 주석으로 추가하고 GitLab 커밋에서 작업을 종료할 수 있습니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- V1 Asana URL 형식에 대한 지원이 GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/523692)되었습니다.

{{< /history >}}

Asana 통합은 커밋 메시지를 Asana 작업에 주석으로 추가합니다. 통합을 활성화한 후 커밋 메시지가 Asana 작업 URL(예: `https://app.asana.com/1/12345/project/67890/task/987654`) 또는 `#`(예: `#987654`)로 시작하는 작업 ID에 대해 확인됩니다. 발견된 모든 작업 ID에 커밋 주석이 추가됩니다.

`fix #123456`를 포함하는 메시지로 작업을 종료할 수도 있습니다. 다음 단어 중 하나를 사용할 수 있습니다:

- `fix`
- `fixed`
- `fixes`
- `fixing`
- `close`
- `closes`
- `closed`
- `closing`

[Asana 통합 API 설명서](../../../api/project_integrations.md#asana)도 참조하세요.

## 설정 {#setup}

Asana에서 개인 액세스 토큰을 생성합니다. [Asana의 개인 액세스 토큰에 대해 알아보기](https://developers.asana.com/docs/personal-access-token).

GitLab에서 다음 단계를 완료합니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Asana**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. Asana에서 생성한 토큰을 붙여넣습니다.
1. 선택 사항. 이 설정을 특정 브랜치로 제한하려면 쉼표로 구분하여 **브랜치로 제한** 필드에 나열합니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.
