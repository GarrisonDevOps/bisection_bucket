---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Redmine
description: GitLab 프로젝트를 Redmine 이슈 트래커에 연결하고 GitLab에서 Redmine 이슈를 참조하기 위해 Redmine 통합을 구성합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

사전 요구 사항:

- 프로젝트에서 [GitLab 내부 이슈 추적을 비활성화](../../../integration/external-issue-tracker.md#disable-the-gitlab-issue-tracker)해야 합니다. GitLab 이슈를 비활성화하는 단계 및 결과에 대한 자세한 내용은 [프로젝트 표시 변경](../../public_access.md#change-project-visibility) 및 [프로젝트 기능 및 권한 구성](../settings/_index.md#configure-project-features-and-permissions)을 참조하세요.

[Redmine](https://www.redmine.org/)을 [외부 이슈 트래커](../../../integration/external-issue-tracker.md)로 사용할 수 있습니다. 프로젝트에서 Redmine 통합을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Redmine**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 필수 필드를 채웁니다:

   - **프로젝트 URL**: 이 GitLab 프로젝트에 연결할 Redmine 프로젝트의 URL입니다.
   - **이슈 URL**: 이 GitLab 프로젝트에 연결할 Redmine 프로젝트 이슈의 URL입니다. URL에는 `:id`이 포함되어야 합니다. GitLab은 이 ID를 이슈 번호로 바꿉니다.
   - **새 이슈 URL**: 이 GitLab 프로젝트에 연결된 Redmine 프로젝트에서 새 이슈를 생성하는 데 사용할 URL입니다.

     <!-- The note below was originally added in January 2018: <https://gitlab.com/gitlab-org/gitlab/-/commit/778b231f3a5dd42ebe195d4719a26bf675093350> -->

     > [!note]
     > 이 URL은 사용되지 않으며 향후 릴리스에서 제거될 예정입니다. 자세한 내용은 [이슈 327503](https://gitlab.com/gitlab-org/gitlab/-/issues/327503)을 참조하세요.

1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

Redmine을 구성하고 활성화하면 GitLab 프로젝트 페이지에 링크가 나타납니다. 이 링크는 Redmine 프로젝트로 이동합니다.

예를 들어 `gitlab-ci`이라는 프로젝트의 구성은 다음과 같습니다:

- 프로젝트 URL: `https://redmine.example.com/projects/gitlab-ci`
- 이슈 URL: `https://redmine.example.com/issues/:id`
- 새 이슈 URL: `https://redmine.example.com/projects/gitlab-ci/issues/new`

## GitLab에서 Redmine 이슈 참조 {#reference-redmine-issues-in-gitlab}

다음을 사용하여 Redmine 이슈를 참조할 수 있습니다:

- `#<ID>`(여기서 `<ID>`는 숫자입니다. 예: `#143`).
- `<PROJECT>-<ID>`(예: `API_32-143`) 형식은 다음과 같습니다:
  - `<PROJECT>`은 대문자로 시작하고 그 뒤에 대문자, 숫자 또는 밑줄이 따릅니다.
  - `<ID>`은 숫자입니다.

링크에서 `<PROJECT>` 부분은 무시되고 항상 **이슈 URL**에 지정된 주소를 가리킵니다.

내부 및 외부 이슈 트래커가 모두 활성화된 경우 더 긴 형식(`<PROJECT>-<ID>`)을 사용합니다. 더 짧은 형식을 사용하고 내부 이슈 트래커에 같은 ID를 가진 이슈가 있으면 내부 이슈가 연결됩니다.
