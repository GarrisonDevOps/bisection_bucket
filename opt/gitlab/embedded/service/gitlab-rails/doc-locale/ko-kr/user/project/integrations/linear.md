---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Linear
description: Linear 통합을 구성하여 GitLab 프로젝트를 Linear 작업 영역에 연결하고 GitLab에서 Linear 이슈를 참조합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/198297)되었습니다.

{{< /history >}}

[Linear](https://linear.app/)를 [외부 이슈 추적 도구](../../../integration/external-issue-tracker.md)로 사용할 수 있습니다. 프로젝트에서 Linear 통합을 켜려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Linear**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 필수 필드를 입력합니다:

   - **작업공간 URL**: 이 GitLab 프로젝트에 연결할 Linear 작업 영역 프로젝트의 URL입니다.

1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

Linear를 구성하고 켠 후, GitLab 프로젝트 페이지에 링크가 나타납니다. 링크는 Linear 작업 영역으로 이동합니다.

예를 들어, `example`라는 이름의 작업 영역에 대한 구성은 다음과 같습니다:

- 작업공간 URL: `https://linear.app/example`

이 프로젝트에서 [GitLab 내부 이슈 추적](../issues/_index.md)을 끌 수도 있습니다. GitLab 이슈를 끄는 단계 및 결과에 대한 자세한 내용은 다음을 참조합니다:

- [프로젝트 공개 범위 변경](../../public_access.md#change-project-visibility).
- [프로젝트 기능 및 권한 구성](../settings/_index.md#configure-project-features-and-permissions).

## GitLab에서 Linear 이슈 참조 {#reference-linear-issues-in-gitlab}

다음을 사용하여 Linear 이슈를 참조할 수 있습니다:

- `<TEAM>-<ID>`(예: `API-123`) 여기서:
  - `<TEAM>`는 팀 식별자입니다.
  - `<ID>`은 숫자입니다.
