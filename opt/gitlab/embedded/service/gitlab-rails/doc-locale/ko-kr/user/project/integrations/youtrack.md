---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: YouTrack
description: YouTrack 통합을 구성하여 GitLab 프로젝트를 YouTrack 인스턴스에 연결하고 GitLab에서 YouTrack 이슈를 참조합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

JetBrains [YouTrack](https://www.jetbrains.com/youtrack/)는 웹 기반 이슈 추적 및 프로젝트 관리 플랫폼입니다.

YouTrack을 GitLab의 [외부 이슈 추적 도구](../../../integration/external-issue-tracker.md)로 구성할 수 있습니다.

프로젝트에서 YouTrack 통합을 활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **YouTrack**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 필수 필드를 입력합니다:
   - **프로젝트 URL**: YouTrack의 프로젝트에 대한 URL입니다.
   - **이슈 URL**: YouTrack 프로젝트에서 이슈를 보기 위한 URL입니다. URL은 `:id`을 포함해야 합니다. GitLab은 `:id`을 이슈 번호로 바꿉니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

YouTrack을 구성하고 활성화하면 GitLab 프로젝트 페이지에 링크가 나타납니다. 이 링크는 해당 YouTrack 프로젝트로 이동합니다.

이 프로젝트에서 [GitLab 내부 이슈 추적](../issues/_index.md)을 끌 수도 있습니다. GitLab 이슈를 끄는 단계 및 결과에 대한 자세한 내용은 다음을 참조합니다:

- [프로젝트 공개 범위 변경](../../public_access.md#change-project-visibility).
- [프로젝트 기능 및 권한 구성](../settings/_index.md#configure-project-features-and-permissions).

## GitLab에서 YouTrack 이슈 참조 {#reference-youtrack-issues-in-gitlab}

`<PROJECT>-<ID>`(예: `YT-101`, `Api_32-143` 또는 `gl-030`)를 사용하여 YouTrack의 이슈를 참조할 수 있습니다. 여기서:

- `<PROJECT>`은 문자로 시작하며 그 뒤에 문자, 숫자 또는 밑줄이 따릅니다.
- `<ID>`은 숫자입니다.

병합 요청, 커밋 또는 댓글에서 `<PROJECT>-<ID>`에 대한 참조는 YouTrack 이슈 URL로 자동으로 연결됩니다.
