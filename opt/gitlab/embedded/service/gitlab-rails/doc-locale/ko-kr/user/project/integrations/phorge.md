---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Phorge
description: Phorge 통합을 구성하여 GitLab 프로젝트를 Phorge 인스턴스에 연결하고 GitLab에서 Phorge 작업을 참조합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab에서 [Phorge](https://we.phorge.it/)를 [외부 이슈 추적 도구](../../../integration/external-issue-tracker.md)로 사용할 수 있습니다.

## 통합 구성 {#configure-the-integration}

GitLab 프로젝트에서 Phorge를 구성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Phorge**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. **프로젝트 URL**에 Phorge 프로젝트의 URL을 입력합니다.
1. **이슈 URL**에 Phorge 프로젝트 이슈의 URL을 입력합니다. URL에는 `:id`이 포함되어야 합니다. GitLab이 이 토큰을 Maniphest 작업 ID(예: `T123`)로 바꿉니다.
1. **새 이슈 URL**에 새 Phorge 프로젝트 이슈의 URL을 입력합니다. 이 프로젝트와 관련된 태그를 미리 채우려면 `?tags=`을 사용할 수 있습니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

해당 GitLab 프로젝트에서 Phorge 프로젝트로의 링크를 볼 수 있습니다. 이제 `T<ID>`(여기서 `<ID>`은 Maniphest 작업 ID, 예: `T123`)를 사용하여 GitLab에서 Phorge 이슈 및 작업을 참조할 수 있습니다.
