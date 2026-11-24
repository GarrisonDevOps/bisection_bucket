---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 머지 리퀘스트를 포크할 때 상위 리포지토리의 멤버가 포크에 기여할 수 있는지 여부를 설정할 수 있습니다.
title: 포크 간 머지 리퀘스트에서 협력하기
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[포크](../repository/forking_workflow.md)에서 머지 리퀘스트를 열면 상위 멤버와 브랜치에서 협력할 수 있습니다. 이 옵션을 활성화하면 대상 브랜치로 병합할 수 있는 권한이 있는 멤버가 머지 리퀘스트의 소스 브랜치에 쓸 수 있는 권한을 얻습니다.

상위 프로젝트의 멤버는 병합하기 전에 작은 수정을 하거나 브랜치를 리베이스할 수 있습니다.

이 기능은 [공개적으로 액세스 가능한](../../public_access.md) 포크된 프로젝트의 머지 리퀘스트에 사용할 수 있습니다.

## 상위 멤버의 커밋 허용 {#allow-commits-from-upstream-members}

머지 리퀘스트의 작성자는 기여하는 프로젝트의 상위 멤버로부터 커밋 편집을 허용할 수 있습니다:

1. 머지 리퀘스트를 생성하거나 편집할 때 **기여**로 스크롤하고 **대상 브랜치로 병합할 수 있는 멤버로부터의 커밋 허용** 확인란을 선택합니다.
1. 머지 리퀘스트 생성을 완료합니다.

머지 리퀘스트를 생성한 후 머지 리퀘스트 위젯에 **병합할 수 있는 멤버가 커밋을 추가할 수 있습니다** 메시지가 표시됩니다. 그러면 상위 멤버는:

- 브랜치에 직접 커밋합니다.
- 머지 리퀘스트의 파이프라인과 작업을 재시도합니다.

## 상위 멤버의 커밋 방지 {#prevent-commits-from-upstream-members}

머지 리퀘스트의 작성자는 기여하는 프로젝트의 상위 멤버로부터 커밋 편집을 방지할 수 있습니다:

1. 머지 리퀘스트를 생성하거나 편집할 때 **기여**로 스크롤하고 **대상 브랜치로 병합할 수 있는 멤버로부터의 커밋 허용** 확인란을 선택 해제합니다.
1. 머지 리퀘스트 생성을 완료합니다.

## 상위 멤버로서 포크에 푸시 {#push-to-the-fork-as-the-upstream-member}

다음의 경우 포크된 리포지토리의 브랜치에 직접 푸시할 수 있습니다:

- 머지 리퀘스트의 작성자가 상위 멤버의 기여를 활성화했습니다.
- 상위 프로젝트의 개발자, 유지보수자 또는 소유자 역할을 가지고 있습니다.

포크의 브랜치에 변경을 푸시하거나 커밋을 추가하려면 명령줄 Git을 사용할 수 있습니다. 자세한 내용은 [상위 멤버로서 포크에 푸시하기 위해 Git 사용](../../../topics/git/forks.md#push-to-a-fork-as-an-upstream-member)을 참고합니다.

## 문제 해결 {#troubleshooting}

### 포크된 프로젝트의 MR 페이지에서 파이프라인 상태를 사용할 수 없음 {#pipeline-status-unavailable-from-mr-page-of-forked-project}

사용자가 프로젝트를 포크할 때 포크된 복사본의 권한이 원본 프로젝트에서 복사되지 않습니다. 포크의 작성자는 상위 프로젝트의 멤버가 머지 리퀘스트의 변경을 보거나 병합하기 전에 포크된 복사본에 권한을 부여해야 합니다.

포크된 프로젝트의 머지 리퀘스트 페이지에서 파이프라인 상태를 보고 원본 프로젝트로 돌아가려면:

1. [그룹 생성](../../group/_index.md#create-a-group)은 모든 상위 멤버를 포함합니다.
1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 포크된 프로젝트를 찾습니다.
1. 포크된 프로젝트에서 **관리** > **멤버** 페이지로 이동하여 새로 생성된 그룹을 포크된 프로젝트에 초대합니다.
