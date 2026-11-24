---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 머지 리퀘스트에서 커밋 표시를 읽는 방법을 이해합니다.
title: 커밋
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

커밋은 소스 코드 변경 사항을 [리포지토리](../repository/_index.md)에 기록하고 전송합니다. 자세한 내용은 [리포지토리에 변경 사항 기록](https://git-scm.com/book/en/v2/Git-Basics-Recording-Changes-to-the-Repository)을 참조하세요.

## 명령줄을 사용하여 커밋 변경 {#commit-changes-using-the-command-line}

명령줄을 사용할 때는 [`git commit`](../../../topics/git/commands.md#git-commit)을 사용합니다. 변경 사항을 푸시하기 전에 여러 커밋을 추가할 수 있습니다.

- 커밋 메시지:

  커밋 메시지는 변경된 내용과 이유를 식별합니다. 변경 사항을 명확히 하기 위해 설명적 메시지를 사용합니다. GitLab에서는 커밋 메시지에 키워드를 추가하여 다음 중 하나의 작업을 수행할 수 있습니다:

  - GitLab CI/CD 파이프라인 트리거:

    프로젝트가 [GitLab CI/CD](../../../ci/_index.md)로 구성되어 있으면 커밋당이 아니라 푸시당 파이프라인을 트리거합니다.

  - 파이프라인 건너뛰기:

    [`ci skip`](../../../ci/pipelines/_index.md#skip-a-pipeline) 키워드를 커밋 메시지에 추가하여 GitLab CI/CD가 파이프라인을 건너뛰도록 합니다.

  - 이슈 및 머지 리퀘스트 교차 연결:

    [교차 연결](../issues/crosslinking_issues.md#from-commit-messages)을 사용하여 워크플로우의 관련 부분을 추적합니다. 커밋 메시지에서 이슈 또는 머지 리퀘스트를 언급하면 각 스레드에 표시됩니다.

- 커밋 체리 픽:

  GitLab에서는 UI에서 [커밋 체리 픽](cherry_pick_changes.md#cherry-pick-a-single-commit)을 수행할 수 있습니다.

- 커밋 되돌리기:

  UI에서 [커밋 되돌리기](revert_changes.md#revert-a-commit)를 선택한 브랜치로 수행합니다.

- 커밋 서명:

  [커밋 서명](../repository/signed_commits/_index.md)으로 추가 보안을 제공합니다.

자세한 내용은 [스테이지, 커밋 및 변경 사항 푸시](../../../topics/git/commit.md)를 참조하세요.

## 머지 리퀘스트 커밋 {#merge-request-commits}

각 머지 리퀘스트에는 머지 리퀘스트가 생성된 후 소스 브랜치에 만들어진 커밋의 이력이 있습니다.

이 커밋들은 머지 리퀘스트의 **커밋** 탭에 표시됩니다. 이 탭에서 커밋 메시지를 검토하고 커밋을 [체리 픽](cherry_pick_changes.md)해야 할 때 커밋의 SHA를 복사할 수 있습니다.

### 머지 리퀘스트에서 커밋 보기 {#view-commits-in-a-merge-request}

머지 리퀘스트에 포함된 커밋을 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **머지 리퀘스트**를 선택한 후 머지 리퀘스트를 선택합니다.
1. 머지 리퀘스트의 커밋 목록을 최신순으로 표시하려면 **커밋**을 선택합니다. 커밋에 대해 자세히 알아보려면 모든 커밋에서 **커밋 설명 토글**({{< icon name="ellipsis_h" >}})을 선택합니다.
1. 커밋의 변경 사항을 보려면 커밋 링크의 제목을 선택합니다.
1. 머지 리퀘스트의 다른 커밋을 보려면 다음 중 하나를 수행합니다:

   - **이전** 또는 **다음**을 선택합니다.
   - 키보드 단축키를 사용합니다: <kbd>X</kbd>(이전 커밋) 및 <kbd>C</kbd>(다음 커밋).

머지 리퀘스트가 이전 머지 리퀘스트를 기반으로 하는 경우 [컨텍스트를 위해 더 많은 커밋을 포함](#show-commits-from-previous-merge-requests)해야 할 수 있습니다.

### 이전 머지 리퀘스트에서 커밋 표시 {#show-commits-from-previous-merge-requests}

머지 리퀘스트를 검토할 때 검토 중인 커밋을 이해하기 위해 이전 커밋의 정보가 필요할 수 있습니다. 다른 머지 리퀘스트의 경우 더 많은 컨텍스트가 필요할 수 있습니다:

- 현재 머지 리퀘스트가 수정하지 않는 파일을 변경하여 해당 파일이 현재 머지 리퀘스트의 diff에 표시되지 않습니다.
- 현재 머지 리퀘스트에서 수정 중인 파일을 변경하고 작업 진행 과정을 확인해야 합니다.

더 많은 컨텍스트를 위해 이전에 머지된 커밋을 머지 리퀘스트에 추가하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **머지 리퀘스트**를 선택한 후 머지 리퀘스트를 선택합니다.
1. **커밋**을 선택합니다.
1. 커밋 목록의 끝으로 스크롤하고 **이전에 머지된 커밋 추가**를 선택합니다.
1. 추가하려는 커밋을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

이전에 머지된 커밋은 **컨텍스트 커밋**으로 [머지 리퀘스트 컨텍스트 커밋 API](../../../api/merge_request_context_commits.md)에서 참조됩니다.

### 커밋에 댓글 추가 {#add-a-comment-to-a-commit}

> [!warning]
> 이러한 방식으로 생성된 스레드는 강제 푸시 후 커밋 ID가 변경되면 손실됩니다.

특정 커밋에 토론을 추가하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **커밋**을 선택합니다.
1. 커밋 아래의 **댓글** 필드에 댓글을 입력합니다.
1. 독립 실행형 댓글 또는 스레드로 댓글을 저장합니다:
   - 댓글을 추가하려면 **댓글**를 선택합니다.
   - 스레드를 시작하려면 아래쪽 화살표({{< icon name="chevron-down" >}})를 선택한 다음 **스레드 시작**을 선택합니다.

### 커밋 간 diff 보기 {#view-diffs-between-commits}

이전에 머지된 커밋 간의 변경 사항을 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **머지 리퀘스트**를 선택한 후 머지 리퀘스트를 선택합니다.
1. **변경사항**을 선택합니다.
1. **비교**({{< icon name="file-tree" >}}) 옆에서 비교할 커밋을 선택합니다:

   ![이전에 머지된 커밋](img/previously_merged_commits_v16_0.png)

컨텍스트에 대해 이전에 머지된 커밋을 추가하도록 선택한 경우 해당 커밋도 목록에 표시됩니다.

### 변경 사항을 도입한 머지 리퀘스트 찾기 {#find-the-merge-request-that-introduced-a-change}

커밋 세부 정보 페이지를 볼 때 GitLab은 해당 커밋을 포함하는 하나 이상의 머지 리퀘스트에 링크합니다.

이 동작은 머지 리퀘스트의 가장 최근 버전에 있는 커밋에만 적용됩니다. 커밋이 머지 리퀘스트에 있었고 해당 머지 리퀘스트에서 리베이스된 경우 커밋이 연결되지 않습니다.
