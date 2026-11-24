---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 직접 기여할 수 있는 권한이 없는 업스트림 리포지토리에 변경 사항을 제안하려는 경우 Git 리포지토리를 포크합니다.
title: 포크 업데이트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

포크는 선택한 네임스페이스에서 생성되는 리포지토리 및 모든 브랜치의 개인 복사본입니다. 포크를 사용하여 액세스 권한이 없는 다른 프로젝트에 변경 사항을 제안할 수 있습니다. 자세한 내용은 [포크 워크플로우](../../user/project/repository/forking_workflow.md)를 참조하세요.

[GitLab UI](../../user/project/repository/forking_workflow.md#from-the-ui)를 사용하여 포크를 업데이트할 수도 있습니다.

전제 조건:

- 로컬 머신에 [Git 클라이언트를 다운로드 및 설치](how_to_install_git/_index.md)해야 합니다.
- 업데이트할 리포지토리의 [포크를 생성](../../user/project/repository/forking_workflow.md#create-a-fork)해야 합니다.

명령줄에서 포크를 업데이트하려면:

1. `upstream` 원격 리포지토리가 포크에 대해 구성되어 있는지 확인하세요:

   1. 아직 포크를 로컬로 복제하지 않았다면 복제하세요. 자세한 내용은 [리포지토리 복제](clone.md)를 참조하세요.
   1. 포크에 대해 구성된 원격을 확인하세요:

      ```shell
      git remote -v
      ```

   1. 포크에 원본 리포지토리를 가리키는 원격이 없으면 다음 예 중 하나를 사용하여 upstream이라는 원격을 구성하세요:

      ```shell
      # Set any repository as your upstream after editing <upstream_url>
      git remote add upstream <upstream_url>

      # Set the main GitLab repository as your upstream
      git remote add upstream https://gitlab.com/gitlab-org/gitlab.git
      ```

1. 포크를 업데이트하세요:

   1. 로컬 복사본에서 [기본 브랜치](../../user/project/repository/branches/default.md)를 체크아웃하세요. `main`를 기본 브랜치의 이름으로 바꾸세요:

      ```shell
      git checkout main
      ```

      > [!note]
      > Git에서 스테이징되지 않은 변경 사항을 식별하면 계속하기 전에 [커밋 또는 stash](commit.md)하세요.

   1. 업스트림 리포지토리에서 변경 사항을 가져오세요:

      ```shell
      git fetch upstream
      ```

   1. 변경 사항을 포크로 가져오세요. `main`를 업데이트할 브랜치의 이름으로 바꾸세요:

      ```shell
      git pull upstream main
      ```

   1. 변경 사항을 서버의 포크 리포지토리에 푸시하세요:

      ```shell
      git push origin main
      ```

## 포크 간 협업 {#collaborate-across-forks}

GitLab은 업스트림 프로젝트 유지 관리자와 포크 소유자 간의 협업을 지원합니다. 자세한 정보는 다음을 참조하세요.

- [포크 간 머지 리퀘스트에서 협업](../../user/project/merge_requests/allow_collaboration.md)
  - [업스트림 멤버의 커밋 허용](../../user/project/merge_requests/allow_collaboration.md#allow-commits-from-upstream-members)
  - [업스트림 멤버의 커밋 방지](../../user/project/merge_requests/allow_collaboration.md#prevent-commits-from-upstream-members)

### 업스트림 멤버로 포크에 푸시 {#push-to-a-fork-as-an-upstream-member}

다음 조건에서 포크된 리포지토리의 브랜치에 직접 푸시할 수 있습니다:

- 머지 리퀘스트 작성자가 업스트림 멤버로부터의 기여를 활성화했습니다.
- 업스트림 프로젝트에 대한 Developer, Maintainer 또는 Owner 역할이 있습니다.

다음 예에서:

- 포크된 리포지토리 URL은 `git@gitlab.com:contributor/forked-project.git`입니다.
- 머지 리퀘스트의 브랜치는 `fork-branch`입니다.

기여자의 머지 리퀘스트에 변경 사항을 추가하거나 커밋을 추가하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **코드** > **머지 리퀘스트**로 이동하여 머지 리퀘스트를 찾으세요.
1. 오른쪽 위 모서리에서 **코드**를 선택한 다음 **브랜치 체크아웃**을 선택하세요.
1. 대화 상자에서 **복사**({{< icon name="copy-to-clipboard" >}})를 선택하세요.
1. 터미널에서 리포지토리의 복제된 버전으로 이동한 다음 명령을 붙여넣으세요. 예를 들어:

   ```shell
   git fetch "git@gitlab.com:contributor/forked-project.git" 'fork-branch'
   git checkout -b 'contributor/fork-branch' FETCH_HEAD
   ```

   이 명령은 포크된 프로젝트에서 브랜치를 가져오고 작업할 수 있는 로컬 브랜치를 생성합니다.
1. 브랜치의 로컬 복사본을 변경한 다음 커밋하세요.
1. 로컬 변경 사항을 포크된 프로젝트에 푸시하세요. 다음 명령은 로컬 브랜치 `contributor/fork-branch`를 `git@gitlab.com:contributor/forked-project.git` 리포지토리의 `fork-branch` 브랜치에 푸시합니다:

   ```shell
   git push git@gitlab.com:contributor/forked-project.git contributor/fork-branch:fork-branch
   ```

   커밋을 수정했거나 스쿼시한 경우 `git push --force`를 사용해야 합니다. 이 명령은 커밋 기록을 다시 작성하므로 주의해서 진행하세요.

   ```shell
   git push --force git@gitlab.com:contributor/forked-project.git contributor/fork-branch:fork-branch
   ```

   콜론(`:`)은 소스 브랜치와 대상 브랜치를 지정합니다. 스키마는:

   ```shell
   git push <forked_repository_git_url> <local_branch>:<fork_branch>
   ```

## 관련 항목 {#related-topics}

- [포크 워크플로우](../../user/project/repository/forking_workflow.md)
  - [포크 생성](../../user/project/repository/forking_workflow.md#create-a-fork)
  - [포크 연결 해제](../../user/project/repository/forking_workflow.md#unlink-a-fork)
- [포크 간 머지 리퀘스트에서 협업](../../user/project/merge_requests/allow_collaboration.md)
- [머지 리퀘스트](../../user/project/merge_requests/_index.md)
