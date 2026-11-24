---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Git 리베이스와 강제 푸시 소개, 명령어를 통한 머지 충돌 해결 방법."
title: 리베이스 및 머지 충돌 해결
---

Git 리베이스는 커밋을 대상 브랜치의 끝으로 이동시켜 한 브랜치의 변경 사항을 다른 브랜치로 결합합니다. 이 작업은:

- 대상 브랜치의 최신 코드로 브랜치를 업데이트합니다.
- 더 쉬운 디버깅과 코드 검토를 위해 깔끔한 선형 커밋 히스토리를 유지합니다.
- [머지 충돌](../../user/project/merge_requests/conflicts.md)을 커밋 수준에서 해결하여 충돌 해결을 위한 기능을 제공합니다.
- 코드 변경의 시간순 순서를 유지합니다.

리베이스할 때:

1. Git은 브랜치를 처음 생성한 후 대상 브랜치에 제출된 모든 커밋을 가져옵니다.
1. Git은 가져온 커밋 위에 브랜치의 커밋을 적용합니다. 이 예제에서는 `feature`라는 이름의 브랜치를 생성한 후(주황색), `main`의 4개 커밋(자주색)이 `feature` 브랜치로 가져와집니다:

   ![메인 브랜치로 리베이스된 기능 브랜치.](img/rebase_v17_10.drawio.svg)

대부분의 리베이스는 `main`에 대해 수행되지만, 다른 브랜치에 대해 리베이스할 수 있습니다. 다른 원격 리포지토리를 지정할 수도 있습니다. 예를 들어, `upstream` 대신 `origin`를 사용합니다.

> [!warning]
> `git rebase`는 커밋 히스토리를 다시 작성합니다. 공유 브랜치에서 충돌이 발생할 수 있으며 복잡한 머지 충돌을 초래할 수 있습니다. 기본 브랜치에 대해 리베이스하는 대신 `git pull origin master`를 사용하는 것을 권장합니다. 풀링은 비슷한 효과를 제공하지만 다른 사람의 작업을 손상시킬 위험이 적습니다.

## 리베이스 {#rebase}

Git을 사용하여 리베이스할 때, 각 커밋이 브랜치에 적용됩니다. 머지 충돌이 발생하면 해결하라는 메시지가 표시됩니다.

커밋을 위한 더 많은 옵션을 보려면 [대화형 리베이스](#interactive-rebase)를 사용하세요.

전제 조건:

- 브랜치에 강제 푸시하려면 [권한](../../user/permissions.md)이 필요합니다.

Git을 사용하여 대상 브랜치에 대해 브랜치를 리베이스하려면:

1. 터미널을 열고 프로젝트 디렉토리로 변경합니다.
1. 대상 브랜치의 최신 내용이 있는지 확인합니다. 이 예제에서 대상 브랜치는 `main`입니다:

   ```shell
   git fetch origin main
   ```

1. 브랜치를 확인합니다:

   ```shell
   git checkout my-branch
   ```

1. 선택사항. 브랜치의 백업을 만듭니다:

   ```shell
   git branch my-branch-backup
   ```

   `my-branch`에 추가된 변경 사항은 백업 브랜치에서 복원하면 손실됩니다.
1. `main` 브랜치에 대해 리베이스합니다:

   ```shell
   git rebase origin/main
   ```

1. 머지 충돌이 존재하면:
   1. 편집기에서 충돌을 해결합니다.
   1. 변경 사항을 스테이지합니다:

      ```shell
      git add .
      ```

   1. 리베이스를 계속합니다:

      ```shell
      git rebase --continue
      ```

1. 변경 사항을 대상 브랜치로 강제 푸시하면서 다른 사람의 커밋을 보호합니다:

   ```shell
   git push origin my-branch --force-with-lease
   ```

## 대화형 리베이스 {#interactive-rebase}

대화형 리베이스를 사용하여 각 커밋을 처리하는 방법을 지정합니다. 다음 지시사항은 [Vim](https://www.vim.org/) 텍스트 편집기를 사용하여 커밋을 편집합니다.

대화형으로 리베이스하려면:

1. 터미널을 열고 프로젝트 디렉토리로 변경합니다.
1. 대상 브랜치의 최신 내용이 있는지 확인합니다. 이 예제에서 대상 브랜치는 `main`입니다:

   ```shell
   git fetch origin main
   ```

1. 브랜치를 확인합니다:

   ```shell
   git checkout my-branch
   ```

1. 선택사항. 브랜치의 백업을 만듭니다:

   ```shell
   git branch my-branch-backup
   ```

   `my-branch`에 추가된 변경 사항은 백업 브랜치에서 복원하면 손실됩니다.
1. GitLab UI의 머지 리퀘스트에서 **커밋** 탭에 리베이스할 커밋 개수를 확인합니다.
1. 이 커밋을 엽니다. 예를 들어, 마지막 5개 커밋을 편집하려면:

   ```shell
   git rebase -i HEAD~5
   ```

   Git은 터미널 텍스트 편집기에서 커밋을 가장 오래된 항목부터 엽니다. 각 커밋은 실행할 작업, SHA 및 커밋 제목을 표시합니다. 예를 들어:

   ```shell
   pick 111111111111 Second round of structural revisions
   pick 222222222222 Update inbound link to this changed page
   pick 333333333333 Shifts from H4 to H3
   pick 444444444444 Adds revisions from editorial
   pick 555555555555 Revisions continue to build the concept part out

   # Rebase 111111111111..222222222222 onto zzzzzzzzzzzz (5 commands)
   #
   # Commands:
   # p, pick <commit> = use commit
   # r, reword <commit> = use commit, but edit the commit message
   # e, edit <commit> = use commit, but stop for amending
   # s, squash <commit> = use commit, but meld into previous commit
   # f, fixup [-C | -c] <commit> = like "squash" but keep only the previous
   ```

1. <kbd>i</kbd>를 눌러 Vim의 편집 모드로 전환합니다.
1. 화살표 키를 사용하여 커서를 편집하려는 커밋으로 이동합니다.
1. 첫 번째를 제외한 각 커밋에 대해 `pick`을 `squash` 또는 `fixup`(또는 `s` 또는 `f`)으로 변경합니다.
1. 남은 커밋에 대해 반복합니다.
1. 편집 모드를 종료하고 저장한 후 종료합니다:

   - <kbd>ESC</kbd>를 누릅니다.
   - `:wq`을 입력합니다.

1. 스쿼싱할 때 Git은 커밋 메시지를 편집하라는 메시지를 표시합니다:

   - `#`로 시작하는 줄은 무시되며 커밋 메시지에 포함되지 않습니다.
   - 현재 메시지를 유지하려면 `:wq`을 입력합니다.
   - 커밋 메시지를 편집하려면 편집 모드로 전환하고 변경 사항을 만든 후 저장합니다.

1. 변경 사항을 대상 브랜치로 푸시합니다.

   - 리베이스하기 전에 커밋을 대상 브랜치로 푸시하지 않은 경우:

     ```shell
     git push origin my-branch
     ```

   - 이미 커밋을 푸시한 경우:

     ```shell
     git push origin my-branch --force-with-lease
     ```

     일부 작업은 브랜치를 변경하기 위해 강제 푸시가 필요합니다. 자세한 내용은 [원격 브랜치에 강제 푸시](#force-push-to-a-remote-branch)를 참조하세요.

## 명령어에서 충돌 해결 {#resolve-conflicts-from-the-command-line}

각 변경사항을 가장 잘 제어하려면 GitLab 대신 명령어에서 로컬로 복잡한 충돌을 해결해야 합니다.

전제 조건:

- 브랜치에 강제 푸시하려면 [권한](../../user/permissions.md)이 필요합니다.

1. 터미널을 열고 기능 브랜치를 확인합니다:

   ```shell
   git switch my-feature-branch
   ```

1. 대상 브랜치에 대해 브랜치를 리베이스합니다. 이 예제에서 대상 브랜치는 `main`입니다:

   ```shell
   git fetch
   git rebase origin/main
   ```

1. 원하는 코드 편집기에서 충돌하는 파일을 엽니다.
1. 충돌 블록을 찾아 해결합니다:
   1. `=======`보다 전에 또는 후의 버전 중 유지할 버전을 선택합니다.
   1. 유지하지 않을 버전을 삭제합니다.
   1. 충돌 마커를 삭제합니다.
1. 파일을 저장합니다.
1. 충돌이 있는 각 파일에 대해 프로세스를 반복합니다.
1. 변경 사항을 스테이지합니다:

   ```shell
   git add .
   ```

1. 변경 사항을 커밋합니다:

   ```shell
   git commit -m "Resolve merge conflicts"
   ```

   > [!warning]
   > `git rebase --abort`를 실행하여 이 지점 전에 프로세스를 중지할 수 있습니다. Git은 리베이스를 중단하고 `git rebase`를 실행하기 전 상태로 브랜치를 롤백합니다. `git rebase --continue`를 실행한 후에는 리베이스를 중단할 수 없습니다.
1. 리베이스를 계속합니다:

   ```shell
   git rebase --continue
   ```

1. 원격 브랜치에 변경 사항을 강제 푸시합니다:

   ```shell
   git push origin my-feature-branch --force-with-lease
   ```

## 원격 브랜치에 강제 푸시 {#force-push-to-a-remote-branch}

커밋 스쿼싱, 브랜치 재설정 또는 리베이싱과 같은 복잡한 Git 작업은 브랜치 히스토리를 다시 작성합니다. Git은 이러한 변경 사항에 대해 강제 업데이트가 필요합니다.

공유 브랜치에서 강제 푸시는 권장되지 않습니다. 다른 사람의 변경 사항을 손상시킬 위험이 있기 때문입니다.

브랜치가 [보호됨](../../user/project/repository/branches/protected.md)인 경우 다음 중 하나를 수행하지 않는 한 강제 푸시할 수 없습니다:

- 보호를 해제합니다.
- 강제 푸시를 허용합니다.

자세한 내용은 [보호된 브랜치에서 강제 푸시 허용](../../user/project/repository/branches/protected.md#allow-force-push)을 참조하세요.

## 백업 브랜치 복원 {#restore-your-backed-up-branch}

리베이스 또는 강제 푸시가 실패하면 백업에서 브랜치를 복원합니다:

1. 올바른 브랜치에 있는지 확인합니다:

   ```shell
   git checkout my-branch
   ```

1. 브랜치를 백업으로 재설정합니다:

   ```shell
   git reset --hard my-branch-backup
   ```

## 리베이스 후 승인 {#approving-after-rebase}

브랜치를 리베이스한 후 Git은 각 리베이스된 커밋에 대해 Git 커미터를 변경하고 Git 작성자를 보존합니다. 프로젝트가 [커밋을 추가하는 사용자의 승인 방지](../../user/project/merge_requests/approvals/settings.md#prevent-approvals-by-users-who-add-commits)로 구성된 경우 GitLab은 Git 커미터로서 승인에서 사용자를 제외합니다. GitLab은 또한 각 원본 Git 작성자를 제외합니다.

머지 리퀘스트를 승인하고 리베이스한 후 GitLab은 계속해서 승인을 표시할 수 있습니다. 승인은 머지 리퀘스트에 필요한 승인에 포함되지 않습니다.

## 관련 항목 {#related-topics}

- [변경 사항 되돌리기 및 실행 취소](undo.md)
- [브랜치 및 리베이스를 위한 Git 설명서](https://git-scm.com/book/en/v2/Git-Branching-Rebasing)
- [프로젝트 스쿼시 및 머지 설정](../../user/project/merge_requests/squash_and_merge.md#configure-squash-options-for-a-project)
- [병합 충돌](../../user/project/merge_requests/conflicts.md)

## 문제 해결 {#troubleshooting}

CI/CD 파이프라인 문제 해결 정보는 [CI/CD 파이프라인 디버깅](../../ci/debugging.md)을 참조하세요.

### `Unmergeable state` (`/rebase` 빠른 작업 후) {#unmergeable-state-after-rebase-quick-action}

`/rebase` 명령은 백그라운드 작업을 예약합니다. 작업은 소스 브랜치의 변경 사항을 대상 브랜치의 최신 커밋에 리베이스하려고 시도합니다. [`/rebase` 빠른 작업](../../user/project/quick_actions.md#rebase)을 사용한 후 이 오류가 표시되면 리베이스를 예약할 수 없습니다:

```plaintext
This merge request is currently in an unmergeable state, and cannot be rebased.
```

이 오류는 다음 조건 중 하나라도 참인 경우 발생합니다:

- 소스 및 대상 브랜치 간에 충돌이 존재합니다.
- 소스 브랜치에 커밋이 없습니다.
- 소스 또는 대상 브랜치 중 하나가 존재하지 않습니다.
- 오류가 발생하여 diff가 생성되지 않았습니다.

`unmergeable state` 오류를 해결하려면:

1. 머지 충돌을 해결합니다.
1. 소스 브랜치가 존재하고 커밋이 있음을 확인합니다.
1. 대상 브랜치가 존재함을 확인합니다.
1. diff가 생성되었음을 확인합니다.

### `/merge` 빠른 작업은 `/rebase` 후 무시됩니다 {#merge-quick-action-ignored-after-rebase}

`/rebase`이 사용되면 `/merge`는 소스 브랜치가 리베이스되기 전에 병합되거나 삭제되는 경쟁 조건을 피하기 위해 무시됩니다.
