---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 변경 사항 임시 저장하기
---

다른 브랜치로 변경하고 싶지만 커밋할 준비가 되지 않은 미커밋 변경 사항이 있을 때 `git stash`을 사용합니다.

## 임시 저장 항목 만들기 {#create-stash-entries}

기본적으로 `git stash`은 워킹 디렉토리의 추적된 변경 사항과 스테이지된 모든 변경 사항을 저장합니다. 포함할 변경 사항을 제어하는 옵션을 사용할 수 있습니다.

- 추적된 변경 사항을 임시 저장하려면:

  ```shell
  git stash
  ```

- 메시지와 함께 변경 사항을 임시 저장하려면:

  ```shell
  git stash push -m "describe your changes here"
  ```

- 변경 사항을 임시 저장하되 워킹 디렉토리에서 스테이지된 변경 사항을 유지하려면:

  ```shell
  git stash push -k
  ```

  `-k` (`--keep-index`) 옵션은 변경 사항을 임시 저장하되 워킹 디렉토리에도 유지합니다. 변경 사항을 임시로 저장하면서 계속 작업하려는 경우 이 옵션을 사용합니다.
- 변경 사항을 임시 저장하고 추적되지 않는 파일을 포함하려면:

  ```shell
  git stash push -u
  ```

  `-u` (`--include-untracked`) 옵션은 Git에서 아직 추적하지 않는 파일도 임시 저장합니다. 이 옵션이 없으면 커밋되지 않은 새 파일은 워킹 디렉토리에 남아있습니다.
- 스테이지된 변경 사항만 임시 저장하려면:

  ```shell
  git stash push -S
  ```

  `-S` (`--staged`) 옵션은 스테이지된 변경 사항만 임시 저장합니다. 스테이지된 변경 사항을 저장하면서 스테이지되지 않은 변경 사항에 대해 계속 작업하려는 경우 이 옵션을 사용합니다.

## 임시 저장 항목 적용하기 {#apply-stash-entries}

작업을 임시 저장한 후 많은 변경 사항을 만들면 임시 저장을 적용할 때 충돌이 발생할 수 있습니다. 변경 사항을 적용하기 전에 이러한 충돌을 해결해야 합니다.

- 가장 최근의 임시 저장 항목을 적용하고 임시 저장에 유지하려면:

  ```shell
  git stash apply
  ```

- 특정 임시 저장 항목을 적용하려면:

  ```shell
  git stash apply stash@{3}
  ```

- 가장 최근의 임시 저장 항목을 적용하고 임시 저장에서 제거하려면:

  ```shell
  git stash pop
  ```

## 임시 저장 항목 보기 {#view-stash-entries}

- 모든 임시 저장 항목을 보려면:

  ```shell
  git stash list
  ```

- 더 자세한 임시 저장 항목을 보려면:

  ```shell
  git stash list --stat
  ```

## 임시 저장 항목 삭제하기 {#delete-stash-entries}

- 가장 최근의 임시 저장 항목을 삭제하려면:

  ```shell
  git stash drop
  ```

- 특정 임시 저장 항목을 삭제하려면:

  ```shell
  git stash drop <name>
  ```

- 모든 임시 저장 항목을 삭제하려면:

  ```shell
  git stash clear
  ```

## 예: 임시 저장 항목 만들고 적용하기 {#example-create-and-apply-a-stash-entry}

Git 임시 저장을 사용해 보려면:

1. Git 리포지토리에서 파일을 수정합니다.
1. 수정 사항을 임시 저장합니다:

   ```shell
   git stash push -m "Saving changes from edit"
   ```

1. 임시 저장 목록을 봅니다:

   ```shell
   git stash list
   ```

1. 대기 중인 변경 사항이 없는지 확인합니다:

   ```shell
   git status
   ```

1. 임시 저장된 변경 사항을 적용하고 임시 저장에서 항목을 제거합니다:

   ```shell
   git stash pop
   ```

1. 항목이 제거되었는지 확인하기 위해 임시 저장 목록을 봅니다:

   ```shell
   git stash list
   ```

## 관련 항목 {#related-topics}

- [공식 Git 임시 저장 문서](https://git-scm.com/docs/git-stash)
