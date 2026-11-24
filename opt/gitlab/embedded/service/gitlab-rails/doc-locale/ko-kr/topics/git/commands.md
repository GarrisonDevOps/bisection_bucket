---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "일반적으로 사용되는 Git 명령을 사용하여 코드, 브랜치, 커밋 및 리포지토리 히스토리를 관리하고 예시 및 모범 사례를 포함한 참고 가이드입니다."
title: 일반 Git 명령
---

Git 명령은 개발 워크플로 전반에서 시간을 절약합니다. 이 참고 페이지는 코드 변경, 브랜치 관리, 히스토리 검토 등의 일반적인 작업에 자주 사용되는 명령을 포함합니다. 각 명령 섹션은 정확한 구문, 실용적인 예시 및 추가 문서 링크를 제공합니다.

## `git add` {#git-add}

`git add`을 사용하여 파일을 스테이징 영역에 추가합니다.

```shell
git add <file_path>
```

현재 작업 디렉터리에서 `git add .`으로 변경 사항을 재귀적으로 스테이징하거나, Git 리포지토리의 모든 변경 사항을 `git add --all`으로 스테이징할 수 있습니다.

자세한 내용은 [브랜치에 파일 추가](add_files.md)를 참고하세요.

## `git blame` {#git-blame}

`git blame`을 사용하여 파일의 어느 부분을 누가 변경했는지 확인합니다.

```shell
git blame <file_name>
```

`git blame -L <line_start>,<line_end>`을 사용하여 특정 줄 범위를 확인할 수 있습니다.

자세한 내용은 [Git 파일 blame](../../user/project/repository/files/git_blame.md)을 참고하세요.

### 예 {#example}

`example.txt`의 5번 줄을 가장 최근에 수정한 사용자를 확인하려면:

```shell
$ git blame -L 5,5 example.txt
123abc (Zhang Wei 2021-07-04 12:23:04 +0000 5)
```

## `git bisect` {#git-bisect}

`git bisect`을 사용하여 이진 검색으로 버그를 도입한 커밋을 찾습니다.

버그를 포함한 "나쁜" 커밋과 버그를 포함하지 않은 "좋은" 커밋을 식별하는 것으로 시작합니다.

```shell
git bisect start
git bisect bad                 # Current version is bad
git bisect good v2.6.13-rc2    # v2.6.13-rc2 is known to be good
```

`git bisect`은 두 시점 사이의 커밋을 선택하고 `git bisect good` 또는 `git bisect bad`으로 커밋이 "좋은"지 "나쁜"지 식별하도록 요청합니다. 커밋을 찾을 때까지 프로세스를 반복합니다.

## `git checkout` {#git-checkout}

`git checkout`을 사용하여 특정 브랜치로 전환합니다.

```shell
git checkout <branch_name>
```

새 브랜치를 만들고 전환하려면 `git checkout -b <branch_name>`을 사용합니다.

자세한 내용은 [변경 사항을 위한 Git 브랜치 만들기](branch.md)를 참고하세요.

## `git clone` {#git-clone}

`git clone`을 사용하여 기존 Git 리포지토리를 복사합니다.

```shell
git clone <repository>
```

자세한 내용은 [로컬 컴퓨터에 Git 리포지토리 복제](clone.md)를 참고하세요.

## `git commit` {#git-commit}

`git commit`을 사용하여 스테이징된 변경 사항을 리포지토리에 커밋합니다.

```shell
git commit -m "<commit_message>"
```

커밋 메시지에 빈 줄이 포함되어 있으면 첫 번째 줄은 커밋 제목이 되고 나머지는 커밋 본문이 됩니다. 제목을 사용하여 변경 사항을 간단히 요약하고, 커밋 본문을 사용하여 추가 세부 정보를 제공합니다.

자세한 내용은 [스테이징, 커밋 및 푸시 변경 사항](commit.md)을 참고하세요.

## `git commit --amend` {#git-commit---amend}

`git commit --amend`을 사용하여 가장 최근 커밋을 수정합니다.

```shell
git commit --amend
```

## `git diff` {#git-diff}

`git diff`을 사용하여 로컬 언스테이징된 변경 사항과 복제하거나 풀한 최신 버전 간의 차이를 확인합니다.

```shell
git diff
```

로컬 변경 사항과 브랜치의 가장 최근 버전 간의 차이(또는 diff)를 표시할 수 있습니다. diff를 확인하여 변경 사항을 브랜치에 커밋하기 전에 로컬 변경 사항을 이해합니다.

특정 브랜치에 대한 변경 사항을 비교하려면 다음을 실행합니다:

```shell
git diff <branch>
```

출력에서:

- 추가 항목이 있는 줄은 더하기 기호(`+`)로 시작하며 녹색으로 표시됩니다.
- 제거 또는 변경 항목이 있는 줄은 빼기 기호(`-`)로 시작하며 빨간색으로 표시됩니다.

## `git init` {#git-init}

`git init`을 사용하여 디렉터리를 초기화하여 Git이 리포지토리로 추적하도록 합니다.

```shell
git init
```

구성 및 로그 파일이 있는 `.git` 파일이 디렉터리에 추가됩니다. `.git` 파일을 직접 편집하지 않아야 합니다.

기본 브랜치는 `main`로 설정됩니다. `git branch -m <branch_name>`으로 기본 브랜치의 이름을 변경하거나 `git init -b <branch_name>`으로 초기화할 수 있습니다.

## `git pull` {#git-pull}

`git pull`을 사용하여 마지막으로 프로젝트를 복제하거나 풀한 이후 사용자가 만든 모든 변경 사항을 가져옵니다.

```shell
git pull <optional_remote> <branch_name>
```

## `git push` {#git-push}

`git push`을 사용하여 원격 참조를 업데이트합니다.

```shell
git push
```

자세한 내용은 [스테이징, 커밋 및 푸시 변경 사항](commit.md)을 참고하세요.

## `git reflog` {#git-reflog}

`git reflog`을 사용하여 Git 참조 로그의 변경 사항 목록을 표시합니다.

```shell
git reflog
```

기본적으로 `git reflog`은 `HEAD`의 변경 사항 목록을 표시합니다.

자세한 내용은 [변경 사항 실행 취소](undo.md)를 참고하세요.

## `git remote add` {#git-remote-add}

`git remote add`을 사용하여 GitLab의 어느 원격 리포지토리가 로컬 디렉터리와 연결되어 있는지 Git에 알립니다.

```shell
git remote add <remote_name> <repository_url>
```

리포지토리를 복제하면 기본적으로 소스 리포지토리는 원격 이름 `origin`과 연결됩니다.

추가 원격 구성에 대한 자세한 내용은 [포크](../../user/project/repository/forking_workflow.md)를 참고하세요.

## `git log` {#git-log}

`git log`을 사용하여 커밋 목록을 시간순으로 표시합니다.

```shell
git log
```

## `git show` {#git-show}

`git show`을 사용하여 Git의 객체에 대한 정보를 표시합니다.

### 예 {#example-1}

`HEAD`이 가리키는 커밋을 확인하려면:

```shell
$ git show HEAD
commit ab123c (HEAD -> main, origin/main, origin/HEAD)
```

## `git merge` {#git-merge}

`git merge`을 사용하여 한 브랜치의 변경 사항을 다른 브랜치와 병합합니다.

`git merge`의 대체 방법에 대한 자세한 내용은 [머지 충돌을 해결하기 위한 리베이스](git_rebase.md)를 참고하세요.

### 예 {#example-2}

`feature_branch`의 변경 사항을 `target_branch`에 적용하려면:

```shell
git checkout target_branch
git merge feature_branch
```

## `git rebase` {#git-rebase}

`git rebase`을 사용하여 브랜치의 커밋 히스토리를 다시 작성합니다.

```shell
git rebase <branch_name>
```

`git rebase`을 사용하여 [머지 충돌 해결](git_rebase.md)할 수 있습니다.

대부분의 경우 기본 브랜치에 대해 리베이스하려고 합니다.

## `git reset` {#git-reset}

`git reset`을 사용하여 커밋을 실행 취소하고 커밋 히스토리를 되감기하고 이전 커밋에서 계속합니다.

```shell
git reset
```

자세한 내용은 [변경 사항 실행 취소](undo.md)를 참고하세요.

## `git status` {#git-status}

`git status`을 사용하여 작업 디렉터리 및 스테이징된 파일의 상태를 표시합니다.

```shell
git status
```

파일을 추가, 변경 또는 삭제하면 Git이 변경 사항을 표시합니다.
