---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 변경 사항을 위한 Git 브랜치 생성
---

브랜치는 브랜치를 생성할 때 리포지토리의 파일 복사본입니다. 다른 브랜치에 영향을 주지 않으면서 브랜치에서 작업할 수 있습니다. 주 코드베이스에 변경 사항을 추가할 준비가 되면 브랜치를 기본 브랜치(예: `main`)로 병합할 수 있습니다.

다음과 같은 경우 브랜치를 사용합니다:

- 프로젝트에 코드를 추가하려고 하지만 제대로 작동하는지 확실하지 않은 경우.
- 다른 사람과 함께 프로젝트를 협업하고 있으며 작업이 섞이기를 원하지 않는 경우.

## 브랜치 생성 {#create-a-branch}

브랜치를 생성하려면:

```shell
git checkout -b <name-of-branch>
```

GitLab은 [브랜치 명명 규칙](../../user/project/repository/branches/_index.md#name-your-branch)을 적용하여 문제를 방지하고, [브랜치 명명 패턴](../../user/project/repository/branches/_index.md#prefix-branch-names-with-a-number)을 제공하여 머지 리퀘스트 생성을 간소화합니다.

## 브랜치로 전환 {#switch-to-a-branch}

Git의 모든 작업은 브랜치에서 수행됩니다. 브랜치 간을 전환하여 파일 상태를 확인하고 해당 브랜치에서 작업할 수 있습니다.

기존 브랜치로 전환하려면:

```shell
git checkout <name-of-branch>
```

예를 들어 `main` 브랜치로 변경하려면:

```shell
git checkout main
```

## 브랜치를 최신 상태로 유지 {#keep-a-branch-up-to-date}

브랜치는 다른 브랜치에서 기본 브랜치로 병합된 변경 사항을 자동으로 포함하지 않습니다. 브랜치를 생성한 후 병합된 변경 사항을 포함하려면 브랜치를 수동으로 업데이트해야 합니다.

브랜치를 기본 브랜치의 최신 변경 사항으로 업데이트하려면 다음 중 하나를 수행합니다:

- 브랜치를 기본 브랜치에 대해 [리베이스](git_rebase.md)하려면 다음을 실행합니다:

  ```shell
  git rebase
  ```

  기본 브랜치의 변경 사항 이후에 Git 로그에 변경 사항을 나열하려고 할 때 이 명령을 사용합니다.

- 기본 브랜치를 브랜치로 병합하려면 다음을 실행합니다:

  ```shell
  git pull <remote-name> <default-branch-name>
  ```

  기본 브랜치의 변경 사항과 함께 Git 로그에서 변경 사항을 시간 순서로 표시하거나 다른 사람과 브랜치를 공유하려는 경우 이 명령을 사용합니다. `<remote-name>`의 올바른 값이 확실하지 않으면 `git remote`을 실행합니다.

## 관련 항목 {#related-topics}

- [브랜치](../../user/project/repository/branches/_index.md)
- [태그](../../user/project/repository/tags/_index.md)
