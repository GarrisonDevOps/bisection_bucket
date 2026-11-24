---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "명령줄을 사용하여 파일을 Git 리포지토리에 추가, 커밋 및 푸시합니다."
title: 브랜치에 파일 추가
---

Git을 사용하여 로컬 리포지토리의 브랜치에 파일을 추가합니다. 이 작업은 다음 커밋을 위해 파일의 스냅샷을 생성하고 버전 제어 모니터링을 시작합니다. Git으로 파일을 추가할 때:

- 버전 제어 추적을 위한 콘텐츠를 준비합니다.
- 파일 추가 및 수정 기록을 생성합니다.
- 향후 참조를 위해 파일 기록을 보존합니다.
- 팀 협업을 위해 프로젝트 파일을 사용 가능하게 만듭니다.

## Git 리포지토리에 파일 추가 {#add-files-to-a-git-repository}

명령줄에서 새 파일을 추가하려면:

1. 터미널을 엽니다.
1. 프로젝트 폴더에 있을 때까지 디렉터리를 변경합니다.

   ```shell
   cd my-project
   ```

1. 작업할 Git 브랜치를 선택합니다.
   - 브랜치를 생성하려면:

     ```shell
     git checkout -b <branchname>
     ```

   - 기존 브랜치로 전환하려면:

     ```shell
     git checkout <branchname>
     ```

1. 추가하려는 파일을 추가하려는 디렉터리에 복사합니다.
1. 파일이 디렉터리에 있는지 확인합니다:
   - Windows: `dir`
   - 기타 모든 운영 체제: `ls`

   파일 이름이 표시되어야 합니다.
1. 파일의 상태를 확인합니다:

   ```shell
   git status
   ```

   파일 이름이 빨간색으로 표시되어야 합니다. 파일이 파일 시스템에 있지만 Git이 아직 추적하지 않습니다.
1. Git에서 파일을 추적하도록 지시합니다:

   ```shell
   git add <filename>
   ```

1. 파일의 상태를 다시 확인합니다:

   ```shell
   git status
   ```

   파일 이름이 녹색으로 표시되어야 합니다. 파일이 Git에 의해 스테이징되었지만(로컬로 추적됨) [커밋 및 푸시](commit.md)되지 않았습니다.

## 마지막 커밋에 파일 추가 {#add-a-file-to-the-last-commit}

새 커밋 대신 마지막 커밋에 파일의 변경 사항을 추가하려면 기존 커밋을 수정합니다:

```shell
git add <filename>
git commit --amend
```

커밋 메시지를 편집하지 않으려면 `--no-edit`을 `commit` 명령에 추가합니다.

## 관련 항목 {#related-topics}

- [UI에서 파일 추가](../../user/project/repository/_index.md#add-a-file-from-the-ui)
- [Web IDE에서 파일 추가](../../user/project/repository/web_editor.md#upload-a-file)
- [커밋 서명](../../user/project/repository/signed_commits/gpg.md)
