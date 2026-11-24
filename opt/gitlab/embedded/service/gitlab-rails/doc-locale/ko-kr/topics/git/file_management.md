---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 일반적인 명령어 및 작업 흐름.
title: 파일 관리
---

Git은 변경 사항을 추적하고, 다른 사람들과 협업하며, 대용량 파일을 효율적으로 관리할 수 있도록 도와주는 파일 관리 기능을 제공합니다.

## 파일 히스토리 {#file-history}

`git log`을 사용하여 파일의 전체 히스토리를 확인하고 시간 경과에 따라 어떻게 변경되었는지 이해할 수 있습니다. 파일 히스토리는 다음을 표시합니다:

- 각 변경의 작성자.
- 각 수정의 날짜 및 시간.
- 각 커밋에서 변경한 특정 내용.

예를 들어, `history` 정보를 `gitlab` 리포지토리의 루트에 있는 `CONTRIBUTING.md` 파일에 대해 확인하려면 다음을 실행합니다:

```shell
git log CONTRIBUTING.md
```

출력 예:

```shell
commit b350bf041666964c27834885e4590d90ad0bfe90
Author: Nick Malcolm <nmalcolm@gitlab.com>
Date:   Fri Dec 8 13:43:07 2023 +1300

    Update security contact and vulnerability disclosure info

commit 8e4c7f26317ff4689610bf9d031b4931aef54086
Author: Brett Walker <bwalker@gitlab.com>
Date:   Fri Oct 20 17:53:25 2023 +0000

    Fix link to Code of Conduct

    and condense some of the verbiage
```

## 파일의 이전 변경 사항 확인 {#check-previous-changes-to-a-file}

`git blame`을 사용하여 누가 파일을 마지막으로 변경했고 언제 변경했는지 확인합니다. 이를 통해 파일 내용의 컨텍스트를 이해하고, 충돌을 해결하며, 특정 변경을 담당한 사람을 파악할 수 있습니다.

로컬 디렉터리에서 `README.md` 파일에 대한 `blame` 정보를 찾으려면:

1. 터미널 또는 명령 프롬프트를 엽니다.
1. Git 리포지토리로 이동합니다.
1. 다음 명령어를 실행합니다:

   ```shell
   git blame README.md
   ```

1. 결과 페이지를 탐색하려면 <kbd>Space</kbd> 키를 누르세요.
1. 결과를 종료하려면 <kbd>Q</kbd> 키를 누르세요.

이 출력에는 파일 내용과 각 라인의 커밋 SHA, 작성자 및 날짜를 표시하는 주석이 표시됩니다. 예를 들어:

```shell
58233c4f1054c (Dan Rhodes           2022-05-13 07:02:20 +0000  1) ## Contributor License Agreement
b87768f435185 (Jamie Hurewitz       2017-10-31 18:09:23 +0000  2)
8e4c7f26317ff (Brett Walker         2023-10-20 17:53:25 +0000  3) Contributions to this repository are subject to the
58233c4f1054c (Dan Rhodes           2022-05-13 07:02:20 +0000  4)
```

## Git LFS {#git-lfs}

Git Large File Storage(LFS)는 Git 리포지토리에서 대용량 파일을 관리할 수 있도록 도와주는 확장 기능입니다. Git에서 대용량 파일을 텍스트 포인터로 대체하고 파일 내용을 원격 서버에 저장합니다.

전제 조건:

- 운영 체제에 맞는 [Git LFS용 CLI 확장](https://git-lfs.com)의 적절한 버전을 다운로드하고 설치합니다.
- [Git LFS를 사용하도록 프로젝트를 구성합니다](lfs/_index.md).
- Git LFS 사전 푸시 훅을 설치합니다. 이를 수행하려면 리포지토리의 루트 디렉터리에서 `git lfs install`을 실행합니다.

### 파일 추가 및 추적 {#add-and-track-files}

Git 리포지토리에 대용량 파일을 추가하고 Git LFS로 추적하려면:

1. 특정 파일 유형에 대해 추적을 구성합니다. `iso`을 원하는 파일 유형으로 바꿉니다:

   ```shell
   git lfs track "*.iso"
   ```

   이 명령어는 `.gitattributes` 파일을 생성하여 모든 ISO 파일을 Git LFS로 처리하기 위한 지침이 포함됩니다. 다음 라인이 `.gitattributes` 파일에 추가됩니다:

   ```plaintext
   *.iso filter=lfs -text
   ```

1. 해당 유형의 파일인 `.iso`을 리포지토리에 추가합니다.
1. `.gitattributes` 파일과 `.iso` 파일의 변경 사항을 추적합니다:

   ```shell
   git add .
   ```

1. 두 파일을 모두 추가했는지 확인합니다:

   ```shell
   git status
   ```

   `.gitattributes` 파일은 커밋에 포함되어야 합니다. 포함되지 않으면 Git이 ISO 파일을 Git LFS로 추적하지 않습니다.

   > [!note]
   > 변경 중인 파일이 `.gitignore` 파일에 나열되지 않았는지 확인합니다. 포함된 경우 Git은 변경 사항을 로컬로 커밋하지만 업스트림 리포지토리로 푸시하지 않습니다.
1. 두 파일을 리포지토리의 로컬 복사본으로 커밋합니다:

   ```shell
   git commit -m "Add an ISO file and .gitattributes"
   ```

1. 변경 사항을 업스트림으로 푸시합니다. `main`을 브랜치 이름으로 바꿉니다:

   ```shell
   git push origin main
   ```

1. 머지 리퀘스트를 생성합니다.

> [!note]
> Git LFS 추적에 새 파일 유형을 추가하면, 이 유형의 기존 파일은 Git LFS로 변환되지 않습니다. 추적을 시작한 후 추가되는 이 유형의 파일만 Git LFS에 추가됩니다. `git lfs migrate`을 사용하여 기존 파일을 Git LFS를 사용하도록 변환합니다.

### 파일 추적 중지 {#stop-tracking-a-file}

Git LFS로 파일 추적을 중지하면, 파일이 여전히 리포지토리 히스토리의 일부이므로 디스크에 유지됩니다.

Git LFS로 파일 추적을 중지하려면:

1. `git lfs untrack` 명령어를 실행하고 파일 경로를 제공합니다:

   ```shell
   git lfs untrack doc/example.iso
   ```

1. `touch` 명령어를 사용하여 표준 파일로 변환합니다:

   ```shell
   touch doc/example.iso
   ```

1. 파일의 변경 사항을 추적합니다:

   ```shell
   git add .
   ```

1. 변경 사항을 커밋하고 푸시합니다.
1. 머지 리퀘스트를 생성하고 검토를 요청합니다.
1. 대상 브랜치로 요청을 머지합니다.

> [!note]
> Git LFS로 추적되는 객체를 `git lfs untrack`으로 추적하지 않고 삭제하면, 객체가 `git status`에 `modified`으로 표시됩니다.

### 단일 유형의 모든 파일 추적 중지 {#stop-tracking-all-files-of-a-single-type}

Git LFS에서 특정 유형의 모든 파일 추적을 중지하려면:

1. `git lfs untrack` 명령어를 실행하고 추적을 중지할 파일 유형을 제공합니다:

   ```shell
   git lfs untrack "*.iso"
   ```

1. `touch` 명령어를 사용하여 파일을 표준 파일로 변환합니다:

   ```shell
   touch *.iso
   ```

1. 파일의 변경 사항을 추적합니다:

   ```shell
   git add .
   ```

1. 변경 사항을 커밋하고 푸시합니다.
1. 머지 리퀘스트를 생성하고 검토를 요청합니다.
1. 대상 브랜치로 요청을 머지합니다.

## 단독 파일 잠금 {#exclusive-file-locks}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

단독 파일 잠금은 충돌을 방지하고 한 번에 한 사람만 파일을 편집할 수 있도록 합니다. 다음의 경우 좋은 옵션입니다:

- 병합할 수 없는 바이너리 파일. 예를 들어 디자인 파일 및 비디오.
- 편집 중에 단독 액세스가 필요한 파일.

단독 파일 잠금은 리포지토리의 모든 브랜치에 적용됩니다. 기본 브랜치에서만 파일을 잠가야 하는 경우 대신 [기본 브랜치 파일 및 디렉터리 잠금](../../user/project/file_lock.md#default-branch-file-and-directory-locks)을 사용합니다.

전제 조건:

- [Git LFS가 설치](lfs/_index.md)되어 있어야 합니다.
- 프로젝트에 대한 Maintainer 역할이 있어야 합니다.

### 파일 잠금 구성 {#configure-file-locks}

특정 파일 유형에 대한 파일 잠금을 구성하려면:

1. `git lfs track` 명령어를 `--lockable` 옵션과 함께 사용합니다. 예를 들어 PNG 파일을 구성하려면:

   ```shell
   git lfs track "*.png" --lockable
   ```

   이 명령어는 `.gitattributes` 파일을 생성하거나 업데이트하여 다음 내용을 포함합니다:

    ```plaintext
    *.png filter=lfs diff=lfs merge=lfs -text lockable
    ```

1. `.gitattributes` 파일을 원격 리포지토리로 푸시하여 변경 사항을 적용합니다.

> [!note]
> 파일 유형이 잠금 가능으로 등록되면, 자동으로 읽기 전용으로 표시됩니다.

#### LFS 없이 파일 잠금 구성 {#configure-file-locks-without-lfs}

Git LFS를 사용하지 않고 파일 유형을 잠금 가능으로 등록하려면:

1. `.gitattributes` 파일을 수동으로 편집합니다:

   ```shell
   *.pdf lockable
   ```

1. `.gitattributes` 파일을 원격 리포지토리로 푸시합니다.

### 파일 잠금 및 잠금 해제 {#lock-and-unlock-files}

단독 파일 잠금으로 파일을 잠금 또는 잠금 해제하려면:

1. 리포지토리 디렉터리에서 터미널 창을 엽니다.
1. 다음 명령어 중 하나를 실행합니다:

   {{< tabs >}}

   {{< tab title="파일 잠금" >}}

   ```shell
   git lfs lock path/to/file.png
   ```

   {{< /tab >}}

   {{< tab title="파일 잠금 해제" >}}

   ```shell
   git lfs unlock path/to/file.png
   ```

   {{< /tab >}}

   {{< tab title="ID로 파일 잠금 해제" >}}

   ```shell
   git lfs unlock --id=123
   ```

   {{< /tab >}}

   {{< tab title="파일 강제 잠금 해제" >}}

   ```shell
   git lfs unlock --id=123 --force
   ```

   {{< /tab >}}

   {{< /tabs >}}

### 잠긴 파일 보기 {#view-locked-files}

잠긴 파일을 보려면:

1. 리포지토리에서 터미널 창을 엽니다.
1. 다음 명령어를 실행합니다:

   ```shell
   git lfs locks
   ```

   출력은 잠긴 파일, 파일을 잠근 사용자 및 파일 ID를 나열합니다.

GitLab UI에서:

- 리포지토리 파일 트리는 Git LFS로 추적되는 파일에 대해 LFS 배지를 표시합니다.
- 단독으로 잠긴 파일은 자물쇠 아이콘을 표시합니다.

> [!note]
> 단독으로 잠긴 파일의 이름을 바꾸면 잠금이 해제됩니다. 잠금을 유지하려면 다시 잠가야 합니다.

### 파일 잠금 및 편집 {#lock-and-edit-a-file}

파일을 잠금하고 편집한 다음 선택적으로 잠금 해제하려면:

1. 파일을 잠금합니다:

   ```shell
   git lfs lock <file_path>
   ```

1. 파일을 편집합니다.
1. 선택사항. 완료되면 파일의 잠금을 해제합니다:

   ```shell
   git lfs unlock <file_path>
   ```

## 관련 항목 {#related-topics}

- [GitLab UI로 파일 관리](../../user/project/repository/files/_index.md)
- [Git Large File Storage(LFS) 문서](lfs/_index.md)
- [파일 잠금](../../user/project/file_lock.md)
