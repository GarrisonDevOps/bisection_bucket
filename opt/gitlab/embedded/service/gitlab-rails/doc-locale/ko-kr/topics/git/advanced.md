---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 고급 Git 작업
description: "리베이스, 체리픽, 변경 사항 되돌리기, 리포지토리 및 파일 관리."
---

고급 Git 작업은 코드를 유지 관리하고 관리하기 위한 작업을 수행하는 데 도움이 됩니다. 이는 [기본 Git 작업](basics.md)을 넘어 더 복잡한 작업입니다. 이러한 작업으로 다음을 수행할 수 있습니다:

- 커밋 히스토리를 다시 작성합니다.
- 변경 사항을 되돌리고 실행 취소합니다.
- 원격 리포지토리 연결을 관리합니다.

다음과 같은 이점을 제공합니다:

- 코드 품질: 깔끔하고 선형적인 프로젝트 히스토리를 유지합니다.
- 문제 해결: 실수를 수정하거나 리포지토리 상태를 조정하는 도구를 제공합니다.
- 워크플로우 최적화: 복잡한 개발 프로세스를 간소화합니다.
- 협업: 크거나 복잡한 프로젝트에서 더 매끄러운 팀워크를 용이하게 합니다.

Git 작업을 효과적으로 사용하려면 리포지토리, 브랜치, 커밋 및 머지 리퀘스트와 같은 주요 개념을 이해하는 것이 중요합니다. 자세한 내용은 [Git 시작 학습](get_started.md)을 참조하세요.

## 모범 사례 {#best-practices}

고급 Git 작업을 사용할 때는 다음을 수행해야 합니다:

- 백업을 생성하거나 [별도 브랜치](branch.md)에서 작업합니다.
- 공유 브랜치 히스토리에 영향을 주는 작업을 사용하기 전에 팀과 소통합니다.
- 히스토리를 다시 작성할 때 설명적인 [커밋 메시지](../../tutorials/update_commit_messages/_index.md)를 사용합니다.
- 최신 모범 사례 및 새로운 기능으로 최신 상태를 유지하기 위해 Git 지식을 업데이트합니다. 자세한 내용은 [Git 문서](https://git-scm.com/docs)를 참조하세요.
- 테스트 리포지토리에서 고급 작업을 연습합니다.

## 리베이스 및 충돌 해결 {#rebase-and-resolve-conflicts}

`git rebase` 명령은 브랜치를 다른 브랜치의 내용으로 업데이트합니다. 브랜치의 변경 사항이 대상 브랜치의 변경 사항과 충돌하지 않음을 확인합니다. [머지 충돌](../../user/project/merge_requests/conflicts.md)이 있으면 리베이스하여 수정할 수 있습니다.

자세한 내용은 [머지 충돌을 해결하기 위해 리베이스](git_rebase.md)를 참조하세요.

## 체리픽 변경 {#cherry-pick-changes}

`git cherry-pick` 명령은 한 브랜치의 특정 커밋을 다른 브랜치에 적용합니다. 다음을 수행하는 데 사용합니다:

- 기본 브랜치에서 이전 릴리스 브랜치로 버그 수정을 백포트합니다.
- 포크에서 업스트림 리포지토리로 변경 사항을 복사합니다.
- 전체 브랜치를 병합하지 않고 특정 변경 사항을 적용합니다.

자세한 내용은 [Git으로 체리픽 변경](cherry_pick.md)을 참조하세요.

## 변경 사항 되돌리기 및 실행 취소 {#revert-and-undo-changes}

다음 Git 명령은 변경 사항을 되돌리고 실행 취소하는 데 도움이 됩니다:

- `git revert`: 이전 커밋에서 수행한 변경 사항을 실행 취소하는 새 커밋을 만듭니다. 이를 통해 실수 또는 더 이상 필요 없는 변경 사항을 실행 취소할 수 있습니다. 커밋이 이미 푸시되어 다른 사용자와 공유된 경우 `git revert`을 사용합니다. 이 명령은 기존 커밋 히스토리를 보존하므로 공유 브랜치에 적합합니다.
- `git reset`: 아직 커밋되지 않은 변경 사항을 재설정하고 실행 취소합니다. 공유 브랜치에 푸시되지 않은 로컬 변경 사항에 `git reset`을 사용합니다. 이 명령은 커밋 히스토리를 다시 작성할 수 있습니다.
- `git restore`: 손실되거나 삭제된 변경 사항을 복원합니다.

자세한 내용은 [변경 사항 되돌리기](undo.md)를 참조하세요.

## 리포지토리 크기 줄이기 {#reduce-repository-size}

Git 리포지토리의 크기는 성능 및 스토리지 비용에 영향을 미칠 수 있습니다. 압축, 하우스키핑 및 기타 요소로 인해 인스턴스마다 약간 다를 수 있습니다. 리포지토리 크기에 대한 자세한 내용은 [리포지토리 크기](../../user/project/repository/repository_size.md)를 참조하세요.

Git을 사용하여 리포지토리 히스토리에서 파일을 제거하고 크기를 줄일 수 있습니다. 자세한 내용은 [리포지토리 크기 줄이기](repository.md)를 참조하세요.

## 파일 관리 {#file-management}

Git을 사용하여 리포지토리의 파일을 관리할 수 있습니다. 변경 사항을 추적하고 다른 사용자와 협업하고 대용량 파일을 관리하는 데 도움이 됩니다. 다음 옵션을 사용할 수 있습니다:

- `git log`: 리포지토리의 파일에 대한 변경 사항을 봅니다.
- `git blame`: 파일에서 코드 라인을 마지막으로 수정한 사람을 식별합니다.
- `git lfs`: 리포지토리의 파일을 관리, 추적 및 잠금합니다.

자세한 내용은 [파일 관리](file_management.md)를 참조하세요.

## Git 원격 URL 업데이트 {#update-git-remote-urls}

`git remote set-url` 명령은 원격 리포지토리의 URL을 업데이트합니다. 다음과 같은 경우에 사용합니다:

- 다른 Git 리포지토리 호스트에서 기존 프로젝트를 가져왔습니다.
- 조직이 새 도메인 이름이 있는 새 GitLab 인스턴스로 프로젝트를 이동했습니다.
- 프로젝트가 같은 GitLab 인스턴스의 새 경로로 이름이 바뀌었습니다.

자세한 내용은 [Git 원격 URL 업데이트](../../tutorials/update_git_remote_url/_index.md)를 참조하세요.

## 관련 항목 {#related-topics}

- [시작하기](get_started.md)
- [기본 Git 작업](basics.md)
- [일반 Git 명령](commands.md)
