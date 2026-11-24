---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Git 리포지토리에서 원하지 않는 대용량 파일을 제거하고 저장소 크기를 줄이려면 filter-repo 명령을 사용합니다.
title: 리포지토리 크기 줄이기
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Git 리포지토리의 크기는 성능과 저장소 비용에 상당한 영향을 미칠 수 있습니다. 압축, 하우스키핑 및 기타 요소로 인해 인스턴스마다 약간씩 다를 수 있습니다.

리포지토리 크기에 대한 자세한 정보는 다음을 참조하세요:

- [리포지토리 크기](../../user/project/repository/repository_size.md)
  - [리포지토리 크기를 계산하는 방법](../../user/project/repository/repository_size.md#size-calculation)
  - [크기 및 저장소 제한](../../user/project/repository/repository_size.md#size-and-storage-limits)
  - [GitLab UI에서 리포지토리 크기를 줄이는 방법](../../user/project/repository/repository_size.md#methods-to-reduce-repository-size)

## 리포지토리 기록에서 파일 삭제 {#purge-files-from-repository-history}

이 방법을 사용하여 전체 Git 기록에서 대용량 파일을 제거합니다.

리포지토리에서 암호나 키 같은 중요한 데이터를 제거하는 데는 적합하지 않습니다. 커밋에 대한 정보(파일 콘텐츠 포함)는 데이터베이스에 캐시되며 리포지토리에서 제거된 후에도 계속 표시됩니다. 중요한 데이터를 제거하려면 [블롭 제거](../../user/project/repository/repository_size.md#remove-blobs)에서 설명하는 방법을 사용합니다.

전제 조건:

- [`git filter-repo`](https://github.com/newren/git-filter-repo/blob/main/INSTALL.md)를 설치해야 합니다.
- 선택사항. [`git-sizer`](https://github.com/github/git-sizer#getting-started)를 설치합니다.

> [!warning]
> 파일 삭제는 파괴적인 작업입니다. 진행하기 전에 리포지토리의 백업이 있는지 확인합니다.

GitLab 리포지토리에서 파일을 삭제하려면:

1. [프로젝트 내보내기](../../user/project/settings/import_export.md#export-a-project-and-its-data)를 수행하여 리포지토리의 복사본을 포함한 후 다운로드합니다.

   - 큰 프로젝트의 경우 [프로젝트 관계 내보내기 API](../../api/project_relations_export.md)를 사용할 수 있습니다.

1. 백업을 압축 해제하고 추출합니다:

   ```shell
   tar xzf project-backup.tar.gz
   ```

1. `--bare` 및 `--mirror` 옵션을 사용하여 리포지토리를 복제합니다:

   ```shell
   git clone --bare --mirror /path/to/project.bundle
   ```

1. `project.git` 디렉터리로 이동합니다:

   ```shell
   cd project.git
   ```

1. 원격 URL을 업데이트합니다:

   ```shell
   git remote set-url origin https://gitlab.example.com/<namespace>/<project_name>.git
   ```

1. `git filter-repo` 또는 `git-sizer`를 사용하여 리포지토리를 분석합니다:

   - `git filter-repo`:

     ```shell
     git filter-repo --analyze
     head filter-repo/analysis/*-{all,deleted}-sizes.txt
     ```

   - `git-sizer`:

     ```shell
     git-sizer
     ```

1. 다음 `git filter-repo` 옵션 중 하나를 사용하여 리포지토리의 기록을 삭제합니다:

   - `--path` 및 `--invert-paths`를 사용하여 특정 파일을 삭제합니다:

     ```shell
     git filter-repo --path path/to/file.ext --invert-paths
     ```

   - 예를 들어 10M보다 큰 모든 파일을 삭제하려면 `--strip-blobs-bigger-than`을 사용합니다:

     ```shell
     git filter-repo --strip-blobs-bigger-than 10M
     ```

   자세한 예는 [`git filter-repo` 설명서](https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html#EXAMPLES)를 참조하세요.

1. `commit-map`을 백업합니다:

   ```shell
   cp filter-repo/commit-map ./_filter_repo_commit_map_$(date +%s)
   ```

1. 미러 플래그를 해제합니다:

   ```shell
    git config --unset remote.origin.mirror
   ```

1. 변경 사항을 강제로 푸시합니다:

   ```shell
   git push origin --force 'refs/heads/*'
   git push origin --force 'refs/tags/*'
   git push origin --force 'refs/replace/*'
   ```

   참조에 대한 자세한 정보는 Gitaly에서 사용하는 Git 참조를 참조하세요.

   > [!note]
   > 이 단계는 [보호된 브랜치](../../user/project/repository/branches/protected.md) 및 [보호된 태그](../../user/project/protected_tags.md)에 대해 실패합니다. 진행하려면 보호를 임시로 제거합니다.
1. 다음 단계 전에 최소 30분을 기다립니다.
1. [리포지토리 정리](../../user/project/repository/repository_size.md#clean-up-repository) 프로세스를 실행합니다. 이 프로세스는 30분 이상 된 객체만 정리합니다. 자세한 정보는 [정리 후 공간이 해제되지 않음](../../user/project/repository/repository_size.md#space-not-being-freed-after-cleanup)을 참조하세요.
