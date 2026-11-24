---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "리포지토리 크기를 계산하고 표시하는 방법, 크기 제한, Git 리포지토리 스토리지를 줄이는 방법을 이해합니다."
title: 리포지토리 크기
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Git 리포지토리의 크기는 성능과 스토리지 비용에 큰 영향을 미칠 수 있습니다. 압축, 정리, 및 기타 요인으로 인해 한 인스턴스에서 다른 인스턴스로 약간 다를 수 있습니다.

## 크기 계산 {#size-calculation}

리포지토리 크기는 리포지토리의 모든 파일의 누적 크기입니다. 이 계산은 리포지토리의 [해시된 스토리지 경로](../../../administration/repository_storage_paths.md)에서 `du --summarize --bytes`를 실행하는 것과 유사합니다. 크기는 리포지토리가 변경될 때 다시 계산되지만 15분마다 한 번 이상 계산되지 않습니다.

리포지토리 크기는 프로젝트 크기의 부분집합입니다. 프로젝트 개요 페이지의 **프로젝트 정보**에 나열된 프로젝트 크기는 리포지토리, LFS 객체, 작업 아티팩트, 패키지, 위키를 포함합니다.

### 리포지토리 크기 보기 {#view-repository-size}

사전 요구 사항:

- 프로젝트의 유지보수자 또는 소유자 역할, 또는 네임스페이스의 소유자 역할입니다.

리포지토리 크기를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **사용 할당량**을 선택합니다.
1. **스토리지** 탭을 선택합니다.
1. 사용 현황 분석에서 **리포지토리** 행의 값을 봅니다.

프로젝트에서 사용하는 스토리지에 대한 자세한 정보는 [스토리지](../../storage_usage_quotas.md)를 참조하세요.

## 크기 및 스토리지 제한 {#size-and-storage-limits}

관리자는 GitLab Self-Managed의 [리포지토리 크기 제한](../../../administration/settings/account_and_limit_settings.md#repository-size-limit)을 설정할 수 있습니다. GitLab.com의 경우 크기 제한은 [미리 정의되어](../../gitlab_com/_index.md#account-and-limit-settings) 있습니다.

프로젝트가 크기 제한에 도달하면 푸시, 머지 리퀘스트 생성, LFS 객체 업로드와 같은 특정 작업이 제한됩니다.

## Git 기록을 다시 작성하기 전에 {#before-you-rewrite-git-history}

Git 기록을 다시 작성하고 리포지토리에서 데이터를 제거하기 전에 다음 섹션의 정보를 고려해야 합니다.

### 로컬 클론을 변경해야 함 {#local-clones-must-be-changed}

리포지토리의 클론을 가진 모든 사용자는 다음 중 하나를 수행해야 합니다:

- 로컬 복사본을 삭제하고 리포지토리의 새 복사본을 클론합니다.
- 모든 원격 변경 사항을 가져오고 진행 중인 모든 작업이 그 위에 리베이스되도록 합니다.

제대로 수행되지 않으면 로컬 변경 사항을 푸시하는 사용자가 삭제되어야 하는 파일을 되살릴 수 있습니다.

### 실행 중인 파이프라인은 정리를 실패하게 할 수 있음 {#running-pipelines-can-cause-cleanup-to-fail}

정리 중에 여전히 파이프라인이 실행 중일 때 리포지토리와 상호 작용할 수 있고 정리가 제대로 작동하지 않을 수 있습니다.

### 가비지 수집 유예 기간 {#garbage-collection-grace-period}

GitLab은 30분의 유예 기간으로 Git 가비지 수집을 실행합니다. 이 프로세스는 다음 두 가지 객체를 정리합니다:

- 모든 참조에서 도달할 수 없습니다.
- 최소 30분 이상 된 객체입니다.

제거하려는 데이터가 커밋에서 도달할 수 있거나 30분 미만인 경우 Git 가비지 수집은 제거하지 않습니다.

결과적으로 정리 실행 후 **도달할 수 없는 객체 정리**를 선택하기 전에 최소 30분을 기다려야 합니다.

### 포크된 프로젝트에서 기록을 다시 작성할 수 없음 {#history-cannot-be-rewritten-on-forked-project}

포크된 리포지토리에서는 내장 방법을 사용할 수 없습니다. GitLab 객체가 포크에서 저장되는 방식으로 인해 Git이 포크 간에 공유되는 객체를 가비지 수집하는 것이 불가능합니다.

### 해결 방법: 프로젝트 아카이브 {#workaround-archive-the-project}

정리 전에 [아카이브](../working_with_projects.md#archive-a-project)를 수행하면 리포지토리가 읽기 전용이 됩니다. 이는 정리가 진행 중인 동안 아무도 변경할 수 없도록 합니다.

리포지토리를 아카이브하면 포크 관계도 제거됩니다. 즉, 데이터를 정리할 수 있습니다. 하지만 데이터가 포크로 끌어올려진 경우 거기서도 정리가 필요합니다.

## 리포지토리 크기를 줄이는 방법 {#methods-to-reduce-repository-size}

리포지토리의 크기를 줄이기 위해 다음 방법을 사용할 수 있습니다:

- [기록에서 파일 제거](#purge-files-from-repository-history): 전체 Git 기록에서 큰 파일을 제거합니다.
- [리포지토리 정리](#clean-up-repository): 내부 Git 참조 및 참조되지 않는 객체를 제거합니다.
- [Blob 제거](#remove-blobs): 민감하거나 기밀인 정보가 포함된 Blob을 영구 삭제합니다.

리포지토리 크기를 줄이기 전에 [리포지토리의 전체 백업을 생성](../../../administration/backup_restore/_index.md)해야 합니다. 이 방법은 되돌릴 수 없으며 프로젝트의 기록과 데이터에 잠재적으로 영향을 미칠 수 있습니다.

사용 가능한 방법 중 하나로 리포지토리 크기를 줄일 때 프로젝트에 대한 액세스를 차단할 필요가 없습니다. 프로젝트가 사용자에게 계속 액세스 가능한 상태로 유지되는 동안 이러한 작업을 수행할 수 있습니다. 이 방법은 알려진 성능 영향이 없으며 가동 중단을 발생하지 않습니다. 그러나 이러한 작업은 활동이 적은 기간에 수행하여 사용자에 미칠 수 있는 잠재적 영향을 최소화해야 합니다.

### 리포지토리 기록에서 파일 제거 {#purge-files-from-repository-history}

Git 기록에서 큰 파일을 제거하려면 [`git filter-repo`로 파일 제거](../../../topics/git/repository.md#purge-files-from-repository-history)를 수행할 수 있습니다. 이 방법을 사용하여 비밀번호나 키와 같은 민감한 데이터를 제거하지 마세요. 대신 [Blob 제거](#remove-blobs) 또는 [텍스트 수정](#redact-text-from-repository)을 사용하세요.

이 프로세스는:

- 전체 Git 기록을 수정합니다.
- 열린 머지 리퀘스트에 영향을 미칠 수 있습니다.
- 기존 파이프라인에 영향을 미칠 수 있습니다.
- 로컬 리포지토리의 다시 클론이 필요합니다.
- LFS 객체에는 영향을 미치지 않습니다.
- 커밋 서명을 지정하지 않습니다.
- 되돌릴 수 없습니다.

> [!note]
> 커밋에 대한 정보(파일 콘텐츠 포함)는 데이터베이스에 캐시되며 리포지토리에서 제거된 후에도 계속 표시됩니다.

### 리포지토리 정리 {#clean-up-repository}

이 방법을 사용하여 리포지토리에서 내부 Git 참조 및 참조되지 않는 객체를 제거합니다. 이 방법을 사용하여 민감한 데이터를 제거하지 마세요. 민감한 데이터를 제거하려면 [Blob 제거 방법](#remove-blobs)을 사용하세요.

이 프로세스는:

- `git gc --prune=30.minutes.ago`을 실행하여 참조되지 않는 객체를 제거합니다.
- 사용하지 않는 LFS 객체의 연결을 끊고 스토리지 공간을 해제합니다.
- 디스크의 리포지토리 크기를 다시 계산합니다.
- 되돌릴 수 없습니다.

> [!warning]
> 내부 Git 참조를 제거하면 관련된 머지 리퀘스트 커밋, 파이프라인 및 변경 세부 정보를 사용할 수 없게 됩니다.

사전 요구 사항:

- 제거할 객체 목록입니다. [`git filter-repo`](https://github.com/newren/git-filter-repo)을 사용하여 `commit-map` 파일에서 객체 목록을 생성합니다.

리포지토리를 정리하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **설정** > **리포지토리**로 이동합니다.
1. **리포지토리 유지 보수**를 확장합니다.
1. 제거할 객체 목록을 업로드합니다. 예를 들어 `filter-repo` 디렉터리의 `commit-map` 파일입니다.

   `commit-map` 파일이 너무 크면 백그라운드 정리 프로세스가 시간 초과되어 실패할 수 있습니다. 결과적으로 리포지토리 크기가 예상대로 줄어들지 않습니다. 이 문제를 해결하려면 파일을 분할하고 부분적으로 업로드합니다. `20000`부터 시작하여 필요에 따라 줄입니다. 예를 들어:

   ```shell
   split -l 20000 filter-repo/commit-map filter-repo/commit-map-
   ```

1. **정리 시작**을 선택합니다.

GitLab은 정리가 완료된 후 다시 계산된 리포지토리 크기가 포함된 이메일 알림을 보냅니다.

## 리포지토리에서 데이터 제거 {#remove-data-from-a-repository}

리포지토리에서 민감하거나 기밀인 데이터를 제거하려면 이러한 방법 중 하나를 사용합니다:

- 파일을 완전히 제거하려면 [Blob 제거](#remove-blobs)를 수행합니다.
- 파일을 유지하되 기밀 텍스트를 `***REMOVED***`로 바꾸려면 [텍스트 수정](#redact-text-from-repository)을 수행합니다.

### Blob 제거 {#remove-blobs}

{{< history >}}

- GitLab 17.1에서 `rewrite_history_ui`이라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/450701)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab.com에서 [활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/462999) (GitLab 17.2).
- GitLab Self-Managed 및 GitLab Dedicated에서 [활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/462999) (GitLab 17.3).
- GitLab 17.9에서 [일반 공급 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/472018). 기능 플래그 `rewrite_history_ui`이 제거되었습니다.

{{< /history >}}

Git 바이너리 큰 객체(Blob)는 메타데이터 없이 파일 콘텐츠를 저장합니다. 각 Blob에는 리포지토리의 파일의 특정 버전을 나타내는 고유한 SHA 해시가 있습니다.

이 방법을 사용하여 민감하거나 기밀인 정보가 포함된 Blob을 영구 삭제합니다.

이 프로세스는:

- Git 기록을 다시 작성합니다.
- 커밋 서명을 드롭합니다.
- 열린 머지 리퀘스트가 병합에 실패하여 수동 리베이스가 필요할 수 있습니다.
- 이전 커밋 SHA를 참조하는 파이프라인이 중단될 수 있습니다.
- 이전 커밋 기록을 기반으로 한 과거 태그 및 브랜치에 영향을 미칠 수 있습니다.
- 로컬 리포지토리의 다시 클론이 필요합니다.
- 되돌릴 수 없습니다.

> [!note]
> 또한 문자열을 `***REMOVED***`로 바꿀 수 있습니다. 자세한 정보는 [리포지토리에서 텍스트 수정](#redact-text-from-repository)을 참조하세요.

사전 요구 사항:

- 프로젝트에 대해 Owner 역할이 필요합니다.
- [제거할 객체 ID 목록](#get-a-list-of-object-ids).
- 프로젝트는 다음이 아니어야 합니다:
  - 공개 업스트림 프로젝트의 포크입니다.
  - 다운스트림 포크가 있는 공개 업스트림 프로젝트입니다.

> [!note]
> 성공적인 Blob 제거를 보장하려면 프로세스 중에 리포지토리 액세스를 일시적으로 제한하는 것을 고려하세요. Blob 제거 중에 푸시된 새 커밋은 작업을 실패하게 할 수 있습니다.

리포지토리에서 Blob을 제거하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **리포지토리 유지 보수**를 확장합니다.
1. **Blob 제거**를 선택합니다.
1. 제거할 Blob ID 목록을 입력하며, 각 ID는 고유한 줄에 있어야 합니다.
1. **Blob 제거**를 선택합니다.
1. 확인 대화 상자에서 프로젝트 경로를 입력합니다.
1. **예, Blob을 제거합니다.**를 선택합니다.
1. 계속하기 전에 Blob 제거가 완료될 때까지 기다립니다:
   - [이메일 알림](../../profile/notifications.md)이 활성화되면 리포지토리 기록 다시 작성이 완료되었음을 나타내는 이메일을 받을 때까지 기다립니다.
   - 이메일 알림이 활성화되지 않으면 최소 5분을 기다립니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급**이라는 레이블의 섹션을 확장합니다.
1. **정리 실행**을 선택합니다. 작업이 완료될 때까지 최소 30분을 기다립니다.
1. 같은 **설정** > **일반** > **고급** 섹션에서 **도달할 수 없는 객체 정리**를 선택합니다. 이 작업은 완료하는 데 약 5-10분이 소요됩니다.

> [!note]
> 민감한 정보가 포함된 프로젝트가 포크된 경우 정리 작업이 이 프로세스를 완료하지 못할 수 있습니다. 정리는 포크된 데이터가 포함된 [특별한 객체 풀 리포지토리](../../../administration/housekeeping.md#object-pool-repositories)의 무결성을 유지해야 합니다. 도움을 받으려면 GitLab Support에 문의하세요.

#### 객체 ID 목록 얻기 {#get-a-list-of-object-ids}

Blob을 제거하려면 제거할 객체의 목록이 필요합니다. 이러한 ID를 얻으려면 `ls-tree` 명령이나 [리포지토리 트리 API 엔드포인트 나열](../../../api/repositories.md#list-all-repository-trees-in-a-project)을 사용합니다. 다음 지침은 `ls-tree` 명령을 사용합니다.

사전 요구 사항:

- 리포지토리는 로컬 머신에 클론되어야 합니다.

주어진 커밋 또는 브랜치에서 크기순으로 정렬된 Blob 목록을 얻으려면:

1. 터미널을 열고 리포지토리 디렉터리로 이동합니다.
1. 다음 명령을 실행합니다:

   ```shell
   git ls-tree -r -t --long --full-name <COMMIT/BRANCH> | sort -nk 4
   ```

   예제 출력:

   ```plaintext
   100644 blob 8150ee86f923548d376459b29afecbe8495514e9  133508 doc/howto/img/remote-development-new-workspace-button.png
   100644 blob cde4360b3d3ee4f4c04c998d43cfaaf586f09740  214231 doc/howto/img/dependency_proxy_macos_config_new.png
   100644 blob 2ad0e839a709e73a6174e78321e87021b20be445  216452 doc/howto/img/gdk-in-gitpod.jpg
   100644 blob 115dd03fc0828a9011f012abbc58746f7c587a05  242304 doc/howto/img/gitpod-button-repository.jpg
   100644 blob c41ebb321a6a99f68ee6c353dd0ed29f52c1dc80  491158 doc/howto/img/dependency_proxy_macos_config.png
   ```

   출력의 세 번째 열은 Blob의 객체 ID입니다. 예: `8150ee86f923548d376459b29afecbe8495514e9`.

### 리포지토리에서 텍스트 수정 {#redact-text-from-repository}

{{< history >}}

- GitLab 17.1에서 [기능 플래그](../../../administration/feature_flags/_index.md) `rewrite_history_ui` 이름으로 도입되었습니다. 기본적으로 비활성화되었습니다. GitLab 팀 멤버는 이 기밀 이슈에서 자세한 정보를 볼 수 있습니다: `https://gitlab.com/gitlab-org/gitlab/-/issues/450701`.
- GitLab 17.2에서 기밀 이슈 `https://gitlab.com/gitlab-org/gitlab/-/issues/462999`에서 GitLab.com에 활성화되었습니다.
- GitLab 17.3에서 기밀 이슈 `https://gitlab.com/gitlab-org/gitlab/-/issues/462999`에서 GitLab Self-Managed 및 GitLab Dedicated에 활성화되었습니다.
- GitLab 17.9에서 기밀 이슈 `https://gitlab.com/gitlab-org/gitlab/-/issues/472018`에서 일반적으로 사용 가능합니다. 기능 플래그 `rewrite_history_ui`이 제거되었습니다.

{{< /history >}}

실수로 커밋된 민감하거나 기밀인 정보를 영구 삭제하여 리포지토리 기록에서 더 이상 액세스할 수 없도록 합니다. 문자열 목록을 `***REMOVED***`로 바꿉니다.

> [!warning]
> 이 작업은 되돌릴 수 없습니다. 기록을 다시 작성하고 정리를 실행한 후 변경 사항은 영구적입니다.

GitLab에서 파일을 수정하면 노출된 비밀을 제거하지만 다음도 수행합니다:

- Git 기록을 다시 작성합니다. 이전 커밋 기록을 기반으로 한 과거 태그 및 브랜치가 올바르게 작동하지 않을 수 있습니다.
- 파괴적입니다. 기존 로컬 클론은 업데이트된 리포지토리와 호환되지 않으며 다시 클론해야 합니다.
- 수정이 콘텐츠를 업데이트하기 때문에 커밋 해시를 업데이트합니다.
- 다시 작성 프로세스 중에 커밋 서명을 드롭합니다.
- 커밋 해시에 따라 달라지는 기능을 중단합니다. 다음을 포함합니다:
  - 머지 리퀘스트를 엽니다. 열린 머지 리퀘스트가 병합에 실패하고 수동 리베이스가 필요할 수 있습니다.
  - 이전 커밋에 대한 링크로 인해 404 오류가 발생합니다.
- 이전 커밋 SHA를 참조하는 파이프라인이 중단되고 재구성이 필요할 수 있습니다.

더 나은 리포지토리 무결성을 위해 대신 다음을 수행해야 합니다:

- 노출된 비밀을 취소하거나 회전합니다.
- [GitLab의 시크릿 검색 기능](../../application_security/secret_detection/_index.md)을 구현합니다.

이 접근 방식은:

- 향후 비밀 유출을 사전에 방지합니다.
- 보안 준수를 보장하면서 Git 기록을 유지합니다.

자세한 정보는 [시크릿 푸시 보호](../../application_security/secret_detection/secret_push_protection/_index.md)를 참조하세요.

또는 리포지토리에서 특정 파일을 완전히 삭제하려면 [Blob 제거](#remove-blobs)를 참조하세요.

사전 요구 사항:

- 프로젝트에 대해 Owner 역할이 필요합니다.

리포지토리에서 텍스트를 수정하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **리포지토리 유지 보수**를 확장합니다.
1. **텍스트 수정**을 선택합니다.
1. 드로어에 수정할 텍스트를 입력합니다. 정규식 및 glob 패턴을 허용합니다.
1. **일치하는 문자열 수정**을 선택합니다.
1. 확인 대화 상자에서 프로젝트 경로를 입력합니다.
1. **예, 일치하는 문자열을 수정합니다.**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급**을 확장합니다.
1. **정리 실행**을 선택합니다. 작업이 완료될 때까지 최소 30분을 기다립니다.
1. 같은 **설정** > **일반** > **고급** 섹션에서 **도달할 수 없는 객체 정리**를 선택합니다. 이 작업은 완료하는 데 약 5-10분이 소요됩니다.

> [!note]
> 민감한 정보가 포함된 프로젝트가 포크된 경우 정리 작업이 [포크된 데이터를 포함](../../../administration/housekeeping.md#object-pool-repositories)하는 특별한 객체 풀 리포지토리의 무결성을 유지하기 위해 이 수정 프로세스를 완료하지 못할 수 있습니다. 도움을 받으려면 GitLab Support에 문의하세요.

## 문제 해결 {#troubleshooting}

이 섹션에는 발생할 수 있는 문제에 대한 해결책이 있습니다.

### GUI에 잘못된 리포지토리 통계가 표시됨 {#incorrect-repository-statistics-shown-in-the-gui}

GitLab 인터페이스에 표시된 리포지토리 크기 또는 커밋 번호가 내보낸 `.tar.gz` 또는 로컬 리포지토리와 다른 경우:

1. GitLab 관리자에게 Rails 콘솔을 사용하여 강제로 업데이트하도록 요청합니다.
1. 관리자는 다음 명령을 실행해야 합니다:

   ```ruby
   p = Project.find_by_full_path('<namespace>/<project>')
   p.statistics.refresh!
   ```

1. 프로젝트 통계를 지우고 다시 계산을 트리거하려면:

   ```ruby
   p.repository.expire_all_method_caches
   UpdateProjectStatisticsWorker.perform_async(p.id, ["commit_count","repository_size","storage_size","lfs_objects_size","container_registry_size"])
   ```

1. 전체 아티팩트 스토리지 공간을 확인하려면:

   ```ruby
   builds_with_artifacts = p.builds.with_downloadable_artifacts.all

   artifact_storage = 0
   builds_with_artifacts.find_each do |build|
     artifact_storage += build.artifacts_size
   end

   puts "#{artifact_storage} bytes"
   ```

### 정리 후 공간이 해제되지 않음 {#space-not-being-freed-after-cleanup}

리포지토리 정리 프로세스를 완료했지만 스토리지 사용량이 변경되지 않은 경우:

- 도달할 수 없는 객체가 2주 유예 기간 동안 리포지토리에 남아 있다는 것을 알아둡니다.
- 이러한 객체는 내보내기에 포함되지 않지만 여전히 파일 시스템 공간을 차지합니다.
- 2주 후 이러한 객체는 자동으로 정리되어 스토리지 사용량 통계를 업데이트합니다.
- 이 프로세스를 가속화하려면 관리자에게 ['도달할 수 없는 객체 정리' 정리 작업](../../../administration/housekeeping.md)을 실행하도록 요청합니다.

### Blob이 제거되지 않음 {#blobs-are-not-removed}

Blob이 성공적으로 제거되면 GitLab은 프로젝트 감사 로그에 항목을 추가하고 작업을 시작한 사람에게 이메일 알림을 보냅니다.

Blob 제거가 실패하면 GitLab은 제목 `<project_name> | Project history rewrite failure`이 있는 이메일 알림을 시작자에게 보냅니다. 이메일 본문에는 전체 오류 메시지가 포함됩니다.

가능한 오류 및 해결책:

- `validating object ID: invalid object ID`: 객체 ID 목록에는 구문 오류 또는 잘못된 객체 ID가 포함되어 있습니다. 이 문제를 해결하려면:
  1. [객체 ID 목록](#get-a-list-of-object-ids)을 다시 생성합니다.
  1. [Blob 제거 단계](#remove-blobs)를 다시 실행합니다.
- `source repository checksum altered`: 이는 누군가가 Blob 제거 프로세스 중에 커밋을 푸시할 때 발생합니다. 이 문제를 해결하려면:
  1. 리포지토리에 대한 모든 푸시를 일시적으로 차단합니다.
  1. [Blob 제거 단계](#remove-blobs)를 다시 실행합니다.
  1. 프로세스가 성공적으로 완료된 후 푸시를 다시 활성화합니다.

### 리포지토리 크기 제한 도달 {#repository-size-limit-reached}

리포지토리 크기 제한에 도달한 경우:

- 일부 데이터를 제거하고 새 커밋을 만들어 봅니다.
- 실패하면 일부 Blob을 [Git LFS](../../../topics/git/lfs/_index.md)로 이동하거나 기록에서 이전 의존성 업데이트를 제거하는 것을 고려합니다.
- 여전히 변경 사항을 푸시할 수 없으면 GitLab 관리자에게 문의하여 [프로젝트에 대한 제한을 일시적으로 증가](../../../administration/settings/account_and_limit_settings.md#repository-size-limit)시킵니다.
- 마지막 수단으로 새 프로젝트를 생성하고 데이터를 마이그레이션합니다.

> [!note]
> 새 커밋에서 파일을 삭제해도 리포지토리 크기가 즉시 줄어들지 않습니다. 이전 커밋 및 Blob이 여전히 존재하기 때문입니다. 크기를 효과적으로 줄이려면 [`git filter-repo`](https://github.com/newren/git-filter-repo)과 같은 도구를 사용하여 기록을 다시 작성해야 합니다.
