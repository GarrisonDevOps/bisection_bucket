---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Git LFS를 사용하여 이미지, 비디오 등의 이진 자산을 관리하되 Git 리포지토리 크기가 증가하지 않도록 합니다."
title: Git 대용량 파일 스토리지(LFS)
---

Git 대용량 파일 스토리지(LFS)는 Git 리포지토리가 대용량 이진 파일을 효율적으로 관리할 수 있도록 돕는 오픈소스 Git 확장입니다. Git은 텍스트 파일에 대한 변경 사항을 추적하는 것과 같은 방식으로 이진 파일(오디오, 비디오, 이미지 파일 등)에 대한 변경 사항을 추적할 수 없습니다. 텍스트 기반 파일은 평문 diff를 생성할 수 있지만 이진 파일의 변경 사항은 Git이 리포지토리의 파일을 완전히 교체해야 합니다. 대용량 파일에 대한 반복적인 변경 사항은 리포지토리 크기를 증가시킵니다. 시간이 지남에 따라 이러한 크기 증가는 `clone`, `fetch`, `pull`과 같은 일반적인 Git 작업의 속도를 늦출 수 있습니다.

Git LFS를 사용하여 Git 리포지토리 외부에 대용량 이진 파일을 저장하고 Git이 관리할 수 있도록 작은 텍스트 기반 포인터만 남깁니다. Git LFS를 사용하여 리포지토리에 파일을 추가하면 GitLab이 다음을 수행합니다:

1. Git 리포지토리 대신 프로젝트의 구성된 객체 스토리지에 파일을 추가합니다.
1. 대용량 파일 대신 Git 리포지토리에 포인터를 추가합니다. 포인터에는 파일에 대한 정보가 포함되어 있습니다. 예를 들면 다음과 같습니다:

   ```plaintext
   version https://git-lfs.github.com/spec/v1
   oid sha256:lpca0iva5kpz9wva5rgsqsicxrxrkbjr0bh4sy6rz08g2c4tyc441rto5j5bctit
   size 804
   ```

   - 버전 - 사용 중인 Git LFS 사양의 버전
   - OID - 사용된 해싱 방법과 고유한 객체 ID는 `{hash-method}:{hash}` 형식입니다.
   - 크기 - 파일 크기(바이트)입니다.

1. 프로젝트 통계를 다시 계산하도록 작업을 대기열에 넣습니다. 이는 스토리지 크기 및 LFS 객체 스토리지를 포함합니다. LFS 객체 스토리지는 리포지토리와 연결된 모든 LFS 객체의 크기의 합입니다.

Git LFS로 관리되는 파일은 파일명 옆에 **LFS** 배지를 표시합니다:

![Git LFS 추적 상태](img/lfs_badge_v16_0.png)

Git LFS 클라이언트는 HTTP 기본 인증을 사용하고 HTTPS를 통해 서버와 통신합니다. 요청을 인증한 후 Git LFS 클라이언트는 대용량 파일을 가져오거나 푸시할 위치에 대한 지침을 받습니다.

Git 리포지토리는 더 작은 크기로 유지되므로 리포지토리 크기 제한을 준수할 수 있습니다. 자세한 정보는 리포지토리 크기 제한 [GitLab Self-Managed용](../../../administration/settings/account_and_limit_settings.md#repository-size-limit) 및 [GitLab.com용](../../../user/gitlab_com/_index.md#account-and-limit-settings)을 참조하세요.

## Git LFS가 포크와 함께 작동하는 방식 이해 {#understand-how-git-lfs-works-with-forks}

리포지토리를 포크할 때 포크에는 포크 시점에 존재했던 업스트림 리포지토리의 기존 LFS 객체가 포함됩니다. 포크에 새로운 LFS 객체를 추가하면 이들은 포크에만 속하며 업스트림 리포지토리에는 속하지 않습니다. 총 객체 스토리지는 포크에 대해서만 증가합니다.

포크에서 업스트림 프로젝트로 머지 리퀘스트를 생성하고 머지 리퀘스트에 새로운 Git LFS 객체가 포함되면 GitLab은 머지 후 새로운 LFS 객체를 업스트림 프로젝트와 연결합니다.

## 프로젝트에 대해 Git LFS 구성 {#configure-git-lfs-for-a-project}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab은 GitLab Self-Managed 및 GitLab.com 모두에 대해 기본적으로 Git LFS를 활성화합니다. 서버 설정 및 프로젝트별 설정을 모두 제공합니다.

- 인스턴스에서 Git LFS를 구성하려면(예: 원격 객체 스토리지 설정) [Git 대용량 파일 스토리지(LFS) 관리](../../../administration/lfs/_index.md)를 참조하세요.
- 특정 프로젝트에 대해 Git LFS를 구성하려면:

  1. 리포지토리의 로컬 복사본의 루트 디렉터리에서 `git lfs install`를 실행합니다. 이 명령은 다음을 추가합니다:
     - 리포지토리에 사전 푸시 Git 훅을 추가합니다.
     - [`.gitattributes` 파일](../../../user/project/repository/files/git_attributes.md)을 추가하여 개별 파일 및 파일 유형에 대한 처리를 추적합니다.
  1. Git LFS로 추적하려는 파일 및 파일 유형을 추가합니다.

## 프로젝트에 대해 Git LFS 활성화 또는 비활성화 {#enable-or-disable-git-lfs-for-a-project}

Git LFS는 GitLab Self-Managed 및 GitLab.com 모두에 대해 기본적으로 활성화됩니다.

전제 조건:

- 프로젝트에 대해 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

프로젝트에 대해 Git LFS를 활성화하거나 비활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한** 섹션을 확장합니다.
1. **Git 대용량 파일 스토리지 (LFS)** 토글을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 파일 추가 및 추적 {#add-and-track-files}

Git LFS에 대용량 파일을 추가할 수 있습니다. 이는 Git 리포지토리의 파일을 관리하는 데 도움이 됩니다. Git LFS로 파일을 추적하면 Git의 텍스트 포인터로 교체되고 원격 서버에 저장됩니다. 자세한 정보는 [Git LFS](../file_management.md#git-lfs)를 참조하세요.

[프로젝트에 대해 Git LFS를 구성](#configure-git-lfs-for-a-project)할 때 프로젝트의 루트 디렉터리에 `.gitattributes` 파일이 있는지 확인하세요. 루트 수준의 `.gitattributes` 파일이 없으면 프로젝트 하위 디렉터리에서 LFS를 올바르게 구성한 경우에도 UI에 경고가 표시됩니다. 자세한 정보는 [LFS 구성 경고 메시지](troubleshooting.md#warning-possible-lfs-configuration-issue)를 참조하세요.

## Git LFS를 사용하는 리포지토리 복제 {#clone-a-repository-that-uses-git-lfs}

Git LFS를 사용하는 리포지토리를 복제할 때 Git은 LFS 추적 파일을 감지하고 HTTPS를 통해 복제합니다. `git clone`을 SSH URL(예: `user@hostname.com:group/project.git`)과 함께 실행하면 HTTPS 인증을 위해 GitLab 자격 증명을 다시 입력해야 합니다.

기본적으로 Git이 SSH를 통해 리포지토리와 통신하는 경우에도 Git LFS 작업은 HTTPS를 통해 발생합니다. GitLab 17.2에서는 [LFS에 대한 순수 SSH 지원](https://gitlab.com/groups/gitlab-org/-/work_items/11872)이 도입되었습니다. 이 기능을 활성화하는 방법에 대한 정보는 [순수 SSH 전송 프로토콜](../../../administration/lfs/_index.md#pure-ssh-transfer-protocol)을 참조하세요.

이미 복제한 리포지토리에 대해 새로운 LFS 객체를 가져오려면 다음 명령을 실행합니다:

```shell
git lfs fetch origin main
```

## 기존 리포지토리를 Git LFS로 마이그레이션 {#migrate-an-existing-repository-to-git-lfs}

[`git-lfs-migrate` 문서](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-migrate.adoc)에서 기존 Git 리포지토리를 Git LFS로 마이그레이션하는 방법을 읽어보세요.

## 리포지토리 기록에서 Git LFS 파일 삭제 {#delete-a-git-lfs-file-from-repository-history}

Git LFS에서 파일을 추적 해제하는 것과 파일을 삭제하는 것의 차이점을 이해하는 것이 중요합니다:

- 추적 해제: 파일은 디스크 및 리포지토리 기록에 남아 있습니다. 사용자가 과거 브랜치 또는 태그를 확인하면 여전히 파일의 LFS 버전이 필요합니다.
- 삭제: 파일이 제거되었지만 리포지토리 기록에 남아 있습니다.

Git LFS로 추적되는 파일을 삭제하려면 [파일 제거](../undo.md#remove-a-file-from-a-repository)를 참조하세요.

파일의 모든 기록(과거 및 현재)을 완전히 제거하려면 [민감한 정보 처리](../undo.md#handle-sensitive-information)를 참조하세요.

> [!warning]
> 파일 기록 제거는 Git 기록을 다시 작성해야 합니다. 이 작업은 파괴적이고 되돌릴 수 없습니다.

## 대용량 파일 제거 후 리포지토리 크기 축소 {#reduce-repository-size-after-removing-large-files}

리포지토리 기록에서 대용량 파일을 제거하여 리포지토리의 총 크기를 축소해야 하는 경우 [리포지토리 크기 축소](../../../user/project/repository/repository_size.md#methods-to-reduce-repository-size)를 참조하세요.

## 관련 항목 {#related-topics}

- Git LFS를 사용하여 [독점 파일 잠금](../file_management.md#configure-file-locks)을 설정합니다.
- 블로그 게시물: [Git LFS 시작하기](https://about.gitlab.com/blog/getting-started-with-git-lfs-tutorial/)
- [Git으로 Git LFS 사용](../file_management.md#git-lfs)
- [GitLab Git 대용량 파일 스토리지(LFS) 관리](../../../administration/lfs/_index.md) \- GitLab Self-Managed용
- [Git LFS 문제 해결](troubleshooting.md)
- [`.gitattributes` 파일](../../../user/project/repository/files/git_attributes.md)
