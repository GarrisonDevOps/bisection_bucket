---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 이전 GitLab 버전으로 롤백
description: Linux 패키지 또는 Docker 인스턴스를 이전 버전으로 롤백합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

Linux 패키지 또는 Docker를 사용하여 설치된 이전 버전의 GitLab 인스턴스로 롤백할 수 있습니다.

롤백할 때는 이전에 업그레이드할 때 발생한 [버전별 변경 사항](../versions/_index.md)을 고려해야 합니다.

## 전제 조건 {#prerequisites}

인스턴스가 업그레이드될 때 변경된 데이터베이스 스키마 변경 사항(마이그레이션)을 되돌려야 하므로 다음이 필요합니다:

- 롤백하는 버전 및 에디션과 정확히 동일한 조건에서 생성된 데이터베이스 백업 이상이 필요합니다.
- 이상적으로는 롤백하는 정확히 동일한 버전 및 에디션의 [전체 백업 아카이브](../../administration/backup_restore/_index.md)가 필요합니다.

## Linux 패키지 인스턴스 롤백 {#roll-back-a-linux-package-instance}

Linux 패키지 인스턴스를 이전 GitLab 버전으로 롤백하려면:

1. GitLab을 중지하고 현재 패키지를 제거합니다:

   ```shell
   # If running Puma
   sudo gitlab-ctl stop puma

   # Stop sidekiq
   sudo gitlab-ctl stop sidekiq

   # If on Ubuntu: remove the current package
   sudo dpkg -r gitlab-ee

   # If on Centos: remove the current package
   sudo yum remove gitlab-ee
   ```

1. 롤백할 GitLab 버전을 확인합니다:

   ```shell
   # (Replace with gitlab-ce if you have GitLab FOSS installed)

   # Ubuntu
   sudo apt-cache madison gitlab-ee

   # CentOS:
   sudo yum --showduplicates list gitlab-ee
   ```

1. GitLab을 원하는 버전으로 롤백합니다(예: GitLab 19.2.1):

   ```shell
   # (Replace with gitlab-ce if you have GitLab FOSS installed)

   # Ubuntu
   sudo apt install gitlab-ee=19.2.1-ee.0

   # CentOS:
   sudo yum install gitlab-ee-19.2.1-ee.0.el8
   ```

1. GitLab을 재구성합니다.

   ```shell
   sudo gitlab-ctl reconfigure
   ```

1. [GitLab 복원](../../administration/backup_restore/restore_gitlab.md#restore-for-linux-package-installations)하여 롤백을 완료합니다.

## Docker 인스턴스 롤백 {#roll-back-a-docker-instance}

복원은 모든 새로운 GitLab 데이터베이스 콘텐츠를 이전 상태로 덮어씁니다. 롤백은 필요한 경우에만 권장됩니다. 예를 들어, 업그레이드 후 테스트에서 빠르게 해결할 수 없는 문제가 나타나는 경우입니다.

> [!warning]
> 다운그레이드하려는 정확히 동일한 버전 및 에디션으로 생성된 데이터베이스 백업 이상이 필요합니다. 백업은 업그레이드 중에 적용된 스키마 변경 사항(마이그레이션)을 되돌리기 위해 필요합니다.

업그레이드 직후 GitLab을 롤백하려면:

1. 업그레이드 절차를 수행하되, 설치된 버전보다 [이전 버전을 지정](../../install/docker/installation.md#find-the-gitlab-version-and-edition-to-use)합니다.
1. 업그레이드 전에 [생성한 데이터베이스 백업](../../install/docker/backup.md#create-a-database-backup)을 복원합니다.

   - [Docker 이미지용 복원 단계를 따르고](../../administration/backup_restore/restore_gitlab.md#restore-for-docker-image-and-gitlab-helm-chart-installations), Puma 및 Sidekiq 중지를 포함합니다. 데이터베이스만 복원해야 하므로 `SKIP=artifacts,repositories,registry,uploads,builds,pages,lfs,packages,terraform_state`을 `gitlab-backup restore` 명령줄 인수에 추가합니다.
