---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Docker 인스턴스 업그레이드
description: 단일 노드 Docker 기반 인스턴스를 업그레이드합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

Docker 기반 인스턴스를 최신 버전의 GitLab으로 업그레이드합니다.

## 전제 조건 {#prerequisites}

Docker 인스턴스를 업그레이드하기 전에 먼저 [필수 정보를 읽고 필수 단계를 수행](../plan_your_upgrade.md)해야 합니다.

## Docker 기반 인스턴스 업그레이드 {#upgrade-a-docker-based-instance}

Docker 기반 인스턴스를 업그레이드하려면:

1. 업그레이드 중에 [유지 관리 모드 활성화](../../administration/maintenance_mode/_index.md)를 고려하세요.
1. [실행 중인 CI/CD 파이프라인 및 작업](../plan_your_upgrade.md#pause-cicd-pipelines-and-jobs)을 일시 중지합니다.
1. [GitLab Runner를 업그레이드](https://docs.gitlab.com/runner/install/)하여 대상 GitLab 버전과 동일한 버전으로 만듭니다.
1. GitLab 자체를 다음 중 하나로 업그레이드합니다:
   - [Docker Engine 사용](#upgrade-with-docker-engine).
   - [Docker Compose 사용](#upgrade-with-docker-compose).

업그레이드 후:

1. [실행 중인 CI/CD 파이프라인 및 작업](../plan_your_upgrade.md#pause-cicd-pipelines-and-jobs)을 다시 시작합니다.
1. 활성화된 경우 [유지 관리 모드 비활성화](../../administration/maintenance_mode/_index.md#disable-maintenance-mode)합니다.
1. [업그레이드 상태 확인](../plan_your_upgrade.md#run-upgrade-health-checks)을 실행합니다.

### Docker Engine으로 업그레이드 {#upgrade-with-docker-engine}

[Docker Engine으로 설치](../../install/docker/installation.md#install-gitlab-by-using-docker-engine)된 GitLab 인스턴스를 업그레이드하려면:

1. [백업](../../install/docker/backup.md)을 만듭니다. 최소한 [데이터베이스](../../install/docker/backup.md#create-a-database-backup) 및 GitLab 시크릿 파일을 백업합니다.
1. 실행 중인 컨테이너를 중지합니다:

   ```shell
   sudo docker stop gitlab
   ```

1. 기존 컨테이너를 제거합니다:

   ```shell
   sudo docker rm gitlab
   ```

1. 새 이미지를 가져옵니다:

   {{< tabs >}}

   {{< tab title="GitLab Enterprise Edition" >}}

   ```shell
   sudo docker pull gitlab/gitlab-ee:<version>-ee.0
   ```

   {{< /tab >}}

   {{< tab title="GitLab Community Edition" >}}

   ```shell
   sudo docker pull gitlab/gitlab-ce:<version>-ce.0
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. `GITLAB_HOME` 환경 변수가 [정의](../../install/docker/installation.md#create-a-directory-for-the-volumes)되었는지 확인합니다:

   ```shell
   echo $GITLAB_HOME
   ```

1. [이전에 지정된](../../install/docker/installation.md#install-gitlab-by-using-docker-engine) 옵션으로 컨테이너를 다시 만듭니다:

   ```shell
   sudo docker run --detach \
   --hostname gitlab.example.com \
   --publish 443:443 --publish 80:80 --publish 22:22 \
   --name gitlab \
   --restart always \
   --volume $GITLAB_HOME/config:/etc/gitlab \
   --volume $GITLAB_HOME/logs:/var/log/gitlab \
   --volume $GITLAB_HOME/data:/var/opt/gitlab \
   --shm-size 256m \
   gitlab/gitlab-ee:<version>-ee.0
   ```

처음 실행할 때 GitLab은 자동으로 재구성되고 업그레이드됩니다.

### Docker Compose로 업그레이드 {#upgrade-with-docker-compose}

[Docker Compose로 설치](../../install/docker/installation.md#install-gitlab-by-using-docker-compose)된 GitLab 인스턴스를 업그레이드하려면:

1. [백업](../../install/docker/backup.md)을 만듭니다. 최소한 [데이터베이스](../../install/docker/backup.md#create-a-database-backup) 및 GitLab 시크릿 파일을 백업합니다.
1. `docker-compose.yml`을(를) 편집하고 가져올 버전을 변경합니다.
1. 최신 릴리스를 다운로드하고 GitLab 인스턴스를 업그레이드합니다:

   ```shell
   docker compose pull
   docker compose up -d
   ```
