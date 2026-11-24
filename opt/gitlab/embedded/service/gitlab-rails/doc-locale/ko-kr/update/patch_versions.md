---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 패치 버전으로 자체 컴파일된 인스턴스 업데이트
description: 패치 버전으로 단일 노드 자체 컴파일된 인스턴스 업데이트합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

패치 버전으로 자체 컴파일된 인스턴스를 업데이트합니다.

## 전제 조건 {#prerequisites}

업데이트하기 전에:

1. 필수 정보를 [읽고 필수 단계를 수행](plan_your_upgrade.md)해야 합니다.
1. 자체 컴파일된 인스턴스를 [백업](../administration/backup_restore/_index.md)합니다.

## 패치 버전으로 자체 컴파일된 인스턴스 업데이트 {#update-a-self-compiled-instance-with-a-patch-version}

패치 버전으로 자체 컴파일된 인스턴스를 업데이트하려면:

1. 업데이트 중에 [유지 보수 모드를 활성화](../administration/maintenance_mode/_index.md)하는 것을 고려하세요.
1. 실행 중인 [CI/CD 파이프라인 및 작업](plan_your_upgrade.md#pause-cicd-pipelines-and-jobs)을 일시 중지합니다.
1. [GitLab Runner를 업그레이드](https://docs.gitlab.com/runner/install/)하여 대상 GitLab 버전과 동일한 버전으로 설정합니다.
1. 이 페이지의 지시사항에 따라 GitLab을 업데이트합니다.

업데이트 후:

1. 일시 중지된 [CI/CD 파이프라인 및 작업](plan_your_upgrade.md#pause-cicd-pipelines-and-jobs)을 재개합니다.
1. 활성화된 경우 [유지 보수 모드를 비활성화](../administration/maintenance_mode/_index.md#disable-maintenance-mode)합니다.
1. [상태 확인](plan_your_upgrade.md#run-upgrade-health-checks)을 실행합니다.

### GitLab 서버 중지 {#stop-gitlab-server}

GitLab 서버를 중지하려면:

```shell
# For systems running systemd
sudo systemctl stop gitlab.target

# For systems running SysV init
sudo service gitlab stop
```

### 안정적 브랜치의 최신 코드 가져오기 {#get-latest-code-for-the-stable-branch}

다음 명령에서 `LATEST_TAG`을 업데이트할 GitLab 태그로 바꿉니다. 예를 들어, `v8.0.3`입니다.

1. 현재 버전 확인:

   ```shell
   cat VERSION
   ```

1. 사용 가능한 모든 태그 목록 가져오기:

   ```shell
   git tag -l 'v*.[0-9]' --sort='v:refname'
   ```

1. 현재 주 버전 및 보조 버전에 대한 패치 버전을 선택합니다.
1. 사용할 패치 버전의 코드를 확인합니다:

   ```shell
   cd /home/git/gitlab

   sudo -u git -H git fetch --all
   sudo -u git -H git checkout -- Gemfile.lock db/structure.sql locale
   sudo -u git -H git checkout LATEST_TAG -b LATEST_TAG
   ```

### 라이브러리 설치 및 마이그레이션 실행 {#install-libraries-and-run-migrations}

라이브러리를 설치하고 마이그레이션을 실행하려면 다음 명령을 실행합니다:

```shell
cd /home/git/gitlab

# If you haven't done so during installation or a previous upgrade already
sudo -u git -H bundle config set --local deployment 'true'
sudo -u git -H bundle config set --local without 'development test kerberos'

# Update gems
sudo -u git -H bundle install

# Optional: clean up old gems
sudo -u git -H bundle clean

# Run database migrations
sudo -u git -H bundle exec rake db:migrate RAILS_ENV=production

# Clean up assets and cache
sudo -u git -H bundle exec rake yarn:install gitlab:assets:clean gitlab:assets:compile cache:clear RAILS_ENV=production NODE_ENV=production NODE_OPTIONS="--max_old_space_size=4096"
```

### GitLab Workhorse를 새 패치 버전으로 업데이트 {#update-gitlab-workhorse-to-the-new-patch-version}

GitLab Workhorse를 새 패치 버전으로 업데이트하려면:

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake "gitlab:workhorse:install[/home/git/gitlab-workhorse]" RAILS_ENV=production
```

### Gitaly를 새 패치 버전으로 업데이트 {#update-gitaly-to-the-new-patch-version}

Gitaly를 새 패치 버전으로 업데이트하려면:

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake "gitlab:gitaly:install[/home/git/gitaly,/home/git/repositories]" RAILS_ENV=production
```

### GitLab Shell을 새 패치 버전으로 업데이트 {#update-gitlab-shell-to-the-new-patch-version}

GitLab Shell을 새 패치 버전으로 업데이트하려면:

```shell
cd /home/git/gitlab-shell

sudo -u git -H git fetch --all --tags
sudo -u git -H git checkout v$(</home/git/gitlab/GITLAB_SHELL_VERSION) -b v$(</home/git/gitlab/GITLAB_SHELL_VERSION)
sudo -u git -H make build
```

### GitLab Pages를 새 패치 버전으로 업데이트(필요한 경우) {#update-gitlab-pages-to-the-new-patch-version-if-required}

GitLab Pages를 사용 중이면 GitLab Pages를 새 패치 버전으로 업데이트합니다:

```shell
cd /home/git/gitlab-pages

sudo -u git -H git fetch --all --tags
sudo -u git -H git checkout v$(</home/git/gitlab/GITLAB_PAGES_VERSION)
sudo -u git -H make
```

### `gitlab-elasticsearch-indexer` 설치 또는 업데이트 {#install-or-update-gitlab-elasticsearch-indexer}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

`gitlab-elasticsearch-indexer`을 설치하거나 업데이트하려면 [설치 지시사항](../integration/advanced_search/elasticsearch.md#install-an-elasticsearch-or-aws-opensearch-cluster)을 따릅니다.

### GitLab 시작 {#start-gitlab}

GitLab을 시작하려면 다음 명령을 실행합니다:

```shell
# For systems running systemd
sudo systemctl start gitlab.target
sudo systemctl restart nginx.service

# For systems running SysV init
sudo service gitlab start
sudo service nginx restart
```

### GitLab 및 환경 확인 {#check-gitlab-and-its-environment}

GitLab 및 환경이 올바르게 구성되었는지 확인하려면 다음을 실행합니다:

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake gitlab:env:info RAILS_ENV=production
```

놓친 부분이 없는지 확인하려면 다음 명령으로 더 철저한 확인을 실행합니다:

```shell
sudo -u git -H bundle exec rake gitlab:check RAILS_ENV=production
```

### 백그라운드 마이그레이션이 완료되었는지 확인 {#make-sure-background-migrations-are-finished}

[백그라운드 마이그레이션의 상태 확인](background_migrations.md)하고 완료되었는지 확인합니다.
