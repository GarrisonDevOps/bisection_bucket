---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 자체 컴파일 인스턴스 업그레이드
description: 단일 노드 자체 컴파일 인스턴스를 업그레이드합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

자체 컴파일 인스턴스를 GitLab의 최신 버전으로 업그레이드합니다.

## 전제 조건 {#prerequisites}

업그레이드하기 전에:

1. 필수 정보를 [읽고 필수 단계를 수행](plan_your_upgrade.md)해야 합니다.
1. [소프트웨어 요구 사항](../install/self_compiled/_index.md#software-requirements)에서 Ruby, Node.js, Go 및 PostgreSQL을 검토합니다.

## 자체 컴파일 인스턴스 업그레이드 {#upgrade-a-self-compiled-instance}

자체 컴파일 인스턴스를 업그레이드하려면:

1. 업그레이드 중에 [유지 관리 모드 설정](../administration/maintenance_mode/_index.md)을 고려하세요.
1. 실행 중인 [CI/CD 파이프라인 및 작업](plan_your_upgrade.md#pause-cicd-pipelines-and-jobs)을 일시 중지합니다.
1. [GitLab Runner를 업그레이드](https://docs.gitlab.com/runner/install/)하여 대상 GitLab 버전과 동일한 버전으로 설정합니다.
1. 이 페이지의 지침에 따라 GitLab을 업그레이드합니다.

업그레이드 후:

1. 일시 중지된 [CI/CD 파이프라인 및 작업](plan_your_upgrade.md#pause-cicd-pipelines-and-jobs)을 재개합니다.
1. 활성화된 경우 [유지 보수 모드를 비활성화](../administration/maintenance_mode/_index.md#disable-maintenance-mode)합니다.
1. [업그레이드 상태 확인](plan_your_upgrade.md#run-upgrade-health-checks)을 실행합니다.

### 백업 생성 {#create-a-backup}

전제 조건:

- `rsync`가 설치되어 있는지 확인하세요.

백업을 생성하려면:

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake gitlab:backup:create RAILS_ENV=production
```

### GitLab 중지 {#stop-gitlab}

GitLab을 중지하려면:

```shell
# For systems running systemd
sudo systemctl stop gitlab.target

# For systems running SysV init
sudo service gitlab stop
```

### Ruby 업데이트 {#update-ruby}

Ruby의 최신 버전이 필요한 경우 Ruby를 업데이트해야 합니다:

1. 설치된 Ruby 버전을 확인하려면 다음을 실행합니다:

   ```shell
   ruby -v
   ```

1. Ruby의 최신 버전으로 업데이트하는 지침은 [Ruby 설치 지침](https://www.ruby-lang.org/en/documentation/installation/)을 참조하세요.

### Node.js 업데이트 {#update-nodejs}

Node.js의 최신 버전이 필요한 경우 Node.js를 업데이트해야 합니다:

1. 설치된 Node.js 버전을 확인하려면 다음을 실행합니다:

   ```shell
   node -v
   ```

1. Node.js의 최신 버전으로 업데이트하는 지침은 [Node.js 다운로드 지침](https://nodejs.org/en/download)을 참조하세요.

GitLab은 또한 JavaScript 종속성을 관리하기 위해 Yarn `>= v1.10.0`을 필요로 합니다. 자세한 내용은 [Yarn 웹사이트](https://classic.yarnpkg.com/en/docs/install)를 참조하세요.

### Go 업데이트 {#update-go}

Go의 최신 버전이 필요한 경우 Go를 업데이트해야 합니다:

1. 설치된 Go 버전을 확인하려면 다음을 실행합니다:

   ```shell
   go version
   ```

1. Go의 최신 버전으로 업데이트하는 지침은 [Go 설치 지침](https://go.dev/doc/install)을 참조하세요.

### Git 업데이트 {#update-git}

Gitaly에서 제공하는 Git 버전을 사용해야 합니다. 자세한 내용은 [Git용 GitLab 설치 지침](../install/self_compiled/_index.md#git)을 참조하세요.

### PostgreSQL 업데이트 {#update-postgresql}

PostgreSQL의 최신 버전이 필요한 경우 PostgreSQL을 업데이트해야 합니다:

1. 설치된 PostgreSQL 버전을 확인하려면 다음을 실행합니다:

   ```shell
   pg_ctl --version
   ```

1. PostgreSQL의 최신 버전으로 업데이트하는 지침은 [PostgreSQL 업그레이드 설명서](https://www.postgresql.org/docs/16/upgrading.html)를 참조하세요.
1. 필요한 [PostgreSQL 확장](../install/requirements.md#postgresql)이 있는지 확인하세요.

### GitLab 코드베이스 업데이트 {#update-the-gitlab-codebase}

GitLab 코드베이스의 복제본을 업데이트하려면:

1. 리포지토리 메타데이터 가져오기:

   ```shell
   cd /home/git/gitlab

   sudo -u git -H git fetch --all --prune
   sudo -u git -H git checkout -- Gemfile.lock db/structure.sql locale
   ```

1. 업그레이드할 버전의 브랜치를 확인합니다:

   {{< tabs >}}

   {{< tab title="GitLab Enterprise Edition" >}}

   ```shell
   cd /home/git/gitlab

   sudo -u git -H git checkout <BRANCH-ee>
   ```

   {{< /tab >}}

   {{< tab title="GitLab Community Edition" >}}

   ```shell
   cd /home/git/gitlab

   sudo -u git -H git checkout <BRANCH>
   ```

   {{< /tab >}}

   {{< /tabs >}}

### 구성 파일 업데이트 {#update-configuration-files}

GitLab 업그레이드에는 다음 구성 업데이트가 필요할 수 있습니다:

- `gitlab.yml`
- `database.yml`
- NGINX (또는 Apache)
- SMTP
- systemd
- SysV

다음 섹션에서는 구성 업데이트가 필요한지 확인하는 방법을 설명합니다.

#### `gitlab.yml`에 대한 새 구성 {#new-configuration-for-gitlabyml}

[`gitlab.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/config/gitlab.yml.example)에 사용할 수 있는 새로운 구성 옵션이 있을 수 있습니다.

1. 가능한 새로운 구성을 확인합니다:

   ```shell
   cd /home/git/gitlab
   git diff origin/PREVIOUS_BRANCH:config/gitlab.yml.example origin/BRANCH:config/gitlab.yml.example
   ```

1. 현재 `gitlab.yml`에 새 구성을 수동으로 적용합니다.

#### `database.yml`에 대한 새 구성 {#new-configuration-for-databaseyml}

[`database.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/config/database.yml.postgresql)에 사용할 수 있는 새로운 구성 옵션이 있을 수 있습니다.

1. 가능한 새로운 구성을 확인합니다:

   ```shell
   cd /home/git/gitlab
   git diff origin/PREVIOUS_BRANCH:config/database.yml.postgresql origin/BRANCH:config/database.yml.postgresql
   ```

1. 현재 `database.yml`에 새 구성을 수동으로 적용합니다.

#### NGINX 또는 Apache에 대한 새 구성 {#new-configuration-for-nginx-or-apache}

최신 NGINX 구성 변경 사항을 최신 상태로 유지하는지 확인하세요:

```shell
cd /home/git/gitlab

# For HTTPS configurations
git diff origin/PREVIOUS_BRANCH:lib/support/nginx/gitlab-ssl origin/BRANCH:lib/support/nginx/gitlab-ssl

# For HTTP configurations
git diff origin/PREVIOUS_BRANCH:lib/support/nginx/gitlab origin/BRANCH:lib/support/nginx/gitlab
```

GitLab 애플리케이션은 더 이상 설치에서 Strict-Transport-Security를 설정하지 않습니다. 계속 사용하려면 NGINX 구성에서 이를 활성화해야 합니다.

NGINX 대신 Apache를 사용 중인 경우 업데이트된 [Apache 템플릿](https://gitlab.com/gitlab-org/gitlab-recipes/tree/master/web-server/apache)을 참조하세요. Apache는 Unix 소켓 뒤의 업스트림을 지원하지 않으므로 [`/etc/default/gitlab`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/support/init.d/gitlab.default.example#L38)을(를) 사용하여 GitLab Workhorse가 TCP 포트에서 수신 대기하도록 해야 합니다.

#### SMTP 구성 {#smtp-configuration}

SMTP를 사용하여 메일을 전달하는 경우 `config/initializers/smtp_settings.rb`에 다음 줄을 추가해야 합니다:

```ruby
ActionMailer::Base.delivery_method = :smtp
```

예제는 [`smtp_settings.rb.sample`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/config/initializers/smtp_settings.rb.sample#L13)를 참조하세요.

#### systemd 단위 구성 {#configure-systemd-units}

1. systemd 단위가 업데이트되었는지 확인합니다:

   ```shell
   cd /home/git/gitlab

   git diff origin/PREVIOUS_BRANCH:lib/support/systemd origin/BRANCH:lib/support/systemd
   ```

1. 복사합니다:

   ```shell
   sudo mkdir -p /usr/local/lib/systemd/system
   sudo cp lib/support/systemd/* /usr/local/lib/systemd/system/
   sudo systemctl daemon-reload
   ```

#### SysV init 스크립트 구성 {#configure-sysv-init-script}

[`gitlab.default.example`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/support/init.d/gitlab.default.example)에 사용할 수 있는 새로운 구성 옵션이 있을 수 있습니다.

1. 가능한 새로운 구성을 확인합니다:

   ```shell
   cd /home/git/gitlab

   git diff origin/PREVIOUS_BRANCH:lib/support/init.d/gitlab.default.example origin/BRANCH:lib/support/init.d/gitlab.default.example
   ```

1. 현재 `/etc/default/gitlab`에 수동으로 적용합니다.

최신 init 스크립트 변경 사항을 최신 상태로 유지하는지 확인하세요:

```shell
cd /home/git/gitlab

sudo cp lib/support/init.d/gitlab /etc/init.d/gitlab
```

systemd를 init으로 실행하는 시스템에서 init 스크립트를 사용 중이고 아직 네이티브 systemd 단위로 전환하지 않은 경우 다음을 실행합니다:

```shell
sudo systemctl daemon-reload
```

### 라이브러리 설치 및 마이그레이션 실행 {#install-libraries-and-run-migrations}

라이브러리를 설치하고 마이그레이션을 실행하려면:

1. 필요한 라이브러리를 설치합니다:

   ```shell
   cd /home/git/gitlab

   # If you haven't done so during installation or a previous upgrade already
   sudo -u git -H bundle config set --local deployment 'true'
   sudo -u git -H bundle config set --local without 'development test kerberos'

   # Update gems
   sudo -u git -H bundle install

   # Optional: clean up old gems
   sudo -u git -H bundle clean
   ```

1. 마이그레이션을 실행합니다:

   ```shell
   # Run database migrations
   sudo -u git -H bundle exec rake db:migrate RAILS_ENV=production

   # Update node dependencies and recompile assets
   sudo -u git -H bundle exec rake yarn:install gitlab:assets:clean gitlab:assets:compile RAILS_ENV=production NODE_ENV=production NODE_OPTIONS="--max_old_space_size=4096"

   # Clean up cache
   sudo -u git -H bundle exec rake cache:clear RAILS_ENV=production
   ```

### GitLab Shell 업데이트 {#update-gitlab-shell}

GitLab Shell을 업데이트하려면 다음 명령을 실행합니다:

```shell
cd /home/git/gitlab-shell

sudo -u git -H git fetch --all --tags --prune
sudo -u git -H git checkout v$(</home/git/gitlab/GITLAB_SHELL_VERSION)
sudo -u git -H make build
```

### GitLab Workhorse 업데이트 {#update-gitlab-workhorse}

GitLab Workhorse를 설치하고 컴파일하려면 다음 명령을 실행합니다:

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake "gitlab:workhorse:install[/home/git/gitlab-workhorse]" RAILS_ENV=production
```

### Gitaly 업데이트 {#update-gitaly}

애플리케이션 서버를 업그레이드하기 전에 Gitaly 서버를 최신 버전으로 업그레이드합니다. 이렇게 하면 애플리케이션 서버의 gRPC 클라이언트가 이전 Gitaly 버전에서 지원하지 않는 RPC를 보내는 것을 방지합니다.

Gitaly가 자체 서버에 위치하거나 Gitaly Cluster(Praefect)를 사용하는 경우 [무중단 업그레이드](zero_downtime.md)를 참조하세요.

빌드 프로세스 중에 Gitaly는 [Git 바이너리를 컴파일하고 포함](https://gitlab.com/gitlab-org/gitaly/-/issues/6089)하며, 이는 추가 종속성이 필요합니다.

```shell
# Install dependencies
sudo apt-get install -y libcurl4-openssl-dev libexpat1-dev gettext libz-dev libssl-dev libpcre2-dev build-essential

# Fetch Gitaly source with Git and compile with Go
cd /home/git/gitlab
sudo -u git -H bundle exec rake "gitlab:gitaly:install[/home/git/gitaly,/home/git/repositories]" RAILS_ENV=production
```

### GitLab Pages 업데이트 {#update-gitlab-pages}

GitLab Pages를 설치하고 컴파일하려면:

```shell
cd /home/git/gitlab-pages

sudo -u git -H git fetch --all --tags --prune
sudo -u git -H git checkout v$(</home/git/gitlab/GITLAB_PAGES_VERSION)
sudo -u git -H make
```

### 업그레이드 후 단계 {#post-upgrade-steps}

업그레이드한 후:

1. [GitLab 및 NGINX 시작](#start-gitlab-and-nginx)을(를) 수행합니다.
1. [GitLab 상태 확인](#check-gitlab-status)을(를) 수행합니다.

#### GitLab 및 NGINX 시작 {#start-gitlab-and-nginx}

GitLab 및 NGINX를 시작하려면:

```shell
# For systems running systemd
sudo systemctl start gitlab.target
sudo systemctl restart nginx.service

# For systems running SysV init
sudo service gitlab start
sudo service nginx restart
```

#### GitLab 상태 확인 {#check-gitlab-status}

GitLab의 상태를 확인하려면:

1. GitLab 및 해당 환경이 올바르게 구성되었는지 확인합니다:

   ```shell
   cd /home/git/gitlab
   sudo -u git -H bundle exec rake gitlab:env:info RAILS_ENV=production
   ```

1. 놓친 항목이 없는지 확인하려면 더 철저한 확인을 실행합니다:

   ```shell
   cd /home/git/gitlab

   sudo -u git -H bundle exec rake gitlab:check RAILS_ENV=production
   ```

모든 항목이 녹색이면 축하합니다. 업그레이드가 완료되었습니다!

## 문제 해결 {#troubleshooting}

업그레이드 중에 문제가 발생하면 다음 섹션의 일부 단계를 시도하세요.

### 코드를 이전 버전으로 되돌리기 {#revert-the-code-to-the-previous-version}

이전 버전으로 되돌리려면 이전 버전의 업그레이드 가이드를 따라야 합니다.

예를 들어 GitLab 19.2로 업그레이드했다가 19.1로 되돌리려고 하는 경우 19.0에서 19.1로 업그레이드하는 가이드를 따릅니다.

되돌릴 때:

- 백업이 이미 이전 버전으로 마이그레이션되었으므로 데이터베이스 마이그레이션 가이드를 따르지 않아야 합니다.
- 데이터베이스 마이그레이션을 실행한 경우 다운그레이드 후 백업을 복원해야 합니다. 코드의 버전은 사용 중인 스키마의 버전과 호환되어야 합니다. 이전 스키마는 백업에 있습니다.

### 백업에서 복원 {#restore-from-a-backup}

백업에서 복원하려면:

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake gitlab:backup:restore RAILS_ENV=production
```

백업 `*.tar` 파일이 두 개 이상인 경우 이전 코드 블록에 `BACKUP=timestamp_of_backup`를 추가합니다.
