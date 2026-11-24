---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 자체 컴파일된 CE 인스턴스를 EE로 변환
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

기존의 자체 컴파일된 인스턴스를 Community Edition(CE)에서 Enterprise Edition(EE)으로 변환할 수 있습니다.

다음 지침은 GitLab CE가 올바르게 구성되고 테스트된 자체 컴파일 설치가 있다고 가정합니다.

## CE에서 EE로 변환 {#convert-from-ce-to-ee}

다음 지침에서 다음을 바꿉니다:

- `EE_BRANCH`을(를) 사용 중인 버전의 EE 브랜치로 바꿉니다. EE 브랜치 이름은 `major-minor-stable-ee` 형식을 사용합니다. 예를 들어, `17-7-stable-ee`입니다.
- `CE_BRANCH`을(를) Community Edition 브랜치로 바꿉니다. CE 브랜치 이름은 `major-minor-stable` 형식을 사용합니다. 예를 들어, `17-7-stable`입니다.

### 백업 {#backup}

GitLab을 백업하려면:

```shell
cd /home/git/gitlab
sudo -u git -H bundle exec rake gitlab:backup:create RAILS_ENV=production
```

### GitLab 서버 중지 {#stop-gitlab-server}

GitLab 서버를 중지하려면:

```shell
sudo service gitlab stop
```

### EE 코드 가져오기 {#get-the-ee-code}

EE 코드를 가져오려면:

```shell
cd /home/git/gitlab
sudo -u git -H git remote add -f ee https://gitlab.com/gitlab-org/gitlab.git
sudo -u git -H git checkout EE_BRANCH
```

### 라이브러리 설치 및 마이그레이션 실행 {#install-libraries-and-run-migrations}

라이브러리를 설치하고 마이그레이션을 실행하려면:

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

# Update node dependencies and recompile assets
sudo -u git -H bundle exec rake yarn:install gitlab:assets:clean gitlab:assets:compile RAILS_ENV=production NODE_ENV=production NODE_OPTIONS="--max_old_space_size=4096"

# Clean up cache
sudo -u git -H bundle exec rake cache:clear RAILS_ENV=production
```

### `gitlab-elasticsearch-indexer` 설치 {#install-gitlab-elasticsearch-indexer}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

`gitlab-elasticsearch-indexer`을(를) 설치하려면 [설치 지침](../../integration/advanced_search/elasticsearch.md#install-an-elasticsearch-or-aws-opensearch-cluster)을 따릅니다.

### 애플리케이션 시작 {#start-the-application}

애플리케이션을 시작하려면:

```shell
sudo service gitlab start
sudo service nginx restart
```

### 애플리케이션 상태 확인 {#check-application-status}

GitLab과 그 환경이 올바르게 구성되었는지 확인합니다:

```shell
sudo -u git -H bundle exec rake gitlab:env:info RAILS_ENV=production
```

놓친 것이 없는지 확인하려면 더 철저한 확인을 실행합니다:

```shell
sudo -u git -H bundle exec rake gitlab:check RAILS_ENV=production
```

모든 항목이 녹색이면 업그레이드가 완료되었습니다!

## CE로 되돌리기 {#revert-back-to-ce}

EE로 변환하는 과정에서 문제가 발생하여 CE로 되돌리려면:

1. 코드를 이전 버전으로 되돌립니다:

   ```shell
   cd /home/git/gitlab
   sudo -u git -H git checkout CE_BRANCH
   ```

1. 백업에서 복원합니다:

   ```shell
   cd /home/git/gitlab
   sudo -u git -H bundle exec rake gitlab:backup:restore RAILS_ENV=production
   ```

EE 인스턴스를 CE로 되돌리는 방법에 대한 자세한 내용은 [EE에서 CE로 되돌리는 방법](revert.md)을 참조합니다.
