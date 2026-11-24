---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Linux 패키지 인스턴스 업그레이드 문제 해결
description: Linux 패키지 인스턴스 업그레이드 시 발생하는 문제에 대한 해결책입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

문제 해결에 도움이 되도록 다음 명령을 실행합니다.

```shell
sudo gitlab-ctl status
sudo gitlab-rake gitlab:check SANITIZE=true
```

다음에 대한 자세한 정보:

- 유지 보수를 위해 `gitlab-ctl`을 사용하는 방법은 [유지 보수 명령](https://docs.gitlab.com/omnibus/maintenance/)을 참조하세요.
- 구성 확인을 위해 `gitlab-rake`을 사용하는 방법은 [GitLab 구성 확인](../../administration/raketasks/maintenance.md#check-gitlab-configuration)을 참조하세요.

## 운영 체제 업그레이드 후 새 버전을 찾을 수 없음 {#no-new-version-found-after-upgrading-operating-system}

GitLab을 업그레이드하기 전에 운영 체제 업그레이드가 필요한 경우가 있습니다. 운영 체제를 업그레이드할 때 운영 체제의 패키지 관리자 구성에서 GitLab 패키지 소스 URL을 업데이트해야 할 수도 있습니다.

패키지 관리자에서 사용 가능한 업그레이드를 찾을 수 없지만 업그레이드가 있어야 하는 경우 GitLab 패키지 리포지토리를 다시 추가합니다. 자세한 정보는 [Linux 패키지를 사용하여 GitLab 설치](../../install/package/_index.md)에 대한 정보를 참조하세요.

향후 GitLab 업그레이드는 업그레이드된 운영 체제에 따라 가져옵니다.

## `PG::UndefinedColumn: ERROR:..` 메시지가 포함된 500 오류 {#500-errors-with-pgundefinedcolumn-error-message-in-logs}

업그레이드 후 `500` 오류가 표시되고 `PG::UndefinedColumn: ERROR:...`과 유사한 메시지가 로그에 표시되면 이러한 오류는 다음 중 하나로 인해 발생할 수 있습니다:

- [데이터베이스 마이그레이션](../background_migrations.md)이 완료되지 않았습니다. 마이그레이션이 완료될 때까지 기다립니다.
- 데이터베이스 마이그레이션은 완료되었지만 GitLab에서 새 스키마를 로드해야 합니다. 새 스키마를 로드하려면 [GitLab 재시작](../../administration/restart_gitlab.md)을 수행합니다.

## 오류: 내부 GitLab API에 연결할 수 없음 {#error-failed-to-connect-to-the-internal-gitlab-api}

별도의 GitLab Pages 서버에서 `Failed to connect to the internal GitLab API` 오류가 발생하면 [GitLab Pages 관리 문제 해결](../../administration/pages/troubleshooting.md#failed-to-connect-to-the-internal-gitlab-api)을 참조하세요.

## 서명 확인 중 오류 발생 {#an-error-occurred-during-the-signature-verification}

`apt-get update`을 실행할 때 이 오류가 발생하면:

```plaintext
An error occurred during the signature verification
```

다음 명령을 사용하여 GitLab 패키지 서버의 GPG 키를 업데이트합니다:

```shell
[ -x /usr/bin/apt-key ] &&
    [ -s /etc/apt/trusted.gpg ] &&
    apt-key --keyring /etc/apt/trusted.gpg del packages@gitlab.com
curl --fail --silent --show-error \
     --output /etc/apt/trusted.gpg.d/gitlab.asc \
     --url "https://packages.gitlab.com/gpg.key"
apt-get update
```

## 오류: `Command timed out after 3600s` {#error-command-timed-out-after-3600s}

데이터베이스 스키마 및 데이터 변경(데이터베이스 마이그레이션)을 실행하는 데 1시간 이상이 소요되면 업그레이드가 `timed out` 오류로 실패합니다:

```plaintext
FATAL: Mixlib::ShellOut::CommandTimeout: rails_migration[gitlab-rails] (gitlab::database_migrations line 51)
had an error: Mixlib::ShellOut::CommandTimeout: bash[migrate gitlab-rails database]
(/opt/gitlab/embedded/cookbooks/cache/cookbooks/gitlab/resources/rails_migration.rb line 16)
had an error: Mixlib::ShellOut::CommandTimeout: Command timed out after 3600s:
```

이 오류를 수정하려면:

1. 나머지 데이터베이스 마이그레이션을 실행합니다:

   ```shell
   sudo gitlab-rake db:migrate
   ```

   이 명령을 완료하는 데 시간이 매우 오래 걸릴 수 있습니다. `screen`을 사용하거나 다른 메커니즘을 사용하여 SSH 세션이 끊어지면 프로그램이 중단되지 않도록 합니다.

1. 업그레이드를 완료합니다:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

1. `puma`과 `sidekiq` 서비스를 재로드합니다:

   ```shell
   sudo gitlab-ctl hup puma
   sudo gitlab-ctl restart sidekiq
   ```

## 누락된 자산 파일 {#missing-asset-files}

업그레이드 후 GitLab에서 다음과 같은 자산을 올바르게 제공하지 못할 수 있습니다:

- 이미지
- JavaScript
- 스타일시트

GitLab에서 500 오류를 생성하거나 웹 UI가 올바르게 렌더링되지 않을 수 있습니다.

확대된 GitLab 환경에서 로드 밸런서 뒤의 웹 서버 중 하나가 이 문제를 나타내면 문제가 간헐적으로 발생합니다.

[다시 컴파일하는 Rake 작업](../../administration/raketasks/maintenance.md#precompile-the-assets)은 사전 컴파일된 자산을 `/opt/gitlab/embedded/service/gitlab-rails/public/assets`에서 제공하는 Linux 패키지 설치에 적용되지 않습니다.

다음 섹션에서 가능한 원인 및 해결책을 설명합니다.

### 오래된 프로세스 {#old-processes}

오래된 프로세스의 가장 가능성 있는 원인은 오래된 Puma 프로세스가 실행 중이라는 것입니다. 오래된 Puma 프로세스는 클라이언트에서 GitLab의 이전 릴리스의 자산 파일을 요청하도록 지시할 수 있습니다. 파일이 더 이상 존재하지 않으므로 HTTP 404 오류가 반환됩니다.

재부팅이 이러한 오래된 Puma 프로세스가 더 이상 실행되지 않도록 하는 가장 좋은 방법입니다. 또는 다음을 수행할 수 있습니다:

1. Puma를 중지합니다:

   ```shell
   gitlab-ctl stop puma
   ```

1. 남은 Puma 프로세스를 확인하고 중단합니다:

   ```shell
   ps -ef | egrep 'puma[: ]'
   kill <processid>
   ```

1. `ps`을 사용하여 Puma 프로세스가 중지되었는지 확인합니다.
1. Puma를 시작합니다.

   ```shell
   gitlab-ctl start puma
   ```

### 중복된 sprockets 파일 {#duplicate-sprockets-files}

컴파일된 자산 파일은 각 릴리스에서 고유한 파일 이름을 가집니다. sprockets 파일은 애플리케이션 코드의 파일 이름을 고유한 파일 이름에 매핑합니다.

```plaintext
/opt/gitlab/embedded/service/gitlab-rails/public/assets/.sprockets-manifest*.json
```

sprockets 파일이 하나만 있는지 확인합니다. [Rails에서 첫 번째 파일을 사용합니다](https://github.com/rails/sprockets-rails/blob/118ce60b1ffeb7a85640661b014cd2ee3c4e3e56/lib/sprockets/railtie.rb#L201).

Linux 패키지 업그레이드 중에 중복된 sprockets 파일 확인이 실행됩니다:

```plaintext
GitLab discovered stale file(s) from the previous install that need to be cleaned up.
The following files need to be removed:

/opt/gitlab/embedded/service/gitlab-rails/public/assets/.sprockets-manifest-e16fdb7dd73cfdd64ed9c2cc0e35718a.json
```

이 문제를 해결하는 옵션은 다음과 같습니다:

- 패키지 업그레이드의 출력이 있으면 지정된 파일을 제거합니다. 그런 다음 Puma를 재시작합니다:

  ```shell
  gitlab-ctl restart puma
  ```

- 메시지가 없으면 재설치를 수행하여 다시 생성합니다. 자세한 정보는 [불완전한 설치](#incomplete-installation)를 참조하세요.
- 모든 sprockets 파일을 제거한 다음 [불완전한 설치](#incomplete-installation)에 대한 지침을 따릅니다.

### 불완전한 설치 {#incomplete-installation}

불완전한 설치는 누락된 자산 파일 문제의 원인이 될 수 있습니다.

패키지를 확인하여 이것이 문제인지 확인합니다:

- Debian 배포의 경우:

  ```shell
  apt-get install debsums
  debsums -c gitlab-ee
  ```

- Red Hat/SUSE (RPM) 배포의 경우:

  ```shell
  rpm -V gitlab-ee
  ```

불완전한 설치를 수정하기 위해 패키지를 재설치하려면:

1. 설치된 버전을 확인합니다:

   - Debian 배포의 경우:

     ```shell
     apt --installed list gitlab-ee
     ```

   - Red Hat/SUSE (RPM) 배포의 경우:

     ```shell
     rpm -qa gitlab-ee
     ```

1. 설치된 버전을 지정하여 패키지를 재설치합니다. 예를 들어 14.4.0 Enterprise Edition:

   - Debian 배포의 경우:

     ```shell
     apt-get install --reinstall gitlab-ee=14.4.0-ee.0
     ```

   - Red Hat/SUSE (RPM) 배포의 경우:

     ```shell
     yum reinstall gitlab-ee-14.4.0
     ```

### NGINX Gzip 지원 비활성화 {#nginx-gzip-support-disabled}

`nginx['gzip_enabled']`이 비활성화되었는지 확인합니다:

```shell
grep gzip /etc/gitlab/gitlab.rb
```

이렇게 하면 일부 자산이 제공되지 않을 수 있습니다. [자세히 알아보기](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/6087#note_558194395)는 관련 이슈 중 하나를 참조하세요.

## ActiveRecord::LockWaitTimeout 오류, 절전 후 재시도 {#activerecordlockwaittimeout-error-retrying-after-sleep}

드문 경우이지만 Sidekiq이 바쁘고 마이그레이션이 변경하려는 테이블을 잠급니다. 이 이슈를 해결하려면:

1. GitLab을 읽기 전용 모드로 설정합니다.
1. Sidekiq을 중지합니다:

   ```shell
   gitlab-ctl stop sidekiq
   ```

## GPG 서명 확인 오류: 잘못된 GPG 서명 {#gpg-signature-verification-error-bad-gpg-signature}

`yum update`을 실행하거나 `dnf update`을 실행할 때 다음 오류가 나타날 수 있습니다:

```plaintext
Error: Failed to download metadata for repo 'gitlab_gitlab-ee-source': repomd.xml GPG signature verification error: Bad GPG signature
```

이 이슈를 해결하려면:

1. `dnf clean all`를 실행합니다.
1. [최신 서명 키를 가져옵니다](https://docs.gitlab.com/omnibus/update/package_signatures/?tab=CentOS%2FOpenSUSE%2FSLES#fetch-latest-signing-key).
1. 다시 업그레이드를 시도합니다.

`dnf clean all` 후에도 오류가 계속되면 영향을 받는 리포지토리 캐시 디렉터리를 수동으로 제거합니다. 이 예에서:

1. `/var/cache/dnf/gitlab_gitlab-ee-source`을 제거합니다.
1. `dnf makecache`를 실행합니다.
