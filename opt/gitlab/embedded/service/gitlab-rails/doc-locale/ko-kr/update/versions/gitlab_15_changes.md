---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 15 업그레이드 노트
---

<!-- vale gitlab_base.OutdatedVersions = NO-->

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

이 페이지에는 GitLab 15의 마이너 버전 및 패치 버전 업그레이드 정보가 포함되어 있습니다. 다음 사항을 검토했는지 확인하세요:

- 설치 유형.
- 현재 버전과 목표 버전 사이의 모든 버전.

Helm 차트 설치에 대한 추가 정보는 [Helm 차트 업그레이드 노트](https://docs.gitlab.com/charts/releases/)를 참조하세요.

## 15.11.1 {#15111}

- 많은 [그룹 및 프로젝트 가져오기](../../user/import/_index.md)에서 개발자 역할만 필요로 하는 대신 유지관리자 역할이 필요합니다. 자세한 내용은 사용하는 가져오기의 설명서를 참조하세요.

## 15.11.0 {#15110}

- 패치 릴리스 15.11.3 이상으로 업그레이드합니다. 이는 15.5.0 이전 버전에서 업그레이드할 때 [이슈 408304](https://gitlab.com/gitlab-org/gitlab/-/issues/408304)를 피합니다.
- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Linux 패키지 설치 {#linux-package-installations}

GitLab 15.11에서는 다음의 경우를 제외하고 PostgreSQL이 자동으로 13.x로 업그레이드됩니다:

- Patroni를 사용하여 고가용성 데이터베이스를 실행 중입니다.
- 데이터베이스 노드가 GitLab Geo 구성의 일부입니다.
- 명시적으로 [PostgreSQL 자동 업그레이드를 거부](https://docs.gitlab.com/omnibus/settings/database/#opt-out-of-automatic-postgresql-upgrades)했습니다.
- `postgresql['version'] = 12`이 `/etc/gitlab/gitlab.rb`에 있습니다.

장애 허용 및 Geo 설치는 PostgreSQL 13에 대한 수동 업그레이드를 지원합니다. [HA/Geo 클러스터에 배포된 패키지 PostgreSQL](https://docs.gitlab.com/omnibus/settings/database/#packaged-postgresql-deployed-in-an-hageo-cluster)을 참조하세요.

### Geo 설치 {#geo-installations}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- 일부 프로젝트 가져오기에서는 프로젝트 생성 시 wiki 리포지토리를 초기화하지 않습니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#wiki-repositories-not-initialized-on-project-creation)을 참조하세요.
- `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못합니다. [세부 정보 및 해결 방법](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13)을 참조하세요.

#### `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못함 {#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13}

| 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
|-------------------------|-------------------------|----------|
| 15.2 - 15.10            | 모두                     | 없음     |
| 15.11                   | 15.11.0 - 15.11.11      | 15.11.12 이상 |

기본 제공 `pg-upgrade` 도구의 [버그](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7841)로 인해 번들로 제공되는 PostgreSQL 데이터베이스를 버전 13으로 업그레이드할 수 없습니다. 이로 인해 보조 사이트가 손상된 상태가 되고 Geo 설치를 GitLab 16.x로 업그레이드할 수 없습니다([PostgreSQL 12 지원이 16.0에서 제거됨](../deprecations.md#postgresql-12-deprecated) 및 이후 릴리스). 이는 번들로 제공되는 PostgreSQL 소프트웨어를 사용하는 보조 사이트에서 동일한 노드에서 보조 메인 Rails 데이터베이스 및 추적 데이터베이스를 실행할 때 발생합니다. 15.11.12 이상으로 업그레이드할 수 없는 경우 수동 [해결 방법](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7841#workaround)이 있습니다.

## 15.11.x {#1511x}

- [버그](https://gitlab.com/gitlab-org/gitlab/-/issues/411604)로 인해 처음 로그인하는 새 LDAP 사용자에게 LDAP 사용자 이름 특성 대신 이메일 주소를 기반으로 사용자 이름을 할당할 수 있습니다. 수동 해결 방법은 `gitlab_rails['omniauth_auto_link_ldap_user'] = true`를 설정하거나 버그가 수정된 GitLab 16.1 이상으로 업그레이드하는 것입니다.

## 15.10.5 {#15105}

- [Elastic Indexer Cron Workers의 버그](https://gitlab.com/gitlab-org/gitlab/-/issues/408214)로 인해 Sidekiq에서 포화 상태가 발생할 수 있습니다.
  - 이 문제가 발생하면 병합 리퀘스트 병합, 파이프라인, Slack 알림 및 기타 이벤트가 생성되지 않거나 생성되는 데 오랜 시간이 걸립니다.
  - 이 문제는 Sidekiq이 충분히 포화될 때까지 최대 1주일이 걸릴 수 있으므로 즉시 나타나지 않을 수 있습니다.
  - Elasticsearch을 활성화할 필요가 없어도 이 문제가 발생할 수 있습니다.
  - 이 문제를 해결하려면 15.11로 업그레이드하거나 문제의 해결 방법을 사용하세요.
- 많은 [그룹 및 프로젝트 가져오기](../../user/import/_index.md)에서 개발자 역할만 필요로 하는 대신 유지관리자 역할이 필요합니다. 자세한 내용은 사용하는 가져오기의 설명서를 참조하세요.

## 15.10.0 {#15100}

- [Elastic Indexer Cron Workers의 버그](https://gitlab.com/gitlab-org/gitlab/-/issues/408214)로 인해 Sidekiq에서 포화 상태가 발생할 수 있습니다.
  - 이 문제가 발생하면 병합 리퀘스트 병합, 파이프라인, Slack 알림 및 기타 이벤트가 생성되지 않거나 생성되는 데 오랜 시간이 걸립니다.
  - 이 문제는 Sidekiq이 충분히 포화될 때까지 최대 1주일이 걸릴 수 있으므로 즉시 나타나지 않을 수 있습니다.
  - Elasticsearch을 활성화할 필요가 없어도 이 문제가 발생할 수 있습니다.
  - 이 문제를 해결하려면 15.11로 업그레이드하거나 문제의 해결 방법을 사용하세요.
- [무중단 재인덱싱 버그](https://gitlab.com/gitlab-org/gitlab/-/issues/422938)로 인해 재인덱싱할 때 `Couldn't load task status` 오류가 발생할 수 있습니다. Elasticsearch 호스트에서 `sliceId must be greater than 0 but was [-1]` 오류가 발생할 수도 있습니다. 해결 방법으로, [처음부터 재인덱싱](../../integration/elasticsearch/troubleshooting/indexing.md#last-resort-to-recreate-an-index)하거나 GitLab 16.3으로 업그레이드하는 것을 고려하세요.
- GitLab 16.0에서 Linux 패키지 인스턴스의 Gitaly 구성이 크게 변경됩니다. GitLab 16.0으로 향하는 동안 하위 호환성이 유지되는 동안 GitLab 15.10에서 새로운 구조로 마이그레이션을 시작할 수 있습니다. [이 변경 사항에 대해 자세히 읽기](gitlab_16_changes.md#gitaly-configuration-structure-change).
- GitLab 15.10 이상으로 업그레이드하는 동안 다음 오류가 발생할 수 있습니다:

  ```shell
  STDOUT: rake aborted!
  StandardError: An error has occurred, all later migrations canceled:
  PG::CheckViolation: ERROR:  check constraint "check_70f294ef54" is violated by some row
  ```

  이 오류는 GitLab 15.10 이전에 완료되지 않은 [GitLab 15.8에 도입된 배치 백그라운드 마이그레이션](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/107701)으로 인해 발생합니다. 이 오류를 해결하려면:

  1. 데이터베이스 콘솔(`sudo gitlab-psql`, Linux 패키지 설치의 경우)을 사용하여 다음 SQL 문을 실행합니다:

     ```sql
     UPDATE oauth_access_tokens SET expires_in = '7200' WHERE expires_in IS NULL;
     ```

  1. [데이터베이스 마이그레이션 다시 실행](../../administration/raketasks/maintenance.md#run-incomplete-database-migrations).
- GitLab 15.10 이상으로 업그레이드하는 동안 다음 오류가 발생할 수도 있습니다:

  ```shell
  "exception.class": "ActiveRecord::StatementInvalid",
  "exception.message": "PG::SyntaxError: ERROR:  zero-length delimited identifier at or near \"\"\"\"\nLINE 1: ...COALESCE(\"lock_version\", 0) + 1 WHERE \"ci_builds\".\"\" IN (SEL...\n
  ```

  이 오류는 GitLab 15.10 이상으로 업그레이드하기 이전에 완료되지 않은 [GitLab 14.9에 도입된 배치 백그라운드 마이그레이션](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/81410)으로 인해 발생합니다. 이 오류를 해결하려면 [마이그레이션을 완료로 표시](../background_migrations.md#mark-a-failed-migration-finished)하는 것이 안전합니다:

  ```ruby
  # Start the rails console

  connection = Ci::ApplicationRecord.connection

  Gitlab::Database::SharedModel.using_connection(connection) do
    migration = Gitlab::Database::BackgroundMigration::BatchedMigration.find_for_configuration(
      Gitlab::Database.gitlab_schemas_for_connection(connection), 'NullifyOrphanRunnerIdOnCiBuilds', :ci_builds, :id, [])

    # mark all jobs completed
    migration.batched_jobs.update_all(status: Gitlab::Database::BackgroundMigration::BatchedJob.state_machine.states[:succeeded].value)
    migration.update_attribute(:status, Gitlab::Database::BackgroundMigration::BatchedMigration.state_machine.states[:finished].value)
  end
  ```

  자세한 내용은 [이슈 415724](https://gitlab.com/gitlab-org/gitlab/-/issues/415724)를 참조하세요.

- [Terraform 구성 버그](https://gitlab.com/gitlab-org/gitlab/-/issues/348453)로 인해 `gitlab_rails['terraform_state_enabled']`가 `gitlab.rb` 구성 파일에서 `false`로 설정되었을 때에도 Terraform 상태가 활성화된 상태로 남아있었습니다. 이 버그가 GitLab 15.10에서 수정되었으므로, GitLab 15.10으로 업그레이드하면 `gitlab.rb` 구성에서 비활성화된 경우 [Terraform 상태](../../administration/terraform_state.md) 기능을 사용하는 프로젝트가 손상될 수 있습니다. `gitlab_rails['terraform_state_enabled'] = false`을 `gitlab.rb`에 구성한 경우 Terraform 상태 기능을 사용 중인 프로젝트가 있는지 확인하세요. 확인하려면:
  1. [Rails 콘솔](../../administration/operations/rails_console.md) 경고를 읽습니다.
  1. [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)을 시작합니다.
  1. `Terraform::State.pluck(:project_id)` 명령을 실행합니다. 이 명령은 Terraform 상태가 있는 모든 프로젝트 ID의 배열을 반환합니다.
  1. 각 프로젝트로 이동하여 필요에 따라 이해관계자와 협력하여 Terraform 상태 기능이 적극적으로 사용되는지 결정합니다. 더 이상 Terraform 상태가 필요하지 않은 경우 [상태 파일 제거](../../user/infrastructure/iac/terraform_state.md#remove-a-state-file) 단계를 따를 수 있습니다.

### Geo 설치 {#geo-installations-1}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못합니다. [세부 정보 및 해결 방법](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13)을 참조하세요.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

## 15.9.0 {#1590}

- [Elastic Indexer Cron Workers의 버그](https://gitlab.com/gitlab-org/gitlab/-/issues/408214)로 인해 Sidekiq에서 포화 상태가 발생할 수 있습니다.
  - 이 문제가 발생하면 병합 리퀘스트 병합, 파이프라인, Slack 알림 및 기타 이벤트가 생성되지 않거나 생성되는 데 오랜 시간이 걸립니다.
  - 이 문제는 Sidekiq이 충분히 포화될 때까지 최대 1주일이 걸릴 수 있으므로 즉시 나타나지 않을 수 있습니다.
  - Elasticsearch을 활성화할 필요가 없어도 이 문제가 발생할 수 있습니다.
  - 이 문제를 해결하려면 15.11로 업그레이드하거나 문제의 해결 방법을 사용하세요.
- [`BackfillTraversalIdsToBlobsAndWikiBlobs` 고급 검색 마이그레이션의 버그](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/107730)로 인해 Elasticsearch 클러스터가 포화될 수 있습니다.
  - 이 문제가 발생하면 검색이 느려지고 Elasticsearch 클러스터에 대한 업데이트가 완료되는 데 오랜 시간이 걸릴 수 있습니다.
  - 이 문제를 해결하려면 GitLab 15.10으로 업그레이드하여 [마이그레이션 배치 크기 축소](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/113719)합니다.
- 패치 릴리스 15.9.3 이상으로 업그레이드합니다. 이는 두 가지 데이터베이스 마이그레이션 버그에 대한 수정 사항을 제공합니다:
  - 패치 릴리스 15.9.0, 15.9.1, 15.9.2는 사용자 프로필 필드 `linkedin`, `twitter`, `skype`, `website_url`, `location` 및 `organization`에서 데이터 손실을 야기할 수 있는 버그가 있습니다. 자세한 내용은 [이슈 393216](https://gitlab.com/gitlab-org/gitlab/-/issues/393216)을 참조하세요.
  - 두 번째 [버그 수정](https://gitlab.com/gitlab-org/gitlab/-/issues/394760)은 15.4.x에서 직접 업그레이드할 수 있도록 합니다.
- [CI 파티셔닝 노력](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/ci_data_decay/pipeline_partitioning/)의 일부로, `ci_builds_needs`에 [새 외래 키](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/107547)가 추가되었습니다. 큰 CI 테이블이 있는 GitLab 인스턴스에서는 이 제약 조건을 추가하는 데 평소보다 오래 걸릴 수 있습니다.
- Praefect의 메타데이터 검증 도구 [잘못된 메타데이터 삭제 동작](../../administration/gitaly/praefect/configure.md#enable-deletions)이 이제 기본적으로 활성화됩니다.

  메타데이터 검증 도구는 Praefect 데이터베이스의 복제본 레코드를 처리하고 복제본이 실제로 Gitaly 노드에 존재하는지 확인합니다. 복제본이 존재하지 않으면 해당 메타데이터 레코드가 삭제됩니다. 이를 통해 Praefect는 복제본이 메타데이터 레코드로는 정상이지만 실제로는 디스크에 존재하지 않는 상황을 수정할 수 있습니다. 메타데이터 레코드가 삭제된 후 Praefect의 조정자는 복제본을 다시 생성하기 위해 복제 작업을 예약합니다.

  과거 상태 관리 논리의 문제로 인해 데이터베이스에 유효하지 않은 메타데이터 레코드가 있을 수 있습니다. 이는 예를 들어 리포지토리의 불완전한 삭제 또는 부분적으로 완료된 이름 바꾸기로 인해 존재할 수 있습니다. 검증 도구는 영향을 받는 리포지토리의 이러한 오래된 복제본 레코드를 삭제합니다. 이러한 리포지토리는 복제본 레코드가 제거되어 메트릭 및 `praefect dataloss` 하위 명령에서 사용할 수 없는 리포지토리로 나타날 수 있습니다. 이러한 리포지토리가 발생하면 `praefect remove-repository`를 사용하여 리포지토리를 제거하여 리포지토리의 나머지 레코드를 제거합니다.

  GitLab 15.0 이상에서 검증 도구에서 출력한 로그 레코드를 검색하여 유효하지 않은 메타데이터 레코드가 있는 리포지토리를 찾을 수 있습니다. [리포지토리 검증에 대해 자세히 읽고 예제 로그 항목 확인](../../administration/gitaly/praefect/configure.md#repository-verification).
- GitLab 16.0에서 Linux 패키지 인스턴스의 Praefect 구성이 크게 변경됩니다. GitLab 16.0으로 향하는 동안 하위 호환성이 유지되는 동안 GitLab 15.9에서 새로운 구조로 마이그레이션을 시작할 수 있습니다. [이 변경 사항에 대해 자세히 읽기](gitlab_16_changes.md#praefect-configuration-structure-change).

### 소스에서 컴파일한 설치 {#self-compiled-installations}

- **자체 컴파일된(소스) 설치**의 경우 `gitlab-sshd`의 추가로 인해 Kerberos 헤더가 GitLab Shell을 빌드하는 데 필요합니다.

  ```shell
  sudo apt install libkrb5-dev
  ```

### Geo 설치 {#geo-installations-2}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못합니다. [세부 정보 및 해결 방법](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13)을 참조하세요.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

## 15.8.2 {#1582}

### Geo 설치 {#geo-installations-3}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.8.1 {#1581}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-4}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.8.0 {#1580}

- Gitaly에는 Git 2.38.0 이상이 필요합니다. 자체 컴파일된 설치의 경우 [Gitaly에서 제공하는 Git 버전](../../install/self_compiled/_index.md#git)을 사용해야 합니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-5}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못합니다. [세부 정보 및 해결 방법](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13)을 참조하세요.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

## 15.7.6 {#1576}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-6}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.7.5 {#1575}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-7}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.7.4 {#1574}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-8}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.7.3 {#1573}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-9}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.7.2 {#1572}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-10}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- [컨테이너 레지스트리 푸시 이벤트가 거부됨](https://gitlab.com/gitlab-org/gitlab/-/issues/386389)으로 인해 `/api/v4/container_registry_event/events` 엔드포인트에서 Geo 보조 사이트가 컨테이너 레지스트리 이미지의 업데이트를 인식하지 못하고 결과적으로 업그레이드를 복제하지 않습니다. 결과적으로 보조 사이트에는 장애 조치 후 오래된 컨테이너 이미지가 포함될 수 있습니다. 이는 버전 15.6.0 - 15.6.6 및 15.7.0 - 15.7.2에 영향을 미칩니다. Geo를 컨테이너 리포지토리와 함께 사용 중인 경우 이 문제에 대한 수정 사항을 포함하는 GitLab 15.6.7, 15.7.3 또는 15.8.0으로 업그레이드하고 장애 조치 후 잠재적 데이터 손실을 피하는 것을 권장합니다.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.7.1 {#1571}

- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-11}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- [컨테이너 레지스트리 푸시 이벤트가 거부됨](https://gitlab.com/gitlab-org/gitlab/-/issues/386389)으로 인해 `/api/v4/container_registry_event/events` 엔드포인트에서 Geo 보조 사이트가 컨테이너 레지스트리 이미지의 업데이트를 인식하지 못하고 결과적으로 업데이트를 복제하지 않습니다. 결과적으로 보조 사이트에는 장애 조치 후 오래된 컨테이너 이미지가 포함될 수 있습니다. 이는 버전 15.6.0 - 15.6.6 및 15.7.0 - 15.7.2에 영향을 미칩니다. Geo를 컨테이너 리포지토리와 함께 사용 중인 경우 이 문제에 대한 수정 사항을 포함하는 GitLab 15.6.7, 15.7.3 또는 15.8.0으로 업그레이드하고 장애 조치 후 잠재적 데이터 손실을 피하는 것을 권장합니다.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.7.0 {#1570}

- 이 버전은 `issues.work_item_type_id` 열에서 `NOT NULL DB` 제약 조건을 검증합니다. 이 버전으로 업그레이드하려면 `issues` 테이블에 `NULL` `work_item_type_id`이 있는 레코드가 없어야 합니다. `EnsureWorkItemTypeBackfillMigrationFinished` 배포 후 마이그레이션으로 완료될 여러 `BackfillWorkItemTypeIdForIssues` 백그라운드 마이그레이션이 있습니다.
- GitLab 15.4.0은 [배치 백그라운드 마이그레이션](../background_migrations.md#check-for-pending-database-background-migrations)을 도입하여 [문제 테이블의 `namespace_id` 값 채우기](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/91921)합니다. 이 마이그레이션은 더 큰 GitLab 인스턴스에서 완료하는 데 여러 시간 또는 일이 걸릴 수 있습니다. 15.7.0으로 업그레이드하기 전에 마이그레이션이 성공적으로 완료되었는지 확인하세요.
- 데이터베이스 제약 조건이 추가되어 문제 테이블의 `namespace_id` 열에 `NULL` 값이 없음을 지정합니다.

  - 15.4의 `namespace_id` 배치 백그라운드 마이그레이션이 실패한 경우(이전 항목 참조) 15.7 업그레이드는 데이터베이스 마이그레이션 오류로 실패합니다.

  - 큰 문제 테이블이 있는 GitLab 인스턴스에서 이 제약 조건을 검증하면 업그레이드가 평소보다 오래 걸립니다. 모든 데이터베이스 변경은 1시간 제한 내에 완료되어야 합니다:

    ```plaintext
    FATAL: Mixlib::ShellOut::CommandTimeout: rails_migration[gitlab-rails]
    [..]
    Mixlib::ShellOut::CommandTimeout: Command timed out after 3600s:
    ```

    데이터 변경 및 업그레이드를 수동으로 [완료](../package/package_troubleshooting.md#error-command-timed-out-after-3600s)할 수 있는 해결 방법이 있습니다.
- 기본 Sidekiq `max_concurrency`은 20으로 변경되었습니다. 이제 설명서 및 제품 기본값에서 일관됩니다.

  예를 들어, 이전에는:

  - Linux 패키지 설치 기본값(`sidekiq['max_concurrency']`): 50
  - 자체 컴파일된 설치 기본값: 50
  - Helm 차트 기본값(`gitlab.sidekiq.concurrency`): 25

  참조 아키텍처는 이러한 구성에서 특별히 설정되므로 여전히 기본값 10을 사용합니다.

  `max_concurrency`을 구성한 사이트는 이 변경의 영향을 받지 않습니다. [Sidekiq 동시성 설정에 대해 자세히 읽기](../../administration/sidekiq/extra_sidekiq_processes.md#concurrency).
- GitLab Runner 15.7.0은 CI/CD 작업에 영향을 주는 주요 변경을 도입했습니다: [작업 파일 변수의 확장을 올바르게 처리](https://gitlab.com/gitlab-org/gitlab-runner/-/merge_requests/3613)합니다. 이전에는 [파일 유형 변수](../../ci/variables/_index.md#use-file-type-cicd-variables)를 참조하는 작업 정의 변수가 파일 변수(해당 내용)의 값으로 확장되었습니다. 이 동작은 셸 변수 확장의 일반적인 규칙을 따르지 않았습니다. 또한 파일 변수와 해당 내용이 인쇄되는 경우 비밀 또는 민감한 정보가 유출될 수 있는 가능성도 있었습니다. 예를 들어, 에코 출력에 인쇄되는 경우입니다. [GitLab 15.7의 파일 유형 변수 확장 변경 이해](https://about.gitlab.com/blog/impact-of-the-file-type-variable-change-15-7/)를 참조하세요.
- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

### Geo 설치 {#geo-installations-12}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못합니다. [세부 정보 및 해결 방법](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13)을 참조하세요.
- [컨테이너 레지스트리 푸시 이벤트가 거부됨](https://gitlab.com/gitlab-org/gitlab/-/issues/386389)으로 인해 `/api/v4/container_registry_event/events` 엔드포인트에서 Geo 보조 사이트가 컨테이너 레지스트리 이미지의 업데이트를 인식하지 못하고 결과적으로 업데이트를 복제하지 않습니다. 결과적으로 보조 사이트에는 장애 조치 후 오래된 컨테이너 이미지가 포함될 수 있습니다. 이는 버전 15.6.0 - 15.6.6 및 15.7.0 - 15.7.2에 영향을 미칩니다. Geo를 컨테이너 리포지토리와 함께 사용 중인 경우 이 문제에 대한 수정 사항을 포함하는 GitLab 15.6.7, 15.7.3 또는 15.8.0으로 업그레이드하고 장애 조치 후 잠재적 데이터 손실을 피하는 것을 권장합니다.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.6.7 {#1567}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-13}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.6.6 {#1566}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-14}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- [컨테이너 레지스트리 푸시 이벤트가 거부됨](https://gitlab.com/gitlab-org/gitlab/-/issues/386389)으로 인해 `/api/v4/container_registry_event/events` 엔드포인트에서 Geo 보조 사이트가 컨테이너 레지스트리 이미지의 업데이트를 인식하지 못하고 결과적으로 업데이트를 복제하지 않습니다. 결과적으로 보조 사이트에는 장애 조치 후 오래된 컨테이너 이미지가 포함될 수 있습니다. 이는 버전 15.6.0 - 15.6.6 및 15.7.0 - 15.7.2에 영향을 미칩니다. Geo를 컨테이너 리포지토리와 함께 사용 중인 경우 이 문제에 대한 수정 사항을 포함하는 GitLab 15.6.7, 15.7.3 또는 15.8.0으로 업그레이드하고 장애 조치 후 잠재적 데이터 손실을 피하는 것을 권장합니다.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.

## 15.6.5 {#1565}

### Geo 설치 {#geo-installations-15}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- [컨테이너 레지스트리 푸시 이벤트가 거부됨](https://gitlab.com/gitlab-org/gitlab/-/issues/386389)으로 인해 `/api/v4/container_registry_event/events` 엔드포인트에서 Geo 보조 사이트가 컨테이너 레지스트리 이미지의 업데이트를 인식하지 못하고 결과적으로 업데이트를 복제하지 않습니다. 결과적으로 보조 사이트에는 장애 조치 후 오래된 컨테이너 이미지가 포함될 수 있습니다. 이는 버전 15.6.0 - 15.6.6 및 15.7.0 - 15.7.2에 영향을 미칩니다. Geo를 컨테이너 리포지토리와 함께 사용 중인 경우 이 문제에 대한 수정 사항을 포함하는 GitLab 15.6.7, 15.7.3 또는 15.8.0으로 업그레이드하고 장애 조치 후 잠재적 데이터 손실을 피하는 것을 권장합니다.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.6.4 {#1564}

### Geo 설치 {#geo-installations-16}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- [컨테이너 레지스트리 푸시 이벤트가 거부됨](https://gitlab.com/gitlab-org/gitlab/-/issues/386389)으로 인해 `/api/v4/container_registry_event/events` 엔드포인트에서 Geo 보조 사이트가 컨테이너 레지스트리 이미지의 업데이트를 인식하지 못하고 결과적으로 업데이트를 복제하지 않습니다. 결과적으로 보조 사이트에는 장애 조치 후 오래된 컨테이너 이미지가 포함될 수 있습니다. 이는 버전 15.6.0 - 15.6.6 및 15.7.0 - 15.7.2에 영향을 미칩니다. Geo를 컨테이너 리포지토리와 함께 사용 중인 경우 이 문제에 대한 수정 사항을 포함하는 GitLab 15.6.7, 15.7.3 또는 15.8.0으로 업그레이드하고 장애 조치 후 잠재적 데이터 손실을 피하는 것을 권장합니다.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.6.3 {#1563}

### Geo 설치 {#geo-installations-17}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- [컨테이너 레지스트리 푸시 이벤트가 거부됨](https://gitlab.com/gitlab-org/gitlab/-/issues/386389)으로 인해 `/api/v4/container_registry_event/events` 엔드포인트에서 Geo 보조 사이트가 컨테이너 레지스트리 이미지의 업데이트를 인식하지 못하고 결과적으로 업데이트를 복제하지 않습니다. 결과적으로 보조 사이트에는 장애 조치 후 오래된 컨테이너 이미지가 포함될 수 있습니다. 이는 버전 15.6.0 - 15.6.6 및 15.7.0 - 15.7.2에 영향을 미칩니다. Geo를 컨테이너 리포지토리와 함께 사용 중인 경우 이 문제에 대한 수정 사항을 포함하는 GitLab 15.6.7, 15.7.3 또는 15.8.0으로 업그레이드하고 장애 조치 후 잠재적 데이터 손실을 피하는 것을 권장합니다.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.
- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.6.2 {#1562}

### Geo 설치 {#geo-installations-18}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- [컨테이너 레지스트리 푸시 이벤트가 거부됨](https://gitlab.com/gitlab-org/gitlab/-/issues/386389)으로 인해 `/api/v4/container_registry_event/events` 엔드포인트에서 Geo 보조 사이트가 컨테이너 레지스트리 이미지의 업데이트를 인식하지 못하고 결과적으로 업데이트를 복제하지 않습니다. 결과적으로 보조 사이트에는 장애 조치 후 오래된 컨테이너 이미지가 포함될 수 있습니다. 이는 버전 15.6.0 - 15.6.6 및 15.7.0 - 15.7.2에 영향을 미칩니다. Geo를 컨테이너 리포지토리와 함께 사용 중인 경우 이 문제에 대한 수정 사항을 포함하는 GitLab 15.6.7, 15.7.3 또는 15.8.0으로 업그레이드하고 장애 조치 후 잠재적 데이터 손실을 피하는 것을 권장합니다.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.
- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.6.1 {#1561}

### Geo 설치 {#geo-installations-19}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- [컨테이너 레지스트리 푸시 이벤트가 거부됨](https://gitlab.com/gitlab-org/gitlab/-/issues/386389)으로 인해 `/api/v4/container_registry_event/events` 엔드포인트에서 Geo 보조 사이트가 컨테이너 레지스트리 이미지의 업데이트를 인식하지 못하고 결과적으로 업데이트를 복제하지 않습니다. 결과적으로 보조 사이트에는 장애 조치 후 오래된 컨테이너 이미지가 포함될 수 있습니다. 이는 버전 15.6.0 - 15.6.6 및 15.7.0 - 15.7.2에 영향을 미칩니다. Geo를 컨테이너 리포지토리와 함께 사용 중인 경우 이 문제에 대한 수정 사항을 포함하는 GitLab 15.6.7, 15.7.3 또는 15.8.0으로 업그레이드하고 장애 조치 후 잠재적 데이터 손실을 피하는 것을 권장합니다.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.
- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.6.0 {#1560}

- [공식적으로 지원되는 PostgreSQL 버전](../../administration/package_information/postgresql_versions.md) 중 하나를 사용해야 합니다. 일부 데이터베이스 마이그레이션은 이전 PostgreSQL 버전과의 안정성 및 성능 문제를 야기할 수 있습니다.
- Gitaly에는 Git 2.37.0 이상이 필요합니다. 자체 컴파일된 설치의 경우 [Gitaly에서 제공하는 Git 버전](../../install/self_compiled/_index.md#git)을 사용해야 합니다.
- 이러한 인덱스가 존재하지 않는 인스턴스에서 4개 인덱스의 동작을 수정하기 위한 데이터베이스 변경이 실패합니다:

  ```plaintext
  Caused by:
  PG::UndefinedTable: ERROR:  relation "index_issues_on_title_trigram" does not exist
  ```

  다른 3개의 인덱스는 `index_merge_requests_on_title_trigram`, `index_merge_requests_on_description_trigram` 및 `index_issues_on_description_trigram`입니다.

  이 문제는 [GitLab 15.7에서 수정되었으며](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/105375) GitLab 15.6.2로 백포트되었습니다. 이 문제는 또한 다음과 같이 해결할 수 있습니다: [이러한 인덱스를 만드는 방법에 대해 읽기](https://gitlab.com/gitlab-org/gitlab/-/issues/378343#note_1199863087).

### Linux 패키지 설치 {#linux-package-installations-1}

GitLab 15.6에서 [`omnibus-gitlab` 패키지와 함께 제공되는 PostgreSQL 버전](../../administration/package_information/postgresql_versions.md)이 12.12 및 13.8로 업그레이드되었습니다. [명시적으로 선택 해제](https://docs.gitlab.com/omnibus/settings/database/#automatic-restart-when-the-postgresql-version-changes)하지 않으면 PostgreSQL 서비스의 자동 재시작을 야기할 수 있으며 다운타임을 야기할 수 있습니다.

### Geo 설치 {#geo-installations-20}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못합니다. [세부 정보 및 해결 방법](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13)을 참조하세요.
- [컨테이너 레지스트리 푸시 이벤트가 거부됨](https://gitlab.com/gitlab-org/gitlab/-/issues/386389)으로 인해 `/api/v4/container_registry_event/events` 엔드포인트에서 Geo 보조 사이트가 컨테이너 레지스트리 이미지의 업데이트를 인식하지 못하고 결과적으로 업데이트를 복제하지 않습니다. 결과적으로 보조 사이트에는 장애 조치 후 오래된 컨테이너 이미지가 포함될 수 있습니다. 이는 버전 15.6.0 - 15.6.6 및 15.7.0 - 15.7.2에 영향을 미칩니다. Geo를 컨테이너 리포지토리와 함께 사용 중인 경우 이 문제에 대한 수정 사항을 포함하는 GitLab 15.6.7, 15.7.3 또는 15.8.0으로 업그레이드하고 장애 조치 후 잠재적 데이터 손실을 피하는 것을 권장합니다.
- 적은 수의 Geo 설치에서 [프로젝트 및 위키의 복제 및 검증이 따라가지 못하는](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) 문제를 발견했습니다. 일부 프로젝트나 위키가 검증 시 '대기 중' 상태로 계속 표시되는 경우 설치가 영향을 받을 수 있습니다. 이는 장애 조치 후 데이터 손실로 이어질 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 15.6.x, 15.7.x 및 15.8.0 - 15.8.2.
  - 수정 사항이 포함된 버전: GitLab 15.8.3 이상.
- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

## 15.5.5 {#1555}

- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.5.4 {#1554}

- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.5.3 {#1553}

- GitLab 15.4.0은 모든 작업을 `default` 큐로 라우팅하는 기본 [Sidekiq 라우팅 규칙](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules)을 도입했습니다. [큐 선택기](https://archives.docs.gitlab.com/17.0/ee/administration/sidekiq/processing_specific_job_classes.html#queue-selectors-deprecated)를 사용하는 인스턴스의 경우 일부 Sidekiq 프로세스가 유휴 상태가 되어 [성능 문제](https://gitlab.com/gitlab-com/gl-infra/scalability/-/issues/1991)가 발생합니다.
  - 기본 라우팅 규칙이 15.5.4에서 되돌려졌으므로 해당 버전 이상으로 업그레이드하면 이전 동작으로 돌아갑니다.
  - GitLab 인스턴스가 이제 `default` 큐만 수신하는 경우(현재 권장되지 않음) `/etc/gitlab/gitlab.rb`에서 이 라우팅 규칙을 다시 추가해야 합니다:

    ```ruby
    sidekiq['routing_rules'] = [['*', 'default']]
    ```

- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.5.2 {#1552}

- GitLab 15.4.0은 모든 작업을 `default` 큐로 라우팅하는 기본 [Sidekiq 라우팅 규칙](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules)을 도입했습니다. [큐 선택기](https://archives.docs.gitlab.com/17.0/ee/administration/sidekiq/processing_specific_job_classes.html#queue-selectors-deprecated)를 사용하는 인스턴스의 경우 일부 Sidekiq 프로세스가 유휴 상태가 되어 [성능 문제](https://gitlab.com/gitlab-com/gl-infra/scalability/-/issues/1991)가 발생합니다.
  - 기본 라우팅 규칙이 15.5.4에서 되돌려졌으므로 해당 버전 이상으로 업그레이드하면 이전 동작으로 돌아갑니다.
  - GitLab 인스턴스가 이제 `default` 큐만 수신하는 경우(현재 권장되지 않음) `/etc/gitlab/gitlab.rb`에서 이 라우팅 규칙을 다시 추가해야 합니다:

    ```ruby
    sidekiq['routing_rules'] = [['*', 'default']]
    ```

- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.5.1 {#1551}

- GitLab 15.4.0은 모든 작업을 `default` 큐로 라우팅하는 기본 [Sidekiq 라우팅 규칙](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules)을 도입했습니다. [큐 선택기](https://archives.docs.gitlab.com/17.0/ee/administration/sidekiq/processing_specific_job_classes.html#queue-selectors-deprecated)를 사용하는 인스턴스의 경우 일부 Sidekiq 프로세스가 유휴 상태가 되어 [성능 문제](https://gitlab.com/gitlab-com/gl-infra/scalability/-/issues/1991)가 발생합니다.
  - 기본 라우팅 규칙이 15.5.4에서 되돌려졌으므로 해당 버전 이상으로 업그레이드하면 이전 동작으로 돌아갑니다.
  - GitLab 인스턴스가 이제 `default` 큐만 수신하는 경우(현재 권장되지 않음) `/etc/gitlab/gitlab.rb`에서 이 라우팅 규칙을 다시 추가해야 합니다:

    ```ruby
    sidekiq['routing_rules'] = [['*', 'default']]
    ```

- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.5.0 {#1550}

- GitLab 15.4.0은 모든 작업을 `default` 큐로 라우팅하는 기본 [Sidekiq 라우팅 규칙](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules)을 도입했습니다. [큐 선택기](https://archives.docs.gitlab.com/17.0/ee/administration/sidekiq/processing_specific_job_classes.html#queueselectors-deprecated)를 사용하는 인스턴스의 경우 일부 Sidekiq 프로세스가 유휴 상태가 되어 [성능 문제](https://gitlab.com/gitlab-com/gl-infra/scalability/-/issues/1991)가 발생합니다.
  - 기본 라우팅 규칙이 15.5.4에서 되돌려졌으므로 해당 버전 이상으로 업그레이드하면 이전 동작으로 돌아갑니다.
  - GitLab 인스턴스가 이제 `default` 큐만 수신하는 경우(현재 권장되지 않음) `/etc/gitlab/gitlab.rb`에서 이 라우팅 규칙을 다시 추가해야 합니다:

    ```ruby
    sidekiq['routing_rules'] = [['*', 'default']]
    ```

- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

### Geo 설치 {#geo-installations-21}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못합니다. [세부 정보 및 해결 방법](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13)을 참조하세요.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

## 15.4.6 {#1546}

- `no_proxy` [사용자 정의 환경 변수](https://docs.gitlab.com/omnibus/settings/environment-variables.md)는 GitLab 15.4.6에 포함된 [cURL 버전](https://github.com/curl/curl/issues/10122)의 버그로 인해 Linux 패키지(Omnibus)에서 제대로 작동하지 않을 수 있습니다. 이 문제로 인해 `.example.com`와 같은 모든 와일드카드 도메인이 `no_proxy` 변수에 나열된 마지막 도메인을 제외한 모든 도메인에서 무시됩니다. 이 문제를 해결하려면 와일드카드 도메인을 목록의 끝으로 이동하거나 [수정된 cURL이 있는 최신 버전](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/)으로 업그레이드할 수 있습니다.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.4.5 {#1545}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.4.4 {#1544}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.4.3 {#1543}

- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.4.2 {#1542}

- [라이선스 캐싱 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/376706)는 새 라이선스를 추가할 때 GitLab의 일부 프리미엄 기능이 제대로 작동하지 않도록 합니다. 이 문제에 대한 해결 방법:
  - 새 라이선스를 적용한 후 모든 Rails, Sidekiq 및 Gitaly 노드를 다시 시작합니다. 이렇게 하면 관련 라이선스 캐시가 지워지고 모든 프리미엄 기능을 올바르게 작동할 수 있습니다.
  - 이 이슈의 영향을 받지 않는 버전으로 업그레이드합니다. 영향을 받는 버전에 대해 다음 업그레이드 경로를 사용할 수 있습니다:
    - 15.2.5 --> 15.3.5
    - 15.3.0 - 15.3.4 --> 15.3.5
    - 15.4.1 --> 15.4.3
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.4.1 {#1541}

- [라이선스 캐싱 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/376706)는 새 라이선스를 추가할 때 GitLab의 일부 프리미엄 기능이 제대로 작동하지 않도록 합니다. 이 문제에 대한 해결 방법:
  - 새 라이선스를 적용한 후 모든 Rails, Sidekiq 및 Gitaly 노드를 다시 시작합니다. 이렇게 하면 관련 라이선스 캐시가 지워지고 모든 프리미엄 기능을 올바르게 작동할 수 있습니다.
  - 이 이슈의 영향을 받지 않는 버전으로 업그레이드합니다. 영향을 받는 버전에 대해 다음 업그레이드 경로를 사용할 수 있습니다:
    - 15.2.5 --> 15.3.5
    - 15.3.0 - 15.3.4 --> 15.3.5
    - 15.4.1 --> 15.4.3
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.

## 15.4.0 {#1540}

- GitLab 15.4.0에는 `ci_job_artifacts` 테이블의 `expire_at`에서 [잘못된 값을 제거](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/89318)하기 위한 [배치 처리된 백그라운드 마이그레이션](../background_migrations.md#check-for-pending-database-background-migrations)이 포함되어 있습니다. 이 마이그레이션은 더 큰 GitLab 인스턴스에서 완료하는 데 시간 또는 며칠이 걸릴 수 있습니다.
- 기본적으로 Gitaly 및 Praefect 노드는 `pool.ntp.org`의 시간 서버를 사용합니다. 인스턴스가 `pool.ntp.org`에 연결할 수 없는 경우, [`NTP_HOST` 변수를 구성](../../administration/gitaly/praefect/configure.md#customize-time-server-setting)하세요. 그렇지 않으면 로그 및 `gitlab-rake gitlab:gitaly:check`의 출력에 `ntp: read udp ... i/o timeout` 오류가 발생할 수 있습니다. 그러나 Gitaly 호스트의 시간이 동기화되어 있으면 이러한 오류는 무시할 수 있습니다.
- GitLab 15.4.0은 모든 작업을 `default` 큐로 라우팅하는 기본 [Sidekiq 라우팅 규칙](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules)을 도입했습니다. [큐 선택기](https://archives.docs.gitlab.com/17.0/ee/administration/sidekiq/processing_specific_job_classes.html#queue-selectors-deprecated)를 사용하는 인스턴스의 경우 일부 Sidekiq 프로세스가 유휴 상태가 되어 [성능 문제](https://gitlab.com/gitlab-com/gl-infra/scalability/-/issues/1991)가 발생합니다.
  - 기본 라우팅 규칙이 15.4.5에서 되돌려졌으므로, 해당 버전 이상으로 업그레이드하면 이전 동작으로 돌아갑니다.
  - GitLab 인스턴스가 이제 `default` 큐만 수신하는 경우(현재 권장되지 않음) `/etc/gitlab/gitlab.rb`에서 이 라우팅 규칙을 다시 추가해야 합니다:

    ```ruby
    sidekiq['routing_rules'] = [['*', 'default']]
    ```

- `/etc/gitlab/gitlab-secrets.json`의 구조가 [GitLab 15.4](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/6310)에서 수정되었으며, `gitlab_pages`, `grafana` 및 `mattermost` 섹션에 새로운 구성이 추가되었습니다. 고가용성 또는 GitLab Geo 환경에서는 모든 노드에서 시크릿이 동일해야 합니다. 시크릿 파일을 노드 간에 수동으로 동기화하거나 `/etc/gitlab/gitlab.rb`에서 수동으로 시크릿을 지정하는 경우, `/etc/gitlab/gitlab-secrets.json`이(가) 모든 노드에서 동일한지 확인하세요.
- GitLab 15.4.0은 [배치 백그라운드 마이그레이션](../background_migrations.md#check-for-pending-database-background-migrations)을 도입하여 [문제 테이블의 `namespace_id` 값 채우기](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/91921)합니다. 이 마이그레이션은 더 큰 GitLab 인스턴스에서 완료하는 데 여러 시간 또는 일이 걸릴 수 있습니다. 15.7.0 이상으로 업그레이드하기 전에 마이그레이션이 성공적으로 완료되었는지 확인하세요.
- GitLab 15.4에서 [도입된 버그](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)로 인해 Gitaly 클러스터(Praefect)의 하나 이상의 Git 리포지토리가 [사용할 수 없으면](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), [리포지토리 확인](../../administration/repository_checks.md) 및 [Geo 복제 및 검증](../../administration/geo/_index.md)이 영향을 받는 Gitaly 클러스터(Praefect)의 모든 프로젝트 또는 프로젝트 위키 리포지토리에 대해 실행을 중지합니다. 이 버그는 [GitLab 15.9.0에서 변경을 되돌려서](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823) 수정되었습니다. 이 버전으로 업그레이드하기 전에 '사용할 수 없는' 리포지토리가 있는지 확인하세요. 자세한 내용은 [버그 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155)를 참조하세요.
- 다시 디자인된 로그인 페이지는 GitLab 15.4 이상에서 기본적으로 활성화되며, 향후 릴리스에서 개선 사항이 제공됩니다. 자세한 내용은 [에픽 8557](https://gitlab.com/groups/gitlab-org/-/work_items/8557)을 참조하세요. 기능 플래그로 비활성화할 수 있습니다. [Rails 콘솔을 시작](../../administration/operations/rails_console.md)하고 실행합니다:

  ```ruby
  Feature.disable(:restyle_login_page)
  ```

### Geo 설치 {#geo-installations-22}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못합니다. [세부 정보 및 해결 방법](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13)을 참조하세요.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

## 15.3.4 {#1534}

[라이선스 캐싱 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/376706)는 새 라이선스를 추가할 때 GitLab의 일부 프리미엄 기능이 제대로 작동하지 않도록 합니다. 이 문제에 대한 해결 방법:

- 새 라이선스를 적용한 후 모든 Rails, Sidekiq 및 Gitaly 노드를 다시 시작합니다. 이렇게 하면 관련 라이선스 캐시가 지워지고 모든 프리미엄 기능을 올바르게 작동할 수 있습니다.
- 이 이슈의 영향을 받지 않는 버전으로 업그레이드합니다. 영향을 받는 버전에 대해 다음 업그레이드 경로를 사용할 수 있습니다:
  - 15.2.5 --> 15.3.5
  - 15.3.0 - 15.3.4 --> 15.3.5
  - 15.4.1 --> 15.4.3

## 15.3.3 {#1533}

- GitLab 15.3.3에서 [SAML Group Links](../../api/saml.md#saml-group-links) API `access_level` 특성 유형이 `integer`로 변경되었습니다. [API 설명서](../../api/group_members.md)를 참조하세요.
- [라이선스 캐싱 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/376706)는 새 라이선스를 추가할 때 GitLab의 일부 프리미엄 기능이 제대로 작동하지 않도록 합니다. 이 문제에 대한 해결 방법:

  - 새 라이선스를 적용한 후 모든 Rails, Sidekiq 및 Gitaly 노드를 다시 시작합니다. 이렇게 하면 관련 라이선스 캐시가 지워지고 모든 프리미엄 기능을 올바르게 작동할 수 있습니다.
  - 이 이슈의 영향을 받지 않는 버전으로 업그레이드합니다. 영향을 받는 버전에 대해 다음 업그레이드 경로를 사용할 수 있습니다:
    - 15.2.5 --> 15.3.5
    - 15.3.0 - 15.3.4 --> 15.3.5
    - 15.4.1 --> 15.4.3

## 15.3.2 {#1532}

[라이선스 캐싱 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/376706)는 새 라이선스를 추가할 때 GitLab의 일부 프리미엄 기능이 제대로 작동하지 않도록 합니다. 이 문제에 대한 해결 방법:

- 새 라이선스를 적용한 후 모든 Rails, Sidekiq 및 Gitaly 노드를 다시 시작합니다. 이렇게 하면 관련 라이선스 캐시가 지워지고 모든 프리미엄 기능을 올바르게 작동할 수 있습니다.
- 이 이슈의 영향을 받지 않는 버전으로 업그레이드합니다. 영향을 받는 버전에 대해 다음 업그레이드 경로를 사용할 수 있습니다:
  - 15.2.5 --> 15.3.5
  - 15.3.0 - 15.3.4 --> 15.3.5
  - 15.4.1 --> 15.4.3

## 15.3.1 {#1531}

[라이선스 캐싱 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/376706)는 새 라이선스를 추가할 때 GitLab의 일부 프리미엄 기능이 제대로 작동하지 않도록 합니다. 이 문제에 대한 해결 방법:

- 새 라이선스를 적용한 후 모든 Rails, Sidekiq 및 Gitaly 노드를 다시 시작합니다. 이렇게 하면 관련 라이선스 캐시가 지워지고 모든 프리미엄 기능을 올바르게 작동할 수 있습니다.
- 이 이슈의 영향을 받지 않는 버전으로 업그레이드합니다. 영향을 받는 버전에 대해 다음 업그레이드 경로를 사용할 수 있습니다:
  - 15.2.5 --> 15.3.5
  - 15.3.0 - 15.3.4 --> 15.3.5
  - 15.4.1 --> 15.4.3

## 15.3.0 {#1530}

- Gitaly Cluster(Praefect)에서 생성된 새 Git 리포지토리는 더 이상 `@hashed` 저장소 경로를 사용하지 않습니다. 새 리포지토리용 서버 훅은 다른 위치로 복사해야 합니다. Praefect는 이제 Gitaly 클러스터에서 사용할 복제본 경로를 생성합니다. 이 변경은 Gitaly Cluster(Praefect)가 원자적으로 Git 리포지토리를 생성, 삭제 및 이름을 바꾸기 위한 전제 조건입니다.

  복제본 경로를 식별하려면 [Praefect 리포지토리 메타데이터를 쿼리](../../administration/gitaly/praefect/troubleshooting.md#view-repository-metadata)하고 `@hashed` 저장소 경로를 `-relative-path`에 전달하세요.

  이 정보를 사용하면 [서버 훅](../../administration/server_hooks.md)을 올바르게 설치할 수 있습니다.

- [라이선스 캐싱 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/376706)는 새 라이선스를 추가할 때 GitLab의 일부 프리미엄 기능이 제대로 작동하지 않도록 합니다. 이 문제에 대한 해결 방법:

  - 새 라이선스를 적용한 후 모든 Rails, Sidekiq 및 Gitaly 노드를 다시 시작합니다. 이렇게 하면 관련 라이선스 캐시가 지워지고 모든 프리미엄 기능을 올바르게 작동할 수 있습니다.
  - 이 이슈의 영향을 받지 않는 버전으로 업그레이드합니다. 영향을 받는 버전에 대해 다음 업그레이드 경로를 사용할 수 있습니다:
    - 15.2.5 --> 15.3.5
    - 15.3.0 - 15.3.4 --> 15.3.5
    - 15.4.1 --> 15.4.3

### Geo 설치 {#geo-installations-23}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못합니다. [세부 정보 및 해결 방법](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13)을 참조하세요.
- LFS 전송은 세션 중간에 보조 사이트에서 주 사이트로 리디렉션될 수 있습니다. [세부 정보 및 해결 방법](#lfs-transfers-redirect-to-primary-from-secondary-site-mid-session)을 참조하세요.
- Geo 보조 사이트에서 잘못된 객체 스토리지 LFS 파일 삭제입니다. [세부 정보 및 해결 방법](#incorrect-object-storage-lfs-file-deletion-on-secondary-sites)을 참조하세요.

#### LFS 전송이 세션 중간에 보조 사이트에서 주 사이트로 리디렉션됨 {#lfs-transfers-redirect-to-primary-from-secondary-site-mid-session}

| 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
|-------------------------|-------------------------|----------|
| 15.1                    | 모두                     | 없음     |
| 15.2                    | 모두                     | 없음     |
| 15.3                    | 15.3.0 - 15.3.2         | 15.3.3 이상 |

LFS 전송은 [세션 중간에 보조 사이트에서 주 사이트로 리디렉션](https://gitlab.com/gitlab-org/gitlab/-/issues/371571)될 수 있으며, [Geo 프록시](../../administration/geo/secondary_proxy/_index.md)가 활성화되면 GitLab 15.1.0~15.3.2에서 끌어오기 및 복제 요청이 실패합니다. Geo 프록시는 GitLab 15.1 이상에서 기본적으로 활성화됩니다.

이 문제는 GitLab 15.3.3에서 해결되므로, 다음 구성을 사용하는 고객은 15.3.3 이상으로 업그레이드해야 합니다:

- LFS가 활성화됩니다.
- LFS 개체가 Geo 사이트 간에 복제됩니다.
- Geo 보조 사이트를 사용하여 리포지토리를 끌어오고 있습니다.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

#### 보조 사이트에서 잘못된 객체 스토리지 LFS 파일 삭제 {#incorrect-object-storage-lfs-file-deletion-on-secondary-sites}

| 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
|-------------------------|-------------------------|----------|
| 15.0                    | 모두                     | 없음     |
| 15.1                    | 모두                     | 없음     |
| 15.2                    | 모두                     | 없음     |
| 15.3                    | 15.3.0 - 15.3.2         | 15.3.3 이상 |

[Geo 보조 사이트의 객체 스토리지 파일을 잘못 삭제](https://gitlab.com/gitlab-org/gitlab/-/issues/371397)할 수 있으며, GitLab 15.0.0~15.3.2에서 다음 상황에서 발생할 수 있습니다:

- GitLab 관리 객체 스토리지 복제가 비활성화되어 있고, 객체 스토리지가 활성화된 상태에서 프로젝트를 가져오는 동안 LFS 개체가 생성됩니다.
- GitLab 관리 복제가 객체 스토리지를 동기화하도록 활성화되었다가 이후 비활성화됩니다.

이 문제는 15.3.3에서 해결됩니다. LFS가 활성화되어 있고 LFS 개체가 Geo 사이트 간에 복제되는 고객은 보조 사이트의 데이터 손실 위험을 줄이기 위해 15.3.3으로 직접 업그레이드해야 합니다.

## 15.2.5 {#1525}

[라이선스 캐싱 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/376706)는 새 라이선스를 추가할 때 GitLab의 일부 프리미엄 기능이 제대로 작동하지 않도록 합니다. 이 문제에 대한 해결 방법:

- 새 라이선스를 적용한 후 모든 Rails, Sidekiq 및 Gitaly 노드를 다시 시작합니다. 이렇게 하면 관련 라이선스 캐시가 지워지고 모든 프리미엄 기능을 올바르게 작동할 수 있습니다.
- 이 이슈의 영향을 받지 않는 버전으로 업그레이드합니다. 영향을 받는 버전에 대해 다음 업그레이드 경로를 사용할 수 있습니다:
  - 15.2.5 --> 15.3.5
  - 15.3.0 - 15.3.4 --> 15.3.5
  - 15.4.1 --> 15.4.3

## 15.2.0 {#1520}

- 복수의 웹 노드가 있는 GitLab 설치는 Rails의 구성 변경으로 인해 일관되지 않은 ETag 키 생성이 될 수 있으므로 15.2(이상)로 업그레이드하기 전에 [15.1로 업그레이드](#1510)해야 합니다.
- 일부 Sidekiq 워커가 이 릴리스에서 이름이 바뀌었습니다. 모든 방해를 피하려면 GitLab 15.2.0으로 업그레이드를 시작하기 전에 [Rake 작업을 실행하여 보류 중인 작업을 마이그레이션](../../administration/sidekiq/sidekiq_job_migration.md#migrate-queued-and-future-jobs)하세요.
- Gitaly는 이제 [런타임 위치](https://gitlab.com/gitlab-org/gitaly/-/merge_requests/4670)에서 바이너리를 실행합니다. Linux 패키지 인스턴스의 경우 기본적으로 이 경로는 `/var/opt/gitlab/gitaly/run/`입니다. 이 위치가 `noexec`로 마운트되면 머지 요청이 다음 오류를 생성합니다:

  ```plaintext
  fork/exec /var/opt/gitlab/gitaly/run/gitaly-<nnnn>/gitaly-git2go-v15: permission denied
  ```

  이를 해결하려면 파일 시스템 마운트에서 `noexec` 옵션을 제거합니다. 다른 방법은 Gitaly 런타임 디렉터리를 변경하는 것입니다:

  1. `gitaly['runtime_dir'] = '<PATH_WITH_EXEC_PERM>'`을(를) `/etc/gitlab/gitlab.rb`에 추가하고 `noexec`이(가) 설정되지 않은 위치를 지정합니다.
  1. `sudo gitlab-ctl reconfigure`를 실행합니다.

### Geo 설치 {#geo-installations-24}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- `pg_upgrade`에서 번들로 제공되는 PostregSQL 데이터베이스를 버전 13으로 업그레이드하지 못합니다. [세부 정보 및 해결 방법](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13)을 참조하세요.
- LFS 전송은 세션 중간에 보조 사이트에서 주 사이트로 리디렉션될 수 있습니다. [세부 정보 및 해결 방법](#lfs-transfers-redirect-to-primary-from-secondary-site-mid-session)을 참조하세요.
- Geo 보조 사이트에서 잘못된 객체 스토리지 LFS 파일 삭제입니다. [세부 정보 및 해결 방법](#incorrect-object-storage-lfs-file-deletion-on-secondary-sites)을 참조하세요.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

## 15.1.0 {#1510}

- GitLab 15.1.0에서는 Rails `ActiveSupport::Digest`을(를) MD5 대신 SHA256을 사용하도록 전환합니다. 이는 원본 스니펫 파일 다운로드와 같은 리소스에 대한 ETag 키 생성에 영향을 줍니다. 업그레이드할 때 여러 웹 노드 간에 일관된 ETag 키 생성을 보장하려면 먼저 모든 서버를 15.1.6으로 업그레이드한 후 15.2.0 이상으로 업그레이드해야 합니다:

  1. 모든 GitLab 웹 노드가 GitLab 15.1.6을 실행 중인지 확인합니다.
  1. [GitLab on Kubernetes](https://docs.gitlab.com/charts/installation/)를 실행하는 경우, 클라우드 네이티브 GitLab Helm 차트를 사용하여 모든 웹 서비스 팟이 GitLab 15.1.Z를 실행 중인지 확인하세요:

     ```shell
     kubectl get pods -l app=webservice -o custom-columns=webservice-image:{.spec.containers[0].image},workhorse-image:{.spec.containers[1].image}
     ```

  1. `ActiveSupport::Digest`을(를) SHA256을 사용하도록 전환하기 위해 [`active_support_hash_digest_sha256` 기능 플래그 활성화](../../administration/feature_flags/_index.md#how-to-enable-and-disable-features-behind-flags):

     1. [Rails 콘솔 시작](../../administration/operations/rails_console.md)
     1. 기능 플래그 활성화:

        ```ruby
        Feature.enable(:active_support_hash_digest_sha256)
        ```

  1. 그런 다음 GitLab의 최신 버전으로 업그레이드를 계속합니다.
- [`ciConfig` GraphQL 필드](../../api/graphql/reference/queries.md#ciconfig)에 대한 인증되지 않은 요청은 더 이상 지원되지 않습니다. GitLab 15.1로 업그레이드하기 전에 요청에 [액세스 토큰](../../api/rest/authentication.md)을(를) 추가하세요. 토큰을 생성하는 사용자는 프로젝트에서 파이프라인을 생성할 [권한](../../user/permissions.md)이 있어야 합니다.

### Geo 설치 {#geo-installations-25}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- [Geo 프록시](../../administration/geo/secondary_proxy/_index.md)는 15.1에서 [다양한 URL에 대해 기본적으로 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/346112)되었습니다. 이것은 주요 변경일 수 있습니다. 필요한 경우, [Geo 프록시를 비활성화](../../administration/geo/secondary_proxy/_index.md#disable-secondary-site-http-proxying)할 수 있습니다. 다양한 URL이 있는 SAML을 사용하는 경우, SAML 구성 및 ID 공급자 구성을 수정해야 합니다. 자세한 내용은 [Geo with Single Sign-On (SSO) 설명서](../../administration/geo/replication/single_sign_on.md)를 참조하세요.
- LFS 전송은 세션 중간에 보조 사이트에서 주 사이트로 리디렉션될 수 있습니다. [세부 정보 및 해결 방법](#lfs-transfers-redirect-to-primary-from-secondary-site-mid-session)을 참조하세요.
- Geo 보조 사이트에서 잘못된 객체 스토리지 LFS 파일 삭제입니다. [세부 정보 및 해결 방법](#incorrect-object-storage-lfs-file-deletion-on-secondary-sites)을 참조하세요.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

## 15.0.0 {#1500}

- Elasticsearch 6.8은 [더 이상 지원되지 않습니다](../../integration/advanced_search/elasticsearch.md#version-compatibility). GitLab 15.0으로 업그레이드하기 전에 [Elasticsearch를 7.x 버전으로 업데이트](../../integration/advanced_search/elasticsearch.md#upgrade-to-a-new-elasticsearch-version)하세요.
- 외부 PostgreSQL(특히 AWS RDS)로 GitLab을 실행하는 경우, GitLab 14.8 이상으로 업그레이드하기 전에 PostgreSQL을 최소한 12.7 또는 13.3의 패치 수준으로 업그레이드해야 합니다.

  GitLab Enterprise Edition의 경우 [14.8](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/75511)에서, GitLab Community Edition의 경우 [15.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/87983)에서 Loose Foreign Keys라는 GitLab 기능이 활성화되었습니다.

  활성화된 후, 분할 오류를 유발하는 데이터베이스 엔진 버그로 인한 계획되지 않은 PostgreSQL 재시작 보고가 있습니다.

  자세한 내용은 [이슈 364763](https://gitlab.com/gitlab-org/gitlab/-/issues/364763)을 참조하세요.

- 저장소 관련 구성으로 암호화된 S3 버킷의 사용은 [`background_upload` 사용 지원 제거](../deprecations.md#background-upload-for-object-storage) 후 더 이상 지원되지 않습니다.
- [인증서 기반 Kubernetes 통합(더 이상 사용되지 않음)](../../user/infrastructure/clusters/_index.md#certificate-based-kubernetes-integration-deprecated)은 기본적으로 비활성화되어 있지만, GitLab 16.0까지 [`certificate_based_clusters` 기능 플래그](../../administration/feature_flags/_index.md#how-to-enable-and-disable-features-behind-flags)를 통해 다시 활성화할 수 있습니다.
- 사용자 지정 `serviceAccount`을(를) 사용하는 GitLab Helm 차트 프로젝트를 사용할 때, `serviceAccount` 및 `secret` 리소스에 대한 `get` 및 `list` 권한이 있는지 확인하세요.
- `FF_GITLAB_REGISTRY_HELPER_IMAGE` [기능 플래그](../../administration/feature_flags/_index.md#enable-or-disable-the-feature)는 제거되었으며 도우미 이미지는 항상 GitLab Registry에서 가져옵니다.

### Linux 패키지 설치 {#linux-package-installations-2}

- 전역 서버 훅을 구성하기 위한 [`custom_hooks_dir`](../../administration/server_hooks.md#create-global-server-hooks-for-all-repositories) 설정은 이제 Gitaly에서 구성됩니다. GitLab Shell의 이전 구현은 GitLab 15.0에서 제거되었습니다. 이 변경으로 전역 서버 훅은 훅 유형 후 이름이 지정된 하위 디렉터리 내에만 저장됩니다. 전역 서버 훅은 더 이상 사용자 정의 훅 디렉터리의 루트에 있는 단일 훅 파일일 수 없습니다. 예를 들어, `<custom_hooks_dir>/<hook_name>` 대신 `<custom_hooks_dir>/<hook_name>.d/*`을(를) 사용해야 합니다.
  - Linux 패키지 인스턴스의 경우 `gitlab.rb`에서 `gitaly['custom_hooks_dir']`을(를) 사용하세요. 이것은 `gitlab_shell['custom_hooks_dir']`을(를) 대체합니다.
- PostgreSQL 13.6은 신규 설치 기본 버전으로, 업그레이드는 12.10으로 제공됩니다. [업그레이드 설명서](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server)에 따라 PostgreSQL 13.6으로 수동 업그레이드할 수 있습니다:

  ```shell
  sudo gitlab-ctl pg-upgrade -V 13
  ```

  PostgreSQL 12가 제거될 때까지, 호환성이나 테스트 환경 이유로 필요한 경우 [PostgreSQL 버전을 고정](https://docs.gitlab.com/omnibus/settings/database/#pin-the-packaged-postgresql-version-fresh-installs-only)할 수 있습니다.

  [장애 조치 및 Geo 설치에는 추가 단계 및 계획이 필요](../../administration/postgresql/replication_and_failover.md#upgrading-postgresql-major-version-in-a-patroni-cluster)합니다.

  기본 구조적 변경으로 인해 실행 중인 PostgreSQL 프로세스는 데이터베이스 마이그레이션을 실행하기 전에 업그레이드할 때 다시 시작해야 합니다. 자동 재시작을 건너뛴 경우, 마이그레이션을 실행하기 전에 다음 명령을 실행해야 합니다:

  ```shell
  # If using PostgreSQL
  sudo gitlab-ctl restart postgresql

  # If using Patroni for Database replication
  sudo gitlab-ctl restart patroni
  ```

  PostgreSQL을 다시 시작하지 않으면 [라이브러리 로드와 관련된 오류](https://docs.gitlab.com/omnibus/settings/database/#could-not-load-library-plpgsqlso)가 발생할 수 있습니다.

- GitLab 15.0부터 `postgresql` 및 `geo-postgresql` 서비스는 PostgreSQL 버전이 변경될 때 자동으로 다시 시작됩니다. PostgreSQL 서비스를 다시 시작하면 데이터베이스의 일시적인 사용 불가로 인해 다운타임이 발생합니다. 이 재시작은 데이터베이스 서비스의 적절한 기능을 위해 필수이지만, PostgreSQL이 다시 시작되는 시점을 더 자세히 제어할 수 있습니다. 이를 위해 `gitlab-ctl reconfigure`의 일부로 자동 재시작을 건너뛰고 서비스를 수동으로 다시 시작하도록 선택할 수 있습니다.

  GitLab 15.0 업그레이드의 일부로 자동 재시작을 건너뛰려면 업그레이드 전에 다음 단계를 수행하세요:

  1. `/etc/gitlab/gitlab.rb`을(를) 편집하고 다음 줄을 추가합니다:

     ```ruby
     # For PostgreSQL/Patroni
     postgresql['auto_restart_on_version_change'] = false

     # For Geo PostgreSQL
     geo_postgresql['auto_restart_on_version_change'] = false
     ```

  1. GitLab을 재구성합니다.

     ```shell
     sudo gitlab-ctl reconfigure
     ```

  > [!note]
  > 기본 버전 변경 시 PostgreSQL을 다시 시작하는 것이 필수이며, 다운타임을 유발할 수 있는 [필요한 라이브러리 로드와 관련된 오류](https://docs.gitlab.com/omnibus/settings/database/#could-not-load-library-plpgsqlso)를 방지해야 합니다. 따라서 이전 방법을 사용하여 자동 재시작을 건너뛴 경우, GitLab 15.0으로 업그레이드하기 전에 서비스를 수동으로 다시 시작해야 합니다.

- GitLab 15.0부터 `AES256-GCM-SHA384` SSL 암호는 NGINX에서 기본적으로 허용되지 않습니다. [AWS Classic Load Balancer](https://docs.aws.amazon.com/en_en/elasticloadbalancing/latest/classic/elb-ssl-security-policy.html#ssl-ciphers)를 사용하고 암호가 필요한 경우, 이를 허용 목록에 다시 추가할 수 있습니다. SSL 암호를 허용 목록에 추가하려면:

  1. `/etc/gitlab/gitlab.rb`을(를) 편집하고 다음 줄을 추가합니다:

     ```ruby
     nginx['ssl_ciphers'] = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:AES256-GCM-SHA384"
     ```

  1. GitLab을 재구성합니다.

     ```shell
     sudo gitlab-ctl reconfigure
     ```

- Gitaly의 내부 소켓 경로에 대한 지원이 제거되었습니다. GitLab 14.10에서 Gitaly는 Gitaly가 올바르게 작동하는 데 필요한 모든 런타임 데이터를 보유하는 새 디렉터리를 도입했습니다. 이 새 디렉터리는 이전 내부 소켓 디렉터리를 대체하며, 결과적으로 `gitaly['internal_socket_dir']`의 사용이 `gitaly['runtime_dir']`을(를) 선호하도록 더 이상 사용되지 않습니다.

  이전 `gitaly['internal_socket_dir']` 구성이 이 릴리스에서 제거되었습니다.

- 객체 스토리지의 백그라운드 업로드 설정이 제거되었습니다. 객체 스토리지는 이제 기본적으로 직접 업로드를 사용합니다.

  다음 키는 `/etc/gitlab/gitlab.rb`에서 더 이상 지원되지 않습니다:

  - `gitlab_rails['artifacts_object_store_direct_upload']`
  - `gitlab_rails['artifacts_object_store_background_upload']`
  - `gitlab_rails['external_diffs_object_store_direct_upload']`
  - `gitlab_rails['external_diffs_object_store_background_upload']`
  - `gitlab_rails['lfs_object_store_direct_upload']`
  - `gitlab_rails['lfs_object_store_background_upload']`
  - `gitlab_rails['uploads_object_store_direct_upload']`
  - `gitlab_rails['uploads_object_store_background_upload']`
  - `gitlab_rails['packages_object_store_direct_upload']`
  - `gitlab_rails['packages_object_store_background_upload']`
  - `gitlab_rails['dependency_proxy_object_store_direct_upload']`
  - `gitlab_rails['dependency_proxy_object_store_background_upload']`

### 소스에서 컴파일한 설치 {#self-compiled-installations-1}

- GitLab에 여러 데이터베이스에 대한 지원이 추가되었습니다. **자체 컴파일(소스) 설치**의 경우, `config/database.yml`은(는) 데이터베이스 구성에 데이터베이스 이름을 포함해야 합니다. `main: database`이(가) 먼저 와야 합니다. 잘못된 또는 더 이상 사용되지 않는 구문이 사용되면, 애플리케이션 시작 중에 오류가 생성됩니다:

  ```plaintext
  ERROR: This installation of GitLab uses unsupported 'config/database.yml'.
  The main: database needs to be defined as a first configuration item instead of primary. (RuntimeError)
  ```

  이전에 `config/database.yml` 파일은 다음과 같이 보였습니다:

  ```yaml
  production:
    adapter: postgresql
    encoding: unicode
    database: gitlabhq_production
    ...
  ```

  GitLab 15.0부터 `main` 데이터베이스를 먼저 정의해야 합니다:

  ```yaml
  production:
    main:
      adapter: postgresql
      encoding: unicode
      database: gitlabhq_production
      ...
  ```

### Geo 설치 {#geo-installations-26}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

- Geo 보조 사이트에서 잘못된 객체 스토리지 LFS 파일 삭제입니다. [세부 정보 및 해결 방법](#incorrect-object-storage-lfs-file-deletion-on-secondary-sites)을 참조하세요.
