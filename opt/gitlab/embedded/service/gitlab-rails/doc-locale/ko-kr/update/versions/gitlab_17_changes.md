---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 17 업그레이드 노트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

이 페이지는 GitLab 17의 마이너 및 패치 버전 업그레이드 정보를 포함합니다. 다음 사항을 검토했는지 확인하세요:

- 설치 유형.
- 현재 버전과 목표 버전 사이의 모든 버전.

Helm 차트 설치에 대한 추가 정보는 [Helm 차트 8.0 업그레이드 노트](https://docs.gitlab.com/charts/releases/8_0/)를 참조하세요.

## 업그레이드할 때 주의할 문제 {#issues-to-be-aware-of-when-upgrading}

특정 GitLab 버전에서 업그레이드할 때 업그레이드에 영향을 줄 수 있는 몇 가지 문제를 알아야 합니다.

### GitLab 16.11 {#from-gitlab-1611}

GitLab 16.11에서 업그레이드할 때:

- 백그라운드 마이그레이션 `AlterWebhookDeletedAuditEvent: audit_events`는 완료하는 데 몇 시간이 걸릴 수 있습니다. [머지 리퀘스트 161320](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/161320)에서 자세히 알아볼 수 있습니다.
- [현재 더 이상 지원되지 않는 번들 Grafana](../deprecations.md#bundled-grafana-deprecated-and-disabled) 키에 대한 참조를 `gitlab.rb`에서 제거해야 GitLab 17.0 이상으로 업그레이드하기 전에 해야 합니다. 업그레이드 후 `gitlab.rb`의 키에 대한 참조가 있으면 `gitlab-ctl reconfigure`가 실패합니다.
- GitLab 17.0으로 업그레이드하기 전에 [새 러너 등록 워크플로우로 마이그레이션](../../ci/runners/new_creation_workflow.md)해야 합니다.

  GitLab 16.0에서 러너 인증 토큰을 사용하여 러너를 등록하는 새 러너 생성 워크플로우를 도입했습니다. 등록 토큰을 사용하는 레거시 워크플로우는 이제 GitLab 17.0에서 기본적으로 비활성화되며 GitLab 20.0에서 제거될 예정입니다. 등록 토큰이 여전히 사용 중이면 GitLab 17.0으로 업그레이드하면 러너 등록이 실패합니다.
- Gitaly 스토리지는 더 이상 이 예제와 같은 경로를 공유할 수 없습니다:

  ```ruby
  gitaly['configuration'] = {
    storage: [
      {
         name: 'default',
         path: '/var/opt/gitlab/git-data/repositories',
      },
      {
         name: 'duplicate-path',
         path: '/var/opt/gitlab/git-data/repositories',
      },
    ],
  }
  ```

  이 예제에서 `duplicate-path` 스토리지를 제거하거나 새 경로로 재배치해야 합니다. Gitaly 노드가 2개 이상인 경우, 해당 노드의 `gitlab.rb` 파일에 해당 노드에 대한 스토리지만 나열되는지 확인해야 합니다.

  스토리지가 노드의 `gitlab.rb` 파일에서 제거되면 관련된 모든 프로젝트의 스토리지를 GitLab 데이터베이스에서 업데이트해야 합니다. Rails 콘솔을 사용하여 스토리지를 업데이트할 수 있습니다. 예를 들어:

  ```shell
  $ sudo gitlab-rails console
  Project.where(repository_storage: 'duplicate-path').update_all(repository_storage: 'default')
  ```

- GitLab 16.x에서 GitLab 17.1.0 또는 17.1.1로 직접 업그레이드할 때 마이그레이션 실패. 이 버그는 GitLab 17.1.2로 수정되었습니다. GitLab 16.x에서 17.1.2로 직접 업그레이드하면 이러한 문제가 발생하지 않습니다.

  GitLab 17.1.0 및 17.1.1의 백그라운드 작업 완료가 올바르게 적용되지 않은 버그로 인해 GitLab 17.1.0 및 17.1.1로 직접 업그레이드할 때 실패할 수 있습니다. 업그레이드 마이그레이션 중 오류는 다음과 같습니다:

  ```shell
  main: == [advisory_lock_connection] object_id: 55460, pg_backend_pid: 8714
  main: == 20240531173207 ValidateNotNullCheckConstraintOnEpicsIssueId: migrating =====
  main: -- execute("SET statement_timeout TO 0")
  main:    -> 0.0004s
  main: -- execute("ALTER TABLE epics VALIDATE CONSTRAINT check_450724d1bb;")
  main: -- execute("RESET statement_timeout")
  main: == [advisory_lock_connection] object_id: 55460, pg_backend_pid: 8714
  STDERR:
  ```

  업그레이드하려면 다음 중 하나를 수행합니다:

  - GitLab 17.0으로 업그레이드하고 모든 백그라운드 마이그레이션이 완료될 때까지 기다립니다.
  - GitLab 17.1로 업그레이드하고 다음 명령을 실행하여 백그라운드 작업 및 마이그레이션을 수동으로 실행합니다:

    ```shell
    sudo gitlab-rake gitlab:background_migrations:finalize[BackfillEpicBasicFieldsToWorkItemRecord,epics,id,'[null]']
    ```

  이제 GitLab 17.1에서 마이그레이션을 완료하고 업그레이드를 마칠 수 있어야 합니다.

- GitLab 17.0.x 및 GitLab 17.1.x와 함께 제공되는 Git 버전의 [알려진 문제](https://gitlab.com/gitlab-org/gitlab/-/issues/476542)는 로드 상태에서 CPU 사용량이 눈에 띄게 증가합니다. 이 회귀의 주요 원인은 GitLab 17.2와 함께 제공되는 Git 버전에서 해결되었으므로, 높은 최대 로드를 보는 시스템의 경우 GitLab 17.2로 업그레이드해야 합니다.

#### Linux 패키지 설치 {#linux-package-installations}

특정 정보는 Linux 패키지 설치에 적용됩니다:

- PostgreSQL 13의 바이너리가 제거되었습니다.

  업그레이드하기 전에 설치 시 [PostgreSQL 14](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server)를 사용하고 있는지 확인해야 합니다.
- Ubuntu 18.04용 패키지는 더 이상 빌드되지 않습니다.

  GitLab을 업그레이드하려고 시도하기 전에 운영 체제를 Ubuntu 20.04 이상으로 업그레이드했는지 확인하세요.

#### 만료되지 않는 액세스 토큰 {#non-expiring-access-tokens}

만료 날짜가 없는 액세스 토큰은 무한정 유효하며, 액세스 토큰이 유출된 경우 보안 위험입니다.

GitLab 16.0 이상으로 업그레이드하면 만료 날짜가 없는 모든 [개인](../../user/profile/personal_access_tokens.md), [프로젝트](../../user/project/settings/project_access_tokens.md) 또는 [그룹](../../user/group/settings/group_access_tokens.md) 액세스 토큰이 업그레이드 날짜로부터 1년으로 자동 설정됩니다.

이 자동 만료 날짜가 적용되기 전에 다음을 수행하여 중단을 최소화해야 합니다:

1. [만료 날짜가 없는 액세스 토큰 확인](../../administration/raketasks/tokens/_index.md#find-tokens-the-rake-tasks-do-not-report).
1. [해당 토큰에 만료 날짜 부여](../../administration/raketasks/tokens/_index.md#extend-expiration-dates).

자세한 내용은 다음을 참조하세요:

- [사용 중단 및 제거 설명서](../deprecations.md#non-expiring-access-tokens).
- [사용 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/369122).

### GitLab 17.0 및 이전 {#from-gitlab-170-and-earlier}

Linux 패키지 설치의 경우 GitLab 17.1 이상으로 업그레이드하기 전에 [현재 더 이상 지원되지 않는 번들 Grafana](../deprecations.md#bundled-grafana-deprecated-and-disabled) 키(`grafana[]`)에 대한 참조를 `/etc/gitlab/gitlab.rb`에서 제거해야 합니다. 업그레이드 후 `/etc/gitlab/gitlab.rb`의 해당 키에 대한 참조가 있으면 [머지 리퀘스트 위젯과 같은](https://support.gitlab.com/hc/en-us/articles/19677647414812-Error-after-upgrade-Unable-to-load-the-merge-request-widget) 기능을 중단할 수 있습니다.

자세한 내용은 다음 문제를 참조하세요:

- [Grafana 속성 및 사용 중단 메시지 제거](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8200).
- [Grafana 사용 중단 및 주요 변경으로 비활성화](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7772).

### GitLab 17.1 및 이전 {#from-gitlab-171-and-earlier}

GitLab 17.1 및 이전에서 업그레이드할 때:

- GitLab Duo를 사용하고 있고 GitLab 17.2.3 이상으로 업그레이드하는 경우, 다음 중 둘 다를 수행해야 합니다:
  - 라이선스를 다시 동기화합니다.
  - 업그레이드 후 서버를 다시 시작합니다.
- GitLab Duo를 사용하고 있고 GitLab 17.2.4 이상으로 업그레이드하는 경우, 다음 중 하나를 수행해야 합니다:
  - 라이선스를 다시 동기화합니다.
  - 24시간마다 발생하는 다음 예약된 라이선스 동기화를 기다립니다.

GitLab 17.2.4 이상으로 업그레이드한 후, 이러한 단계는 향후 업그레이드에는 필요하지 않습니다.

자세한 내용은 [문제 480328](https://gitlab.com/gitlab-org/gitlab/-/issues/480328)을 참조하세요.

### GitLab 17.3 {#from-gitlab-173}

GitLab 17.3에서 업그레이드할 때 마이그레이션 실패.

17.3에서 17.4로 업그레이드할 때 오류가 발생할 가능성이 약간 있습니다. 마이그레이션 프로세스 중에 다음과 같은 오류 메시지가 표시될 수 있습니다:

```shell
main: == [advisory_lock_connection] object_id: 127900, pg_backend_pid: 76263
main: == 20240812040748 AddUniqueConstraintToRemoteDevelopmentAgentConfigs: migrating
main: -- transaction_open?(nil)
main:    -> 0.0000s
main: -- view_exists?(:postgres_partitions)
main:    -> 0.0181s
main: -- index_exists?(:remote_development_agent_configs, :cluster_agent_id, {:name=>"index_remote_development_agent_configs_on_unique_agent_id", :unique=>true, :algorithm=>:concurrently})
main:    -> 0.0026s
main: -- execute("SET statement_timeout TO 0")
main:    -> 0.0004s
main: -- add_index(:remote_development_agent_configs, :cluster_agent_id, {:name=>"index_remote_development_agent_configs_on_unique_agent_id", :unique=>true, :algorithm=>:concurrently})
main: -- execute("RESET statement_timeout")
main:    -> 0.0002s
main: == [advisory_lock_connection] object_id: 127900, pg_backend_pid: 76263
rake aborted!
StandardError: An error has occurred, all later migrations canceled:

PG::UniqueViolation: ERROR:  could not create unique index "index_remote_development_agent_configs_on_unique_agent_id"
DETAIL:  Key (cluster_agent_id)=(1000141) is duplicated.
```

이 오류는 마이그레이션이 `cluster_agent_id` 열에 `remote_development_agent_configs` 테이블의 고유 제약 조건을 추가하지만 여전히 중복 항목이 있기 때문에 발생합니다. 이전 마이그레이션은 이러한 중복을 제거해야 하지만, 드문 경우 두 마이그레이션 사이에 새 중복이 삽입될 수 있습니다.

이 문제를 안전하게 해결하려면 다음 단계를 따르세요:

1. 마이그레이션이 실행 중인 Rails 콘솔을 엽니다.
1. Rails 콘솔에서 다음 스크립트를 실행합니다.
1. 마이그레이션을 다시 실행하면 성공적으로 완료되어야 합니다.

```ruby
# Get the IDs to keep for each cluster_agent_id; if there are duplicates, only the row with the latest updated_at will be kept.
latest_ids = ::RemoteDevelopment::RemoteDevelopmentAgentConfig.select("DISTINCT ON (cluster_agent_id) id")
  .order("cluster_agent_id, updated_at DESC")
  .map(&:id)

# Get the list of remote_development_agent_configs to be removed.
agent_configs_to_remove = ::RemoteDevelopment::RemoteDevelopmentAgentConfig.where.not(id: latest_ids)

# Delete all duplicated agent_configs.
agent_configs_to_remove.delete_all
```

### GitLab 17.4 {#from-gitlab-174}

17.4에서 17.5로 업그레이드할 때 백그라운드 작업 마이그레이션 실패.

17.4에서 17.5로 업그레이드할 때 제거된 백그라운드 데이터 마이그레이션과 관련된 Sidekiq 작업의 오류를 볼 수 있습니다. 오류 메시지는 다음과 같습니다. `uninitialized constant Gitlab::BackgroundMigration::SetProjectVulnerabilityCount`.

이 오류는 결국 스스로 사라지지만 Rails 콘솔에서 다음 스크립트를 실행하여 오류를 보지 않도록 할 수도 있습니다:

```ruby
Gitlab::Database::BackgroundMigration::BatchedMigration.for_configuration(
  :gitlab_main, 'SetProjectVulnerabilityCount', :project_settings, :project_id, []
).delete_all
```

### GitLab 17.5 {#from-gitlab-175}

GitLab 17.5에서 업그레이드할 때 마이그레이션 실패.

17.5에서 17.6으로 업그레이드할 때 오류가 발생할 가능성이 약간 있습니다. 마이그레이션 프로세스 중에 다음과 같은 오류 메시지가 표시될 수 있습니다:

```shell
rake aborted!
StandardError: An error has occurred, all later migrations canceled:

PG::CheckViolation: ERROR: new row for relation "ci_deleted_objects" violates check constraint "check_98f90d6c53"
```

이 오류는 마이그레이션이 `ci_deleted_objects` 테이블에서 일부 행을 업데이트하려고 시도하지만 필수 확인 제약 조건에 대한 값이 누락된 오래된 레코드일 수 있기 때문에 발생합니다.

이 문제를 안전하게 해결하려면 다음 단계를 따르세요:

1. 확인 제약 조건의 영향을 받는 레코드를 수정하려면 다음 마이그레이션만 실행합니다.
1. 마이그레이션을 다시 실행하면 성공적으로 완료되어야 합니다.

   ```shell
   gitlab-rake db:migrate:up:ci VERSION=20241028085044
   ```

## 17.11.0으로 업그레이드 {#upgrades-to-17110}

- 데이터베이스 마이그레이션이 오래 실행되고 과도한 CPU를 사용하는 [알려진 문제](https://gitlab.com/gitlab-org/gitlab/-/issues/537325)를 방지하려면 GitLab 17.11.3 이상으로 업데이트하세요.

### 새 암호화 시크릿 {#new-encryption-secrets}

GitLab 17.8에서는 새 암호화 프레임워크를 지원하기 위해 3개의 새로운 시크릿이 추가되었습니다(17.9에서 사용되기 시작):

- `active_record_encryption_primary_key`
- `active_record_encryption_deterministic_key`
- `active_record_encryption_key_derivation_salt`

다중 노드 구성이 있는 경우 [이러한 시크릿이 모든 노드에서 동일한지 확인](#unify-new-encryption-secrets)해야 합니다.

### Geo 설치 17.11.0 {#geo-installations-17110}

- GitLab 버전 17.11부터 18.1까지는 보조 Geo 사이트에서 프록시된 Git 작업이 HTTP 500 오류로 실패하는 알려진 문제가 있습니다. 이 문제를 해결하려면 GitLab 17.11.5 이상으로 업그레이드하세요.

## 17.10.0으로 업그레이드 {#upgrades-to-17100}

- GitLab 17.10으로 업그레이드할 때 러너 태그가 누락됨, [문제 524402](https://gitlab.com/gitlab-org/gitlab/-/issues/524402) 참조. 먼저 GitLab 17.6으로 업그레이드하면 이 문제를 피할 수 있습니다. 버그는 GitLab 17.11에서 수정되었습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 17.8                    |  17.8.0 - 17.8.6        | 17.8.7   |
  | 17.9                    |  17.9.0 - 17.9.4        | 17.9.5   |
  | 17.10                   |  17.10.0 - 17.10.4      | 17.10.5  |

  17.5에서 표에 언급된 패치 릴리스보다 오래된 버전을 통해 업그레이드할 때 러너 태그 테이블이 비워질 가능성이 있습니다.

  러너 태그 테이블을 확인하려면 `ci` 데이터베이스에서 다음 PostgreSQL 쿼리를 실행하여 영향을 받는지 확인하세요:

  ```sql
  SELECT 'OK, ci_runner_taggings is populated.' FROM ci_runner_taggings LIMIT 1;
  ```

  쿼리가 `OK, ci_runner_taggings is populated.` 대신 빈 결과를 반환하면 관련 문제의 [해결 방법](https://gitlab.com/gitlab-org/gitlab/-/issues/524402#workaround)을 참조하세요.

### 새 암호화 시크릿 {#new-encryption-secrets-1}

GitLab 17.8에서는 새 암호화 프레임워크를 지원하기 위해 3개의 새로운 시크릿이 추가되었습니다(17.9에서 사용되기 시작):

- `active_record_encryption_primary_key`
- `active_record_encryption_deterministic_key`
- `active_record_encryption_key_derivation_salt`

다중 노드 구성이 있는 경우 [이러한 시크릿이 모든 노드에서 동일한지 확인](#unify-new-encryption-secrets)해야 합니다.

### Geo 설치 17.10.0 {#geo-installations-17100}

- GitLab 버전 17.10부터 18.1까지는 보조 Geo 사이트에서 프록시된 Git 작업이 HTTP 500 오류로 실패하는 알려진 문제가 있습니다. 이 문제를 해결하려면 GitLab 17.11.5 이상으로 업그레이드하세요.

## 17.9.0으로 업그레이드 {#upgrades-to-1790}

- GitLab 17.9로 업그레이드할 때 러너 태그가 누락됨, [문제 524402](https://gitlab.com/gitlab-org/gitlab/-/issues/524402) 참조. 먼저 GitLab 17.6으로 업그레이드하면 이 문제를 피할 수 있습니다. 버그는 GitLab 17.11에서 수정되었습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 17.8                    |  17.8.0 - 17.8.6        | 17.8.7   |
  | 17.9                    |  17.9.0 - 17.9.4        | 17.9.5   |
  | 17.10                   |  17.10.0 - 17.10.4      | 17.10.5  |

  17.5에서 표에 언급된 패치 릴리스보다 오래된 버전을 통해 업그레이드할 때 러너 태그 테이블이 비워질 가능성이 있습니다.

  러너 태그 테이블을 확인하려면 `ci` 데이터베이스에서 다음 PostgreSQL 쿼리를 실행하여 영향을 받는지 확인하세요:

  ```sql
  SELECT 'OK, ci_runner_taggings is populated.' FROM ci_runner_taggings LIMIT 1;
  ```

  쿼리가 `OK, ci_runner_taggings is populated.` 대신 빈 결과를 반환하면 관련 문제의 [해결 방법](https://gitlab.com/gitlab-org/gitlab/-/issues/524402#workaround)을 참조하세요.

### 새 암호화 시크릿 {#new-encryption-secrets-2}

GitLab 17.8에서는 새 암호화 프레임워크를 지원하기 위해 3개의 새로운 시크릿이 추가되었습니다(17.9에서 사용되기 시작):

- `active_record_encryption_primary_key`
- `active_record_encryption_deterministic_key`
- `active_record_encryption_key_derivation_salt`

다중 노드 구성이 있는 경우 [이러한 시크릿이 모든 노드에서 동일한지 확인](#unify-new-encryption-secrets)해야 합니다.

## 17.8.0으로 업그레이드 {#upgrades-to-1780}

- GitLab 17.8로 업그레이드할 때 마이그레이션 실패.

  17.8로 업그레이드할 때 오류가 발생할 가능성이 약간 있습니다. 마이그레이션 프로세스 중에 다음과 같은 오류 메시지가 표시될 수 있습니다:

  ```shell
  ERROR:  duplicate key value violates unique constraint "work_item_types_pkey"
  DETAIL:  Key (id)=(1) already exists.
  ```

  오류를 생성하는 마이그레이션은 `db/post_migrate/20241218223002_fix_work_item_types_id_column_values.rb`입니다.

  이 오류는 일부 경우 `work_item_types` 테이블의 레코드가 애플리케이션에 추가된 순서와 동일한 순서로 데이터베이스에 생성되지 않았기 때문에 발생합니다.

  이 문제를 안전하게 해결하려면 다음 단계를 따르세요:

  1. 17.8로 업그레이드를 시도할 때 이 오류가 발생한 경우에만 수행합니다. `gitlab_main` 데이터베이스에서 다음 SQL 쿼리를 실행합니다:

      ```sql
      UPDATE work_item_types set id = (id * 10);
      ```

  1. 실패한 마이그레이션을 다시 실행합니다. 이제 성공해야 합니다.

- GitLab 17.8로 업그레이드할 때 러너 태그가 누락됨, [문제 524402](https://gitlab.com/gitlab-org/gitlab/-/issues/524402) 참조.

  먼저 GitLab 17.6으로 업그레이드하면 이 문제를 피할 수 있습니다. 버그는 GitLab 17.11에서 수정되었습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 17.8                    |  17.8.0 - 17.8.6        | 17.8.7   |
  | 17.9                    |  17.9.0 - 17.9.4        | 17.9.5   |
  | 17.10                   |  17.10.0 - 17.10.4      | 17.10.5  |

  17.5에서 표에 언급된 패치 릴리스보다 오래된 버전을 통해 업그레이드할 때 러너 태그 테이블이 비워질 가능성이 있습니다.

  러너 태그 테이블을 확인하려면 `ci` 데이터베이스에서 다음 PostgreSQL 쿼리를 실행하여 영향을 받는지 확인하세요:

  ```sql
  SELECT 'OK, ci_runner_taggings is populated.' FROM ci_runner_taggings LIMIT 1;
  ```

  쿼리가 `OK, ci_runner_taggings is populated.` 대신 빈 결과를 반환하면 관련 문제의 [해결 방법](https://gitlab.com/gitlab-org/gitlab/-/issues/524402#workaround)을 참조하세요.

### 새 암호화 시크릿 {#new-encryption-secrets-3}

GitLab 17.8에서는 새 암호화 프레임워크를 지원하기 위해 3개의 새로운 시크릿이 추가되었습니다(17.9에서 사용되기 시작):

- `active_record_encryption_primary_key`
- `active_record_encryption_deterministic_key`
- `active_record_encryption_key_derivation_salt`

다중 노드 구성이 있는 경우 [이러한 시크릿이 모든 노드에서 동일한지 확인](#unify-new-encryption-secrets)해야 합니다.

### GitLab 에이전트 서버 for Kubernetes 변경 {#change-to-the-gitlab-agent-server-for-kubernetes}

GitLab 17.8.0에서 GitLab 에이전트 서버 for Kubernetes(KAS)는 GitLab Linux 패키지(Omnibus) 및 Docker 설치에서 기본 설정으로 시작되지 않습니다.

이 문제를 해결하려면 `/etc/gitlab/gitlab.rb`을(를) 편집하세요:

```ruby
gitlab_kas['env'] = { 'OWN_PRIVATE_API_URL' => 'grpc://127.0.0.1:8155' }
```

다중 노드 설치는 [설명서](../../administration/clusters/kas.md)에 설명된 설정을 사용해야 합니다.

### Workhorse의 S3 객체 스토리지 업로드 변경 {#change-to-s3-object-storage-uploads-in-workhorse}

Workhorse의 S3 객체 스토리지 업로드는 이제 [AWS SDK v2 for Go](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/164597)만 사용합니다. `workhorse_use_aws_sdk_v2` 기능 플래그가 제거되었습니다. AWS SDK v2 [`Accept-Encoding: identity`를 설정하고 서명된 헤더로 포함합니다](https://github.com/aws/aws-sdk-go-v2/issues/2848). 그러나 Cloudflare와 같은 일부 프록시 서비스는 [이 헤더를 변경하여 서명 불일치 오류를 유발합니다](https://gitlab.com/gitlab-org/gitlab/-/issues/492973#note_2312726631). [SignatureDoesNotMatch 오류](https://repost.aws/knowledge-center/s3-presigned-url-signature-mismatch)가 표시되면 프록시 서버에서 서명된 HTTP 헤더를 변경하거나 제거하지 않는지 확인하세요.

### 17.5에서 17.8로 업그레이드 {#175-to-178-upgrade}

- GitLab 17.5에서 17.8로 업그레이드할 때 백그라운드 마이그레이션이 `group_type_ci_runner_machines` 테이블에 삽입하거나 업데이트하는 중 실패합니다.

  UI에서 마이그레이션 경로 `BackfillCiRunnerMachinesPartitionedTable: ci_runner_machines`은 진행 `0.00%` 및 상태 `failed`을(를) 표시합니다. 로그의 해당 오류에는 외래 키 제약 조건 오류가 포함됩니다.

  ```shell
  ERROR:  insert or update on table "group_type_ci_runner_machines_" violates foreign key constraint "fk_rails_"
  ```

  이 오류를 해결하려면 UI에서 마이그레이션을 초기화합니다.

## 17.7.0으로 업그레이드 {#upgrades-to-1770}

- Git 2.47.0 이상이 Gitaly에 필요합니다. 자체 컴파일된 설치의 경우 [Gitaly에서 제공하는 Git 버전](../../install/self_compiled/_index.md#git)을 사용해야 합니다.
- FIPS Linux 패키지는 이제 시스템 Libgcrypt를 사용합니다. 단, AmazonLinux 2용 FIPS Linux 패키지는 예외입니다. 이전 버전의 FIPS Linux 패키지는 일반 Linux 패키지에서 사용하는 동일한 Libgcrypt를 사용했으며, 이는 버그였습니다. 자세한 내용은 FIPS에 대한 GitLab 개발 설명서를 참조하세요.
- Linux `gitlab-runner` 패키지는 `gitlab-runner-helper-images`를 새로운 필수 종속성으로 구분했습니다. `gitlab-runner` 패키지를 수동으로 업그레이드하기 위해 설치하는 경우 [도우미 이미지를 수동으로 다운로드](https://docs.gitlab.com/runner/install/linux-manually/#download)해야 합니다.

### OpenSSL 3 업그레이드 {#openssl-3-upgrade}

> [!note]
> GitLab 17.7로 업그레이드하기 전에 [OpenSSL 3 가이드](https://docs.gitlab.com/omnibus/settings/ssl/openssl_3/)를 사용하여 외부 통합의 호환성을 확인하고 평가합니다.

- Linux 패키지는 OpenSSL을 v1.1.1w에서 v3.0.0으로 업그레이드합니다.
- Cloud Native GitLab(CNG)은 이미 GitLab 16.7.0에서 OpenSSL 3으로 업그레이드했습니다. Cloud Native GitLab을 사용 중인 경우 조치가 필요하지 않습니다. 그러나 [Cloud Native Hybrid](../../administration/reference_architectures/_index.md#infrastructure-and-services) 설치는 Gitaly와 같은 상태 저장 구성 요소에 Linux 패키지를 사용합니다. 이러한 구성 요소의 경우, 다음 토론의 보안 수준 변경 사항과 함께 사용하는 TLS 버전, 암호 및 인증서를 확인해야 합니다.

OpenSSL 3으로 업그레이드하면:

- GitLab은 모든 나가는 TLS 연결과 들어오는 TLS 연결에 TLS 1.2 이상이 필요합니다.
- TLS/SSL 인증서는 최소 112비트의 보안을 가져야 합니다. 2048비트보다 짧은 RSA, DSA, DH 키 및 224비트보다 짧은 ECC 키는 금지됩니다.

LDAP 및 Webhook 서버와 같은 오래된 서비스는 여전히 TLS 1.1을 사용할 수 있습니다. 그러나 TLS 1.0과 1.1은 수명이 다했으며 더 이상 안전한 것으로 간주되지 않습니다. GitLab은 TLS 1.0 또는 1.1을 사용하는 서비스에 `no protocols available` 오류 메시지로 연결하지 못합니다.

또한 OpenSSL 3는 [기본 보안 수준을 레벨 1에서 2로 증가](https://docs.openssl.org/3.0/man3/SSL_CTX_set_security_level/#default-callback-behaviour)시켜 보안 비트의 최소 수를 80에서 112로 올렸습니다. 결과적으로 2048비트 미만의 RSA 및 DSA 키와 224비트 미만의 ECC 키로 서명된 인증서는 금지됩니다.

GitLab은 불충분한 비트로 서명된 인증서를 사용하는 서비스에 `certificate key too weak` 오류 메시지로 연결하지 못합니다. 자세한 내용은 [인증서 요구 사항](../../security/tls_support.md#certificate-requirements)을 참조하세요.

Linux 패키지와 함께 제공되는 모든 구성 요소는 OpenSSL 3과 호환됩니다. 따라서 GitLab 패키지의 일부가 아니며 ["외부"](https://docs.gitlab.com/omnibus/settings/ssl/openssl_3/#identifying-external-integrations)인 서비스 및 통합만 확인하면 됩니다.

SSH 키는 이 업그레이드의 영향을 받지 않습니다. OpenSSL은 SSH가 아닌 TLS에 대한 보안 요구 사항을 설정합니다. [OpenSSH](https://www.openssh.org/) 및 [`gitlab-sshd`](../../administration/operations/gitlab_sshd.md)는 허용된 암호화 알고리즘에 대한 자체 구성 설정이 있습니다.

자세한 내용은 [GitLab 설치 보안 설명서](../../security/_index.md)를 확인하세요.

## 17.5.0으로 업그레이드 {#upgrades-to-1750}

> [!note]
> OpenSSL 3 업그레이드가 GitLab 17.7.0으로 연기되었습니다.

- GitLab Runner 분산 캐시에 대한 S3 객체 스토리지 액세스는 이제 MinIO 클라이언트 대신 [AWS SDK v2 for Go](https://gitlab.com/gitlab-org/gitlab-runner/-/merge_requests/4987)에 의해 처리됩니다. `FF_USE_LEGACY_S3_CACHE_ADAPTER` [GitLab Runner 기능 플래그](https://docs.gitlab.com/runner/configuration/feature-flags/)를 `true`로 설정하여 MinIO 클라이언트를 다시 활성화할 수 있습니다.
- Gitaly가 GitLab을 인증하는 데 사용하는 토큰은 이제 [자체 설정](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8688)입니다. 이는 Gitaly가 GitLab Rails 및 Shell 레시피를 실행하고 셸 디렉터리 내의 기본 시크릿 파일을 채울 필요가 없으며 자체 시크릿 파일을 가질 수 있음을 의미합니다. 일부 사용자 지정 환경은 시크릿 불일치를 방지하기 위해 [인증 구성을 업데이트](../../administration/gitaly/configure_gitaly.md#configure-authentication)해야 할 수 있습니다.

## 17.4.0으로 업그레이드 {#upgrades-to-1740}

- GitLab 17.4부터 새 GitLab 설치에는 ID 열에 관한 다른 데이터베이스 스키마가 있습니다.
  - 이전의 모든 정수(32비트) ID 열(예: `id`, `%_id`, `%_ids`)은 이제 `bigint`(64비트)로 생성됩니다.
  - 기존 설치는 데이터베이스 마이그레이션이 이 변경을 수행하기 위해 제공될 때 나중에 32비트에서 64비트 정수로 마이그레이션됩니다.
  - 업그레이드를 테스트하기 위해 새 GitLab 환경을 구축하는 경우, GitLab 17.3 이상으로 설치하여 기존 환경과 동일한 정수 유형을 가져옵니다. 그런 다음 나중에 릴리스로 업그레이드하여 기존 환경과 동일한 데이터베이스 마이그레이션을 실행할 수 있습니다. 새 환경으로 백업에서 복원하는 경우는 필요하지 않습니다. 데이터베이스 복원은 기존 데이터베이스 스키마 정의를 제거하고 백업의 일부로 저장된 정의를 사용합니다.
- Git 2.46.0 이상이 Gitaly에 필요합니다. 자체 컴파일된 설치의 경우 [Gitaly에서 제공하는 Git 버전](../../install/self_compiled/_index.md#git)을 사용해야 합니다.
- Workhorse의 S3 객체 스토리지 업로드는 이제 [AWS SDK v2 for Go](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/164597)를 사용하여 기본적으로 처리됩니다. S3 객체 스토리지 업로드에 문제가 발생하면 `workhorse_use_aws_sdk_v2` [기능 플래그](../../administration/feature_flags/_index.md#enable-or-disable-the-feature)를 비활성화하여 v1로 다운그레이드할 수 있습니다.
- GitLab 17.4로 업그레이드하면 Web IDE에 대한 OAuth 애플리케이션이 생성됩니다. GitLab 서버의 `GitLab.rb` 파일의 외부 URL 구성에 대문자가 포함되어 있으면 Web IDE가 로드되지 않을 수 있습니다. 이 문제를 해결하려면 [OAuth 콜백 URL 업데이트](../../user/project/web_ide/_index.md#update-the-oauth-callback-url)를 참조하세요.
- [RFC 7540](https://datatracker.ietf.org/doc/html/rfc7540#section-3.3)에 따라 Gitaly 및 Praefect는 ALPN을 지원하지 않는 TLS 연결을 거부합니다. TLS가 활성화된 Praefect 앞에 로드 밸런서를 사용하는 경우 ALPN이 사용되지 않으면 `FAIL: 14:connections to all backends failing` 오류가 발생할 수 있습니다. Praefect 환경에서 `GRPC_ENFORCE_ALPN_ENABLED=false`을(를) 설정하여 이 적용을 비활성화할 수 있습니다. Linux 패키지를 사용하는 경우 `/etc/gitlab/gitlab.rb`을(를) 편집하세요:

  ```ruby
  praefect['env'] = { 'GRPC_ENFORCE_ALPN_ENABLED' => 'false' }
  ```

  그런 다음 `gitlab-ctl reconfigure`을(를) 실행합니다.

  ALPN 적용이 [GitLab 17.5.5 및 기타 버전](../../administration/gitaly/praefect/configure.md#alpn-enforcement)에서 다시 비활성화되었습니다. 해당 버전 중 하나로 업그레이드하면 `GRPC_ENFORCE_ALPN_ENABLED`을(를) 설정할 필요가 없습니다.

## 17.3.0으로 업그레이드 {#upgrades-to-1730}

- Git 2.45.0 이상이 Gitaly에 필요합니다. 자체 컴파일된 설치의 경우 [Gitaly에서 제공하는 Git 버전](../../install/self_compiled/_index.md#git)을 사용해야 합니다.

### Geo 설치 17.3.0 {#geo-installations-1730}

- 보조 사이트의 Geo 복제 세부 정보 페이지는 Geo 복제가 작동하는 경우에도 비어 있는 것으로 나타나며 [문제 468509](https://gitlab.com/gitlab-org/gitlab/-/issues/468509)를 참조하세요. 알려진 해결 방법이 없습니다. 버그가 GitLab 17.4에서 수정되었습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  16.11.5 - 16.11.10     | 없음     |
  | 17.0                    |  모두                    | 17.0.7   |
  | 17.1                    |  모두                    | 17.1.7   |
  | 17.2                    |  모두                    | 17.2.5   |
  | 17.3                    |  모두                    | 17.3.1   |

## 17.2.1로 업그레이드 {#upgrades-to-1721}

- GitLab 17.2.1로의 업그레이드는 [데이터베이스의 알 수 없는 시퀀스](https://gitlab.com/gitlab-org/gitlab/-/issues/474293) 때문에 실패할 수 있습니다. 이 문제는 GitLab 17.2.2에서 수정되었습니다.
- [GitLab 17.2.1로의 업그레이드가 오류로 실패할 수 있습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/473337):

  ```plaintext
  PG::DependentObjectsStillExist: ERROR: cannot drop desired object(s) because other objects depend on them
  ```

  [이 문제에 설명된 대로](https://gitlab.com/gitlab-org/gitlab/-/issues/474525#note_2045274993) 이 데이터베이스 시퀀스 소유권 문제는 GitLab 17.2.1에서 수정되었습니다. 그러나 17.2.0의 마이그레이션이 완료되지 않았지만 Linux 패키지가 형식이 잘못된 JSON 파일로 인해 17.2.1 이상으로의 업그레이드를 방지하는 경우 이를 발생할 수 있습니다. 예를 들어 이 오류가 표시될 수 있습니다:

  ```plaintext
  Malformed configuration JSON file found at /opt/gitlab/embedded/nodes/gitlab.example.com.json.
  This usually happens when your last run of `gitlab-ctl reconfigure` didn't complete successfully.
  This file is used to check if any of the unsupported configurations are enabled,
  and hence require a working reconfigure before upgrading.
  Please run `sudo gitlab-ctl reconfigure` to fix it and try again.
  ```

  현재 해결 방법은 다음과 같습니다:

  1. `/opt/gitlab/embedded/nodes`에서 JSON 파일을 제거합니다:

     ```shell
     rm /opt/gitlab/embedded/nodes/*.json
     ```

  1. GitLab 17.2.1 이상으로 업그레이드합니다.

### Geo 설치 17.2.1 {#geo-installations-1721}

- GitLab 16.11부터 GitLab 17.2까지 누락된 PostgreSQL 인덱스로 인해 높은 CPU 사용량, 느린 작업 아티팩트 확인 진행률 및 느리거나 시간 초과 Geo 메트릭 상태 업데이트가 발생할 수 있습니다. 인덱스가 GitLab 17.3에서 추가되었습니다. 인덱스를 수동으로 추가하려면 [Geo 문제 해결 - 작업 아티팩트 확인 중 주 사이트의 높은 CPU 사용량](../../administration/geo/replication/troubleshooting/common.md#high-cpu-usage-on-primary-during-object-verification)을 참조하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  모두                    | 없음     |
  | 17.0                    |  모두                    | 17.0.7   |
  | 17.1                    |  모두                    | 17.1.7   |
  | 17.2                    |  모두                    | 17.2.5   |

- 보조 사이트의 Geo 복제 세부 정보 페이지는 Geo 복제가 작동하는 경우에도 비어 있는 것으로 나타나며 [문제 468509](https://gitlab.com/gitlab-org/gitlab/-/issues/468509)를 참조하세요. 알려진 해결 방법이 없습니다. 버그가 GitLab 17.4에서 수정되었습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  16.11.5 - 16.11.10     | 없음     |
  | 17.0                    |  모두                    | 17.0.7   |
  | 17.1                    |  모두                    | 17.1.7   |
  | 17.2                    |  모두                    | 17.2.5   |
  | 17.3                    |  모두                    | 17.3.1   |

## 17.1.0으로 업그레이드 {#upgrades-to-1710}

- 신뢰할 수 없는 `extern_uid` 비트버킷 ID를 삭제했습니다. 자세한 내용은 [문제 452426](https://gitlab.com/gitlab-org/gitlab/-/issues/452426)을(를) 참조하세요.
- 기본 [변경 로그](../../user/project/changelogs.md) 템플릿은 GitLab 관련 참조 대신 전체 URL로 링크를 생성합니다. 자세한 내용은 [머지 리퀘스트 155806](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/155806)을(를) 참조하세요.
- Git 2.44.0 이상이 Gitaly에 필요합니다. 자체 컴파일된 설치의 경우 [Gitaly에서 제공하는 Git 버전](../../install/self_compiled/_index.md#git)을 사용해야 합니다.
- GitLab 17.1.0 또는 17.1.1로 업그레이드하거나 GitLab 17.0에서 미완료 백그라운드 마이그레이션이 있으면 마이그레이션 실행 시 실패할 수 있습니다. 이는 버그 때문입니다. [문제 468875](https://gitlab.com/gitlab-org/gitlab/-/issues/468875)는 GitLab 17.1.2로 수정되었습니다.

### 오래 실행되는 파이프라인 메시지 데이터 변경 {#long-running-pipeline-messages-data-change}

GitLab 17.1은 `ci_pipeline_messages` 테이블에 많은 레코드가 있는 대규모 GitLab 인스턴스의 필수 중지입니다.

더 큰 GitLab 인스턴스에서 데이터 변경은 완료하는 데 많은 시간이 걸릴 수 있으며, 시간당 150만~200만 레코드 처리 속도입니다. 인스턴스가 영향을 받는 경우:

1. 17.1로 업그레이드합니다.
1. [모든 배치 마이그레이션이 성공적으로 완료되었는지 확인](../background_migrations.md#check-for-pending-database-background-migrations).
1. 17.2 또는 17.3으로 업그레이드합니다.

영향을 받는지 확인하려면:

1. [데이터베이스 콘솔](../../administration/troubleshooting/postgresql.md#start-a-database-console) 시작
1. 실행:

   ```sql
   SELECT relname as table,n_live_tup as rows FROM pg_stat_user_tables
   WHERE relname='ci_pipeline_messages' and n_live_tup>1500000;
   ```

1. 쿼리가 `ci_pipeline_messages`의 개수로 출력을 반환하면 인스턴스가 이 필수 중지의 임계값을 충족합니다. `0 rows`를 보고하는 인스턴스는 17.1 업그레이드 중지를 건너뛸 수 있습니다.

GitLab 17.1은 [배치 백그라운드 마이그레이션](../background_migrations.md#check-for-pending-database-background-migrations)을 도입했으므로 `ci_pipeline_messages` 테이블의 모든 레코드는 [올바른 파티셔닝 키](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/153391)를 갖습니다. CI 테이블 파티셔닝은 대량의 CI 데이터가 있는 인스턴스에 대한 성능 개선을 제공할 것으로 예상됩니다.

GitLab 17.2로의 업그레이드는 `Finalize` 마이그레이션을 실행하며, 이는 17.1 백그라운드 마이그레이션이 완료되었는지 확인하고 필요한 경우 17.1 변경을 업그레이드 중에 동기식으로 실행합니다.

GitLab 17.2도 [외래 키 데이터베이스 제약 조건을 추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/158065)하여 파티셔닝 키를 채워야 합니다. 제약 조건은 [검증](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/159571)되며 GitLab 17.3로의 업그레이드의 일부입니다.

17.1이 업그레이드 경로에서 생략되거나 17.1 마이그레이션이 완료되지 않은 경우:

- 업그레이드가 완료되는 동안 영향을 받는 인스턴스의 연장된 다운타임이 있습니다.
- 앞으로 수정하는 것이 안전합니다.
- 환경을 더 빨리 사용할 수 있도록 하기 위해 Rake 작업을 사용하여 마이그레이션을 실행할 수 있습니다:

  ```shell
  sudo gitlab-rake gitlab:background_migrations:finalize[BackfillPartitionIdCiPipelineMessage,ci_pipeline_messages,id,'[]']
  ```

모든 데이터베이스 마이그레이션이 완료될 때까지 GitLab은 `500` 오류를 생성하여 사용할 수 없게 될 가능성이 높으며, 이는 부분적으로 업그레이드된 데이터베이스 스키마와 실행 중인 Sidekiq 및 Puma 프로세스 사이의 비호환성 때문입니다.

Linux 패키지(Omnibus) 또는 Docker 업그레이드는 1시간 후 시간 초과로 실패할 가능성이 높습니다:

```plaintext
FATAL: Mixlib::ShellOut::CommandTimeout: rails_migration[gitlab-rails]
[..]
Mixlib::ShellOut::CommandTimeout: Command timed out after 3600s:
```

이 문제를 해결하려면:

1. 이전 Rake 작업을 실행하여 배치 마이그레이션을 완료합니다.
1. [시간 초과된 작업의 나머지 완료](../package/package_troubleshooting.md#error-command-timed-out-after-3600s). 이 프로세스의 끝에서 Sidekiq 및 Puma는 `500` 오류를 수정하도록 다시 시작됩니다.

업그레이드 경로의 이 조건부 중지에 대한 피드백은 [문제에서](https://gitlab.com/gitlab-org/gitlab/-/issues/503891) 제공할 수 있습니다.

### Geo 설치 17.1.0 {#geo-installations-1710}

- GitLab 16.11부터 GitLab 17.2까지 누락된 PostgreSQL 인덱스로 인해 높은 CPU 사용량, 느린 작업 아티팩트 확인 진행률 및 느리거나 시간 초과 Geo 메트릭 상태 업데이트가 발생할 수 있습니다. 인덱스가 GitLab 17.3에서 추가되었습니다. 인덱스를 수동으로 추가하려면 [Geo 문제 해결 - 작업 아티팩트 확인 중 주 사이트의 높은 CPU 사용량](../../administration/geo/replication/troubleshooting/common.md#high-cpu-usage-on-primary-during-object-verification)을 참조하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  모두                    | 없음     |
  | 17.0                    |  모두                    | 17.0.7   |
  | 17.1                    |  모두                    | 17.1.7   |
  | 17.2                    |  모두                    | 17.2.5   |

- 보조 사이트의 Geo 복제 세부 정보 페이지는 Geo 복제가 작동하는 경우에도 비어 있는 것으로 나타나며 [문제 468509](https://gitlab.com/gitlab-org/gitlab/-/issues/468509)를 참조하세요. 알려진 해결 방법이 없습니다. 버그가 GitLab 17.4에서 수정되었습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  16.11.5 - 16.11.10     | 없음     |
  | 17.0                    |  모두                    | 17.0.7   |
  | 17.1                    |  모두                    | 17.1.7   |
  | 17.2                    |  모두                    | 17.2.5   |
  | 17.3                    |  모두                    | 17.3.1   |

## 17.0.0으로 업그레이드 {#upgrades-to-1700}

### Geo 설치 17.0.0 {#geo-installations-1700}

- GitLab 16.11부터 GitLab 17.2까지 누락된 PostgreSQL 인덱스로 인해 높은 CPU 사용량, 느린 작업 아티팩트 확인 진행률 및 느리거나 시간 초과 Geo 메트릭 상태 업데이트가 발생할 수 있습니다. 인덱스가 GitLab 17.3에서 추가되었습니다. 인덱스를 수동으로 추가하려면 [Geo 문제 해결 - 작업 아티팩트 확인 중 주 사이트의 높은 CPU 사용량](../../administration/geo/replication/troubleshooting/common.md#high-cpu-usage-on-primary-during-object-verification)을 참조하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  모두                    | 없음     |
  | 17.0                    |  모두                    | 17.0.7   |
  | 17.1                    |  모두                    | 17.1.7   |
  | 17.2                    |  모두                    | 17.2.5   |

- 보조 사이트의 Geo 복제 세부 정보 페이지는 Geo 복제가 작동하는 경우에도 비어 있는 것으로 나타나며 [문제 468509](https://gitlab.com/gitlab-org/gitlab/-/issues/468509)를 참조하세요. 알려진 해결 방법이 없습니다. 버그가 GitLab 17.4에서 수정되었습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  16.11.5 - 16.11.10     | 없음     |
  | 17.0                    |  모두                    | 17.0.7   |
  | 17.1                    |  모두                    | 17.1.7   |
  | 17.2                    |  모두                    | 17.2.5   |
  | 17.3                    |  모두                    | 17.3.1   |

## 새 암호화 시크릿 통합 {#unify-new-encryption-secrets}

[GitLab 17.8에서는 3개의 새로운 시크릿을 도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/175154)하여 새 암호화 프레임워크를 지원하고, [이는 GitLab 17.9에서 도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/179559):

- `active_record_encryption_primary_key`
- `active_record_encryption_deterministic_key`
- `active_record_encryption_key_derivation_salt`

다중 노드 구성이 있는 경우 이러한 시크릿이 모든 노드에서 동일한지 확인해야 합니다. 그렇지 않으면 애플리케이션이 시작 시 누락된 시크릿을 자동으로 생성합니다.

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

1. 가능하면 [유지 관리 모드 활성화](../../administration/maintenance_mode/_index.md#enable-maintenance-mode).
1. (GitLab >= 17.9만 해당) `CloudConnector::Keys` 레코드 삭제:

   ```shell
   gitlab-rails runner 'CloudConnector::Keys.delete_all'
   ```

1. 모든 Sidekiq 및 GitLab 애플리케이션 노드에서 암호화 키 및 사용 방법에 대한 정보를 수집합니다.

   GitLab >= 18.0.0, >= 17.11.2, >= 17.10.6 또는 >= 17.9.8에서 실행:

   ```shell
   gitlab-rake gitlab:doctor:encryption_keys
   ```

   다른 버전의 경우 아래 목록의 참조 노드 선택("경우 1")으로 직접 진행할 수 있으며, 아직 암호화된 데이터가 없다고 가정합니다.

   명령 출력을 기반으로 따를 프로세스를 결정합니다:

   - 경우 1: 모든 `Encryption keys usage for <model>`이 `NONE`를 표시하는 경우:
     - Sidekiq 또는 GitLab 애플리케이션 노드를 참조 노드로 선택합니다.
     - `/etc/gitlab/gitlab-secrets.json`을(를) 이 노드에서 다른 모든 노드로 복사합니다.
   - 경우 2: 보고된 모든 키가 동일한 키 ID를 사용하는 경우:
     - 키가 존재하는 노드를 참조 노드로 선택합니다.
     - `/etc/gitlab/gitlab-secrets.json`을(를) 이 노드에서 다른 모든 노드로 복사합니다.

       예를 들어 노드 1이 다음 출력을 제공하는 경우:

       ```shell
       Gathering existing encryption keys:
       - active_record_encryption_primary_key: ID => `bb32`; truncated secret => `bEt...eBU`
       - active_record_encryption_deterministic_key: ID => `445f`; truncated secret => `MJo...yg5`

       [... snipped for brevity ...]

       Encryption keys usage for VirtualRegistries::Packages::Maven::Upstream: NONE
       Encryption keys usage for Ai::ActiveContext::Connection: NONE
       Encryption keys usage for CloudConnector::Keys: NONE
       Encryption keys usage for DependencyProxy::GroupSetting:
       - `bb32` => 8
       Encryption keys usage for Ci::PipelineScheduleInput:
       - `bb32` => 1
       ```

       그리고 노드 2는 다음 출력을 제공합니다(`(UNKNOWN KEY!)`은 단일 키 ID가 사용되는 한 문제없습니다. 예를 들어 `bb32`):

       ```shell
       Gathering existing encryption keys:
       - active_record_encryption_primary_key: ID => `83kf`; truncated secret => `pKq...ikC`
       - active_record_encryption_deterministic_key: ID => `b722`; truncated secret => `Lma...iJ7`

       [... snipped for brevity ...]

       Encryption keys usage for VirtualRegistries::Packages::Maven::Upstream: NONE
       Encryption keys usage for Ai::ActiveContext::Connection: NONE
       Encryption keys usage for CloudConnector::Keys: NONE
       Encryption keys usage for DependencyProxy::GroupSetting:
       - `bb32` (UNKNOWN KEY!) => 8
       Encryption keys usage for Ci::PipelineScheduleInput:
       - `bb32` (UNKNOWN KEY!) => 1
       ```

       이 예제에서는 두 노드에서 사용하는 `bb32` 키를 포함하기 때문에 노드 1을 참조 노드로 선택합니다.
   - 경우 3: 노드 간 동일한 데이터에 다른 키 ID를 사용하는 경우(예: 노드 1이 `-bb32 => 1`을(를) 표시하고 노드 2가 `-83kf => 1`을(를) 표시하는 경우):
     - 이를 위해서는 단일 암호화 키로 모든 데이터를 다시 암호화해야 합니다.
     - 또는 일부 데이터를 잃을 의향이 있는 경우 레코드를 삭제하여 모든 나머지 레코드가 동일한 키 ID를 사용하도록 할 수 있습니다.
     - [GitLab 지원](https://support.gitlab.com/)에 문의하여 도움을 받으세요.

1. 참조 노드가 어느 것인지 결정한 후 참조 노드의 어떤 시크릿을 다른 노드로 복사해야 할지 결정합니다.
1. 참조 노드를 제외한 모든 Sidekiq 및 Rails 노드에서:

   1. [구성 파일](https://docs.gitlab.com/omnibus/settings/backups/#backup-and-restore-configuration-on-a-linux-package-installation) 백업:

      ```shell
      sudo gitlab-ctl backup-etc
      ```

   1. 참조 노드에서 `/etc/gitlab/gitlab-secrets.json`을(를) 복사하고 현재 노드의 같은 이름의 파일을 바꿉니다.
   1. GitLab을 재구성합니다.

      ```shell
      sudo gitlab-ctl reconfigure
      ```

   1. 버전에 따라 다음 명령 중 하나를 사용하여 암호화 키 및 사용 방법을 다시 확인합니다:

      GitLab >= 18.0.0, >= 17.11.2, >= 17.10.6 또는 >= 17.9.8에서 실행:

      ```shell
      gitlab-rake gitlab:doctor:encryption_keys
      ```

      다른 버전의 경우 아직 암호화된 데이터가 없다고 가정하므로 이 확인을 건너뛸 수 있습니다.

      보고된 모든 키 사용은 동일한 키 ID에 대한 것입니다. 예를 들어 노드 1에서:

      ```shell
      Gathering existing encryption keys:
      - active_record_encryption_primary_key: ID => `bb32`; truncated secret => `bEt...eBU`
      - active_record_encryption_deterministic_key: ID => `445f`; truncated secret => `MJo...yg5`

      [... snipped for brevity ...]

      Encryption keys usage for VirtualRegistries::Packages::Maven::Upstream: NONE
      Encryption keys usage for Ai::ActiveContext::Connection: NONE
      Encryption keys usage for CloudConnector::Keys:
      - `bb32` => 1
      Encryption keys usage for DependencyProxy::GroupSetting:
      - `bb32` => 8
      Encryption keys usage for Ci::PipelineScheduleInput:
      - `bb32` => 1
      ```

      예를 들어 노드 2에서(`(UNKNOWN KEY!)` 이번에는 표시되지 않아야 함):

      ```shell
      Gathering existing encryption keys:
      - active_record_encryption_primary_key: ID => `bb32`; truncated secret => `bEt...eBU`
      - active_record_encryption_deterministic_key: ID => `445f`; truncated secret => `MJo...yg5`

      [... snipped for brevity ...]

      Encryption keys usage for VirtualRegistries::Packages::Maven::Upstream: NONE
      Encryption keys usage for Ai::ActiveContext::Connection: NONE
      Encryption keys usage for CloudConnector::Keys:
      - `bb32` => 1
      Encryption keys usage for DependencyProxy::GroupSetting:
      - `bb32` => 8
      Encryption keys usage for Ci::PipelineScheduleInput:
      - `bb32` => 1
      ```

1. 새 Cloud Connector 키 생성:

   GitLab >= 17.10의 경우:

   ```shell
   gitlab-rake cloud_connector:keys:create
   ```

   GitLab 17.9의 경우:

   ```shell
   gitlab-rails runner 'CloudConnector::Keys.create!(secret_key: OpenSSL::PKey::RSA.new(2048).to_pem)'
   ```

1. [유지 관리 모드 비활성화](../../administration/maintenance_mode/_index.md#disable-maintenance-mode).

{{< /tab >}}

{{< tab title="Helm 차트(Kubernetes)" >}}

[공유 시크릿 차트](https://docs.gitlab.com/charts/charts/shared-secrets/)를 비활성화한 경우 [이러한 시크릿을 수동으로 생성](https://docs.gitlab.com/charts/releases/8_0/)해야 합니다.

{{< /tab >}}

{{< /tabs >}}
