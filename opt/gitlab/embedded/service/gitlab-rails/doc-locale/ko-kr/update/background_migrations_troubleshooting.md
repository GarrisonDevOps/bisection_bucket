---
stage: Data Access
group: Database Frameworks
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 배경 마이그레이션 문제 해결
description: 배경 마이그레이션의 문제에 대한 해결책입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

<!-- Linked from `lib/gitlab/database/migrations/batched_background_migration_helpers.rb` -->

## 배경 마이그레이션이 완료되지 않아 데이터베이스 마이그레이션 실패 {#database-migrations-failing-because-of-batched-background-migration-not-finished}

GitLab 버전 14.2 이상으로 업데이트할 때 데이터베이스 마이그레이션이 다음과 같은 메시지로 실패할 수 있습니다:

```plaintext
StandardError: An error has occurred, all later migrations canceled:

Expected batched background migration for the given configuration to be marked as 'finished', but it is 'active':
  {:job_class_name=>"CopyColumnUsingBackgroundMigrationJob",
   :table_name=>"push_event_payloads",
   :column_name=>"event_id",
   :job_arguments=>[["event_id"],
   ["event_id_convert_to_bigint"]]
  }
```

이 오류를 해결하려면:

- [14.2용 버전별 업그레이드 지침](https://archives.docs.gitlab.com/17.3/ee/update/versions/gitlab_14_changes.html#1420)을 따랐다면 [배경 마이그레이션을 수동으로 완료](background_migrations.md#finish-a-failed-migration-manually)하세요.
- 해당 지침을 따르지 않았다면 다음 중 하나를 수행해야 합니다:
  - [롤백 및 업그레이드](#roll-back-and-follow-the-required-upgrade-path)를 수행하여 14.2+로 업데이트하기 전에 필수 버전 중 하나를 거쳐야 합니다.
  - [롤포워드](#roll-forward-and-finish-the-migrations-on-the-upgraded-version)를 수행하여 현재 버전을 유지하면서 배경 마이그레이션이 성공적으로 완료되도록 수동으로 확인합니다.

### 필수 업그레이드 경로를 따라 롤백하기 {#roll-back-and-follow-the-required-upgrade-path}

필수 업그레이드 경로를 따라 롤백하려면:

1. [이전에 설치된 버전으로 롤백 및 복원](../administration/backup_restore/_index.md)하세요.
1. 14.2+로 업데이트하기 전에 14.0.5 또는 14.1로 업데이트하세요.
1. 배경 마이그레이션의 [상태를 확인](background_migrations.md#check-the-status-of-batched-background-migrations)하고 다시 업그레이드를 시도하기 전에 모두 완료된 것으로 표시되었는지 확인하세요. 활성 상태로 표시된 것이 남아있으면 [수동으로 완료](background_migrations.md#finish-a-failed-migration-manually)하세요.

### 업그레이드된 버전에서 마이그레이션을 롤포워드하고 완료하기 {#roll-forward-and-finish-the-migrations-on-the-upgraded-version}

롤포워드 프로세스는 가동 중단이 필요한지 여부에 따라 다릅니다.

#### 가동 중단이 있는 배포의 경우 {#for-a-deployment-with-downtime}

모든 배경 마이그레이션을 실행하는 데 걸리는 시간은 GitLab 설치 규모에 따라 크게 달라질 수 있습니다.

1. 데이터베이스에서 배경 마이그레이션의 [상태를 확인](background_migrations.md#check-the-status-of-batched-background-migrations)하고 상태 쿼리가 행을 반환하지 않을 때까지 적절한 인자로 [수동으로 실행](background_migrations.md#finish-a-failed-migration-manually)하세요.
1. 모든 항목의 상태가 완료된 것으로 표시되면 설치를 위해 마이그레이션을 다시 실행하세요.
1. GitLab 업그레이드에서 [데이터베이스 마이그레이션 완료](../administration/raketasks/maintenance.md#run-incomplete-database-migrations):

   ```plaintext
   sudo gitlab-rake db:migrate
   ```

1. 재구성을 실행하세요:

   ```plaintext
   sudo gitlab-ctl reconfigure
   ```

1. 설치의 업그레이드를 완료하세요.

#### 가동 중단이 없는 배포의 경우 {#for-a-no-downtime-deployment}

실패한 마이그레이션이 배포 후 마이그레이션이므로 업그레이드된 버전의 실행 중인 인스턴스에 남아 있으면서 배경 마이그레이션이 완료될 때까지 기다릴 수 있습니다.

1. 오류 메시지에서 배경 마이그레이션의 [상태를 확인](background_migrations.md#check-the-status-of-batched-background-migrations)하고 완료된 것으로 나열되었는지 확인하세요. 마이그레이션이 여전히 활성 상태이면 다음 중 하나를 수행하세요:
   - 완료될 때까지 기다리세요.
   - [수동으로 완료](background_migrations.md#finish-a-failed-migration-manually)하세요.
1. 설치를 위해 마이그레이션을 다시 실행하여 남은 배포 후 마이그레이션이 완료되도록 하세요.

## 고급 검색 마이그레이션이 중단됨 {#advanced-search-migrations-are-stuck}

보류 중인 문제로 인해 중단된 고급 검색 마이그레이션의 경우 [중단된 마이그레이션 재시도](../integration/advanced_search/elasticsearch.md#retry-a-halted-migration)하세요.

보류 중인 모든 고급 검색 마이그레이션이 완료되기 전에 GitLab을 업그레이드하면 새 버전에서 제거된 보류 중인 마이그레이션은 실행하거나 재시도할 수 없습니다. 이 경우 [인덱스를 처음부터 다시 생성](../integration/elasticsearch/troubleshooting/indexing.md#last-resort-to-recreate-an-index)해야 합니다.

## 오류: `Elasticsearch version not compatible` {#error-elasticsearch-version-not-compatible}

Elasticsearch 또는 OpenSearch 버전이 GitLab과 호환되지 않으면 데이터 손실을 방지하기 위해 인덱싱이 일시 중지되고 이 메시지가 [`elasticsearch.log`](../administration/logs/_index.md#elasticsearchlog)에 기록됩니다.

이 문제를 해결하려면 [Elasticsearch 또는 OpenSearch 버전이 GitLab과 호환되는지 확인](../integration/advanced_search/elasticsearch.md#version-compatibility)하세요.

호환되는 버전을 사용 중이면 [인덱싱 재개](../integration/advanced_search/elasticsearch.md#resume-indexing)하세요.
