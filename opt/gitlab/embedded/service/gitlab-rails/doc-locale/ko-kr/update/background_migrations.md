---
stage: Data Access
group: Database Frameworks
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 업그레이드 전에 마이그레이션 확인
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

## Rake 작업으로 백그라운드 마이그레이션 관리 {#manage-background-migrations-with-rake-tasks}

{{< history >}}

- GitLab 18.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/191722)되었습니다.
- GitLab 18.7에서 [향상됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/211674).
- GitLab 18.9에서 [향상됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/222806).

{{< /history >}}

GitLab은 명령줄에서 백그라운드 마이그레이션을 관리하기 위한 Rake 작업 세트를 제공합니다. 이러한 작업은 다운타임 업그레이드 또는 유지 보수 기간 동안 Admin UI를 사용할 수 없을 때 백그라운드 마이그레이션을 관리해야 하는 GitLab Self-Managed 관리자에게 특히 유용합니다.

모든 Rake 작업은 모든 데이터베이스(main 및 ci)에서 작동하며 통합된 마이그레이션 ID 형식을 사용합니다: `{database}_{id}`. 예를 들어 `main_85`는 main 데이터베이스의 마이그레이션 ID 85를 나타내고, `ci_10`는 ci 데이터베이스의 마이그레이션 ID 10을 나타냅니다.

활성 마이그레이션의 경우 `progress` 열에는 사용 가능할 때 예상 남은 시간이 포함됩니다(예: `42.50% (estimated time remaining: 5 minutes)`).

### 모든 백그라운드 마이그레이션 나열 {#list-all-background-migrations}

모든 데이터베이스에서 배치된 모든 백그라운드 마이그레이션을 보려면:

{{< tabs >}}

{{< tab title="GitLab 18.9 이상" >}}

```shell
sudo gitlab-rake gitlab:background_migrations:list
```

예시 출력:

```plaintext
id      | table_name                       | job_class_name                                | status    | progress
--------|----------------------------------|-----------------------------------------------|-----------|----------------------------------------------------------
main_1  | namespace_settings               | UpdateRequireDpopForManageApiEndpointsToFalse | finished  | 100.00%
main_2  | resource_iteration_events        | BackfillResourceIterationEventsNamespaceId    | finalized | 100.00%
main_3  | identities                       | DeleteTwitterIdentities                       | finalized | 100.00%
main_4  | software_license_policies        | BackfillLicensesOutsideSpdxCatalogue          | finalized | 100.00%
main_5  | security_policies                | BackfillPipelineExecutionPoliciesMetadata     | active    | 42.50% (estimated time remaining: 5 minutes)
ci_1    | ci_runners                       | MarkAdminBotRunnersAsHosted                   | finalized | 100.00%
ci_2    | p_ci_build_trace_metadata        | BackfillUpsertedCiBuildTraceMetadataProjectId | finalized | 100.00%
ci_3    | ci_runners                       | BackfillOrganizationIdOnCiRunners             | active    | 78.30% (estimated time remaining: about 1 hour)
```

{{< /tab >}}

{{< tab title="GitLab 18.8 이하" >}}

```shell
sudo gitlab-rake gitlab:background_migrations:status
```

{{< /tab >}}

{{< /tabs >}}

### 마이그레이션 세부 정보 표시 {#show-migration-details}

특정 마이그레이션에 대한 자세한 정보를 보려면:

```shell
sudo gitlab-rake gitlab:background_migrations:show[<migration_id>]
```

예를 들어:

```shell
sudo gitlab-rake gitlab:background_migrations:show[ci_1]
```

예시 출력:

```plaintext
id                       | ci_1
created_at               | 2025-05-06 22:40:08 UTC
updated_at               | 2025-08-20 22:29:07 UTC
min_value                | 1
max_value                | 30
batch_size               | 1000
sub_batch_size           | 100
interval                 | 120
status                   | finalized
job_class_name           | MarkAdminBotRunnersAsHosted
batch_class_name         | PrimaryKeyBatchingStrategy
table_name               | ci_runners
column_name              | id
job_arguments            | []
total_tuple_count        |
pause_ms                 | 100
max_batch_size           |
started_at               | 2025-05-06 22:40:08 UTC
on_hold_until            |
gitlab_schema            | gitlab_ci
finished_at              | 2025-05-06 22:40:13 UTC
queued_migration_version | 20250505095336
min_cursor               |
max_cursor               |
```

### 마이그레이션 일시 중지 {#pause-a-migration}

활성 백그라운드 마이그레이션을 일시 중지하려면:

```shell
sudo gitlab-rake gitlab:background_migrations:pause[<migration_id>]
```

예를 들어:

```shell
sudo gitlab-rake gitlab:background_migrations:pause[main_85]
```

> [!note]
> `active` 상태인 마이그레이션만 일시 중지할 수 있습니다. 다른 상태의 마이그레이션을 일시 중지하려고 하면 오류가 발생합니다.

### 마이그레이션 재개 {#resume-a-migration}

일시 중지된 백그라운드 마이그레이션을 재개하려면:

```shell
sudo gitlab-rake gitlab:background_migrations:resume[<migration_id>]
```

예를 들어:

```shell
sudo gitlab-rake gitlab:background_migrations:resume[main_85]
```

> [!note]
> `paused` 상태인 마이그레이션만 재개할 수 있습니다. 다른 상태의 마이그레이션을 재개하려고 하면 오류가 발생합니다.

### 마이그레이션 실행 {#execute-a-migration}

{{< history >}}

- GitLab 18.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/211674)되었습니다.

{{< /history >}}

> [!warning]
> 이 작업은 마이그레이션을 포그라운드에서 동기적으로 실행합니다. 마이그레이션은 완료되거나 실패할 때까지 실행됩니다. 대규모 마이그레이션의 경우 상당한 시간이 소요될 수 있으며 데이터베이스 성능에 영향을 미칠 수 있습니다. 가능한 유지 보수 기간 동안 이 작업을 사용합니다.

특정 백그라운드 마이그레이션을 즉시 실행하려면:

```shell
sudo gitlab-rake gitlab:background_migrations:execute[<migration_id>]
```

예를 들어:

```shell
sudo gitlab-rake gitlab:background_migrations:execute[ci_10]
```

예시 출력:

```plaintext
Are you sure you want to execute this migration? yes
Executing background migration `ci_10`...
Done.
```

작업은 실행 전에 확인을 요청합니다. 마이그레이션이 완료되지 않으면 `gitlab:background_migrations:show[<migration_id>]`으로 마이그레이션 상태를 확인하여 자세한 내용을 확인합니다.

### 모든 마이그레이션 실행 {#execute-all-migrations}

{{< history >}}

- GitLab 18.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/211674)되었습니다.

{{< /history >}}

> [!warning]
> 이 작업은 완료되지 않은 모든 마이그레이션을 포그라운드에서 동기적으로 실행합니다. 이는 매우 오래 걸릴 수 있으며 데이터베이스 성능에 크게 영향을 미칠 수 있습니다. 계획된 유지 보수 기간 동안에만 이 작업을 사용합니다. 작업은 개별 마이그레이션이 실패하더라도 계속 진행되지만 출력에서 실패를 보고합니다.

모든 데이터베이스에서 완료되지 않은 모든 백그라운드 마이그레이션을 실행하려면:

```shell
sudo gitlab-rake gitlab:background_migrations:execute_all
```

예시 출력:

<!--
The following codeblock uses extra spaces to avoid the Vale ReferenceLinks test.
Do not remove the two-space nesting.
-->

  ```plaintext
  Are you sure you want to execute all unfinished migrations? yes
  [main] Executing 6 background migrations...
  [main_85]: Start.
  [main_85]: Done.
  [main_86]: Start.
  [main_86]: Done.
  [main_87]: Start.
  [main_87]: Done.
  [main_88]: Start.
  [main_88]: Done.
  [main_89]: Start.
  [main_89]: Done.
  [main_90]: Start.
  [main_90]: Done.
  [ci] Executing 3 background migrations...
  [ci_8]: Start.
  [ci_8]: Done.
  [ci_9]: Start.
  [ci_9]: Done.
  [ci_10]: Start.
  [ci_10]: Done.
  ```

작업:

- 실행 전에 확인을 요청합니다.
- ID 순서대로 마이그레이션을 처리합니다.
- 완료될 때마다 각 마이그레이션의 상태를 보고합니다.
- 일부가 실패하더라도 나머지 마이그레이션 처리를 계속합니다.

### 모든 마이그레이션이 완료될 때까지 기다리기 {#wait-for-all-migrations-to-finish}

{{< history >}}

- GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258378).

{{< /history >}}

모든 데이터베이스에서 완료되지 않은 모든 배치된 백그라운드 마이그레이션이 완료될 때까지 차단하려면:

```shell
sudo gitlab-rake gitlab:background_migrations:wait
```

예시 출력:

```plaintext
Waiting for batched background migrations to finish, checking every 30s...
Still waiting on 1 batched background migration(s):
Database: main
  active | BackfillPipelineExecutionPoliciesMetadata,security_policies,id,[]
All batched background migrations have finished.
```

이 작업은 자동화를 위해 고안되었으며, 예를 들어 현재 버전의 마이그레이션이 다음 업그레이드를 시작하기 전에 완료될 때까지 제로 다운타임 업그레이드를 게이트하는 데 사용됩니다. [모든 마이그레이션 실행](#execute-all-migrations)과 달리 마이그레이션 자체를 실행하지 않습니다. 스케줄러가 처리하는 동안만 해당 상태를 폴링합니다.

작업:

- 구성된 모든 데이터베이스(`main`, `ci` 등)를 확인합니다.
- `paused`, `active` 또는 `finalizing` 상태의 마이그레이션이 남지 않을 때까지 폴링한 다음 `0`로 종료합니다.
- 마이그레이션이 `failed` 상태에 있으면 대기가 이를 해결할 수 없으므로 0이 아닌 상태로 종료합니다. [실패한 배치된 백그라운드 마이그레이션 해결](#resolve-failed-batched-background-migrations)로 먼저 이를 해결합니다.

작업이 폴링하는 빈도를 제어하려면 `BATCHED_MIGRATIONS_WAIT_INTERVAL_SECONDS` 환경 변수를 양의 정수로 설정합니다(기본값 `30`):

```shell
sudo BATCHED_MIGRATIONS_WAIT_INTERVAL_SECONDS=60 gitlab-rake gitlab:background_migrations:wait
```

작업에는 내부 타임아웃이 없습니다. 호출자로부터 총 대기를 제한합니다(예: `timeout` 또는 작업 기한 사용).

작업은 일시적인 데이터베이스 오류를 포착하지 않습니다. 오류가 발생하면 전체 작업을 다시 시도합니다.

## 보류 중인 데이터베이스 백그라운드 마이그레이션 확인 {#check-for-pending-database-background-migrations}

{{< history >}}

- 기능 [플래그](../administration/feature_flags/_index.md) `execute_batched_migrations_on_schedule`는 GitLab 13.12에서 [기본적으로 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/329511).
- GitLab Self-Managed의 경우 관리자가 비활성화하도록 선택할 수 있습니다.

{{< /history >}}

데이터베이스 테이블을 배치로 업데이트하기 위해 GitLab은 배치된 백그라운드 마이그레이션을 사용할 수 있습니다. 이러한 마이그레이션은 GitLab 개발자에 의해 생성되며 업그레이드 시 자동으로 실행됩니다. 그러나 이러한 마이그레이션은 일부 `integer` 데이터베이스 열을 `bigint`로 마이그레이션하는 데 도움이 되도록 범위가 제한되어 있으며, 이는 일부 테이블의 정수 오버플로우를 방지하기 위해 필요합니다.

배치된 백그라운드 마이그레이션은 Sidekiq에 의해 처리되며 격리된 상태에서 실행되므로 마이그레이션이 처리되는 동안 인스턴스는 운영 상태를 유지할 수 있습니다. 그러나 배치된 백그라운드 마이그레이션이 실행되는 동안 많이 사용되는 대규모 인스턴스의 성능이 저하될 수 있습니다. 모든 마이그레이션이 완료될 때까지 [Sidekiq 상태를 적극적으로 모니터링](../administration/admin_area.md#background-jobs)해야 합니다.

이러한 마이그레이션을 완료하는 데 필요한 시간을 줄이려면 `background_migration` 큐에서 작업을 처리할 수 있는 [Sidekiq 작업자](../administration/sidekiq/extra_sidekiq_processes.md)의 수를 늘립니다.

### 배치된 백그라운드 마이그레이션의 상태 확인 {#check-the-status-of-batched-background-migrations}

GitLab UI에서 또는 데이터베이스를 직접 쿼리하여 배치된 백그라운드 마이그레이션의 상태를 확인할 수 있습니다. GitLab을 업그레이드하기 전에 모든 마이그레이션은 `Finished` 상태를 가져야 합니다.

마이그레이션이 완료되지 않고 GitLab을 업그레이드하려고 하면 다음 오류가 표시될 수 있습니다:

```plaintext
Expected batched background migration for the given configuration to be marked
as 'finished', but it is 'active':
```

이 오류가 발생하면 [옵션 검토](background_migrations_troubleshooting.md#database-migrations-failing-because-of-batched-background-migration-not-finished)하여 GitLab 업그레이드에 필요한 배치된 백그라운드 마이그레이션을 완료하는 방법을 확인합니다.

#### GitLab UI에서 {#from-the-gitlab-ui}

전제 조건:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

배치된 백그라운드 마이그레이션의 상태를 확인하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **모니터링** > **백그라운드 마이그레이션**을 선택합니다.
1. **대기 중** 또는 **완료중**을 선택하여 불완전한 마이그레이션을 확인하고, **실패함**를 선택하여 실패한 마이그레이션을 확인합니다.

마이그레이션이 **진행 상황 없음**을 표시하면 마이그레이션이 큐에 대기할 때 GitLab이 테이블 크기를 추정할 수 없어 백분율을 계산할 수 없습니다. 상태가 **활성**이면 마이그레이션이 예상대로 실행 중입니다.

#### 데이터베이스에서 {#from-the-database}

전제 조건:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

배치된 백그라운드 마이그레이션의 상태를 데이터베이스에서 직접 쿼리하려면:

1. `psql` 프롬프트에 로그인합니다(인스턴스의 설치 방법에 따른 지시사항에 따름). 예를 들어 Linux 패키지 설치의 경우 `sudo gitlab-psql`.
1. 배치된 백그라운드 마이그레이션에 대한 세부 정보를 보려면 `psql` 세션에서 이 쿼리를 실행합니다:

   ```sql
   SELECT
     job_class_name,
     table_name,
     column_name,
     job_arguments
   FROM batched_background_migrations
   WHERE status NOT IN(3, 6);
   ```

또는 `gitlab-psql -c "<QUERY>"`으로 쿼리를 래핑하여 배치된 백그라운드 마이그레이션의 상태를 확인할 수 있습니다:

```shell
gitlab-psql -c "SELECT job_class_name, table_name, column_name, job_arguments FROM batched_background_migrations WHERE status NOT IN(3, 6);"
```

쿼리가 0개 행을 반환하면 모든 배치된 백그라운드 마이그레이션이 완료된 것입니다.

### 고급 기능 활성화 또는 비활성화 {#enable-or-disable-advanced-features}

배치된 백그라운드 마이그레이션은 마이그레이션을 사용자 정의하거나 전체적으로 일시 중지할 수 있는 기능 플래그를 제공합니다. 이러한 기능 플래그는 위험을 이해하는 고급 사용자만 비활성화해야 합니다.

#### 배치된 백그라운드 마이그레이션 일시 중지 {#pause-batched-background-migrations}

> [!warning]
> [릴리스된 기능을 비활성화할 때의 위험](../administration/feature_flags/_index.md#risks-when-disabling-released-features)이 있을 수 있습니다. 각 기능의 기록을 참조하여 자세한 내용을 확인합니다.

진행 중인 배치된 백그라운드 마이그레이션을 일시 중지하려면 배치된 백그라운드 마이그레이션 기능을 비활성화합니다. 기능을 비활성화하면 현재 마이그레이션 배치가 완료된 후 기능을 다시 활성화할 때까지 다음 배치의 시작을 대기합니다.

전제 조건:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

다음 데이터베이스 쿼리를 사용하여 현재 배치된 백그라운드 마이그레이션의 상태를 확인합니다:

1. 실행 중인 마이그레이션의 ID를 가져옵니다:

   ```sql
   SELECT
    id,
    job_class_name,
    table_name,
    column_name,
    job_arguments
   FROM batched_background_migrations
   WHERE status NOT IN(3, 6);
   ```

1. 이 쿼리를 실행하여 이전 단계에서 가져온 ID로 `XX`을 바꾸고 마이그레이션의 상태를 확인합니다:

   ```sql
   SELECT
    started_at,
    finished_at,
    finished_at - started_at AS duration,
    min_value,
    max_value,
    batch_size,
    sub_batch_size
   FROM batched_background_migration_jobs
   WHERE batched_background_migration_id = XX
   ORDER BY id DESC
   limit 10;
   ```

1. 몇 분 이내에 쿼리를 여러 번 실행하여 새로운 행이 추가되지 않았는지 확인합니다. 새로운 행이 추가되지 않았으면 마이그레이션이 일시 중지된 것입니다.
1. 마이그레이션이 일시 중지되었음을 확인한 후, `enable` 명령을 사용하여 마이그레이션을 다시 시작하여 준비가 되면 배치를 진행합니다. 대규모 인스턴스에서는 백그라운드 마이그레이션이 각 배치를 완료하는 데 48시간까지 걸릴 수 있습니다.

#### 자동 배치 크기 최적화 {#automatic-batch-size-optimization}

{{< history >}}

- GitLab 13.2에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/60133) [기능 플래그](../administration/feature_flags/_index.md)(`optimize_batched_migrations` 이름). 기본적으로 활성화되어 있습니다.
- GitLab 18.4에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/204173). 기능 플래그 `optimize_batched_migrations`이 제거되었습니다.

{{< /history >}}

> [!warning]
> [릴리스된 기능을 비활성화할 때의 위험](../administration/feature_flags/_index.md#risks-when-disabling-released-features)이 있을 수 있습니다. 이 기능의 기록을 참조하여 자세한 내용을 확인합니다.

배치된 백그라운드 마이그레이션의 처리량을 최대화하려면(시간 단위당 업데이트된 튜플 수 측면에서) 이전 배치가 완료되는 데 걸린 시간에 따라 배치 크기가 자동으로 조정됩니다.

#### 병렬 실행 {#parallel-execution}

배치된 백그라운드 마이그레이션의 실행을 빠르게 하려면 두 개의 마이그레이션이 동시에 실행됩니다.

[GitLab Rails 콘솔에 접근할 수 있는 GitLab 관리자](../administration/feature_flags/_index.md)는 병렬로 실행되는 배치된 백그라운드 마이그레이션의 수를 변경할 수 있습니다:

```ruby
ApplicationSetting.update_all(database_max_running_batched_background_migrations: 4)
```

### 실패한 배치된 백그라운드 마이그레이션 해결 {#resolve-failed-batched-background-migrations}

배치된 백그라운드 마이그레이션이 실패하면 [수정 및 재시도](#fix-and-retry-the-migration)합니다. 마이그레이션이 오류로 인해 계속 실패하면 다음 중 하나를 수행합니다:

- [실패한 마이그레이션을 수동으로 완료](#finish-a-failed-migration-manually)
- [실패한 마이그레이션 완료됨으로 표시](#mark-a-failed-migration-finished)

#### 마이그레이션 수정 및 재시도 {#fix-and-retry-the-migration}

실패한 모든 배치된 백그라운드 마이그레이션은 GitLab의 최신 버전으로 업그레이드하기 위해 해결되어야 합니다. 배치된 백그라운드 마이그레이션의 [상태를 확인](#check-the-status-of-batched-background-migrations)하면 일부 마이그레이션이 **실패함** 탭에 **실패** 상태로 표시될 수 있습니다:

![실패한 배치된 백그라운드 마이그레이션 테이블.](img/batched_background_migrations_failed_v14_3.png)

배치된 백그라운드 마이그레이션이 실패한 이유를 확인하려면 실패 오류 로그를 확인하거나 UI에서 오류 정보를 확인합니다.

전제 조건:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **모니터링** > **백그라운드 마이그레이션**을 선택합니다.
1. **실패함** 탭을 선택합니다. 이는 실패한 배치된 백그라운드 마이그레이션 목록을 표시합니다.
1. 실패한 **마이그레이션**을 선택하여 마이그레이션 매개 변수와 실패한 작업을 확인합니다.
1. **실패한 작업** 아래에서 각 **ID**를 선택하여 작업이 실패한 이유를 확인합니다.

GitLab 고객인 경우 배치된 백그라운드 마이그레이션이 실패한 이유를 디버깅하기 위해 [지원 요청](https://support.gitlab.com/hc/en-us/requests/new)을 여는 것을 고려하세요.

문제를 해결하기 위해 실패한 마이그레이션을 재시도할 수 있습니다.

전제 조건:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **모니터링** > **백그라운드 마이그레이션**을 선택합니다.
1. **실패함** 탭을 선택합니다. 이는 실패한 배치된 백그라운드 마이그레이션 목록을 표시합니다.
1. 재시도 버튼({{< icon name="retry" >}})을 클릭하여 실패한 배치된 백그라운드 마이그레이션을 재시도하도록 선택합니다.

재시도된 배치된 백그라운드 마이그레이션을 모니터링하려면 정기적으로 [배치된 백그라운드 마이그레이션의 상태를 확인](#check-the-status-of-batched-background-migrations)할 수 있습니다.

#### 실패한 마이그레이션을 수동으로 완료 {#finish-a-failed-migration-manually}

오류로 인해 실패한 배치된 백그라운드 마이그레이션을 수동으로 완료하려면 실패 오류 로그 또는 데이터베이스의 정보를 사용합니다:

{{< tabs >}}

{{< tab title="실패 오류 로그에서" >}}

1. 실패 오류 로그를 보고 `An error has occurred, all later migrations canceled` 오류 메시지를 찾습니다:

   ```plaintext
   StandardError: An error has occurred, all later migrations canceled:

   Expected batched background migration for the given configuration to be marked as
   'finished', but it is 'active':
     {:job_class_name=>"CopyColumnUsingBackgroundMigrationJob",
      :table_name=>"push_event_payloads",
      :column_name=>"event_id",
      :job_arguments=>[["event_id"],
      ["event_id_convert_to_bigint"]]
     }
   ```

1. 다음 명령을 실행하여 꺾인괄호의 값을 올바른 인수로 바꿉니다:

   ```shell
   sudo gitlab-rake gitlab:background_migrations:finalize[<job_class_name>,<table_name>,<column_name>,'<job_arguments>']
   ```

   `[["id"],["id_convert_to_bigint"]]`과 같은 여러 인수를 다룰 때 각 인수 사이의 쉼표를 백슬래시 ` \ `로 이스케이프하여 잘못된 문자 오류를 방지합니다. 예를 들어 이전 단계에서 마이그레이션을 완료하려면:

   ```shell
   sudo gitlab-rake gitlab:background_migrations:finalize[CopyColumnUsingBackgroundMigrationJob,push_event_payloads,event_id,'[["event_id"]\, ["event_id_convert_to_bigint"]]']
   ```

{{< /tab >}}

{{< tab title="데이터베이스에서" >}}

1. 데이터베이스에서 마이그레이션의 [상태를 확인](#check-the-status-of-batched-background-migrations)합니다.
1. 쿼리 결과를 사용하여 마이그레이션 명령을 구성하여 꺾인괄호의 값을 올바른 인수로 바꿉니다:

   ```shell
   sudo gitlab-rake gitlab:background_migrations:finalize[<job_class_name>,<table_name>,<column_name>,'<job_arguments>']
   ```

   예를 들어 쿼리가 다음 데이터를 반환하는 경우:

   - `job_class_name`: `CopyColumnUsingBackgroundMigrationJob`
   - `table_name`: `events`
   - `column_name`: `id`
   - `job_arguments`: `[["id"], ["id_convert_to_bigint"]]`

   `[["id"],["id_convert_to_bigint"]]`과 같은 여러 인수를 다룰 때 각 인수 사이의 쉼표를 백슬래시 ` \ `로 이스케이프하여 잘못된 문자 오류를 방지합니다. `job_arguments` 매개 변수 값의 모든 쉼표를 백슬래시로 이스케이프해야 합니다.

   예를 들어:

   ```shell
   sudo gitlab-rake gitlab:background_migrations:finalize[CopyColumnUsingBackgroundMigrationJob,ci_builds,id,'[["id"\, "stage_id"]\,["id_convert_to_bigint"\,"stage_id_convert_to_bigint"]]']
   ```

{{< /tab >}}

{{< /tabs >}}

#### 실패한 마이그레이션 완료됨으로 표시 {#mark-a-failed-migration-finished}

> [!warning]
> 이 지침을 사용하기 전에 [GitLab 지원 연락](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#contact-support). 이 작업으로 인해 데이터 손실이 발생할 수 있으며 복구하기 어려운 방식으로 인스턴스에 오류가 발생할 수 있습니다.

백그라운드 마이그레이션이 실패할 수 있는 경우가 있습니다: 너무 많은 버전 업그레이드를 건너뛸 때 또는 하위 호환성이 없는 데이터베이스 스키마 변경이 있을 때입니다. (예: [이슈 393216](https://gitlab.com/gitlab-org/gitlab/-/issues/393216) 참조). 실패한 백그라운드 마이그레이션으로 인해 추가 애플리케이션 업그레이드가 방지됩니다.

백그라운드 마이그레이션이 건너뛰기에 "안전"하다고 판단되면 마이그레이션을 수동으로 완료됨으로 표시할 수 있습니다:

> [!warning]
> 진행하기 전에 반드시 백업을 만들어야 합니다.

```ruby
# Start the rails console

connection = ApplicationRecord.connection # or Ci::ApplicationRecord.connection, depending on which DB was the migration scheduled

Gitlab::Database::SharedModel.using_connection(connection) do
  migration = Gitlab::Database::BackgroundMigration::BatchedMigration.find_for_configuration(
    Gitlab::Database.gitlab_schemas_for_connection(connection),
    'BackfillUserDetailsFields',
    :users,
    :id,
    []
  )

  # mark all jobs completed
  migration.batched_jobs.update_all(status: Gitlab::Database::BackgroundMigration::BatchedJob.state_machine.states['succeeded'].value)
  migration.update_attribute(:status, Gitlab::Database::BackgroundMigration::BatchedMigration.state_machine.states[:finished].value)
end
```

### 모든 백그라운드 마이그레이션을 동기적으로 실행 {#run-all-background-migrations-synchronously}

유지 보수 기간 동안 백그라운드 마이그레이션을 포그라운드에서 실행하도록 강제하고 싶은 경우가 있을 수 있습니다.

이 스크립트는 모든 마이그레이션이 완료되기 전에 시간 초과/종료될 수 있습니다. 모든 마이그레이션이 완료될 때까지 다시 실행할 수 있습니다.

```ruby
# Start the rails console

databases = ActiveRecord::Tasks::DatabaseTasks.setup_initial_database_yaml

Gitlab::Database.database_base_models.each do |database_name, model|
  Gitlab::Database::SharedModel.using_connection(model.connection) do
    Gitlab::Database::BackgroundMigration::BatchedMigration.with_status([:paused, :active]).find_each(batch_size: 100) do |migration|
      puts "#{database_name}: Finalizing migration #{migration.job_class_name} (ID: #{migration.id})... "
      Gitlab::Database::BackgroundMigration::BatchedMigrationRunner.finalize(
        migration.job_class_name,
        migration.table_name,
        migration.column_name,
        Gitlab::Json.parse(migration.job_arguments),
        connection: model.connection
      )
      puts("done!\n")
    end
  end
end
```

## 배치된 백그라운드 마이그레이션 로그 보기 {#view-batched-background-migration-logs}

배치된 백그라운드 마이그레이션을 문제 해결할 때 여러 위치에서 자세한 실행 로그를 볼 수 있습니다.

### Sidekiq 로그 {#sidekiq-logs}

[Sidekiq 로그](../administration/logs/_index.md#sidekiq-logs)는 `Database::BatchedBackgroundMigrationWorker` 작업이 실행될 때를 표시합니다. 이러한 로그는 작업 실행을 표시하지만 실행 중인 특정 마이그레이션을 식별하지 않습니다.

### 애플리케이션 로그 {#application-logs}

실행 중인 배치된 백그라운드 마이그레이션을 식별하려면 [애플리케이션 로그](../administration/logs/_index.md#application_jsonlog)를 확인합니다. 애플리케이션 로그에는 다음을 포함한 자세한 정보가 포함됩니다:

- 특정 배치된 백그라운드 마이그레이션의 클래스 이름(`job_class_name`)
- 상태 전환(보류 중, 실행 중 및 성공 또는 실패)

### 마이그레이션 실행 추적 {#trace-a-migration-execution}

특정 배치된 백그라운드 마이그레이션을 추적하려면:

1. Sidekiq 로그 항목에서 `correlation_id`을 찾습니다(`Database::BatchedBackgroundMigrationWorker` 인 경우).
1. 그 `correlation_id`으로 애플리케이션 로그를 검색하여 자세한 상태 전환을 확인합니다.

예제 애플리케이션 로그 항목:

```json
{
  "severity": "INFO",
  "time": "2025-08-27T22:52:07.806Z",
  "meta.caller_id": "Database::BatchedBackgroundMigration::MainExecutionWorker",
  "correlation_id": "74d0295cbe4bb6147230a7d481fb0f8a",
  "message": "BatchedJob transition",
  "batched_job_id": 725,
  "previous_state": "pending",
  "new_state": "running",
  "batched_migration_id": 638,
  "job_class_name": "BackfillSentNotificationsAfterPartition",
  "job_arguments": []
},
{
  "severity": "INFO",
  "time": "2025-08-27T22:52:14.293Z",
  "meta.caller_id": "Database::BatchedBackgroundMigration::MainExecutionWorker",
  "correlation_id": "74d0295cbe4bb6147230a7d481fb0f8a",
  "message": "BatchedJob transition",
  "batched_job_id": 725,
  "previous_state": "running",
  "new_state": "succeeded",
  "batched_migration_id": 638,
  "job_class_name": "BackfillSentNotificationsAfterPartition",
  "job_arguments": []
}
```

## 보류 중인 고급 검색 마이그레이션 확인 {#check-for-pending-advanced-search-migrations}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

이 섹션은 [Elasticsearch 통합](../integration/advanced_search/elasticsearch.md)을 활성화한 경우에만 적용됩니다. 주요 릴리스의 경우 현재 버전의 가장 최신 부 릴리스에서 모든 [고급 검색 마이그레이션](../integration/advanced_search/elasticsearch.md#advanced-search-migrations)이 완료되어야 주요 버전 업그레이드 전에 진행할 수 있습니다. 다음 명령을 실행하여 보류 중인 마이그레이션을 찾을 수 있습니다.

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

```shell
sudo gitlab-rake gitlab:elastic:list_pending_migrations
```

{{< /tab >}}

{{< tab title="Self-compiled(소스)" >}}

```shell
cd /home/git/gitlab
sudo -u git -H bundle exec rake gitlab:elastic:list_pending_migrations
```

{{< /tab >}}

{{< /tabs >}}

고급 검색 인덱싱이 활성화된 경우 [`gitlab:check` Rake 작업](../integration/advanced_search/elasticsearch.md#all-migrations-must-be-finished-before-doing-a-major-upgrade)도 보류 중인 고급 검색 마이그레이션이 있는지와 개수를 보고합니다. 확인은 상태만 보고하며 업그레이드를 중지하지 않으므로 출력을 읽고 결과에 따라 조치해야 합니다.

긴 업그레이드 경로에 있고 보류 중인 마이그레이션이 많은 경우 **인덱싱 처리기 대기열 재조정** 및 **비코드 인덱싱을 위한 샤드 수**를 구성하여 인덱싱 속도를 높일 수 있습니다. 또 다른 옵션은 보류 중인 마이그레이션을 무시하고 GitLab을 대상 버전으로 업그레이드한 후 [인스턴스를 다시 인덱싱](../integration/advanced_search/elasticsearch.md#index-the-instance)하는 것입니다. [**고급 검색으로 검색**](../integration/advanced_search/elasticsearch.md#advanced-search-configuration) 설정으로 이 프로세스 중에 고급 검색을 비활성화할 수도 있습니다.

> [!warning]
> 대규모 인스턴스 인덱싱에는 위험이 따릅니다. 자세한 내용은 [대규모 인스턴스 효율적으로 인덱싱](../integration/advanced_search/elasticsearch.md#index-large-instances-efficiently)을 참조합니다.
