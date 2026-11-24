---
stage: GitLab Dedicated
group: Geo
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Geo 배경 작업
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Geo는 모든 동기화 및 확인 의도를 Sidekiq 작업 인수가 아닌 Geo 추적 데이터베이스의 레지스트리 테이블에 유지합니다. 작업이 중단되면 레지스트리 레코드는 해당 상태를 유지하고 크론 기반 스케줄러가 작업을 다시 큐에 넣습니다. 이 설계는 Geo를 근본적으로 충돌 안전하게 만듭니다.

## 레지스트리 동기화 상태 {#registry-sync-states}

모든 복제 가능한 데이터 유형에는 동기화 상태를 추적하는 보조 사이트의 레지스트리 레코드가 있습니다:

| 상태 | 설명 |
|-------|-------------|
| `pending` | 동기화가 필요합니다. 동기화 스케줄러 크론에 의해 선택됩니다. |
| `started` | 동기화 진행 중입니다. 워커가 중단되면 레코드가 이 상태로 유지됩니다. |
| `synced` | 성공적으로 복제되었습니다. |
| `failed` | 동기화 실패했습니다. 지수 백오프 재시도를 위해 `retry_at` 타임스탬프가 있습니다. |

동기화 작업이 중단되면 레지스트리가 `started`에 유지됩니다. 10분마다 실행되는 `Geo::SyncTimeoutCronWorker`는 동기화 작업 상태를 감지하고 레지스트리를 `failed`로 표시하고 재시도 백오프를 수행합니다. 그러면 동기화 스케줄러 크론 워커가 동기화를 위해 레지스트리를 다시 큐에 넣습니다.

## 복구 메커니즘 {#recovery-mechanisms}

다음 크론 워커는 자동 복구를 제공합니다. 해당 스케줄은 [`ee/config/schedule.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/config/schedule.yml)에 정의되어 있으며 구성 가능합니다.

크론 작업 이름은 **Cron** 탭에 표시되는 이름과 일치하며, 이는 [**운영자** 영역](../../admin_area.md#background-jobs)의 Sidekiq 대시보드에 있습니다.

| 메커니즘 | 워커 | 크론 작업 이름 | 기본 스케줄 | 목적 |
|-----------|--------|---------------|------------------|---------|
| 동기화 시간 초과 복구 | `Geo::SyncTimeoutCronWorker` | `geo_sync_timeout_cron_worker` | 10분마다(보조) | `started` 상태로 교착된 레지스트리를 `failed`로 표시하고 재시도 백오프를 수행합니다. |
| Blob 동기화 스케줄러 | `Geo::RegistrySyncWorker` | `geo_registry_sync_worker` | 1분마다(보조) | `pending` 및 `failed` blob 레지스트리를 폴링하고 `Geo::SyncWorker`를 큐에 넣습니다. |
| 리포지토리 동기화 스케줄러 | `Geo::RepositoryRegistrySyncWorker` | `geo_repository_registry_sync_worker` | 1분마다(보조) | `pending` 및 `failed` 리포지토리 레지스트리를 폴링하고 `Geo::SyncWorker`를 큐에 넣습니다. |
| 레지스트리 일관성 | `Geo::Secondary::RegistryConsistencyWorker` | `geo_secondary_registry_consistency_worker` | 1분마다(보조) | 추적되지 않은 복제 가능 항목에 대한 누락된 레지스트리 레코드를 생성합니다. 고아 레지스트리를 감지합니다. |
| 확인 시간 초과 | `Geo::VerificationTimeoutWorker` | `geo_verification_cron_worker`에 의해 트리거됩니다. | 1분마다(주 및 보조) | `verification_started`에 고착된 확인을 `verification_failed`로 표시합니다. |
| 확인 스케줄러 | `Geo::VerificationCronWorker` | `geo_verification_cron_worker` | 1분마다(주 및 보조) | 확인 일괄 처리, 시간 초과, 재확인 및 상태 백필 워커를 트리거합니다. |

## 큐 안전 참조 {#queue-safety-reference}

다음 섹션은 Geo Sidekiq 큐에 대한 워커별 안전 정보를 제공합니다.

### 크론 워커 {#cron-workers}

크론 워커는 자동으로 스케줄되고, 큐가 비워지면 다음 크론 틱에서 다시 실행됩니다. 모든 크론 워커 큐는 안전하게 비울 수 있습니다.

| 워커 | 동작 | 큐 비우기 안전 | 비우기의 부정적 결과 | 복구 메커니즘 |
|--------|-------------|:-------------------:|-----------------------------------|-------------------|
| `Geo::RegistrySyncWorker` | 대기 중인 blob 레지스트리와 실패한 blob 레지스트리를 폴링합니다. `Geo::SyncWorker`를 큐에 넣습니다. | 예 | 동기화가 다음 크론 틱까지 지연됩니다. | 1분마다 다시 실행됩니다. |
| `Geo::RepositoryRegistrySyncWorker` | 대기 중인 리포지토리 레지스트리와 실패한 리포지토리 레지스트리를 폴링합니다. `Geo::SyncWorker`를 큐에 넣습니다. | 예 | 동기화가 다음 크론 틱까지 지연됩니다. | 1분마다 다시 실행됩니다. |
| `Geo::SyncTimeoutCronWorker` | `started` 상태에 고착된 레지스트리를 찾습니다. `failed`로 표시하고 재시도 백오프를 수행합니다. | 예 | `started`에 고착된 레지스트리는 다음 틱까지 `failed`로 전환되지 않습니다. 동기화가 다음 틱 이후에 재개됩니다. | 10분마다 다시 실행됩니다. |
| `Geo::Secondary::RegistryConsistencyWorker` | 모든 레지스트리 유형을 스캔합니다. 누락된 레지스트리를 생성합니다. 고아 레지스트리를 감지하고 `Geo::DestroyWorker`를 큐에 넣습니다. | 예 | 누락된 레지스트리는 생성되지 않고 고아 레지스트리는 다음 틱까지 정리되지 않습니다. | 1분마다 다시 실행됩니다. |
| `Geo::VerificationCronWorker` | 모든 확인 하위 워커를 트리거합니다. | 예 | 확인이 다음 크론 틱까지 지연됩니다. | 1분마다 다시 실행됩니다. |
| `Geo::VerificationTimeoutWorker` | `verification_started`에 고착된 레코드를 복구합니다. | 예 | `verification_started`에 고착된 레코드는 다음 틱까지 전환되지 않습니다. | 1분마다 다시 실행됩니다. |
| `Geo::PruneEventLogWorker` | 모든 보조 사이트에서 사용된 오래된 이벤트 로그 항목을 삭제합니다(주 사이트만). | 예 | 이벤트 로그는 워커가 다시 실행될 때까지 증가합니다. 데이터 손실 없음. | 5분마다 다시 실행됩니다. |
| `Geo::MetricsUpdateWorker` | 노드 상태를 계산하고, Prometheus 게이지를 업데이트하고, 상태를 주 사이트로 보냅니다. | 예 | 메트릭은 워커가 다시 실행될 때까지 오래됩니다. | 1분마다 다시 실행됩니다. |
| `Geo::SidekiqCronConfigWorker` | 노드 유형(주 또는 보조)을 기반으로 크론 작업을 활성화하고 비활성화합니다. | 예 | 크론 작업 구성은 워커가 다시 실행될 때까지 잘못될 수 있습니다. | 1분마다 다시 실행됩니다. |

### 동기화 워커(보조) {#sync-workers-secondary}

| 워커 | 동작 | 큐 비우기 안전 | 비우기의 부정적 결과 | 복구 메커니즘 |
|--------|-------------|:-------------------:|-----------------------------------|-------------------|
| `Geo::SyncWorker` | 주 사이트에서 단일 blob을 다운로드하거나 단일 리포지토리를 가져옵니다. | 예 | 비행 중인 작업에 대한 레지스트리는 `started`에 유지됩니다. 동기화가 복구될 때까지 지연됩니다. | `SyncTimeoutCronWorker`는 고착된 레지스트리를 `failed`로 전환합니다. 동기화 스케줄러가 다시 큐에 넣습니다. |
| `Geo::ContainerRepositorySyncWorker` | 주 사이트에서 단일 컨테이너 리포지토리를 동기화합니다. | 예 | 레지스트리가 상태를 유지합니다. 동기화가 복구될 때까지 지연됩니다. | 동기화 스케줄러가 다시 큐에 넣습니다. |
| `Geo::BulkRegistryResyncWorker` | 레지스트리 클래스의 대량 재동기화를 트리거합니다. | 예 | 대량 재동기화가 시작되지 않습니다. 개별 레지스트리가 상태를 유지합니다. | 호출자가 다시 큐에 넣습니다. |

### 이벤트 워커(주 및 보조) {#event-workers-primary-and-secondary}

> [!warning]
> 이벤트 워커 큐를 비우면 큐의 이벤트가 손실될 수 있습니다. 손실된 이벤트는 보조 사이트의 데이터가 일시적으로 오래되도록 할 수 있습니다.

| 워커 | 동작 | 큐 비우기 안전 | 비우기의 부정적 결과 | 복구 메커니즘 |
|--------|-------------|:-------------------:|-----------------------------------|-------------------|
| `Geo::EventWorker` | 보조 사이트에서 Geo 복제 이벤트(`created`, `updated`, `deleted`)를 처리합니다. | 주의해서 사용하세요. | `updated` 이벤트를 잃으면 재확인 또는 다음 업데이트 이벤트까지 리소스가 오래될 수 있습니다. `deleted` 이벤트를 잃으면 보조 사이트에 고아 파일이 남을 수 있습니다(낭비된 디스크, 데이터 손실 없음). `created` 이벤트를 잃으면 지속적인 영향이 없습니다. Sidekiq 재시도 3회가 있습니다. | 모든 재시도가 실패하더라도 레지스트리 레코드가 존재하고 동기화 스케줄러가 다시 큐에 넣습니다. `RegistryConsistencyWorker`도 고아 레지스트리를 감지합니다. |
| `Geo::BatchEventCreateWorker` | 주 사이트에 Geo 이벤트를 대량 삽입합니다. | 주의해서 사용하세요. | 큐의 이벤트는 비워지면 손실됩니다. 보조 사이트는 재확인까지 변경 사항을 알지 못할 수 있습니다. | 보조 사이트의 `RegistryConsistencyWorker`는 결과적으로 누락된 레지스트리를 감지합니다(1분마다). |
| `Geo::CreateRepositoryUpdatedEventWorker` | 주 사이트에서 리포지토리가 업데이트되면 Geo 이벤트를 생성합니다. | 주의해서 사용하세요. | `Geo::BatchEventCreateWorker`과 동일합니다. | `Geo::BatchEventCreateWorker`과 동일합니다. |

### 확인 워커(주 및 보조) {#verification-workers-primary-and-secondary}

| 워커 | 동작 | 큐 비우기 안전 | 비우기의 부정적 결과 | 복구 메커니즘 |
|--------|-------------|:-------------------:|-----------------------------------|-------------------|
| `Geo::VerificationBatchWorker` | 레코드의 체크섬 배치를 생성합니다. | 예 | 확인이 지연됩니다. | 크론이 다시 큐에 넣습니다. `VerificationTimeoutWorker`는 고착된 레코드를 캡처합니다. |
| `Geo::ReverificationBatchWorker` | 주기적인 재확인을 위해 이미 확인된 레코드를 표시합니다. | 예 | 재확인이 지연됩니다. | 크론이 다시 큐에 넣습니다. |
| `Geo::VerificationStateBackfillWorker` | 복제 가능한 유형에 대한 확인 상태 테이블을 백필합니다. | 예 | 백필이 지연됩니다. 배타적 임대가 30분 후 만료됩니다. | 자신을 다시 큐에 넣습니다. |
| `Geo::BulkPrimaryVerificationWorker` | 주 사이트에서 모델 클래스의 대량 확인을 트리거합니다. | 예 | 대량 확인이 시작되지 않습니다. | 호출자가 다시 큐에 넣습니다. |
| `Geo::BulkRegistryReverificationWorker` | 보조 사이트에서 레지스트리 클래스의 대량 재확인을 트리거합니다. | 예 | 대량 재확인이 시작되지 않습니다. | 호출자가 다시 큐에 넣습니다. |

### 워커 삭제(보조) {#destroy-workers-secondary}

> [!warning]
> 워커 큐를 삭제하면 손실된 작업이 보조 사이트에 고아 파일이나 리포지토리를 남길 수 있습니다.

| 워커 | 동작 | 큐 비우기 안전 | 비우기의 부정적 결과 | 복구 메커니즘 |
|--------|-------------|:-------------------:|-----------------------------------|-------------------|
| `Geo::DestroyWorker` | 주 사이트에서 삭제 후 보조 사이트에서 복제된 파일 또는 리포지토리를 삭제합니다. | 주의해서 사용하세요. | 고아 파일이나 리포지토리가 보조 사이트에 남아있어 디스크 공간을 낭비합니다. 데이터 손실 없음. Sidekiq 재시도 3회가 있습니다. | `RegistryConsistencyWorker`는 고아 레지스트리를 감지하고 `DestroyWorker`를 다시 큐에 넣습니다. |
