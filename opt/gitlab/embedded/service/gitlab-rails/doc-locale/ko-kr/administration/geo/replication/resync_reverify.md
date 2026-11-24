---
stage: GitLab Dedicated
group: Geo
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Geo 데이터 재동기화 및 재검증
description: "UI 또는 Rails 콘솔에서 개별 Geo 구성 요소 또는 여러 구성 요소를 대량으로 수동으로 재동기화하고 재검증합니다."
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

재동기화 및 재검증은 표준 운영 작업입니다. 자동 재시도 간격을 기다리지 않고 복제 또는 검증을 다시 시도하거나 복제 또는 검증 실패 후 복구하는 데 사용할 수 있습니다.

[Rails 콘솔](../../operations/rails_console.md#starting-a-rails-console-session)의 보조 Geo 사이트에서 다음을 수행할 수 있습니다:

- [개별 구성 요소 수동으로 재동기화 및 재검증](#resync-and-reverify-individual-components)
- [여러 구성 요소 수동으로 재동기화 및 재검증](#resync-and-reverify-multiple-components)

## 개별 구성 요소 재동기화 및 재검증 {#resync-and-reverify-individual-components}

보조 사이트에서 **운영자** > **Geo** > **Replication**을 방문하여 개별 항목의 재동기화 또는 재검증을 강제로 실행합니다.

그러나 이것이 작동하지 않으면 Rails 콘솔을 사용하여 동일한 작업을 수행할 수 있습니다. 다음 섹션에서는 [Rails 콘솔](../../operations/rails_console.md#starting-a-rails-console-session)의 내부 애플리케이션 명령을 사용하여 개별 레코드에 대해 복제 또는 검증을 동기식 또는 비동기식으로 수행하는 방법을 설명합니다.

### Replicator 인스턴스 획득 {#obtaining-a-replicator-instance}

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 적절한 조건에서 실행되지 않으면 손상을 초래할 수 있습니다. 항상 명령을 먼저 테스트 환경에서 실행하고 복원할 준비가 된 백업 인스턴스를 준비합니다.

동기화 또는 검증 작업을 수행하기 전에 Replicator 인스턴스를 획득해야 합니다.

먼저 수행하려는 작업에 따라 기본 또는 보조 사이트에서 [Rails 콘솔 세션을 시작](../../operations/rails_console.md#starting-a-rails-console-session)합니다.

기본 사이트:

- 리소스의 체크섬을 계산할 수 있습니다

보조 사이트:

- 리소스를 동기화할 수 있습니다
- 리소스의 체크섬을 계산하고 기본 사이트의 체크섬과 대조하여 검증할 수 있습니다

다음으로, 다음 스니펫 중 하나를 실행하여 Replicator 인스턴스를 가져옵니다.

#### 모델 레코드의 ID가 주어진 경우 {#given-a-model-records-id}

- `123`을 실제 ID로 바꿉니다.
- `Packages::PackageFile`을 [Geo 데이터 타입 모델 클래스](#geo-data-type-model-classes) 중 하나로 바꿉니다.

```ruby
model_record = Packages::PackageFile.find_by(id: 123)
replicator = model_record.replicator
```

#### 레지스트리 레코드의 ID가 주어진 경우 {#given-a-registry-records-id}

- `432`을 실제 ID로 바꿉니다. 레지스트리 레코드는 추적하는 모델 레코드와 동일한 ID 값을 가질 수도 있고 가지지 않을 수도 있습니다.
- `Geo::PackageFileRegistry`을 [Geo 레지스트리 클래스](#geo-registry-classes) 중 하나로 바꿉니다.

보조 Geo 사이트:

```ruby
registry_record = Geo::PackageFileRegistry.find_by(id: 432)
replicator = registry_record.replicator
```

#### 레지스트리 레코드의 `last_sync_failure`에서 오류 메시지가 주어진 경우 {#given-an-error-message-in-a-registry-records-last_sync_failure}

- `Geo::PackageFileRegistry`을 [Geo 레지스트리 클래스](#geo-registry-classes) 중 하나로 바꿉니다.
- `error message here`을 실제 오류 메시지로 바꿉니다.

```ruby
registry = Geo::PackageFileRegistry.find_by("last_sync_failure LIKE '%error message here%'")
replicator = registry.replicator
```

#### 레지스트리 레코드의 `verification_failure`에서 오류 메시지가 주어진 경우 {#given-an-error-message-in-a-registry-records-verification_failure}

- `Geo::PackageFileRegistry`을 [Geo 레지스트리 클래스](#geo-registry-classes) 중 하나로 바꿉니다.
- `error message here`을 실제 오류 메시지로 바꿉니다.

```ruby
registry = Geo::PackageFileRegistry.find_by("verification_failure LIKE '%error message here%'")
replicator = registry.replicator
```

### Replicator 인스턴스로 작업 수행 {#performing-operations-with-a-replicator-instance}

`replicator` 변수에 저장된 Replicator 인스턴스가 있으면 많은 작업을 수행할 수 있습니다:

#### 콘솔에서 동기화 {#sync-in-the-console}

이 스니펫은 보조 사이트에서만 작동합니다.

이렇게 하면 동기화 코드가 콘솔에서 동기식으로 실행되므로 리소스를 동기화하는 데 걸리는 시간을 관찰하거나 전체 오류 백트레이스를 볼 수 있습니다.

```ruby
replicator.sync
```

필요에 따라 콘솔의 로그 수준을 구성된 로그 수준보다 더 자세하게 한 다음 동기화를 수행합니다:

```ruby
Rails.logger.level = :debug
```

#### 콘솔에서 체크섬 또는 검증 {#checksum-or-verify-in-the-console}

이 스니펫은 모든 기본 또는 보조 사이트에서 작동합니다.

기본 사이트에서 리소스의 체크섬을 계산하여 결과를 주 GitLab 데이터베이스에 저장합니다. 보조 사이트에서 리소스의 체크섬을 계산하고 주 GitLab 데이터베이스의 체크섬(기본 사이트에서 생성됨)과 대조하여 결과를 Geo 추적 데이터베이스에 저장합니다.

이렇게 하면 체크섬 및 검증 코드가 콘솔에서 동기식으로 실행되므로 소요 시간을 관찰하거나 전체 오류 백트레이스를 볼 수 있습니다.

```ruby
replicator.verify
```

#### Sidekiq 작업에서 동기화 {#sync-in-a-sidekiq-job}

이 스니펫은 보조 사이트에서만 작동합니다.

Sidekiq에 대한 [동기화](#sync-in-the-console) 작업을 큐에 추가합니다.

```ruby
replicator.enqueue_sync
```

#### Sidekiq 작업에서 검증 {#verify-in-a-sidekiq-job}

이 스니펫은 모든 기본 또는 보조 사이트에서 작동합니다.

Sidekiq에 대한 [체크섬 또는 검증](#checksum-or-verify-in-the-console) 작업을 큐에 추가합니다.

```ruby
replicator.verify_async
```

#### 모델 레코드 가져오기 {#get-a-model-record}

이 스니펫은 모든 기본 또는 보조 사이트에서 작동합니다.

```ruby
replicator.model_record
```

#### 레지스트리 레코드 가져오기 {#get-a-registry-record}

이 스니펫은 보조 사이트에서만 작동합니다. 레지스트리 테이블은 Geo 추적 DB에 저장되기 때문입니다.

```ruby
replicator.registry
```

### Geo 데이터 타입 모델 클래스 {#geo-data-type-model-classes}

Geo 데이터 타입은 하나 이상의 GitLab 기능에서 관련 데이터를 저장하기 위해 필요하고 Geo에 의해 보조 사이트로 복제되는 특정 데이터 클래스입니다.

- **Blob 타입**:
  - `Ci::JobArtifact`
  - `Ci::PipelineArtifact`
  - `Ci::SecureFile`
  - `LfsObject`
  - `MergeRequestDiff`
  - `Packages::PackageFile`
  - `PagesDeployment`
  - `Terraform::StateVersion`
  - `Upload`
  - `DependencyProxy::Manifest`
  - `DependencyProxy::Blob`
- **Git 리포지토리 타입**:
  - `DesignManagement::Repository`
  - `ProjectRepository`
  - `ProjectWikiRepository`
  - `SnippetRepository`
  - `GroupWikiRepository`
- **기타 타입**:
  - `ContainerRepository`

주요 클래스의 종류는 Registry, Model, Replicator입니다. 이 클래스 중 하나의 인스턴스가 있으면 다른 것을 얻을 수 있습니다. Registry와 Model은 주로 PostgreSQL DB 상태를 관리합니다. Replicator는 비-PostgreSQL 데이터(파일/Git 리포지토리/컨테이너 리포지토리)를 복제하거나 검증하는 방법을 알고 있습니다.

### Geo 레지스트리 클래스 {#geo-registry-classes}

GitLab Geo의 맥락에서 **레지스트리 레코드**는 Geo 추적 데이터베이스의 레지스트리 테이블을 나타냅니다. 각 레코드는 주 GitLab 데이터베이스의 단일 복제 가능 항목(예: LFS 파일 또는 프로젝트 Git 리포지토리)을 추적합니다. Geo 레지스트리 테이블에 해당하는 쿼리 가능한 Rails 모델은:

- **Blob 타입**:
  - `Geo::CiSecureFileRegistry`
  - `Geo::DependencyProxyBlobRegistry`
  - `Geo::DependencyProxyManifestRegistry`
  - `Geo::JobArtifactRegistry`
  - `Geo::LfsObjectRegistry`
  - `Geo::MergeRequestDiffRegistry`
  - `Geo::PackageFileRegistry`
  - `Geo::PagesDeploymentRegistry`
  - `Geo::PipelineArtifactRegistry`
  - `Geo::ProjectWikiRepositoryRegistry`
  - `Geo::SnippetRepositoryRegistry`
  - `Geo::TerraformStateVersionRegistry`
  - `Geo::UploadRegistry`
- **Git 리포지토리 타입**:
  - `Geo::DesignManagementRepositoryRegistry`
  - `Geo::ProjectRepositoryRegistry`
  - `Geo::ProjectWikiRepositoryRegistry`
  - `Geo::SnippetRepositoryRegistry`
  - `Geo::GroupWikiRepositoryRegistry`
- **기타 타입**:
  - `Geo::ContainerRepositoryRegistry`

## 여러 구성 요소 재동기화 및 재검증 {#resync-and-reverify-multiple-components}

구성 요소 리소스가 동기화 또는 검증에 실패하면 대량 작업을 트리거하여 복제 대기열을 다시 시작할 수 있습니다. 이러한 작업은 재시도 카운트와 예약 시간을 0으로 재설정하여 시스템이 최대 1시간까지 기다리지 않고 실패한 리소스를 더 빨리 처리하도록 합니다.

> [!note]
> 이러한 작업은 리소스를 즉시 처리하지 않습니다. 대신 동기화 및 검증을 처리하는 백그라운드 작업을 다시 큐에 추가합니다. 실제 복제 작업은 표준 Geo 복제 프로세스를 통해 비동기식으로 발생합니다.

### 재동기화 및 재검증의 작동 방식 {#how-resync-and-reverification-works}

재동기화 또는 재검증 작업을 트리거하면 시스템은 일치하는 레코드를 `pending`로 표시합니다. Geo 재동기화 및 재검증 백그라운드 작업자는 이 레코드를 가져와 일반적인 큐 우선순위에 따라 처리합니다. 이 메커니즘을 사용하면 작업을 즉시 차단하지 않고 실패한 리소스의 처리를 가속화할 수 있습니다.

> [!note]
> 성공적으로 동기화되지 않은 레코드를 재검증할 수 없습니다. 동기화된 레코드만 검증할 수 있습니다.

UI 또는 Rails 콘솔에서 대량 작업을 트리거할 수 있습니다.

### UI에서 {#from-the-ui}

UI에서 하나의 구성 요소의 모든 리소스의 전체 재동기화를 예약할 수 있습니다:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **Geo** > **사이트**를 선택합니다.
1. **Replication details** 아래에서 원하는 구성 요소를 선택합니다.

#### 선택한 구성 요소에 대한 리소스 재동기화 {#resync-resources-for-the-selected-component}

1. **전체 재동기화**를 선택합니다: 이렇게 하면 선택한 리소스에 대한 모든 레코드의 상태가 이미 동기화되었는지 여부에 관계없이 재설정됩니다.
1. **모든 재동기화에 실패함**을 선택합니다: 이렇게 하면 동기화에 실패한 모든 레코드가 재설정됩니다.

#### 선택한 구성 요소에 대한 리소스 재검증 {#reverify-resources-for-the-selected-component}

1. **전체 재인증**을 선택합니다: 이렇게 하면 선택한 리소스에 대한 모든 레코드의 상태가 이미 검증되었는지 여부에 관계없이 재설정됩니다.
1. **실패 항목 재검증**을 선택합니다: 이렇게 하면 검증에 실패했지만 동기화는 성공한 모든 레코드가 재설정됩니다.

#### 모든 사이트에서 하나의 구성 요소 재검증 {#reverify-one-component-on-all-sites}

기본 사이트의 체크섬이 의심스러운 경우 기본 사이트가 체크섬을 다시 계산하도록 해야 합니다. 그러면 "전체 재검증"이 달성됩니다. 왜냐하면 기본 사이트에서 각 체크섬이 다시 계산된 후 모든 보조 사이트에 전파되는 이벤트가 생성되어 체크섬을 다시 계산하고 값을 비교하도록 하기 때문입니다. 불일치가 있으면 레지스트리를 `sync failed`로 표시하여 동기화 재시도가 예약되도록 합니다.

UI에서 기본 사이트의 체크섬을 다시 계산할 수 있습니다:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **모니터링** > **데이터 관리**를 선택합니다.
1. 드롭다운 목록에서 원하는 구성 요소를 선택합니다.
1. **전체 체크섬**을 선택합니다.

> [!warning]
> **전체 재동기화**, **전체 재인증** 및 **전체 체크섬**은 이미 동기화되었는지 또는 검증되었는지 여부에 관계없이 모든 리소스의 업데이트를 트리거합니다. 인스턴스에 객체 타입이 수천 개 있을 때는 실행해서는 안 됩니다(예: CI 작업 아티팩트).

### Rails 콘솔에서 {#from-the-rails-console}

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 적절한 조건에서 실행되지 않으면 손상을 초래할 수 있습니다. 항상 명령을 먼저 테스트 환경에서 실행하고 복원할 준비가 된 백업 인스턴스를 준비합니다.

다음 섹션에서는 [Rails 콘솔](../../operations/rails_console.md#starting-a-rails-console-session)의 내부 애플리케이션 명령을 사용하여 대량 복제 또는 검증을 수행하는 방법을 설명합니다.

#### 동기화에 실패한 하나의 구성 요소의 모든 리소스 동기화 {#sync-all-resources-of-one-component-that-failed-to-sync}

다음 스크립트:

- 모든 실패한 리포지토리를 반복합니다.
- 마지막 실패의 이유를 포함하여 Geo 동기화 및 검증 메타데이터를 표시합니다.
- 리포지토리를 재동기화하려고 시도합니다.
- 실패가 발생하면 실패 이유를 보고합니다.
- 완료하는 데 시간이 걸릴 수 있습니다. 각 리포지토리 확인은 결과를 보고하기 전에 완료되어야 합니다. 세션이 시간 초과되면 `screen` 세션을 시작하거나 [Rails runner](../../operations/rails_console.md#using-the-rails-runner)를 사용하여 실행하고 `nohup`을 사용하는 등의 프로세스를 계속 실행할 수 있도록 조치를 취하십시오.

보조 Geo 사이트에서 이 스크립트를 실행합니다.

```ruby
Geo::ProjectRepositoryRegistry.failed.find_each do |registry|
   begin
     puts "ID: #{registry.id}, Project ID: #{registry.project_id}, Last Sync Failure: '#{registry.last_sync_failure}'"
     registry.replicator.sync
     puts "Sync initiated for registry ID: #{registry.id}"
   rescue => e
     puts "ID: #{registry.id}, Project ID: #{registry.project_id}, Failed: '#{e}'", e.backtrace.join("\n")
   end
end; nil
```

#### 기본 사이트에서 체크섬에 실패한 모든 리소스 재검증 {#reverify-all-resources-that-failed-to-checksum-on-the-primary-site}

시스템은 자동으로 기본 사이트에서 체크섬에 실패한 모든 리소스를 재검증하지만 과도한 실패를 피하기 위해 점진적 백오프 방식을 사용합니다.

선택적으로, 예를 들어 시도한 개입을 완료했을 경우 수동으로 재검증을 더 빨리 트리거할 수 있습니다:

1. 기본 사이트의 GitLab Rails 노드에 SSH를 실행합니다.
1. [Rails 콘솔](../../operations/rails_console.md#starting-a-rails-console-session)을 엽니다.
1. `LfsObject`을 [Geo 데이터 타입 모델 클래스](#geo-data-type-model-classes) 중 하나로 바꿔 모든 리소스를 `pending verification`로 표시합니다:

   ```ruby
   LfsObject.verification_state_table_class.where(verification_state: 3).each_batch do |relation|
     relation.update_all(verification_state: 0)
   end
   ```
