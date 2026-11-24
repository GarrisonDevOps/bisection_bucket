---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 직접 이전 마이그레이션 문제 해결
description: "Rails 콘솔 명령어, 오류 해결 및 구성 팁을 통해 GitLab 직접 이전 마이그레이션 문제를 해결합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Rails 콘솔 세션](../../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 다음을 사용하여 그룹 가져오기 시도에 대한 실패 또는 오류 메시지를 찾을 수 있습니다:

```ruby
# Get relevant import records
import = BulkImports::Entity.where(namespace_id: Group.id).map(&:bulk_import).last

# Alternative lookup by user
import = BulkImport.where(user_id: User.find(...)).last

# Get list of import entities. Each entity represents either a group or a project
entities = import.entities

# Get a list of entity failures
entities.map(&:failures).flatten

# Alternative failure lookup by status
entities.where(status: [-1]).pluck(:destination_name, :destination_namespace, :status)
```

[API 엔드포인트](../../../api/bulk_imports.md#list-all-group-or-project-migration-entities)를 사용하여 마이그레이션된 모든 엔티티와 이와 관련된 모든 오류를 볼 수도 있습니다.

## 마이그레이션이 느리거나 시간 초과 상태 {#migrations-are-slow-or-timing-out}

매우 느린 마이그레이션이나 마이그레이션 중 [시간 초과](../../../administration/instance_limits.md#direct-transfer-migration)가 발생하는 경우 이러한 전략을 사용하여 마이그레이션 기간을 줄입니다.

### 대상 인스턴스에 Sidekiq 워커 추가 {#add-sidekiq-workers-to-the-destination-instance}

GitLab Self-Managed 인스턴스로 마이그레이션하려면 마이그레이션 속도를 높이기 위해 대상 인스턴스에 Sidekiq 워커를 추가할 수 있습니다. Sidekiq 워커 수를 늘릴 때는 다음을 고려해야 합니다:

- 단일 직접 이전 마이그레이션은 대상 인스턴스에서 사용 가능한 Sidekiq 워커 수에 관계없이 한 번에 5개의 그룹 또는 프로젝트를 마이그레이션합니다.
- 대상 인스턴스는 더 많은 동시 작업을 처리할 수 있는 용량이 필요합니다. 그렇다면 Sidekiq 워커를 더 추가하면 각 그룹 또는 프로젝트를 가져오는 데 걸리는 시간을 줄일 수 있습니다.

대상 인스턴스에 Sidekiq 워커를 추가하는 방법에 대한 자세한 내용은 [가져오기용 Sidekiq 구성](../../../administration/sidekiq/configuration_for_imports.md)을 참조하세요.

### 별도의 마이그레이션 시작 {#start-separate-migrations}

소스 인스턴스에 5개의 그룹을 병렬로 내보낼 리소스가 없으면 지연 및 잠재적 시간 초과가 발생할 수 있습니다. 소스 인스턴스의 리소스가 부족한 경우 대상 인스턴스는 내보낸 데이터가 사용 가능할 때까지 기다려야 합니다.

병렬 내보내기로 인한 지연을 줄이려면 모든 그룹 및 프로젝트를 동시에 마이그레이션하는 대신 각 그룹에 대해 별도의 마이그레이션을 시작합니다. GitLab UI는 최상위 그룹만 마이그레이션할 수 있으므로 API를 사용하여 해당 하위 그룹의 프로젝트를 마이그레이션해야 할 수 있습니다.

## 오래된 가져오기 {#stale-imports}

마이그레이션은 중단되거나 소스 또는 대상 인스턴스의 문제로 인해 `timeout` 상태로 완료될 수 있습니다. 이러한 문제를 해결하려면 소스 및 대상 인스턴스의 로그를 검사합니다.

### 소스 인스턴스 {#source-instance}

소스 인스턴스에서 오래된 가져오기는 종종 과도한 메모리 사용으로 인해 발생하며, 이는 Sidekiq 프로세스를 다시 시작하고 내보내기 작업을 중단할 수 있습니다. 대상 인스턴스는 마이그레이션이 결국 시간 초과될 때까지 내보낸 파일을 기다릴 수 있습니다.

[그룹](../../../api/group_relations_export.md#retrieve-the-status-of-an-export) 또는 [프로젝트](../../../api/project_relations_export.md#retrieve-the-status-of-an-export) 관계가 성공적으로 내보내졌는지 확인하려면 다음 명령을 실행합니다:

```shell
curl --request GET --location "https://example.gitlab.com/api/v4/projects/:ID/export_relations/status" \
--header "PRIVATE-TOKEN: <your_access_token>"
```

{{< glossary-tooltip text="관계" >}}의 상태가 `1` 이외인 경우 관계가 성공적으로 내보내지지 않았으며 문제는 소스 인스턴스에 있습니다.

다음 명령을 실행하여 중단된 내보내기 작업을 검색할 수도 있습니다. Sidekiq 로그는 다시 시작한 후 회전할 수 있으므로 회전된 로그도 확인해야 합니다.

```shell
grep `BulkImports::RelationBatchExportWorker` sidekiq.log | grep "interrupted_count"
```

Sidekiq 다시 시작이 문제의 원인인 경우:

- 내보내기 작업을 위해 별도의 Sidekiq 프로세스를 구성합니다. 자세한 내용은 [가져오기용 Sidekiq 구성](../../../administration/sidekiq/configuration_for_imports.md)을 참조하세요. 문제가 지속되면 Sidekiq 동시성을 줄여 동시에 처리되는 작업 수를 제한합니다.
- Sidekiq 메모리 한도 증가: 인스턴스에 사용 가능한 메모리가 있으면 Sidekiq 프로세스의 [최대 RSS 한도를 증가](../../../administration/sidekiq/sidekiq_memory_killer.md#configuring-the-limits)시킵니다. 예를 들어 한도를 2GB에서 3GB로 증가하여 빈번한 다시 시작을 방지할 수 있습니다.
- 최대 중단 횟수 증가: 작업이 실패하기 전에 더 많은 중단을 허용하려면 [`BulkImports::RelationBatchExportWorker`](https://gitlab.com/gitlab-org/gitlab/-/blob/b8e11d267cdd4a00807984f98a9d8d8cfa51602e/app/workers/bulk_imports/relation_batch_export_worker.rb#L4)의 최대 중단 횟수를 증가할 수 있습니다:

  1. 한도를 `20`(기본값은 `3`)로 증가하려면 다음 구성을 추가합니다:

     ```ruby
     sidekiq_options max_retries_after_interruption: 20
     ```

  1. 변경 사항을 적용하려면 Sidekiq를 다시 시작합니다.

이제 새 마이그레이션을 트리거하거나 [프로젝트 관계 내보내기 API](../../../api/project_relations_export.md#schedule-a-new-export-for-a-project)를 사용하여 내보내기를 수동으로 트리거할 수 있습니다. [내보내기 상태](../../../api/project_relations_export.md#retrieve-the-status-of-an-export)를 확인하여 관계가 성공적으로 내보내지고 있는지 확인합니다.

예를 들어 특정 프로젝트의 내보내기를 트리거하려면 다음 명령을 실행합니다:

```shell
curl --request POST --location "https://example.gitlab.com/api/v4/projects/:ID/export_relations" \
--header "PRIVATE-TOKEN: <your_access_token>" \
--form 'batched="true"'
```

### 대상 인스턴스 {#destination-instance}

드문 경우지만 대상 인스턴스가 그룹 또는 프로젝트 마이그레이션에 실패할 수 있습니다. 자세한 내용은 [이슈 498720](https://gitlab.com/gitlab-org/gitlab/-/issues/498720)을 참조하세요.

이 문제를 해결하려면 [가져오기 API](../../../api/import.md)를 사용하여 실패한 그룹 또는 프로젝트를 마이그레이션합니다. 이 API를 사용하면 특정 그룹 및 프로젝트를 개별적으로 마이그레이션할 수 있습니다.

## 기타 `404` 오류 {#other-404-errors}

그룹을 가져올 때 다른 `404` 오류가 발생할 수 있습니다(예시):

```json
"exception_message": "Unsuccessful response 404 from [FILTERED] Bo...",
"exception_class": "BulkImports::NetworkError",
```

이 오류는 소스 인스턴스에서 전송하는 과정에서 문제가 있음을 나타냅니다. 이를 해결하려면 소스 인스턴스에서 [사전 요구 사항](direct_transfer_migrations.md#prerequisites)을 충족했는지 확인합니다.

## 일치하지 않는 그룹 또는 프로젝트 경로 이름 {#mismatched-group-or-project-path-names}

소스 그룹 또는 프로젝트 경로가 [명명 규칙](../../reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs)을 준수하지 않으면 경로가 정규화되어 유효하도록 합니다. 예를 들어 `Destination-Project-Path`는 `destination-project-path`으로 정규화됩니다.

## 오류: `command exited with error code 15 and Unable to save [FILTERED] into [FILTERED]` {#error-command-exited-with-error-code-15-and-unable-to-save-filtered-into-filtered}

직접 이전을 사용하여 프로젝트를 마이그레이션할 때 로그에서 `command exited with error code 15 and Unable to save [FILTERED] into [FILTERED]` 오류가 발생할 수 있습니다. 이 오류가 발생하면 안전하게 무시할 수 있습니다. GitLab이 종료된 명령을 다시 시도합니다.

## 오류: `Batch export [batch_number] from source instance failed` {#error-batch-export-batch_number-from-source-instance-failed}

대상 인스턴스에서 다음 오류가 발생할 수 있습니다:

```plaintext
Batch export [batch_number] from source instance failed: [source instance error]
```

이 오류는 소스 인스턴스가 일부 레코드를 내보내는 데 실패할 때 발생합니다. 가장 일반적인 원인은 다음과 같습니다:

- 디스크 공간 부족
- 메모리 부족으로 인한 Sidekiq 작업 중단이 여러 번 발생
- 데이터베이스 명령문 시간 초과

이 이슈를 해결하려면:

1. 소스 인스턴스의 문제를 파악하고 수정합니다.
1. 대상 인스턴스에서 부분적으로 가져온 프로젝트 또는 그룹을 삭제하고 새 가져오기를 시작합니다.

내보내기에 실패한 관계 및 배치에 대한 자세한 내용은 소스 인스턴스에서 [프로젝트](../../../api/project_relations_export.md#retrieve-the-status-of-an-export) 및 [그룹](../../../api/group_relations_export.md#retrieve-the-status-of-an-export)에 대한 내보내기 상태 API 엔드포인트를 사용합니다.

## 오류: `duplicate key value violates unique constraint` {#error-duplicate-key-value-violates-unique-constraint}

레코드를 가져올 때 다음 오류가 발생할 수 있습니다:

```plaintext
PG::UniqueViolation: ERROR:  duplicate key value violates unique constraint
```

이 오류는 다음과 같은 경우에 발생할 수 있습니다:

- 가져오기를 처리 중인 Sidekiq 워커가 높은 메모리 또는 CPU 사용량으로 인해 다시 시작됩니다. 가져오기 중 Sidekiq 리소스 문제를 줄이려면:
  - [가져오기용 Sidekiq 구성](../../../administration/sidekiq/configuration_for_imports.md)을 최적화합니다.
  - `bulk_import_concurrent_pipeline_batch_limit` [애플리케이션 설정](../../../api/settings.md)에서 동시 작업 수를 제한합니다.
- [다른 소스 그룹의 그룹 또는 프로젝트를 단일 대상 그룹으로 통합](_index.md#known-issues)하고 있습니다. 다른 소스 그룹의 에픽이 동일한 내부 ID를 가진 경우(이는 단일 그룹 내에서만 고유), 이를 단일 대상 그룹으로 가져오면 충돌이 발생합니다. 이 충돌은 `PG::UniqueViolation: ERROR:  duplicate key value violates unique constraint` 오류를 발생시키며 `index_issues_on_namespace_id_iid_unique` 또는 `index_epics_on_group_id_and_iid`를 참조합니다.

## 오류: `Import::BulkImports::FileDownloadStrategy::ServiceError Invalid content type` {#error-importbulkimportsfiledownloadstrategyserviceerror-invalid-content-type}

GitLab 인스턴스 간 직접 이전을 사용할 때 다음 오류가 발생할 수 있습니다:

```plaintext
Import::BulkImports::FileDownloadStrategy::ServiceError Invalid content type
```

이 오류는 인스턴스 간 네트워크 트래픽이 라우팅되는 방식과 관련이 있습니다. `application/gzip` 이외의 콘텐츠 유형이 반환되면 네트워크 요청이 GitLab Workhorse를 우회할 수 있습니다.

이 이슈를 해결하려면:

- Ingress가 Puma에 직접 연결하는 대신 포트 `8181`의 GitLab Workhorse를 통해 트래픽을 라우팅하도록 구성되어 있는지 확인합니다.
- 객체 스토리지에 대해 [프록시 다운로드](../../../administration/object_storage.md#proxy-download) 활성화를 고려합니다.

## `(imported-xx-datetime)`으로 추가된 마일스톤 제목 {#milestone-titles-appended-with-imported-xx-datetime}

그룹을 가져올 때 그룹 및 프로젝트 마일스톤 제목이 대상 네임스페이스의 기존 제목과 [충돌](../../project/milestones/_index.md#milestone-title-rules)하면 가져온 마일스톤의 제목에 고유한 접미사가 추가됩니다. 예를 들어, `18.0 (imported-3d-1770206299)`입니다.

이러한 마일스톤을 식별하려면 대상 인스턴스의 `log/importer.log` 파일을 검색하여 다음을 찾습니다:

```plaintext
Updating milestone title - source title used by existing group or project milestone
```

로그 항목에는 다음이 포함됩니다:

- `importable_id`: 가져온 그룹의 ID입니다.
- `milestone_title`: 이름을 바꾸고 있는 마일스톤의 제목입니다.
- `existing_group_id` 또는 `existing_project_id`: 기존 마일스톤이 포함된 그룹 또는 프로젝트의 ID입니다.

이 정보를 사용하여 마일스톤을 찾고 제목을 원하는 것으로 업데이트할 수 있습니다.

## 오류: `Destination belongs to a different organization than the current one` {#error-destination-belongs-to-a-different-organization-than-the-current-one}

소스 및 대상 네임스페이스가 다른 조직에 속하고 조직이 격리된 것으로 표시된 경우 직접 이전으로 마이그레이션이 실패합니다.

이 오류를 해결하려면 현재 조직에 속하는 대상 네임스페이스로 마이그레이션합니다. 자세한 내용은 [이슈 595674](https://gitlab.com/gitlab-org/gitlab/-/issues/595674)를 참조하세요.

## 다운로드한 파일이 최대 다운로드 파일 크기를 초과할 때 직접 이전이 실패함 {#direct-transfer-fails-when-a-downloaded-file-exceeds-the-maximum-download-file-size}

소스 인스턴스에서 다운로드한 파일이 기본값으로 5GiB인 최대 다운로드 파일 크기보다 큰 경우 직접 이전이 실패합니다. 직접 이전은 대부분의 데이터를 작은 배치로 내보내므로 대부분의 파일은 이 한도를 초과하지 않습니다. `repository`, `lfs` 및 `uploads` 관계만 초과할 가능성이 있습니다.

GitLab Self-Managed 및 GitLab Dedicated에서 관리자는 [최대 다운로드 파일 크기](../../../administration/settings/import_and_export_settings.md#maximum-download-file-size-for-imports-by-direct-or-offline-transfer)를 증가할 수 있습니다.

GitLab.com에서는 한도가 고정되어 있으며 높일 수 없습니다. 한도를 초과하는 프로젝트를 마이그레이션하려면 마이그레이션 전에 영향을 받는 관계의 크기를 줄입니다:

- `repository`: Git 기록을 다시 작성하여 큰 파일을 제거합니다. 이 작업은 모든 커밋 SHA를 변경합니다. 자세한 내용은 [리포지토리 크기를 줄이는 방법](../../project/repository/repository_size.md#methods-to-reduce-repository-size)을 참조하세요.
- `lfs`: 프로젝트를 마이그레이션한 다음 누락된 LFS 객체를 대상으로 수동으로 푸시합니다. 자세한 내용은 [푸시 시 LFS 객체 누락](../../../topics/git/lfs/troubleshooting.md#lfs-objects-are-missing-on-push)을 참조하세요.
- `uploads`: 해결 방법이 없습니다. 자세한 내용은 [이슈 526344](https://gitlab.com/gitlab-org/gitlab/-/issues/526344)를 참조하세요.
