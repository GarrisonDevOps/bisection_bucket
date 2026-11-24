---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 오프라인 전송을 사용하여 그룹 및 프로젝트 마이그레이션
description: "객체 저장소를 통해 GitLab 그룹 및 프로젝트를 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed
- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- [도입](https://gitlab.com/groups/gitlab-org/-/work_items/8985)되었으며 GitLab 19.3에서 [실험](../../../policy/development_stages_support.md#experiment)으로 [기능 플래그](../../../administration/feature_flags/_index.md)(`offline_transfer_exports`, `offline_transfer_imports`, `offline_transfer_ui`)로 제공됩니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트 가능하지만 프로덕션 사용은 준비되지 않았습니다.

오프라인 전송은 원본 인스턴스와 대상 인스턴스 간의 직접 네트워크 연결 없이 객체 저장소를 통해 GitLab 그룹 및 프로젝트를 인스턴스 간에 복사합니다. 원본 인스턴스는 데이터를 저장소 버킷으로 내보내고, 대상 인스턴스는 액세스할 수 있는 버킷에서 데이터를 가져옵니다.

대상 인스턴스가 원본 인스턴스에 연결해야 하는 [직접 전송을 통한 마이그레이션](../../group/import/direct_transfer_migrations.md)과 달리 오프라인 전송은 내보내기와 가져오기를 분리합니다. 내보내기 버킷과 가져오기 버킷은 같은 버킷이거나 같은 객체 저장소 공급자를 사용할 필요가 없습니다. 대상 인스턴스가 내보내기 버킷에 액세스할 수 없는 경우, 내보내기 파일을 대상이 액세스할 수 있는 버킷으로 이동합니다. GitLab은 이 파일을 자동으로 이동하지 않습니다.

파일을 이동할 때 객체 키 구조를 유지합니다. 오프라인 전송은 내보내기 접두사에서 모든 객체 키를 구성합니다:

- `<export_prefix>/metadata.json.gz`
- `<export_prefix>/<entity_prefix>/<relation>.<extension>`
- `<export_prefix>/<entity_prefix>/<relation>/batch_<number>.<extension>`

예를 들어, `2026-04-16_19-39-00_export_dJtnb3CV/project_1/repository.tar.gz`입니다.

가져오기를 시작할 때 제공하므로 최상위 내보내기 접두사의 이름을 바꿀 수 있습니다. 내보내기 접두사 아래의 모든 항목은 동일한 구조 및 파일 이름을 유지해야 합니다.

인스턴스 간에 직접 연결이 없다고 해서 어느 인스턴스도 오프라인 상태가 아닙니다. 원본 및 대상 인스턴스 모두 내보내기 또는 가져오기를 수행하기 위해 객체 저장소에 대한 네트워크 액세스가 필요합니다.

오프라인 전송은 기능 플래그와 응용 프로그램 설정 모두로 제어됩니다. 모두 기본적으로 꺼져 있으며, 주어진 작업의 경우 두 계층 모두 켜져 있어야 합니다:

- 내보내기: `offline_transfer_exports_enabled` 응용 프로그램 설정입니다.
- 가져오기: `offline_transfer_imports_enabled` 응용 프로그램 설정입니다.

내보내기 및 가져오기를 수행하려면 [오프라인 전송 REST API](https://api.gitlab.com/rest/#gitlab/tag/offline-transfers)를 사용합니다. GitLab UI의 오프라인 전송 지원은 [작업 항목 19870](https://gitlab.com/groups/gitlab-org/-/work_items/19870)에서 제안됩니다.

## 버전 요구 사항 {#version-requirements}

오프라인 전송 내보내기를 만들려면 원본 인스턴스가 GitLab 19.3 이상을 실행해야 합니다. 내보내기를 가져오려면 대상 인스턴스가 GitLab 19.3 이상을 실행해야 합니다.

모든 내보내기는 이를 생성한 원본 인스턴스의 버전을 기록합니다. 해당 버전이 대상 인스턴스에서 지원하는 최소 버전보다 이전인 경우, `Unsupported GitLab version` 오류로 가져오기가 실패합니다.

## 지원되는 객체 저장소 공급자 {#supported-object-storage-providers}

오프라인 전송은 다음 객체 저장소 공급자를 지원합니다:

| 공급자 | 설명 |
| -------- | ----------- |
| AWS S3 | Amazon S3 객체 저장소입니다. |
| S3 호환 | MinIO 및 기타 S3 호환 공급자입니다. 관리자가 [S3 호환 객체 저장소를 켜야](../../../administration/settings/import_and_export_settings.md#allow-s3-compatible-object-storage-for-offline-transfer) 합니다. |
| Google Cloud Storage (서비스 계정) | 서비스 계정 JSON 키로 인증된 Google Cloud Storage입니다. |
| Google Cloud Storage (HMAC) | S3 상호 운용성 HMAC 키로 인증된 Google Cloud Storage입니다. |
| 응용 프로그램 기본 자격 증명을 사용한 Google Cloud Storage | 응용 프로그램 기본 자격 증명(ADC)으로 인증된 Google Cloud Storage입니다. 관리자 및 특정 버킷으로만 제한되며 GitLab.com에서 사용할 수 없습니다. 자세한 내용은 [응용 프로그램 기본 자격 증명](#application-default-credentials)을 참조하세요. |

### 필요한 권한 {#required-permissions}

제공하는 객체 저장소 자격 증명에는 다음 권한이 있어야 합니다.

AWS S3의 경우:

- 내보내기: `s3:PutObject` 및 `s3:ListBucket`
- 가져오기: `s3:GetObject` 및 `s3:ListBucket`

서비스 계정이 있는 Google Cloud Storage의 경우:

- 내보내기: `storage.buckets.get`, `storage.objects.create`, 및 `storage.objects.list`
- 가져오기: `storage.objects.get`

ADC를 사용한 Google Cloud Storage는 제공하는 키가 아니라 인스턴스의 서비스 계정이 보유한 동일한 권한이 필요합니다.

Google Cloud Storage HMAC 키는 S3 상호 운용성 API를 통해 인증되므로 `storage.*` 권한이 아닌 위에 나열된 AWS S3 권한이 필요합니다.

다른 S3 호환 공급자의 권한은 공급자에 따라 다릅니다. 공급자를 위에 나열된 AWS S3 권한과 동등한 읽기 및 쓰기 권한으로 구성합니다.

### 응용 프로그램 기본 자격 증명 {#application-default-credentials}

ADC를 사용한 Google Cloud Storage는 전송을 시작하는 사용자가 아니라 GitLab을 실행하는 인스턴스의 서비스 계정으로 인증됩니다. 해당 서비스 계정이 일반적으로 모든 개별 사용자보다 더 많은 권한이 있으므로 GitLab은 ADC 전송을 관리자 및 `gitlab-offline-transfer-`로 시작하는 이름의 버킷으로 제한합니다.

관리자는 또한 인스턴스에 대해 ADC를 켜야 합니다. 보안 영향 및 제한 사항의 전체 목록은 [오프라인 전송에 대한 응용 프로그램 기본 자격 증명 허용](../../../administration/settings/import_and_export_settings.md#allow-application-default-credentials-for-offline-transfer)을 참조하세요.

## 마이그레이션된 항목 {#migrated-items}

{{< history >}}

- 그룹 및 프로젝트 멤버십 가져오기가 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/538356)되었습니다.

{{< /history >}}

오프라인 전송은 직접 전송을 통한 마이그레이션과 동일한 그룹 및 프로젝트 항목을 가져옵니다. 전체 목록은 [마이그레이션된 그룹 항목](../../group/import/migrated_items.md#migrated-group-items) 및 [마이그레이션된 프로젝트 항목](../../group/import/migrated_items.md#migrated-project-items)을 참조하세요.

다음 항목은 오프라인 전송으로 가져오지 않습니다:

- 위키입니다. 위키 가져오기 지원은 [작업 항목 538858](https://gitlab.com/gitlab-org/gitlab/-/work_items/538858)에서 제안됩니다.
- 코드 조각입니다. 코드 조각 가져오기 지원은 [작업 항목 538347](https://gitlab.com/gitlab-org/gitlab/-/work_items/538347)에서 제안됩니다.
- 배지입니다. 배지 가져오기 지원은 [작업 항목 538355](https://gitlab.com/gitlab-org/gitlab/-/work_items/538355)에서 제안됩니다.

그룹을 가져올 때 하위 그룹 및 프로젝트가 내보내기에 있으면 항상 가져옵니다.

## 사용자 기여 매핑 {#user-contribution-mapping}

오프라인 전송은 대상 인스턴스에서 실제 사용자를 만들지 않습니다. 대신 가져온 기여도는 [자리 표시자 사용자](../../import/mapping/post_migration_mapping.md#placeholder-users)로 매핑됩니다. 가져오기가 완료되면 [자리 표시자 사용자를](../../import/mapping/reassignment.md) 대상 인스턴스의 사용자에게 다시 할당합니다.

오프라인 전송은 그룹 및 프로젝트 멤버십을 자리 표시자 멤버십으로 가져옵니다. 자리 표시자 사용자를 다시 할당할 때 GitLab은 해당 멤버십을 대상 인스턴스의 해당 사용자에게 다시 할당합니다.

## 표시 여부 규칙 {#visibility-rules}

오프라인 전송은 직접 전송을 통한 마이그레이션과 동일한 표시 여부 규칙을 적용합니다. 자세한 내용은 [표시 여부 규칙](../../group/import/_index.md#visibility-rules)을 참조하세요.

## 그룹 내보내기 및 가져오기 범위 {#group-export-and-import-scope}

GitLab은 전체 그룹 구조, 모든 하위 그룹 및 프로젝트를 얼마나 깊이 중첩되어 있든 내보냅니다. 그룹의 하위 그룹 또는 프로젝트의 하위 집합을 내보낼 수 없습니다.

GitLab은 내보낸 그룹의 하위 집합을 가져올 수 있습니다. 웨이브로 그룹을 마이그레이션하려는 경우:

1. 전체 그룹을 한 번 내보냅니다.
1. 가져올 때 각 웨이브마다 가져올 하위 그룹 및 프로젝트를 선택합니다.

또는 내보내기 요청에서 고유 엔터티로 각 프로젝트의 전체 경로를 제공하여 부모 그룹 대신 개별 프로젝트를 내보낼 수 있습니다.

## 그룹 또는 프로젝트 마이그레이션 {#migrate-a-group-or-project}

사전 요구 사항:

- 프로젝트를 내보내려면 프로젝트의 유지 관리자 역할이 최소한 필요합니다.
- 그룹을 내보내려면 그룹의 소유자 역할이 필요합니다.
- 그룹으로 가져오려면 대상 그룹의 소유자 역할이 필요합니다.
- 최상위 그룹으로 그룹을 가져오려면 그룹을 만들 수 있는 권한이 필요합니다.
- 내보내기 또는 가져오기에 응용 프로그램 기본 자격 증명을 사용하려면 관리자 액세스 권한이 필요합니다.

그룹 또는 프로젝트를 마이그레이션하려면:

1. 원본 인스턴스에서 REST API를 사용하여 [오프라인 전송 내보내기를 만들고](https://api.gitlab.com/rest/#gitlab/tag/offline-transfers/POST/api/v4/offline_exports) 객체 저장소 버킷으로 내보냅니다.
1. 내보내기가 완료되면 GitLab은 내보내기 접두사가 포함된 전자 메일을 보냅니다. 가져오기를 시작하려면 이 접두사가 필요합니다. 전자 메일을 받지 못한 경우 내보내기 접두사는 객체 저장소 서비스에서 볼 수 있습니다.
1. 대상 인스턴스가 내보내기 버킷에 액세스할 수 없는 경우, 내보내기 파일을 대상이 액세스할 수 있는 버킷으로 이동합니다.
1. 대상 인스턴스에서 [오프라인 전송 가져오기를 만들고](https://api.gitlab.com/rest/#gitlab/tag/offline-transfers/POST/api/v4/offline_imports) 버킷 및 내보내기 접두사에서 가져옵니다.
1. [그룹 및 프로젝트 직접 전송 API](../../../api/bulk_imports.md#retrieve-a-group-or-project-migration)를 통해 가져오기를 모니터링합니다.

## 전체 내보내기 가져오기 {#import-an-entire-export}

기본적으로 오프라인 전송 가져오기는 가져올 모든 그룹 또는 프로젝트 및 배치 위치를 나열하는 `entities` 배열이 필요합니다. 대신 `import_all` 객체를 전달하여 내보내기의 모든 최상위 그룹을 하위 그룹 및 프로젝트와 함께 가져올 수 있으며, 대상 네임스페이스 아래에서 원본 인스턴스의 구조를 다시 만듭니다. `entities` 또는 `import_all` 중 정확히 하나가 필요합니다.

전체 내보내기를 가져오려면 `import_all`을(를) `destination_namespace` 특성과 함께 [오프라인 전송 가져오기 만들기](https://api.gitlab.com/rest/#tag/offline-transfers/POST/api/v4/offline_imports) API에 전달합니다:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --header "Content-Type: application/json" \
  --url "https://gitlab.example.com/api/v4/offline_imports" \
  --data '{
    "bucket": "example-bucket",
    "export_prefix": "example-export-prefix",
    "aws_s3_configuration": {
      "aws_access_key_id": "<aws_access_key_id>",
      "aws_secret_access_key": "<aws_secret_access_key>",
      "region": "us-east-1"
    },
    "import_all": {
      "destination_namespace": "dest-group"
    }
  }'
```

`destination_namespace`을(를) 기존 그룹의 전체 경로(예: `dest-group/subgroup`)로 설정하여 해당 그룹 아래에서 구조를 다시 만듭니다. 빈 문자열(`""`)로 설정하여 구조를 새 최상위 그룹으로 다시 만듭니다.

최상위 그룹만 가져옵니다:

- 내보내기에 최상위 그룹 자체가 내보내지지 않은 경로가 포함되어 있으면(예: 내보내기에 `group-a/subgroup-b`은 포함되지만 `group-a`은 포함되지 않음), GitLab은 누락된 부모 그룹을 만드는 대신 해당 경로를 건너뜁니다.
- 최상위 그룹의 경로가 대상 네임스페이스의 기존 그룹과 충돌하면 GitLab은 해당 그룹 및 그 아래의 모든 항목을 건너뜁니다. 나머지 내보내기는 여전히 가져옵니다.
- 모든 최상위 그룹이 기존 대상 경로와 충돌하면 가져오기가 실패합니다.
- 내보내기에 최상위 그룹이 없으면 가져오기가 실패합니다.

[그룹 및 프로젝트 직접 전송 API](../../../api/bulk_imports.md#retrieve-a-group-or-project-migration)를 통해 가져오기를 모니터링합니다.

## 속도 제한 {#rate-limits}

오프라인 전송 내보내기 및 가져오기는 속도 제한이 있습니다. 자세한 내용은 [구성할 수 없는 속도 제한](../../../rate_limits/non_configurable.md)을 참조하세요.

## 파일 크기 제한 {#file-size-limits}

오프라인 전송 가져오기는 직접 전송 마이그레이션과 동일한 최대 다운로드 파일 크기를 적용합니다. 이 제한은 각 관계 파일 개별적으로 적용되므로 대규모 리포지토리 번들이 나머지 마이그레이션이 제한 아래에 맞아도 이를 초과할 수 있습니다. GitLab은 가져오기 중에 제한을 확인하므로 제한을 초과하는 파일은 내보내기를 대상 환경으로 이미 이동한 후에만 실패합니다.

마이그레이션에 대규모 리포지토리가 포함되면 가져오기를 시작하기 전에 대상 인스턴스의 관리자에게 이 제한을 늘려 달라고 요청하세요. 자세한 내용은 [직접 또는 오프라인 전송으로 가져오기 위한 최대 다운로드 파일 크기](../../../administration/settings/import_and_export_settings.md#maximum-download-file-size-for-imports-by-direct-or-offline-transfer)를 참조하세요.

## 객체 저장소 버킷 수명 주기 {#object-storage-bucket-lifecycle}

GitLab은 가져오기가 완료된 후 버킷에서 내보내기 파일을 삭제하지 않습니다. 내보내기에는 리포지토리 번들, LFS 객체, 업로드된 파일 및 설계 번들뿐만 아니라 이슈 및 머지 리퀘스트 설명 및 메모가 포함된 줄 바꿈 구분 JSON(NDJSON) 파일이 포함됩니다. 버킷을 나머지 GitLab 데이터에 적용하는 것과 동일한 데이터 처리 및 상주 제어로 취급합니다.

마이그레이션 후 내보내기 파일 유지 및 삭제는 사용자의 책임입니다.

## 관련 항목 {#related-topics}

- [직접 전송을 사용하여 그룹 및 프로젝트 마이그레이션](../../group/import/direct_transfer_migrations.md)

## 문제 해결 {#troubleshooting}

오프라인 전송을 사용한 마이그레이션에 문제가 있으면 다음 섹션에서 가능한 솔루션을 참조하세요.

### 객체 저장소에서 내보내기 데이터 지우기 {#clear-export-data-from-object-storage}

각 내보내기는 객체 저장소에서 새로운 접두사를 생성하므로 한 내보내기가 다른 내보내기를 덮어쓰지 않습니다. 실패한 내보내기에서 저장된 데이터를 삭제하는 것은 내보내기를 다시 시도하는 데 필요하지 않지만 객체 저장소 비용을 줄일 수 있습니다.

객체 저장소에서 내보내기 데이터를 제거하려면 제공한 버킷 및 내보내기 API에서 반환한 `export_prefix`을(를) 사용하여 데이터를 식별하고 삭제합니다. 객체 저장소 구성에 따라 이 작업은 되돌릴 수 없을 수 있습니다.

### 가져오기 오류 식별 {#identify-import-errors}

- `exceptions_json.log` 및 `importer.log`을(를) 검토하여 관련 오류를 찾으세요.
- Rails 콘솔에서 오류를 추출하는 방법에 대한 조언은 [직접 전송 마이그레이션 문제 해결](../../group/import/troubleshooting.md)을 참조하세요.

### 가져오기 다시 시도 {#retry-an-import}

가져오기를 다시 시도하려면:

1. 다시 시도하려는 그룹 또는 프로젝트를 삭제합니다. 전체 가져오기를 다시 시도하거나 그룹 또는 프로젝트의 하위 집합을 대상으로 할 수 있습니다:

   - [그룹 즉시 삭제](../../group/_index.md#delete-a-group-immediately)
   - [프로젝트 즉시 삭제](../../project/working_with_projects.md#delete-a-project-immediately)

1. REST API를 사용하여 전체 가져오기를 다시 시도하거나 `entities` 매개 변수에서 이전에 실패한 엔터티만 지정합니다.
