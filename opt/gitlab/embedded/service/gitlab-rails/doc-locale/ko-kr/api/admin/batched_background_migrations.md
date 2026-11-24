---
stage: Data Access
group: Database Frameworks
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "배치 처리된 백그라운드 마이그레이션을 나열하고, 검색하고, 일시 중지하고, 재개하기 위한 REST API입니다."
title: 배치 처리된 백그라운드 마이그레이션 API
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

이 API를 사용하여 [배치 처리된 백그라운드 마이그레이션](../../update/background_migrations.md)을 모니터링하고 관리합니다.

전제 조건:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

## 최근 20개의 배치 처리된 백그라운드 마이그레이션 나열 {#list-the-last-20-batched-background-migrations}

모든 배치 처리된 백그라운드 마이그레이션을 나열합니다.

```plaintext
GET /api/v4/admin/batched_background_migrations
```

지원되는 속성:

| 속성        | 형식   | 필수 | 설명 |
|------------------|--------|----------|-------------|
| `database`       | 문자열 | 아니요       | 데이터베이스의 이름입니다. 기본값은 `main`입니다. |
| `job_class_name` | 문자열 | 아니요       | 작업 클래스 이름으로 마이그레이션을 필터링합니다. |

성공하면 [`200 OK`](../rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성                  | 형식     | 설명 |
|----------------------------|----------|-------------|
| `column_name`              | 문자열   | 마이그레이션이 반복되는 열의 이름입니다. |
| `created_at`               | 날짜/시간 | 마이그레이션이 생성된 시간의 타임스탬프입니다. |
| `estimated_time_remaining` | 문자열   | 마이그레이션이 완료될 때까지의 예상 시간입니다. 때때로 null입니다 |
| `id`                       | 정수  | 배치 처리된 백그라운드 마이그레이션의 ID입니다. |
| `job_class_name`           | 문자열   | 마이그레이션 작업 클래스의 이름입니다. |
| `progress`                 | float    | 마이그레이션의 완료 백분율입니다. |
| `status`                   | 문자열   | 마이그레이션의 상태입니다. `paused`, `active`, `finished`, `failed`, `finalizing` 또는 `finalized` 중 하나일 수 있습니다. |
| `table_name`               | 문자열   | 마이그레이션이 반복되는 테이블의 이름입니다. |

요청 예:

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/admin/batched_background_migrations"
```

응답 예:

```json
[
  {
    "id": 1234,
    "job_class_name": "CopyColumnUsingBackgroundMigrationJob",
    "table_name": "events",
    "column_name": "id",
    "status": "active",
    "progress": 50.0,
    "created_at": "2022-11-28T16:26:39+02:00",
    "estimated_time_remaining": "1 day"
  }
]
```

## 배치 처리된 백그라운드 마이그레이션 검색 {#retrieve-a-batched-background-migration}

배치 처리된 백그라운드 마이그레이션을 검색합니다.

```plaintext
GET /api/v4/admin/batched_background_migrations/:id
```

지원되는 속성:

| 속성  | 형식    | 필수 | 설명 |
|------------|---------|----------|-------------|
| `id`       | 정수 | 예      | 배치 처리된 백그라운드 마이그레이션의 ID입니다. |
| `database` | 문자열  | 아니요       | 데이터베이스의 이름입니다. 기본값은 `main`입니다. |

성공하면 [`200 OK`](../rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성                  | 형식     | 설명 |
|----------------------------|----------|-------------|
| `column_name`              | 문자열   | 마이그레이션이 반복되는 열의 이름입니다. |
| `created_at`               | 날짜/시간 | 마이그레이션이 생성된 시간의 타임스탬프입니다. |
| `estimated_time_remaining` | 문자열   | 마이그레이션이 완료될 때까지의 예상 시간입니다. |
| `id`                       | 정수  | 배치 처리된 백그라운드 마이그레이션의 ID입니다. |
| `job_class_name`           | 문자열   | 마이그레이션 작업 클래스의 이름입니다. |
| `progress`                 | float    | 마이그레이션의 완료 백분율입니다. |
| `status`                   | 문자열   | 마이그레이션의 상태입니다. `paused`, `active`, `finished`, `failed`, `finalizing` 또는 `finalized` 중 하나일 수 있습니다. |
| `table_name`               | 문자열   | 마이그레이션이 반복되는 테이블의 이름입니다. |

요청 예:

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/admin/batched_background_migrations/1234"
```

응답 예:

```json
{
  "id": 1234,
  "job_class_name": "CopyColumnUsingBackgroundMigrationJob",
  "table_name": "events",
  "column_name": "id",
  "status": "active",
  "progress": 50.0,
  "created_at": "2022-11-28T16:26:39+02:00",
  "estimated_time_remaining": "1 day"
}
```

## 배치 처리된 백그라운드 마이그레이션 일시 중지 {#pause-a-batched-background-migration}

배치 처리된 백그라운드 마이그레이션을 일시 중지합니다. `active` 상태의 마이그레이션만 일시 중지할 수 있습니다.

```plaintext
PUT /api/v4/admin/batched_background_migrations/:id/pause
```

지원되는 속성:

| 속성  | 형식    | 필수 | 설명 |
|------------|---------|----------|-------------|
| `id`       | 정수 | 예      | 배치 처리된 백그라운드 마이그레이션의 ID입니다. |
| `database` | 문자열  | 아니요       | 데이터베이스의 이름입니다. 기본값은 `main`입니다. |

성공하면 [`200 OK`](../rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성                  | 형식     | 설명 |
|----------------------------|----------|-------------|
| `column_name`              | 문자열   | 마이그레이션이 반복되는 열의 이름입니다. |
| `created_at`               | 날짜/시간 | 마이그레이션이 생성된 시간의 타임스탬프입니다. |
| `estimated_time_remaining` | 문자열   | 마이그레이션이 완료될 때까지의 예상 시간입니다. |
| `id`                       | 정수  | 배치 처리된 백그라운드 마이그레이션의 ID입니다. |
| `job_class_name`           | 문자열   | 마이그레이션 작업 클래스의 이름입니다. |
| `progress`                 | float    | 마이그레이션의 완료 백분율입니다. |
| `status`                   | 문자열   | 마이그레이션의 상태입니다. `paused`, `active`, `finished`, `failed`, `finalizing` 또는 `finalized` 중 하나일 수 있습니다. |
| `table_name`               | 문자열   | 마이그레이션이 반복되는 테이블의 이름입니다. |

마이그레이션이 `active` 상태가 아니면 [`422 Unprocessable Entity`](../rest/troubleshooting.md#status-codes)을 반환합니다.

요청 예:

```shell
curl --request PUT \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/admin/batched_background_migrations/1234/pause"
```

응답 예:

```json
{
  "id": 1234,
  "job_class_name": "CopyColumnUsingBackgroundMigrationJob",
  "table_name": "events",
  "column_name": "id",
  "status": "paused",
  "progress": 50.0,
  "created_at": "2022-11-28T16:26:39+02:00",
  "estimated_time_remaining": "1 day"
}
```

## 배치 처리된 백그라운드 마이그레이션 재개 {#resume-a-batched-background-migration}

배치 처리된 백그라운드 마이그레이션을 재개합니다. `paused` 상태의 마이그레이션만 재개할 수 있습니다.

```plaintext
PUT /api/v4/admin/batched_background_migrations/:id/resume
```

지원되는 속성:

| 속성  | 형식    | 필수 | 설명 |
|------------|---------|----------|-------------|
| `id`       | 정수 | 예      | 배치 처리된 백그라운드 마이그레이션의 ID입니다. |
| `database` | 문자열  | 아니요       | 데이터베이스의 이름입니다. 기본값은 `main`입니다. |

성공하면 [`200 OK`](../rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성                  | 형식     | 설명 |
|----------------------------|----------|-------------|
| `column_name`              | 문자열   | 마이그레이션이 반복되는 열의 이름입니다. |
| `created_at`               | 날짜/시간 | 마이그레이션이 생성된 시간의 타임스탬프입니다. |
| `estimated_time_remaining` | 문자열   | 마이그레이션이 완료될 때까지의 예상 시간입니다. |
| `id`                       | 정수  | 배치 처리된 백그라운드 마이그레이션의 ID입니다. |
| `job_class_name`           | 문자열   | 마이그레이션 작업 클래스의 이름입니다. |
| `progress`                 | float    | 마이그레이션의 완료 백분율입니다. |
| `status`                   | 문자열   | 마이그레이션의 상태입니다. `paused`, `active`, `finished`, `failed`, `finalizing` 또는 `finalized` 중 하나일 수 있습니다. |
| `table_name`               | 문자열   | 마이그레이션이 반복되는 테이블의 이름입니다. |

마이그레이션이 `paused` 상태가 아니면 [`422 Unprocessable Entity`](../rest/troubleshooting.md#status-codes)을 반환합니다.

요청 예:

```shell
curl --request PUT \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/admin/batched_background_migrations/1234/resume"
```

응답 예:

```json
{
  "id": 1234,
  "job_class_name": "CopyColumnUsingBackgroundMigrationJob",
  "table_name": "events",
  "column_name": "id",
  "status": "active",
  "progress": 50.0,
  "created_at": "2022-11-28T16:26:39+02:00",
  "estimated_time_remaining": "1 day"
}
```
