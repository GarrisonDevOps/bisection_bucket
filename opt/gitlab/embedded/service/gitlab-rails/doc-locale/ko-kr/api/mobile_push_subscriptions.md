---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 푸시 알림을 위한 모바일 디바이스를 등록 및 등록 해제하는 REST API입니다.
title: 모바일 푸시 구독 API
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.3에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248023)되었습니다. [기능 플래그](../administration/feature_flags/_index.md) `mobile_push_registration_api`로 이름이 지정됩니다. 기본적으로 비활성화되었습니다.
- 알림 전달은 GitLab 19.3에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248026)되었습니다. [기능 플래그](../administration/feature_flags/_index.md) `mobile_push_notifications_dispatch` 및 `mobile_push_notifications`로 이름이 지정됩니다. 기본적으로 비활성화되었습니다.
- 기능 플래그 `mobile_push_notifications`이(가) GitLab 19.6에서 [제거](https://gitlab.com/gitlab-org/gitlab/-/issues/607603)되었습니다.

{{< /history >}}

인증된 사용자의 [할 일 항목](todos.md)에 대한 푸시 알림을 수신하도록 모바일 디바이스를 등록합니다. 모든 푸시 알림은 할 일 항목에 해당합니다. 디바이스를 등록하면 자동으로 알림이 전달되지 않습니다. `mobile_push_notifications_dispatch` 기능 플래그를 사용하여 인스턴스에 대해 전달이 별도로 활성화됩니다.

## 디바이스 등록 {#register-a-device}

인증된 사용자를 위한 디바이스 토큰을 등록합니다. 이 엔드포인트는 멱등성(idempotent) upsert입니다. 기존 토큰을 다시 등록하면 해당 속성과 `last_seen_at` 타임스탬프가 새로 고쳐지므로 클라이언트가 애플리케이션 시작 시마다 다시 등록됩니다. 요청에서 생략된 속성은 토큰이 이미 등록된 경우 저장된 값을 유지합니다. 다른 사용자에게 속한 토큰을 등록하면 인증된 사용자에게 다시 할당됩니다.

각 사용자는 최대 20개의 디바이스를 등록할 수 있습니다. 90일 동안 보지 못한 구독은 자동으로 제거됩니다.

```plaintext
POST /user/push_subscriptions
```

지원되는 속성:

<!-- markdownlint-disable MD055 MD056 -->

| 속성          | 형식   | 필수 | 설명 |
|--------------------|--------|----------|-------------|
| `device_token`     | 문자열 | 예      | 16진수 APNs 디바이스 토큰입니다. |
| `platform`         | 문자열 | 아니요       | 디바이스 플랫폼입니다. `ios` 또는 `macos`. 새 등록의 기본값은 `ios`입니다. |
| `apns_environment` | 문자열 | 아니요       | 토큰이 발급된 APNs 환경: `production` 또는 `sandbox`입니다. 기본값: `production`. |
| `bundle_id`        | 문자열 | 아니요       | 애플리케이션 번들 식별자입니다. |
| `device_name`      | 문자열 | 아니요       | 사람이 읽을 수 있는 디바이스 이름입니다. |
| `app_version`      | 문자열 | 아니요       | 설치된 애플리케이션 버전입니다. |
| `locale`           | 문자열 | 아니요       | 디바이스 로캘입니다. |
| `payload_mode`     | 문자열 | 아니요       | `full`은 푸시 페이로드에서 알림 콘텐츠를 전송합니다. `id_only`은 콘텐츠 없는 페이로드에 대해 레코드 식별자만 전송합니다. 새 등록의 기본값은 `full`입니다. |
{.sortable}

<!-- markdownlint-enable MD055 MD056 -->

요청 예:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --data "device_token=abcdef0123456789abcdef0123456789" \
  --data "apns_environment=sandbox" \
  --url "https://gitlab.example.com/api/v4/user/push_subscriptions"
```

성공하면 [`201`](rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성    | 형식    | 설명 |
|--------------|---------|-------------|
| `id`         | 정수 | 구독의 ID입니다. |
| `created_at` | 문자열  | 구독이 생성된 날짜 및 시간(ISO 8601 형식)입니다. |

응답 예:

```json
{
  "id": 1,
  "created_at": "2026-07-30T18:15:31.189Z"
}
```

## 디바이스 등록 해제 {#unregister-a-device}

인증된 사용자의 디바이스 토큰에 대한 구독을 삭제합니다(예: 로그아웃 시). 토큰이 URL이 아닌 요청 본문에 전달되므로 액세스 로그에 나타나지 않습니다. 성공하면 `204 No Content`을(를) 반환하고, 일치하는 구독이 없으면 `404 Not Found`을(를) 반환합니다.

```plaintext
DELETE /user/push_subscriptions
```

지원되는 속성:

| 속성      | 형식   | 필수 | 설명 |
|----------------|--------|----------|-------------|
| `device_token` | 문자열 | 예      | 16진수 APNs 디바이스 토큰입니다. |

요청 예:

```shell
curl --request DELETE \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --data "device_token=abcdef0123456789abcdef0123456789" \
  --url "https://gitlab.example.com/api/v4/user/push_subscriptions"
```
