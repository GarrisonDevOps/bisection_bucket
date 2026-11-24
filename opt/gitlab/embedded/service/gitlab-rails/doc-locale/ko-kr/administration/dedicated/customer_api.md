---
stage: GitLab Dedicated
group: Switchboard
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab Dedicated 인스턴스의 상태 및 유지보수 기간을 검색하고 구성을 업데이트하는 REST API입니다.
title: Switchboard 고객 API
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Dedicated

{{< /details >}}

이 API를 사용하여 [GitLab Dedicated](_index.md) 인스턴스의 상태 및 유지보수 기간을 검색하고, Switchboard 콘솔에서 편집할 수 있는 구성을 업데이트합니다.

API는 테넌트 관리자 액세스 권한이 있는 인스턴스에 대한 데이터만 반환합니다. 경로에 인스턴스를 포함하지 않습니다. API는 액세스 권한에서 이를 가져옵니다.

모든 엔드포인트는 이 기본 URL을 사용합니다:

```plaintext
https://console.gitlab-dedicated.com/api/customer/v1
```

Switchboard 콘솔의 URL이 다른 경우, 로그인하는 콘솔의 URL을 사용하세요. 클라이언트 ID와 엔드포인트 경로는 모든 콘솔에서 동일합니다.

전제 조건:

- Switchboard에서 인스턴스에 대한 테넌트 관리자 액세스 권한이 있어야 합니다.

## 인증 {#authentication}

`Authorization` 헤더에 Switchboard OAuth 2.0 액세스 토큰이 있어야 합니다.

Switchboard는 PKCE(Proof Key for Code Exchange)를 포함한 OAuth 2.0 인증 코드 플로우를 통해 토큰을 제공합니다. 공개 클라이언트 `switchboard_customer_api_auth`을(를) 사용하세요. 이 클라이언트에는 클라이언트 비밀이 없습니다. `read_write` 범위를 요청하세요.

액세스 토큰은 24시간 후에 만료됩니다. 토큰 응답에는 새로 고침 토큰도 있습니다. 브라우저에 로그인하지 않고 새 액세스 토큰을 얻으려면 새로 고침 토큰을 사용하세요.

### 액세스 토큰 가져오기 {#get-an-access-token}

표준을 따르는 모든 OAuth 2.0 클라이언트를 사용할 수 있습니다. 이 예제에서는 [oauth2c](https://github.com/cloudentity/oauth2c)를 사용합니다.

액세스 토큰을 얻으려면 다음을 수행하세요:

1. 다음 명령을 실행합니다:

   ```shell
   oauth2c https://console.gitlab-dedicated.com \
     --client-id switchboard_customer_api_auth \
     --grant-type authorization_code \
     --response-types code \
     --response-mode query \
     --auth-method none \
     --scopes read_write \
     --pkce \
     --redirect-url http://localhost:3290/callback \
     --authorization-endpoint https://console.gitlab-dedicated.com/oauth/authorize \
     --token-endpoint https://console.gitlab-dedicated.com/oauth/token
   ```

   명령이 브라우저를 엽니다.
1. Switchboard에 로그인하세요.
1. 요청을 승인하세요.

명령이 `http://localhost:3290/callback`에서 콜백을 가져오고 액세스 토큰을 표시합니다. 각 요청에서 토큰을 보내세요:

```shell
curl --request GET \
  --header "Authorization: Bearer <your_access_token>" \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant/sla_status"
```

### 액세스 토큰 새로 고침 {#refresh-an-access-token}

브라우저에 로그인하지 않고 새 토큰 쌍을 얻으려면 새로 고침 토큰을 토큰 엔드포인트로 보내세요:

```shell
curl --request POST \
  --url "https://console.gitlab-dedicated.com/oauth/token" \
  --data "grant_type=refresh_token" \
  --data "client_id=switchboard_customer_api_auth" \
  --data "refresh_token=<your_refresh_token>"
```

각 새로 고침마다 새 새로 고침 토큰이 반환됩니다. 최신 새로 고침 토큰을 유지하세요.

브라우저에 처음 로그인한 후 최대 30일 동안 토큰을 새로 고칠 수 있습니다. 30일이 지난 후 또는 Switchboard에서 토큰을 취소하면 토큰 엔드포인트가 `invalid_grant`을(를) 반환합니다. 계속하려면 브라우저에 로그인하여 새 액세스 토큰을 얻으세요.

## 속도 제한 {#rate-limits}

Switchboard는 1분 윈도우에서 각 액세스 토큰 및 각 소스 IP 주소에 대한 요청을 계산합니다.

| 한도 | 분당 요청 수 |
|-------|--------------------------|
| 각 액세스 토큰 | 60 |
| 각 소스 IP 주소 | 120 |
| 토큰 엔드포인트(`/oauth/token`), 각 소스 IP 주소 | 20 |

한도가 적용되면 응답에 최대값에 가장 가까운 한도에 대한 다음 헤더가 있습니다:

| 헤더 | 설명 |
|--------|-------------|
| `RateLimit-Limit` | 현재 윈도우에서 한도가 허용하는 요청 수입니다. |
| `RateLimit-Remaining` | 현재 윈도우에서 한도가 여전히 허용하는 요청 수입니다. |
| `RateLimit-Reset` | 현재 윈도우가 재설정되는 Unix 시간(초)입니다. 이 값은 시간이며 카운트다운이 아닙니다. |

응답에 이러한 헤더가 없으면 요청에 적용된 한도가 없습니다. 헤더의 값을 사용하세요. 표의 숫자를 고정된 값으로 사용하지 마세요.

요청이 한도를 초과하면 API가 `429 Too Many Requests`을(를) 반환합니다. `Retry-After` 헤더는 대기할 시간(초)을 제공합니다. 한도를 초과하는 동안 수행하는 요청도 한도에 대해 계산됩니다. 클라이언트가 계속 요청을 보내면 윈도우가 재설정될 때까지 차단된 상태가 유지됩니다.

## 오류 {#errors}

모든 엔드포인트는 다음 상태 코드를 반환할 수 있습니다:

| 상태 코드 | 설명 |
|-------------|-------------|
| `401 Unauthorized` | 액세스 토큰이 유효하지 않거나 요청에 액세스 토큰이 없습니다. |
| `403 Forbidden` | 필요한 액세스 권한이 없습니다. |
| `404 Not Found` | 고객 API는 인스턴스에서 사용할 수 없거나 항목이 존재하지 않습니다. |
| `422 Unprocessable Entity` | Switchboard에서 변경을 수락하지 않았습니다. 응답 본문에 문제가 표시됩니다. |
| `429 Too Many Requests` | 요청이 속도 제한을 초과했습니다. |

오류 응답에는 `message` 특성이 있습니다. 일부 오류에는 더 자세한 정보를 담은 `errors` 특성도 있습니다.

## 페이지 매김 {#pagination}

목록 엔드포인트는 한 페이지의 항목을 반환합니다. 다음 특성을 사용하여 페이지를 선택하세요:

| 속성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `page` | 정수 | 아니요 | 페이지 번호입니다. 첫 번째 페이지는 `1`입니다. |
| `per_page` | 정수 | 아니요 | 각 페이지의 항목 수입니다. 최대값은 `100`입니다. |

응답에는 `items` 배열과 `meta` 객체가 있습니다:

| 속성 | 형식 | 설명 |
|-----------|------|-------------|
| `meta.current_page` | 정수 | 이 응답의 페이지 번호입니다. |
| `meta.total` | 정수 | 모든 페이지의 항목 수입니다. |
| `meta.total_pages` | 정수 | 페이지 수입니다. |

## 인스턴스 세부정보 검색 {#retrieve-instance-details}

인스턴스에 대한 세부정보를 검색합니다.

```plaintext
GET /tenant
```

성공하면 [`200 OK`](../../api/rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성 | 형식 | 설명 |
|-----------|------|-------------|
| `ever_deployed` | 부울 | `true`는 인스턴스의 첫 번째 배포 후입니다. 값은 프로비저닝 해제 후에도 `true`로 유지됩니다. |
| `external_url` | 문자열 | GitLab 인스턴스의 URL입니다. |
| `gitlab_version` | 문자열 | 인스턴스에 현재 있는 GitLab 버전입니다. |
| `identifier` | 문자열 | 인스턴스의 안정적인 식별자입니다. 인스턴스에 대해 Support에 문의할 때 이 값을 사용하세요. |
| `name` | 문자열 | 인스턴스의 표시 이름입니다. |
| `prerelease_version` | 문자열 | 인스턴스가 프리릴리스 버전을 실행하는 경우, 인스턴스의 프리릴리스 버전입니다. 그렇지 않으면 `null`입니다. |
| `reference_architecture_label` | 문자열 | 예를 들어 `Up to 10,000 users (XL)`과(와) 같은 인스턴스의 크기입니다. |
| `regions` | 개체 | 인스턴스의 클라우드 리전: `primary`, `backup`, `sites`. 인스턴스의 클라우드 계정이 구성되기 전에는 `null`입니다. |

요청 예:

```shell
curl --request GET \
  --header "Authorization: Bearer <your_access_token>" \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant"
```

응답 예:

```json
{
  "identifier": "example1a2b3c",
  "name": "Example Corp",
  "external_url": "https://example.gitlab-dedicated.com",
  "gitlab_version": "19.3.3",
  "prerelease_version": null,
  "reference_architecture_label": "Up to 10,000 users (XL)",
  "ever_deployed": true,
  "regions": {
    "primary": "eu-west-1",
    "backup": "eu-central-1",
    "sites": ["eu-west-1"]
  }
}
```

## SLA 상태 검색 {#retrieve-sla-status}

인스턴스의 가장 최근 가용성 상태를 검색합니다. 상태는 Switchboard의 **상태** 페이지와 동일한 데이터를 표시합니다.

> [!note]
> 상태는 계약상 서비스 수준 약정(SLA)이 아닙니다. GitLab은 월간 SLA를 별도로 계산하며, 자체 집계 및 제외 항목이 있습니다. 하나의 `down` 상태는 SLA 위반을 나타내지 않습니다. API는 과거 데이터를 반환하지 않습니다. 모니터링 또는 경고 피드로 사용하지 마세요.

```plaintext
GET /tenant/sla_status
```

성공하면 [`200 OK`](../../api/rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성 | 형식 | 설명 |
|-----------|------|-------------|
| `covered_experiences` | 배열 | 예를 들어 `web`, `git_operations`, `api`, `package_registry`와 같은 각 적용 범위 경험의 상태입니다. 각 항목에는 `covered_experience`, `status`, `data_as_of`이(가) 있습니다. `data_available`이(가) `false`이면 비어 있습니다. |
| `data_as_of` | 문자열 | Switchboard가 관찰한 가장 최근 분의 UTC 시간입니다. `data_available`이(가) `false`이면 `null`입니다. |
| `data_available` | 부울 | 응답에 상태가 있으면 `true`입니다. 응답에 `reason`이(가) 있으면 `false`입니다. |
| `reason` | 문자열 | 상태를 사용할 수 없는 이유입니다. `data_available`이(가) `false`일 때만 설정됩니다. |
| `status` | 문자열 | Switchboard가 관찰한 가장 최근 분의 인스턴스 상태입니다. `data_available`이(가) `false`이면 `null`입니다. |

`status` 특성은 다음 값 중 하나를 가집니다:

| 값 | 설명 |
|-------|-------------|
| `up` | 인스턴스에 알려진 문제가 없습니다. |
| `down` | 인스턴스에 서비스 중단이 있습니다. |
| `maintenance_window` | 인스턴스는 예약된 유지보수 중입니다. |
| `insufficient_traffic` | 인스턴스의 가용성을 계산할 트래픽이 너무 적습니다. 인스턴스가 조용할 때 일반적입니다. 중단을 나타내지 않습니다. |

`reason` 특성은 다음 값 중 하나를 가집니다:

| 값 | 설명 |
|-------|-------------|
| `not_configured` | 인스턴스에 대해 SLA 보고가 켜지지 않았습니다. SLA 보고가 필요하면 Support에 문의하세요. |
| `no_data` | SLA 보고가 켜져 있지만 Switchboard에는 지난 6시간의 데이터가 없습니다. 새 인스턴스 또는 보고가 짧은 시간 동안 중지될 때 일반적입니다. |
| `upstream_error` | 데이터를 가져올 때 Switchboard에 일시적 오류가 발생했습니다. 잠시 후 다시 시도하세요. |

요청 예:

```shell
curl --request GET \
  --header "Authorization: Bearer <your_access_token>" \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant/sla_status"
```

응답 예:

```json
{
  "data_available": true,
  "status": "up",
  "data_as_of": "2026-10-08T09:41:00.000Z",
  "reason": null,
  "covered_experiences": [
    { "covered_experience": "web", "status": "up", "data_as_of": "2026-10-08T09:41:00.000Z" },
    { "covered_experience": "git_operations", "status": "up", "data_as_of": "2026-10-08T09:41:00.000Z" }
  ]
}
```

## 모든 유지보수 기간 나열 {#list-all-maintenance-windows}

인스턴스의 모든 계획된 유지보수 기간을 나열합니다. 목록에는 미래의 기간과 완료된 기간이 있습니다.

```plaintext
GET /tenant/maintenances
```

지원되는 속성:

| 속성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `page` | 정수 | 아니요 | 페이지 번호입니다. |
| `per_page` | 정수 | 아니요 | 각 페이지의 항목 수입니다. 최대값은 `100`입니다. |
| `scope` | 문자열 | 아니요 | 반환할 기간: `all`(기본값), `upcoming`, 또는 `past`. `upcoming`는 가장 가까운 기간을 먼저 표시합니다. `all` 및 `past`은 가장 최근 기간을 먼저 표시합니다. |

[`200 OK`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 `items` 배열을 반환합니다. 각 항목에는 다음 특성이 있습니다:

| 속성 | 형식 | 설명 |
|-----------|------|-------------|
| `approval_status` | 문자열 | `pending`, `approved` 또는 `rejected` 중 하나입니다. |
| `completed_at` | 문자열 | 유지보수가 완료된 시간입니다. 유지보수가 완료될 때까지 `null`입니다. |
| `emergency` | 부울 | `true`은(는) 일반적인 기간 외의 긴급 유지보수용입니다. |
| `end_at` | 문자열 | 기간의 예약된 종료 시간입니다. |
| `gitlab_version` | 문자열 | 유지보수가 배포하는 GitLab 버전입니다. |
| `gitlab_version_pinned` | 부울 | 인스턴스에 대해 GitLab 버전 업그레이드가 보류 중인 경우 `true`입니다. |
| `id` | 정수 | 유지보수 기간의 ID입니다. |
| `previous_gitlab_version` | 문자열 | 유지보수 전의 GitLab 버전입니다. 미래 기간의 경우 인스턴스에 현재 있는 버전입니다. |
| `start_at` | 문자열 | 기간의 예약된 시작 시간입니다. |
| `started_at` | 문자열 | 유지보수가 시작된 시간입니다. 유지보수가 시작될 때까지 `null`입니다. |
| `status` | 문자열 | `planned`, `running`, `completed`, `failed`, `interrupted` 또는 `not_run` 중 하나입니다. |

`scope` 값을 알 수 없으면 API가 `422 Unprocessable Entity`을(를) 반환합니다.

요청 예:

```shell
curl --request GET \
  --header "Authorization: Bearer <your_access_token>" \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant/maintenances?scope=upcoming"
```

응답 예:

```json
{
  "items": [
    {
      "id": 4821,
      "start_at": "2026-10-11T21:00:00.000Z",
      "end_at": "2026-10-12T01:00:00.000Z",
      "started_at": null,
      "completed_at": null,
      "status": "planned",
      "approval_status": "approved",
      "emergency": false,
      "gitlab_version": "19.3.4",
      "previous_gitlab_version": "19.3.3",
      "gitlab_version_pinned": false
    }
  ],
  "meta": { "current_page": 1, "total": 1, "total_pages": 1 }
}
```

## 모든 구성 변경 나열 {#list-all-configuration-changes}

인스턴스의 모든 구성 변경을 나열합니다. 가장 최근 변경이 먼저 표시됩니다. 각 변경 사항은 변경된 내용, 시간, 변경 사항이 인스턴스에 있는지 여부를 표시합니다.

```plaintext
GET /tenant/config_changes
```

지원되는 속성:

| 속성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `page` | 정수 | 아니요 | 페이지 번호입니다. |
| `per_page` | 정수 | 아니요 | 각 페이지의 항목 수입니다. 최대값은 `100`입니다. |

[`200 OK`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 `items` 배열을 반환합니다. 각 항목에는 다음 특성이 있습니다:

| 속성 | 형식 | 설명 |
|-----------|------|-------------|
| `completed_at` | 문자열 | 변경이 인스턴스에 도달한 시간입니다. 그때까지 `null`입니다. |
| `config_type` | 문자열 | 변경된 구성의 이름입니다. |
| `id` | 정수 | 변경의 ID입니다. |
| `requested_at` | 문자열 | 변경 요청의 시간입니다. |
| `status` | 문자열 | `pending`, `queued`, `deployed`, 또는 `failed` 중 하나입니다. |

요청 예:

```shell
curl --request GET \
  --header "Authorization: Bearer <your_access_token>" \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant/config_changes?per_page=20"
```

응답 예:

```json
{
  "items": [
    {
      "id": 912,
      "config_type": "IP allowlist",
      "status": "deployed",
      "requested_at": "2026-10-06T14:02:11.000Z",
      "completed_at": "2026-10-06T14:20:47.000Z"
    }
  ],
  "meta": { "current_page": 1, "total": 1, "total_pages": 1 }
}
```

## 구성 {#configuration}

이러한 엔드포인트는 Switchboard 콘솔에서 편집할 수 있는 설정을 검색하고 업데이트합니다. 각 엔드포인트는 콘솔의 한 섹션과 일치합니다.

`PUT` 엔드포인트는 전체 섹션을 바꿉니다. 원하는 전체 구성을 보내세요. Switchboard는 전송하지 않은 항목을 제거합니다. 한 항목을 변경하려면 섹션을 가져오고, 항목을 변경한 후, 전체 섹션을 다시 보내세요. `PUT` 엔드포인트는 관련된 `GET` 엔드포인트의 응답을 변경 없이 허용합니다. Switchboard가 설정한 특성을 무시합니다.

Switchboard는 인스턴스의 구성 변경에서 각 변경을 기록합니다. 연락처 정보 변경은 이 기록에 포함되지 않습니다.

### IP 허용 목록 검색 {#retrieve-ip-allowlist}

인스턴스의 IP 허용 목록을 검색합니다.

```plaintext
GET /tenant/ip_allowlist
```

성공하면 [`200 OK`](../../api/rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성 | 형식 | 설명 |
|-----------|------|-------------|
| `addresses` | 배열 | 허용된 주소입니다. 각 항목에는 `address`, `description`, `status`, `created_at`가 있습니다. |
| `addresses[].address` | 문자열 | IPv4 또는 IPv6 CIDR 블록입니다. |
| `addresses[].created_at` | 문자열 | 주소를 추가한 시간입니다. Switchboard가 이 값을 설정합니다. |
| `addresses[].description` | 문자열 | 주소에 대한 설명입니다. |
| `addresses[].status` | 문자열 | 주소가 인스턴스에 있는지 표시합니다. Switchboard가 이 값을 설정합니다. |
| `enabled` | 부울 | `true`이면 인스턴스가 허용 목록을 사용합니다. `false`이면 인스턴스가 모든 소스 주소를 허용합니다. |

### IP 허용 목록 바꾸기 {#replace-ip-allowlist}

인스턴스의 IP 허용 목록을 바꿉니다.

```plaintext
PUT /tenant/ip_allowlist
```

지원되는 속성:

| 속성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `addresses` | 배열 | 예 | 허용된 주소의 전체 목록입니다. 각 항목에는 `address`(필수) 및 `description`가 있습니다. |
| `enabled` | 부울 | 예 | `true`을(를) 사용하여 허용 목록을 사용합니다. |

[`200 OK`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 업데이트된 허용 목록을 반환합니다.

요청 예:

```shell
curl --request PUT \
  --header "Authorization: Bearer <your_access_token>" \
  --header "Content-Type: application/json" \
  --data '{"enabled": true, "addresses": [{"address": "203.0.113.0/24", "description": "Office"}]}' \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant/ip_allowlist"
```

### 연락처 정보 검색 {#retrieve-contact-information}

GitLab이 인스턴스에 대해 연락하기 위해 사용하는 운영 이메일 주소를 검색합니다.

```plaintext
GET /tenant/contact_information
```

성공하면 [`200 OK`](../../api/rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성 | 형식 | 설명 |
|-----------|------|-------------|
| `operational_email_addresses` | 문자열 배열 | 인스턴스에 대한 운영 공지사항의 이메일 주소입니다. |

### 연락처 정보 바꾸기 {#replace-contact-information}

인스턴스의 운영 이메일 주소를 바꿉니다.

```plaintext
PUT /tenant/contact_information
```

지원되는 속성:

| 속성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `operational_email_addresses` | 문자열 배열 | 예 | 이메일 주소의 전체 목록입니다. |

[`200 OK`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 업데이트된 연락처 정보를 반환합니다.

GitLab은 내부 연락처 및 할당된 지원 엔지니어를 설정합니다. 이 API를 사용하여 읽거나 변경할 수 없습니다.

### 리소스 액세스 설정 검색 {#retrieve-resource-access-settings}

인스턴스의 애플리케이션 로그 버킷을 읽을 수 있는 AWS 보안 주체를 검색합니다.

```plaintext
GET /tenant/resource_access
```

성공하면 [`200 OK`](../../api/rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성 | 형식 | 설명 |
|-----------|------|-------------|
| `bucket_read_arns` | 문자열 배열 | 애플리케이션 로그 버킷을 읽을 수 있는 AWS 보안 주체 ARN입니다. |

### 리소스 액세스 설정 바꾸기 {#replace-resource-access-settings}

인스턴스의 애플리케이션 로그 버킷을 읽을 수 있는 AWS 보안 주체를 바꿉니다.

```plaintext
PUT /tenant/resource_access
```

지원되는 속성:

| 속성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `bucket_read_arns` | 문자열 배열 | 예 | AWS 보안 주체 ARN의 전체 목록입니다. |

[`200 OK`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 업데이트된 설정을 반환합니다.

### 모든 사용자 정의 인증 기관 나열 {#list-all-custom-certificate-authorities}

인스턴스가 신뢰하는 모든 사용자 정의 인증 기관을 나열합니다.

```plaintext
GET /tenant/custom_certificate_authorities
```

[`200 OK`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 배열을 반환합니다. 각 항목에는 다음 특성이 있습니다:

| 속성 | 형식 | 설명 |
|-----------|------|-------------|
| `authority` | 문자열 | 발급자입니다. Switchboard가 인증서에서 이 값을 가져옵니다. |
| `certificate` | 문자열 | PEM 인코딩 인증서입니다. |
| `id` | 정수 | 인증 기관의 ID입니다. |
| `not_after` | 문자열 | 인증서의 유효 기간 끝입니다. |
| `not_before` | 문자열 | 인증서의 유효 기간 시작입니다. |

### 사용자 정의 인증 기관 바꾸기 {#replace-custom-certificate-authorities}

인스턴스가 신뢰하는 사용자 정의 인증 기관을 바꿉니다.

```plaintext
PUT /tenant/custom_certificate_authorities
```

지원되는 속성:

| 속성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `certificates` | 문자열 배열 | 예 | 신뢰할 PEM 인코딩 인증서의 전체 집합입니다. |

[`200 OK`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 업데이트된 목록을 반환합니다.

한 인증서가 유효하지 않거나 만료된 경우 Switchboard는 요청을 수락하지 않습니다. 오류에서 인증서의 인덱스를 표시합니다.

### 모든 SAML SSO 제공자 나열 {#list-all-saml-sso-providers}

인스턴스의 모든 SAML 단일 로그온(SSO) 제공자를 나열합니다. 가장 오래된 것이 먼저 표시됩니다.

```plaintext
GET /tenant/saml_providers
```

[`200 OK`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 제공자 배열을 반환합니다. 각 제공자는 [제공자 특성](#saml-sso-provider-attributes)과 `id`을(를) 가집니다.

### SAML SSO 제공자 검색 {#retrieve-a-saml-sso-provider}

인스턴스의 한 SAML SSO 제공자를 검색합니다.

```plaintext
GET /tenant/saml_providers/:id
```

| 속성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `id` | 정수 | 예 | 제공자의 ID입니다. |

[`200 OK`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 제공자를 반환합니다. 제공자가 존재하지 않으면 `404 Not Found`을(를) 반환합니다.

### SAML SSO 제공자 만들기 {#create-a-saml-sso-provider}

인스턴스에서 SAML SSO 제공자를 만듭니다.

```plaintext
POST /tenant/saml_providers
```

[제공자 특성](#saml-sso-provider-attributes)을(를) 보내세요.

[`201 Created`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 새 제공자를 반환합니다.

### SAML SSO 제공자 바꾸기 {#replace-a-saml-sso-provider}

인스턴스의 한 SAML SSO 제공자를 바꿉니다.

```plaintext
PUT /tenant/saml_providers/:id
```

전체 제공자를 보내세요. 선택적 특성을 보내지 않으면 Switchboard가 이를 지웁니다. 예를 들어 `admin_groups`을(를) 보내지 않으면 Switchboard가 그룹을 관리자로 매핑하는 것을 제거합니다.

[`200 OK`](../../api/rest/troubleshooting.md#status-codes)을(를) 반환하면 성공하고 업데이트된 제공자를 반환합니다.

### SAML SSO 제공자 삭제 {#delete-a-saml-sso-provider}

인스턴스에서 한 SAML SSO 제공자를 삭제합니다.

```plaintext
DELETE /tenant/saml_providers/:id
```

성공하면 [`204 No Content`](../../api/rest/troubleshooting.md#status-codes)를 반환합니다.

### SAML SSO 제공자 특성 {#saml-sso-provider-attributes}

| 속성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `enabled` | 부울 | 예 | `true`을(를) 사용하여 제공자를 켭니다. |
| `idp_cert_fingerprint` | 문자열 | 예 | ID 제공자 인증서의 지문입니다. |
| `idp_sso_target_url` | 문자열 | 예 | ID 제공자의 SSO URL입니다. |
| `label` | 문자열 | 예 | 로그인 버튼의 이름입니다. |
| `name_identifier_format` | 문자열 | 예 | 이름 식별자 형식입니다. |
| `admin_groups` | 문자열 배열 | 아니요 | 구성원이 관리자인 그룹입니다. |
| `attribute_statements` | 개체 | 아니요 | SAML 특성을 사용자 특성으로 매핑합니다. |
| `auditor_groups` | 문자열 배열 | 아니요 | 구성원이 감사자인 그룹입니다. |
| `external_groups` | 문자열 배열 | 아니요 | 구성원이 외부 사용자인 그룹입니다. |
| `force_authn` | 부울 | 아니요 | `true`을(를) 사용하여 ID 제공자에게 다시 인증을 요청하도록 합니다. |
| `groups_attribute` | 문자열 | 아니요 | 사용자의 그룹을 가지고 있는 SAML 특성입니다. |
| `issuer` | 문자열 | 아니요 | 발급자입니다. |
| `required_groups` | 문자열 배열 | 아니요 | 사용자가 로그인하기 위해 있어야 하는 그룹입니다. |
| `security` | 개체 | 아니요 | SAML 보안 설정입니다. |
| `upstream_two_factor_authn_contexts` | 문자열 배열 | 아니요 | 2단계 인증으로 계산되는 인증 컨텍스트입니다. |

이러한 설정에 대한 자세한 내용은 [GitLab Dedicated용 SAML SSO](configure_instance/authentication/saml.md)를 참조하세요.

## 관련 항목 {#related-topics}

- [GitLab Dedicated 인스턴스 세부정보](tenant_overview.md)
- [GitLab Dedicated 유지보수 작업](maintenance.md)
