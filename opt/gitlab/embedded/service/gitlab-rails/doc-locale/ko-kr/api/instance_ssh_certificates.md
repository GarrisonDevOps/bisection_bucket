---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 인스턴스 SSH 인증서 API
description: "인스턴스 SSH 인증서 기관 공개 키를 나열, 추가 및 삭제하는 REST API입니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed
- 상태:  베타

{{< /details >}}

{{< history >}}

- GitLab 19.5에서 [소개](https://gitlab.com/gitlab-org/gitlab/-/work_items/611314)되었으며 [기능 플래그](../administration/feature_flags/_index.md)는 `instance_ssh_certificates`입니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트 가능하지만 프로덕션 사용은 준비되지 않았습니다.

이 API를 사용하여 인스턴스가 신뢰하는 SSH 인증서 기관(CA) 공개 키를 관리합니다. GitLab은 각 CA 공개 키를 데이터베이스에 저장하고 인스턴스 전체에서 신뢰하므로 `sshd_config` 또는 `gitlab-sshd` 구성 파일 변경 대신 API 호출로 CA를 회전합니다. 파일 기반 대안의 경우 [`gitlab-sshd`를 사용한 인스턴스 수준 SSH 인증서](../administration/operations/gitlab_sshd_ssh_certificates.md)를 참조하세요.

`key` 속성에는 CA 공개 키가 포함되어 있으며, 개인 키나 서명된 사용자 인증서가 아닙니다.

## 인증 및 가용성 {#authentication-and-availability}

모든 엔드포인트에는 [REST API](rest/authentication.md)로 인증된 관리자가 필요합니다. 인스턴스에 대해 관리자 모드가 활성화된 경우 기존 [관리자 모드 요구 사항](../administration/settings/sign_in_restrictions.md#admin-mode)이 적용되며, 개인 액세스 토큰 또는 OAuth 토큰의 `admin_mode` 범위가 포함됩니다.

GitLab은 기능 가용성 전에 인증 및 관리자 액세스를 확인합니다. 다음 오류는 기능 플래그가 비활성화된 경우에도 모든 엔드포인트에 적용됩니다:

| 상태 | 설명 |
|--------|-------------|
| `401 Unauthorized` | 요청이 인증되지 않았습니다. |
| `403 Forbidden` | 인증된 사용자가 관리자 액세스 권한을 갖고 있지 않습니다. |
| `404 Not Found` | 사용자가 관리자 액세스 권한을 가지고 있지만 기능을 사용할 수 없습니다. |

## 모든 인스턴스 SSH 인증서 나열 {#list-all-instance-ssh-certificates}

모든 인스턴스 SSH CA 공개 키 레코드를 내림차순 ID 순서로 나열합니다.

```plaintext
GET /admin/ssh_certificates
```

이 엔드포인트는 표준 [페이지 매김](rest/_index.md#offset-based-pagination)을 지원합니다.

| 특성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `page` | 정수 | 아니요 | 검색할 페이지입니다. 기본값: `1`. |
| `per_page` | 정수 | 아니요 | 페이지당 레코드 수입니다. 기본값: `20`. 최대: `100`. |

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes)과 다음 응답 속성을 포함한 객체 배열을 반환합니다:

| 특성 | 형식 | 설명 |
|-----------|------|-------------|
| `created_at` | 문자열 | 레코드가 생성된 날짜 및 시간(ISO 8601 형식)입니다. |
| `fingerprint` | 문자열 | SSH CA 공개 키의 SHA256 지문입니다. |
| `id` | 정수 | 인스턴스 SSH 인증서 레코드의 ID입니다. |
| `key` | 문자열 | SSH CA 공개 키입니다. |
| `title` | 문자열 | 레코드의 제목입니다. |

요청 예시:

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/admin/ssh_certificates?page=1&per_page=20"
```

응답 예시(`<ca_public_key>`는 전체 SSH CA 공개 키를 나타냅니다):

```json
[
  {
    "id": 2,
    "title": "Engineering CA",
    "key": "<ca_public_key>",
    "fingerprint": "<ca_public_key_fingerprint>",
    "created_at": "2026-09-08T12:39:00.172Z"
  },
  {
    "id": 1,
    "title": "Operations CA",
    "key": "<ca_public_key>",
    "fingerprint": "<ca_public_key_fingerprint>",
    "created_at": "2026-09-08T11:30:00.000Z"
  }
]
```

빈 결과는 `[]`을 반환합니다.

## 인스턴스 SSH 인증서 추가 {#add-an-instance-ssh-certificate}

인스턴스 SSH CA 공개 키 레코드를 추가합니다.

```plaintext
POST /admin/ssh_certificates
```

| 특성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `key` | 문자열 | 예 | SSH CA 공개 키입니다. 공백이 아니어야 합니다. 최대: 5,000자입니다. |
| `title` | 문자열 | 예 | 레코드의 제목입니다. 공백이 아니어야 합니다. 최대: 255자입니다. |

성공하면 [`201 Created`](rest/troubleshooting.md#status-codes)과 다음 응답 속성을 반환합니다:

| 특성 | 형식 | 설명 |
|-----------|------|-------------|
| `created_at` | 문자열 | 레코드가 생성된 날짜 및 시간(ISO 8601 형식)입니다. |
| `fingerprint` | 문자열 | SSH CA 공개 키의 SHA256 지문입니다. |
| `id` | 정수 | 인스턴스 SSH 인증서 레코드의 ID입니다. |
| `key` | 문자열 | SSH CA 공개 키입니다. |
| `title` | 문자열 | 레코드의 제목입니다. |

`/path/to/ca_key.pub`에 있는 CA 공개 키를 사용한 요청 예시:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --data-urlencode "title=Engineering CA" \
  --data-urlencode "key@/path/to/ca_key.pub" \
  --url "https://gitlab.example.com/api/v4/admin/ssh_certificates"
```

응답 예시:

```json
{
  "id": 2,
  "title": "Engineering CA",
  "key": "<ca_public_key>",
  "fingerprint": "<ca_public_key_fingerprint>",
  "created_at": "2026-09-08T12:39:00.172Z"
}
```

공유되는 인증 및 가용성 오류 외에도 이 엔드포인트는 다음을 반환할 수 있습니다:

| 상태 | 설명 |
|--------|-------------|
| `400 Bad Request` | 필수 매개변수가 누락되었거나 `title` 또는 `key`이(가) 최대 길이를 초과했습니다. |
| `422 Unprocessable Entity` | 값이 공백이거나 유효하지 않습니다. 또한 중복 키 지문의 경우 또는 [SSH 키 제한](../security/ssh_keys_restrictions.md) 또는 FIPS(Federal Information Processing Standards) 제한에 의해 거부된 키의 경우에도 반환됩니다. |

## 인스턴스 SSH 인증서 삭제 {#delete-an-instance-ssh-certificate}

지정된 인스턴스 SSH CA 공개 키 레코드를 삭제합니다.

```plaintext
DELETE /admin/ssh_certificates/:id
```

| 특성 | 형식 | 필수 | 설명 |
|-----------|------|----------|-------------|
| `id` | 정수 | 예 | 인스턴스 SSH 인증서 레코드의 ID입니다. |

성공하면 [`204 No Content`](rest/troubleshooting.md#status-codes)을 반환하고 응답 본문이 비어 있으며 응답 속성이 없습니다.

요청 예시:

```shell
curl --request DELETE \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/admin/ssh_certificates/2"
```

공유되는 인증 및 가용성 오류 외에도 이 엔드포인트는 다음을 반환할 수 있습니다:

| 상태 | 설명 |
|--------|-------------|
| `404 Not Found` | 지정된 ID를 가진 인스턴스 SSH 인증서 레코드가 없습니다. |
| `422 Unprocessable Entity` | GitLab이 레코드를 삭제할 수 없습니다. |
