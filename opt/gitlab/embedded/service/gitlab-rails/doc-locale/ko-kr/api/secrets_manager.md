---
stage: Software Supply Chain Security
group: Pipeline Security
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Secrets Manager API
description: GitLab Secrets Manager용 단기 액세스 토큰을 발급하는 REST API입니다.
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed
- 상태: 베타

{{< /details >}}

{{< history >}}

- GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/594090)되었으며 [플래그](../administration/feature_flags/_index.md) `secrets_manager_api_access`를 사용합니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

이 API를 사용하여 비 CI/CD 워크로드에서 [GitLab Secrets Manager](../ci/secrets/secrets_manager/_index.md) 암호에 액세스합니다.

API는 프로젝트 또는 그룹에 대해 단기 JSON 웹 토큰(JWT)을 발급합니다. 클라이언트는 이 토큰을 OpenBao 백엔드에 제시하여 암호를 직접 읽으며, GitLab Runner가 CI/CD 작업 중에 암호를 읽는 것과 동일한 방식입니다. 응답에는 클라이언트가 필요로 하는 OpenBao 연결 세부 정보가 포함됩니다.

`api` 범위를 가진 개인 액세스 토큰, 프로젝트 또는 그룹 액세스 토큰, 또는 서비스 계정 토큰으로 이 API를 호출합니다. API가 반환하는 토큰은 GitLab 액세스 토큰이 아닌 별도의 단기 OpenBao JWT입니다. 5분 후 만료됩니다. 암호 값을 읽으려면 주체가 해당 암호에 대한 읽기 값 권한을 가져야 합니다.

반환된 연결 세부 정보를 사용하여 암호를 읽으려면 [비 CI/CD 워크로드에서 암호 액세스](../ci/secrets/secrets_manager/non_cicd_access.md)를 참조하세요.

## 프로젝트를 위한 Secrets Manager 액세스 토큰 생성 {#create-a-secrets-manager-access-token-for-a-project}

프로젝트의 암호를 읽기 위한 액세스 토큰을 발급합니다.

```plaintext
POST /projects/:id/secrets_manager/access_token
```

지원되는 속성:

| 속성 | 형식              | 필수 | 설명 |
|-----------|-------------------|----------|-------------|
| `id`      | 정수 또는 문자열 | 예      | 프로젝트의 ID 또는 [URL 인코딩 경로](rest/_index.md#namespaced-paths). |

요청 예:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/projects/1/secrets_manager/access_token"
```

응답 예:

```json
{
  "expires_at": "2026-05-27T10:35:00Z",
  "provider": {
    "vault": {
      "server": "https://secrets.gitlab.com",
      "namespace": "org_5/group_42/project_99",
      "path": "secrets/kv",
      "version": "v2",
      "secrets_path": "explicit",
      "auth": {
        "jwt": {
          "path": "api_jwt/cel",
          "role": "all_api",
          "token": "<JWT>"
        }
      }
    }
  }
}
```

응답 속성:

| 속성 | 형식 | 설명 |
|-----------|------|-------------|
| `expires_at` | 문자열 | 토큰이 만료되는 ISO 8601 타임스탬프입니다. 토큰은 5분 동안 유효합니다. |
| `provider.vault.server` | 문자열 | 연결할 OpenBao 서버의 URL입니다. GitLab.com에서 이것은 `https://secrets.gitlab.com`입니다. GitLab Self-Managed에서는 인스턴스에 대해 구성된 OpenBao URL입니다. |
| `provider.vault.namespace` | 문자열 | 프로젝트의 암호를 보유하는 OpenBao 네임스페이스입니다. 이것을 `X-Vault-Namespace` 헤더로 전달합니다. |
| `provider.vault.path` | 문자열 | KV 암호 엔진의 마운트 경로입니다. |
| `provider.vault.version` | 문자열 | KV 암호 엔진의 버전입니다. |
| `provider.vault.secrets_path` | 문자열 | 암호가 저장되는 KV 엔진 아래의 기본 경로입니다. 이것을 암호 이름에 앞에 두어 읽기 경로를 구성합니다(`<path>/data/<secrets_path>/<secret_name>`). |
| `provider.vault.auth.jwt.path` | 문자열 | JWT 인증 방법의 마운트 경로입니다. `auth/<path>/login`에서 인증합니다. |
| `provider.vault.auth.jwt.role` | 문자열 | 로그인할 JWT 인증 역할입니다. |
| `provider.vault.auth.jwt.token` | 문자열 | 클라이언트가 OpenBao에 제시하는 단기 JWT입니다. |

## 그룹을 위한 Secrets Manager 액세스 토큰 생성 {#create-a-secrets-manager-access-token-for-a-group}

그룹의 암호를 읽기 위한 액세스 토큰을 발급합니다.

```plaintext
POST /groups/:id/secrets_manager/access_token
```

지원되는 속성:

| 속성 | 형식              | 필수 | 설명 |
|-----------|-------------------|----------|-------------|
| `id`      | 정수 또는 문자열 | 예      | 그룹의 ID 또는 [URL 인코딩된 경로](rest/_index.md#namespaced-paths)입니다. |

요청 예:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/groups/1/secrets_manager/access_token"
```

응답 예:

```json
{
  "expires_at": "2026-05-27T10:35:00Z",
  "provider": {
    "vault": {
      "server": "https://secrets.gitlab.com",
      "namespace": "org_5/group_42/group_99",
      "path": "secrets/kv",
      "version": "v2",
      "secrets_path": "explicit",
      "auth": {
        "jwt": {
          "path": "api_jwt/cel",
          "role": "all_api",
          "token": "<JWT>"
        }
      }
    }
  }
}
```

응답 속성은 [프로젝트를 위한 Secrets Manager 액세스 토큰 생성](#create-a-secrets-manager-access-token-for-a-project)과 같으며, `provider.vault.namespace`는 그룹으로 범위가 지정됩니다.
