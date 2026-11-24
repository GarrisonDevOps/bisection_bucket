---
stage: Software Supply Chain Security
group: Pipeline Security
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 프로젝트의 종속성 방화벽을 확인하고 평가하는 REST API입니다.
title: 종속성 방화벽 API
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태: 실험

{{< /details >}}

{{< history >}}

- GitLab 19.4에서 `dependency_firewall_phase1` [기능 플래그](../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/23242)되었습니다. 기본적으로 비활성화되어 있습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트용으로 사용 가능하지만 프로덕션 사용을 위한 준비가 되어 있지 않습니다.

이 API를 사용하여 프로젝트의 종속성 방화벽과 상호 작용합니다. 종속성 방화벽은 프로젝트의 보안 정책을 충족하지 않는 패키지를 가져오기 전에 차단합니다.

## 프로젝트의 종속성 방화벽 상태 검색 {#retrieve-status-of-dependency-firewall-for-a-project}

지정된 프로젝트의 종속성 방화벽 상태를 검색합니다. 이 엔드포인트를 사용하여 전체 실행에 대해 방화벽을 건너뛸지 여부를 결정합니다. 방화벽이 꺼져 있는 프로젝트는 `404 Not Found` 대신 성공적인 응답을 반환하므로 액세스할 수 없는 프로젝트와 구분할 수 있습니다.

이 엔드포인트는 개인 액세스 토큰, 프로젝트 액세스 토큰, 그룹 액세스 토큰, OAuth 토큰 또는 [CI/CD 작업 토큰](../ci/jobs/ci_job_token.md)을(를) 허용합니다. 배포 토큰은 지원되지 않습니다. 공개 프로젝트를 포함하여 인증되지 않은 요청은 거부됩니다.

CI/CD 작업 토큰은 특정 세분화된 권한이 필요하지 않습니다. 이를 제한하는 것은 작업이 실행되는 프로젝트입니다. 작업 토큰은 해당 프로젝트만 확인할 수 있습니다. 다른 프로젝트에 대한 요청은 `403 Forbidden`로 거부됩니다. 대상 프로젝트가 [인바운드 작업 토큰 허용 목록](../ci/jobs/ci_job_token.md)에서 작업 프로젝트를 허용하는 경우에도, 그리고 해당 허용 목록 항목이 부여하는 세분화된 권한에 관계없이 거부됩니다. 한 프로젝트의 방화벽 상태는 다른 프로젝트의 파이프라인이 필요로 하는 정보가 아닙니다.

전제 조건:

- 프로젝트를 읽을 수 있는 권한이 있어야 합니다.

```plaintext
GET /projects/:id/dependency_firewall/enablement
```

지원되는 속성:

| 속성 | 형식              | 필수 | 설명 |
| --------- | ----------------- | -------- | ----------- |
| `id`      | 정수 또는 문자열 | 예      | 프로젝트의 ID 또는 [URL 인코딩 경로](rest/_index.md#namespaced-paths). |

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성  | 형식    | 설명 |
| ---------- | ------- | ----------- |
| `enabled`  | 부울 | 프로젝트에 대해 종속성 방화벽이 활성화되어 있는지 여부입니다. 단일 통합 응답입니다. 응답에는 라이선스 또는 네임스페이스 설정이 이를 생성했는지 여부가 표시되지 않습니다. |

가능한 응답 코드:

| 상태 코드 | 설명 |
| ----------- | ----------- |
| `401`       | 인증되지 않음. 요청에 유효한 인증이 포함되지 않았습니다. |
| `403`       | 금지됨. 자격 증명은 이 엔드포인트를 사용할 수 없습니다. 작업이 실행되는 프로젝트 이외의 프로젝트에 대한 CI/CD 작업 토큰 또는 프로젝트를 읽을 수 있는 권한이 없는 세분화된 토큰입니다. 프로젝트를 읽을 수 없는 사용자는 대신 `404`을(를) 받습니다. |
| `404`       | 찾을 수 없음. 의미는 응답 본문이 사용하는 키에 따라 달라집니다: `enabled`, `message` 또는 `error`. 이 테이블 이후의 지침을 참조하세요. |
| `429`       | 요청이 너무 많습니다. 이 엔드포인트의 속도 제한을 초과했습니다. 이는 호출 사용자로 범위가 지정됩니다. 제한은 다른 프로젝트 엔드포인트의 제한과 별개입니다. |

기능 플래그가 꺼져 있는 동안 엔드포인트는 `404` 대신 `200`를 반환합니다. 엔드포인트가 아직 일반적으로 사용 가능하지 않기 때문입니다. `404` 응답은 따라서 세 가지 중 하나를 의미하며, 클라이언트는 텍스트의 표현 방식이 아니라 응답 본문이 사용하는 키에 따라 이를 구분합니다:

- `enabled` 키가 있는 본문(예: `{"enabled": false}`)은 이 프로젝트에 대해 기능 플래그가 꺼져 있음을 의미합니다. 방화벽이 활성화되지 않았으므로 클라이언트가 이 실행을 건너뛸 수 있습니다.
- `error` 키가 있는 본문(예: `{"error":"404 Not Found"}`)은 이 엔드포인트가 인스턴스에 존재하지 않음을 의미합니다. 예를 들어 인스턴스는 GitLab Community Edition을 실행하거나 이 엔드포인트가 추가되기 전에 릴리스된 버전을 실행할 수 있습니다. 클라이언트는 구성 문제를 보고하는 대신 이전 동작으로 돌아가야 합니다.
- `message` 키가 있는 본문은 엔드포인트가 존재하며 요청을 거부했음을 의미합니다. 프로젝트가 존재하지 않거나 읽을 수 없습니다. 클라이언트는 구성 문제를 보고해야 하며 프로젝트를 보호되지 않은 것으로 취급하면 안 됩니다.

메시지 텍스트를 기반으로 이 결정을 하지 마세요. 읽을 수 없는 프로젝트가 있는 호출자는 `{"message":"404 Project Not Found"}`을(를) 받지만 프로젝트에 대한 액세스 권한이 없는 세분화된 토큰은 `{"message":"404 Not Found"}`을(를) 받습니다. 이는 표현 방식만 비교하면 엔드포인트 누락 사례와 동일하게 읽힙니다.

요청 예:

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/projects/1/dependency_firewall/enablement"
```

응답 예:

```json
{
  "enabled": true
}
```

파이프라인 작업에서 인증하려면 [CI/CD 작업 토큰](../ci/jobs/ci_job_token.md)을(를) `JOB-TOKEN` 헤더와 함께 사용하세요:

```shell
curl --request GET \
  --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
  --url "https://gitlab.example.com/api/v4/projects/1/dependency_firewall/enablement"
```

## 프로젝트의 종속성 방화벽 정책에 대해 패키지 평가 {#evaluate-a-package-against-dependency-firewall-policies-for-a-project}

지정된 프로젝트의 종속성 방화벽 정책에 대해 단일 패키지를 평가합니다.

이 엔드포인트는 개인 액세스 토큰, 프로젝트 액세스 토큰, 그룹 액세스 토큰, OAuth 토큰 또는 [CI/CD 작업 토큰](../ci/jobs/ci_job_token.md)을(를) 허용합니다. 작업 토큰은 작업이 실행되는 프로젝트에 대한 패키지만 평가할 수 있습니다. 다른 프로젝트에 대한 작업 토큰은 `403 Forbidden` 상태 코드로 거부됩니다. 대상 프로젝트가 [인바운드 작업 토큰 허용 목록](../ci/jobs/ci_job_token.md)에서 작업 프로젝트를 허용하는 경우에도 그렇습니다. 배포 토큰은 지원되지 않습니다.

전제 조건:

- 프로젝트에 대해 최소한 보고자 역할이 있어야 합니다. 패키지 레지스트리를 켜야 할 필요가 없습니다. 종속성 방화벽은 업스트림 레지스트리에서 가져온 종속성을 평가하므로 평가 권한은 프로젝트의 패키지 레지스트리 설정과 관계없습니다.

```plaintext
POST /projects/:id/dependency_firewall/evaluate
```

지원되는 속성:

| 속성   | 형식              | 필수 | 설명 |
|-------------|-------------------|----------|-------------|
| `id`        | 정수 또는 문자열 | 예      | 프로젝트의 ID 또는 [URL 인코딩 경로](rest/_index.md#namespaced-paths). |
| `ecosystem` | 문자열            | 예      | 패키지 생태계입니다. `cargo`, `composer`, `conan`, `gem`, `golang`, `maven`, `npm`, `nuget`, `pub`, `pypi` 또는 `swift` 중 하나입니다. |
| `name`      | 문자열            | 예      | 패키지 이름, 최대 255자입니다. `maven`의 경우 `groupId:artifactId` 형식을 사용하세요. 예: `com.example:trivial-lib`. `pypi`의 경우 이름은 평가 전에 PEP 503에 따라 정규화되므로 `Flask_Login`와 `flask-login`은(는) 동등합니다. |
| `version`   | 문자열            | 예      | 패키지 버전, 최대 255자입니다. |
| `operation` | 문자열            | 아니요       | 평가 중인 패키지 작업입니다. `download` 또는 `upload` 중 하나입니다. 기본값은 `download`입니다. |

요청 헤더:

- `X-Gitlab-Dependency-Firewall-Session-Id`: 선택 사항입니다. 단일 패키지 관리자 호출의 모든 평가를 그룹화하므로 패키지당 하나의 평가를 트리거하는 단일 설치 명령을 이 값으로 상관 관계를 지정할 수 있습니다. GitLab은 감사 이벤트 및 평가의 분석 이벤트에 값을 기록하고 이를 검증하지 않고 불투명한 값으로 취급합니다.

값은 1자에서 255자여야 하며 문자, 숫자, 밑줄 및 하이픈만 포함할 수 있습니다. 값이 이러한 제약을 충족하지 않으면 GitLab은 이를 무시하고 평가는 헤더를 보내지 않은 것처럼 진행됩니다. 요청이 실패하지 않습니다.

성공하면 [`200 OK`](rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성 | 형식   | 설명 |
|-----------|--------|-------------|
| `outcome` | 문자열 | 평가 결과입니다. `allowed`, `warned` 또는 `blocked` 중 하나입니다. |
| `reason`  | 문자열 | 패키지가 경고되거나 차단된 이유를 설명하는 메시지입니다. 일치하는 정책의 이름입니다. `outcome`이(가) `allowed`일 때 `null`입니다. |

`outcome` 속성은 다음 값 중 하나입니다:

- `allowed`: 정책 규칙이 패키지와 일치하지 않았습니다. 종속성 방화벽이 활성화되어 있지만 연결된 정책이 없는 프로젝트는 항상 `allowed`을(를) 반환합니다. `allowed` 결과는 GitLab이 패키지에 대한 취약성 또는 라이선스 데이터를 보유하고 있음을 주장하지 않습니다. 패키지 메타데이터 데이터베이스에서 없는 패키지도 허용됩니다.
- `warned`: 정책 규칙이 패키지와 일치했고 일치하는 정책이 경고 모드입니다.
- `blocked`: 정책 규칙이 패키지와 일치했고 일치하는 정책이 적용 모드입니다.

이 엔드포인트는 다음 상태 코드도 반환할 수 있습니다:

| 상태 코드 | 코드 | 설명 |
|-------------|------|-------------|
| `400` | 없음 | `name` 또는 `version`이(가) 비어 있거나 `ecosystem` 또는 `operation`이(가) 허용된 값 중 하나가 아닙니다. |
| `401` | 없음 | 요청이 인증되지 않았습니다. |
| `403` | 없음 | 인증된 사용자가 프로젝트에 대해 최소한 보고자 역할이 없거나 요청이 작업이 실행되는 프로젝트 이외의 프로젝트에 대한 CI/CD 작업 토큰을 사용했습니다. |
| `404` | 없음 | 프로젝트가 존재하지 않거나 인증된 사용자가 액세스할 수 없거나 `dependency_firewall_phase1` 기능 플래그가 비활성화되어 있습니다. |
| `422` | `dependency_firewall_not_enforced` | 프로젝트에 대해 종속성 방화벽이 활성화되지 않았습니다. |
| `429` | 없음 | 이 엔드포인트의 속도 제한이 초과되었습니다. 제한은 프로젝트와 사용자의 조합으로 범위가 지정됩니다. |
| `503` | `dependency_firewall_evaluation_failed` | 패키지 메타데이터 조회가 완료되지 않았습니다. 페치를 차단합니다. |

요청 예:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --header "Content-Type: application/json" \
  --url "https://gitlab.example.com/api/v4/projects/1/dependency_firewall/evaluate" \
  --data '{"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}'
```

응답 예:

```json
{
  "outcome": "blocked",
  "reason": "Package 'lodash' violates 'deny-mit' policy"
}
```

종속성 방화벽이 활성화되어 있지만 연결된 정책이 없는 프로젝트의 응답 예시:

```json
{
  "outcome": "allowed",
  "reason": null
}
```

파이프라인 작업에서 [CI/CD 작업 토큰](../ci/jobs/ci_job_token.md)으로 인증:

```shell
curl --request POST \
  --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
  --header "Content-Type: application/json" \
  --url "https://gitlab.example.com/api/v4/projects/1/dependency_firewall/evaluate" \
  --data '{"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}'
```
