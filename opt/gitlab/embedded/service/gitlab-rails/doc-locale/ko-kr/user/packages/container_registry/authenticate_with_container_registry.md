---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "GitLab 로그인 자격 증명, 토큰 또는 CI 작업 토큰과 같은 CI/CD 변수를 사용하여 컨테이너 레지스트리로 인증하는 방법을 알아봅니다."
title: 컨테이너 레지스트리로 인증
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

컨테이너 레지스트리로 인증하려면 다음을 사용할 수 있습니다:

- GitLab 사용자 이름 및 암호(2FA가 활성화된 경우 사용 불가)
- [개인 액세스 토큰](../../profile/personal_access_tokens.md)
- [배포 토큰](../../project/deploy_tokens/_index.md)
- [프로젝트 액세스 토큰](../../project/settings/project_access_tokens.md)
- [그룹 액세스 토큰](../../group/settings/group_access_tokens.md)
- [GitLab CLI](https://docs.gitlab.com/cli/)

토큰 기반 인증 방법의 최소 필수 범위:

- 읽기(풀) 액세스의 경우 `read_registry`이어야 합니다.
- 쓰기(푸시) 액세스의 경우 `write_registry` 및 `read_registry`이어야 합니다.

> [!note]
> 관리자 모드는 컨테이너 레지스트리로 인증할 때 적용되지 않습니다. 관리자 권한이 있고 관리자 모드가 활성화된 경우, `admin_mode` 범위 없이 개인 액세스 토큰을 만들면 관리자 모드가 활성화되어 있어도 해당 토큰이 작동합니다. 자세한 내용은 [관리자 모드](../../../administration/settings/sign_in_restrictions.md#admin-mode)를 참조하세요.

## 사용자 이름 및 암호로 인증 {#authenticate-with-username-and-password}

> [!note]
> 계정에서 [2단계 인증(2FA)](../../profile/account/two_factor_authentication.md)(이메일 OTP 포함)를 활성화한 경우 [토큰으로 인증](#authenticate-with-a-token)해야 합니다.

사용자 이름 및 암호로 인증하려면 `docker login` 명령을 실행하세요:

```shell
docker login registry.example.com -u <username> -p <password>
```

보안상의 이유로 `-p` 대신 `--password-stdin` 플래그를 사용하는 것이 좋습니다:

```shell
echo "<password>" | docker login registry.example.com -u <username> --password-stdin
```

## 토큰으로 인증 {#authenticate-with-a-token}

토큰으로 인증하려면 `docker login` 명령을 실행하세요:

```shell
TOKEN=<token>
echo "$TOKEN" | docker login registry.example.com -u <username> --password-stdin
```

인증 후 클라이언트가 자격 증명을 캐시합니다. 이후 작업은 JWT 토큰을 반환하는 인증 요청을 만들며, 이는 지정된 작업만 수행하도록 승인됩니다. 토큰은 다음 기간 동안 유효합니다:

- GitLab Self-Managed의 경우 [기본적으로 5분](../../../administration/packages/container_registry.md#increase-token-duration)
- GitLab.com의 경우 [15분](../../gitlab_com/_index.md#container-registry)

## GitLab CI/CD를 사용하여 인증 {#use-gitlab-cicd-to-authenticate}

CI/CD를 사용하여 컨테이너 레지스트리로 인증하려면 다음을 사용할 수 있습니다:

- `CI_REGISTRY_USER` 및 `CI_REGISTRY_PASSWORD` CI/CD 변수입니다.

  `CI_REGISTRY_USER`은 컨테이너 레지스트리에 대한 읽기-쓰기 액세스 권한이 있는 작업별 사용자를 보유하고, `CI_REGISTRY_PASSWORD`는 자동으로 생성된 암호를 보유합니다.

  ```shell
  echo "$CI_REGISTRY_PASSWORD" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
  ```

- [CI 작업 토큰](../../../ci/jobs/ci_job_token.md)입니다.

  이 토큰은 작업을 실행하는 프로젝트의 컨테이너 레지스트리에 대한 읽기(풀) 및 쓰기(푸시) 액세스 권한이 있습니다. [CI/CD 작업 토큰 허용 목록](../../../ci/jobs/ci_job_token.md#control-job-token-access-to-your-project)은 다른 프로젝트의 레지스트리에 대한 액세스를 제어합니다.

  ```shell
  echo "$CI_JOB_TOKEN" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
  ```

  `gitlab-ci-token` 스키마를 사용할 수도 있습니다:

  ```shell
  echo "$CI_JOB_TOKEN" | docker login $CI_REGISTRY -u gitlab-ci-token --password-stdin
  ```

- 최소 범위가 포함된 [GitLab 배포 토큰](../../project/deploy_tokens/_index.md#gitlab-deploy-token)입니다:
  - 읽기(풀) 액세스의 경우 `read_registry`입니다.
  - 쓰기(푸시) 액세스의 경우 `read_registry` 및 `write_registry`입니다.

  ```shell
  echo "$CI_DEPLOY_PASSWORD" | docker login $CI_REGISTRY -u $CI_DEPLOY_USER --password-stdin
  ```

- 최소 범위가 포함된 개인 액세스 토큰입니다:
  - 읽기(풀) 액세스의 경우 `read_registry`입니다.
  - 쓰기(푸시) 액세스의 경우 `read_registry` 및 `write_registry`입니다.

  ```shell
  echo "<access_token>" | docker login $CI_REGISTRY -u <username> --password-stdin
  ```

## 문제 해결 {#troubleshooting}

### 오류: `docker login` 명령이 `access forbidden` {#error-docker-login-command-fails-with-access-forbidden}

컨테이너 레지스트리는 자격 증명을 확인하기 위해 GitLab API URL을 Docker 클라이언트에 반환합니다. Docker 클라이언트는 기본 인증을 사용하므로 요청에는 `Authorization` 헤더가 포함됩니다. `Authorization` 헤더가 레지스트리 구성에서 `token_realm`에 구성된 `/jwt/auth` 엔드포인트에 대한 요청에서 누락된 경우 `access forbidden` 오류 메시지가 표시됩니다.

예를 들어:

```plaintext
> docker login gitlab.example.com:4567

Username: user
Password:
Error response from daemon: Get "https://gitlab.company.com:4567/v2/": denied: access forbidden
```

이 오류를 방지하려면 `Authorization` 헤더가 요청에서 제거되지 않도록 하세요. 예를 들어 GitLab 앞의 프록시가 `/jwt/auth` 엔드포인트로 리디렉션될 수 있습니다.

Docker 클라이언트를 사용한 자격 증명 검증에 대한 자세한 내용은 [컨테이너 레지스트리 아키텍처](../../../administration/packages/container_registry.md#container-registry-architecture)를 참조하세요.

### 오류: `docker login`이 인증 오류로 실패함 {#error-docker-login-fails-with-an-authentication-error}

GitLab이 `docker login` 요청을 거부하면 Docker 클라이언트는 오류 코드 및 메시지가 포함된 JSON 오류 봉투를 표시합니다.

오류를 해결하려면 오류 코드를 식별하고 지침을 따르세요:

- `UNAUTHORIZED` (`401`): GitLab이 자격 증명을 확인할 수 없습니다. 해결하려면:
  - 암호 또는 토큰이 정확하고 만료되지 않았는지 확인하세요.
  - 개인 액세스 토큰 또는 배포 토큰에 풀 액세스를 위한 `read_registry` 범위가 있거나 푸시 액세스를 위한 `read_registry` 및 `write_registry` 범위가 있는지 확인하세요.
  - 계정이 2단계 인증을 사용하는 경우 암호 대신 토큰으로 인증하세요. 자세한 내용은 [토큰으로 인증](#authenticate-with-a-token)을 참조하세요.
- `DENIED` (`403`): GitLab이 액세스를 거부했습니다. 메시지를 확인하세요:
  - `access forbidden`: 자격 증명은 유효하지만 레지스트리 액세스 권한을 부여하지 않습니다. 토큰에 `read_registry` 범위(및 푸시 액세스를 위한 `write_registry`)가 있는지 확인하고 역할이 프로젝트의 레지스트리에 대한 액세스를 허용하는지 확인하세요.
  - `Pushing to protected repository path forbidden`: 대상 경로는 컨테이너 레지스트리 보호 규칙으로 보호됩니다.
  - `Access denied: too many failed authentication attempts from this network`: 남용 보호가 네트워크를 차단했습니다. 차단이 만료될 때까지 기다리거나 다른 네트워크에서 다시 시도하세요.
  - `Access denied: too many distinct sources for this account`: 계정이 너무 많은 IP 주소에서 사용되었습니다. 계정이 사용 중인 위치를 검토한 후 요청을 통합하거나 엇갈리게 하세요.
- `UNSUPPORTED` (`404`): GitLab이 요청한 인증 서비스를 인식하지 못합니다. 해결하려면:
  - 레지스트리 토큰 서비스가 올바르게 구성되었는지 확인하세요.

Docker 클라이언트가 대신 `unexpected end of JSON input`을 보고하면 응답 본문이 비어 있거나 유효하지 않은 JSON이 포함되어 있습니다:

### 오류: `unexpected end of JSON input` {#error-unexpected-end-of-json-input}

GitLab 앞의 프록시 또는 로드 밸런서가 응답 본문을 제거하면 다음 오류가 표시될 수 있습니다:

```plaintext
Error response from daemon: error parsing HTTP <status> response body: unexpected end of JSON input: ""
```

이 문제를 해결하려면 Docker 클라이언트와 GitLab 간의 요청 경로를 확인하세요.

### 오류: 큰 이미지를 푸시할 때 `unauthorized: authentication required` {#error-unauthorized-authentication-required-when-pushing-large-images}

큰 이미지를 푸시할 때 다음과 같은 인증 오류가 표시될 수 있습니다:

```shell
docker push gitlab.example.com/myproject/docs:latest
The push refers to a repository [gitlab.example.com/myproject/docs]
630816f32edb: Preparing
530d5553aec8: Preparing
...
4b0bab9ff599: Waiting
d1c800db26c7: Waiting
42755cf4ee95: Waiting
unauthorized: authentication required
```

이 오류는 이미지 푸시가 완료되기 전에 인증 토큰이 만료될 때 발생합니다. 기본적으로 GitLab Self-Managed 인스턴스의 컨테이너 레지스트리용 토큰은 5분 후 만료됩니다. GitLab.com에서 토큰 만료 시간은 15분입니다.
