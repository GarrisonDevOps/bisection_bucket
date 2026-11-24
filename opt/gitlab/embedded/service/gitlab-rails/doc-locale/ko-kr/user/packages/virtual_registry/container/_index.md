---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 컨테이너 가상 레지스트리
description: 컨테이너 가상 레지스트리를 사용하여 업스트림 레지스트리에서 컨테이너 이미지를 캐시합니다.
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed
- 상태:  베타

{{< /details >}}

{{< history >}}

- GitLab 18.5에서 `container_virtual_registries`라는 [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/548794)되었습니다. 기본적으로 비활성화되었습니다.
- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/589631): GitLab 18.9에서 실험에서 베타로 변경됨.
- [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224250) (GitLab 18.10).

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

GitLab 컨테이너 가상 레지스트리는 업스트림 레지스트리에서 컨테이너 이미지를 캐시하는 데 사용할 수 있는 로컬 프록시입니다. 풀스루 캐시로 작동하며, 자주 액세스하는 이미지를 로컬에 저장하여 대역폭 사용을 줄이고 빌드 성능을 개선합니다.

## 사전 요구 사항 {#prerequisites}

컨테이너 가상 레지스트리를 사용하기 전에 다음을 수행하세요:

- 가상 레지스트리를 사용하기 위한 [전제 조건](../_index.md#prerequisites)을 검토하세요.
- 가상 레지스트리에 대한 인증을 구성합니다. 자세한 내용은 [가상 레지스트리에 인증](../_index.md#authenticate-to-the-virtual-registry)을 참조하세요.

컨테이너 가상 레지스트리를 사용할 때 다음 제한 사항을 기억하세요:

- 최상위 그룹당 최대 `5` 개의 컨테이너 가상 레지스트리를 생성할 수 있습니다.
- 주어진 컨테이너 가상 레지스트리에 `5` 개의 업스트림만 설정할 수 있습니다.
- 지역 지원은 구현되지 않았습니다.

## 가상 레지스트리 관리 {#manage-virtual-registries}

{{< history >}}

- `ui_for_container_virtual_registries`라는 이름의 [기능 플래그](../../../../administration/feature_flags/_index.md)로 GitLab 18.10에 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/19283)되었습니다.
- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/582167) (GitLab 18.11): `container_virtual_registries`이라는 플래그로 변경됨. 기능 플래그 `ui_for_container_virtual_registries`이 제거되었습니다.

{{< /history >}}

그룹의 컨테이너 가상 레지스트리를 관리합니다.

[API를 사용](../../../../api/container_virtual_registries.md)할 수도 있습니다.

### 컨테이너 가상 레지스트리 생성 {#create-a-container-virtual-registry}

컨테이너 가상 레지스트리를 생성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 레벨에 있어야 합니다.
1. **배포** > **가상 레지스트리**를 선택합니다.
1. 다음 조건에 해당하는 경우:
   - 기존 레지스트리가 있는 경우 **레지스트리 생성**을 선택합니다. 드롭다운 목록에서 **컨테이너**를 선택합니다.
   - 기존 레지스트리가 없는 경우, 드롭다운 목록에서 **컨테이너**를 선택합니다. 그런 다음 **레지스트리 생성**을 선택합니다.
1. **이름** 및 선택적 **설명**을 입력합니다.
1. **레지스트리 생성**을 선택합니다.

## 업스트림 레지스트리 관리 {#manage-upstream-registries}

가상 레지스트리에서 업스트림 컨테이너 레지스트리를 관리합니다.

### 컨테이너 업스트림 레지스트리 생성 {#create-a-container-upstream-registry}

컨테이너 업스트림 레지스트리를 생성하여 가상 레지스트리에 연결합니다.

사전 요구 사항:

- 컨테이너 가상 레지스트리가 있어야 합니다. 자세한 내용은 [가상 레지스트리 생성](#create-a-container-virtual-registry)을 참조하세요.

컨테이너 업스트림 레지스트리를 생성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 레벨에 있어야 합니다.
1. **배포** > **가상 레지스트리**를 선택합니다.
1. **레지스트리 유형** 아래에서 **레지스트리 보기**를 선택합니다.
1. **레지스트리** 탭 아래에서 레지스트리를 선택합니다.
1. **업스트림 추가**를 선택합니다. 가상 레지스트리에 기존 업스트림이 있는 경우, 드롭다운 목록에서 다음 중 하나를 선택합니다:
   - **새 업스트림 생성**하여 업스트림을 구성합니다.
   - **기존 업스트림 링크** > **기존 업스트림 선택**.
     1. 드롭다운 목록에서 업스트림을 선택합니다.
     1. 선택 사항. **업스트림 테스트**를 선택하여 생성하기 전에 업스트림 연결을 테스트합니다.
     1. **업스트림 추가**를 선택합니다.
1. 필드를 완성하세요.
   - **사용자명** 및 **암호**를 모두 포함하거나 둘 다 포함하지 않습니다. 설정하지 않으면 업스트림에 액세스할 때 공개(익명) 요청이 사용됩니다.
   - 업스트림을 Docker Hardened 이미지에 연결하려면 **업스트림 URL**로 다음을 사용하세요:

     ```plaintext
     https://dhi.io
     ```

   - 업스트림을 Docker Hub에 연결하려면 **업스트림 URL**로 다음을 사용하세요:

     ```plaintext
     https://registry-1.docker.io
     ```

     Docker Hub 레지스트리 API는 `registry-1.docker.io`에 호스트되며, `docker.io`에는 호스트되지 않습니다. 대부분의 컨테이너 도구는 `docker.io`을 자동으로 다시 작성하지만, 가상 레지스트리는 제공된 URL로 프록시합니다.

     `https://docker.io`을 사용하면 레지스트리는 OCI 응답 대신 HTML을 반환합니다.

   - **아티팩트 캐싱 기간**은 기본값으로 24시간입니다. `0`로 설정하여 캐시 항목 검사를 비활성화합니다.
   - 생성하기 전에 업스트림 연결을 테스트하려면 **업스트림 테스트**를 선택합니다.

1. **업스트림 생성**을 선택합니다.

캐시 유효성 설정에 대한 자세한 내용은 [캐시 유효성 기간 설정](../_index.md#set-the-cache-validity-period)을 참조하세요.

## 컨테이너 가상 레지스트리로 인증 {#authenticate-with-the-container-virtual-registry}

컨테이너 가상 레지스트리는 최상위 그룹과 연결된 레지스트리에 컨테이너 이미지를 저장하고 연결합니다. 컨테이너 이미지에 액세스하려면 그룹의 컨테이너 가상 레지스트리로 인증해야 합니다.

수동으로 인증하려면 다음 명령을 실행하세요:

```shell
echo "$CONTAINER_REGISTRY_PASSWORD" | docker login gitlab.example.com/virtual_registries/container/1 --username <your_username> --password-stdin
```

또는 [가상 레지스트리에 인증](../_index.md#authenticate-to-the-virtual-registry)에 설명된 방법 중 하나로 인증을 구성합니다.

컨테이너 가상 레지스트리는 [Docker v2 토큰 인증 흐름](https://distribution.github.io/distribution/spec/auth/token/)을 따릅니다:

1. 클라이언트 인증 후, 클라이언트에 발급된 JWT 토큰은 클라이언트가 컨테이너 이미지를 가져올 수 있도록 인증합니다.
1. 토큰은 만료 시간에 따라 만료됩니다.
1. 토큰이 만료되면, 대부분의 Docker 클라이언트는 사용자 자격 증명을 저장하고 추가 작업 없이 자동으로 새 토큰을 요청합니다.

## 가상 레지스트리에서 컨테이너 이미지 가져오기 {#pull-container-images-from-the-virtual-registry}

가상 레지스트리를 통해 컨테이너 이미지를 가져오려면:

1. 가상 레지스트리로 인증합니다.
1. 가상 레지스트리 URL 형식을 사용하여 이미지를 가져옵니다:

   ```plaintext
   gitlab.example.com/virtual_registries/container/<registry_id>/<image_path>:<tag>
   ```

예를 들어:

- 태그로 이미지를 가져옵니다:

  ```shell
  docker pull gitlab.example.com/virtual_registries/container/1/library/alpine:latest
  ```

- 다이제스트로 이미지를 가져옵니다:

  ```shell
  docker pull gitlab.example.com/virtual_registries/container/1/library/alpine@sha256:c9375e662992791e3f39e919b26f510e5254b42792519c180aad254e6b38f4dc
  ```

- `Dockerfile`에서 이미지를 가져옵니다:

  ```dockerfile
  FROM gitlab.example.com/virtual_registries/container/1/library/alpine:latest
  ```

- `.gitlab-ci.yml` 파일에서 이미지를 가져옵니다:

  ```yaml
  image: gitlab.example.com/virtual_registries/container/1/library/alpine:latest
  ```

이미지를 가져올 때 가상 레지스트리는:

1. 이미지가 이미 캐시되었는지 확인합니다.
   1. 이미지가 캐시되어 있고 업스트림의 `cache_validity_hours` 설정을 기반으로 유효한 경우, 이미지가 캐시에서 제공됩니다.
   1. 이미지가 캐시되지 않았거나 캐시가 무효인 경우, 이미지가 구성된 업스트림 레지스트리에서 가져와지고 캐시됩니다.
1. Docker 클라이언트에 이미지를 제공합니다.

### 가상 레지스트리 캐시 유효성 검사 (이미지용) {#virtual-registry-cache-validation-for-images}

`alpine:latest`과 같은 이미지 태그는 항상 이미지의 최신 버전을 가져옵니다. 새 버전에는 업데이트된 이미지 매니페스트가 포함됩니다. 컨테이너 가상 레지스트리는 매니페스트가 변경될 때 새 이미지를 가져오지 않습니다.

대신 컨테이너 가상 레지스트리는:

1. 업스트림의 `cache_validity_hours` 설정을 확인하여 이미지 매니페스트가 언제 무효인지 결정합니다.
1. 업스트림에 HEAD 요청을 보냅니다. 매니페스트가 무효이면 새 이미지가 가져와집니다.

예를 들어, 파이프라인이 `node:latest`을 가져오고 `cache_validity_period`을 24시간으로 설정한 경우, 가상 레지스트리는 이미지를 캐시하고 캐시가 만료되거나 `node:latest`이 업스트림에서 변경될 때 업데이트합니다.

## 문제 해결 {#troubleshooting}

### 인증 오류: `HTTP Basic: Access Denied` {#authentication-error-http-basic-access-denied}

가상 레지스트리에 대해 인증할 때 `HTTP Basic: Access denied` 오류가 발생하면 [2단계 인증 문제 해결](../../../profile/account/two_factor_authentication_troubleshooting.md#error-http-basic-access-denied-if-a-password-was-provided-for-git-authentication-)을 참조하세요.

### 가상 레지스트리 연결 실패 {#virtual-registry-connection-failure}

서비스 별칭이 설정되지 않으면 `docker:20.10.16` 이미지가 `dind` 서비스를 찾을 수 없으며 다음과 같은 오류가 발생합니다:

```plaintext
error during connect: Get http://docker:2376/v1.39/info: dial tcp: lookup docker on 192.168.0.1:53: no such host
```

이 오류를 해결하려면 Docker 서비스에 대한 서비스 별칭을 설정하세요:

```yaml
services:
  - name: docker:20.10.16-dind
    alias: docker
```

### CI/CD 작업에서 가상 레지스트리 인증 문제 {#virtual-registry-authentication-issues-from-cicd-jobs}

GitLab Runner는 CI/CD 작업 토큰을 사용하여 자동으로 인증합니다. 하지만 기본 Docker 엔진은 여전히 [인증 확인 프로세스](https://docs.gitlab.com/runner/configuration/advanced-configuration/#precedence-of-docker-authorization-resolving)의 적용을 받습니다.

인증 메커니즘의 잘못된 구성으로 인해 `HTTP Basic: Access denied` 및 `403: Access forbidden` 오류가 발생할 수 있습니다.

작업 로그를 사용하여 가상 레지스트리에 대해 인증하는 데 사용되는 인증 메커니즘을 볼 수 있습니다:

```plaintext
Authenticating with credentials from $DOCKER_AUTH_CONFIG
```

```plaintext
Authenticating with credentials from /root/.docker/config.json
```

```plaintext
Authenticating with credentials from job payload (GitLab Registry)
```

예상되는 인증 메커니즘을 사용하고 있는지 확인하세요.

### `Not Found` 또는 `404` 오류 (이미지 가져오기 중) {#not-found-or-404-error-when-pulling-image}

이러한 오류는 다음을 나타낼 수 있습니다:

- 작업을 실행 중인 사용자가 게스트, 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 없거나, `read_virtual_registry` 기능을 가진 최소 액세스가 있는 사용자 지정 역할이 없으며, 가상 레지스트리를 소유한 그룹에 대한 권한이 없습니다.
- URL의 가상 레지스트리 ID가 올바르지 않습니다.
- 업스트림 레지스트리에 요청된 이미지가 포함되어 있지 않습니다.
- 가상 레지스트리에 구성된 업스트림이 없습니다.

예제 오류 메시지:

```plaintext
ERROR: gitlab.example.com/virtual_registries/container/1/library/alpine:latest: not found
```

```plaintext
ERROR: Job failed: failed to pull image "gitlab.example.com/virtual_registries/container/1/library/alpine:latest" with specified policies [always]:
Error response from daemon: error parsing HTTP 404 response body: unexpected end of JSON input: "" (manager.go:237:1s)
```

이 오류들을 해결하려면:

1. 게스트, 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나, `read_virtual_registry` 기능을 가진 최소 액세스가 있는 사용자 지정 역할이 있는지 그룹에 대해 확인하세요.
1. 가상 레지스트리 ID가 올바른지 확인하세요.
1. 가상 레지스트리에 구성된 업스트림이 하나 이상 있는지 확인하세요.
1. 이미지가 업스트림 레지스트리에 존재하는지 확인하세요.

### 오류: `unexpected EOF` (S3 버킷에 Object Lock이 활성화됨) {#error-unexpected-eof-when-the-s3-bucket-has-object-lock-enabled}

Dependency Proxy의 객체 저장소 버킷에 S3 Object Lock이 활성화되면 컨테이너 이미지 가져오기가 레이어 중간에 `unexpected EOF`로 인해 실패할 수 있습니다.

Docker 클라이언트의 예제 오류:

```plaintext
sha256:9db411d588e2: Downloading [==================================================>]  12.18MB/12.18MB
unexpected EOF
```

GitLab Workhorse 로그는 업스트림 S3 `PutObject` 호출로부터 `400` 응답을 표시합니다:

```plaintext
operation error S3: PutObject, https response error StatusCode: 400, ...
InvalidRequest: Content-MD5 OR x-amz-checksum- HTTP header is required for
Put Object requests with Object Lock parameters
```

버킷에 Object Lock이 구성되면 S3는 모든 `PutObject` 요청에 무결성 헤더를 포함하도록 요구합니다. 기본적으로 Workhorse에서 사용하는 AWS SDK는 이러한 헤더를 보내지 않습니다. 업로드가 실패하면 Workhorse가 Docker 클라이언트로 스트리밍하는 응답이 잘립니다.

원인을 확인하려면:

1. Dependency Proxy 버킷에 Object Lock이 활성화되었는지 확인하세요:

   ```shell
   aws s3api get-object-lock-configuration --bucket DEPENDENCY_PROXY_BUCKET
   ```

   Object Lock이 활성화되면 응답에 `"ObjectLockEnabled": "Enabled"`이 포함됩니다.
1. 실패한 가져오기 중 Workhorse 로그를 검사하세요. `InvalidRequest: Content-MD5 OR x-amz-checksum-` 메시지가 원인을 확인합니다.

이 문제를 해결하려면:

1. Workhorse의 AWS SDK를 구성하여 체크섬 헤더를 보냅니다. Workhorse 컨테이너에서 다음 환경 변수를 모두 설정합니다:

   - `AWS_REQUEST_CHECKSUM_CALCULATION=when_supported`
   - `AWS_RESPONSE_CHECKSUM_VALIDATION=when_supported`

1. 다음의 경우:
   - Helm 차트로 설치한 GitLab의 경우, `values.yaml`에 변수를 추가하세요:

   ```yaml
   gitlab:
     webservice:
       extraEnv:
         AWS_REQUEST_CHECKSUM_CALCULATION: when_supported
         AWS_RESPONSE_CHECKSUM_VALIDATION: when_supported
   ```

   그런 다음 값을 적용합니다:

   ```shell
   helm upgrade gitlab gitlab/gitlab -f values.yaml
   ```

   - Linux 패키지로 설치한 GitLab의 경우, `/etc/gitlab/gitlab.rb`에 변수를 추가하세요:

   ```ruby
   gitlab_workhorse['env'] = {
     'AWS_REQUEST_CHECKSUM_CALCULATION' => 'when_supported',
     'AWS_RESPONSE_CHECKSUM_VALIDATION' => 'when_supported'
   }
   ```

   그런 다음 다시 구성합니다:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

Workhorse가 새 환경 변수로 다시 시작된 후 가져오기를 다시 시도합니다. 다음 요청은 Blob을 S3에 저장하고 전체 레이어를 Docker 클라이언트로 반환합니다.
