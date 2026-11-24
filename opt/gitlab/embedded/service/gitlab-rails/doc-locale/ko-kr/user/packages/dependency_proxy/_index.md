---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 컨테이너 이미지를 위한 의존성 프록시
description: 업스트림 컨테이너 이미지로부터의 데이터 전송을 줄이려면 컨테이너 이미지에 대해 GitLab 의존성 프록시를 구성하세요.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 의존성 프록시 컨테이너 이미지는 자주 접근하는 업스트림 이미지에 사용할 수 있는 로컬 프록시입니다.

CI/CD의 경우 의존성 프록시는 요청을 수신하고 레지스트리에서 업스트림 이미지를 반환하며 풀 스루 캐시 역할을 합니다.

## 사전 요구 사항 {#prerequisites}

컨테이너 이미지를 위한 의존성 프록시를 사용하려면 GitLab 인스턴스에 대해 활성화해야 합니다. 기본적으로 활성화되어 있지만 [관리자는 이를 비활성화할 수 있습니다](../../../administration/packages/dependency_proxy.md).

GitLab Self-Managed에서 관리자는 인증된 의존성 프록시 요청에 대해 전용 속도 제한을 구성할 수도 있습니다. 자세한 내용은 [사용자 및 IP 속도 제한](../../../administration/settings/user_and_ip_rate_limits.md#enable-authenticated-dependency-proxy-request-rate-limit)을 참조하세요.

### 지원되는 이미지 및 패키지 {#supported-images-and-packages}

다음 이미지 및 패키지가 지원됩니다.

| 이미지/패키지    | GitLab 버전 |
| ---------------- | -------------- |
| Docker           | 14.0+         |

계획된 추가 기능 목록을 보려면 [방향 페이지](https://about.gitlab.com/direction/package/#dependency-proxy)를 참조하세요.

## 그룹에 대한 의존성 프록시 활성화 또는 비활성화 {#enable-or-turn-off-the-dependency-proxy-for-a-group}

{{< history >}}

- 필수 역할이 GitLab 17.0에서 유지 관리자에서 소유자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/370471)되었습니다.

{{< /history >}}

그룹에 대한 의존성 프록시를 활성화하거나 비활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **의존성 프록시** 섹션을 확장하세요.
1. 프록시를 활성화하려면 **프록시 활성화**를 켜세요. 비활성화하려면 토글을 끄세요.

이 설정은 그룹의 의존성 프록시에만 영향을 미칩니다. 관리자만 전체 GitLab 인스턴스에 대해 [의존성 프록시를 켜거나 끌](../../../administration/packages/dependency_proxy.md) 수 있습니다.

## 컨테이너 이미지를 위한 의존성 프록시 보기 {#view-the-dependency-proxy-for-container-images}

컨테이너 이미지를 위한 의존성 프록시를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **의존성 프록시**를 선택하세요.

의존성 프록시는 프로젝트에 사용할 수 없습니다.

## Docker 이미지를 위한 의존성 프록시 사용 {#use-the-dependency-proxy-for-docker-images}

GitLab을 Docker 이미지 소스로 사용할 수 있습니다.

사전 요구 사항:

- 이미지는 [Docker Hub](https://hub.docker.com/)에 저장되어야 합니다.

### 컨테이너 이미지를 위한 의존성 프록시로 인증 {#authenticate-with-the-dependency-proxy-for-container-images}

{{< history >}}

- 배포 토큰 범위 `read_virtual_registry` 및 `write_virtual_registry`이(가) `dependency_proxy_read_write_scopes` 플래그를 사용하여 GitLab 17.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/336800)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/517249)하게 되었습니다. 기능 플래그 `dependency_proxy_read_write_scopes`이 제거되었습니다.

{{< /history >}}

의존성 프록시 컨테이너 이미지는 그룹과 관련된 공간에 Docker 이미지를 저장하므로 이를 사용하여 인증해야 합니다.

[개인 레지스트리에서 이미지를 사용하기 위한 지침](../../../ci/docker/using_docker_images.md#access-an-image-from-a-private-container-registry)을 따르되, `registry.example.com:5000` 대신 포트 없이 GitLab 도메인 `gitlab.example.com`을 사용하세요.

> [!note]
> [관리자 모드](../../../administration/settings/sign_in_restrictions.md#admin-mode)는 의존성 프록시 컨테이너 이미지로 인증할 때 적용되지 않습니다. 관리자 모드가 활성화된 관리자이고 `admin_mode` 범위 없이 개인 액세스 토큰을 만드는 경우, 관리자 모드가 활성화되어 있어도 해당 토큰이 작동합니다.

예를 들어 수동으로 로그인하려면:

```shell
echo "$CONTAINER_REGISTRY_PASSWORD" | docker login gitlab.example.com --username my_username --password-stdin
```

다음을 사용하여 인증할 수 있습니다:

- GitLab 사용자 이름과 비밀번호입니다.
- [GitLab CLI](https://docs.gitlab.com/cli/)입니다.
- [개인 액세스 토큰](../../profile/personal_access_tokens.md)입니다.
- [그룹 배포 토큰](../../project/deploy_tokens/_index.md)입니다.
- 그룹의 [그룹 액세스 토큰](../../group/settings/group_access_tokens.md)입니다.

토큰의 범위를 다음 중 하나로 설정해야 합니다:

- `api`: 전체 API 액세스 권한을 부여합니다.
- `read_registry`: 컨테이너 레지스트리에 대한 읽기 전용 액세스 권한을 부여합니다.
- `write_registry`: 컨테이너 레지스트리에 대한 읽기 및 쓰기 액세스 권한을 모두 부여합니다.
- `read_virtual_registry`: 그룹 수준 의존성 프록시를 통한 컨테이너 이미지에 대한 읽기 전용(풀) 액세스 권한을 부여합니다. 의존성 프록시가 활성화된 경우에만 사용 가능합니다.
- `write_virtual_registry`: 캐시된 이미지 채우기 및 정리를 포함하여 그룹 수준 의존성 프록시 캐시에 대한 쓰기 액세스 권한을 부여합니다. 또한 해당 캐시를 통한 풀 액세스 권한을 부여합니다. 프로젝트의 컨테이너 레지스트리에 대한 푸시 또는 삭제 액세스 권한을 부여하지 않습니다. 의존성 프록시가 켜진 경우에만 사용 가능합니다.

의존성 프록시 컨테이너 이미지로 인증할 때 토큰은 다음 범위 조합 중 하나를 포함해야 합니다:

- 컨테이너 레지스트리 범위: `read_registry` 및 `write_registry`입니다.
- 의존성 프록시 범위: `read_virtual_registry` 및 `write_virtual_registry`입니다. 의존성 프록시를 통해 이미지를 가져올 때 GitLab은 그룹 수준 의존성 프록시 캐시에 데이터를 씁니다.

개인 액세스 토큰 또는 사용자 이름과 비밀번호로 컨테이너 이미지를 위한 의존성 프록시에 액세스하는 사용자는 이미지를 가져올 그룹에 대해 게스트, 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

컨테이너 이미지를 위한 의존성 프록시는 [Docker v2 토큰 인증 흐름](https://distribution.github.io/distribution/spec/auth/token/)을 따르며, 풀에 사용할 JWT를 클라이언트에 발급합니다. 인증 결과로 발급된 JWT는 일정 시간이 지나면 만료됩니다. 토큰이 만료되면 대부분의 Docker 클라이언트는 자격 증명을 저장하고 추가 작업 없이 자동으로 새 토큰을 요청합니다.

토큰 만료 시간은 [구성 가능한 설정](../../../administration/packages/dependency_proxy.md#changing-the-jwt-expiration)입니다. GitLab.com에서 만료 시간은 15분입니다.

#### SAML SSO {#saml-sso}

[SSO 적용](../../group/saml_sso/_index.md#sso-enforcement)이 활성화되면 사용자가 의존성 프록시를 통해 컨테이너 이미지를 가져오기 전에 SSO를 통해 로그인해야 합니다.

SSO 적용은 [자동 병합](../../project/merge_requests/auto_merge.md)에도 영향을 미칩니다. SSO 세션이 자동 병합을 트리거하기 전에 만료되면 병합 파이프라인이 의존성 프록시를 통해 이미지를 가져오지 못합니다.

#### CI/CD 내에서 인증 {#authenticate-within-cicd}

러너는 컨테이너 이미지를 위한 의존성 프록시에 자동으로 로그인합니다. 의존성 프록시를 통해 가져오려면 [미리 정의된 변수](../../../ci/variables/predefined_variables.md) 중 하나를 사용하세요:

- `CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX`은(는) 최상위 그룹을 통해 가져옵니다.
- `CI_DEPENDENCY_PROXY_DIRECT_GROUP_IMAGE_PREFIX`은(는) 하위 그룹 또는 프로젝트가 있는 직접 그룹을 통해 가져옵니다.

최신 alpine 이미지를 가져오는 예:

```yaml
# .gitlab-ci.yml
image: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/alpine:latest
```

또한 사용할 수 있는 다른 미리 정의된 CI/CD 변수가 있습니다:

- `CI_DEPENDENCY_PROXY_USER`: 의존성 프록시에 로그인하기 위한 CI/CD 사용자입니다.
- `CI_DEPENDENCY_PROXY_PASSWORD`: 의존성 프록시에 로그인하기 위한 CI/CD 비밀번호
- `CI_DEPENDENCY_PROXY_SERVER`: 의존성 프록시에 로그인하기 위한 서버입니다.
- `CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX`: 최상위 그룹에서 의존성 프록시를 통해 이미지를 가져오기 위한 이미지 접두사입니다.
- `CI_DEPENDENCY_PROXY_DIRECT_GROUP_IMAGE_PREFIX`: 프로젝트가 속한 직접 그룹 또는 하위 그룹에서 의존성 프록시를 통해 이미지를 가져오기 위한 이미지 접두사입니다.

`CI_DEPENDENCY_PROXY_SERVER`, `CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX` 및 `CI_DEPENDENCY_PROXY_DIRECT_GROUP_IMAGE_PREFIX`은(는) 서버 포트를 포함합니다. 의존성 프록시 경로를 명시적으로 포함하는 경우 포트를 포함해야 합니다. 단, 포트를 포함하지 않고 의존성 프록시에 수동으로 로그인한 경우는 제외됩니다:

```shell
docker pull gitlab.example.com:443/my-group/dependency_proxy/containers/alpine:latest
```

의존성 프록시를 사용하여 이미지를 빌드할 때의 예:

```plaintext
# Dockerfile
FROM gitlab.example.com:443/my-group/dependency_proxy/containers/alpine:latest
```

```yaml
# .gitlab-ci.yml
image: docker:20.10.16

variables:
  DOCKER_HOST: tcp://docker:2375
  DOCKER_TLS_CERTDIR: ""

services:
  - docker:20.10.16-dind

build:
  image: docker:20.10.16-cli
  before_script:
    - echo "$CI_DEPENDENCY_PROXY_PASSWORD" | docker login $CI_DEPENDENCY_PROXY_SERVER -u $CI_DEPENDENCY_PROXY_USER --password-stdin
  script:
    - docker build -t test .
```

[사용자 정의 CI/CD 변수](../../../ci/variables/_index.md#for-a-project)를 사용하여 개인 액세스 토큰 또는 배포 토큰을 저장하고 액세스할 수도 있습니다.

### Docker Hub로 인증 {#authenticate-with-docker-hub}

{{< history >}}

- Docker Hub 자격 증명에 대한 지원이 GitLab 17.10에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/331741)되었습니다.
- UI 지원이 GitLab 17.11에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/521954)되었습니다.

{{< /history >}}

기본적으로 의존성 프록시는 Docker Hub에서 이미지를 가져올 때 자격 증명을 사용하지 않습니다. Docker Hub 자격 증명 또는 토큰을 사용하여 Docker Hub 인증을 구성할 수 있습니다.

Docker Hub로 인증하려면 다음을 사용할 수 있습니다:

- Docker Hub 사용자 이름과 비밀번호입니다.
  - 이 방법은 [SSO(Single Sign-On)를 적용](https://docs.docker.com/security/faqs/single-sign-on/enforcement-faqs/#does-docker-sso-support-authenticating-through-the-command-line)하는 Docker Hub 조직과 호환되지 않습니다.
- Docker Hub [개인 액세스 토큰](https://docs.docker.com/security/for-developers/access-tokens/)입니다.
- Docker Hub [조직 액세스 토큰](https://docs.docker.com/security/for-admins/access-tokens/)입니다.

#### 자격 증명 구성 {#configure-credentials}

그룹의 의존성 프록시에 대해 Docker Hub 자격 증명을 설정하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **의존성 프록시** 섹션을 확장하세요.
1. **프록시 활성화**를 켜세요.
1. **Docker Hub 인증** 아래에서 자격 증명을 입력하세요:
   - **ID**는 사용자 이름(비밀번호 또는 개인 액세스 토큰의 경우) 또는 조직 이름(조직 액세스 토큰의 경우)입니다.
   - **비밀**은 비밀번호, 개인 액세스 토큰 또는 조직 액세스 토큰입니다.

   두 필드를 모두 완성하거나 둘 다 비워 두어야 합니다. 두 필드를 모두 비우면 Docker Hub에 대한 요청은 인증되지 않습니다.

#### GraphQL API를 사용하여 자격 증명 구성 {#configure-credentials-using-the-graphql-api}

[GraphQL API](../../../api/graphql/_index.md)를 사용하여 의존성 프록시 설정에서 Docker Hub 자격 증명을 설정하려면:

1. GraphiQL로 이동하세요:
   - GitLab.com의 경우 <https://gitlab.com/-/graphql-explorer>을 사용하세요.
   - GitLab Self-Managed의 경우 `https://gitlab.example.com/-/graphql-explorer`을 사용하세요.
1. GraphiQL에서 다음 변형을 입력하세요:

   ```graphql
   mutation {
     updateDependencyProxySettings(input: {
       enabled: true,
         identity: "<identity>",
         secret: "<secret>",
         groupPath: "<group path>"
     }) {
       dependencyProxySetting {
        enabled
        identity
       }
       errors
     }
   }
   ```

   위치:
   - `<identity>`은 사용자 이름(비밀번호 또는 개인 액세스 토큰의 경우) 또는 조직 이름(조직 액세스 토큰의 경우)입니다.
   - `<secret>`은 비밀번호, 개인 액세스 토큰 또는 조직 액세스 토큰입니다.
   - `<group path>`은 의존성 프록시가 있는 그룹의 경로입니다.

1. **재생**을 선택하세요.
1. 결과 창에서 오류를 확인하세요.

#### 자격 증명 확인 {#verify-your-credentials}

의존성 프록시로 인증한 후 Docker 이미지를 가져와 Docker Hub 자격 증명을 확인하세요:

```shell
docker pull gitlab.example.com/groupname/dependency_proxy/containers/alpine:latest
```

인증이 성공하면 [Docker Hub 사용량 대시보드](https://hub.docker.com/usage/pulls)에서 활동을 볼 수 있습니다.

### 의존성 프록시 캐시에 Docker 이미지 저장 {#store-a-docker-image-in-dependency-proxy-cache}

Docker 이미지를 의존성 프록시 저장소에 저장하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **의존성 프록시**를 선택하세요.
1. **의존성 프록시 이미지 접두사**를 복사하세요.
1. 다음 명령 중 하나를 사용하세요. 이 예에서 이미지는 `alpine:latest`입니다.
1. 또한 다이제스트로 이미지를 가져와 정확히 어떤 버전의 이미지를 가져올지 지정할 수 있습니다.

   - 태그로 이미지를 가져오려면 이미지를 [`.gitlab-ci.yml`](../../../ci/yaml/_index.md#image) 파일에 추가하세요:

     ```shell
     image: gitlab.example.com/groupname/dependency_proxy/containers/alpine:latest
     ```

   - 다이제스트로 이미지를 가져오려면 이미지를 [`.gitlab-ci.yml`](../../../ci/yaml/_index.md#image) 파일에 추가하세요:

     ```shell
     image: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/alpine@sha256:c9375e662992791e3f39e919b26f510e5254b42792519c180aad254e6b38f4dc
     ```

   - Docker 이미지를 수동으로 가져오세요:

     ```shell
     docker pull gitlab.example.com/groupname/dependency_proxy/containers/alpine:latest
     ```

   - `Dockerfile`에 URL을 추가하세요:

     ```shell
     FROM gitlab.example.com/groupname/dependency_proxy/containers/alpine:latest
     ```

GitLab은 Docker Hub에서 Docker 이미지를 가져오고 GitLab 서버에 블롭을 캐시합니다. 다음에 동일한 이미지를 가져올 때 GitLab은 Docker Hub에서 이미지에 대한 최신 정보를 가져오지만 GitLab 서버에서 기존 블롭을 제공합니다.

## 저장소 사용량 줄이기 {#reduce-storage-usage}

컨테이너 이미지를 위한 의존성 프록시의 저장소 사용을 줄이는 것에 대한 정보는 [의존성 프록시 저장소 사용 줄이기](reduce_dependency_proxy_storage.md)를 참조하세요.

## Docker Hub 속도 제한 및 의존성 프록시 {#docker-hub-rate-limits-and-the-dependency-proxy}

<i class="fa-youtube-play" aria-hidden="true"></i> [의존성 프록시를 사용하여 Docker Hub 속도 제한을 피하는 방법](https://youtu.be/Nc4nUo7Pq08)을 시청하세요.

Docker Hub는 [풀에 대한 속도 제한](https://docs.docker.com/docker-hub/usage/pulls/)을 적용합니다. GitLab [CI/CD 구성](../../../ci/_index.md)이 Docker Hub에서 이미지를 사용하는 경우, 작업이 실행될 때마다 풀로 계산될 수 있습니다. 이 제한을 극복하려면 대신 의존성 프록시 캐시에서 이미지를 가져올 수 있습니다.

이미지를 가져올 때(`docker pull` 같은 명령을 사용하거나, `.gitlab-ci.yml` 파일에서 `image: foo:latest`), Docker 클라이언트는 요청 모음을 만듭니다:

1. 이미지 매니페스트가 요청됩니다. 매니페스트에는 이미지를 빌드하는 방법에 대한 정보가 포함되어 있습니다.
1. 매니페스트를 사용하여 Docker 클라이언트는 블롭이라고도 하는 계층 모음을 한 번에 하나씩 요청합니다.

Docker Hub 속도 제한은 매니페스트에 대한 GET 요청 수를 기반으로 합니다. 의존성 프록시는 주어진 이미지에 대한 매니페스트와 블롭을 모두 캐시하므로 다시 요청할 때 Docker Hub에 연결할 필요가 없습니다.

### GitLab은 캐시된 태그가 지정된 이미지가 오래되었는지 어떻게 알 수 있나요? {#how-does-gitlab-know-if-a-cached-tagged-image-is-stale}

`alpine:latest` 같은 이미지 태그를 사용하는 경우, 이미지는 시간이 지남에 따라 변경됩니다. 변경될 때마다 매니페스트에는 요청할 블롭에 대한 다른 정보가 포함됩니다. 의존성 프록시는 매니페스트가 변경될 때마다 새 이미지를 가져오지 않으며, 매니페스트가 오래될 때만 확인합니다.

Docker는 이미지 매니페스트에 대한 HEAD 요청을 속도 제한으로 계산하지 않습니다. `alpine:latest`에 대해 HEAD 요청을 수행하고, 헤더에 반환된 다이제스트(체크섬) 값을 보고, 매니페스트가 변경되었는지 확인할 수 있습니다.

의존성 프록시는 모든 요청을 HEAD 요청으로 시작합니다. 매니페스트가 오래된 경우에만 새 이미지가 가져와집니다.

예를 들어, 파이프라인이 5분마다 `node:latest`을 가져오는 경우, 의존성 프록시는 전체 이미지를 캐시하고 `node:latest`이 변경된 경우에만 업데이트합니다. 따라서 6시간 내에 이미지에 대해 360개의 요청을 갖는 대신(Docker Hub 속도 제한을 초과함), 매니페스트가 그 기간 동안 변경되지 않으면 풀이 하나만 됩니다.

### Docker Hub 속도 제한 확인 {#check-your-docker-hub-rate-limit}

Docker Hub에 몇 개의 요청을 했고 몇 개가 남았는지 궁금하면 러너나 CI/CD 스크립트에서 이러한 명령을 실행할 수 있습니다:

```shell
# Note, you must have jq installed to run this command
TOKEN=$(curl "https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull" | jq --raw-output .token) && curl --head --header "Authorization: Bearer $TOKEN" "https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest" 2>&1 | grep --ignore-case RateLimit
...
```

출력은 다음과 같습니다:

```shell
RateLimit-Limit: 100;w=21600
RateLimit-Remaining: 98;w=21600
```

이 예에서는 6시간 동안 100회 풀의 총 제한이 있고 98회 풀이 남아 있습니다.

#### CI/CD 작업에서 속도 제한 확인 {#check-the-rate-limit-in-a-cicd-job}

이 예에서는 `jq` 및 `curl`이(가) 설치된 이미지를 사용하는 GitLab CI/CD 작업을 보여줍니다:

```yaml
hub_docker_quota_check:
    stage: build
    image: alpine:latest
    tags:
        - <optional_runner_tag>
    before_script: apk add curl jq
    script:
      - |
        TOKEN=$(curl "https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull" | jq --raw-output .token) && curl --head --header "Authorization: Bearer $TOKEN" "https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest" 2>&1
```

## 문제 해결 {#troubleshooting}

### 인증 오류: `HTTP Basic: Access Denied` {#authentication-error-http-basic-access-denied}

의존성 프록시에 대해 인증할 때 `HTTP Basic: Access denied` 오류가 발생하면 [2단계 인증 문제 해결 가이드](../../profile/account/two_factor_authentication_troubleshooting.md)를 참조하세요.

### 의존성 프록시 연결 실패 {#dependency-proxy-connection-failure}

서비스 별칭이 설정되지 않으면 `docker:20.10.16` 이미지가 `dind` 서비스를 찾을 수 없으며 다음과 같은 오류가 발생합니다:

```plaintext
error during connect: Get http://docker:2376/v1.39/info: dial tcp: lookup docker on 192.168.0.1:53: no such host
```

이는 Docker 서비스에 대한 서비스 별칭을 설정하여 해결할 수 있습니다:

```yaml
services:
    - name: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/docker:18.09.7-dind
      alias: docker
```

### CI/CD 작업에서 의존성 프록시로 인증할 때의 문제 {#issues-when-authenticating-to-the-dependency-proxy-from-cicd-jobs}

GitLab 러너는 의존성 프록시에 자동으로 인증합니다. 그러나 기본 Docker 엔진은 여전히 [인증 해결 프로세스](https://docs.gitlab.com/runner/configuration/advanced-configuration/#precedence-of-docker-authorization-resolving)의 대상입니다.

인증 메커니즘의 잘못된 구성으로 인해 `HTTP Basic: Access denied` 및 `403: Access forbidden` 오류가 발생할 수 있습니다.

작업 로그를 사용하여 의존성 프록시에 대해 인증하는 데 사용되는 인증 메커니즘을 볼 수 있습니다:

```plaintext
Authenticating with credentials from $DOCKER_AUTH_CONFIG
```

```plaintext
Authenticating with credentials from /root/.docker/config.json
```

```plaintext
Authenticating with credentials from job payload (GitLab Registry)
```

예상된 인증 메커니즘을 사용하고 있는지 확인하세요.

### `Not Found` 또는 `404` 오류(이미지 가져올 때) {#not-found-or-404-error-when-pulling-image}

이와 같은 오류는 작업을 실행하는 사용자가 의존성 프록시 그룹에 대한 게스트 역할의 최소값이 없음을 나타낼 수 있습니다:

- ```plaintext
  ERROR: gitlab.example.com:443/group1/dependency_proxy/containers/alpine:latest: not found

  failed to solve with frontend dockerfile.v0: failed to create LLB definition: gitlab.example.com:443/group1/dependency_proxy/containers/alpine:latest: not found
  ```

- ```plaintext
  ERROR: Job failed: failed to pull image "gitlab.example.com:443/group1/dependency_proxy/containers/alpine:latest" with specified policies [always]:
  Error response from daemon: error parsing HTTP 404 response body: unexpected end of JSON input: "" (manager.go:237:1s)
  ```

`Access denied`과 유사한 경우의 오류 메시지 개선 작업에 대한 자세한 내용은 [이슈 354826](https://gitlab.com/gitlab-org/gitlab/-/issues/354826)을 참조하세요.

### `MissingFile` 오류(백업 복원 후) {#missingfile-errors-after-restoring-a-backup}

`MissingFile` 또는 `Cannot read file` 오류가 발생하면 [백업 아카이브](../../../administration/backup_restore/backup_gitlab.md)에 `gitlab-rails/shared/dependency_proxy/`의 콘텐츠가 포함되지 않기 때문일 수 있습니다.

이 [알려진 문제](https://gitlab.com/gitlab-org/gitlab/-/issues/354574)를 해결하려면 `rsync`, `scp` 또는 유사한 도구를 사용하여 영향을 받은 파일 또는 전체 `gitlab-rails/shared/dependency_proxy/` 폴더 구조를 백업 소스인 GitLab 인스턴스에서 복사할 수 있습니다.

데이터가 필요하지 않으면 다음을 사용하여 데이터베이스 항목을 삭제할 수 있습니다:

```shell
gitlab-psql -c "DELETE FROM dependency_proxy_blobs; DELETE FROM dependency_proxy_blob_states; DELETE FROM dependency_proxy_manifest_states; DELETE FROM dependency_proxy_manifests;"
```
