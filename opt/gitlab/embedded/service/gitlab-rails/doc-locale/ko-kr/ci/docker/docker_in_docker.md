---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Docker-in-Docker 사용
description: Docker 또는 Kubernetes 실행기를 사용하여 GitLab CI/CD 작업에 Docker-in-Docker를 구성합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Docker-in-Docker(`dind`)는 등록된 러너가 [Docker 실행기](https://docs.gitlab.com/runner/executors/docker/) 또는 [Kubernetes 실행기](https://docs.gitlab.com/runner/executors/kubernetes/)를 사용하는 것을 의미합니다. 실행기는 Docker에서 제공하는 [Docker의 컨테이너 이미지](https://hub.docker.com/_/docker/)를 사용하여 CI/CD 작업을 실행합니다.

Docker 이미지에는 모든 `docker` 도구가 포함되어 있으며 특권 모드에서 이미지 컨텍스트 내에서 작업 스크립트를 실행할 수 있습니다.

항상 `docker:24.0.5`과 같이 이미지의 특정 버전을 고정합니다. `docker:latest`와 같은 태그를 사용하면 어느 버전이 사용되는지 제어할 수 없습니다. 이 작업으로 인해 새 버전이 출시될 때 호환성 문제가 발생할 수 있습니다.

## Docker 실행기와 함께 사용 {#use-with-docker-executor}

Docker 실행기를 사용하여 Docker 컨테이너에서 작업을 실행할 수 있습니다.

### Docker 실행기에서 TLS가 활성화된 Docker-in-Docker(권장) {#docker-in-docker-with-tls-enabled-in-the-docker-executor-recommended}

Docker 데몬은 TLS를 통한 연결을 지원합니다. 가능할 때 TLS를 사용합니다. TLS는 Docker 19.03.12 이상의 기본값이며 [GitLab.com 인스턴스 러너](../runners/_index.md)에서 지원합니다.

> [!warning]
> 이 작업을 수행하면 `--docker-privileged`이 활성화되어 컨테이너의 보안 메커니즘이 비활성화되고 호스트가 권한 상승 공격에 노출됩니다. 이 작업으로 인해 컨테이너 탈출이 발생할 수 있습니다. 자세한 내용은 [런타임 권한 및 Linux 기능](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)을 참조하세요.

TLS가 활성화된 Docker-in-Docker를 사용하려면:

1. [GitLab Runner](https://docs.gitlab.com/runner/install/)를 설치합니다.
1. 명령줄에서 GitLab Runner를 등록합니다. `docker` 및 `privileged` 모드를 사용합니다:

   ```shell
   sudo gitlab-runner register -n \
     --url "https://gitlab.com/" \
     --registration-token REGISTRATION_TOKEN \
     --executor docker \
     --description "My Docker Runner" \
     --tag-list "tls-docker-runner" \
     --docker-image "docker:24.0.5-cli" \
     --docker-privileged \
     --docker-volumes "/certs/client"
   ```

   - 이 명령은 새 러너를 등록하여 `docker:24.0.5-cli` 이미지를 사용합니다(작업 수준에서 지정되지 않은 경우). 빌드 및 서비스 컨테이너를 시작하려면 `privileged` 모드를 사용합니다. Docker-in-Docker를 사용하려면 항상 Docker 컨테이너에서 `privileged = true`을 사용해야 합니다.
   - 이 명령은 `/certs/client`을 서비스 및 빌드 컨테이너에 마운트하며, 이는 Docker 클라이언트가 해당 디렉터리의 인증서를 사용하는 데 필요합니다. 자세한 내용은 [Docker 이미지 설명서](https://hub.docker.com/_/docker/)를 참조하세요.

   이전 명령은 다음 예제와 유사한 `config.toml` 항목을 생성합니다:

   ```toml
   [[runners]]
     url = "https://gitlab.com/"
     token = TOKEN
     executor = "docker"
     [runners.docker]
       tls_verify = false
       image = "docker:24.0.5-cli"
       privileged = true
       disable_cache = false
       volumes = ["/certs/client", "/cache"]
     [runners.cache]
       [runners.cache.s3]
       [runners.cache.gcs]
   ```

1. 이제 작업 스크립트에서 `docker`을 사용할 수 있습니다. `docker:24.0.5-dind` 서비스를 포함합니다:

   ```yaml
   default:
     image: docker:24.0.5-cli
     services:
       - docker:24.0.5-dind
     before_script:
       - docker info

   variables:
     # When you use the dind service, you must instruct Docker to talk with
     # the daemon started inside of the service. The daemon is available
     # with a network connection instead of the default
     # /var/run/docker.sock socket. Docker 19.03 does this automatically
     # by setting the DOCKER_HOST in
     # https://github.com/docker-library/docker/blob/d45051476babc297257df490d22cbd806f1b11e4/19.03/docker-entrypoint.sh#L23-L29
     #
     # The 'docker' hostname is the alias of the service container as described at
     # https://docs.gitlab.com/ci/services/#accessing-the-services.
     #
     # Specify to Docker where to create the certificates. Docker
     # creates them automatically on boot, and creates
     # `/certs/client` to share between the service and job
     # container, thanks to volume mount from config.toml
     DOCKER_TLS_CERTDIR: "/certs"

   build:
     stage: build
     tags:
       - tls-docker-runner
     script:
       - docker build -t my-docker-image .
       - docker run my-docker-image /script/to/run/tests
   ```

### Docker 실행기에서 TLS가 비활성화된 Docker-in-Docker {#docker-in-docker-with-tls-disabled-in-the-docker-executor}

때로는 TLS를 비활성화하는 정당한 이유가 있습니다. 예를 들어, 사용 중인 GitLab Runner 구성을 제어할 수 없습니다.

1. 명령줄에서 GitLab Runner를 등록합니다. `docker` 및 `privileged` 모드를 사용합니다:

   ```shell
   sudo gitlab-runner register -n \
     --url "https://gitlab.com/" \
     --registration-token REGISTRATION_TOKEN \
     --executor docker \
     --description "My Docker Runner" \
     --tag-list "no-tls-docker-runner" \
     --docker-image "docker:24.0.5-cli" \
     --docker-privileged
   ```

   이전 명령은 다음 예제와 유사한 `config.toml` 항목을 생성합니다:

   ```toml
   [[runners]]
     url = "https://gitlab.com/"
     token = TOKEN
     executor = "docker"
     [runners.docker]
       tls_verify = false
       image = "docker:24.0.5-cli"
       privileged = true
       disable_cache = false
       volumes = ["/cache"]
     [runners.cache]
       [runners.cache.s3]
       [runners.cache.gcs]
   ```

1. 작업 스크립트에 `docker:24.0.5-dind` 서비스를 포함합니다:

   ```yaml
   default:
     image: docker:24.0.5-cli
     services:
       - docker:24.0.5-dind
     before_script:
       - docker info

   variables:
     # When using dind service, you must instruct docker to talk with the
     # daemon started inside of the service. The daemon is available with
     # a network connection instead of the default /var/run/docker.sock socket.
     #
     # The 'docker' hostname is the alias of the service container as described at
     # https://docs.gitlab.com/ci/services/#accessing-the-services
     #
     DOCKER_HOST: tcp://docker:2375
     #
     # This instructs Docker not to start over TLS.
     DOCKER_TLS_CERTDIR: ""

   build:
     stage: build
     tags:
       - no-tls-docker-runner
     script:
       - docker build -t my-docker-image .
       - docker run my-docker-image /script/to/run/tests
   ```

### Docker-in-Docker와 빌드 컨테이너 간의 공유 볼륨에서 Unix 소켓 사용 {#use-a-unix-socket-on-a-shared-volume-between-docker-in-docker-and-build-container}

`volumes = ["/certs/client", "/cache"]`에 정의된 디렉터리는 [Docker 실행기에서 TLS가 활성화된 Docker-in-Docker](#docker-in-docker-with-tls-enabled-in-the-docker-executor-recommended) 접근 방식에서 [빌드 간에 지속됩니다](https://docs.gitlab.com/runner/executors/docker/#persistent-storage). Docker 실행기 러너를 사용하는 여러 CI/CD 작업에 Docker-in-Docker 서비스가 활성화되어 있으면 각 작업이 디렉터리 경로에 쓰입니다. 이 접근 방식으로 인해 충돌이 발생할 수 있습니다.

이 충돌을 해결하려면 Docker-in-Docker 서비스와 빌드 컨테이너 간의 공유 볼륨에서 Unix 소켓을 사용합니다. 이 접근 방식은 성능을 개선하고 서비스와 클라이언트 간의 보안 연결을 설정합니다.

다음은 빌드 및 서비스 컨테이너 간에 공유되는 임시 볼륨이 있는 `config.toml` 샘플입니다:

```toml
[[runners]]
  url = "https://gitlab.com/"
  token = TOKEN
  executor = "docker"
  [runners.docker]
    image = "docker:24.0.5-cli"
    privileged = true
    volumes = ["/runner/services/docker"] # Temporary volume shared between build and service containers.
```

Docker-in-Docker 서비스는 `docker.sock`을 생성합니다. Docker 클라이언트는 Docker Unix 소켓 볼륨을 통해 `docker.sock`에 연결합니다.

```yaml
job:
  variables:
    # This variable is shared by both the DinD service and Docker client.
    # For the service, it will instruct DinD to create `docker.sock` here.
    # For the client, it tells the Docker client which Docker Unix socket to connect to.
    DOCKER_HOST: "unix:///runner/services/docker/docker.sock"
  services:
    - docker:24.0.5-dind
  image: docker:24.0.5-cli
  script:
    - docker version
```

### Docker 실행기에서 프록시가 활성화된 Docker-in-Docker {#docker-in-docker-with-proxy-enabled-in-the-docker-executor}

`docker push` 명령을 사용하기 위해 프록시 설정을 구성해야 할 수 있습니다.

자세한 내용은 [`dind` 서비스를 사용할 때의 프록시 설정](https://docs.gitlab.com/runner/configuration/proxy/#proxy-settings-when-using-dind-service)을 참조하세요.

## Kubernetes 실행기와 함께 사용 {#use-with-kubernetes-executor}

[Kubernetes 실행기](https://docs.gitlab.com/runner/executors/kubernetes/)를 사용하여 Docker 컨테이너에서 작업을 실행할 수 있습니다.

### Kubernetes에서 TLS가 활성화된 Docker-in-Docker(권장) {#docker-in-docker-with-tls-enabled-in-kubernetes-recommended}

Kubernetes에서 TLS가 활성화된 Docker-in-Docker를 사용하려면:

1. [Helm 차트](https://docs.gitlab.com/runner/install/kubernetes/)를 사용하여 [`values.yml` 파일](https://gitlab.com/gitlab-org/charts/gitlab-runner/-/blob/00c1a2098f303dffb910714752e9a981e119f5b5/values.yaml#L133-137)을 업데이트하여 볼륨 마운트를 지정합니다.

   ```yaml
   runners:
     tags: "tls-dind-kubernetes-runner"
     config: |
       [[runners]]
         [runners.kubernetes]
           image = "ubuntu:20.04"
           privileged = true
         [[runners.kubernetes.volumes.empty_dir]]
           name = "docker-certs"
           mount_path = "/certs/client"
           medium = "Memory"
   ```

1. 작업에 `docker:24.0.5-dind` 서비스를 포함합니다:

   ```yaml
   default:
     image: docker:24.0.5-cli
     services:
       - name: docker:24.0.5-dind
         variables:
           HEALTHCHECK_TCP_PORT: "2376"
     before_script:
       - docker info

   variables:
     # When using dind service, you must instruct Docker to talk with
     # the daemon started inside of the service. The daemon is available
     # with a network connection instead of the default
     # /var/run/docker.sock socket.
     DOCKER_HOST: tcp://docker:2376
     #
     # The 'docker' hostname is the alias of the service container as described at
     # https://docs.gitlab.com/ci/services/#accessing-the-services.
     #
     # Specify to Docker where to create the certificates. Docker
     # creates them automatically on boot, and creates
     # `/certs/client` to share between the service and job
     # container, thanks to volume mount from config.toml
     DOCKER_TLS_CERTDIR: "/certs"
     # These are usually specified by the entrypoint, however the
     # Kubernetes executor doesn't run entrypoints
     # https://gitlab.com/gitlab-org/gitlab-runner/-/issues/4125
     DOCKER_TLS_VERIFY: 1
     DOCKER_CERT_PATH: "$DOCKER_TLS_CERTDIR/client"

   build:
     stage: build
     tags:
       - tls-dind-kubernetes-runner
     script:
       - docker build -t my-docker-image .
       - docker run my-docker-image /script/to/run/tests
   ```

### Kubernetes에서 TLS가 비활성화된 Docker-in-Docker {#docker-in-docker-with-tls-disabled-in-kubernetes}

Kubernetes에서 TLS가 비활성화된 Docker-in-Docker를 사용하려면 이전 예제를 다음과 같이 조정해야 합니다:

- `values.yml` 파일에서 `[[runners.kubernetes.volumes.empty_dir]]` 섹션을 제거합니다.
- `DOCKER_HOST: tcp://docker:2375`를 사용하여 포트를 `2376`에서 `2375`로 변경합니다.
- `DOCKER_TLS_CERTDIR: ""`을 사용하여 TLS가 비활성화된 상태에서 Docker를 시작하도록 지시합니다.

예를 들어:

1. [Helm 차트](https://docs.gitlab.com/runner/install/kubernetes/)를 사용하여 [`values.yml` 파일](https://gitlab.com/gitlab-org/charts/gitlab-runner/-/blob/00c1a2098f303dffb910714752e9a981e119f5b5/values.yaml#L133-137)을 업데이트합니다:

   ```yaml
   runners:
     tags: "no-tls-dind-kubernetes-runner"
     config: |
       [[runners]]
         [runners.kubernetes]
           image = "ubuntu:20.04"
           privileged = true
   ```

1. 이제 작업 스크립트에서 `docker`을 사용할 수 있습니다. `docker:24.0.5-dind` 서비스를 포함합니다:

   ```yaml
   default:
     image: docker:24.0.5-cli
     services:
       - name: docker:24.0.5-dind
         variables:
           HEALTHCHECK_TCP_PORT: "2375"
     before_script:
       - docker info

   variables:
     # When using dind service, you must instruct Docker to talk with
     # the daemon started inside of the service. The daemon is available
     # with a network connection instead of the default
     # /var/run/docker.sock socket.
     DOCKER_HOST: tcp://docker:2375
     #
     # The 'docker' hostname is the alias of the service container as described at
     # https://docs.gitlab.com/ci/services/#accessing-the-services.
     #
     # This instructs Docker not to start over TLS.
     DOCKER_TLS_CERTDIR: ""
   build:
     stage: build
     tags:
       - no-tls-dind-kubernetes-runner
     script:
       - docker build -t my-docker-image .
       - docker run my-docker-image /script/to/run/tests
   ```

## Docker-in-Docker의 알려진 문제 {#known-issues-with-docker-in-docker}

Docker-in-Docker는 권장되는 구성이지만 다음 문제를 알아야 합니다:

- `docker-compose` 명령: 이 명령은 기본적으로 이 구성에서 사용할 수 없습니다. 작업 스크립트에서 `docker-compose`을 사용하려면 Docker Compose [설치 지침](https://docs.docker.com/compose/install/)을 따릅니다.
- 캐시: 각 작업은 새 환경에서 실행됩니다. 모든 빌드가 자체 Docker 엔진 인스턴스를 가지므로 동시 작업으로 인해 충돌이 발생하지 않습니다. 하지만 레이어가 캐시되지 않으므로 작업이 더 느릴 수 있습니다. [Docker 레이어 캐싱](using_docker_build.md#docker-layer-caching)을 참조하세요.
- 스토리지 드라이버: 기본적으로 Docker의 이전 버전은 각 작업에 대해 파일 시스템을 복사하는 `vfs` 스토리지 드라이버를 사용합니다. Docker 17.09 이상은 권장 스토리지 드라이버인 `--storage-driver overlay2`을 사용합니다. 자세한 내용은 [OverlayFS 드라이버 사용](using_docker_build.md#use-the-overlayfs-driver)을 참조하세요.
- 루트 파일 시스템: `docker:24.0.5-dind` 컨테이너와 러너 컨테이너가 루트 파일 시스템을 공유하지 않기 때문에 작업의 작업 디렉터리를 자식 컨테이너의 마운트 지점으로 사용할 수 있습니다. 예를 들어, 자식 컨테이너와 공유하려는 파일이 있는 경우 `/builds/$CI_PROJECT_PATH` 아래에 하위 디렉터리를 만들고 이를 마운트 지점으로 사용할 수 있습니다. 자세한 설명은 [이슈 #41227](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/41227)을 참조하세요.

  ```yaml
  variables:
    MOUNT_POINT: /builds/$CI_PROJECT_PATH/mnt
  script:
    - mkdir -p "$MOUNT_POINT"
    - docker run -v "$MOUNT_POINT:/mnt" my-docker-image
  ```
