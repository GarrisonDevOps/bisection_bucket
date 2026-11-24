---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 컨테이너 레지스트리 데이터 전송 감소
description: GitLab 컨테이너 레지스트리의 데이터 전송량을 줄이는 팁입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

컨테이너 레지스트리에서 이미지 또는 태그를 다운로드하는 빈도에 따라 데이터 전송량이 상당할 수 있습니다. 이 페이지에서는 컨테이너 레지스트리를 통해 전송하는 데이터양을 줄이기 위한 몇 가지 권장 사항과 팁을 제공합니다.

## 데이터 전송 사용 확인 {#check-data-transfer-use}

GitLab UI 내에서 전송 사용량을 확인할 수 없습니다. [GitLab-#350905](https://gitlab.com/gitlab-org/gitlab/-/issues/350905)는 이 정보를 표시하는 작업을 추적하는 에픽입니다.

## 이미지 크기 결정 {#determine-image-size}

다음 도구 및 기법을 사용하여 이미지 크기를 결정합니다:

- [Skopeo](https://github.com/podman-container-tools/skopeo): Skopeo `inspect` 명령을 사용하여 API 호출을 통해 레이어 개수와 크기를 확인합니다. `docker pull IMAGE`을 실행하기 전에 이 데이터를 검사할 수 있습니다.

- Docker in CI: Docker로 이미지를 푸시하기 전에 GitLab CI를 사용할 때 이미지 크기를 확인하고 기록합니다. 예를 들어:

  ```shell
  docker inspect "$CI_REGISTRY_IMAGE:$IMAGE_TAG" \
        | awk '/"Size": ([0-9]+)[,]?/{ printf "Final Image Size: %d\n", $2 }'
  ```

- [Dive](https://github.com/wagoodman/dive)는 Docker 이미지를 탐색하고, 레이어 내용을 검사하며, 크기를 줄이는 방법을 찾기 위한 도구입니다.

## 이미지 크기 줄이기 {#reduce-image-size}

### 더 작은 기본 이미지 사용 {#use-a-smaller-base-image}

[Alpine Linux](https://alpinelinux.org/)와 같은 더 작은 기본 이미지를 사용하는 것을 고려하세요. Alpine 이미지는 약 5MB이며, [Debian](https://hub.docker.com/_/debian)과 같은 인기 있는 기본 이미지보다 몇 배 작습니다. Go 애플리케이션과 같은 자체 포함된 정적 바이너리로 애플리케이션을 배포하는 경우, Docker [scratch](https://hub.docker.com/_/scratch/) 기본 이미지를 사용하는 것도 고려할 수 있습니다.

특정 기본 이미지 OS를 사용해야 하는 경우, `-slim` 또는 `-minimal` 변형을 찾아보세요. 이렇게 하면 이미지 크기를 줄이는 데 도움이 됩니다.

기본 이미지 위에 설치하는 운영 체제 패키지에 주의하세요. 이는 수백 MB에 달할 수 있습니다. 설치된 패키지의 개수를 최소한으로 유지하세요.

[다단계 빌드](#use-multi-stage-builds)는 임시 빌드 종속성을 정리하는 강력한 도구입니다.

다음과 같은 도구를 사용하는 것도 고려할 수 있습니다:

- [DockerSlim](https://github.com/docker-slim/docker-slim)은 컨테이너 이미지의 크기를 줄이기 위한 일련의 명령을 제공합니다.
- [Distroless](https://github.com/GoogleContainerTools/distroless) 이미지는 애플리케이션 및 해당 런타임 종속성만 포함합니다. 패키지 관리자, 셸 또는 표준 Linux 배포판에서 찾을 수 있는 기타 프로그램을 포함하지 않습니다.

### 레이어 최소화 {#minimize-layers}

Dockerfile의 모든 명령어는 새 레이어를 만들며, 이는 그 명령어 동안 적용된 파일 시스템 변경 사항을 기록합니다. 일반적으로 더 많거나 더 큰 레이어는 더 큰 이미지를 만듭니다. Dockerfile에 패키지를 설치하기 위해 레이어의 개수를 최소화하세요. 그렇지 않으면 빌드 프로세스의 각 단계가 이미지 크기를 증가시킬 수 있습니다.

레이어의 개수와 크기를 줄이기 위한 여러 전략이 있습니다. 예를 들어, 설치하려는 운영 체제 패키지마다 `RUN` 명령을 사용하는 대신(패키지마다 레이어가 생성됨), 빌드 프로세스의 단계 수를 줄이고 이미지 크기를 줄이기 위해 모든 패키지를 단일 `RUN` 명령에 설치할 수 있습니다.

또 다른 유용한 전략은 모든 임시 빌드 종속성을 제거하고 패키지를 설치하기 전후에 운영 체제 패키지 관리자 캐시를 비활성화하거나 비우는 것입니다.

이미지를 빌드할 때 관련 파일만 복사하도록 하세요. Docker의 경우 [`.dockerignore`](https://docs.docker.com/reference/dockerfile/#dockerignore-file)를 사용하면 빌드 프로세스가 관련 없는 파일을 무시하도록 할 수 있습니다.

[DockerSlim](https://github.com/docker-slim/docker-slim)과 같은 다른 타사 도구를 사용하여 이미지를 축소할 수 있습니다. 이러한 도구가 부적절하게 사용되면 애플리케이션이 특정 조건에서 작동하는 데 필요한 종속성을 제거할 수 있으므로 주의하세요. 따라서 이미지를 축소한 후가 아니라 빌드 프로세스 중에 더 작은 이미지를 만들기 위해 노력하는 것이 좋습니다.

### 다단계 빌드 사용 {#use-multi-stage-builds}

[다단계 빌드](https://docs.docker.com/build/building/multi-stage/)를 사용하면 Dockerfile에서 여러 `FROM` 문을 사용합니다. 각 `FROM` 명령어는 다른 기본을 사용할 수 있으며, 각 명령어는 새로운 빌드 스테이지를 시작합니다. 한 스테이지에서 다른 스테이지로 아티팩트를 선택적으로 복사할 수 있으며, 최종 이미지에 원하지 않는 모든 것을 남겨둘 수 있습니다. 이는 빌드 종속성을 설치해야 하지만 최종 이미지에 있을 필요가 없는 경우에 특히 유용합니다.

## 이미지 풀 정책 사용 {#use-an-image-pull-policy}

`docker` 또는 `docker+machine` 실행기를 사용할 때, 러너 `config.toml` 에서 [`pull_policy`](https://docs.gitlab.com/runner/executors/docker/#using-the-if-not-present-pull-policy) 매개변수를 설정할 수 있으며, 이는 Docker 이미지를 풀할 때 러너가 작동하는 방식을 정의합니다. 크고 거의 업데이트되지 않는 이미지를 사용할 때 데이터 전송을 피하려면 원격 레지스트리에서 이미지를 풀할 때 `if-not-present` 풀 정책을 사용하는 것을 고려하세요.

## Docker 레이어 캐싱 사용 {#use-docker-layer-caching}

Docker 레이어 캐싱은 빌드 속도를 높이고 전송되는 데이터의 양을 줄일 수 있습니다. 자세한 내용은 [Docker-in-Docker 빌드에서 Docker 레이어 캐싱](../../../ci/docker/docker_layer_caching.md)을 참조하세요.

## 자동화 빈도 확인 {#check-automation-frequency}

특정 간격으로 정기적인 작업을 수행하기 위해 컨테이너 이미지에 번들로 제공되는 자동화 스크립트를 자주 만듭니다. 자동화가 GitLab 레지스트리에서 GitLab.com 외부의 서비스로 컨테이너 이미지를 풀하는 경우 해당 간격의 빈도를 줄일 수 있습니다.

## 관련 이슈 {#related-issues}

- 기본 Docker 이미지가 업데이트될 때 이미지를 다시 빌드할 수 있습니다. 그러나 [파이프라인 구독 한도가 너무 낮아서](https://gitlab.com/gitlab-org/gitlab/-/issues/225278) 이 기능을 활용할 수 없습니다. 해결책으로 매일 또는 하루에 여러 번 다시 빌드할 수 있습니다. [GitLab-#225278](https://gitlab.com/gitlab-org/gitlab/-/issues/225278)은 이 워크플로를 돕기 위해 한도를 높일 것을 제안합니다.
