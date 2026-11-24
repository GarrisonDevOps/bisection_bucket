---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 컨테이너 레지스트리에 컨테이너 이미지 빌드 및 푸시
description: Docker 명령 또는 CI/CD 파이프라인을 사용하여 컨테이너 이미지를 빌드하고 GitLab 레지스트리에 푸시합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

컨테이너 이미지를 빌드 및 푸시하기 전에 컨테이너 레지스트리로 [인증](authenticate_with_container_registry.md)해야 합니다.

## Docker 명령 사용 {#use-docker-commands}

Docker 명령을 사용하여 컨테이너 이미지를 빌드하고 컨테이너 레지스트리에 푸시할 수 있습니다:

1. 컨테이너 레지스트리로 [인증](authenticate_with_container_registry.md)합니다.
1. Docker 명령을 실행하여 빌드하거나 푸시합니다. 예를 들어:

   - 빌드하려면:

     ```shell
     docker build -t registry.example.com/group/project/image .
     ```

   - 푸시하려면:

     ```shell
     docker push registry.example.com/group/project/image
     ```

## GitLab CI/CD 사용 {#use-gitlab-cicd}

[GitLab CI/CD](../../../ci/_index.md)를 사용하여 컨테이너 레지스트리의 컨테이너 이미지를 빌드, 푸시, 테스트 및 배포합니다.

### `.gitlab-ci.yml` 파일 구성 {#configure-your-gitlab-ciyml-file}

컨테이너 레지스트리에 컨테이너 이미지를 빌드하고 푸시하도록 `.gitlab-ci.yml` 파일을 구성할 수 있습니다.

- 여러 작업에 인증이 필요한 경우 인증 명령을 `before_script`에 넣습니다.
- 빌드하기 전에 `docker build --pull`을(를) 사용하여 기본 이미지에 대한 변경 사항을 가져옵니다. 약간 더 오래 걸리지만 이미지가 최신 상태인지 확인합니다.
- 각 `docker run` 전에 `docker pull`을(를) 명시적으로 실행하여 방금 빌드한 이미지를 가져옵니다. 여러 러너를 사용하여 이미지를 로컬로 캐시하는 경우 이 단계가 특히 중요합니다.

  이미지 태그에서 Git SHA를 사용하면 각 작업이 고유하며 오래된 이미지를 가질 수 없습니다. 그러나 종속성이 변경된 후 주어진 커밋을 다시 빌드하는 경우 오래된 이미지를 가질 수 있습니다.
- 여러 작업이 동시에 발생할 수 있으므로 `latest` 태그에 직접 빌드하지 마세요.

### Docker-in-Docker 컨테이너 이미지 사용 {#use-a-docker-in-docker-container-image}

컨테이너 레지스트리 또는 종속성 프록시와 함께 자체 Docker-in-Docker(DinD) 컨테이너 이미지를 사용할 수 있습니다.

CI/CD 파이프라인에서 DinD를 사용하여 컨테이너화된 애플리케이션을 빌드, 테스트 및 배포합니다.

사전 요구 사항:

- [Docker-in-Docker](../../../ci/docker/using_docker_build.md#use-docker-in-docker)를 설정합니다.

{{< tabs >}}

{{< tab title="컨테이너 레지스트리에서" >}}

GitLab 컨테이너 레지스트리에 저장된 이미지를 사용하려는 경우 이 방법을 사용합니다.

`.gitlab-ci.yml` 파일에서:

- `image` 및 `services`을(를) 업데이트하여 레지스트리를 가리킵니다.
- 서비스 [별칭](../../../ci/services/_index.md#available-settings-for-services)을(를) 추가합니다.

`.gitlab-ci.yml`은(는) 다음과 같아야 합니다:

```yaml
build:
  image: $CI_REGISTRY/group/project/docker:24.0.5-cli
  services:
    - name: $CI_REGISTRY/group/project/docker:24.0.5-dind
      alias: docker
  stage: build
  script:
    - docker build -t my-docker-image .
    - docker run my-docker-image /script/to/run/tests
```

{{< /tab >}}

{{< tab title="종속성 프록시 사용" >}}

이 방법을 사용하여 Docker Hub와 같은 외부 레지스트리의 이미지를 캐시하여 빌드 속도를 높이고 속도 제한을 방지합니다.

`.gitlab-ci.yml` 파일에서:

- `image` 및 `services`을(를) 업데이트하여 종속성 프록시 접두사를 사용합니다.
- 서비스 [별칭](../../../ci/services/_index.md#available-settings-for-services)을(를) 추가합니다.

`.gitlab-ci.yml`은(는) 다음과 같아야 합니다:

```yaml
build:
  image: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/docker:24.0.5-cli
  services:
    - name: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/docker:24.0.5-dind
      alias: docker
  stage: build
  script:
    - docker build -t my-docker-image .
    - docker run my-docker-image /script/to/run/tests
```

{{< /tab >}}

{{< /tabs >}}

서비스 별칭을 설정하지 않으면 컨테이너 이미지가 `dind` 서비스를 찾을 수 없으며 다음과 같은 오류가 표시됩니다:

```plaintext
error during connect: Get http://docker:2376/v1.39/info: dial tcp: lookup docker on 192.168.0.1:53: no such host
```

## GitLab CI/CD를 사용한 컨테이너 레지스트리 예제 {#container-registry-examples-with-gitlab-cicd}

러너에서 DinD를 사용하는 경우 `.gitlab-ci.yml` 파일이 다음과 같아야 합니다:

```yaml
build:
  image: docker:24.0.5-cli
  stage: build
  services:
    - docker:24.0.5-dind
  script:
    - echo "$CI_REGISTRY_PASSWORD" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
    - docker build -t $CI_REGISTRY/group/project/image:latest .
    - docker push $CI_REGISTRY/group/project/image:latest
```

`.gitlab-ci.yml` 파일에서 [CI/CD 변수](../../../ci/variables/_index.md)를 사용할 수 있습니다. 예를 들어:

```yaml
build:
  image: docker:24.0.5-cli
  stage: build
  services:
    - docker:24.0.5-dind
  variables:
    IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
  script:
    - echo "$CI_REGISTRY_PASSWORD" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
    - docker build -t $IMAGE_TAG .
    - docker push $IMAGE_TAG
```

앞의 예제에서:

- `$CI_REGISTRY_IMAGE`은(는) 이 프로젝트와 연결된 레지스트리의 주소로 확인됩니다.
- `$IMAGE_TAG`은(는) `$CI_COMMIT_REF_SLUG`(이미지 태그)와 레지스트리 주소를 결합하는 사용자 지정 변수입니다. [`$CI_COMMIT_REF_NAME` 사전 정의된 변수](../../../ci/variables/predefined_variables.md#predefined-variables)는 브랜치 또는 태그 이름으로 확인되며 슬래시를 포함할 수 있습니다. 이미지 태그에는 슬래시를 포함할 수 없습니다. 대신 `$CI_COMMIT_REF_SLUG`을 사용합니다.

다음 예제는 CI/CD 작업을 4개의 파이프라인 스테이지로 분할합니다. 여기에는 병렬로 실행되는 2개의 테스트가 포함됩니다.

`build`은(는) 컨테이너 레지스트리에 저장되며 필요할 때 컨테이너 이미지를 다운로드하는 후속 스테이지에서 사용됩니다. `main` 브랜치로 변경 사항을 푸시하면 파이프라인이 이미지를 `latest`(으)로 태그하고 애플리케이션별 배포 스크립트를 사용하여 배포합니다:

```yaml
default:
  image: docker:24.0.5-cli
  services:
    - docker:24.0.5-dind
  before_script:
    - echo "$CI_REGISTRY_PASSWORD" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin

stages:
  - build
  - test
  - release
  - deploy

variables:
  # Use TLS https://docs.gitlab.com/ci/docker/using_docker_build/#use-docker-in-docker
  DOCKER_HOST: tcp://docker:2376
  DOCKER_TLS_CERTDIR: "/certs"
  CONTAINER_TEST_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
  CONTAINER_RELEASE_IMAGE: $CI_REGISTRY_IMAGE:latest

build:
  stage: build
  script:
    - docker build --pull -t $CONTAINER_TEST_IMAGE .
    - docker push $CONTAINER_TEST_IMAGE

test1:
  stage: test
  script:
    - docker pull $CONTAINER_TEST_IMAGE
    - docker run $CONTAINER_TEST_IMAGE /script/to/run/tests

test2:
  stage: test
  script:
    - docker pull $CONTAINER_TEST_IMAGE
    - docker run $CONTAINER_TEST_IMAGE /script/to/run/another/test

release-image:
  stage: release
  script:
    - docker pull $CONTAINER_TEST_IMAGE
    - docker tag $CONTAINER_TEST_IMAGE $CONTAINER_RELEASE_IMAGE
    - docker push $CONTAINER_RELEASE_IMAGE
  rules:
    - if: $CI_COMMIT_BRANCH == "main"

deploy:
  stage: deploy
  script:
    - ./deploy.sh
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment: production
```

> [!note]
> 이전 예제에서는 `docker pull`을(를) 명시적으로 호출합니다. `image:`을(를) 사용하여 컨테이너 이미지를 암시적으로 가져오려면 [Docker](https://docs.gitlab.com/runner/executors/docker/) 또는 [Kubernetes](https://docs.gitlab.com/runner/executors/kubernetes/) 실행기를 사용하는 경우 [`pull_policy`](https://docs.gitlab.com/runner/executors/docker/#set-the-always-pull-policy)이(가) `always`으로 설정되어 있는지 확인합니다.
