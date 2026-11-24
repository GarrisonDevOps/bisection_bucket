---
stage: Application Security Testing
group: Composition Analysis
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
title: '자습서: Docker 컨테이너의 취약점 검사'
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[컨테이너 스캔](../../user/application_security/container_scanning/_index.md)을 사용하여 [컨테이너 레지스트리](../../user/packages/container_registry/_index.md)에 저장된 컨테이너 이미지의 취약점을 확인할 수 있습니다.

컨테이너 스캔 구성이 프로젝트의 파이프라인 구성에 추가됩니다. 이 튜토리얼에서 수행하는 작업은 다음과 같습니다:

1. [새 프로젝트](#create-a-new-project)를 생성합니다.
1. [`Dockerfile` 파일을 프로젝트에 추가](#add-a-dockerfile-to-new-project)합니다. 이 `Dockerfile`은 Docker 이미지를 만드는 데 필요한 최소 구성을 포함합니다.
1. 새 프로젝트에 대한 [파이프라인 구성](#create-pipeline-configuration)을 만들어 `Dockerfile`에서 Docker 이미지를 만들고, Docker 이미지를 컨테이너 레지스트리에 빌드 및 푸시한 후, Docker 이미지의 취약점을 검사합니다.
1. [보고된 취약점 확인](#check-for-reported-vulnerabilities)합니다.
1. [Docker 이미지를 업데이트](#update-the-docker-image)하고 업데이트된 이미지를 검사합니다.

## 새 프로젝트 만들기 {#create-a-new-project}

새 프로젝트를 만들려면

1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. **프로젝트 이름**에 `Tutorial container scanning project`을 입력합니다.
1. **프로젝트 URL**에서 프로젝트의 네임스페이스를 선택합니다.
1. **프로젝트 생성**을 선택합니다.

## 새 프로젝트에 `Dockerfile` 추가 {#add-a-dockerfile-to-new-project}

컨테이너 스캔이 작동하도록 할 대상을 제공하려면 최소 구성으로 `Dockerfile`을 만듭니다:

1. `Tutorial container scanning project` 프로젝트에서 {{< icon name="plus" >}} > **새 파일**을 선택합니다.
1. 파일 이름 `Dockerfile`을 입력하고 다음 내용을 파일에 입력합니다:

   ```Dockerfile
   FROM hello-world:latest
   ```

이 `Dockerfile`에서 만든 Docker 이미지는 [`hello-world`](https://hub.docker.com/_/hello-world) Docker 이미지를 기반으로 합니다.

1. **변경 사항 커밋**을 선택합니다.

## 파이프라인 구성 만들기 {#create-pipeline-configuration}

이제 파이프라인 구성을 만들 준비가 되었습니다. 파이프라인 구성은 다음과 같습니다:

1. `Dockerfile` 파일에서 Docker 이미지를 빌드하고 Docker 이미지를 컨테이너 레지스트리로 푸시합니다. `build-image` 작업은 [Docker-in-Docker](../../ci/docker/using_docker_build.md)를 [CI/CD 서비스](../../ci/services/_index.md)로 사용하여 Docker 이미지를 빌드합니다.
1. `Container-Scanning.gitlab-ci.yml` 템플릿을 포함하여 컨테이너 레지스트리에 저장된 Docker 이미지를 검사합니다.

파이프라인 구성을 만들려면:

1. 프로젝트의 루트 디렉터리에서 {{< icon name="plus" >}} > **새 파일**을 선택합니다.
1. 파일 이름 `.gitlab-ci.yml`을 입력하고 다음 내용을 파일에 입력합니다:

   ```yaml
   include:
     - template: Jobs/Container-Scanning.gitlab-ci.yml

   container_scanning:
     variables:
       CS_IMAGE: $CI_REGISTRY_IMAGE/tutorial-image

   build-image:
     image: docker:24.0.2-cli
     stage: build
     services:
       - docker:24.0.2-dind
     script:
       - docker build --tag $CI_REGISTRY_IMAGE/tutorial-image --file Dockerfile .
       - docker login --username gitlab-ci-token --password $CI_JOB_TOKEN $CI_REGISTRY
       - docker push $CI_REGISTRY_IMAGE/tutorial-image
   ```

1. **변경 사항 커밋**을 선택합니다.

거의 완료되었습니다. 파일을 커밋하면 이 구성으로 새 파이프라인이 시작됩니다. 완료되면 검사 결과를 확인할 수 있습니다.

## 보고된 취약점 확인 {#check-for-reported-vulnerabilities}

검사의 취약점은 검사를 실행한 파이프라인에 있습니다. 보고된 취약점을 확인하려면:

1. **CI/CD** > **파이프라인**을 선택하고 최근 파이프라인을 선택합니다. 이 파이프라인은 `test` 스테이지에서 `container_scanning`라는 작업으로 구성되어야 합니다.
1. `container_scanning` 작업이 성공했으면 **보안** 탭을 선택합니다. 취약점이 발견되면 해당 페이지에 나열됩니다.

## Docker 이미지 업데이트 {#update-the-docker-image}

`hello-world:latest`을 기반으로 한 Docker 이미지는 취약점을 표시할 가능성이 낮습니다. 취약점을 보고하는 검사의 예:

1. 프로젝트의 루트 디렉터리에서 기존 `Dockerfile` 파일을 선택합니다.
1. **편집**을 선택합니다.
1. `FROM hello-world:latest`을 [`FROM`](https://docs.docker.com/reference/dockerfile/#from) 명령어의 다른 Docker 이미지로 바꿉니다. 컨테이너 스캔을 시연하기 위한 최고의 Docker 이미지는 다음을 포함합니다:
   - 운영 체제 패키지. 예를 들어 Debian, Ubuntu, Alpine 또는 Red Hat의 패키지입니다.
   - 프로그래밍 언어 패키지. 예를 들어 NPM 패키지 또는 Python 패키지입니다.
1. **변경 사항 커밋**을 선택합니다.

파일에 변경 사항을 커밋하면 이 업데이트된 `Dockerfile`으로 새 파이프라인이 시작됩니다. 완료되면 새 검사 결과를 확인할 수 있습니다.
