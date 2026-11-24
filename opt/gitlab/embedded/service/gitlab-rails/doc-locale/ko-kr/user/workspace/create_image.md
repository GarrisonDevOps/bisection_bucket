---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab에서 만들 수 있는 모든 워크스페이스를 지원하도록 커스텀 워크스페이스 이미지를 생성합니다.
title: '튜토리얼: 임의 사용자 ID를 지원하는 커스텀 워크스페이스 이미지 생성'
---

<!-- vale gitlab_base.FutureTense = NO -->

이 튜토리얼은 프로젝트 요구 사항을 충족하는 커스텀 워크스페이스 이미지를 생성하는 과정을 안내합니다. 완료 후 GitLab에서 생성한 모든 [워크스페이스](_index.md)에서 이 커스텀 이미지를 사용할 수 있습니다.

임의 사용자 ID를 지원하는 커스텀 워크스페이스 이미지를 생성하려면:

1. [Dockerfile 생성](#create-a-dockerfile).
1. [커스텀 워크스페이스 이미지 빌드](#build-the-custom-workspace-image).
1. [커스텀 워크스페이스 이미지를 GitLab 컨테이너 레지스트리에 푸시](#push-the-custom-workspace-image-to-the-gitlab-container-registry).
1. [GitLab에서 커스텀 워크스페이스 이미지 사용](#use-the-custom-workspace-image-in-gitlab).

## 시작하기 전에 {#before-you-begin}

다음이 필요합니다:

- GitLab 컨테이너 레지스트리에 컨테이너 이미지를 생성하고 푸시할 수 있는 권한이 있는 GitLab 계정.
- 로컬 머신에 설치된 Docker.

## Dockerfile 생성 {#create-a-dockerfile}

[워크스페이스 기본 이미지](_index.md#workspace-base-image) (`registry.gitlab.com/gitlab-org/gitlab-build-images:workspaces-base`)를 GitLab 컨테이너 레지스트리에서 시작점으로 사용하는 Dockerfile을 생성합니다:

```Dockerfile
FROM registry.gitlab.com/gitlab-org/gitlab-build-images:workspaces-base

# Install additional tools your project needs
RUN sudo apt-get update && \
    sudo apt-get install -y tree && \
    sudo rm -rf /var/lib/apt/lists/*

# Install project-specific tools using mise
# For example, install Node.js version 20
RUN mise install node@20 && \
    mise use node@20

# Install global packages
RUN npm install -g @angular/cli

# Set up your project environment
ENV NODE_ENV=development

# Create project directories
RUN mkdir -p /home/gitlab-workspaces/projects
```

프로젝트의 특정 요구 사항에 따라 이 단계를 사용자 지정합니다. 다음으로 커스텀 워크스페이스 이미지를 빌드합니다.

## 커스텀 워크스페이스 이미지 빌드 {#build-the-custom-workspace-image}

Dockerfile을 완성했으므로 커스텀 워크스페이스 이미지를 빌드할 준비가 되었습니다:

1. Dockerfile을 생성한 디렉터리에서 다음 명령을 실행합니다:

   ```shell
   docker build -t my-gitlab-workspace .
   ```

   인터넷 연결 및 시스템 속도에 따라 몇 분 정도 소요될 수 있습니다.

1. 빌드 프로세스가 완료된 후 이미지를 로컬에서 테스트합니다:

   ```shell
   docker run -ti my-gitlab-workspace sh
   ```

`gitlab-workspaces` 사용자로 명령을 실행할 수 있는 권한이 있어야 합니다. 완벽합니다! 이미지가 로컬에서 작동합니다. 다음으로 GitLab에서 사용할 수 있도록 해야 합니다.

## 커스텀 워크스페이스 이미지를 GitLab 컨테이너 레지스트리에 푸시 {#push-the-custom-workspace-image-to-the-gitlab-container-registry}

커스텀 워크스페이스 이미지를 GitLab 컨테이너 레지스트리에 푸시하여 프로젝트에서 사용합니다:

1. GitLab 계정에 로그인합니다:

   ```shell
   docker login registry.gitlab.com
   ```

1. GitLab 컨테이너 레지스트리 URL로 이미지에 태그를 지정합니다:

   ```shell
   docker tag my-gitlab-workspace registry.gitlab.com/your-namespace/my-gitlab-workspace:latest
   ```

   `your-namespace`을 실제 GitLab 네임스페이스로 바꾸어야 합니다.

1. GitLab 컨테이너 레지스트리에 이미지를 푸시합니다:

   ```shell
   docker push registry.gitlab.com/your-namespace/my-gitlab-workspace:latest
   ```

   인터넷 연결 속도에 따라 업로드 시간이 걸릴 수 있습니다.

잘했습니다! 커스텀 워크스페이스 이미지가 이제 GitLab 컨테이너 레지스트리에 안전하게 저장되고 사용 준비가 완료되었습니다.

## GitLab에서 커스텀 워크스페이스 이미지 사용 {#use-the-custom-workspace-image-in-gitlab}

마지막 단계로 프로젝트를 구성하여 커스텀 워크스페이스 이미지를 사용합니다:

1. 프로젝트의 `.devfile.yaml`에서 컨테이너 이미지를 업데이트합니다:

   ```yaml
   schemaVersion: 2.2.0
   components:
     - name: tooling-container
       attributes:
         gl/inject-editor: true
       container:
         image: registry.gitlab.com/your-namespace/my-gitlab-workspace:latest
   ```

   `your-namespace`을 실제 GitLab 네임스페이스로 바꾸어야 합니다.

축하합니다! 임의 사용자 ID를 지원하는 커스텀 워크스페이스 이미지를 성공적으로 생성하고 구성했습니다. 이제 GitLab에서 생성한 모든 [워크스페이스](_index.md)에서 이 커스텀 이미지를 사용할 수 있습니다.

## 관련 항목 {#related-topics}

- [워크스페이스 문제 해결](workspaces_troubleshooting.md)
