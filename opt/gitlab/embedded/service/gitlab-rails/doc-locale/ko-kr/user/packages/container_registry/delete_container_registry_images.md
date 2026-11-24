---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 컨테이너 레지스트리에서 컨테이너 이미지 삭제
description: GitLab에서 컨테이너 이미지를 삭제하기 위한 자동 및 수동 방법입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

컨테이너 레지스트리에서 컨테이너 이미지를 삭제할 수 있습니다.

특정 기준에 따라 컨테이너 이미지를 자동으로 삭제하려면 [가비지 컬렉션](#garbage-collection)을 사용합니다. 또는 3rd-party 도구를 사용하여 특정 프로젝트에서 컨테이너 이미지를 삭제하기 위해 [CI/CD 작업을 생성](#use-gitlab-cicd)할 수 있습니다.

프로젝트 또는 그룹에서 특정 컨테이너 이미지를 삭제하려면 [GitLab UI](#use-the-gitlab-ui) 또는 [GitLab API](#use-the-gitlab-api)를 사용할 수 있습니다.

> [!warning]
> 컨테이너 이미지 삭제는 소멸적 작업이며 실행 취소할 수 없습니다. 삭제된 컨테이너 이미지를 복원하려면 이미지를 다시 빌드하고 다시 업로드해야 합니다.

## 가비지 컬렉션 {#garbage-collection}

GitLab Self-Managed 인스턴스에서 컨테이너 이미지를 삭제해도 저장 공간이 확보되지 않으며, 이미지만 삭제 대상으로 표시됩니다. 실제로 참조되지 않은 컨테이너 이미지를 삭제하고 저장 공간을 복구하려면 GitLab Self-Managed 인스턴스 관리자가 [가비지 컬렉션](../../../administration/packages/container_registry.md#container-registry-garbage-collection)을 실행해야 합니다.

GitLab.com의 컨테이너 레지스트리는 자동 온라인 가비지 컬렉터를 포함합니다. 자동 가비지 컬렉터를 사용하면 다음이 24시간 이내에 자동으로 삭제 예약되며, 참조되지 않은 경우:

- 이미지 매니페스트에 의해 참조되지 않은 계층입니다.
- 태그가 없고 다른 매니페스트(예: 다중 아키텍처 이미지)에 의해 참조되지 않은 이미지 매니페스트입니다.

온라인 가비지 컬렉터는 인스턴스 차원의 기능이며 모든 네임스페이스에 적용됩니다.

## GitLab UI 사용 {#use-the-gitlab-ui}

GitLab UI를 사용하여 컨테이너 이미지를 삭제하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 다음의 경우:
   - 그룹의 경우 **운영** > **Container Registry**를 선택합니다.
   - 프로젝트의 경우 **배포** > **Container Registry**를 선택합니다.
1. **Container Registry** 페이지에서 다음 중 하나의 방법으로 삭제할 항목을 선택할 수 있습니다:

   - 전체 리포지토리와 포함된 모든 태그를 삭제하고, 빨간색 {{< icon name="remove" >}} **Trash** 아이콘을 선택합니다.
   - 리포지토리로 이동하고, 삭제할 태그 옆의 빨간색 {{< icon name="remove" >}} **Trash** 아이콘을 선택하여 태그를 개별적으로 또는 대량으로 삭제합니다.

1. 대화상자에서 **태그 제거**를 선택합니다.

[10회 이상 삭제에 실패한](../../../administration/packages/container_registry.md#max-retries-for-deleting-container-images) 컨테이너 리포지토리는 자동으로 이미지 삭제를 시도하지 않습니다.

## GitLab API 사용 {#use-the-gitlab-api}

API를 사용하여 컨테이너 이미지 삭제 프로세스를 자동화할 수 있습니다. 자세한 내용은 다음 엔드포인트를 참조합니다:

- [레지스트리 리포지토리 삭제](../../../api/container_registry.md#delete-registry-repository)
- [개별 레지스트리 리포지토리 태그 삭제](../../../api/container_registry.md#delete-a-registry-repository-tag)
- [레지스트리 리포지토리 태그 대량 삭제](../../../api/container_registry.md#delete-registry-repository-tags-in-bulk)

## GitLab CI/CD 사용 {#use-gitlab-cicd}

> [!note]
> GitLab CI/CD는 컨테이너 이미지를 제거할 수 있는 기본 제공 방법을 제공하지 않습니다. 이 예제는 GitLab Registry API와 통신하는 [`regctl`](https://github.com/regclient/regclient)라는 3rd-party 도구를 사용합니다. 이 3rd-party 도구에 대한 도움말은 [regclient 이슈 추적기](https://github.com/regclient/regclient/issues)를 참조합니다.

다음 예제는 두 개의 스테이지 `build` 및 `clean`를 정의합니다. `build_image` 작업은 브랜치에 대한 컨테이너 이미지를 빌드하고 `delete_image` 작업은 이를 삭제합니다. `reg` 실행 파일을 다운로드하여 `$CI_PROJECT_PATH:$CI_COMMIT_REF_SLUG` [미리 정의된 CI/CD 변수](../../../ci/variables/predefined_variables.md)와 일치하는 컨테이너 이미지를 제거하는 데 사용합니다.

이 예제를 사용하려면 `IMAGE_TAG` 변수를 필요에 맞게 변경합니다.

```yaml
stages:
  - build
  - clean

build_image:
  image: docker:20.10.16
  stage: build
  services:
    - docker:20.10.16-dind
  variables:
    IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -t $IMAGE_TAG .
    - docker push $IMAGE_TAG
  rules:
      - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
        when: never
      - if: $CI_COMMIT_BRANCH

delete_image:
  stage: clean
  variables:
    IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
    REGCTL_VERSION: v0.6.1
  rules:
      - if: $CI_COMMIT_REF_NAME != $CI_DEFAULT_BRANCH
  image: alpine:latest
  script:
    - apk update
    - apk add curl
    - curl --fail-with-body --location "https://github.com/regclient/regclient/releases/download/${REGCTL_VERSION}/regctl-linux-amd64" > /usr/bin/regctl
    - chmod 755 /usr/bin/regctl
    - regctl registry login ${CI_REGISTRY} -u ${CI_REGISTRY_USER} -p ${CI_REGISTRY_PASSWORD}
    - regctl tag rm $IMAGE
```

> [!note]
> 최신 `regctl` 릴리스를 [릴리스 페이지](https://github.com/regclient/regclient/releases)에서 다운로드한 후 `delete_image` 작업에 정의된 `REGCTL_VERSION` 변수를 변경하여 코드 예제를 업데이트할 수 있습니다.

## 정리 정책 사용 {#use-a-cleanup-policy}

프로젝트당 [정리 정책](reduce_container_registry_storage.md#cleanup-policy)을 생성하여 오래된 태그 및 이미지가 컨테이너 레지스트리에서 정기적으로 제거되도록 할 수 있습니다.
