---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '튜토리얼: 빌드 프로비저넌스 데이터로 컨테이너 이미지에 주석 달기'
description: Cosign을 사용하여 GitLab CI/CD 파이프라인에서 빌드 프로비저넌스 데이터로 컨테이너 이미지에 주석을 달고 서명합니다.
---

주석은 빌드 프로세스에 대한 귀중한 메타데이터를 제공합니다. 이 정보는 감시 및 추적성을 위해 사용됩니다. 보안 사고 발생 시 상세한 프로비저넌스 데이터를 보유하면 조사 및 수정 프로세스를 크게 빠르게 할 수 있습니다.

이 자습서에서는 Cosign을 사용하여 컨테이너 이미지를 빌드, 서명 및 주석 처리하는 프로세스를 자동화하기 위해 GitLab 파이프라인을 설정하는 방법을 설명합니다. `.gitlab-ci.yml` 파일을 구성하여 Docker 이미지를 빌드, 푸시 및 서명한 후 GitLab 컨테이너 레지스트리로 푸시할 수 있습니다.

컨테이너 이미지에 주석을 달려면:

1. [이미지 및 서비스 이미지 설정](#set-image-and-service-image).
1. [CI/CD 변수 정의](#define-cicd-variables).
1. [OIDC 토큰 준비](#prepare-oidc-token).
1. [컨테이너 준비](#prepare-the-container).
1. [이미지 빌드 및 푸시](#build-and-push-the-image).
1. [Cosign으로 이미지 서명](#sign-the-image-with-cosign).
1. [서명 및 주석 확인](#verify-the-signature-and-annotations).

모든 것을 함께 구성하면 `.gitlab-ci.yml`은 이 자습서 끝에 제공된 [샘플 구성](#example-gitlab-ciyml-configuration)과 유사하게 보입니다.

## 시작하기 전에 {#before-you-begin}

다음이 필요합니다:

- Cosign v2.0 이상이 설치되어 있어야 합니다.
- GitLab Self-Managed의 경우, GitLab 컨테이너 레지스트리를 [메타데이터 데이터베이스로 구성](../../../administration/packages/container_registry_metadata_database.md)하여 서명을 표시합니다.

## 이미지 및 서비스 이미지 설정 {#set-image-and-service-image}

`.gitlab-ci.yml` 파일에서 `docker:cli` 이미지를 사용하고 Docker-in-Docker 서비스를 활성화하여 CI/CD 작업에서 Docker 명령을 실행할 수 있도록 합니다.

```yaml
build_and_sign:
  stage: build
  image: docker:cli
  services:
    - docker:dind  # Enable Docker-in-Docker service to allow Docker commands inside the container
```

## CI/CD 변수 정의 {#define-cicd-variables}

GitLab CI/CD 사전 정의된 변수를 사용하여 이미지 태그 및 URI에 대한 변수를 정의합니다.

```yaml
variables:
  IMAGE_TAG: $CI_COMMIT_SHORT_SHA  # Use the commit short SHA as the image tag
  IMAGE_URI: $CI_REGISTRY_IMAGE:$IMAGE_TAG  # Construct the full image URI with the registry, project path, and tag
  COSIGN_YES: "true"  # Automatically confirm actions in Cosign without user interaction
  FF_SCRIPT_SECTIONS: "true"  # Enables GitLab's CI script sections for better multi-line script output
```

## OIDC 토큰 준비 {#prepare-oidc-token}

Cosign으로 키 없는 서명을 위한 OIDC 토큰을 설정합니다.

```yaml
id_tokens:
  SIGSTORE_ID_TOKEN:
    aud: sigstore  # Provide an OIDC token for keyless signing with Cosign
```

## 컨테이너 준비 {#prepare-the-container}

`before_script` 파일의 `.gitlab-ci.yml` 섹션에서:

- Cosign 및 jq(JSON 처리용) 설치: `apk add --no-cache cosign jq`
- CI/CD 작업 토큰을 사용하여 GitLab 컨테이너 레지스트리 로그인 활성화: `docker login -u "gitlab-ci-token" -p "$CI_JOB_TOKEN" "$CI_REGISTRY"`

파이프라인은 필요한 환경을 설정하여 시작합니다.

## 이미지 빌드 및 푸시 {#build-and-push-the-image}

`script` 파일의 `.gitlab-ci.yml` 섹션에서 다음 명령을 입력하여 Docker 이미지를 빌드하고 GitLab 컨테이너 레지스트리로 푸시합니다.

```yaml
- docker build --pull -t "$IMAGE_URI" .
- docker push "$IMAGE_URI"
```

이 명령은 현재 디렉터리의 Dockerfile을 사용하여 이미지를 생성하고 레지스트리로 푸시합니다.

## Cosign으로 이미지 서명 {#sign-the-image-with-cosign}

이미지를 GitLab 컨테이너 레지스트리로 빌드하고 푼 후 Cosign을 사용하여 서명합니다.

`script` 파일의 `.gitlab-ci.yml` 섹션에서 다음 명령을 입력합니다:

```yaml
- IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE_URI")
- |
  cosign sign "$IMAGE_DIGEST" \
    --registry-referrers-mode oci-1-1 \
    --annotations "com.gitlab.ci.user.name=$GITLAB_USER_NAME" \
    --annotations "com.gitlab.ci.pipeline.id=$CI_PIPELINE_ID" \
    # Additional annotations removed for readability
    --annotations "tag=$IMAGE_TAG"
```

이 단계는 이미지 다이제스트를 검색합니다. 그런 다음 Cosign을 사용하여 이미지에 서명하고 여러 주석을 추가합니다.

## 서명 및 주석 확인 {#verify-the-signature-and-annotations}

이미지에 서명한 후 서명 및 추가된 주석을 확인하는 것이 중요합니다.

`.gitlab-ci.yml` 파일에서 `cosign verify` 명령을 사용하는 확인 단계를 포함합니다:

```yaml
- |
  cosign verify \
    --annotations "tag=$IMAGE_TAG" \
    --certificate-identity "$CI_PROJECT_URL//.gitlab-ci.yml@refs/heads/$CI_COMMIT_REF_NAME" \
    --certificate-oidc-issuer "$CI_SERVER_URL" \
    "$IMAGE_URI" | jq .
```

확인 단계는 이미지에 첨부된 프로비저넌스 데이터가 올바르고 손상되지 않았는지 확인합니다. `cosign verify` 명령은 서명을 확인하고 주석을 확인합니다. 출력에는 서명 프로세스 중에 이미지에 추가한 모든 주석이 표시됩니다.

출력에서 다음을 포함하여 이전에 추가한 모든 주석을 볼 수 있습니다:

- GitLab 사용자 이름
- 파이프라인 ID 및 URL
- 작업 ID 및 URL
- 커밋 SHA 및 참조 이름
- 프로젝트 경로
- 이미지 소스 및 리비전

이러한 주석을 확인하면 이미지의 프로비저넌스 데이터가 손상되지 않았는지 확인하고 빌드 프로세스를 기반으로 예상하는 것과 일치하는지 확인할 수 있습니다.

## 예 `.gitlab-ci.yml` 구성 {#example-gitlab-ciyml-configuration}

앞의 모든 단계를 따르면 `.gitlab-ci.yml` 파일이 다음과 같이 표시되어야 합니다:

```yaml
stages:
  - build

build_and_sign:
  stage: build
  image: docker:cli
  services:
    - docker:dind  # Enable Docker-in-Docker service to allow Docker commands inside the container
  variables:
    IMAGE_TAG: $CI_COMMIT_SHORT_SHA  # Use the commit short SHA as the image tag
    IMAGE_URI: $CI_REGISTRY_IMAGE:$IMAGE_TAG  # Construct the full image URI with the registry, project path, and tag
    COSIGN_YES: "true"  # Automatically confirm actions in Cosign without user interaction
    FF_SCRIPT_SECTIONS: "true"  # Enables GitLab's CI script sections for better multi-line script output
  id_tokens:
    SIGSTORE_ID_TOKEN:
      aud: sigstore  # Provide an OIDC token for keyless signing with Cosign
  before_script:
    - apk add --no-cache cosign jq  # Install Cosign (mandatory) and jq (optional)
    - docker login -u "gitlab-ci-token" -p "$CI_JOB_TOKEN" "$CI_REGISTRY"  # Log in to the Docker registry using GitLab CI token
  script:
    # Build the Docker image using the specified tag and push it to the registry
    - docker build --pull -t "$IMAGE_URI" .
    - docker push "$IMAGE_URI"

    # Retrieve the digest of the pushed image to use in the signing step
    - IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE_URI")

    # Sign the image using Cosign with annotations that provide metadata about the build and tag annotation to allow verifying
    # the tag->digest mapping (https://github.com/sigstore/cosign?tab=readme-ov-file#tag-signing)
    - |
      cosign sign "$IMAGE_DIGEST" \
        --registry-referrers-mode oci-1-1 \
        --annotations "com.gitlab.ci.user.name=$GITLAB_USER_NAME" \
        --annotations "com.gitlab.ci.pipeline.id=$CI_PIPELINE_ID" \
        --annotations "com.gitlab.ci.pipeline.url=$CI_PIPELINE_URL" \
        --annotations "com.gitlab.ci.job.id=$CI_JOB_ID" \
        --annotations "com.gitlab.ci.job.url=$CI_JOB_URL" \
        --annotations "com.gitlab.ci.commit.sha=$CI_COMMIT_SHA" \
        --annotations "com.gitlab.ci.commit.ref.name=$CI_COMMIT_REF_NAME" \
        --annotations "com.gitlab.ci.project.path=$CI_PROJECT_PATH" \
        --annotations "org.opencontainers.image.source=$CI_PROJECT_URL" \
        --annotations "org.opencontainers.image.revision=$CI_COMMIT_SHA" \
        --annotations "tag=$IMAGE_TAG"

    # Verify the image signature using Cosign to ensure it matches the expected annotations and certificate identity
    - |
      cosign verify \
        --annotations "tag=$IMAGE_TAG" \
        --certificate-identity "$CI_PROJECT_URL//.gitlab-ci.yml@refs/heads/$CI_COMMIT_REF_NAME" \
        --certificate-oidc-issuer "$CI_SERVER_URL" \
        "$IMAGE_URI" | jq .  # Use jq to format the verification output for easier readability
```
