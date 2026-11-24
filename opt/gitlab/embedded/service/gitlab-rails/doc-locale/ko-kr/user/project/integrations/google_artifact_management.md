---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Google 아티팩트 관리
description: "Google Artifact Registry를 GitLab 프로젝트에 연결하여 Docker 및 OCI 이미지를 보고, 푸시하고, 풀할 수 있습니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- [GitLab 16.10에서 도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/141127)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md)의 이름은 `google_cloud_support_feature_flag`입니다. 이 기능은 [베타](../../../policy/development_stages_support.md) 단계입니다.
- GitLab 17.1에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/150472)되었습니다. 기능 플래그 `google_cloud_support_feature_flag`이 제거되었습니다.

{{< /history >}}

Google 아티팩트 관리 통합을 사용하여 [Google Artifact Registry](https://docs.cloud.google.com/artifact-registry/docs) 리포지토리를 GitLab 프로젝트에 구성하고 연결할 수 있습니다.

Google Artifact Registry를 프로젝트에 연결한 후 [OCI](https://opencontainers.org/) 이미지를 포함한 Docker 및 [Google Artifact Registry](https://docs.cloud.google.com/artifact-registry/docs) 리포지토리에서 이미지를 보고, 푸시하고, 풀할 수 있습니다.

## GitLab 프로젝트에서 Google Artifact Registry 설정 {#set-up-the-google-artifact-registry-in-a-gitlab-project}

사전 요구 사항:

- GitLab 프로젝트의 유지 관리자 또는 소유자 역할 이상이 필요합니다.
- Artifact Registry 리포지토리가 있는 Google Cloud 프로젝트에 대한 액세스를 관리하는 데 필요한 [권한](https://cloud.google.com/iam/docs/granting-changing-revoking-access#required-permissions)이 있어야 합니다.
- [워크로드 ID 페더레이션](../../../integration/google_cloud_iam.md)(WLIF) 풀과 공급자를 구성하여 Google Cloud에 인증해야 합니다.
- 다음 구성을 사용한 [Google Artifact Registry 리포지토리](https://docs.cloud.google.com/artifact-registry/docs/repositories):
  - [Docker](https://docs.cloud.google.com/artifact-registry/docs/supported-formats) 형식.
  - [표준](https://docs.cloud.google.com/artifact-registry/docs/repositories/create-repos) 모드. 다른 리포지토리 형식 및 모드는 지원되지 않습니다.

Google Artifact Registry 리포지토리를 GitLab 프로젝트에 연결하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Google 아티팩트 관리**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 필드를 완성합니다:
   - **Google Cloud 프로젝트 ID**: Artifact Registry 리포지토리가 있는 [Google Cloud 프로젝트 ID](https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects)입니다.
   - **리포지토리 이름**: Artifact Registry 리포지토리의 이름입니다.
   - **리포지토리 위치**: Artifact Registry 리포지토리의 [Google Cloud 위치](https://cloud.google.com/about/locations)입니다.
1. 화면의 지시사항에 따라 Google Cloud ID(ID) 및 액세스 관리(IAM) 정책을 설정합니다. 정책 유형에 대한 자세한 정보는 [IAM 정책](#iam-policies)을 참조하세요.
1. **변경 사항 저장**을 선택합니다.

이제 사이드바의 **배포** 아래에서 **Google Artifact Registry** 항목을 볼 수 있습니다.

## Google Artifact Registry에 저장된 이미지 보기 {#view-images-stored-in-the-google-artifact-registry}

사전 요구 사항:

- Google Artifact Registry는 프로젝트에서 [구성](#set-up-the-google-artifact-registry-in-a-gitlab-project)되어야 합니다.

GitLab UI에서 연결된 Artifact Registry 리포지토리의 이미지 목록을 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Google Artifact Registry**를 선택합니다.
1. 이미지 세부 정보를 보려면 이미지를 선택합니다.
1. Google Cloud 콘솔에서 이미지를 보려면 **Google Cloud에서 열기**를 선택합니다. 해당 Artifact Registry 리포지토리를 보려면 [필요한 권한](https://cloud.google.com/artifact-registry/docs/repositories/list-repos#required_roles)이 있어야 합니다.

## CI/CD {#cicd}

### 사전 정의된 변수 {#predefined-variables}

Artifact Registry 통합이 활성화된 후 다음의 미리 정의된 환경 변수를 CI/CD에서 사용할 수 있습니다. 이러한 환경 변수를 사용하여 Artifact Registry와 상호 작용하거나, 이미지를 연결된 리포지토리로 풀하거나 푸시할 수 있습니다.

| 변수                                       | GitLab | 러너 | 설명 |
|------------------------------------------------|--------|--------|-------------|
| `GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID`          | 16.10  | 16.10  | Artifact Registry 리포지토리가 있는 Google Cloud 프로젝트 ID입니다. |
| `GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME`     | 16.10  | 16.10  | 연결된 Artifact Registry 리포지토리의 이름입니다. |
| `GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION` | 16.10  | 16.10  | 연결된 Artifact Registry 리포지토리의 Google Cloud 위치입니다. |

### Google Artifact Registry로 인증 {#authenticate-with-the-google-artifact-registry}

파이프라인 실행 중에 Google Artifact Registry로 인증하도록 파이프라인을 구성할 수 있습니다. GitLab은 구성된 [워크로드 ID 풀](../../../integration/google_cloud_iam.md) IAM 정책을 사용하고 `GOOGLE_APPLICATION_CREDENTIALS` 및 `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE` 환경 자격 증명을 채웁니다. 이러한 환경 자격 증명은 [gcloud CLI](https://docs.cloud.google.com/sdk/gcloud) 및 [crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md)과 같은 클라이언트 도구에 의해 자동으로 감지됩니다.

Google Artifact Registry로 인증하려면 프로젝트의 `.gitlab-ci.yml` 파일에서 [`identity`](../../../ci/yaml/_index.md#identity) 키워드를 `google_cloud`로 설정합니다.

#### IAM 정책 {#iam-policies}

Google 아티팩트 관리 통합을 사용하려면 Google Cloud 프로젝트에 특정 IAM 정책이 있어야 합니다. [이 통합을 설정](#set-up-the-google-artifact-registry-in-a-gitlab-project)할 때 화면의 지시사항은 Google Cloud 프로젝트에서 다음 IAM 정책을 생성하는 단계를 제공합니다:

- [게스트](../../permissions.md#roles) 역할 이상의 GitLab 프로젝트 멤버에게 [Artifact Registry 리더](https://cloud.google.com/iam/docs/understanding-roles#artifactregistry.reader) 역할을 부여합니다.
- [개발자](../../permissions.md#roles) 역할 이상의 GitLab 프로젝트 멤버에게 [Artifact Registry 작성자](https://cloud.google.com/iam/docs/understanding-roles#artifactregistry.writer) 역할을 부여합니다.

이러한 IAM 정책을 수동으로 생성하려면 다음 `gcloud` 명령을 사용합니다. 다음 값을 바꿉니다:

- `<your_google_cloud_project_id>`을 Artifact Registry 리포지토리가 있는 Google Cloud 프로젝트의 [ID](https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects)로 바꿉니다.
- `<your_workload_identity_pool_id>`을 워크로드 ID 풀의 ID로 바꿉니다. 이는 [Google Cloud IAM 통합](../../../integration/google_cloud_iam.md)에 사용되는 값과 같습니다.
- `<your_google_cloud_project_number>`을 워크로드 ID 풀이 있는 Google Cloud 프로젝트의 [번호](https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects)로 바꿉니다. 이는 [Google Cloud IAM 통합](../../../integration/google_cloud_iam.md)에 사용되는 값과 같습니다.

```shell
gcloud projects add-iam-policy-binding '<your_google_cloud_project_id>' \
  --member='principalSet://iam.googleapis.com/projects/<your_google_cloud_project_number>/locations/global/workloadIdentityPools/<your_workload_identity_pool_id>/attribute.guest_access/true' \
  --role='roles/artifactregistry.reader'

gcloud projects add-iam-policy-binding '<your_google_cloud_project_id>' \
  --member='principalSet://iam.googleapis.com/projects/<your_google_cloud_project_number>/locations/global/workloadIdentityPools/<your_workload_identity_pool_id>/attribute.developer_access/true' \
  --role='roles/artifactregistry.writer'
```

사용 가능한 클레임 목록은 [OIDC 사용자 정의 클레임](../../../integration/google_cloud_iam.md#oidc-custom-claims)을 참조하세요.

### 예제 {#examples}

#### gcloud CLI를 사용하여 이미지 나열 {#use-gcloud-cli-to-list-images}

```yaml
list-images:
  image: gcr.io/google.com/cloudsdktool/google-cloud-cli:466.0.0-alpine
  identity: google_cloud
  script:
    - gcloud artifacts docker images list $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/app
```

#### crane을 사용하여 이미지 나열 {#use-crane-to-list-images}

```yaml
list-images:
  image:
    name: gcr.io/go-containerregistry/crane:debug
    entrypoint: [""]
  identity: google_cloud
  before_script:
    # Temporary workaround for https://github.com/google/go-containerregistry/issues/1886
    - wget -q "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v2.1.22/docker-credential-gcr_linux_amd64-2.1.22.tar.gz" -O - | tar xz -C /tmp && chmod +x /tmp/docker-credential-gcr && mv /tmp/docker-credential-gcr /usr/bin/
    - docker-credential-gcr configure-docker --registries=$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev
  script:
    - crane ls $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/app
```

#### Docker로 이미지 풀 {#pull-an-image-with-docker}

다음 예에서는 Google에서 제공하는 [독립 실행형 Docker 자격 증명 도우미](https://cloud.google.com/artifact-registry/docs/docker/authentication#standalone-helper)를 사용하여 Docker에 대한 인증을 설정하는 방법을 보여줍니다.

```yaml
pull-image:
  image: docker:24.0.5-cli
  identity: google_cloud
  services:
    - docker:24.0.5-dind
  variables:
    # The following two variables ensure that the DinD service starts in TLS
    # mode and that the Docker CLI is properly configured to communicate with
    # the API. More details about the importance of this can be found at
    # https://docs.gitlab.com/ci/docker/using_docker_build/#use-the-docker-executor-with-docker-in-docker
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_CERTDIR: "/certs"
  before_script:
    - wget -q "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v2.1.22/docker-credential-gcr_linux_amd64-2.1.22.tar.gz" -O - | tar xz -C /tmp && chmod +x /tmp/docker-credential-gcr && mv /tmp/docker-credential-gcr /usr/bin/
    - docker-credential-gcr configure-docker --registries=$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev
  script:
    - docker pull $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/app:v0.1.0
```

#### CI/CD 구성 요소를 사용하여 이미지 복사 {#copy-an-image-by-using-a-cicd-component}

Google은 GitLab 컨테이너 레지스트리에서 Artifact Registry로 이미지를 복사하는 데 사용할 수 있는 [`upload-artifact-registry`](https://gitlab.com/explore/catalog/google-gitlab-components/artifact-registry) CI/CD 구성 요소를 제공합니다.

`upload-artifact-registry` 구성 요소를 사용하려면 다음을 `.gitlab-ci.yml`에 추가합니다:

```yaml
include:
  - component: gitlab.com/google-gitlab-components/artifact-registry/upload-artifact-registry@main
    inputs:
      stage: deploy
      source: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
      target: $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/$CI_PROJECT_NAME:$CI_COMMIT_SHORT_SHA
```

자세한 내용은 [구성 요소 설명서](https://gitlab.com/explore/catalog/google-gitlab-components/artifact-registry)를 참조하세요.

`upload-artifact-registry` 구성 요소를 사용하면 Artifact Registry로 이미지를 복사하는 작업이 간소화되며 이것이 이 통합의 의도된 방법입니다. Docker 또는 Crane을 사용하려면 다음 예를 참조하세요.

#### Docker를 사용하여 이미지 복사 {#copy-an-image-by-using-docker}

다음 예에서는 `gcloud` CLI를 사용하여 [독립 실행형 Docker 자격 증명 도우미](https://cloud.google.com/artifact-registry/docs/docker/authentication#standalone-helper)의 대안으로 Docker 인증을 설정합니다.

```yaml
copy-image:
  image: gcr.io/google.com/cloudsdktool/google-cloud-cli:466.0.0-alpine
  identity: google_cloud
  services:
    - docker:24.0.5-dind
  variables:
    SOURCE_IMAGE: $CI_REGISTRY_IMAGE:v0.1.0
    TARGET_IMAGE: $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/app:v0.1.0
    DOCKER_HOST: tcp://docker:2375
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - gcloud auth configure-docker $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev
  script:
    - docker pull $SOURCE_IMAGE
    - docker tag $SOURCE_IMAGE $TARGET_IMAGE
    - docker push $TARGET_IMAGE
```

#### Crane을 사용하여 이미지 복사 {#copy-an-image-by-using-crane}

```yaml
copy-image:
  image:
    name: gcr.io/go-containerregistry/crane:debug
    entrypoint: [""]
  identity: google_cloud
  variables:
    SOURCE_IMAGE: $CI_REGISTRY_IMAGE:v0.1.0
    TARGET_IMAGE: $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/app:v0.1.0
  before_script:
    # Temporary workaround for https://github.com/google/go-containerregistry/issues/1886
    - wget -q "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v2.1.22/docker-credential-gcr_linux_amd64-2.1.22.tar.gz" -O - | tar xz -C /tmp && chmod +x /tmp/docker-credential-gcr && mv /tmp/docker-credential-gcr /usr/bin/
    - docker-credential-gcr configure-docker --registries=$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev
  script:
    - crane auth login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - crane copy $SOURCE_IMAGE $TARGET_IMAGE
```
