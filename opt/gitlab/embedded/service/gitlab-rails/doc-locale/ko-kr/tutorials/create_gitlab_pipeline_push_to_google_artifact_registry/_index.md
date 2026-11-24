---
stage: Verify
group: tutorials
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: GitLab 파이프라인을 만들어 Google Artifact Registry로 푸시합니다'
---

GitLab을 Google Cloud에 연결하고 Compute Engine의 러너를 사용하여 GitLab 파이프라인을 만들어 이미지를 Artifact Registry로 푸시하는 방법을 알아봅니다.

## 시작하기 전에 {#before-you-begin}

1. 이 페이지의 명령을 실행하려면 다음 개발 환경 중 하나에서 `gcloud` CLI를 설정합니다:

   - [Cloud Shell](https://cloud.google.com/shell/docs/using-cloud-shell)
   - [로컬 셸](https://cloud.google.com/sdk/docs/install)

1. Google Cloud 프로젝트를 만들거나 선택합니다.

   > [!note]
   > 이 절차에서 만드는 리소스를 유지하려고 계획하지 않다면 기존 프로젝트를 선택하는 대신 새 Google Cloud 프로젝트를 만듭니다. 이 단계를 완료한 후 프로젝트를 삭제하여 프로젝트와 연결된 모든 리소스를 제거할 수 있습니다.

   Google Cloud 프로젝트를 만들려면 다음 명령을 실행합니다:

   ```shell
   gcloud projects create PROJECT_ID
   ```

   `PROJECT_ID`을(를) 만드는 Google Cloud 프로젝트의 이름으로 바꿉니다.
1. 만든 Google Cloud 프로젝트를 선택합니다:

   ```shell
   gcloud config set project PROJECT_ID
   ```

   `PROJECT_ID`을(를) Google Cloud 프로젝트 이름으로 바꿉니다.
1. [Google Cloud 프로젝트에 청구가 활성화되어 있는지 확인합니다](https://cloud.google.com/billing/docs/how-to/verify-billing-enabled#console).
1. Compute Engine 및 Artifact Registry API를 활성화합니다:

   ```shell
   gcloud services enable compute.googleapis.com artifactregistry.googleapis.com
   ```

1. [Google Cloud Workload Identity Federation 및 IAM 정책](../../integration/google_cloud_iam.md)의 지침을 따라 Google Cloud의 GitLab 통합을 설정합니다.
1. [표준 모드 Docker 형식 Artifact Registry 리포지토리를 만듭니다](https://cloud.google.com/artifact-registry/docs/repositories/create-repos#create).
1. [GitLab 프로젝트에서 Google Artifact Registry 설정](../../user/project/integrations/google_artifact_management.md)의 지침을 따라 Artifact Registry 리포지토리를 GitLab 프로젝트에 연결합니다.

## GitLab 리포지토리 복제 {#clone-your-gitlab-repository}

1. [Git 리포지토리를 로컬 컴퓨터에 복제](../../topics/git/clone.md)의 지침을 따라 GitLab 리포지토리를 SSH 또는 HTTPS를 사용하여 작업 환경에 복제합니다.
1. 로컬 셸에서 작업하는 경우 [Terraform을 설치](https://developer.hashicorp.com/terraform/install?product_intent=terraform)합니다. Terraform은 이미 Cloud Shell에 설치되어 있습니다.

## Dockerfile 만들기 {#create-a-dockerfile}

1. 복제한 리포지토리에서 `Dockerfile`라는 새 파일을 만듭니다.
1. 다음을 복사하여 `Dockerfile`에 붙여넣습니다.

   ```dockerfile
   # Dockerfile for test purposes. Generates a new random image in every build.
   FROM alpine:3.15.11
   RUN dd if=/dev/urandom of=random bs=10 count=1
   ```

1. `Dockerfile`을(를) Git에 추가하고 커밋한 후 GitLab 리포지토리로 푸시합니다.

   ```shell
   git add Dockerfile
   git commit -m "add dockerfile"
   git push
   ```

   사용자 이름과 [개인 액세스 토큰](../../user/profile/personal_access_tokens.md)을 입력하라는 메시지가 표시됩니다.

Dockerfile은 모든 빌드에 대해 새로운 무작위 이미지를 생성하며 테스트 목적으로만 제공됩니다.

## Google Compute Engine에서 지속적 통합(CI) 러너 활성화 {#enable-continuous-integration-ci-runners-on-google-compute-engine}

[GitLab Runner](https://docs.gitlab.com/runner/)는 GitLab CI/CD와 함께 작동하여 파이프라인의 작업을 실행하는 애플리케이션입니다. Google Cloud의 GitLab 통합은 Compute Engine에서 자동 크기 조정 러너 플릿을 설정하는 데 도움이 됩니다. 러너 관리자는 여러 작업을 동시에 실행하기 위해 임시 러너를 만듭니다.

[Google Cloud에서 CI/CD 작업을 실행하도록 GitLab Runner 설정](../set_up_gitlab_google_integration/_index.md#set-up-gitlab-runner-to-execute-your-cicd-jobs-on-google-cloud)의 지침을 따라 자동 크기 조정 러너 플릿을 설정합니다. 러너가 CI/CD 작업을 실행하길 원하는 환경으로 Google Cloud를 선택하고 나머지 구성 세부 정보를 입력합니다.

러너의 세부 정보를 입력한 후 설정 지침을 따라 Google Cloud 프로젝트를 구성하고 GitLab Runner를 설치 및 등록한 후 작업 환경에 제공된 terraform을 적용하여 구성을 적용합니다.

## 파이프라인 만들기 {#create-a-pipeline}

Docker 이미지를 빌드하고 GitLab 컨테이너 레지스트리로 푸시한 후 Google Artifact Registry로 복사하는 파이프라인을 만듭니다.

1. GitLab 프로젝트에서 [`.gitlab-ci.yml` 파일](../../ci/quick_start/_index.md#create-a-gitlab-ciyml-file)을 만듭니다.
1. 이미지를 빌드하고 GitLab 컨테이너 레지스트리로 푸시한 후 Google Artifact Registry로 복사하는 파이프라인을 만들려면 `.gitlab-ci.yml` 파일의 내용을 다음과 같이 수정합니다.

   예에서 다음을 바꿉니다:

   - `LOCATION`: Google Artifact Registry 리포지토리를 만든 Google Cloud 지역
   - `PROJECT`: Google Cloud 프로젝트 ID입니다.
   - `REPOSITORY`: Google Artifact Registry 리포지토리의 리포지토리 ID

   ```yaml
   stages:
     - build
     - deploy

   variables:
     GITLAB_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA

   build-sample-image:
     image: docker:24.0.5-cli
     stage: build
     services:
       - docker:24.0.5-dind
     before_script:
       - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
     script:
       - docker build -t $GITLAB_IMAGE .
       - docker push $GITLAB_IMAGE

   include:
     - component: gitlab.com/google-gitlab-components/artifact-registry/upload-artifact-registry@0.1.0
       inputs:
         stage: deploy
         source: $GITLAB_IMAGE
         target: LOCATION-docker.pkg.dev/PROJECT/REPOSITORY/image:v1.0.0
   ```

파이프라인은 Docker in Docker를 사용하여 `docker:24.0.5` 이미지를 빌드하고 GitLab 컨테이너 레지스트리에 저장한 후 [Google Artifact Registry GitLab 구성 요소](https://gitlab.com/explore/catalog/google-gitlab-components/artifact-registry)를 사용하여 `v1.0.0` 버전으로 Google Artifact Registry 리포지토리로 푸시합니다.

## 아티팩트 보기 {#view-your-artifacts}

GitLab에서 아티팩트를 보려면:

1. GitLab 프로젝트의 왼쪽 사이드바에서 **빌드** > **아티팩트**를 선택합니다.
1. 아티팩트의 이름을 선택하여 빌드의 세부 정보를 봅니다.

Google Artifact Registry에서 아티팩트를 보려면:

1. [Google Cloud 콘솔에서 **리포지토리** 페이지 열기](https://console.cloud.google.com/artifacts).
1. 연결된 리포지토리의 이름을 선택합니다.
1. 이미지의 이름을 선택하여 버전 이름 및 태그를 봅니다.
1. 이미지 버전의 이름을 선택하여 버전의 빌드, 끌어오기 및 매니페스트 정보를 봅니다.

## 정리 {#clean-up}

이 페이지에서 사용한 리소스에 대해 Google Cloud 계정에 요금이 부과되지 않도록 하려면 Google Cloud 프로젝트를 삭제할 수 있습니다. 프로젝트를 유지하려면 Google Artifact Registry 리포지토리를 삭제할 수 있습니다.

GitLab 및 Google Artifact Registry 가격 및 프로젝트 관리에 대한 정보는 다음 리소스를 참조하세요:

- [GitLab 가격 책정](https://about.gitlab.com/free-trial/devsecops)
- [GitLab 프로젝트 삭제](../../user/project/working_with_projects.md#delete-a-project)
- [Google Artifact Registry 가격 책정](https://cloud.google.com/artifact-registry/pricing)

### Google Artifact Registry 리포지토리 삭제 {#delete-your-google-artifact-registry-repository}

Google Cloud 프로젝트를 유지하면서 Google Artifact Registry 리포지토리 리소스만 삭제하려면 이 섹션의 단계를 따릅니다. 전체 Google Cloud 프로젝트를 삭제하려면 [프로젝트 삭제](#delete-your-google-cloud-project)의 단계를 따릅니다.

리포지토리를 제거하기 전에 보관하려는 모든 이미지를 다른 위치에서 사용할 수 있는지 확인합니다.

리포지토리를 삭제하려면 다음 명령을 실행합니다:

```shell
gcloud artifacts repositories delete REPOSITORY \
    --location=LOCATION
```

다음을 바꿉니다:

- `REPOSITORY`을 Google Artifact Registry 리포지토리 ID로 바꾸기
- `LOCATION`을 리포지토리의 위치로 바꾸기

### Google Cloud 프로젝트 삭제 {#delete-your-google-cloud-project}

**주의**: 프로젝트를 삭제하면 다음과 같은 영향이 있습니다:

- 프로젝트의 모든 항목이 삭제됩니다. 이 문서의 작업에 기존 프로젝트를 사용한 경우 삭제할 때 프로젝트에서 수행한 다른 모든 작업도 삭제됩니다.
- 사용자 지정 프로젝트 ID가 손실됩니다. 이 프로젝트를 만들 때 향후 사용하려는 사용자 지정 프로젝트 ID를 만들었을 수 있습니다. 프로젝트 ID를 사용하는 URL(예: appspot.com URL)을 보존하려면 전체 프로젝트를 삭제하는 대신 프로젝트 내의 선택된 리소스를 삭제합니다.

Google Cloud에서 여러 아키텍처, 자습서 또는 빠른 시작 자습서를 살펴보려는 경우 프로젝트를 재사용하면 프로젝트 할당량 제한을 초과하는 것을 피할 수 있습니다.

1. Google Cloud 콘솔에서 [**리소스 관리** 페이지](https://console.cloud.google.com/iam-admin/projects)로 이동합니다.
1. 프로젝트 목록에서 삭제하려는 프로젝트를 선택한 다음 **삭제**를 선택합니다.
1. 대화 상자에서 프로젝트 ID를 입력한 다음 **종료**를 선택하여 프로젝트를 삭제합니다.

## 관련 항목 {#related-topics}

- [GitLab CI/CD 구성 파일 최적화](../../ci/yaml/yaml_optimization.md) 방법을 알아봅니다.
- Google Cloud의 GitLab 통합이 IAM과 워크로드 ID 페더레이션을 사용하여 Google Cloud에 대한 액세스를 제어하는 방식을 [IAM을 사용한 액세스 제어](https://cloud.google.com/docs/gitlab)에서 확인하세요.
