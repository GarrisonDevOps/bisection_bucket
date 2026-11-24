---
stage: Verify
group: tutorials
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: Google Cloud Run 구성 요소를 사용하여 웹 서비스 만들고 배포하기'
---

[Google Cloud Run 구성 요소](https://gitlab.com/google-gitlab-components/cloud-run)를 사용하여 Artifact Registry에 저장된 컨테이너 이미지에서 웹 서비스를 배포하는 방법을 알아봅니다.

## 시작하기 전에 {#before-you-begin}

1. [Google Cloud 통합 설정](../set_up_gitlab_google_integration/_index.md)의 지침을 따릅니다:

   - Google Cloud IAM을 설정합니다.
   - GitLab을 Google Artifact Registry에 연결합니다.
   - GitLab Runner를 설정하여 Google Cloud에서 CI/CD 작업을 실행합니다.

1. 이 페이지의 명령을 실행하려면 다음 개발 환경 중 하나에서 `gcloud` CLI를 설정합니다:

   - [Cloud Shell](https://docs.cloud.google.com/shell/docs/using-cloud-shell)
   - [로컬 셸](https://cloud.google.com/sdk/docs/install)

1. 다음 명령을 실행하여 기본 Google Cloud 프로젝트를 설정합니다:

   ```shell
   gcloud config set project PROJECT_ID
   ```

   기본 프로젝트를 설정한 후에는 `--project` 플래그를 `gcloud` 명령과 함께 전달할 필요가 없습니다.
1. Compute Engine 및 Cloud Run API를 활성화합니다:

   ```shell
   gcloud services enable compute.googleapis.com artifactregistry.googleapis.com run.googleapis.com
   ```

1. 워크로드 아이덴티티 풀에 다음 역할을 부여합니다:

   - Cloud Storage Admin (`roles/run.admin`) - 서비스를 가져오고, 만들고, 업데이트하기
   - Service Account 사용자 (`roles/iam.serviceAccountUser`) - 서비스 계정으로 작업 실행하기

   다음 명령을 실행하여 `roles/run.admin` 및 `roles/iam.serviceAccountUser` 역할을 `developer_access=true` 속성 매핑과 일치하는 워크로드 아이덴티티 풀의 모든 주체에 부여합니다:

   ```shell
   # Replace ${PROJECT_ID}, ${PROJECT_NUMBER}, ${LOCATION}, ${POOL_ID} with your values below
   WORKLOAD_IDENTITY=principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.developer_access/true
   gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="${WORKLOAD_IDENTITY}" --role="roles/run.admin"
   gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="${WORKLOAD_IDENTITY}" --role="roles/iam.serviceAccountUser"
   ```

## 새 GitLab 프로젝트에서 IAM 통합 구성 {#configure-the-iam-integration-in-a-new-gitlab-project}

조직 또는 그룹에 대한 통합을 위해 Google IAM을 설정한 후에는 해당 조직 또는 그룹의 새 프로젝트에서 통합을 재사용할 수 있습니다:

1. [새 GitLab 프로젝트 만들기](../../user/project/_index.md)를 조직 또는 그룹에서 수행합니다.
1. GitLab 프로젝트에서 **설정** > **연동**을 선택합니다.
1. **Google Cloud IAM**을 선택합니다.
1. **구글 클라우드 프로젝트** 섹션에서 다음을 입력합니다:

   - **프로젝트 ID**: 워크로드 아이덴티티 풀의 Google Cloud 프로젝트 ID
   - **프로젝트 번호**: 동일한 프로젝트의 Google Cloud 프로젝트 번호

   Google Cloud 프로젝트 ID 및 번호를 찾으려면 [프로젝트 식별](https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects)을 참조하세요.

1. **워크로드 아이덴티티 제휴** 섹션에서 다음을 입력합니다:

   - **풀 ID**: 워크로드 아이덴티티 풀에 지정한 이름
   - **공급자 ID**: OIDC 공급자에 지정한 이름

   힌트: 통합을 설정하기 위해 원래 사용한 GitLab 프로젝트에서 이 값들을 복사할 수 있습니다.

1. **변경 사항 저장**을 선택합니다. 워크로드 아이덴티티 풀을 생성하므로 제공된 스크립트를 실행하지 마세요. 이미 하나가 있습니다.

## 새 GitLab 프로젝트에서 Google Artifact Registry 통합 구성 {#configure-the-google-artifact-registry-integration-in-a-new-gitlab-project}

Artifact Registry에 여러 컨테이너 이미지를 저장할 수 있습니다. 새 GitLab 프로젝트에 대해 동일한 리포지토리를 재사용하려면 프로젝트에서 Google 아티팩트 관리 통합을 구성합니다.

1. GitLab 프로젝트에서 **설정** > **연동**을 선택합니다.
1. **Google 아티팩트 관리**를 선택합니다
1. **리포지토리** 섹션에서 다음을 입력합니다:

   - **Google Cloud 프로젝트 ID**: 사용하려는 Artifact Registry 리포지토리의 프로젝트 ID
   - **리포지토리 이름**: 리포지토리 이름
   - **리포지토리 위치**: 리포지토리의 위치

1. **변경 사항 저장**을 선택합니다. 워크로드 아이덴티티 풀이 이미 그룹 또는 조직의 GitLab 사용자에게 Artifact Registry 리더 및 쓰기 역할을 부여하므로 제공된 스크립트를 실행하지 마세요.

## GitLab 리포지토리 복제 {#clone-your-gitlab-repository}

SSH 또는 HTTPS를 사용하여 GitLab 리포지토리를 작업 환경으로 복제하려면 [Git 리포지토리를 로컬 컴퓨터에 복제](../../topics/git/clone.md) 지침을 따릅니다.

## Dockerfile 만들기 {#create-a-dockerfile}

1. 복제한 리포지토리에서 `Dockerfile`라는 새 파일을 만듭니다.
1. 다음을 `Dockerfile`에 복사하여 붙여넣습니다:

   ```dockerfile
   FROM python:3.12.4

   ARG name

   RUN mkdir web

   RUN cat <<EOF > web/index.html
   <!DOCTYPE html>
   <html>
       <head>
           <title>Home</title>
       </head>
       <body>
           <h1 color="green">Welcome to $name</h1>
       </body>
   </html>
   EOF

   CMD ["python3", "-m", "http.server", "8080", "-d", "web"]
   ```

1. `Dockerfile`을 Git에 추가하고, 커밋한 다음, GitLab 리포지토리에 푸시합니다:

   ```shell
   git add Dockerfile
   git commit -m "add dockerfile"
   git push
   ```

   사용자 이름과 [개인 액세스 토큰](../../user/profile/personal_access_tokens.md)을 입력하라는 메시지가 표시됩니다.

Dockerfile은 HTTP 웹 서비스를 생성합니다.

## 파이프라인 만들기 {#create-a-pipeline}

Docker 이미지를 빌드하고, GitLab 컨테이너 레지스트리에 푸시하고, 이미지를 Google Artifact Registry에 복사하고, Cloud Run을 사용하여 Google Cloud 인프라에 배포하는 파이프라인을 만듭니다.

1. GitLab 프로젝트에서 [`.gitlab-ci.yml` 파일](../../ci/quick_start/_index.md#create-a-gitlab-ciyml-file)을 만듭니다.
1. 이미지를 빌드하고, GitLab 컨테이너 레지스트리에 푸시하고, Google Artifact Registry에 복사하고, Cloud Run을 사용하여 배포하는 파이프라인을 만들려면 `.gitlab-ci.yml` 파일의 내용을 다음과 같이 수정합니다.

   다음 예제에서 다음을 바꿉니다:

   - `LOCATION`: Google Artifact Registry 리포지토리를 만든 Google Cloud 지역
   - `PROJECT`: Artifact Registry 리포지토리의 Google Cloud 프로젝트 ID
   - `REPOSITORY`: Google Artifact Registry 리포지토리의 리포지토리 ID

   ```yaml
   variables:
     IMAGE_TAG: v$CI_PIPELINE_ID
     AR_IMAGE: LOCATION-docker.pkg.dev/PROJECT/REPOSITORY/python-service

   stages:
     - build
     - push
     - deploy

   build-job:
     stage: build
     services:
       - docker:24.0.5-dind
     image: docker:git
     before_script:
       - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
     script:
       - docker build -t $CI_REGISTRY_IMAGE:$IMAGE_TAG --build-arg="name=Cloud Run" .
       - docker push $CI_REGISTRY_IMAGE:$IMAGE_TAG

   include:
     - component: gitlab.com/google-gitlab-components/artifact-registry/upload-artifact-registry@0.1.0
       inputs:
         stage: push
         source: $CI_REGISTRY_IMAGE:$IMAGE_TAG
         target: $AR_IMAGE:$IMAGE_TAG

     - component: gitlab.com/google-gitlab-components/cloud-run/deploy-cloud-run@0.1.0
       inputs:
         stage: deploy
         image: $AR_IMAGE:$IMAGE_TAG
         project_id: PROJECT
         region: LOCATION
         service: python-service

   ```

1. `.gitlab-ci.yml` 파일을 Git에 추가하고, 커밋한 다음, GitLab 리포지토리에 푸시합니다.

파이프라인은 다음을 완료합니다:

- `python-service` 이미지를 Docker-in-Docker로 빌드합니다.
- 이미지를 GitLab 컨테이너 레지스트리에 저장합니다.
- [Google Artifact Registry GitLab 구성 요소](https://gitlab.com/explore/catalog/google-gitlab-components/artifact-registry)를 사용하여 이미지를 Google Artifact Registry에 푸시합니다.
- `python-service`을 [Google Cloud Run 구성 요소](https://gitlab.com/google-gitlab-components/cloud-run)로 배포합니다.

## Google Cloud Run에서 서비스 보기 {#view-your-service-in-google-cloud-run}

1. Google Cloud 콘솔에서 [Cloud Run 페이지](https://console.cloud.google.com/run)로 이동합니다.
1. **서비스** 탭에서 만든 서비스를 선택합니다.

   서비스 **측정항목** 탭이 표시되며, 서비스 영역, URL 및 기타 세부 정보를 볼 수 있습니다.

## 서비스를 보기 위해 프록시 {#proxy-your-service-to-view}

서비스는 비공개이므로 인증 없이는 Google Cloud 콘솔에 나열된 URL에서 볼 수 없습니다. 서비스를 테스트하려면 `gcloud` CLI를 사용하여 인증하고 서비스를 `http://localhost:8080`로 프록시할 수 있습니다.

서비스를 로컬로 프록시하려면 다음 명령을 실행합니다:

```shell
gcloud run services proxy SERVICE \
    --project PROJECT_ID \
    --region=LOCATION
```

환영 페이지를 `http://localhost:8080`에서 볼 수 있습니다.

## 정리 {#clean-up}

이 페이지에서 사용한 리소스에 대해 Google Cloud 계정에 요금이 부과되는 것을 피하려면 Google Cloud 리소스 또는 전체 Google Cloud 프로젝트를 삭제할 수 있습니다.

워크로드 아이덴티티 풀이 포함된 프로젝트를 삭제하면 모든 설정 지침을 다시 따르지 않는 한 통합을 사용할 수 없습니다.

GitLab 및 Google 가격 책정과 프로젝트 관리에 대한 정보는 다음 리소스를 참조하세요:

- [GitLab 가격 책정](https://about.gitlab.com/free-trial/devsecops/)
- [Google 가격 책정](https://cloud.google.com/pricing)
- [GitLab 프로젝트 삭제](../../user/project/working_with_projects.md#delete-a-project)

### Google Artifact Registry 리포지토리 삭제 {#delete-your-google-artifact-registry-repository}

Google Artifact Registry 리포지토리를 삭제하려면 이 섹션의 단계를 따릅니다. 전체 Google Cloud 프로젝트를 삭제하려면 [프로젝트 삭제](#delete-your-google-cloud-project)의 단계를 따릅니다.

리포지토리를 제거하기 전에 보관하려는 모든 이미지를 다른 위치에서 사용할 수 있는지 확인합니다.

리포지토리를 삭제하려면 다음 명령을 실행합니다:

```shell
gcloud artifacts repositories delete REPOSITORY \
    --location=LOCATION
```

다음을 바꿉니다:

- `REPOSITORY`을 Google Artifact Registry 리포지토리 ID로 바꾸기
- `LOCATION`을 리포지토리의 위치로 바꾸기

### Cloud Run 서비스 삭제 {#delete-your-cloud-run-service}

1. Google Cloud 콘솔에서 [Cloud Run 페이지](https://console.cloud.google.com/run)로 이동합니다.
1. 서비스 옆의 확인란을 선택합니다.
1. **삭제**를 선택합니다.

### Google Cloud 프로젝트 삭제 {#delete-your-google-cloud-project}

**주의**: 프로젝트를 삭제하면 다음과 같은 영향이 있습니다:

- 프로젝트의 모든 항목이 삭제됩니다. 이 문서의 작업에 기존 프로젝트를 사용한 경우 삭제할 때 프로젝트에서 수행한 다른 모든 작업도 삭제됩니다.
- 사용자 지정 프로젝트 ID가 손실됩니다. 이 프로젝트를 만들 때 향후 사용하려는 사용자 지정 프로젝트 ID를 만들었을 수 있습니다. 프로젝트 ID를 사용하는 URL(예: appspot.com URL)을 보존하려면 전체 프로젝트를 삭제하는 대신 프로젝트 내의 선택된 리소스를 삭제합니다.

Google Cloud에서 여러 아키텍처, 자습서 또는 빠른 시작 자습서를 살펴보려는 경우 프로젝트를 재사용하면 프로젝트 할당량 제한을 초과하는 것을 피할 수 있습니다.

1. Google Cloud 콘솔에서 [**리소스 관리** 페이지](https://console.cloud.google.com/iam-admin/projects)로 이동합니다.
1. 프로젝트 목록에서 삭제하려는 프로젝트를 선택한 다음 **삭제**를 선택합니다.
1. 대화 상자에서 프로젝트 ID를 입력한 다음 **종료**를 선택하여 프로젝트를 삭제합니다.

## 관련 항목 {#related-topics}

- [Cloud Run에 대해 자세히 알아보기](https://docs.cloud.google.com/run/docs/overview/what-is-cloud-run).
