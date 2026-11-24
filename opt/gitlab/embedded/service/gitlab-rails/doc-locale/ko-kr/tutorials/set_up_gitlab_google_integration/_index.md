---
stage: Verify
group: Tutorials
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: Google Cloud 연동 설정'
---

<!-- vale gitlab_base.FutureTense = NO -->

이 자습서는 Google Cloud와 GitLab을 연동하여 Google Cloud에 직접 배포할 수 있도록 하는 방법을 보여줍니다.

Google Cloud 연동을 설정하려면:

1. [Google Cloud Identity and Access Management (IAM)를 통한 사용 보안](#secure-your-usage-with-google-cloud-identity-and-access-management-iam)
1. [Google Artifact Registry 리포지토리에 연결](#connect-to-a-google-artifact-registry-repository)
1. [Google Cloud에서 CI/CD 작업을 실행하도록 GitLab Runner 설정](#set-up-gitlab-runner-to-execute-your-cicd-jobs-on-google-cloud)
1. [CI/CD 구성 요소를 사용하여 Google Cloud에 배포](#deploy-to-google-cloud-with-cicd-components)

## 시작하기 전에 {#before-you-begin}

통합을 설정하려면 다음을 수행해야 합니다.

- Maintainer 또는 Owner 역할이 있는 GitLab 프로젝트가 필요합니다.
- 사용할 Google Cloud 프로젝트에서 [Owner](https://cloud.google.com/iam/docs/understanding-roles#owner) IAM 역할이 필요합니다.
- [Google Cloud 프로젝트에 대해 결제가 활성화](https://cloud.google.com/billing/docs/how-to/verify-billing-enabled#confirm_billing_is_enabled_on_a_project)되어 있어야 합니다.
- Docker 형식 및 표준 모드의 Google Artifact Registry 리포지토리가 필요합니다.
- [Google Cloud CLI](https://cloud.google.com/sdk/docs/install)와 [Terraform](https://developer.hashicorp.com/terraform/install)을 설치합니다.

## Google Cloud Identity and Access Management (IAM)를 통한 사용 보안 {#secure-your-usage-with-google-cloud-identity-and-access-management-iam}

Google Cloud의 사용을 보안하려면 Google Cloud IAM 연동을 설정해야 합니다. 이 단계 후에는 GitLab 그룹 또는 프로젝트가 Google Cloud에 연결됩니다. 워크로드 ID 페더레이션을 사용하여 서비스 계정 키가 필요하지 않고 관련된 위험 없이 Google Cloud 리소스에 대한 권한을 처리할 수 있습니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹 또는 프로젝트를 찾습니다. 그룹에서 이를 구성하면 기본적으로 설정이 모든 프로젝트에 적용됩니다.
1. **설정** > **통합**을 선택합니다.
1. **Google Cloud IAM**을 선택합니다.
1. **Guided setup**을 선택하고 지침을 따릅니다.

## Google Artifact Registry 리포지토리에 연결 {#connect-to-a-google-artifact-registry-repository}

Google IAM 연동이 설정되었으므로 Google Artifact Registry 리포지토리에 연결할 수 있습니다. 이 단계 후에는 GitLab에서 Google Cloud 아티팩트를 볼 수 있습니다.

1. GitLab 프로젝트의 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Google Artifact Registry**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 확인란을 선택합니다.
1. 필드를 완성합니다:
   - **[Google Cloud 프로젝트 ID](https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects)**: Artifact Registry 리포지토리가 있는 Google Cloud 프로젝트의 ID입니다.
   - **리포지토리 이름**: Artifact Registry 리포지토리의 이름입니다.
   - **리포지토리 위치**: Artifact Registry 리포지토리의 위치입니다.
1. **Google Cloud IAM 정책 구성**에서 화면의 지침을 따라 Google Cloud의 IAM 정책을 설정합니다. 이러한 정책은 GitLab 프로젝트에서 Artifact Registry 리포지토리를 사용하는 데 필요합니다.
1. **변경 사항 저장**을 선택합니다.
1. Google Cloud 아티팩트를 보려면 왼쪽 사이드바에서 **배포** > **Google Artifact Registry**를 선택합니다.

나중에 컨테이너 이미지를 Google Artifact Registry로 푸시합니다.

## Google Cloud에서 CI/CD 작업을 실행하도록 GitLab Runner 설정 {#set-up-gitlab-runner-to-execute-your-cicd-jobs-on-google-cloud}

Google Cloud에서 CI/CD 작업을 실행하도록 GitLab Runner를 설정할 수 있습니다. 이 단계 후에는 GitLab 프로젝트가 자동 크기 조정 러너 플릿을 보유하며, 러너 관리자가 여러 작업을 동시에 실행하기 위한 임시 러너를 만듭니다.

1. GitLab 프로젝트의 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **러너** 섹션을 확장합니다.
1. **New project runner**를 선택합니다.
1. 필드를 완성합니다.
   - **플랫폼** 섹션에서 **Google Cloud**를 선택합니다.
   - **태그** 섹션의 **태그** 필드에 러너가 실행할 수 있는 작업을 지정하는 작업 태그를 입력합니다. 이 러너에 대한 작업 태그가 없으면 **Run untagged**를 선택합니다.
   - 선택사항. **러너 설명** 필드에서 GitLab에 표시되는 러너의 설명을 추가합니다.
   - 선택사항. **구성** 섹션에서 추가 구성을 추가합니다.
1. **러너 만들기**를 선택합니다.
1. **1단계의 필드를 완료합니다: 환경 지정** 섹션을 완료하여 러너가 CI/CD 작업을 실행하는 Google Cloud의 환경을 지정합니다.
1. **2단계에서: GitLab Runner 설정**에서 **설정 방법**을 선택합니다.
1. 모달의 지침을 따릅니다. Google Cloud 프로젝트에 대해 **1 단계**를 한 번만 수행하면 러너를 프로비전할 준비가 됩니다.

지침을 따른 후 러너가 온라인 상태가 되어 작업을 실행할 준비가 될 때까지 1분 정도 소요될 수 있습니다.

## CI/CD 구성 요소를 사용하여 Google Cloud에 배포 {#deploy-to-google-cloud-with-cicd-components}

개발의 모범 사례는 파이프라인 전반에 걸쳐 일관성을 유지하기 위해 CI/CD 구성 요소와 같은 구문을 재사용하는 것입니다.

GitLab 및 Google의 구성 요소 라이브러리를 사용하여 GitLab 프로젝트가 Google Cloud 리소스와 상호 작용하도록 할 수 있습니다. [Google의 CI/CD 구성 요소](https://gitlab.com/google-gitlab-components)를 참조하세요.

### Google Artifact Registry로 컨테이너 이미지 복사 {#copy-container-images-to-google-artifact-registry}

시작하기 전에 GitLab 컨테이너 레지스트리에 컨테이너 이미지를 빌드하고 푸시하는 작동 중인 CI/CD 구성이 있어야 합니다.

GitLab 컨테이너 레지스트리에서 Google Artifact Registry로 컨테이너 이미지를 복사하려면 파이프라인에 [Google의 CI/CD 구성 요소](https://gitlab.com/explore/catalog/google-gitlab-components/artifact-registry)를 포함합니다. 이 단계 후에는 새 컨테이너 이미지를 GitLab 컨테이너 레지스트리로 푸시할 때마다 Google Artifact Registry로도 푸시됩니다.

1. GitLab 프로젝트의 왼쪽 사이드바에서 **빌드** > **파이프라인 편집기**를 선택합니다.
1. 기존 구성에서 다음과 같이 구성 요소를 추가합니다.
   - `<your_stage>`을(를) 이 작업이 실행되는 스테이지로 바꿉니다. 이미지가 빌드되어 GitLab 컨테이너 레지스트리로 푸시된 후여야 합니다.

   ```yaml
   include:
     - component: gitlab.com/google-gitlab-components/artifact-registry/upload-artifact-registry@main
       inputs:
         stage: <your_stage>
         source: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
         target: $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/$CI_PROJECT_NAME:$CI_COMMIT_SHORT_SHA
   ```

1. 설명적인 커밋 메시지를 추가합니다. **타겟 브랜치**는 기본 브랜치여야 합니다.
1. **변경 사항 커밋**을 선택합니다.
1. **빌드** > **파이프라인**으로 이동하여 새 파이프라인이 실행되는지 확인합니다.
1. 파이프라인이 성공적으로 완료된 후 Google Artifact Registry로 복사된 컨테이너 이미지를 보려면 왼쪽 사이드바에서 **배포** > **Google Artifact Registry**를 선택합니다.

### Google Cloud Deploy 릴리스 생성 {#create-a-google-cloud-deploy-release}

파이프라인을 Google Cloud Deploy와 통합하려면 파이프라인에 [Google의 CI/CD 구성 요소](https://gitlab.com/explore/catalog/google-gitlab-components/cloud-deploy)를 포함합니다. 이 단계 후에는 파이프라인이 애플리케이션으로 Google Cloud Deploy 릴리스를 생성합니다.

1. GitLab 프로젝트의 왼쪽 사이드바에서 **빌드** > **파이프라인 편집기**를 선택합니다.
1. 기존 구성에서 [Google Cloud Deploy 구성 요소](https://gitlab.com/explore/catalog/google-gitlab-components/cloud-deploy)를 추가합니다.
1. 구성 요소 `inputs`을(를) 편집합니다.
1. 설명적인 커밋 메시지를 추가합니다. **타겟 브랜치**는 기본 브랜치여야 합니다.
1. **변경 사항 커밋**을 선택합니다.
1. **빌드** > **파이프라인**으로 이동하여 새 파이프라인이 통과하는지 확인합니다.
1. 파이프라인이 성공적으로 완료된 후 릴리스를 보려면 [Google Cloud 문서](https://docs.cloud.google.com/deploy/docs/view-release)를 참조하세요.

완료되었습니다! 이제 Google Cloud와 GitLab을 통합했으며, GitLab 프로젝트가 Google Cloud에 원활하게 배포됩니다.

## 관련 항목 {#related-topics}

- [Google Cloud IAM 연동](../../integration/google_cloud_iam.md)
- [Google Artifact Management 연동](../../user/project/integrations/google_artifact_management.md)
- [Google Cloud에서 러너 프로비전](../../ci/runners/provision_runners_google_cloud.md)
