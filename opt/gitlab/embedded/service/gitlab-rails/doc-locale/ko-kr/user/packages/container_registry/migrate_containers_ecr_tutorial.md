---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: '튜토리얼: Amazon ECR에서 GitLab으로 컨테이너 이미지 마이그레이션'
description: Amazon Elastic Container Registry에서 GitLab으로 컨테이너 이미지 대량 마이그레이션을 자동화하는 자습서입니다.
---

레지스트리 간에 컨테이너 이미지를 마이그레이션하는 작업은 수동으로 수행할 때 시간이 소요될 수 있습니다. 이 자습서에서는 CI/CD 파이프라인을 설정하여 Amazon Elastic Container Registry(ECR)에서 GitLab 컨테이너 레지스트리로 컨테이너 이미지의 대량 마이그레이션을 자동화하는 방법을 설명합니다.

ECR에서 컨테이너 이미지를 마이그레이션하려면:

1. [AWS 권한 구성](#configure-aws-permissions)
1. [UI에서 AWS 자격 증명을 변수로 추가](#add-aws-credentials-as-variables-in-the-ui)
1. [마이그레이션 파이프라인 생성](#create-the-migration-pipeline)
1. [마이그레이션 실행 및 검증](#run-and-verify-the-migration)

모든 것을 종합하면, `.gitlab-ci.yml`이 본 자습서의 끝에 제공되는 [샘플 구성](#example-gitlab-ciyml-configuration)과 유사해야 합니다.

## 시작하기 전에 {#before-you-begin}

다음이 필요합니다:

- GitLab 프로젝트에서 유지 관리자 또는 소유자 역할
- IAM 사용자를 생성할 수 있는 권한이 있는 AWS 계정에 대한 액세스 권한
- AWS 계정 ID
- ECR 리포지토리가 있는 AWS 리전
- GitLab 컨테이너 레지스트리에 충분한 저장 공간

## AWS 권한 구성 {#configure-aws-permissions}

AWS IAM에서 ECR에 대한 읽기 전용 액세스 권한이 있는 새로운 정책 및 사용자를 생성합니다:

1. AWS Management Console에서 IAM으로 이동합니다.
1. 새로운 정책을 생성합니다:

   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "ecr:GetAuthorizationToken",
                   "ecr:BatchCheckLayerAvailability",
                   "ecr:GetDownloadUrlForLayer",
                   "ecr:DescribeRepositories",
                   "ecr:ListImages",
                   "ecr:DescribeImages",
                   "ecr:BatchGetImage"
               ],
               "Resource": "*"
           }
       ]
   }
   ```

1. 새로운 IAM 사용자를 생성하고 정책을 첨부합니다.
1. IAM 사용자에 대한 액세스 키를 생성하고 저장합니다.

## UI에서 AWS 자격 증명을 변수로 추가 {#add-aws-credentials-as-variables-in-the-ui}

GitLab 프로젝트에서 필요한 AWS 자격 증명을 변수로 구성합니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **변수**를 펼칩니다.
1. **변수 추가**를 선택하고 다음을 추가합니다:
   - `AWS_ACCOUNT_ID`: AWS 계정 번호입니다.
   - `AWS_DEFAULT_REGION`: ECR 리전입니다. 예를 들어, `us-east-1`입니다.
   - `AWS_ACCESS_KEY_ID`: IAM 사용자의 액세스 키 ID입니다.
     - **변수 마스킹**을 선택합니다.
   - `AWS_SECRET_ACCESS_KEY`: IAM 사용자의 비밀 액세스 키입니다.
     - **변수 마스킹**을 선택합니다.

## 마이그레이션 파이프라인 생성 {#create-the-migration-pipeline}

다음 구성으로 리포지토리에 새로운 `.gitlab-ci.yml` 파일을 생성합니다:

### 이미지 및 서비스 설정 {#set-image-and-service}

Docker-in-Docker를 사용하여 컨테이너 작업을 처리합니다:

```yaml
image: docker:20.10
services:
  - docker:20.10-dind
```

### 파이프라인 변수 정의 {#define-pipeline-variables}

파이프라인에 필요한 변수를 설정합니다:

```yaml
variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: ""
  BULK_MIGRATE: "true"
```

### 마이그레이션 작업 구성 {#configure-the-migration-job}

전송을 처리하는 마이그레이션 작업을 생성합니다:

```yaml
migration:
  stage: deploy
  script:
    # Install required tools
    - apk add --no-cache aws-cli jq

    # Verify AWS credentials
    - aws sts get-caller-identity

    # Log in to registries
    - aws ecr get-login-password | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com
    - docker login -u ${CI_REGISTRY_USER} -p ${CI_REGISTRY_PASSWORD} ${CI_REGISTRY}

    # Get list of ECR repositories
    - REPOS=$(aws ecr describe-repositories --query 'repositories[*].repositoryName' --output text)

    # Process each repository
    - |
      for repo in $REPOS; do
        echo "Processing repository: $repo"

        # Get all tags for this repository
        TAGS=$(aws ecr describe-images --repository-name $repo --query 'imageDetails[*].imageTags[]' --output text)

        # Process each tag
        for tag in $TAGS; do
          echo "Processing tag: $tag"

          # Pull image from ECR
          docker pull ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${repo}:${tag}

          # Tag for GitLab registry
          docker tag ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${repo}:${tag} ${CI_REGISTRY_IMAGE}/${repo}:${tag}

          # Push to GitLab
          docker push ${CI_REGISTRY_IMAGE}/${repo}:${tag}
        done
      done
```

## 마이그레이션 실행 및 검증 {#run-and-verify-the-migration}

파이프라인을 설정한 후:

1. `.gitlab-ci.yml` 파일을 리포지토리에 커밋하고 푸시합니다.
1. **CI/CD** > **파이프라인**으로 이동하여 마이그레이션 진행 상황을 모니터링합니다.
1. 완료 후 마이그레이션을 검증합니다:
   - **패키지 및 레지스트리** > **컨테이너 레지스트리**로 이동합니다.
   - 모든 리포지토리 및 태그가 있는지 확인합니다.
   - 마이그레이션된 일부 이미지를 가져오기 테스트합니다.

## 예 `.gitlab-ci.yml` 구성 {#example-gitlab-ciyml-configuration}

이전의 모든 단계를 따르면, `.gitlab-ci.yml` 파일은 다음과 같이 표시됩니다:

```yaml
image: docker:20.10
services:
  - docker:20.10-dind

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: ""
  BULK_MIGRATE: "true"

migration:
  stage: deploy
  script:
    # Install required tools
    - apk add --no-cache aws-cli jq

    # Verify AWS credentials
    - aws sts get-caller-identity

    # Log in to registries
    - aws ecr get-login-password | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com
    - docker login -u ${CI_REGISTRY_USER} -p ${CI_REGISTRY_PASSWORD} ${CI_REGISTRY}

    # Get list of ECR repositories
    - REPOS=$(aws ecr describe-repositories --query 'repositories[*].repositoryName' --output text)

    # Process each repository
    - |
      for repo in $REPOS; do
        echo "Processing repository: $repo"

        # Get all tags for this repository
        TAGS=$(aws ecr describe-images --repository-name $repo --query 'imageDetails[*].imageTags[]' --output text)

        # Process each tag
        for tag in $TAGS; do
          echo "Processing tag: $tag"

          # Pull image from ECR
          docker pull ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${repo}:${tag}

          # Tag for GitLab registry
          docker tag ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${repo}:${tag} ${CI_REGISTRY_IMAGE}/${repo}:${tag}

          # Push to GitLab
          docker push ${CI_REGISTRY_IMAGE}/${repo}:${tag}
        done
      done
  rules:
    - if: $BULK_MIGRATE == "true"
```
