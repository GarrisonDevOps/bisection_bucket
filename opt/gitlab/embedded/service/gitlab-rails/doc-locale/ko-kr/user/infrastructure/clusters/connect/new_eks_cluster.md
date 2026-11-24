---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Amazon EKS 클러스터 생성
---

[코드 기반 인프라(IaC)](../../_index.md)를 통해 Amazon Elastic Kubernetes Service (EKS)에서 클러스터를 생성할 수 있습니다. 이 프로세스는 AWS 및 Kubernetes Terraform 공급자를 사용하여 EKS 클러스터를 생성합니다. Kubernetes용 GitLab 에이전트를 사용하여 클러스터를 GitLab에 연결합니다.

**시작하기 전에**:

- Amazon Web Services (AWS) 계정(구성된 [보안 자격 증명](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-prereqs.html) 포함).
- [러너](https://docs.gitlab.com/runner/install/) GitLab CI/CD 파이프라인을 실행할 수 있습니다.

**단계**:

1. [예제 프로젝트 가져오기](#import-the-example-project).
1. [Kubernetes용 에이전트 등록](#register-the-agent).
1. [프로젝트 구성](#configure-your-project).
1. [클러스터 프로비저닝](#provision-your-cluster).

## 예제 프로젝트 가져오기 {#import-the-example-project}

GitLab에서 코드 기반 인프라를 사용하여 클러스터를 생성하려면 클러스터를 관리할 프로젝트를 생성해야 합니다. 이 자습서에서는 샘플 프로젝트로 시작한 다음 필요에 따라 수정합니다.

[URL로 예제 프로젝트 가져오기](../../../import/third_party_systems/repo_by_url.md)를 시작합니다.

프로젝트를 가져오려면:

1. GitLab의 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
1. **내 모든 프로젝트 보기**를 선택합니다.
1. 페이지 오른쪽에서 **새 프로젝트**를 선택합니다.
1. **프로젝트 가져오기**를 선택합니다.
1. **리포지토리 URL**을 선택합니다.
1. **Git 리포지토리 URL**의 경우 `https://gitlab.com/gitlab-org/configure/examples/gitlab-terraform-eks.git`을 입력합니다.
1. 필드를 완료하고 **프로젝트 생성**을 선택합니다.

이 프로젝트는 다음을 제공합니다:

- Amazon [Virtual Private Cloud (VPC)](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-eks/-/blob/main/vpc.tf).
- Amazon [Elastic Kubernetes Service (EKS)](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-eks/-/blob/main/eks.tf) 클러스터.
- 클러스터에 설치된 [Kubernetes용 GitLab 에이전트](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-eks/-/blob/main/agent.tf).

## 에이전트 등록 {#register-the-agent}

{{< history >}}

- GitLab 14.9에서 [변경됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/81054). `certificate_based_clusters` 명의 [플래그](../../../../administration/feature_flags/_index.md)가 **조치** 메뉴를 인증서가 아닌 에이전트에 중점을 두도록 변경했습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

Kubernetes용 GitLab 에이전트를 생성하려면:

1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. **클러스터 연결 (에이전트)**를 선택합니다.
1. **에이전트 선택** 드롭다운 목록에서 `eks-agent`을(를) 선택한 다음 **에이전트 등록**을 선택합니다.
1. GitLab은 에이전트에 대한 등록 토큰을 생성합니다. 나중에 필요하므로 이 비밀 토큰을 안전하게 저장합니다.
1. GitLab은 에이전트 서버(KAS)에 대한 주소를 제공하며, 나중에 필요할 것입니다.

## AWS 자격 증명 설정 {#set-up-aws-credentials}

AWS를 GitLab으로 인증하려는 경우 AWS 자격 증명을 설정합니다.

1. [IAM 사용자](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html) 또는 [IAM 역할](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)을 생성합니다.
1. IAM 사용자 또는 역할에 프로젝트에 대한 적절한 권한이 있는지 확인합니다. 이 예제 프로젝트의 경우 다음 JSON 블록에 나열된 권한이 있어야 합니다. 자신의 프로젝트를 설정할 때 이러한 권한을 확장할 수 있습니다.

   ```json
   // IAM custom Policy definition
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "VisualEditor0",
         "Effect": "Allow",
         "Action": [
           "ec2:*",
           "eks:*",
           "elasticloadbalancing:*",
           "autoscaling:*",
           "cloudwatch:*",
           "logs:*",
           "kms:DescribeKey",
           "kms:TagResource",
           "kms:UntagResource",
           "kms:ListResourceTags",
           "kms:CreateKey",
           "kms:CreateAlias",
           "kms:ListAliases",
           "kms:DeleteAlias",
           "iam:AddRoleToInstanceProfile",
           "iam:AttachRolePolicy",
           "iam:CreateInstanceProfile",
           "iam:CreateRole",
           "iam:CreateServiceLinkedRole",
           "iam:GetRole",
           "iam:ListAttachedRolePolicies",
           "iam:ListRolePolicies",
           "iam:ListRoles",
           "iam:PassRole",
           "iam:DetachRolePolicy",
           "iam:ListInstanceProfilesForRole",
           "iam:DeleteRole",
           "iam:CreateOpenIDConnectProvider",
           "iam:CreatePolicy",
           "iam:TagOpenIDConnectProvider",
           "iam:GetPolicy",
           "iam:GetPolicyVersion",
           "iam:GetOpenIDConnectProvider",
           "iam:DeleteOpenIDConnectProvider",
           "iam:ListPolicyVersions",
           "iam:DeletePolicy"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

1. [사용자 또는 역할에 대한 액세스 키 생성](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html).
1. 액세스 키와 비밀을 저장합니다. AWS를 GitLab으로 인증하려면 이것들이 필요합니다.

## 프로젝트 구성 {#configure-your-project}

CI/CD 환경 변수를 사용하여 프로젝트를 구성합니다.

**필수 구성**:

1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **변수**를 펼칩니다.
1. 변수 `AWS_ACCESS_KEY_ID`을(를) AWS 액세스 키 ID로 설정합니다.
1. 변수 `AWS_SECRET_ACCESS_KEY`을(를) AWS 비밀 액세스 키로 설정합니다.
1. 변수 `TF_VAR_agent_token`을(를) 이전 작업에 표시된 에이전트 토큰으로 설정합니다.
1. 변수 `TF_VAR_kas_address`을(를) 이전 작업에 표시된 에이전트 서버 주소로 설정합니다.

**선택 사항 구성**:

[`variables.tf`](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-eks/-/blob/main/variables.tf) 파일은 필요에 따라 재정의할 수 있는 다른 변수를 포함합니다:

- `TF_VAR_region`: 클러스터의 지역을 설정합니다.
- `TF_VAR_cluster_name`: 클러스터의 이름을 설정합니다.
- `TF_VAR_cluster_version`: Kubernetes의 버전을 설정합니다.
- `TF_VAR_instance_type`: Kubernetes 노드의 인스턴스 유형을 설정합니다.
- `TF_VAR_instance_count`: Kubernetes 노드의 수를 설정합니다.
- `TF_VAR_agent_namespace`: Kubernetes용 GitLab 에이전트의 Kubernetes 네임스페이스를 설정합니다.

[AWS Terraform 공급자](https://registry.terraform.io/providers/hashicorp/aws/latest/docs) 및 [Kubernetes Terraform 공급자](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs) 설명서를 보고 추가 리소스 옵션을 확인합니다.

## 클러스터 프로비저닝 {#provision-your-cluster}

프로젝트를 구성한 후 클러스터의 프로비저닝을 수동으로 트리거합니다. GitLab에서:

1. 왼쪽 사이드바에서 **빌드** > **파이프라인**으로 이동합니다.
1. **재생** ({{< icon name="play" >}}) 옆에서 드롭다운 목록 아이콘({{< icon name="chevron-lg-down" >}})을 선택합니다.
1. 배포 작업을 수동으로 트리거하려면 **배포**를 선택합니다.

파이프라인이 성공적으로 완료되면 새 클러스터를 볼 수 있습니다:

- AWS에서: [EKS 콘솔](https://console.aws.amazon.com/eks/home)에서 **Amazon EKS** > **클러스터**를 선택합니다.
- GitLab에서: 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.

## 클러스터 사용 {#use-your-cluster}

클러스터를 프로비저닝한 후에는 GitLab에 연결되어 있고 배포할 준비가 되었습니다. 연결을 확인하려면:

1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. 목록에서 **연결 상태** 열을 확인합니다.

연결 기능에 대한 자세한 내용은 [Kubernetes용 GitLab 에이전트 설명서](../_index.md)를 참조하세요.

## 클러스터 제거 {#remove-the-cluster}

정리 작업은 기본적으로 파이프라인에 포함되지 않습니다. 생성된 모든 리소스를 제거하려면 정리 작업을 실행하기 전에 GitLab CI/CD 템플릿을 수정해야 합니다.

모든 리소스를 제거하려면:

1. `.gitlab-ci.yml` 파일에 다음을 추가합니다:

   ```yaml
   stages:
     - init
     - validate
     - test
     - build
     - deploy
     - cleanup

   destroy:
     extends: .terraform:destroy
     needs: []
   ```

1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택하고 가장 최근의 파이프라인을 선택합니다.
1. `destroy` 작업에서 **재생** ({{< icon name="play" >}})을 선택합니다.
