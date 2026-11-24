---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 클러스터 인증서를 통한 EKS 클러스터 연결(deprecated)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 14.5에서 deprecated되었습니다. [코드 기반 인프라](../../infrastructure/iac/_index.md)를 사용하여 새 클러스터를 만듭니다.

GitLab을 통해 새 클러스터를 만들고 Amazon Elastic Kubernetes Service(EKS)에서 호스팅되는 기존 클러스터를 추가할 수 있습니다.

## 기존 EKS 클러스터 연결 {#connect-an-existing-eks-cluster}

이미 EKS 클러스터가 있고 이를 GitLab에 연결하려면 [GitLab agent for Kubernetes](../../clusters/agent/_index.md)를 사용하세요.

## 새 EKS 클러스터 생성 {#create-a-new-eks-cluster}

GitLab에서 새 클러스터를 만들려면 [코드 기반 인프라](../../infrastructure/iac/_index.md)를 사용하세요.

### 클러스터 인증서를 통해 EKS에서 새 클러스터를 만드는 방법(deprecated) {#how-to-create-a-new-cluster-on-eks-through-cluster-certificates-deprecated}

{{< history >}}

- GitLab 14.0에서 [deprecated](https://gitlab.com/gitlab-org/gitlab/-/issues/327908)되었습니다.

{{< /history >}}

사전 요구 사항:

- [Amazon Web Services](https://aws.amazon.com/) 계정이 있어야 합니다.
- IAM 리소스를 관리할 권한이 필요합니다.

인스턴스 수준 클러스터의 경우 [GitLab Self-Managed 인스턴스에 대한 추가 요구 사항](#additional-requirements-for-gitlab-self-managed-instances)을 참조하세요.

인증서 기반 방법을 통해 프로젝트, 그룹 또는 인스턴스에 대한 새 Kubernetes 클러스터를 만들려면 다음을 수행하세요:

1. [클러스터의 접근 제어(RBAC 또는 ABAC) 정의](cluster_access.md)
1. [GitLab에서 클러스터 만들기](#create-a-new-eks-cluster-in-gitlab)
1. [Amazon에서 클러스터 준비](#prepare-the-cluster-in-amazon)
1. [GitLab에서 클러스터 데이터 구성](#configure-your-clusters-data-in-gitlab)

추가 단계:

1. [기본 스토리지 클래스 만들기](#create-a-default-storage-class)
1. [앱을 EKS에 배포](#deploy-the-app-to-eks)

#### GitLab에서 새 EKS 클러스터 만들기 {#create-a-new-eks-cluster-in-gitlab}

클러스터 인증서를 통해 프로젝트, 그룹 또는 인스턴스에 대한 새 EKS 클러스터를 만들려면 다음을 수행하세요:

1. 다음으로 이동합니다:
   - 프로젝트의 **운영** > **Kubernetes 클러스터** 페이지(프로젝트 수준 클러스터의 경우).
   - 그룹의 **Kubernetes** 페이지(그룹 수준 클러스터의 경우).
   - **운영자** 영역의 **Kubernetes** 페이지(인스턴스 수준 클러스터).
1. **클러스터 인증서와 통합**을 선택합니다.
1. **새 클러스터 만들기** 탭에서 **Amazon EKS**를 선택하여 이후 단계에 필요한 `Account ID` 및 `External ID`를 표시합니다.
1. [IAM Management Console](https://console.aws.amazon.com/iam/home)에서 IAM 정책을 만듭니다:
   1. 왼쪽 패널에서 **정책**을 선택합니다.
   1. **정책 만들기**를 선택하여 새 창을 엽니다.
   1. **JSON** 탭을 선택하고 기존 콘텐츠 대신 다음 코드 조각을 붙여넣습니다. 이러한 권한은 GitLab에 리소스를 만들 수 있는 능력을 부여하지만 삭제할 수는 없습니다:

      ```json
      {
          "Version": "2012-10-17",
          "Statement": [
              {
                  "Effect": "Allow",
                  "Action": [
                      "autoscaling:CreateAutoScalingGroup",
                      "autoscaling:DescribeAutoScalingGroups",
                      "autoscaling:DescribeScalingActivities",
                      "autoscaling:UpdateAutoScalingGroup",
                      "autoscaling:CreateLaunchConfiguration",
                      "autoscaling:DescribeLaunchConfigurations",
                      "cloudformation:CreateStack",
                      "cloudformation:DescribeStacks",
                      "ec2:AuthorizeSecurityGroupEgress",
                      "ec2:AuthorizeSecurityGroupIngress",
                      "ec2:RevokeSecurityGroupEgress",
                      "ec2:RevokeSecurityGroupIngress",
                      "ec2:CreateSecurityGroup",
                      "ec2:createTags",
                      "ec2:DescribeImages",
                      "ec2:DescribeKeyPairs",
                      "ec2:DescribeRegions",
                      "ec2:DescribeSecurityGroups",
                      "ec2:DescribeSubnets",
                      "ec2:DescribeVpcs",
                      "eks:CreateCluster",
                      "eks:DescribeCluster",
                      "iam:AddRoleToInstanceProfile",
                      "iam:AttachRolePolicy",
                      "iam:CreateRole",
                      "iam:CreateInstanceProfile",
                      "iam:CreateServiceLinkedRole",
                      "iam:GetRole",
                      "iam:listAttachedRolePolicies",
                      "iam:ListRoles",
                      "iam:PassRole",
                      "ssm:GetParameters"
                  ],
                  "Resource": "*"
              }
          ]
      }
      ```

      이 프로세스 중에 오류가 발생하면 GitLab은 변경 사항을 롤백하지 않습니다. 리소스를 수동으로 제거해야 합니다. 관련 [CloudFormation 스택](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-delete-stack.html)을 삭제하여 수행할 수 있습니다.

   1. **정책 검토**를 선택합니다.
   1. 이 정책에 적합한 이름을 입력하고 **정책 만들기**를 선택합니다. 이제 이 창을 닫을 수 있습니다.

### Amazon에서 클러스터 준비 {#prepare-the-cluster-in-amazon}

1. 클러스터에 대해 [**EKS IAM 역할** 만들기](#create-an-eks-iam-role-for-your-cluster)(**역할 A**).
1. GitLab과의 Amazon 인증을 위해 [**다른 EKS IAM 역할** 만들기](#create-another-eks-iam-role-for-gitlab-authentication-with-amazon)(**역할 B**).

#### 클러스터에 대한 EKS IAM 역할 만들기 {#create-an-eks-iam-role-for-your-cluster}

[IAM Management Console](https://console.aws.amazon.com/iam/home)에서 **EKS IAM 역할**(**역할 A**)을 만들고 [Amazon EKS 클러스터 IAM 역할 지침](https://docs.aws.amazon.com/eks/latest/userguide/cluster-iam-role.html)을 따릅니다. 이 역할은 Amazon EKS에서 관리하는 Kubernetes 클러스터가 서비스에서 사용하는 리소스를 관리하기 위해 대신해서 다른 AWS 서비스에 호출을 할 수 있도록 하기 위해 필요합니다.

GitLab이 EKS 클러스터를 올바르게 관리하려면 가이드에서 제안하는 정책 외에 `AmazonEKSClusterPolicy`를 포함해야 합니다.

#### Amazon과의 GitLab 인증을 위한 다른 EKS IAM 역할 만들기 {#create-another-eks-iam-role-for-gitlab-authentication-with-amazon}

[IAM Management Console](https://console.aws.amazon.com/iam/home)에서 AWS를 사용한 GitLab 인증을 위한 다른 IAM 역할(**역할 B**)을 만듭니다:

1. AWS IAM 콘솔에서 왼쪽 패널의 **역할**을 선택합니다.
1. **역할 생성**을 선택합니다.
1. **신뢰할 수 있는 엔터티 유형 선택**에서 **다른 AWS 계정**을 선택합니다.
1. GitLab의 계정 ID를 **계정 ID** 필드에 입력합니다.
1. **외부 ID 필수**를 확인합니다.
1. GitLab의 외부 ID를 **외부 ID** 필드에 입력합니다.
1. **다음: 권한**을 선택하고 방금 만든 정책을 선택합니다.
1. **다음: 태그**를 선택하고 이 역할과 연관시킬 태그를 선택적으로 입력합니다.
1. **다음: 검토**.
1. 역할 이름과 선택적 설명을 제공된 필드에 입력합니다.
1. **역할 생성**을 선택합니다. 새 역할 이름이 맨 위에 표시됩니다. 이름을 선택하고 새로 만든 역할에서 `Role ARN`를 복사합니다.

### GitLab에서 클러스터 데이터 구성 {#configure-your-clusters-data-in-gitlab}

1. GitLab으로 돌아가 복사한 역할 ARN을 **역할 ARN** 필드에 입력합니다.
1. **클러스터 리전** 필드에 새 클러스터에 사용할 계획인 [리전](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html)을 입력합니다. GitLab은 역할을 인증할 때 이 리전에 대한 액세스 권한이 있음을 확인합니다.
1. **AWS로 인증**을 선택합니다.
1. [클러스터 설정](#cluster-settings)을 조정합니다.
1. **Kubernetes 클러스터 만들기** 버튼을 선택합니다.

약 10분 후 클러스터를 사용할 준비가 됩니다.

> [!note]
> [설치 및 구성](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html#get-started-kubectl)한 `kubectl`이 있고 이를 사용하여 클러스터를 관리하려면 AWS 설정에서 AWS 외부 ID를 추가해야 합니다. AWS CLI를 구성하는 방법에 대한 자세한 내용은 [AWS CLI에서 IAM 역할 사용](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-configure-role-xaccount)을 참조하세요.

#### 클러스터 설정 {#cluster-settings}

새 클러스터를 만들 때 다음 설정이 있습니다:

| 설정                 | 설명 |
| ----------------------- |------------ |
| Kubernetes 클러스터 이름 | 클러스터의 이름입니다. |
| 환경 범위       | [연관된 환경](multiple_kubernetes_clusters.md#setting-the-environment-scope)입니다. |
| 서비스 역할            | **EKS IAM 역할**(**역할 A**)입니다. |
| Kubernetes 버전      | 클러스터의 [Kubernetes 버전](../../clusters/agent/_index.md#supported-kubernetes-versions-for-gitlab-features)입니다. |
| 키 페어 이름           | 작업자 노드에 연결하는 데 사용할 수 있는 [키 페어](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html)입니다. |
| VPC                     | EKS 클러스터 리소스에 사용할 [VPC](https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html)입니다. |
| 서브넷                 | 작업자 노드가 실행되는 VPC의 [서브넷](https://docs.aws.amazon.com/vpc/latest/userguide/configure-subnets.html)입니다. 두 개가 필요합니다. |
| 보안 그룹          | 작업자 노드 서브넷에서 생성되는 EKS 관리형 탄력적 네트워크 인터페이스에 적용할 [보안 그룹](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html)입니다. |
| 인스턴스 유형           | 작업자 노드의 [인스턴스 유형](https://aws.amazon.com/ec2/instance-types/)입니다. |
| 노드 개수              | 작업자 노드의 수입니다. |
| GitLab 관리 클러스터  | GitLab이 이 클러스터에 대한 네임스페이스와 서비스 계정을 관리하도록 하려면 확인합니다. |

## 기본 스토리지 클래스 만들기 {#create-a-default-storage-class}

Amazon EKS는 기본 스토리지 클래스가 기본 제공되지 않으므로 영구 볼륨에 대한 요청이 자동으로 충족되지 않습니다. Auto DevOps의 일부로서 배포된 PostgreSQL 인스턴스는 영구 스토리지를 요청하며 기본 스토리지 클래스가 없으면 시작할 수 없습니다.

기본 스토리지 클래스가 아직 없으면 만들려면 [스토리지 클래스](https://docs.aws.amazon.com/eks/latest/userguide/storage.html#storage-classes)를 참조하세요.

또는 프로젝트 변수 [`POSTGRES_ENABLED`](../../../topics/autodevops/cicd_variables.md)를 `false`로 설정하여 PostgreSQL을 비활성화합니다.

## 앱을 EKS에 배포 {#deploy-the-app-to-eks}

RBAC를 비활성화하고 서비스를 배포한 상태에서 [Auto DevOps](../../../topics/autodevops/_index.md)를 활용하여 앱을 빌드, 테스트 및 배포할 수 있습니다.

아직 활성화되지 않은 경우 [Auto DevOps 활성화](../../../topics/autodevops/_index.md#per-project)합니다. 와일드카드 DNS 항목이 생성되어 로드 밸런서로 확인된 경우 Auto DevOps 설정 아래의 `domain` 필드에 입력합니다. 그렇지 않으면 배포된 앱이 클러스터 외부에서 외부적으로 사용할 수 없습니다.

![EKS에 애플리케이션을 배포하는 파이프라인입니다.](img/pipeline_v11_0.png)

GitLab은 새 파이프라인을 만들고, 이는 앱을 빌드, 테스트 및 배포하기 시작합니다.

파이프라인이 완료된 후 앱이 EKS에서 실행되고 사용자가 사용할 수 있습니다. **운영** > **환경**을 선택합니다.

![배포된 환경 상태 및 액세스 옵션입니다.](img/environment_v11_0.png)

GitLab은 환경 목록 및 배포 상태와 앱을 검색하고, 모니터링 메트릭을 보고, 실행 중인 Pod에서 셸에 액세스할 수 있는 옵션을 표시합니다.

## GitLab Self-Managed 인스턴스에 대한 추가 요구 사항 {#additional-requirements-for-gitlab-self-managed-instances}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Self-Managed를 사용 중인 경우 Amazon 자격증명을 구성해야 합니다. GitLab은 이러한 자격증명을 사용하여 Amazon IAM 역할을 맡아 클러스터를 만듭니다.

IAM 사용자를 만들고 사용자가 EKS 클러스터를 만드는 데 필요한 역할을 맡을 수 있는 권한이 있는지 확인합니다.

예를 들어 다음 정책 문서는 `gitlab-eks-`로 시작하는 이름의 역할을 맡을 수 있도록 허용하며 `123456789012` 계정에 있습니다:

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::123456789012:role/gitlab-eks-*"
  }
}
```

### Amazon 인증 구성 {#configure-amazon-authentication}

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.

GitLab에서 Amazon 인증을 구성하려면 Amazon AWS 콘솔에서 IAM 사용자에 대한 액세스 키를 생성하고 다음 단계를 따릅니다:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **Amazon EKS**를 확장합니다.
1. **Amazon EKS 통합 활성화**를 확인합니다.
1. **계정 ID**를 입력합니다.
1. [액세스 키 및 ID](#eks-access-key-and-id)를 입력합니다.
1. **변경 사항 저장**을 선택합니다.

#### EKS 액세스 키 및 ID {#eks-access-key-and-id}

인스턴스 프로필을 사용하여 필요할 때 AWS에서 임시 자격증명을 동적으로 검색할 수 있습니다. 이 경우 `Access key ID` 및 `Secret access key` 필드를 비워 두고 [EC2 인스턴스에 IAM 역할 전달](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html)합니다.

그렇지 않으면 액세스 키 자격증명을 **액세스 키 ID** 및 **시크릿 액세스 키**에 입력합니다.

## 문제 해결 {#troubleshooting}

새 클러스터를 만들 때 일반적으로 발생하는 오류는 다음과 같습니다.

### 유효성 검사 실패: 역할 ARN은 유효한 Amazon 리소스 이름이어야 합니다 {#validation-failed-role-arn-must-be-a-valid-amazon-resource-name}

`Provision Role ARN`이 올바른지 확인합니다. 유효한 ARN의 예:

```plaintext
arn:aws:iam::123456789012:role/gitlab-eks-provision'
```

### 접근 거부됨: 사용자는 `sts:AssumeRole`를 `arn:aws:iam::y` 리소스에서 수행할 권한이 없습니다 {#access-denied-user-is-not-authorized-to-perform-stsassumerole-on-resource-arnawsiamy}

이 오류는 [Amazon 인증 구성](#configure-amazon-authentication)에 정의된 자격증명이 Provision Role ARN에서 정의된 역할을 맡을 수 없을 때 발생합니다:

```plaintext
User `arn:aws:iam::x` is not authorized to perform: `sts:AssumeRole` on resource: `arn:aws:iam::y`
```

다음을 확인합니다:

1. 초기 AWS 자격증명 집합에 [AssumeRole 정책이 있습니다](#additional-requirements-for-gitlab-self-managed-instances).
1. Provision Role은 주어진 리전에서 클러스터를 만들 수 있는 액세스 권한이 있습니다.
1. 계정 ID 및 [외부 ID](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html)가 AWS의 **신뢰 관계** 탭에 정의된 값과 일치합니다:

   ![EKS 클러스터 생성에 사용되는 AWS IAM 역할에 대한 신뢰 관계 설정입니다.](img/aws_iam_role_trust_v13_7.png)

### 이 VPC에 대한 보안 그룹을 로드할 수 없습니다 {#could-not-load-security-groups-for-this-vpc}

구성 양식에서 옵션을 채울 때 GitLab은 GitLab이 제공된 역할을 성공적으로 맡았지만 역할에 양식에 필요한 리소스를 검색할 권한이 부족하기 때문에 이 오류를 반환합니다. 역할에 올바른 권한을 할당했는지 확인합니다.

### 키 페어가 로드되지 않음 {#key-pairs-are-not-loaded}

GitLab은 지정된 **클러스터 리전**에서 키 페어를 로드합니다. 키 페어가 해당 리전에 있는지 확인합니다.

#### `ROLLBACK_FAILED` 클러스터 생성 중 {#rollback_failed-during-cluster-creation}

생성 프로세스가 중단되었습니다. GitLab이 하나 이상의 리소스를 만들 때 오류가 발생했기 때문입니다. 연결된 [CloudFormation 스택](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-view-stack-data-resources.html)을 검사하여 생성에 실패한 특정 리소스를 찾을 수 있습니다.

`Cluster` 리소스가 오류 `The provided role doesn't have the Amazon EKS Managed Policies associated with it.`로 인해 실패한 경우 **역할 이름**에 지정된 역할이 올바르게 구성되지 않았습니다.

> [!note]
> 이 역할은 [EKS 클러스터 IAM 역할](https://docs.aws.amazon.com/eks/latest/userguide/cluster-iam-role.html) 가이드에 따라 만든 역할이어야 합니다. 가이드에서 제안하는 정책 외에도 GitLab이 EKS 클러스터를 올바르게 관리하기 위해 이 역할에 `AmazonEKSClusterPolicy` 정책을 포함해야 합니다.
