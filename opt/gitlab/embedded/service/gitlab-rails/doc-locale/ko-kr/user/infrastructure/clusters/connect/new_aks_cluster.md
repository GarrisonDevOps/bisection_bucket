---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Azure AKS 클러스터 생성
---

[코드 기반 인프라(IaC)](../../_index.md)를 통해 Azure Kubernetes Service(AKS)에서 클러스터를 생성할 수 있습니다. 이 프로세스는 Azure 및 Kubernetes Terraform 제공자를 사용하여 AKS 클러스터를 생성합니다. Kubernetes용 GitLab 에이전트를 사용하여 클러스터를 GitLab에 연결합니다.

**시작하기 전에**:

- Microsoft Azure 계정(구성된 [보안 자격 증명](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli?view=azure-cli-latest) 포함).
- GitLab CI/CD 파이프라인을 실행하는 데 사용할 수 있는 [러너](https://docs.gitlab.com/runner/install/).

**단계**:

1. [예제 프로젝트 가져오기](#import-the-example-project).
1. [Kubernetes 에이전트 등록](#register-the-agent).
1. [프로젝트 구성](#configure-your-project).
1. [클러스터 프로비저닝](#provision-your-cluster).

## 예제 프로젝트 가져오기 {#import-the-example-project}

GitLab에서 코드 기반 인프라를 사용하여 클러스터를 생성하려면 클러스터를 관리할 프로젝트를 생성해야 합니다. 이 자습서에서는 샘플 프로젝트로 시작하여 필요에 따라 수정합니다.

[URL로 예제 프로젝트 가져오기](../../../import/third_party_systems/repo_by_url.md)로 시작합니다.

프로젝트를 가져오려면:

1. 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택하세요.
1. **프로젝트 가져오기**를 선택하세요.
1. **리포지토리 URL**을 선택합니다.
1. **Git 리포지토리 URL**에 대해 `https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-aks.git`을 입력합니다.
1. 필드를 완료하고 **프로젝트 생성**을 선택합니다.

이 프로젝트는 다음을 제공합니다:

- [Azure Kubernetes Service(AKS)](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-aks/-/blob/main/aks.tf) 클러스터.
- 클러스터에 설치된 [Kubernetes용 GitLab 에이전트](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-aks/-/blob/main/agent.tf).

## 에이전트 등록 {#register-the-agent}

Kubernetes용 GitLab 에이전트를 생성하려면:

1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. **클러스터 연결 (에이전트)**를 선택합니다.
1. **에이전트 선택** 드롭다운 목록에서 `aks-agent`를 선택하고 **에이전트 등록**을 선택합니다.
1. GitLab은 에이전트의 등록 토큰을 생성합니다. 나중에 필요하므로 이 보안 토큰을 안전하게 저장합니다.
1. GitLab은 에이전트 서버(KAS) 주소를 제공하며, 이를 나중에도 필요합니다.

## 프로젝트 구성 {#configure-your-project}

CI/CD 환경 변수를 사용하여 프로젝트를 구성합니다.

**필수 구성**:

1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **변수**를 펼칩니다.
1. 변수 `ARM_CLIENT_ID`을 Azure 클라이언트 ID로 설정합니다.
1. 변수 `ARM_CLIENT_SECRET`을 Azure 클라이언트 보안 정보로 설정합니다.
1. 변수 `ARM_TENANT_ID`을 서비스 주체로 설정합니다.
1. 변수 `TF_VAR_agent_token`을 이전 작업에 표시된 에이전트 토큰으로 설정합니다.
1. 변수 `TF_VAR_kas_address`을 이전 작업에 표시된 에이전트 서버 주소로 설정합니다.

**선택적 구성**:

[`variables.tf`](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-aks/-/blob/main/variables.tf) 파일에는 필요에 따라 재정의할 수 있는 다른 변수가 포함되어 있습니다:

- `TF_VAR_location`: 클러스터 영역을 설정합니다.
- `TF_VAR_cluster_name`: 클러스터 이름을 설정합니다.
- `TF_VAR_kubernetes_version`: Kubernetes 버전을 설정합니다.
- `TF_VAR_create_resource_group`: 새 리소스 그룹 생성을 활성화하거나 비활성화합니다. (기본값은 true로 설정됨).
- `TF_VAR_resource_group_name`: 리소스 그룹의 이름을 설정합니다.
- `TF_VAR_agent_namespace`: Kubernetes용 GitLab 에이전트의 Kubernetes 네임스페이스를 설정합니다.

[Azure Terraform 제공자](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs) 및 [Kubernetes Terraform 제공자](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs) 설명서를 참조하여 추가 리소스 옵션을 확인합니다.

## 클러스터 프로비저닝 {#provision-your-cluster}

프로젝트를 구성한 후 클러스터의 프로비저닝을 수동으로 트리거합니다. GitLab에서:

1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. **재생**({{< icon name="play" >}}) 옆에서 드롭다운 목록 아이콘({{< icon name="chevron-lg-down" >}})을 선택합니다.
1. 배포 작업을 수동으로 트리거하려면 **배포**를 선택합니다.

파이프라인이 성공적으로 완료되면 새 클러스터를 볼 수 있습니다:

- Azure에서: [Azure 포털](https://portal.azure.com/#home)에서 **Kubernetes 서비스** > **보기**를 선택합니다.
- GitLab에서: 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.

## 클러스터 사용 {#use-your-cluster}

클러스터를 프로비저닝한 후 GitLab에 연결되며 배포할 준비가 됩니다. 연결을 확인하려면:

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
1. `destroy` 작업에 대해 **재생**({{< icon name="play" >}})을 선택합니다.
