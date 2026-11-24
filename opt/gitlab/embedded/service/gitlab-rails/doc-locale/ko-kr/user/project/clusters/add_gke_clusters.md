---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 클러스터 인증서를 통해 GKE 클러스터 연결(사용 중단됨)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 14.5에서 [사용 중지](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8)되었습니다. [OpenTofu 및 GitLab을 사용한 코드 기반 인프라](../../infrastructure/iac/_index.md)를 사용하세요. 선호하는 도구를 사용하여 자신만의 IaC 솔루션을 구현할 수도 있습니다.

GitLab을 통해 Google Kubernetes Engine(GKE)에서 호스팅되는 새로운 클러스터를 만들고 기존 클러스터를 연결할 수 있습니다.

## 기존 GKE 클러스터 연결 {#connect-an-existing-gke-cluster}

이미 GKE 클러스터가 있고 GitLab에 연결하려면 [Kubernetes용 GitLab 에이전트](../../clusters/agent/_index.md)를 사용하세요.

## GitLab에서 새 GKE 클러스터 만들기 {#create-a-new-gke-cluster-from-gitlab}

GitLab에서 프로비저닝한 모든 GKE 클러스터는 [VPC-기본](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/alias-ips)입니다.

GitLab에서 새 GKE 클러스터를 만들려면 [OpenTofu 및 GitLab을 사용한 코드 기반 인프라](../../infrastructure/iac/_index.md)를 사용하세요.

## 클러스터 인증서를 통해 GKE에서 새 클러스터 만들기 {#create-a-new-cluster-on-gke-through-cluster-certificates}

사전 요구 사항:

- 액세스 권한이 설정된 [Google Cloud 청구 계정](https://docs.cloud.google.com/billing/docs/how-to/manage-billing-account).
- Kubernetes Engine API 및 관련 서비스가 활성화되었습니다. 즉시 작동해야 하지만 프로젝트를 만든 후 최대 10분이 소요될 수 있습니다. 자세한 내용은 [Kubernetes Engine 문서의 "시작하기 전에" 섹션](https://cloud.google.com/kubernetes-engine/docs/deploy-app-cluster#before-you-begin)을 참조하세요.

다음을 참고하세요.

- [Google 인증 통합](../../../integration/google.md)은 인스턴스 수준에서 GitLab에서 활성화되어야 합니다. 그렇지 않은 경우 GitLab 관리자에게 활성화를 요청하세요. GitLab.com에서는 이 기능이 활성화되어 있습니다.
- GitLab에서 생성한 모든 GKE 클러스터는 RBAC가 활성화되어 있습니다. [RBAC 섹션](cluster_access.md#rbac-cluster-resources)을 참조하여 자세한 내용을 확인하세요.
- 클러스터의 Pod 주소 IP 범위는 일반적인 `/14` 대신 `/16`로 설정됩니다. `/16`은 CIDR 표기법입니다.
- GitLab은 클러스터에 대한 기본 인증이 활성화되고 [초기 서비스 계정](cluster_access.md)을 설정하기 위해 발급된 클라이언트 인증서가 필요합니다. [GitLab 11.10 이상](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/58208)에서 클러스터 생성 프로세스는 기본 인증이 활성화되고 클라이언트 인증서가 있는 클러스터를 만들도록 GKE에 명시적으로 요청합니다.

클러스터 인증서를 통해 프로젝트, 그룹 또는 인스턴스용 새로운 Kubernetes 클러스터를 만들려면:

1. 다음으로 이동합니다:
   - 프로젝트의 {{< icon name="cloud-gear" >}} **운영** > **Kubernetes 클러스터** 페이지(프로젝트 수준 클러스터).
   - 그룹의 {{< icon name="cloud-gear" >}} **Kubernetes** 페이지(그룹 수준 클러스터).
   - **운영자** 영역의 **Kubernetes** 페이지(인스턴스 수준 클러스터).
1. **클러스터 인증서와 통합**을 선택합니다.
1. **새 클러스터 만들기** 탭 아래에서 **Google GKE**를 선택하세요.
1. **Google로 로그인** 버튼을 선택하여 Google 계정에 아직 연결하지 않았다면 지금 연결하세요.
1. 클러스터 설정을 선택하세요:
   - **Kubernetes 클러스터 이름** \- 클러스터에 지정하려는 이름.
   - **환경 범위** \- 이 클러스터와 [관련된 환경](multiple_kubernetes_clusters.md#setting-the-environment-scope).
   - **Google Cloud Platform 프로젝트** \- GCP 콘솔에서 만든 프로젝트를 선택하여 Kubernetes 클러스터를 호스팅합니다. 자세한 내용은 [프로젝트 생성 및 관리](https://cloud.google.com/resource-manager/docs/creating-managing-projects)를 참조하세요.
   - **Zone** \- 클러스터를 만들 [영역](https://docs.cloud.google.com/compute/docs/regions-zones)을 선택하세요.
   - **노드 수** \- 클러스터에 원하는 노드 수를 입력하세요.
   - **머신 유형** \- 클러스터를 기반으로 할 가상 머신 인스턴스의 [머신 유형](https://docs.cloud.google.com/compute/docs/machine-resource).
   - **Anthos용 Cloud Run 활성화** \- 이 클러스터에 Anthos용 Cloud Run을 사용하려면 이 옵션을 선택하세요. 자세한 내용은 [Anthos용 Cloud Run 섹션](#cloud-run-for-anthos)을 참조하세요.
   - **GitLab-관리 클러스터** \- 이 클러스터의 네임스페이스 및 서비스 계정을 GitLab이 관리하도록 하려면 이 확인란을 선택된 상태로 유지합니다. 자세한 내용은 [관리되는 클러스터 섹션](gitlab_managed_clusters.md)을 참조하세요.
1. 마지막으로 **Kubernetes 클러스터 만들기** 버튼을 선택하세요.

몇 분 후에 클러스터가 준비됩니다.

### Anthos용 Cloud Run {#cloud-run-for-anthos}

클러스터를 생성한 후 Knative 및 Istio를 별도로 설치하는 대신 Anthos용 Cloud Run을 사용하도록 선택할 수 있습니다. 이는 Cloud Run(Knative), Istio 및 HTTP 로드 밸런싱이 처음부터 클러스터에서 활성화되며 설치하거나 제거할 수 없음을 의미합니다.
