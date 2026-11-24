---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 관리형 클러스터(더 이상 사용되지 않음)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [GitLab Self-Managed에서 비활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/353410) (GitLab 15.0에서)

{{< /history >}}

> [!flag]
> GitLab Self-Managed에서 기본적으로 이 기능은 사용할 수 없습니다. 사용 가능하게 하려면 관리자가 `certificate_based_clusters`라는 [기능 플래그를 사용으로 설정](../../../administration/feature_flags/_index.md)할 수 있습니다.

GitLab이 클러스터를 관리하도록 허용할 수 있습니다. 클러스터가 GitLab에서 관리되면 프로젝트의 리소스가 자동으로 생성됩니다. 생성된 리소스에 대한 자세한 내용은 [액세스 제어](cluster_access.md) 섹션을 참조하세요.

> [!warning]
> 이 기능은 GitLab 14.5에서 [더 이상 사용되지 않습니다](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8). 클러스터를 GitLab에 연결하려면 [Kubernetes용 GitLab 에이전트](../../clusters/agent/_index.md)를 사용하세요. 애플리케이션을 관리하려면 [클러스터 프로젝트 관리 템플릿](../../clusters/management_project_template.md)을 사용하세요.

자신의 클러스터를 관리하기로 선택하면 프로젝트별 리소스가 자동으로 생성되지 않습니다. [Auto DevOps](../../../topics/autodevops/_index.md)를 사용 중인 경우 배포 작업이 사용할 `KUBE_NAMESPACE`[배포 변수](deploy_to_cluster.md#deployment-variables)를 명시적으로 제공해야 합니다. 그렇지 않으면 네임스페이스가 자동으로 생성됩니다.

> [!warning]
> GitLab이 생성한 리소스(예: 네임스페이스 및 서비스 계정)를 수동으로 관리하면 예상치 못한 오류가 발생할 수 있습니다. 이 경우 [클러스터 캐시 지우기](#clearing-the-cluster-cache)를 시도하세요.

## 클러스터 캐시 지우기 {#clearing-the-cluster-cache}

GitLab이 클러스터를 관리하도록 허용하면 GitLab은 프로젝트를 위해 생성한 네임스페이스 및 서비스 계정의 캐시된 버전을 저장합니다. 클러스터에서 이러한 리소스를 수동으로 수정하면 이 캐시가 클러스터와 동기화되지 않을 수 있습니다. 이로 인해 배포 작업이 실패할 수 있습니다.

캐시를 지우려면:

1. 프로젝트의 **운영** > **Kubernetes 클러스터** 페이지로 이동하여 클러스터를 선택합니다.
1. **고급 설정** 섹션을 확장합니다.
1. **클러스터 캐시 지우기**를 선택합니다.

## 기본 도메인 {#base-domain}

기본 도메인을 지정하면 `KUBE_INGRESS_BASE_DOMAIN`이 배포 변수로 자동으로 설정됩니다. [Auto DevOps](../../../topics/autodevops/_index.md)를 사용 중인 경우 이 도메인은 다양한 스테이지에 사용됩니다. 예를 들어 Auto Review Apps 및 Auto Deploy입니다.

도메인에는 Ingress IP 주소로 구성된 와일드카드 DNS가 있어야 합니다. 다음 중 하나를 수행할 수 있습니다.

- 도메인 제공자를 통해 Ingress IP 주소를 가리키는 `A` 레코드를 만듭니다.
- `nip.io` 또는 `xip.io`와 같은 서비스를 사용하여 와일드카드 DNS 주소를 입력합니다. 예를 들어, `192.168.1.1.xip.io`입니다.

외부 Ingress IP 주소 또는 외부 Ingress 호스트 이름을 확인하려면:

- 클러스터가 GKE에 있는 경우:
  1. **고급 설정**에서 **Google Kubernetes 엔진** 링크를 선택하거나 [Google Kubernetes 엔진 대시보드](https://console.cloud.google.com/kubernetes/)로 직접 이동합니다.
  1. 적절한 프로젝트와 클러스터를 선택합니다.
  1. **연결**을 선택합니다.
  1. 로컬 터미널에서 또는 **Cloud Shell**을 사용하여 `gcloud` 명령을 실행합니다.

- 클러스터가 GKE에 없는 경우: Kubernetes 제공자의 특정 지침에 따라 `kubectl`를 올바른 자격 증명으로 구성합니다. 다음 예의 출력은 클러스터의 외부 엔드포인트를 보여줍니다. 이 정보를 사용하여 배포된 애플리케이션에 대한 외부 액세스를 허용하는 DNS 항목 및 전달 규칙을 설정할 수 있습니다.

Ingress에 따라 외부 IP 주소는 다양한 방법으로 검색할 수 있습니다. 이 목록은 일반적인 솔루션과 일부 GitLab 특정 방법을 제공합니다:

- 일반적으로 다음을 실행하여 모든 로드 밸런서의 IP 주소를 나열할 수 있습니다:

  ```shell
  kubectl get svc --all-namespaces -o jsonpath='{range.items[?(@.status.loadBalancer.ingress)]}{.status.loadBalancer.ingress[*].ip} '
  ```

- **응용 프로그램**을 사용하여 Ingress를 설치한 경우 다음을 실행합니다:

  ```shell
  kubectl get service --namespace=gitlab-managed-apps ingress-nginx-ingress-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
  ```

- 일부 Kubernetes 클러스터는 [Amazon EKS](https://aws.amazon.com/eks/)와 같이 호스트 이름을 대신 반환합니다. 이러한 플랫폼의 경우 다음을 실행합니다:

  ```shell
  kubectl get service --namespace=gitlab-managed-apps ingress-nginx-ingress-controller -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
  ```

  EKS를 사용하는 경우 [Elastic Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/)도 생성되므로 추가 AWS 비용이 발생합니다.

- Istio/Knative는 다른 명령을 사용합니다. 실행합니다:

  ```shell
  kubectl get svc --namespace=istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip} '
  ```

일부 Kubernetes 버전에서 후행 `%`을 보는 경우 포함하지 마세요.
