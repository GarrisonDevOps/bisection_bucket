---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 클러스터 인증서를 통해 기존 클러스터 연결(더 이상 사용 안 함)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 14.5에서 [사용 중지](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8)되었습니다. 클러스터를 GitLab에 연결하려면 대신 [Kubernetes용 GitLab 에이전트](../../clusters/agent/_index.md)를 사용하세요.

기존 Kubernetes 클러스터가 있는 경우 이를 프로젝트, 그룹 또는 인스턴스에 추가하고 GitLab과의 통합의 이점을 활용할 수 있습니다.

## 사전 요구 사항 {#prerequisites}

GitLab에 기존 클러스터를 추가하기 위한 필수 조건은 다음을 참조하세요.

### 모든 클러스터 {#all-clusters}

GitLab에 클러스터를 추가하려면 다음이 필요합니다:

- GitLab.com 또는 GitLab Self-Managed 인스턴스의 계정입니다.
- 그룹 수준 및 프로젝트 수준 클러스터에 대한 유지 관리자 역할입니다.
- 인스턴스 수준 클러스터의 경우 **운영자** 영역에 대한 액세스입니다.
- Kubernetes 클러스터입니다.
- `kubectl`을(를) 사용하여 클러스터에 대한 클러스터 관리 액세스입니다.

클러스터를 [EKS](#eks-clusters), [GKE](#gke-clusters), 온프레미스 또는 다른 공급자에서 호스팅할 수 있습니다. 온프레미스 및 다른 공급자에서 이들을 호스팅하려면 EKS 또는 GKE 방법 중 하나를 사용하여 안내를 받고 클러스터의 설정을 수동으로 입력하세요.

> [!warning]
> GitLab은 `arm64` 클러스터를 지원하지 않습니다. [`arm64` 클러스터에 Helm Tiller 설치 실패](https://gitlab.com/gitlab-org/gitlab/-/issues/29838) 이슈를 참조하세요.

### EKS 클러스터 {#eks-clusters}

기존 EKS 클러스터를 추가하려면 다음이 필요합니다:

- 작업자 노드가 올바르게 구성된 Amazon EKS 클러스터입니다.
- `kubectl` [설치 및 구성](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html#get-started-kubectl)(EKS 클러스터에 대한 액세스용)
- 계정의 토큰이 클러스터에 대한 관리자 권한을 갖는지 확인하세요.

### GKE 클러스터 {#gke-clusters}

기존 GKE 클러스터를 추가하려면 다음이 필요합니다:

- 클러스터 역할 바인딩을 생성하기 위한 `container.clusterRoleBindings.create` 권한입니다. [Google Cloud 설명서](https://cloud.google.com/iam/docs/granting-changing-revoking-access)를 따라 액세스 권한을 부여할 수 있습니다.

## 기존 클러스터를 추가하는 방법 {#how-to-add-an-existing-cluster}

<!-- (REVISE -  BREAK INTO SMALLER STEPS) -->

Kubernetes 클러스터를 프로젝트, 그룹 또는 인스턴스에 추가하려면:

1. 다음으로 이동합니다:
   1. 프로젝트의 {{< icon name="cloud-gear" >}} **운영** > **Kubernetes 클러스터** 페이지(프로젝트 수준 클러스터).
   1. 그룹의 {{< icon name="cloud-gear" >}} **Kubernetes** 페이지(그룹 수준 클러스터).
   1. **운영자** 영역의 **Kubernetes** 페이지(인스턴스 수준 클러스터).
1. **Kubernetes 클러스터** 페이지에서 **조치** 드롭다운 목록에서 **클러스터 연결** 옵션을 선택합니다.
1. **클러스터 연결** 페이지에서 세부 정보를 입력합니다:
   1. **Kubernetes 클러스터 이름**(필수) - 클러스터에 지정할 이름입니다.
   1. **환경 범위**(필수) - 이 클러스터에 [연결된 환경](multiple_kubernetes_clusters.md#setting-the-environment-scope)입니다.
   1. **API URL**(필수) - GitLab이 Kubernetes API에 액세스하는 데 사용하는 URL입니다. Kubernetes는 여러 API를 노출합니다. 모든 항목에 공통적인 "기본" URL을 사용하세요. 예를 들어 `https://kubernetes.example.com` 형식이 `https://kubernetes.example.com/api/v1`보다 좋습니다.

      다음 명령어를 실행하여 API URL을 가져옵니다:

      ```shell
      kubectl cluster-info | grep -E 'Kubernetes master|Kubernetes control plane' | awk '/http/ {print $NF}'
      ```

   1. **CA 인증서**(필수) - 클러스터에 인증하기 위해 유효한 Kubernetes 인증서가 필요합니다. 기본적으로 생성된 인증서를 사용하세요.
      1. `kubectl get secrets`을(를) 사용하여 시크릿을 나열하고 `default-token-xxxxx`과(와) 유사한 이름을 가진 것을 찾습니다. 해당 토큰 이름을 복사하여 아래에서 사용하세요.
      1. 다음 명령어를 실행하여 인증서를 가져옵니다:

         ```shell
         kubectl get secret <secret name> -o jsonpath="{['data']['ca\.crt']}" | base64 --decode
         ```

         명령어가 전체 인증서 체인을 반환하는 경우 체인 하단의 Root CA 인증서 및 모든 중간 인증서를 복사해야 합니다. 체인 파일의 구조는 다음과 같습니다:

         ```plaintext
            -----BEGIN MY CERTIFICATE-----
            -----END MY CERTIFICATE-----
            -----BEGIN INTERMEDIATE CERTIFICATE-----
            -----END INTERMEDIATE CERTIFICATE-----
            -----BEGIN INTERMEDIATE CERTIFICATE-----
            -----END INTERMEDIATE CERTIFICATE-----
            -----BEGIN ROOT CERTIFICATE-----
            -----END ROOT CERTIFICATE-----
         ```

   1. **토큰** \- GitLab은 특정 `namespace`으로 범위가 지정된 서비스 토큰을 사용하여 Kubernetes에 대해 인증합니다. 사용된 토큰은 [`cluster-admin`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles) 권한을 가진 서비스 계정에 속해야 합니다. 이 서비스 계정을 생성하려면:
      1. `gitlab-admin-service-account.yaml` 파일을 생성하고 다음 내용을 입력합니다:

         ```yaml
         apiVersion: v1
         kind: ServiceAccount
         metadata:
           name: gitlab
           namespace: kube-system
         ---
         apiVersion: rbac.authorization.k8s.io/v1
         kind: ClusterRoleBinding
         metadata:
           name: gitlab-admin
         roleRef:
           apiGroup: rbac.authorization.k8s.io
           kind: ClusterRole
           name: cluster-admin
         subjects:
           - kind: ServiceAccount
             name: gitlab
             namespace: kube-system
         ```

      1. 서비스 계정 및 클러스터 역할 바인딩을 클러스터에 적용합니다:

         ```shell
         kubectl apply -f gitlab-admin-service-account.yaml
         ```

         클러스터 수준 역할을 생성하기 위해 `container.clusterRoleBindings.create` 권한이 필요합니다. 이 권한이 없으면 대신 기본 인증을 활성화한 다음 `kubectl apply` 명령어를 관리자로 실행할 수 있습니다:

         ```shell
         kubectl apply -f gitlab-admin-service-account.yaml --username=admin --password=<password>
         ```

         > [!note]
         > 기본 인증을 켤 수 있으며 Google Cloud 콘솔을 사용하여 비밀번호 자격 증명을 가져올 수 있습니다.

         출력:

         ```shell
         serviceaccount "gitlab" created
         clusterrolebinding "gitlab-admin" created
         ```

      1. `gitlab` 서비스 계정의 토큰을 검색합니다:

         ```shell
         kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep gitlab | awk '{print $1}')
         ```

         출력에서 `<authentication_token>` 값을 복사합니다:

         ```plaintext
         Name:         gitlab-token-b5zv4
         Namespace:    kube-system
         Labels:       <none>
         Annotations:  kubernetes.io/service-account.name=gitlab
                      kubernetes.io/service-account.uid=bcfe66ac-39be-11e8-97e8-026dce96b6e8

         Type:  kubernetes.io/service-account-token

         Data
         ====
         ca.crt:     1025 bytes
         namespace:  11 bytes
         token:      <authentication_token>
         ```

   1. **GitLab-관리 클러스터** \- 이 클러스터의 네임스페이스 및 서비스 계정을 GitLab이 관리하도록 하려면 이 확인란을 선택된 상태로 유지합니다. 자세한 내용은 [관리되는 클러스터 섹션](gitlab_managed_clusters.md)을 참조하세요.
   1. **프로젝트 네임스페이스**(선택 사항) - 이 항목을 입력할 필요가 없습니다. 공백으로 두면 GitLab이 자동으로 생성합니다. 또한:
      - 각 프로젝트는 고유한 네임스페이스를 가져야 합니다.
      - 프로젝트 네임스페이스는 반드시 시크릿의 네임스페이스와 같을 필요는 없습니다. 예를 들어 `default`의 시크릿처럼 더 광범위한 권한을 가진 시크릿을 사용하는 경우입니다.
      - 프로젝트 네임스페이스로 `default`을(를) 사용하면 안 됩니다.
      - 프로젝트를 위해 특별히 생성된 시크릿이 있거나 일반적으로 제한된 권한을 가진 경우 시크릿의 네임스페이스와 프로젝트 네임스페이스가 같을 수 있습니다.

1. **Kubernetes 클러스터 추가** 버튼을 선택합니다.

약 10분 후 클러스터가 준비됩니다.

## 역할 기반 액세스 제어(RBAC) 비활성화(선택 사항) {#disable-role-based-access-control-rbac-optional}

GitLab 통합을 통해 클러스터를 연결할 때 클러스터가 RBAC를 사용할 수 있는지 여부를 지정할 수 있습니다. 이는 GitLab이 특정 작업에 대해 클러스터와 상호 작용하는 방식에 영향을 미칩니다. 생성 시 **RBAC-활성화된 클러스터** 확인란을 선택하지 않은 경우 GitLab은 클러스터와 상호 작용할 때 RBAC가 클러스터에 대해 비활성화된 것으로 간주합니다. 그렇다면 통합이 제대로 작동하려면 클러스터에서 RBAC를 비활성화해야 합니다.

![RBAC를 활성화하기 위한 GitLab Kubernetes 클러스터 통합 설정입니다.](img/rbac_v13_1.png)

> [!warning]
> RBAC를 비활성화하면 클러스터에서 실행되는 모든 애플리케이션이나 클러스터에 인증할 수 있는 사용자가 전체 API 액세스 권한을 갖습니다. 이는 [보안 문제](../../infrastructure/clusters/connect/_index.md#security-implications-for-clusters-connected-with-certificates)이며 바람직하지 않을 수 있습니다.

RBAC를 효과적으로 비활성화하려면 전체 액세스 권한을 부여하는 전역 권한을 적용할 수 있습니다:

```shell
kubectl create clusterrolebinding permissive-binding \
  --clusterrole=cluster-admin \
  --user=admin \
  --user=kubelet \
  --group=system:serviceaccounts
```

## 문제 해결 {#troubleshooting}

### 인증 중 CA 인증서 및 토큰 오류 {#ca-certificate-and-token-errors-during-authentication}

Kubernetes 클러스터를 연결할 때 이 오류가 발생하면:

```plaintext
There was a problem authenticating with your cluster.
Please ensure your CA Certificate and Token are valid
```

서비스 토큰을 올바르게 붙여넣었는지 확인하세요. 일부 셸은 서비스 토큰에 줄 바꿈을 추가하여 유효하지 않게 만들 수 있습니다. 토큰을 편집기에 붙여넣고 여분의 공백을 제거하여 줄 바꿈이 없는지 확인하세요.

인증서가 유효하지 않은 경우 이 오류가 발생할 수도 있습니다. 인증서의 주체 대체 이름에 클러스터의 API에 대한 올바른 도메인이 포함되어 있는지 확인하려면 다음 명령어를 실행합니다:

```shell
echo | openssl s_client -showcerts -connect kubernetes.example.com:443 -servername kubernetes.example.com 2>/dev/null |
openssl x509 -inform pem -noout -text
```

`-connect` 인수는 `host:port` 조합을 예상합니다. 예를 들어 `https://kubernetes.example.com`은 `kubernetes.example.com:443`가 됩니다. `-servername` 인수는 URI가 없는 도메인(예: `kubernetes.example.com`)을 예상합니다.
