---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 클러스터 인증서로 Kubernetes 클러스터에 배포(더 이상 사용되지 않음)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 14.5에서 [더 이상 사용되지 않습니다](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8). 클러스터를 GitLab에 연결하려면 [GitLab Kubernetes 에이전트](../../clusters/agent/_index.md)를 사용하세요. 에이전트를 사용하여 배포하려면 [CI/CD 워크플로우](../../clusters/agent/ci_cd_workflow.md)를 사용하세요.

Kubernetes 클러스터는 배포 작업의 대상이 될 수 있습니다. 다음의 경우:

- 클러스터가 GitLab과 통합된 경우, 특수 [배포 변수](#deployment-variables)가 작업에 제공되며 구성이 필요하지 않습니다. `kubectl` 또는 `helm`와 같은 도구를 사용하여 작업에서 클러스터와 즉시 상호 작용하기 시작할 수 있습니다.
- GitLab 클러스터 통합을 사용하지 않는 경우에도 클러스터에 배포할 수 있습니다. 그러나 작업에서 클러스터와 상호 작용하기 전에 [CI/CD 변수](../../../ci/variables/_index.md#for-a-project)를 사용하여 Kubernetes 도구를 직접 구성해야 합니다.

## 배포 변수 {#deployment-variables}

배포 변수는 유효한 [배포 토큰](../deploy_tokens/_index.md)([`gitlab-deploy-token`](../deploy_tokens/_index.md#gitlab-deploy-token)이라고 함)이 필요하며, Kubernetes가 레지스트리에 액세스할 수 있도록 배포 작업 스크립트에 다음 명령이 필요합니다:

- Kubernetes 1.18+ 사용:

  ```shell
  kubectl create secret docker-registry gitlab-registry --docker-server="$CI_REGISTRY" --docker-username="$CI_DEPLOY_USER" --docker-password="$CI_DEPLOY_PASSWORD" --docker-email="$GITLAB_USER_EMAIL" -o yaml --dry-run=client | kubectl apply -f -
  ```

- Kubernetes <1.18 사용:

  ```shell
  kubectl create secret docker-registry gitlab-registry --docker-server="$CI_REGISTRY" --docker-username="$CI_DEPLOY_USER" --docker-password="$CI_DEPLOY_PASSWORD" --docker-email="$GITLAB_USER_EMAIL" -o yaml --dry-run | kubectl apply -f -
  ```

Kubernetes 클러스터 통합은 이러한 [배포 변수](../../../ci/variables/predefined_variables.md#deployment-variables)를 GitLab CI/CD 빌드 환경에서 배포 작업에 표시합니다. 배포 작업은 [대상 환경을 정의했습니다](../../../ci/environments/_index.md).

| 배포 변수        | 설명 |
|----------------------------|-------------|
| `KUBE_URL`                 | API URL과 같습니다. |
| `KUBE_TOKEN`               | [환경 서비스 계정](cluster_access.md)의 Kubernetes 토큰입니다. |
| `KUBE_NAMESPACE`           | 프로젝트의 배포 서비스 계정과 관련된 네임스페이스입니다. `<project_name>-<project_id>-<environment>` 형식입니다. GitLab 관리형 클러스터의 경우, 일치하는 네임스페이스가 GitLab에 의해 클러스터에 자동으로 생성됩니다. 클러스터가 GitLab 12.2 이전에 생성된 경우, 기본값 `KUBE_NAMESPACE`이(가) `<project_name>-<project_id>`(으)로 설정됩니다. |
| `KUBE_CA_PEM_FILE`         | PEM 데이터가 포함된 파일의 경로입니다. 사용자 정의 CA 번들이 지정된 경우에만 나타납니다. |
| `KUBE_CA_PEM`              | (더 이상 사용되지 않음) 원시 PEM 데이터입니다. 사용자 정의 CA 번들이 지정된 경우에만 해당합니다. |
| `KUBECONFIG`               | 이 배포를 위해 `kubeconfig`이(가) 포함된 파일의 경로입니다. CA 번들은 지정된 경우 포함됩니다. 이 구성은 또한 `KUBE_TOKEN`에서 정의된 동일한 토큰을 포함하므로 이 변수만 필요할 가능성이 높습니다. 이 변수명은 `kubectl`에 의해 자동으로 선택되므로 `kubectl`를 사용하는 경우 명시적으로 참조할 필요가 없습니다. |
| `KUBE_INGRESS_BASE_DOMAIN` | 이 변수는 클러스터당 도메인을 설정하는 데 사용할 수 있습니다. 자세한 내용은 [클러스터 도메인](gitlab_managed_clusters.md#base-domain)을 참조하세요. |

## 사용자 정의 네임스페이스 {#custom-namespace}

Kubernetes 통합은 배포 작업에 자동으로 생성된 네임스페이스가 포함된 `KUBECONFIG`을(를) 제공합니다. `<prefix>-<environment>` 형식의 프로젝트-환경 특정 네임스페이스를 사용하도록 기본 설정되며, `<prefix>`은(는) `<project_name>-<project_id>` 형식입니다. 자세한 내용은 [배포 변수](#deployment-variables)를 참조하세요.

배포 네임스페이스를 몇 가지 방식으로 사용자 정의할 수 있습니다:

- **[환경](../../../ci/environments/_index.md)별 네임스페이스** 또는 **프로젝트별 네임스페이스** 중에서 선택할 수 있습니다. 환경별 네임스페이스가 기본값이며 권장되는 설정입니다. 프로덕션과 비프로덕션 환경 간의 리소스 혼합을 방지합니다.
- 프로젝트 수준 클러스터를 사용할 때 네임스페이스 접두사를 추가로 사용자 정의할 수 있습니다. 네임스페이스별 환경을 사용할 때 배포 네임스페이스는 `<prefix>-<environment>`이지만 그 외의 경우에는 `<prefix>`입니다.
- **비관리형** 클러스터의 경우 자동으로 생성된 네임스페이스가 `KUBECONFIG`에 설정되지만 사용자가 그 존재를 확인할 책임이 있습니다. [`environment:kubernetes:namespace`](../../../ci/environments/configure_kubernetes_deployments.md)를 사용하여 `.gitlab-ci.yml`에서 이 값을 완전히 사용자 정의할 수 있습니다.

네임스페이스를 사용자 정의하면 기존 환경이 [클러스터 캐시를 지울](gitlab_managed_clusters.md#clearing-the-cluster-cache) 때까지 현재 네임스페이스에 연결된 상태로 유지됩니다.

### 자격 증명 보호 {#protecting-credentials}

기본적으로 배포 작업을 만들 수 있는 모든 사용자는 환경의 배포 작업에서 CI/CD 변수에 액세스할 수 있습니다. 여기에는 `KUBECONFIG`이(가) 포함되어 있으며, 이는 클러스터의 관련 서비스 계정에서 사용할 수 있는 모든 비밀에 액세스할 수 있습니다. 프로덕션 자격 증명을 안전하게 유지하려면 [보호 환경](../../../ci/environments/protected_environments.md)을(를) 사용하고 다음 중 하나와 함께 사용하는 것을 고려하세요:

- GitLab 관리형 클러스터 및 환경별 네임스페이스입니다.
- 보호 환경별 환경 범위 클러스터입니다. 동일한 클러스터를 제한된 여러 서비스 계정으로 여러 번 추가할 수 있습니다.

## Kubernetes 클러스터용 웹 터미널 {#web-terminals-for-kubernetes-clusters}

Kubernetes 통합은 [웹 터미널](../../../ci/environments/_index.md#web-terminals-deprecated) 지원을 [환경](../../../ci/environments/_index.md)에 추가합니다. 이는 Docker와 Kubernetes에서 발견되는 `exec` 기능을 기반으로 하므로 기존 컨테이너에서 새로운 셸 세션을 얻습니다. 이 통합을 사용하려면 이 페이지의 배포 변수를 사용하여 Kubernetes에 배포해야 하며, 모든 배포, 복제 집합 및 포드에 다음과 같은 주석이 있는지 확인합니다:

- `app.gitlab.com/env: $CI_ENVIRONMENT_SLUG`
- `app.gitlab.com/app: $CI_PROJECT_PATH_SLUG`

`$CI_ENVIRONMENT_SLUG` 및 `$CI_PROJECT_PATH_SLUG`은(는) CI/CD 변수의 값입니다.

터미널을 사용하려면 프로젝트 소유자이거나 `maintainer` 권한이 있어야 합니다. 지원은 환경의 첫 번째 포드의 첫 번째 컨테이너로 제한됩니다.

## 문제 해결 {#troubleshooting}

배포 작업이 시작되기 전에 GitLab은 배포 작업을 위해 특별히 다음을 만듭니다:

- 네임스페이스입니다.
- 서비스 계정입니다.

그러나 때로는 GitLab이 이를 만들 수 없습니다. 이러한 경우 작업이 다음 메시지로 실패할 수 있습니다:

```plaintext
This job failed because the necessary resources were not successfully created.
```

네임스페이스 및 서비스 계정을 만들 때 이 오류의 원인을 찾으려면 [로그](../../../administration/logs/_index.md#kuberneteslog-deprecated)를 확인하세요.

오류의 원인은 다음을 포함합니다:

- GitLab에 제공한 토큰에 GitLab에서 요구하는 [`cluster-admin`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles) 권한이 없습니다.
- `KUBECONFIG` 또는 `KUBE_TOKEN` 배포 변수가 없습니다. 작업에 전달되려면 일치하는 [`environment:name`](../../../ci/environments/_index.md)이(가) 있어야 합니다. 작업에 `environment:name`이(가) 설정되지 않은 경우 Kubernetes 자격 증명이 전달되지 않습니다.

> [!note]
> GitLab 12.0 이상 이전에 업그레이드된 프로젝트 수준 클러스터는 이 오류를 발생시키는 방식으로 구성될 수 있습니다. 네임스페이스 및 서비스 계정을 직접 관리하려면 [GitLab 관리형 클러스터](gitlab_managed_clusters.md) 옵션을 선택 해제했는지 확인하세요.
