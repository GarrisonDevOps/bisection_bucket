---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 그룹 수준 Kubernetes 클러스터(인증서 기반) (지원 중단됨)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 14.5에서 [지원 중단되었습니다](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8). 클러스터를 GitLab에 연결하려면 [GitLab Kubernetes 에이전트](../../clusters/agent/_index.md)를 사용하세요.

[프로젝트 수준](../../project/clusters/_index.md)의 Kubernetes 클러스터 및 [인스턴스 수준](../../instance/clusters/_index.md)의 Kubernetes 클러스터와 유사하게, 그룹 수준 Kubernetes 클러스터를 사용하면 Kubernetes 클러스터를 그룹에 연결하여 여러 프로젝트에서 동일한 클러스터를 사용할 수 있습니다.

그룹 수준 Kubernetes 클러스터를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **Kubernetes**를 선택하세요.

## 클러스터 관리 프로젝트 {#cluster-management-project}

[클러스터 관리 프로젝트](../../clusters/management_project.md)를 클러스터에 연결하여 Ingress 컨트롤러와 같은 설치를 위해 `cluster-admin` 권한이 필요한 공유 리소스를 관리하세요.

## RBAC 호환성 {#rbac-compatibility}

Kubernetes 클러스터가 있는 그룹의 각 프로젝트에 대해 GitLab은 프로젝트 네임스페이스에 [`edit` 권한](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)이 있는 제한된 서비스 계정을 생성합니다.

## 클러스터 우선 순위 {#cluster-precedence}

프로젝트의 클러스터를 사용할 수 있고 비활성화되지 않은 경우 GitLab은 프로젝트를 포함하는 그룹에 속한 모든 클러스터를 사용하기 전에 프로젝트의 클러스터를 사용합니다. 하위 그룹의 경우 GitLab은 클러스터가 비활성화되지 않은 경우 프로젝트에서 가장 가까운 상위 그룹의 클러스터를 사용합니다.

## 여러 Kubernetes 클러스터 {#multiple-kubernetes-clusters}

그룹에 둘 이상의 Kubernetes 클러스터를 연결할 수 있으며, 개발, 스테이징, 프로덕션 등 다양한 환경을 위해 다양한 클러스터를 유지할 수 있습니다.

다른 클러스터를 추가할 때 [환경 범위를 설정](#environment-scopes)하여 새 클러스터를 다른 클러스터와 구별하는 데 도움을 줍니다.

## GitLab 관리 클러스터 {#gitlab-managed-clusters}

GitLab이 클러스터를 관리하도록 허용할 수 있습니다. GitLab이 클러스터를 관리하면 프로젝트에 대한 리소스가 자동으로 생성됩니다. [액세스 제어](../../project/clusters/cluster_access.md) 섹션을 확인하여 GitLab이 생성하는 리소스에 대한 자세한 내용을 알아보세요.

GitLab에서 관리하지 않는 클러스터의 경우 프로젝트별 리소스가 자동으로 생성되지 않습니다. GitLab에서 관리하지 않는 클러스터를 배포에 사용하는 [Auto DevOps](../../../topics/autodevops/_index.md)를 사용하는 경우 다음을 확인해야 합니다:

- 프로젝트의 배포 서비스 계정에 [`KUBE_NAMESPACE`](../../project/clusters/deploy_to_cluster.md#deployment-variables)에 배포할 수 있는 권한이 있습니다.
- `KUBECONFIG`이 `KUBE_NAMESPACE`의 변경 사항을 올바르게 반영합니다 (이것은 [자동이 아닙니다](https://gitlab.com/gitlab-org/gitlab/-/issues/31519)). `KUBE_NAMESPACE`을 직접 편집하는 것은 권장되지 않습니다.

### 클러스터 캐시 지우기 {#clearing-the-cluster-cache}

GitLab이 클러스터를 관리하도록 허용하면 GitLab은 프로젝트에 대해 생성하는 네임스페이스 및 서비스 계정의 캐시된 버전을 저장합니다. 클러스터에서 이러한 리소스를 수동으로 수정하면 이 캐시가 클러스터와 동기화되지 않을 수 있으며, 이로 인해 배포 작업이 실패할 수 있습니다.

캐시를 지우려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **Kubernetes**를 선택하세요.
1. 클러스터를 선택하세요.
1. **고급 설정**을 확장하세요.
1. **클러스터 캐시 지우기**를 선택하세요.

## 기본 도메인 {#base-domain}

클러스터 수준의 도메인은 [여러 Kubernetes 클러스터](#multiple-kubernetes-clusters)당 여러 도메인을 지원할 수 있습니다. 도메인을 지정할 때 [Auto DevOps](../../../topics/autodevops/_index.md) 단계 중에 환경 변수 (`KUBE_INGRESS_BASE_DOMAIN`)로 자동으로 설정됩니다.

도메인에는 Ingress IP 주소로 구성된 와일드카드 DNS가 있어야 합니다. [자세한 정보](../../project/clusters/gitlab_managed_clusters.md#base-domain).

## 환경 범위 {#environment-scopes}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

프로젝트에 둘 이상의 Kubernetes 클러스터를 추가할 때 환경 범위를 사용하여 클러스터를 구분해야 합니다. 환경 범위는 [환경](../../../ci/environments/_index.md)과 연결된 클러스터입니다. [환경별 CI/CD 변수](../../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable)가 작동하는 방식과 유사합니다.

클러스터의 환경 범위와 일치하는 환경을 평가하는 동안 [클러스터 우선 순위](#cluster-precedence)가 적용됩니다. 프로젝트 수준의 클러스터가 우선순위를 갖고, 그 다음 가장 가까운 상위 그룹이 뒤따르고, 그룹의 상위 항목 등이 계속됩니다.

예를 들어 프로젝트에 다음 Kubernetes 클러스터가 있는 경우:

| 클러스터    | 환경 범위   | 위치     |
| ---------- | ------------------- | ----------|
| 프로젝트    | `*`                 | 프로젝트   |
| 스테이징    | `staging/*`         | 프로젝트   |
| 프로덕션 | `production/*`      | 프로젝트   |
| 테스트       | `test`              | 그룹     |
| 개발| `*`                 | 그룹     |

`.gitlab-ci.yml` 파일에 다음 환경이 설정되어 있습니다:

```yaml
stages:
  - test
  - deploy

test:
  stage: test
  script: sh test

deploy to staging:
  stage: deploy
  script: make deploy
  environment:
    name: staging/$CI_COMMIT_REF_NAME
    url: https://staging.example.com/

deploy to production:
  stage: deploy
  script: make deploy
  environment:
    name: production/$CI_COMMIT_REF_NAME
    url: https://example.com/
```

결과는 다음과 같습니다:

- 프로젝트 클러스터는 `test` 작업에 사용됩니다.
- 스테이징 클러스터는 `deploy to staging` 작업에 사용됩니다.
- 프로덕션 클러스터는 `deploy to production` 작업에 사용됩니다.

## 클러스터 환경 {#cluster-environments}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Kubernetes 클러스터에 배포된 CI [환경](../../../ci/environments/_index.md)의 통합 보기를 보려면 [클러스터 환경](../../clusters/environments.md)에 대한 문서를 참조하세요.

## 러너의 보안 {#security-of-runners}

러너를 안전하게 구성하는 방법에 대한 중요한 정보는 프로젝트 수준 클러스터에 대한 [러너의 보안](../../project/clusters/cluster_access.md#security-of-runners) 문서를 참조하세요.

## 자세한 정보 {#more-information}

GitLab과 Kubernetes를 통합하는 방법에 대한 정보는 [Kubernetes 클러스터](../../infrastructure/clusters/_index.md)를 참조하세요.
