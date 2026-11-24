---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Kubernetes 에이전트로 마이그레이션
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Kubernetes 클러스터를 GitLab과 연결하려면 다음을 사용할 수 있습니다:

- [GitOps 워크플로우](../../clusters/agent/gitops.md).
- [GitLab CI/CD 워크플로우](../../clusters/agent/ci_cd_workflow.md).
- [인증서 기반 통합](_index.md).

인증서 기반 통합은 GitLab 14.5에서 [사용이 중단되었습니다](https://about.gitlab.com/blog/deprecating-the-cert-based-kubernetes-integration/). 지원 중단 계획은 다음과 같습니다:

- [GitLab.com 고객](../../../update/deprecations.md#gitlabcom-certificate-based-integration-with-kubernetes)의 경우.
- [GitLab Self-Managed 고객](../../../update/deprecations.md#gitlab-self-managed-certificate-based-integration-with-kubernetes)의 경우.

인증서 기반 통합을 사용 중이라면 가능한 빨리 다른 워크플로우로 전환해야 합니다.

일반적으로 GitLab CI/CD에 의존하는 클러스터를 마이그레이션하려면 [CI/CD 워크플로우](../../clusters/agent/ci_cd_workflow.md)를 사용할 수 있습니다. 이 워크플로우는 에이전트를 사용하여 클러스터에 연결합니다. 에이전트:

- 인터넷에 노출되지 않습니다.
- GitLab에 대한 전체 [`cluster-admin`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles) 액세스가 필요하지 않습니다.

> [!note]
> 인증서 기반 통합은 GitLab 관리 앱, GitLab 관리 클러스터 및 Auto DevOps와 같은 인기 있는 GitLab 기능에 사용되었습니다.

## 인증서 기반 클러스터 찾기 {#find-certificate-based-clusters}

GitLab 인스턴스 또는 그룹(서브그룹 및 프로젝트 포함) 내의 모든 인증서 기반 클러스터는 [전용 API](../../../api/cluster_discovery.md#retrieve-certificate-based-clusters)를 사용하여 찾을 수 있습니다. 그룹 ID로 API를 쿼리하면 제공된 그룹의 해당 수준 이하에서 정의된 모든 인증서 기반 클러스터가 반환됩니다.

이 경우 상위 그룹에서 정의된 클러스터는 반환되지 않습니다. 이 동작은 그룹 소유자가 마이그레이션해야 할 모든 클러스터를 찾을 수 있도록 도와줍니다.

사용하지 않는 클러스터도 반환되어 실수로 클러스터를 남기지 않도록 합니다.

> [!note]
> 클러스터 검색 API는 개인 네임스페이스에서 작동하지 않습니다.

## 일반 배포 마이그레이션 {#migrate-generic-deployments}

일반 배포를 마이그레이션하려면:

1. [GitLab Kubernetes 에이전트](../../clusters/agent/install/_index.md)를 설치합니다.
1. CI/CD 워크플로우를 따라 [에이전트가 그룹 및 프로젝트에 액세스하도록 승인](../../clusters/agent/ci_cd_workflow.md#authorize-agent-access)하거나 [가장을 사용하여 액세스 보안](../../clusters/agent/ci_cd_workflow.md#restrict-project-and-group-access-by-using-impersonation)을 설정합니다.
1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. 인증서 기반 클러스터 섹션에서 동일한 환경 범위를 제공하는 클러스터를 엽니다.
1. **상세정보** 탭을 선택하고 클러스터를 끕니다.

## GitLab 관리 클러스터에서 Kubernetes 리소스로 마이그레이션 {#migrate-from-gitlab-managed-clusters-to-kubernetes-resources}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

GitLab 관리 클러스터를 사용하면 GitLab이 모든 브랜치에 대해 별도의 서비스 계정과 네임스페이스를 생성하고 이러한 리소스를 사용하여 배포합니다.

이제 [GitLab 관리 Kubernetes 리소스](../../clusters/agent/managed_kubernetes_resources.md)를 사용하여 향상된 보안 제어로 리소스를 자체 제공할 수 있습니다.

GitLab 관리 Kubernetes 리소스를 사용하면 다음을 수행할 수 있습니다:

- 수동 개입 없이 안전하게 환경을 설정합니다.
- 개발자에게 관리 클러스터 권한을 부여하지 않고 리소스 생성 및 액세스를 제어합니다.
- 개발자가 새 프로젝트 또는 환경을 생성할 때 자체 제공 기능을 제공합니다.
- 개발자가 전용 또는 공유 네임스페이스에 테스트 및 개발 버전을 배포할 수 있도록 합니다.

사전 요구 사항:

- [GitLab Kubernetes 에이전트](../../clusters/agent/install/_index.md)를 설치합니다.
- [에이전트를 승인](../../clusters/agent/ci_cd_workflow.md#authorize-agent-access)하여 관련 프로젝트 또는 그룹에 액세스합니다.
- 인증서 기반 클러스터 통합 페이지에서 **환경당 네임스페이스** 확인란의 상태를 확인합니다.

GitLab 관리 클러스터에서 GitLab 관리 Kubernetes 리소스로 마이그레이션하려면:

1. 기존 환경을 마이그레이션하는 경우 [Kubernetes 대시보드](../../../ci/environments/kubernetes_dashboard.md#configure-a-dashboard) 또는 [환경 API](../../../api/environments.md)를 통해 환경에 대해 에이전트를 구성합니다.
1. 에이전트 구성 파일에서 리소스 관리를 켜도록 에이전트를 구성합니다:

   ```yaml
   ci_access:
      projects:
        - id: <your_group/your_project>
          access_as:
            ci_job: {}
          resource_management:
            enabled: true
      groups:
        - id: <your_other_group>
          access_as:
            ci_job: {}
          resource_management:
            enabled: true
   ```

1. `.gitlab/agents/<agent-name>/environment_templates/default.yaml` 아래에 환경 템플릿을 생성합니다. 인증서 기반 클러스터 통합 페이지에서 **환경당 네임스페이스** 확인란의 상태를 확인합니다.

   **환경당 네임스페이스**가 선택되었다면 다음 템플릿을 사용합니다:

   ```yaml
   objects:
     - apiVersion: v1
       kind: Namespace
       metadata:
         # the `.legacy_namespace` produces something like:
         # '{{ .project.slug }}-{{ .project.id }}-{{ .environment.slug }}'
         # that is compatible with what the certificate-based cluster integration
         # would have generated.
         name: '{{ .legacy_namespace }}'
     - apiVersion: rbac.authorization.k8s.io/v1
       kind: RoleBinding
       metadata:
         name: 'bind-{{ .agent.id }}-{{ .project.id }}-{{ .environment.slug }}'
         namespace: '{{ .legacy_namespace }}'
       subjects:
         - kind: Group
           apiGroup: rbac.authorization.k8s.io
           name: 'gitlab:project_env:{{ .project.id }}:{{ .environment.slug }}'
       roleRef:
         apiGroup: rbac.authorization.k8s.io
         kind: ClusterRole
         name: admin
   ```

   **환경당 네임스페이스**가 선택 해제되었다면 다음 템플릿을 사용합니다:

   ```yaml
   objects:
     - apiVersion: v1
       kind: Namespace
       metadata:
         name: '{{ .project.slug | slugify }}-{{ .project.id }}'
     - apiVersion: rbac.authorization.k8s.io/v1
       kind: RoleBinding
       metadata:
         name: 'bind-{{ .agent.id }}-{{ .project.id }}-{{ .environment.slug }}'
         namespace: '{{ .project.slug | slugify }}-{{ .project.id }}'
       subjects:
         - kind: Group
           apiGroup: rbac.authorization.k8s.io
           name: 'gitlab:project_env:{{ .project.id }}:{{ .environment.slug }}'
       roleRef:
         apiGroup: rbac.authorization.k8s.io
         kind: ClusterRole
         name: admin
   ```

1. CI/CD 구성에서 `environment.kubernetes.agent: <path/to/agent/project:agent-name>` 구문으로 에이전트를 사용합니다.
1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. 인증서 기반 클러스터 섹션에서 동일한 환경 범위를 제공하는 클러스터를 엽니다.
1. **상세정보** 탭을 선택하고 클러스터를 끕니다.

## Auto DevOps에서 마이그레이션 {#migrate-from-auto-devops}

Auto DevOps 프로젝트에서 GitLab Kubernetes 에이전트를 사용하여 Kubernetes 클러스터에 연결할 수 있습니다.

사전 요구 사항:

- [GitLab Kubernetes 에이전트](../../clusters/agent/install/_index.md)를 설치합니다.
- [에이전트를 승인](../../clusters/agent/ci_cd_workflow.md#authorize-agent-access)하여 관련 프로젝트 또는 그룹에 액세스합니다.

Auto DevOps에서 마이그레이션하려면:

1. GitLab에서 Auto DevOps를 사용하는 프로젝트로 이동합니다.
1. 세 개의 변수를 추가합니다. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택하고 **변수**를 확장합니다.
   - `KUBE_INGRESS_BASE_DOMAIN`이라는 키를 추가하고 애플리케이션 배포 도메인을 값으로 설정합니다.
   - `KUBE_CONTEXT`이라는 키를 추가하고 값으로 `path/to/agent/project:agent-name`를 설정합니다. 원하는 환경 범위를 선택합니다. 에이전트의 컨텍스트가 확실하지 않으면 `.gitlab-ci.yml` 파일을 편집하고 작업을 추가하여 사용 가능한 컨텍스트를 확인합니다:

     ```yaml
     deploy:
       image: debian:13-slim
       variables:
         KUBECTL_VERSION: v1.34
         DEBIAN_FRONTEND: noninteractive
       script:
         # Follows https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-using-native-package-management
         - apt-get update
         - apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl gnupg
         - curl --fail --silent --show-error --location "https://pkgs.k8s.io/core:/stable:/${KUBECTL_VERSION}/deb/Release.key" | gpg --dearmor --output /etc/apt/keyrings/kubernetes-apt-keyring.gpg
         - chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
         - echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${KUBECTL_VERSION}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list
         - chmod 644 /etc/apt/sources.list.d/kubernetes.list
         - apt-get update
         - apt-get install -y --no-install-recommends kubectl
         - kubectl config get-contexts
      ```

   - `KUBE_NAMESPACE`이라는 키를 추가하고 배포를 대상으로 하는 Kubernetes 네임스페이스의 값을 설정합니다. 동일한 환경 범위를 설정합니다.
1. **변수 추가**를 선택합니다.
1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. 인증서 기반 클러스터 섹션에서 동일한 환경 범위를 제공하는 클러스터를 엽니다.
1. **상세정보** 탭을 선택하고 클러스터를 사용하지 않도록 설정합니다.
1. `.gitlab-ci.yml` 파일을 편집하고 Auto DevOps 템플릿을 사용하고 있는지 확인합니다. 예를 들어:

   ```yaml
   include:
     template: Auto-DevOps.gitlab-ci.yml

   variables:
     KUBE_INGRESS_BASE_DOMAIN: 74.220.23.215.nip.io
     KUBE_CONTEXT: "gitlab-examples/ops/gitops-demo/k8s-agents:demo-agent"
     KUBE_NAMESPACE: "demo-agent"
   ```

1. 파이프라인을 테스트하려면 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택한 후 **새 파이프라인**을 선택합니다.

예제는 [이 프로젝트를 보세요](https://gitlab.com/gitlab-examples/ops/gitops-demo/hello-world-service).

## GitLab 관리 애플리케이션에서 마이그레이션 {#migrate-from-gitlab-managed-applications}

GitLab 관리 앱(GMA)은 사용이 중단되고 제거되었습니다. Kubernetes 에이전트는 이를 지원하지 않습니다. GMA에서 에이전트로 마이그레이션하려면 다음 단계를 진행합니다:

1. [GitLab 관리 앱에서 클러스터 관리 프로젝트로 마이그레이션](../../clusters/migrating_from_gma_to_project_template.md).
1. [클러스터 관리 프로젝트를 에이전트를 사용하도록 마이그레이션](../../clusters/management_project_template.md).

## 클러스터 관리 프로젝트 마이그레이션 {#migrate-a-cluster-management-project}

[GitLab Kubernetes 에이전트와 함께 클러스터 관리 프로젝트를 사용하는 방법](../../clusters/management_project_template.md)을 확인합니다.

## 클러스터 모니터링 기능 마이그레이션 {#migrate-cluster-monitoring-features}

Kubernetes 에이전트를 사용하여 Kubernetes 클러스터를 GitLab에 연결한 후 [사용자 액세스](../../clusters/agent/user_access.md)를 활성화한 후 [Kubernetes 대시보드](../../../ci/environments/kubernetes_dashboard.md)를 사용할 수 있습니다.
