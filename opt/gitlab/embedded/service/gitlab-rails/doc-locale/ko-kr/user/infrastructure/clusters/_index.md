---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Kubernetes 클러스터
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab에 클러스터를 연결하려면 [Kubernetes용 GitLab 에이전트](../../clusters/agent/_index.md)를 사용하세요.

## 인증서 기반 Kubernetes 통합(지원 중단) {#certificate-based-kubernetes-integration-deprecated}

> [!warning]
> GitLab 14.5에서 Kubernetes 클러스터를 GitLab에 연결하는 인증서 기반 방식이 [지원 중단](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8)되었으며, 관련 [기능](#deprecated-features)도 함께 지원 중단되었습니다. GitLab Self-Managed 17.0 이후 버전에서는 이 기능이 기본적으로 비활성화됩니다. GitLab.com 사용자의 경우 네임스페이스 계층 구조에 인증서 기반 클러스터가 최소 하나 이상 활성화되어 있는 사용자는 GitLab 15.9까지 이 기능을 사용할 수 있습니다. 이 기능을 이전에 사용한 적 없는 GitLab.com 사용자는 더 이상 이 기능을 사용할 수 없습니다.

GitLab의 인증서 기반 Kubernetes 통합은 지원 중단되었습니다. 이 통합에는 다음과 같은 문제가 있었습니다:

- GitLab이 Kubernetes API에 직접 액세스해야 했기 때문에 보안 문제가 있었습니다.
- 구성 옵션이 유연하지 않았습니다.
- 통합이 불안정했습니다.
- 사용자들은 이 모델을 기반으로 한 기능들과 관련된 문제를 계속 보고했습니다.

이러한 이유로 새로운 모델인 [Kubernetes용 GitLab 에이전트](../../clusters/agent/_index.md)에 집중하기 위해 인증서 기반 통합이 지원 중단되었습니다. 두 방식을 동시에 유지하면 많은 혼란이 발생했으며 사용, 개발, 유지보수 및 문서화의 복잡성이 크게 증가했습니다. 그 결과 새로운 모델을 지원하기 위해 둘 다 지원 중단되었습니다. 인증서 기반 기능은 계속해서:

- 보안 및 중요 수정 사항을 받습니다.
- 지원되는 Kubernetes 버전과 함께 작동합니다.

GitLab에서 이러한 기능을 제거하는 일정은 아직 예정되지 않았습니다.

업데이트를 확인하려면 이 [에픽](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8)을 따르세요.

Kubernetes용 GitLab 에이전트로 마이그레이션할 시간이 더 필요한 경우 [기능 플래그를 활성화](../../../administration/feature_flags/_index.md)할 수 있으며, 이름은 `certificate_based_clusters`입니다. 자세한 내용은 [지원 중단 공지](../../../update/deprecations.md#gitlab-self-managed-certificate-based-integration-with-kubernetes)를 참조하세요. 이 기능 플래그는 인증서 기반 Kubernetes 통합을 다시 활성화합니다.

## 지원 중단된 기능 {#deprecated-features}

- [클러스터 인증서를 통해 기존 클러스터 연결](../../project/clusters/add_existing_cluster.md)
- [접근 제어](../../project/clusters/cluster_access.md)
- [GitLab 관리 클러스터](../../project/clusters/gitlab_managed_clusters.md)
- [인증서 기반 연결을 통해 애플리케이션 배포](../../project/clusters/deploy_to_cluster.md)
- [클러스터 관리 프로젝트](../../clusters/management_project.md)
- [클러스터 환경](../../clusters/environments.md)
- [배포 보드에 Canary Ingress 배포 표시](../../project/canary_deployments.md#show-canary-ingress-deployments-on-deploy-boards-deprecated)
- [배포 보드](../../project/deploy_boards.md)
- [웹 터미널](../../../administration/integration/terminal.md)

### 클러스터 레벨 {#cluster-levels}

[프로젝트 레벨](../../project/clusters/_index.md), [그룹 레벨](../../group/clusters/_index.md), [인스턴스 레벨](../../instance/clusters/_index.md) 클러스터의 개념은 새로운 모델에서는 사라지지만 기능은 어느 정도 유지됩니다.

에이전트는 항상 단일 GitLab 프로젝트에서 구성되며, 클러스터 연결을 다른 프로젝트 및 그룹에 노출하여 [GitLab CI/CD에서 액세스](../../clusters/agent/ci_cd_workflow.md)할 수 있습니다. 이렇게 하면 이러한 프로젝트와 그룹에 동일한 클러스터에 대한 액세스 권한을 부여하게 되며, 이는 그룹 레벨 클러스터의 사용 사례와 유사합니다.
