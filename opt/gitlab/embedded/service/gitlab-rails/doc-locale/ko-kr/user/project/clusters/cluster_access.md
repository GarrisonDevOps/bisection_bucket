---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 클러스터 인증서를 사용한 액세스 제어(RBAC 또는 ABAC) (사용 중단됨)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 14.5에서 [사용 중지](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8)되었습니다. 클러스터를 GitLab에 연결하려면 대신 [Kubernetes용 GitLab 에이전트](../../clusters/agent/_index.md)를 사용하세요.

GitLab에서 클러스터를 생성할 때 다음 중 하나를 생성하시겠습니까?:

- [역할 기반 액세스 제어(RBAC)](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) 클러스터. 이는 GitLab 기본값이자 권장 옵션입니다.
- [속성 기반 액세스 제어(ABAC)](https://kubernetes.io/docs/reference/access-authn-authz/abac/) 클러스터.

GitLab이 클러스터를 생성하면 `gitlab` 서비스 계정이 `cluster-admin` 권한으로 `default` 네임스페이스에 생성되어 새로 생성된 클러스터를 관리합니다.

Helm은 설치된 각 애플리케이션에 대해 추가 서비스 계정 및 기타 리소스도 생성합니다. 각 애플리케이션의 Helm 차트 설명서를 참고하여 자세한 내용을 확인하세요.

[기존 Kubernetes 클러스터를 추가](add_existing_cluster.md)하는 경우 계정의 토큰에 클러스터에 대한 관리자 권한이 있는지 확인하세요.

GitLab에서 생성한 리소스는 클러스터 유형에 따라 다릅니다.

## 중요 참고 사항 {#important-notes}

액세스 제어에 대해 다음을 참고하세요:

- 환경별 리소스는 클러스터가 [GitLab에서 관리](gitlab_managed_clusters.md)되는 경우에만 생성됩니다.
- 클러스터가 GitLab 12.2 이전에 생성된 경우 모든 프로젝트 환경에 단일 네임스페이스를 사용합니다.

## RBAC 클러스터 리소스 {#rbac-cluster-resources}

GitLab은 RBAC 클러스터에 대해 다음 리소스를 생성합니다.

| 이름                  | 형식                 | 세부 정보                                                                                                    | 생성 시점           |
|:----------------------|:---------------------|:-----------------------------------------------------------------------------------------------------------|:-----------------------|
| `gitlab`              | `ServiceAccount`     | `default` 네임스페이스                                                                                        | 새 클러스터 생성 |
| `gitlab-admin`        | `ClusterRoleBinding` | [`cluster-admin`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles) 역할    | 새 클러스터 생성 |
| `gitlab-token`        | `Secret`             | `gitlab` ServiceAccount의 토큰                                                                          | 새 클러스터 생성 |
| 환경 네임스페이스 | `Namespace`          | 모든 환경별 리소스 포함                                                                | 클러스터에 배포 |
| 환경 네임스페이스 | `ServiceAccount`     | 환경의 네임스페이스 사용                                                                              | 클러스터에 배포 |
| 환경 네임스페이스 | `Secret`             | 환경 ServiceAccount의 토큰                                                                       | 클러스터에 배포 |
| 환경 네임스페이스 | `RoleBinding`        | [`admin`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles) 역할            | 클러스터에 배포 |

## ABAC 클러스터 리소스 {#abac-cluster-resources}

GitLab은 ABAC 클러스터에 대해 다음 리소스를 생성합니다.

| 이름                  | 형식                 | 세부 정보                              | 생성 시점               |
|:----------------------|:---------------------|:-------------------------------------|:---------------------------|
| `gitlab`              | `ServiceAccount`     | `default` 네임스페이스                         | 새 클러스터 생성 |
| `gitlab-token`        | `Secret`             | `gitlab` ServiceAccount의 토큰           | 새 클러스터 생성 |
| 환경 네임스페이스 | `Namespace`          | 모든 환경별 리소스 포함 | 클러스터에 배포 |
| 환경 네임스페이스 | `ServiceAccount`     | 환경의 네임스페이스 사용               | 클러스터에 배포 |
| 환경 네임스페이스 | `Secret`             | 환경 ServiceAccount의 토큰        | 클러스터에 배포 |

## 러너의 보안 {#security-of-runners}

러너는 기본적으로 [권한 있는 모드](https://docs.gitlab.com/runner/executors/docker/#the-privileged-mode)가 활성화되어 있으며, 특수 명령을 실행하고 Docker in Docker를 실행할 수 있습니다. 이 기능은 [Auto DevOps](../../../topics/autodevops/_index.md) 작업 중 일부를 실행하는 데 필요합니다. 이는 컨테이너가 권한 있는 모드에서 실행 중이라는 의미이므로 일부 중요한 세부 사항을 알아야 합니다.

권한 있는 플래그는 실행 중인 컨테이너에 모든 기능을 제공하므로 호스트가 할 수 있는 거의 모든 작업을 수행할 수 있습니다. 임의 이미지에서 `docker run` 작업을 수행하는 것과 관련된 본질적인 보안 위험을 인식하세요. 이러한 이미지는 실제로 루트 액세스 권한이 있습니다.

권한 있는 모드에서 러너를 사용하지 않으려면 다음 중 하나를 수행하세요:

- GitLab.com에서 인스턴스 러너를 사용하세요. 이들은 이 보안 문제가 없습니다.
- [`docker+machine`](https://docs.gitlab.com/runner/executors/docker_machine/)를 사용하는 자신의 러너를 설정하세요.
