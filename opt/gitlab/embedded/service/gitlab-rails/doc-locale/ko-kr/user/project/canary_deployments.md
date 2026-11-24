---
stage: Deploy
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 카나리 배포
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

카나리 배포는 인기 있는 [지속적 배포](https://en.wikipedia.org/wiki/Continuous_deployment) 전략으로, 작은 범위의 워크로드가 새로운 버전의 애플리케이션으로 업데이트됩니다.

[지속적 배포](https://about.gitlab.com/blog/continuous-integration-delivery-and-deployment-with-gitlab/)를 도입할 때, 조직은 사용할 배포 전략의 유형을 결정해야 합니다. 가장 인기 있는 전략 중 하나는 카나리 배포로, 작은 범위의 워크로드가 먼저 새로운 버전으로 업데이트됩니다. 이 부분집합인 카나리는 속담적으로 [광산에서의 카나리](https://en.wiktionary.org/wiki/canary_in_a_coal_mine) 역할을 합니다.

애플리케이션의 새로운 버전에 문제가 있으면 사용자의 작은 비율만 영향을 받으며, 변경 사항을 수정하거나 빠르게 되돌릴 수 있습니다.

## 사용 사례 {#use-cases}

카나리 배포는 기능을 파드 워크로드의 일부분에만 제공하고 사용자 기반의 일정 비율이 임시로 배포된 기능을 방문할 때 동작을 감시하려는 경우에 사용할 수 있습니다. 모든 것이 잘 작동하면, 기능을 프로덕션에 배포할 수 있다는 것을 알고 문제를 일으키지 않을 것입니다.

카나리 배포는 백엔드 리팩터링, 성능 개선 또는 사용자 인터페이스가 변경되지 않지만 성능이 동일하게 유지되거나 개선되는지 확인하려는 다른 변경 사항에 특히 필요합니다. 개발자는 사용자 대면 변경 사항과 함께 카나리를 사용할 때 주의해야 합니다. 기본적으로 같은 사용자의 요청은 카나리 파드와 비-카나리 파드 간에 무작위로 분산되므로 혼동이나 오류가 발생할 수 있습니다. 필요한 경우, [`service.spec.sessionAffinity`을 Kubernetes 서비스 정의에서 `ClientIP`으로 설정](https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies)하는 것을 고려할 수 있지만, 이는 이 문서의 범위를 벗어납니다.

## 카나리 Ingress를 사용한 고급 트래픽 제어 {#advanced-traffic-control-with-canary-ingress}

카나리 배포는 [카나리 Ingress](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#canary)를 사용하면 더욱 전략적일 수 있습니다. 카나리 Ingress는 가중치, 세션, 쿠키 등의 요소를 기반으로 안정적인 배포와 카나리 배포 간의 수신 HTTP 요청을 제어하는 고급 트래픽 라우팅 서비스입니다. GitLab은 [Auto Deploy 아키텍처](../../topics/autodevops/upgrading_auto_deploy_dependencies.md#v2-chart-resource-architecture)에서 이 서비스를 사용하여 사용자가 새로운 배포를 빠르고 안전하게 배포할 수 있도록 합니다.

### 카나리 배포에서 카나리 Ingress를 설정하는 방법 {#how-to-set-up-a-canary-ingress-in-a-canary-deployment}

Auto DevOps 파이프라인이 [`v2.0.0+`의 `auto-deploy-image`](../../topics/autodevops/upgrading_auto_deploy_dependencies.md#verify-dependency-versions)을 사용하면 카나리 Ingress가 기본적으로 설치됩니다. 카나리 Ingress는 새로운 카나리 배포를 생성할 때 사용 가능해지며, 카나리 배포가 프로덕션으로 승격될 때 제거됩니다.

처음부터 시작하는 예제 설정 흐름입니다:

1. [Auto DevOps가 활성화된](../../topics/autodevops/_index.md) 프로젝트를 준비합니다.
1. 프로젝트에서 [Kubernetes 클러스터](../infrastructure/clusters/_index.md)를 설정합니다.
1. 클러스터에 [NGINX Ingress](https://github.com/kubernetes/ingress-nginx/tree/main/charts/ingress-nginx)를 설치합니다.
1. 위에 할당된 Ingress 엔드포인트를 기반으로 [기본 도메인](clusters/gitlab_managed_clusters.md#base-domain)을 설정합니다.
1. [Auto DevOps 파이프라인에서 `v2.0.0+`의 `auto-deploy-image`이 사용되는지](../../topics/autodevops/upgrading_auto_deploy_dependencies.md#verify-dependency-versions) 확인합니다. 그렇지 않으면 문서를 따라 이미지 버전을 지정합니다.
1. [새로운 Auto DevOps 파이프라인을 실행](../../ci/pipelines/_index.md#run-a-pipeline-manually)하고 `production` 작업이 성공하고 프로덕션 환경을 생성하는지 확인합니다.
1. Auto DevOps 파이프라인에 대한 [`canary` 배포 작업을 구성](../../topics/autodevops/cicd_variables.md#deploy-policy-for-canary-environments)합니다.
1. [새로운 Auto DevOps 파이프라인을 실행](../../ci/pipelines/_index.md#run-a-pipeline-manually)하고 `canary` 작업이 성공하고 카나리 Ingress를 사용하여 카나리 배포를 생성하는지 확인합니다.

### 배포 보드에 카나리 Ingress 배포 표시 (더 이상 사용되지 않음) {#show-canary-ingress-deployments-on-deploy-boards-deprecated}

> [!warning]
> 이 기능은 GitLab 14.5에서 [사용 중지](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8)되었습니다.

카나리 배포를 보려면 배포 보드를 올바르게 구성해야 합니다:

1. [배포 보드를 활성화](deploy_boards.md#enabling-deploy-boards)하는 단계를 따릅니다.
1. 카나리 배포를 추적하려면 Kubernetes 배포 및 파드에 `track: canary`로 레이블을 지정해야 합니다. 빠르게 시작하려면 GitLab이 제공하는 카나리 배포를 위한 [Auto Deploy](../../topics/autodevops/stages.md#auto-deploy) 템플릿을 사용할 수 있습니다.

배포에 따라 레이블은 `stable` 또는 `canary`이어야 합니다. GitLab은 레이블이 공백이거나 누락된 경우 트랙 레이블을 `stable`으로 간주합니다. 다른 모든 트랙 레이블은 `canary` (임시)로 간주됩니다. 이를 통해 GitLab은 배포가 안정적인지 또는 카나리인지 (임시)를 검색할 수 있습니다.

배포 보드를 구성하고 파이프라인이 최소 한 번 실행된 후 **파이프라인** > **환경**에서 환경 페이지로 이동합니다. 파이프라인이 실행되면서 배포 보드는 카나리 파드를 명확하게 표시하여 각 환경과 배포 상태를 빠르고 명확하게 파악할 수 있습니다.

카나리 배포는 배포 보드에서 노란색 점으로 표시되므로 빠르게 알아볼 수 있습니다.

![배포 보드의 카나리 배포](img/deploy_boards_canary_deployments_v9_2.png)

#### 카나리 Ingress에서 현재 트래픽 가중치를 확인하는 방법 (더 이상 사용되지 않음) {#how-to-check-the-current-traffic-weight-on-a-canary-ingress-deprecated}

> [!warning]
> 이 기능은 GitLab 14.5에서 [사용 중지](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8)되었습니다.

1. [배포 보드](deploy_boards.md)를 방문합니다.
1. 오른쪽에서 현재 가중치를 확인합니다.

   ![롤아웃 상태 카나리 Ingress](img/canary_weight_v13_7.png)

#### 카나리 Ingress에서 트래픽 가중치를 변경하는 방법 (더 이상 사용되지 않음) {#how-to-change-the-traffic-weight-on-a-canary-ingress-deprecated}

> [!warning]
> 이 기능은 GitLab 14.5에서 [사용 중지](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8)되었습니다.

[GraphiQL](../../api/graphql/getting_started.md#graphiql)을 사용하거나 [GraphQL API](../../api/graphql/getting_started.md#command-line)로 요청을 전송하여 환경의 배포 보드에서 트래픽 가중치를 변경할 수 있습니다.

[배포 보드](deploy_boards.md)를 사용하려면:

1. 프로젝트에 대해 **운영** > **환경**으로 이동합니다.
1. 오른쪽의 드롭다운 목록으로 새 가중치를 설정합니다.
1. 선택 항목을 확인합니다.

[GraphiQL](../../api/graphql/getting_started.md#graphiql)을 사용한 예제입니다:

1. [GraphiQL 탐색기](https://gitlab.com/-/graphql-explorer)를 방문합니다.
1. `environmentsCanaryIngressUpdate` GraphQL mutation을 실행합니다:

   ```shell
   mutation {
     environmentsCanaryIngressUpdate(input:{
       id: "gid://gitlab/Environment/29",              # Your Environment ID. You can get the ID from the URL of the environment page.
       weight: 45                                      # The new traffic weight. For example, if you set `45`, 45% of traffic goes to a canary deployment and 55% of traffic goes to a stable deployment.
     }) {
       errors
     }
   }
   ```

1. 요청이 성공하면 `errors` 응답에는 빈 배열이 포함됩니다. GitLab은 카나리 Ingress에서 가중치 매개변수를 업데이트하기 위해 Kubernetes 클러스터에 `PATCH` 요청을 보냅니다.
