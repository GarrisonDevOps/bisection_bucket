---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Auto DevOps용 다중 Kubernetes 클러스터
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Auto DevOps를 사용할 때 다양한 환경을 다양한 Kubernetes 클러스터에 배포할 수 있습니다.

Auto DevOps에서 사용하는 [Deploy Job 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Deploy.gitlab-ci.yml)은 세 가지 환경 이름을 정의합니다:

- `review/` (`review/`로 시작하는 모든 환경)
- `staging`
- `production`

이러한 환경은 [Auto Deploy](stages.md#auto-deploy)를 사용하여 작업에 연결되므로 다양한 배포 도메인을 가져야 합니다. 세 가지 환경 각각에 대해 별도의 [`KUBE_CONTEXT`](../../user/clusters/agent/ci_cd_workflow.md#environments-that-use-auto-devops) 및 [`KUBE_INGRESS_BASE_DOMAIN`](requirements.md#auto-devops-base-domain) 변수를 정의해야 합니다.

## 다양한 클러스터에 배포 {#deploy-to-different-clusters}

환경을 다양한 Kubernetes 클러스터에 배포하려면:

1. [OpenTofu 및 GitLab으로 Kubernetes 클러스터 생성](../../user/infrastructure/iac/_index.md).
1. 클러스터를 프로젝트에 연결합니다:
   1. [각 클러스터에서 Kubernetes용 GitLab 에이전트 설치](../../user/clusters/agent/_index.md).
   1. [프로젝트에 액세스하도록 각 에이전트 구성](../../user/clusters/agent/work_with_agent.md#configure-your-agent).
1. [NGINX Ingress Controller 설치](cloud_deployments/auto_devops_with_gke.md#install-ingress)를 각 클러스터에서 수행합니다. IP 주소와 Kubernetes 네임스페이스를 저장하여 다음 단계를 진행합니다.
1. [Auto DevOps CI/CD 파이프라인 변수 구성](cicd_variables.md#build-and-deployment-variables)
   - `KUBE_CONTEXT` 변수 [각 환경에 대해](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable) 설정합니다. 값은 관련 클러스터의 에이전트를 가리켜야 합니다.
   - `KUBE_INGRESS_BASE_DOMAIN`을 설정합니다. 각 환경에 대해 [기본 도메인을 구성](requirements.md#auto-devops-base-domain)하여 관련 클러스터의 Ingress를 가리키도록 해야 합니다.
   - `KUBE_NAMESPACE` 변수를 추가하고, 배포가 대상으로 하는 Kubernetes 네임스페이스 값을 입력합니다. 변수를 여러 환경에 범위 지정할 수 있습니다.

더 이상 사용되지 않는 [인증서 기반 클러스터](../../user/infrastructure/clusters/_index.md#certificate-based-kubernetes-integration-deprecated)의 경우:

1. 프로젝트로 이동하여 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. [각 클러스터의 환경 범위 설정](../../user/project/clusters/multiple_kubernetes_clusters.md#setting-the-environment-scope).
1. 각 클러스터에 대해 [Ingress IP 주소를 기반으로 도메인 추가](../../user/project/clusters/gitlab_managed_clusters.md#base-domain).

> [!note]
> [활성 Kubernetes 클러스터를 확인할 때 클러스터 환경 범위가 무시됩니다](https://gitlab.com/gitlab-org/gitlab/-/issues/20351). Auto DevOps에서 다중 클러스터 설정이 작동하려면 **클러스터 환경 범위**를 `*`로 설정한 폴백 클러스터를 생성해야 합니다. 이미 추가한 클러스터 중 하나를 폴백 클러스터로 설정할 수 있습니다.

### 구성 예시 {#example-configurations}

| 클러스터 이름 | 클러스터 환경 범위 | `KUBE_INGRESS_BASE_DOMAIN` 값 | `KUBE CONTEXT` 값               | 변수 환경 범위 | 참고 |
|:-------------|:--------------------------|:---------------------------------|:-----------------------------------|:---------------------------|:------|
| review       | `review/*`                | `review.example.com`             | `path/to/project:review-agent`     | `review/*`                 | 모든 [검토 앱](../../ci/review_apps/_index.md)을 실행하는 검토 클러스터입니다. |
| staging      | `staging`                 | `staging.example.com`            | `path/to/project:staging-agent`    | `staging`                  | 선택사항. 스테이징 환경의 배포를 실행하는 스테이징 클러스터입니다. [먼저 활성화](cicd_variables.md#deploy-policy-for-staging-and-production-environments)해야 합니다. |
| production   | `production`              | `example.com`                    | `path/to/project:production-agent` | `production`               | 프로덕션 환경 배포를 실행하는 프로덕션 클러스터입니다. [점진적 롤아웃](cicd_variables.md#incremental-rollout-to-production)을 사용할 수 있습니다. |

## 구성 테스트 {#test-your-configuration}

구성을 완료한 후 머지 리퀘스트를 생성하여 설정을 테스트합니다. 응용 프로그램이 `review/*` 환경 범위를 사용하는 Kubernetes 클러스터에서 검토 앱으로 배포되었는지 확인합니다. 마찬가지로 다른 환경을 확인합니다.
