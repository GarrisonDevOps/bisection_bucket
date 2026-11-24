---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 배포 보드 (지원 중단됨)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [GitLab Self-Managed에서 비활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/353410) (GitLab 15.0).

{{< /history >}}

> [!flag]
> GitLab Self-Managed에서 기본적으로 이 기능은 사용할 수 없습니다. 사용 가능하게 하려면 관리자가 `certificate_based_clusters`라는 [기능 플래그를 사용으로 설정](../../administration/feature_flags/_index.md)할 수 있습니다.

GitLab 배포 보드는 [환경](../../ci/environments/_index.md)에서 실행 중인 각 CI의 현재 상태와 상태를 통합 보기하고 [Kubernetes](https://kubernetes.io)에서 배포 중인 포드의 상태를 표시합니다. 개발자와 다른 팀원은 이미 사용 중인 워크플로에서 포드별로 롤아웃 진행 상황과 상태를 확인할 수 있으며, Kubernetes에 액세스할 필요가 없습니다.

> [!warning]
> 이 기능은 GitLab 14.5에서 [더 이상 사용되지 않습니다](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8). [에픽 2493이 있습니다](https://gitlab.com/groups/gitlab-org/-/work_items/2493). 이 기능을 [에이전트](../clusters/agent/_index.md)에 추가합니다.

Kubernetes 클러스터가 있으면 [Auto DevOps](../../topics/autodevops/_index.md)를 사용하여 프로덕션 환경에 애플리케이션을 자동 배포할 수 있습니다.

배포 보드를 사용하면 다음과 같은 이점이 있는 배포에 대해 더 자세히 알 수 있습니다:

- 완료되었을 때뿐만 아니라 시작부터 배포를 추적합니다
- 여러 서버에서 빌드의 롤아웃을 감시합니다
- 더 세분화된 상태 세부 정보 (성공, 실행 중, 실패, 대기 중, 알 수 없음)
- [카나리 배포](canary_deployments.md) 참조

다음은 프로덕션 환경의 배포 보드 예시입니다.

![Kubernetes 클러스터 포드로 프로덕션 환경 배포를 보여주는 대시보드입니다.](img/deploy_boards_landing_page_v9_0.png)

사각형은 Kubernetes 클러스터의 포드를 나타내며, 이는 주어진 환경과 연결되어 있습니다. 각 사각형 위에 마우스를 놓으면 배포 롤아웃 상태를 확인할 수 있습니다. 백분율은 최신 릴리스로 업데이트된 포드의 백분율입니다.

배포 보드는 Kubernetes와 밀접하게 연결되어 있으므로 다음에 익숙해야 합니다:

- [Kubernetes 포드](https://kubernetes.io/docs/concepts/workloads/pods/)
- [Kubernetes 레이블](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)
- [Kubernetes 네임스페이스](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/)
- [Kubernetes 카나리 배포](https://kubernetes.io/docs/concepts/workloads/management/#canary-deployments)

## 사용 사례 {#use-cases}

배포 보드는 특정 환경의 Kubernetes 포드의 시각적 표현이므로 많은 사용 사례가 있습니다. 몇 가지 예를 들면:

- 스테이징에서 실행 중인 것을 프로덕션으로 승격하려고 합니다. 환경 목록으로 이동하여 스테이징에서 실행 중인 것이 예상한 것인지 확인한 후 [수동 작업](../../ci/jobs/job_control.md#create-a-job-that-must-be-run-manually)을 선택하여 프로덕션에 배포합니다.
- 배포를 트리거했고 업그레이드할 컨테이너가 많으면 시간이 걸린다는 것을 알 수 있습니다 (또한 배포를 조절하여 한 번에 X개의 컨테이너만 중단하도록 설정했습니다). 배포되었을 때 누군가에게 알려야 하므로 환경 목록으로 이동하여 프로덕션 환경을 확인하여 각 포드가 롤링될 때 실시간으로 진행 상황을 확인합니다.
- 프로덕션에서 뭔가 이상하다는 보고를 받으면 프로덕션 환경을 확인하여 실행 중인 것을 보고 배포가 진행 중, 중단됨 또는 실패했는지 확인합니다.
- 좋아 보이는 MR이 있지만 스테이징에서 실행하고 싶습니다. 스테이징이 프로덕션에 더 가깝게 설정되어 있기 때문입니다. 환경 목록으로 이동하여 관심 있는 [검토 앱](../../ci/review_apps/_index.md)을 찾아 수동 작업을 선택하여 스테이징에 배포합니다.

## 배포 보드 활성화 {#enabling-deploy-boards}

특정 [환경](../../ci/environments/_index.md)에 대해 배포 보드를 표시하려면 다음을 수행해야 합니다:

1. [환경을 정의하고](../../ci/environments/_index.md) 배포 스테이지를 포함합니다.
1. Kubernetes 클러스터가 실행 중이어야 합니다.

   > [!note]
   > OpenShift를 사용 중이면 `Deployment` 리소스를 `DeploymentConfiguration` 대신 사용하는지 확인합니다. 그렇지 않으면 배포 보드가 올바르게 렌더링되지 않습니다. 자세한 내용은 [OpenShift 문서](https://docs.openshift.com/container-platform/3.7/dev_guide/deployments/kubernetes_deployments.html#kubernetes-deployments-vs-deployment-configurations) 및 [GitLab 이슈 #4584](https://gitlab.com/gitlab-org/gitlab/-/issues/4584)를 참조합니다.

1. [GitLab Runner를 구성](../../ci/runners/_index.md)하고 [`docker`](https://docs.gitlab.com/runner/executors/docker/) 또는 [`kubernetes`](https://docs.gitlab.com/runner/executors/kubernetes/) 실행기를 사용합니다.
1. 프로젝트에 대해 클러스터용 [Kubernetes 통합](../infrastructure/clusters/_index.md)을 구성합니다. Kubernetes 네임스페이스는 배포 스크립트에 필요하므로 특히 주목할 사항입니다 (`KUBE_NAMESPACE` 배포 변수로 노출됨).
1. Kubernetes 주석 `app.gitlab.com/env: $CI_ENVIRONMENT_SLUG`과 `app.gitlab.com/app: $CI_PROJECT_PATH_SLUG`을(를) 배포, 복제 세트 및 포드에 적용합니다. 여기서 `$CI_ENVIRONMENT_SLUG`과 `$CI_PROJECT_PATH_SLUG`는 CI/CD 변수의 값입니다. GitLab은 이 변수를 사용하여 하나 이상일 수 있는 클러스터/네임스페이스에서 올바른 환경을 찾습니다. 이 리소스는 Kubernetes 서비스 설정에서 정의한 네임스페이스에 포함되어야 합니다. [자동 배포](../../topics/autodevops/stages.md#auto-deploy) `.gitlab-ci.yml` 템플릿을 사용할 수 있습니다. 이는 사전 정의된 스테이지와 명령을 포함하고 주석을 자동으로 적용합니다. 각 프로젝트는 Kubernetes에도 고유한 네임스페이스를 가져야 합니다. 아래 이미지는 이것이 Kubernetes 내에서 어떻게 표시되는지를 보여줍니다.

   GCP를 사용하여 클러스터를 관리하면 **워크로드** > **배포 이름** > **상세정보**로 이동하여 GCP 자체에서 배포 세부 정보를 확인할 수 있습니다:

   ![GCP 배포 보드 세부 정보.](img/deploy_boards_kubernetes_label_v11_9.png)

이전의 모든 지침이 설정되고 파이프라인이 최소 한 번 실행된 후 **운영** > **환경** 아래 환경 페이지로 이동합니다.

배포 보드는 기본적으로 표시됩니다. 각 환경 이름 옆의 삼각형을 명시적으로 선택하여 숨길 수 있습니다.

### 예시 매니페스트 파일 {#example-manifest-file}

다음 예시는 배포 보드를 활성화하기 위해 두 주석 `app.gitlab.com/env`과 `app.gitlab.com/app`을(를) 사용하는 Kubernetes 매니페스트 배포 파일의 발췌입니다:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: "APPLICATION_NAME"
  annotations:
    app.gitlab.com/app: ${CI_PROJECT_PATH_SLUG}
    app.gitlab.com/env: ${CI_ENVIRONMENT_SLUG}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: "APPLICATION_NAME"
  template:
    metadata:
      labels:
        app: "APPLICATION_NAME"
      annotations:
        app.gitlab.com/app: ${CI_PROJECT_PATH_SLUG}
        app.gitlab.com/env: ${CI_ENVIRONMENT_SLUG}
```

주석은 배포, 복제 세트 및 포드에 적용됩니다. `kubectl scale --replicas=3 deploy APPLICATION_NAME -n ${KUBE_NAMESPACE}`과 같이 복제본 수를 변경하면 보드에서 인스턴스 포드를 추적할 수 있습니다.

> [!note]
> YAML 파일은 정적입니다. `kubectl apply`를 사용하여 적용하면 프로젝트 및 환경 슬러그를 수동으로 제공하거나 적용하기 전에 YAML의 변수를 바꾸는 스크립트를 만들어야 합니다.

## 카나리 배포 {#canary-deployments}

차량의 작은 부분을 애플리케이션의 새 버전으로 업데이트하는 인기 있는 CI 전략입니다.

[카나리 배포에 대해 자세히 알아봅니다.](canary_deployments.md)

## 추가 정보 {#further-reading}

- [GitLab 자동 배포](../../topics/autodevops/stages.md#auto-deploy)
- [GitLab CI/CD 변수](../../ci/variables/_index.md)
- [환경 및 배포](../../ci/environments/_index.md)
- [Kubernetes 배포 예시](https://gitlab.com/gitlab-examples/kubernetes-deploy)
