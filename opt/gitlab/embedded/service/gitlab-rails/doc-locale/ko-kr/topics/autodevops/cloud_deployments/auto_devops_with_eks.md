---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Auto DevOps를 사용하여 Amazon Elastic Kubernetes Service(EKS)에 애플리케이션 배포
---

이 튜토리얼은 [자동 DevOps](../_index.md)를 사용하여 Amazon Elastic Kubernetes Service(EKS)에 애플리케이션을 배포하는 방법의 예시로 시작합니다.

이 튜토리얼은 GitLab 기본 Kubernetes 통합을 사용하므로 AWS 콘솔을 사용하여 Kubernetes 클러스터를 수동으로 생성할 필요가 없습니다.

GitLab Self-Managed 인스턴스에서도 이 튜토리얼을 따를 수 있습니다. 자신의 [러너가 구성](../../../ci/runners/_index.md)되었는지 확인하세요.

EKS에 프로젝트를 배포하려면:

1. [Amazon 계정 구성](#configure-your-amazon-account)
1. [Kubernetes 클러스터 생성 및 에이전트 배포](#create-a-kubernetes-cluster)
1. [템플릿에서 새 프로젝트 생성](#create-an-application-project-from-a-template)
1. [에이전트 구성](#configure-the-agent)
1. [Ingress 설치](#install-ingress)
1. [자동 DevOps 구성](#configure-auto-devops)
1. [자동 DevOps 활성화 및 파이프라인 실행](#enable-auto-devops-and-run-the-pipeline)
1. [애플리케이션 배포](#deploy-the-application)

## Amazon 계정 구성 {#configure-your-amazon-account}

Kubernetes 클러스터를 GitLab 프로젝트에 만들고 연결하기 전에 [Amazon Web Services 계정](https://aws.amazon.com/)이 필요합니다. 기존 Amazon 계정으로 로그인하거나 새 계정을 만드세요.

## Kubernetes 클러스터 생성 {#create-a-kubernetes-cluster}

Amazon EKS에서 새 클러스터를 생성하려면:

- [Amazon EKS 클러스터 생성](../../../user/infrastructure/clusters/connect/new_eks_cluster.md)의 단계를 따르세요.

원하면 `eksctl`을(를) 사용하여 클러스터를 수동으로 생성할 수도 있습니다.

## 템플릿에서 애플리케이션 프로젝트 생성 {#create-an-application-project-from-a-template}

GitLab 프로젝트 템플릿을 사용하여 시작하세요. 이름에서 알 수 있듯이, 이러한 프로젝트는 잘 알려진 프레임워크를 기반으로 하는 기본 애플리케이션을 제공합니다.

> [!warning]
> 애플리케이션 프로젝트를 그룹 계층 구조에서 클러스터 관리 프로젝트와 같은 수준 또는 아래에 생성합니다. 그렇지 않으면 [에이전트 권한 부여](../../../user/clusters/agent/ci_cd_workflow.md#authorize-agent-access)에 실패합니다.

1. 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **템플릿으로 부터 생성**을 선택합니다.
1. **Ruby on Rails** 템플릿을 선택합니다.
1. 프로젝트에 이름을 지정하고, 선택적으로 설명을 입력한 후, 공개로 설정하여 [GitLab Ultimate](https://about.gitlab.com/pricing/)에서 사용 가능한 기능을 활용할 수 있습니다.
1. **프로젝트 생성**을 선택합니다.

이제 EKS 클러스터에 배포할 애플리케이션 프로젝트가 있습니다.

## 에이전트 구성 {#configure-the-agent}

다음으로, 애플리케이션 프로젝트를 배포하는 데 사용할 수 있도록 Kubernetes용 GitLab 에이전트를 구성합니다.

1. [클러스터를 관리하기 위해 생성한](#create-a-kubernetes-cluster) 프로젝트로 이동합니다.
1. [에이전트 구성 파일](../../../user/clusters/agent/install/_index.md#create-an-agent-configuration-file) (`.gitlab/agents/eks-agent/config.yaml`)로 이동하여 편집합니다.
1. `ci_access:projects` 속성을 구성합니다. 애플리케이션 프로젝트 경로를 `id`로 사용합니다:

```yaml
ci_access:
  projects:
    - id: path/to/application-project
```

## Ingress 설치 {#install-ingress}

클러스터가 실행 중인 후, 인터넷에서 애플리케이션으로 트래픽을 라우팅하기 위해 로드 밸런서로 NGINX Ingress 컨트롤러를 설치해야 합니다. GitLab [클러스터 관리 프로젝트 템플릿](../../../user/clusters/management_project_template.md)을 통해 또는 명령줄을 사용하여 수동으로 NGINX Ingress 컨트롤러를 설치합니다:

1. 머신에 `kubectl` 및 Helm이 설치되어 있는지 확인하세요.
1. 클러스터에 액세스할 IAM 역할을 생성합니다.
1. 클러스터에 액세스할 액세스 토큰을 생성합니다.
1. `kubectl`을(를) 사용하여 클러스터에 연결합니다:

   ```shell
   helm upgrade --install ingress-nginx ingress-nginx \
   --repo https://kubernetes.github.io/ingress-nginx \
   --namespace gitlab-managed-apps --create-namespace

   # Check that the ingress controller is installed successfully
   kubectl get service ingress-nginx-controller -n gitlab-managed-apps
   ```

## 자동 DevOps 구성 {#configure-auto-devops}

자동 DevOps에 필요한 기본 도메인 및 기타 설정을 구성하려면 다음 단계를 따르세요.

1. NGINX를 설치한 후 몇 분이 지나면 로드 밸런서가 IP 주소를 획득하고 다음 명령으로 외부 IP 주소를 가져올 수 있습니다:

   ```shell
   kubectl get all -n gitlab-managed-apps --selector app.kubernetes.io/instance=ingress-nginx
   ```

   네임스페이스를 덮어쓴 경우 `gitlab-managed-apps`을(를) 바꾸세요.

   다음으로, 다음 명령을 사용하여 클러스터의 실제 외부 IP 주소를 찾습니다:

   ```shell
   nslookup [External IP]
   ```

   `[External IP]`은(는) 이전 명령으로 찾은 호스트명입니다.

   IP 주소는 응답의 `Non-authoritative answer:` 섹션에 나열될 수 있습니다.

   이 IP 주소를 복사합니다. 다음 단계에서 필요합니다.
1. 애플리케이션 프로젝트로 돌아갑니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택하고 **변수**를 확장합니다.
   - `KUBE_INGRESS_BASE_DOMAIN`이라고 하는 키를 추가하고 애플리케이션 배포 도메인을 값으로 사용합니다. 이 예시에서는 도메인 `<IP address>.nip.io`을(를) 사용합니다.
   - `KUBE_NAMESPACE`이라고 하는 키를 추가하고 배포 대상이 될 Kubernetes 네임스페이스의 값을 사용합니다. 환경별로 다른 네임스페이스를 사용할 수 있습니다. 환경을 구성하고 환경 범위를 사용합니다.
   - `KUBE_CONTEXT`이라고 하는 키를 추가하고 `path/to/agent/project:eks-agent`와 같은 값을 사용합니다. 원하는 환경 범위를 선택합니다.
   - **변경 사항 저장**을 선택합니다.

## 자동 DevOps 활성화 및 파이프라인 실행 {#enable-auto-devops-and-run-the-pipeline}

자동 DevOps는 기본적으로 활성화되어 있지만, 전체 인스턴스(GitLab Self-Managed 인스턴스의 경우)와 개별 그룹에 대해 비활성화할 수 있습니다. 자동 DevOps가 비활성화된 경우 활성화하려면 다음 단계를 완료합니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 애플리케이션 프로젝트를 찾습니다.
1. **설정** > **CI/CD**를 선택합니다.
1. **자동 DevOps**를 확장합니다.
1. **Auto DevOps 파이프라인을 기본으로 사용**을 선택하여 더 많은 옵션을 표시합니다.
1. **배포 전략**에서 원하는 [지속적 배포 전략](../requirements.md#auto-devops-deployment-strategy)을 선택하여 파이프라인이 기본 브랜치에서 성공적으로 실행된 후 애플리케이션을 프로덕션으로 배포합니다.
1. **변경 사항 저장**을 선택합니다.
1. `.gitlab-ci.yml` 파일을 편집하여 Auto DevOps 템플릿을 포함하고 변경 사항을 기본 브랜치에 커밋합니다:

   ```yaml
   include:
   - template: Auto-DevOps.gitlab-ci.yml
   ```

커밋은 파이프라인을 트리거해야 합니다. 다음 섹션은 파이프라인의 각 작업이 수행하는 작업을 설명합니다.

## 애플리케이션 배포 {#deploy-the-application}

파이프라인이 실행될 때 무엇을 하고 있습니까?

파이프라인의 작업을 보려면 파이프라인의 상태 배지를 선택합니다. {{< icon name="status_running" >}} 아이콘은 파이프라인 작업이 실행 중일 때 표시되며, 페이지를 새로 고치지 않고 {{< icon name="status_success" >}} (성공) 또는 {{< icon name="status_failed" >}} (실패)로 업데이트됩니다(작업이 완료될 때).

작업들은 스테이지로 분리됩니다:

![파이프라인 스테이지](img/guide_pipeline_stages_v13_0.png)

- **빌드** \- 애플리케이션이 Docker 이미지를 빌드하고 프로젝트의 [컨테이너 레지스트리](../../../user/packages/container_registry/_index.md)에 업로드합니다 ([자동 빌드](../stages.md#auto-build)).
- **테스트** \- GitLab은 애플리케이션에서 다양한 검사를 실행하지만, `test` 제외의 모든 작업은 테스트 스테이지에서 실패하도록 허용됩니다:

  - `test` 작업은 언어 및 프레임워크를 감지하여 단위 및 통합 테스트를 실행합니다 ([자동 테스트](../stages.md#auto-test))
  - `code_quality` 작업은 코드 품질을 확인하며 실패하도록 허용됩니다 ([자동 코드 품질](../stages.md#auto-code-quality))
  - `container_scanning` 작업은 Docker 컨테이너에 취약점이 있는지 확인하며 실패하도록 허용됩니다 ([자동 컨테이너 검사](../stages.md#auto-container-scanning))
  - `dependency_scanning` 작업은 애플리케이션에 취약점에 노출될 수 있는 종속성이 있는지 확인하며 실패하도록 허용됩니다 ([자동 종속성 검사](../stages.md#auto-dependency-scanning))
  - `-sast`이 붙은 작업은 잠재적 보안 문제를 확인하기 위해 현재 코드에서 정적 분석을 실행하며 실패하도록 허용됩니다 ([자동 SAST](../stages.md#auto-sast))
  - `secret-detection` 작업은 유출된 시크릿을 확인하며 실패하도록 허용됩니다 ([자동 시크릿 검색](../stages.md#auto-secret-detection))
- **리뷰** \- 기본 브랜치의 파이프라인에는 `dast_environment_deploy` 작업이 포함된 이 스테이지가 포함됩니다. 자세히 알아보려면 [동적 애플리케이션 보안 테스트(DAST)](../../../user/application_security/dast/_index.md)를 참조하세요.
- **프로덕션** \- 테스트 및 검사가 완료되면 애플리케이션이 Kubernetes에 배포됩니다 ([자동 배포](../stages.md#auto-deploy)).
- **성능** \- 성능 테스트가 배포된 애플리케이션에서 실행됩니다 ([자동 브라우저 성능 테스트](../stages.md#auto-browser-performance-testing)).
- **정리** \- 기본 브랜치의 파이프라인에는 `stop_dast_environment` 작업이 포함된 이 스테이지가 포함됩니다.

파이프라인을 실행한 후 배포된 웹사이트를 보고 모니터링하는 방법을 배워야 합니다.

### 프로젝트 모니터링 {#monitor-your-project}

애플리케이션을 성공적으로 배포한 후, **운영** > **환경**으로 이동하여 **환경** 페이지에서 웹사이트를 보고 상태를 확인할 수 있습니다. 이 페이지는 배포된 애플리케이션에 대한 세부 정보를 표시하며, 오른쪽 열에는 일반 환경 작업으로 연결되는 아이콘이 표시됩니다:

![환경](img/guide_environments_v12_3.png)

- **라이브 환경 열기** ({{< icon name="external-link" >}}) - 프로덕션에 배포된 애플리케이션의 URL을 엽니다
- **모니터링** ({{< icon name="chart" >}}) - Prometheus가 Kubernetes 클러스터에 대한 데이터를 수집하는 메트릭 페이지를 열고, 애플리케이션이 메모리 사용량, CPU 사용량 및 지연시간 측면에서 어떻게 영향을 미치는지 보여줍니다
- **배포 대상** ({{< icon name="play" >}} {{< icon name="chevron-lg-down" >}}) - 배포할 수 있는 환경 목록을 표시합니다
- **터미널** ({{< icon name="terminal" >}}) - 애플리케이션이 실행 중인 컨테이너 내부에서 [웹 터미널](../../../ci/environments/_index.md#web-terminals-deprecated) 세션을 엽니다
- **환경에 재배포** ({{< icon name="repeat" >}}) - 자세한 내용은 [재시도 및 롤백](../../../ci/environments/deployments.md#retry-or-roll-back-a-deployment)을 참조하세요
- **중지 환경** ({{< icon name="stop" >}}) - 자세한 내용은 [환경 중지](../../../ci/environments/_index.md#stopping-an-environment)를 참조하세요

GitLab은 환경 정보 아래에 [배포 보드](../../../user/project/deploy_boards.md)를 표시하며, Kubernetes 클러스터의 파드를 나타내는 사각형이 상태를 표시하도록 색상으로 구분됩니다. 배포 보드의 사각형 위로 마우스를 가져가면 배포 상태가 표시되고, 사각형을 선택하면 파드의 로그 페이지로 이동합니다.

비록 이 예시는 현재 애플리케이션을 호스팅하는 파드 하나만 보여주지만, **설정** > **CI/CD** > **변수**에서 [`REPLICAS` CI/CD 변수](../cicd_variables.md)를 정의하여 더 많은 파드를 추가할 수 있습니다.

### 브랜치 작업 {#work-with-branches}

다음으로, 애플리케이션에 콘텐츠를 추가할 기능 브랜치를 생성합니다:

1. 프로젝트 리포지토리에서 다음 파일로 이동합니다: `app/views/welcome/index.html.erb`. 이 파일은 다음 단락만 포함해야 합니다: `<p>You're on Rails!</p>`.
1. GitLab [웹 IDE](../../../user/project/web_ide/_index.md)를 열어 변경합니다.
1. 파일이 다음을 포함하도록 편집합니다:

   ```html
   <p>You're on Rails! Powered by GitLab Auto DevOps.</p>
   ```

1. 파일을 스테이징합니다. 커밋 메시지를 추가한 후 **커밋**을 선택하여 새 브랜치와 머지 리퀘스트를 생성합니다.

   ![웹 IDE 커밋](img/guide_ide_commit_v12_3.png)

머지 리퀘스트를 제출한 후, GitLab은 [이전에 설명한](#deploy-the-application) 대로 파이프라인 및 파이프라인의 모든 작업을 실행하고, 기본 브랜치 이외의 브랜치에서만 실행되는 몇 가지 추가 작업을 실행합니다.

몇 분 후 테스트가 실패합니다. 즉, 변경으로 인해 테스트가 '깨졌음'을 의미합니다. 실패한 `test` 작업을 선택하여 자세한 정보를 확인합니다:

```plaintext
Failure:
WelcomeControllerTest#test_should_get_index [/app/test/controllers/welcome_controller_test.rb:7]:
<You're on Rails!> expected but was
<You're on Rails! Powered by GitLab Auto DevOps.>..
Expected 0 to be >= 1.

bin/rails test test/controllers/welcome_controller_test.rb:4
```

깨진 테스트를 수정하려면:

1. 머지 리퀘스트로 돌아갑니다.
1. 오른쪽 위 모서리에서 **코드**를 선택한 후 **웹 IDE에서 열기**를 선택합니다.
1. 왼쪽 파일 디렉토리에서 `test/controllers/welcome_controller_test.rb` 파일을 찾아 선택하여 엽니다.
1. 7번 줄을 `You're on Rails! Powered by GitLab Auto DevOps.`로 변경합니다
1. 왼쪽 사이드바에서 **소스 제어** ({{< icon name="merge" >}})를 선택합니다.
1. 커밋 메시지를 작성하고 **커밋**을 선택합니다.

머지 리퀘스트의 **개요** 페이지로 돌아가면, 테스트가 통과할 뿐만 아니라 애플리케이션이 [리뷰 애플리케이션](../stages.md#auto-review-apps)으로 배포된 것을 볼 수 있습니다. **앱 보기** {{< icon name="external-link" >}} 버튼을 선택하여 배포된 변경 사항을 볼 수 있습니다.

머지 리퀘스트를 병합한 후, GitLab은 기본 브랜치에서 파이프라인을 실행한 후 애플리케이션을 프로덕션으로 배포합니다.

## 결론 {#conclusion}

이 프로젝트를 구현한 후, 자동 DevOps의 기본 사항을 확실히 이해해야 합니다. 빌드 및 테스트에서 GitLab 내의 애플리케이션 배포 및 모니터링까지 시작했습니다. 자동 특성에도 불구하고 자동 DevOps를 구성하고 사용자 지정하여 워크플로우에 맞게 할 수 있습니다. 다음은 추가 읽기를 위한 몇 가지 유용한 리소스입니다:

1. [Auto DevOps](../_index.md)
1. [여러 Kubernetes 클러스터](../multiple_clusters_auto_devops.md)
1. [프로덕션에 점진적 롤아웃](../cicd_variables.md#incremental-rollout-to-production)
1. [CI/CD 변수로 필요하지 않은 작업 비활성화](../cicd_variables.md)
1. [자신의 빌드팩을 사용하여 애플리케이션 빌드](../customize.md#custom-buildpacks)
