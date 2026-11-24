---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: CI/CD 변수
---

CI/CD 변수를 사용하여 Auto DevOps 도메인을 설정하고, 사용자 정의 Helm 차트를 제공하거나 애플리케이션을 확장합니다.

## 빌드 및 배포 변수 {#build-and-deployment-variables}

이 변수를 사용하여 빌드를 사용자 정의하고 배포합니다.

| **CI/CD 변수**                      | **설명** |
|-----------------------------------------|-----------------|
| `ADDITIONAL_HOSTS`                      | Ingress 호스트에 추가되는 쉼표로 구분된 목록으로 지정된 정규화된 도메인 이름입니다. |
| `<ENVIRONMENT>_ADDITIONAL_HOSTS`        | 특정 환경의 경우 Ingress 호스트에 추가되는 쉼표로 구분된 목록으로 지정된 정규화된 도메인 이름입니다. 이것은 `ADDITIONAL_HOSTS`보다 우선합니다. |
| `AUTO_BUILD_IMAGE_VERSION`              | `build` 작업에 사용할 이미지 버전을 사용자 정의합니다. [버전 목록](https://gitlab.com/gitlab-org/cluster-integration/auto-build-image/-/releases)을 참조하세요. |
| `AUTO_DEPLOY_IMAGE_VERSION`             | Kubernetes 배포 작업에 사용되는 이미지 버전을 사용자 정의합니다. [버전 목록](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/releases)을 참조하세요. |
| `AUTO_DEVOPS_ATOMIC_RELEASE`            | Auto DevOps는 기본적으로 Helm 배포에 [`--atomic`](https://v2.helm.sh/docs/helm/#options-43)를 사용합니다. 이 변수를 `false`로 설정하여 `--atomic`의 사용을 비활성화합니다. |
| `AUTO_DEVOPS_BUILD_IMAGE_CNB_BUILDER`   | Cloud Native Buildpacks로 빌드할 때 사용되는 빌더입니다. 기본 빌더는 `heroku/buildpacks:22`입니다. [자세히 알아보기](stages.md#auto-build-using-cloud-native-buildpacks). |
| `AUTO_DEVOPS_BUILD_IMAGE_EXTRA_ARGS`    | `docker build` 명령에 전달할 추가 인수입니다. 따옴표를 사용해도 단어 분할을 방지할 수 없습니다. [자세히 알아보기](customize.md#pass-arguments-to-docker-build). |
| `AUTO_DEVOPS_BUILD_IMAGE_FORWARDED_CI_VARIABLES` | [CI/CD 변수 이름의 쉼표로 구분된 목록](customize.md#forward-cicd-variables-to-the-build-environment)을 빌드 환경(buildpack 빌더 또는 `docker build`)으로 전달합니다. |
| `AUTO_DEVOPS_BUILD_IMAGE_CNB_PORT`      | 생성된 Docker 이미지에 의해 노출된 포트입니다. `false`로 설정하여 포트 노출을 방지합니다. 기본값은 `5000`입니다. |
| `AUTO_DEVOPS_BUILD_IMAGE_CONTEXT`       | Dockerfile 및 Cloud Native Buildpacks의 빌드 컨텍스트 디렉터리를 설정하는 데 사용됩니다. 기본값은 루트 디렉터리입니다. |
| `AUTO_DEVOPS_CHART`                     | 앱을 배포하는 데 사용되는 Helm 차트입니다. 기본값은 [GitLab에서 제공하는](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app) 것입니다. |
| `AUTO_DEVOPS_CHART_REPOSITORY`          | 차트를 검색하는 데 사용되는 Helm 차트 리포지토리입니다. 기본값은 `https://charts.gitlab.io`입니다. |
| `AUTO_DEVOPS_CHART_REPOSITORY_NAME`     | Helm 리포지토리의 이름을 설정하는 데 사용됩니다. 기본값은 `gitlab`입니다. |
| `AUTO_DEVOPS_CHART_REPOSITORY_USERNAME` | Helm 리포지토리에 연결할 사용자 이름을 설정하는 데 사용됩니다. 기본값은 자격증명 없음입니다. `AUTO_DEVOPS_CHART_REPOSITORY_PASSWORD`도 설정하세요. |
| `AUTO_DEVOPS_CHART_REPOSITORY_PASSWORD` | Helm 리포지토리에 연결할 암호를 설정하는 데 사용됩니다. 기본값은 자격증명 없음입니다. `AUTO_DEVOPS_CHART_REPOSITORY_USERNAME`도 설정하세요. |
| `AUTO_DEVOPS_CHART_REPOSITORY_PASS_CREDENTIALS` | 차트 아티팩트가 리포지토리와 다른 호스트에 있을 때 Helm 리포지토리 자격증명을 차트 서버로 전달할 수 있도록 하려면 0이 아닌 값으로 설정합니다. |
| `AUTO_DEVOPS_CHART_REPOSITORY_INSECURE` | Helm 명령에 `--insecure-skip-tls-verify` 인수를 추가하려면 0이 아닌 값으로 설정합니다. 기본적으로 Helm은 TLS 검증을 사용합니다. |
| `AUTO_DEVOPS_CHART_CUSTOM_ONLY`         | 사용자 정의 차트만 사용하려면 0이 아닌 값으로 설정합니다. 기본적으로 최신 차트는 GitLab에서 다운로드됩니다. |
| `AUTO_DEVOPS_CHART_VERSION`             | 배포 차트의 버전을 설정합니다. 기본값은 최신 사용 가능한 버전입니다. |
| `AUTO_DEVOPS_COMMON_NAME`               | TLS 인증서에 사용되는 일반 이름을 사용자 정의하려면 유효한 도메인 이름으로 설정합니다. 기본값은 `le-$CI_PROJECT_ID.$KUBE_INGRESS_BASE_DOMAIN`입니다. 이 대체 호스트를 Ingress에 설정하지 않으려면 `false`로 설정합니다. |
| `AUTO_DEVOPS_DEPLOY_DEBUG`              | 이 변수가 있으면 Helm이 디버그 로그를 출력합니다. |
| `AUTO_DEVOPS_ALLOW_TO_FORCE_DEPLOY_V<N>` | [auto-deploy-image](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image) v1.0.0부터 이 변수가 있으면 새로운 주요 버전의 차트가 강제로 배포됩니다. 자세한 내용은 [경고를 무시하고 배포 계속](upgrading_auto_deploy_dependencies.md#ignore-warnings-and-continue-deploying)을 참조하세요. |
| `BUILDPACK_URL`                         | 완전한 Buildpack URL입니다. [Pack에서 지원하는 URL을 가리켜야 합니다](customize.md#custom-buildpacks). |
| `CANARY_ENABLED`                        | [카나리 환경에 대한 배포 정책](#deploy-policy-for-canary-environments)을 정의하는 데 사용됩니다. |
| `BUILDPACK_VOLUMES`                     | 하나 이상의 [Buildpack 볼륨을 마운트](stages.md#mount-volumes-into-the-build-container)하도록 지정합니다. 목록 구분 기호로 파이프 `\|`를 사용합니다. |
| `CANARY_PRODUCTION_REPLICAS`            | 프로덕션 환경에서 [카나리 배포](../../user/project/canary_deployments.md)를 배포할 카나리 복제본 수입니다. `CANARY_REPLICAS`보다 우선합니다. 기본값은 1입니다. |
| `CANARY_REPLICAS`                       | [카나리 배포](../../user/project/canary_deployments.md)를 배포할 카나리 복제본 수입니다. 기본값은 1입니다. |
| `CI_APPLICATION_REPOSITORY`             | 구축 또는 배포되는 컨테이너 이미지의 리포지토리인 `$CI_APPLICATION_REPOSITORY:$CI_APPLICATION_TAG`입니다. 자세한 내용은 [사용자 정의 컨테이너 이미지](customize.md#custom-container-image)를 읽으세요. |
| `CI_APPLICATION_TAG`                    | 구축 또는 배포되는 컨테이너 이미지의 태그인 `$CI_APPLICATION_REPOSITORY:$CI_APPLICATION_TAG`입니다. 자세한 내용은 [사용자 정의 컨테이너 이미지](customize.md#custom-container-image)를 읽으세요. |
| `DAST_AUTO_DEPLOY_IMAGE_VERSION`        | 기본 브랜치에서 DAST 배포에 사용되는 이미지 버전을 사용자 정의합니다. 일반적으로 `AUTO_DEPLOY_IMAGE_VERSION`과 동일해야 합니다. [버전 목록](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/releases)을 참조하세요. |
| `DOCKERFILE_PATH`                       | [빌드 단계의 기본 Dockerfile 경로](customize.md#custom-dockerfiles)를 재정의할 수 있습니다. |
| `HELM_RELEASE_NAME`                     | `helm` 릴리스 이름을 재정의할 수 있습니다. 여러 프로젝트를 단일 네임스페이스에 배포할 때 고유한 릴리스 이름을 할당하는 데 사용할 수 있습니다. |
| `HELM_UPGRADE_VALUES_FILE`              | `helm upgrade` 값 파일을 재정의할 수 있습니다. 기본값은 `.gitlab/auto-deploy-values.yaml`입니다. |
| `HELM_UPGRADE_EXTRA_ARGS`               | 애플리케이션을 배포할 때 `helm upgrade` 명령에서 추가 옵션을 허용합니다. 따옴표를 사용해도 단어 분할을 방지할 수 없습니다. |
| `INCREMENTAL_ROLLOUT_MODE`              | 있으면 프로덕션 환경에 대해 애플리케이션의 [점진적 롤아웃](#incremental-rollout-to-production)을 활성화하는 데 사용할 수 있습니다. 수동 배포 작업의 경우 `manual`로 설정하거나 5분 간격의 자동 롤아웃 배포의 경우 `timed`로 설정합니다. |
| `K8S_SECRET_*`                          | [`K8S_SECRET_`](#configure-application-secret-variables)로 시작하는 모든 변수는 Auto DevOps에 의해 배포된 애플리케이션에 환경 변수로 제공됩니다. |
| `KUBE_CONTEXT`                          | `KUBECONFIG`에서 사용할 컨텍스트를 선택하는 데 사용할 수 있습니다. `KUBE_CONTEXT`가 비어 있으면 `KUBECONFIG`의 기본 컨텍스트(있는 경우)가 사용됩니다. [Kubernetes용 에이전트와 함께](../../user/clusters/agent/ci_cd_workflow.md) 사용할 때 컨텍스트를 선택해야 합니다. |
| `KUBE_INGRESS_BASE_DOMAIN`              | 클러스터당 도메인을 설정하는 데 사용할 수 있습니다. 자세한 내용은 [클러스터 도메인](../../user/project/clusters/gitlab_managed_clusters.md#base-domain)을 참조하세요. |
| `KUBE_NAMESPACE`                        | 배포에 사용되는 네임스페이스입니다. 인증서 기반 클러스터를 사용할 때 [이 값을 직접 덮어쓰면 안 됩니다](../../user/project/clusters/deploy_to_cluster.md#custom-namespace). |
| `KUBECONFIG`                            | 배포에 사용할 kubeconfig입니다. 사용자가 제공한 값은 GitLab에서 제공한 값보다 우선합니다. |
| `PRODUCTION_REPLICAS`                   | 프로덕션 환경에 배포할 복제본 수입니다. `REPLICAS`보다 우선하며 기본값은 1입니다. 무중단 업그레이드의 경우 2 이상으로 설정합니다. |
| `REPLICAS`                              | 배포할 복제본 수입니다. 기본값은 1입니다. [수정](customize.md#customize-helm-chart-values) `replicaCount` 대신 이 변수를 변경합니다. |
| `ROLLOUT_RESOURCE_TYPE`                 | 사용자 정의 Helm 차트를 사용할 때 배포되는 리소스 유형의 지정을 허용합니다. 기본값은 `deployment`입니다. |
| `ROLLOUT_STATUS_DISABLED`               | 모든 리소스 유형을 지원하지 않으므로 롤아웃 상태 확인을 비활성화하는 데 사용됩니다. 예를 들어 `cronjob`입니다. |
| `STAGING_ENABLED`                       | [스테이징 및 프로덕션 환경에 대한 배포 정책](#deploy-policy-for-staging-and-production-environments)을 정의하는 데 사용됩니다. |
| `TRACE`                                 | 모든 값으로 설정하여 Helm 명령이 상세 출력을 생성하도록 합니다. 이 설정을 사용하여 Auto DevOps 배포 문제를 진단할 수 있습니다. |

## 데이터베이스 변수 {#database-variables}

> [!warning]
> `POSTGRES_ENABLED`는 더 이상 기본적으로 설정되지 않습니다.

이 변수를 사용하여 CI/CD를 PostgreSQL 데이터베이스와 통합합니다.

| **CI/CD 변수**                            | **설명**                    |
|-----------------------------------------|------------------------------------|
| `DB_INITIALIZE`                         | 애플리케이션의 PostgreSQL 데이터베이스를 초기화하기 위해 실행할 명령을 지정하는 데 사용됩니다. 애플리케이션 Pod 내부에서 실행됩니다. |
| `DB_MIGRATE`                            | 애플리케이션의 PostgreSQL 데이터베이스를 마이그레이션하기 위해 실행할 명령을 지정하는 데 사용됩니다. 애플리케이션 Pod 내부에서 실행됩니다. |
| `POSTGRES_ENABLED`                      | PostgreSQL이 활성화되어 있는지 여부입니다. `true`로 설정하여 PostgreSQL의 자동 배포를 활성화합니다. |
| `POSTGRES_USER`                         | PostgreSQL 사용자입니다. 기본값은 `user`입니다. 사용자 정의 사용자 이름을 사용하도록 설정합니다. |
| `POSTGRES_PASSWORD`                     | PostgreSQL 암호입니다. 기본값은 `testing-password`입니다. 사용자 정의 암호를 사용하도록 설정합니다. |
| `POSTGRES_DB`                           | PostgreSQL 데이터베이스 이름입니다. [`$CI_ENVIRONMENT_SLUG`](../../ci/variables/_index.md#predefined-cicd-variables)의 값으로 기본값이 설정됩니다. 사용자 정의 데이터베이스 이름을 사용하도록 설정합니다. |
| `POSTGRES_VERSION`                      | 사용할 [`postgres` Docker 이미지](https://hub.docker.com/_/postgres)의 태그입니다. 기본값은 테스트 및 배포의 경우 `9.6.16`입니다. `AUTO_DEVOPS_POSTGRES_CHANNEL`가 `1`로 설정된 경우 배포는 기본 버전 `9.6.2`을 사용합니다. |
| `POSTGRES_HELM_UPGRADE_VALUES_FILE`     | [auto-deploy-image v2](upgrading_auto_deploy_dependencies.md)를 사용할 때 이 변수를 사용하면 PostgreSQL용 `helm upgrade` 값 파일을 재정의할 수 있습니다. 기본값은 `.gitlab/auto-deploy-postgres-values.yaml`입니다. |
| `POSTGRES_HELM_UPGRADE_EXTRA_ARGS`      | [auto-deploy-image v2](upgrading_auto_deploy_dependencies.md)를 사용할 때 이 변수를 사용하면 애플리케이션을 배포할 때 `helm upgrade` 명령에서 추가 PostgreSQL 옵션을 허용합니다. 따옴표를 사용해도 단어 분할을 방지할 수 없습니다. |
| `POSTGRES_CHART_REPOSITORY`             | PostgreSQL 차트를 검색하는 데 사용되는 Helm 차트 리포지토리입니다. 기본값은 `https://raw.githubusercontent.com/bitnami/charts/eb5f9a9513d987b519f0ecd732e7031241c50328/bitnami`입니다. |
| `POSTGRES_CHART_VERSION`                | PostgreSQL 차트에 사용되는 Helm 차트 버전입니다. 기본값은 `8.2.1`입니다. |

## 작업 건너뛰기 변수 {#job-skipping-variables}

 이 변수를 사용하여 특정 유형의 CI/CD 작업을 건너뜁니다. 건너뛸 때 CI/CD 작업이 생성되거나 실행되지 않습니다.

| **작업 이름**                           | **CI/CD 변수**              | **GitLab 버전**    | **설명** |
|----------------------------------------|---------------------------------|-----------------------|-----------------|
| `.fuzz_base`                           | `COVFUZZ_DISABLED`              |                       | [자세히 알아보기](../../user/application_security/coverage_fuzzing/_index.md) `.fuzz_base`가 고유한 작업에 어떤 기능을 제공하는지에 대해. 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `apifuzzer_fuzz`                       | `API_FUZZING_DISABLED`          |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `build`                                | `BUILD_DISABLED`                |                       | 변수가 있으면 작업이 생성되지 않습니다. |
| `build_artifact`                       | `BUILD_DISABLED`                |                       | 변수가 있으면 작업이 생성되지 않습니다. |
| `brakeman-sast`                        | `SAST_DISABLED`                 |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `canary`                               | `CANARY_ENABLED`                |                       | 변수가 있으면 이 수동 작업이 생성됩니다. |
| `code_intelligence`                    | `CODE_INTELLIGENCE_DISABLED`    |                       | 변수가 있으면 작업이 생성되지 않습니다. |
| `code_quality`                         | `CODE_QUALITY_DISABLED`         |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `container_scanning`                   | `CONTAINER_SCANNING_DISABLED`   |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `dast`                                 | `DAST_DISABLED`                 |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `dast_environment_deploy`              | `DAST_DISABLED_FOR_DEFAULT_BRANCH` 또는 `DAST_DISABLED`  |                        | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `dependency_scanning`                  | `DEPENDENCY_SCANNING_DISABLED`  |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `flawfinder-sast`                      | `SAST_DISABLED`                 |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `gemnasium-dependency_scanning`        | `DEPENDENCY_SCANNING_DISABLED`  |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `gemnasium-maven-dependency_scanning`  | `DEPENDENCY_SCANNING_DISABLED`  |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `gemnasium-python-dependency_scanning` | `DEPENDENCY_SCANNING_DISABLED`  |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `kubesec-sast`                         | `SAST_DISABLED`                 |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `license_scanning`                     | `LICENSE_MANAGEMENT_DISABLED`   |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. [GitLab 15.9부터](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/111071) 작업이 사용 중단되었습니다. |
| `load_performance`                     | `LOAD_PERFORMANCE_DISABLED`     |                       | 변수가 있으면 작업이 생성되지 않습니다. |
| `nodejs-scan-sast`                     | `SAST_DISABLED`                 |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `browser_performance`                  | `BROWSER_PERFORMANCE_DISABLED`  |                       | 브라우저 성능입니다. 변수가 있으면 작업이 생성되지 않습니다. |
| `phpcs-security-audit-sast`            | `SAST_DISABLED`                 |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `pmd-apex-sast`                        | `SAST_DISABLED`                 |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `review`                               | `REVIEW_DISABLED`               |                       | 변수가 있으면 작업이 생성되지 않습니다. |
| `review:stop`                          | `REVIEW_DISABLED`               |                       | 수동 작업입니다. 변수가 있으면 작업이 생성되지 않습니다. |
| `secret_detection`                     | `SECRET_DETECTION_DISABLED`     |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `secret_detection_default_branch`      | `SECRET_DETECTION_DISABLED`     |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `semgrep-sast`                         | `SAST_DISABLED`                 |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `sobelow-sast`                         | `SAST_DISABLED`                 |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `stop_dast_environment`                | `DAST_DISABLED_FOR_DEFAULT_BRANCH` 또는 `DAST_DISABLED` |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `spotbugs-sast`                        | `SAST_DISABLED`                 |                       | 값이 `"true"`이면 작업이 생성되지 않습니다. |
| `test`                                 | `TEST_DISABLED`                 |                       | 변수가 있으면 작업이 생성되지 않습니다. |
| `staging`                              | `STAGING_ENABLED`               |                       | 변수가 있으면 작업이 생성됩니다. |
| `stop_review`                          | `REVIEW_DISABLED`               |                       | 변수가 있으면 작업이 생성되지 않습니다. |

## 애플리케이션 시크릿 변수 구성 {#configure-application-secret-variables}

배포된 일부 애플리케이션은 시크릿 변수에 대한 액세스가 필요합니다. Auto DevOps는 `K8S_SECRET_`로 시작하는 CI/CD 변수를 감지하고 배포된 애플리케이션에 환경 변수로 제공합니다.

전제 조건:

- 변수 값은 한 줄이어야 합니다.

시크릿 변수를 구성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **변수**를 펼칩니다.
1. 접두사 `K8S_SECRET_`로 CI/CD 변수를 생성합니다. 예를 들어 `K8S_SECRET_RAILS_MASTER_KEY`라는 변수를 생성할 수 있습니다.
1. Auto DevOps 파이프라인을 실행합니다. 이는 수동으로 새 파이프라인을 만들거나 GitLab에 코드 변경 사항을 푸시하여 수행할 수 있습니다.

### Kubernetes 시크릿 {#kubernetes-secrets}

Auto DevOps 파이프라인은 애플리케이션 시크릿 변수를 사용하여 Kubernetes 시크릿을 채웁니다. 이 시크릿은 환경마다 고유합니다. 애플리케이션을 배포할 때 시크릿은 애플리케이션을 실행하는 컨테이너의 환경 변수로 로드됩니다. 예를 들어 `K8S_SECRET_RAILS_MASTER_KEY`이라는 시크릿을 생성하면 Kubernetes 시크릿은 다음과 같이 표시될 수 있습니다:

```shell
$ kubectl get secret production-secret -n minimal-ruby-app-54 -o yaml

apiVersion: v1
data:
  RAILS_MASTER_KEY: MTIzNC10ZXN0
kind: Secret
metadata:
  creationTimestamp: 2018-12-20T01:48:26Z
  name: production-secret
  namespace: minimal-ruby-app-54
  resourceVersion: "429422"
  selfLink: /api/v1/namespaces/minimal-ruby-app-54/secrets/production-secret
  uid: 57ac2bfd-03f9-11e9-b812-42010a9400e4
type: Opaque
```

## 애플리케이션 시크릿 업데이트 {#update-application-secrets}

환경 변수는 일반적으로 Kubernetes Pod에서 불변입니다. 애플리케이션 시크릿을 업데이트한 후 수동으로 새 파이프라인을 만들면 실행 중인 애플리케이션이 업데이트된 시크릿을 수신하지 않습니다.

애플리케이션 시크릿을 업데이트하려면 다음 중 하나를 수행합니다:

- Kubernetes 배포를 강제로 Pod를 재생성하기 위해 GitLab에 코드 업데이트를 푸시합니다.
- 실행 중인 Pod를 수동으로 삭제하여 Kubernetes가 업데이트된 시크릿으로 새 Pod를 생성하도록 합니다.

Auto DevOps 스크립팅 환경의 제한으로 인해 여러 줄 값을 가진 변수는 지원되지 않습니다.

## 복제본 변수 구성 {#configure-replica-variables}

배포를 확장하려면 복제본 변수를 추가합니다:

1. [프로젝트 CI/CD 변수](../../ci/variables/_index.md#for-a-project)로 복제본 변수를 추가합니다.
1. 애플리케이션을 확장하려면 다시 배포합니다.

   > [!warning]
   > Kubernetes를 직접 사용하여 애플리케이션을 확장하지 마세요. Helm이 변경 사항을 감지하지 못할 수 있으며 Auto DevOps를 사용한 후속 배포가 변경 사항을 취소할 수 있습니다.

### 사용자 정의 복제본 변수 {#custom-replica-variables}

`<TRACK>_<ENV>_REPLICAS` 형식으로 사용자 정의 복제본 변수를 만들 수 있습니다:

- `<TRACK>`는 Helm 차트 앱 정의에서 설정된 `track` [Kubernetes 레이블](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)의 모두 대문자 값입니다. `track`가 설정되지 않은 경우 사용자 정의 변수에서 `<TRACK>`를 생략합니다.
- `<ENV>`는 `.gitlab-ci.yml`에서 설정된 배포 작업의 모두 대문자 환경 이름입니다.

예를 들어 환경이 `qa`이고 트랙이 `foo`인 경우 `FOO_QA_REPLICAS`이라는 환경 변수를 만듭니다:

```yaml
QA testing:
  stage: deploy
  environment:
    name: qa
  script:
    - deploy foo
```

트랙 `foo`은 애플리케이션의 Helm 차트에서 정의해야 합니다. 예를 들어:

```yaml
replicaCount: 1
image:
  repository: gitlab.example.com/group/project
  tag: stable
  pullPolicy: Always
  secrets:
    - name: gitlab-registry
application:
  track: foo
  tier: web
service:
  enabled: true
  name: web
  type: ClusterIP
  url: http://my.host.com/
  externalPort: 5000
  internalPort: 5000
```

## 스테이징 및 프로덕션 환경에 대한 배포 정책 {#deploy-policy-for-staging-and-production-environments}

Auto DevOps는 일반적으로 지속적인 배포를 사용하며 기본 브랜치에서 새 파이프라인이 실행될 때마다 `production` 환경에 자동으로 푸시합니다. 프로덕션에 수동으로 배포하려면 `STAGING_ENABLED` CI/CD 변수를 사용할 수 있습니다.

`STAGING_ENABLED`을 설정하면 GitLab이 애플리케이션을 `staging` 환경에 자동으로 배포합니다. 프로덕션에 배포할 준비가 되면 GitLab이 `production_manual` 작업을 생성합니다.

[프로젝트 설정](requirements.md#auto-devops-deployment-strategy)에서 수동 배포를 활성화할 수도 있습니다.

## 카나리 환경에 대한 배포 정책 {#deploy-policy-for-canary-environments}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

프로덕션에 변경 사항을 배포하기 전에 [카나리 환경](../../user/project/canary_deployments.md)을 사용할 수 있습니다.

`CANARY_ENABLED`을 설정하면 GitLab이 두 개의 [수동 작업](../../ci/pipelines/_index.md#add-manual-interaction-to-your-pipeline)을 생성합니다:

- `canary` - 애플리케이션을 카나리 환경에 배포합니다.
- `production_manual` - 애플리케이션을 프로덕션에 배포합니다.

## 프로덕션으로의 점진적 롤아웃 {#incremental-rollout-to-production}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

점진적 롤아웃을 사용하여 애플리케이션을 지속적으로 배포합니다. 처음에는 몇 개의 Pod로만 시작합니다. Pod 수를 수동으로 증가시킬 수 있습니다.

[프로젝트 설정](requirements.md#auto-devops-deployment-strategy)에서 수동 배포를 활성화하거나 `INCREMENTAL_ROLLOUT_MODE`를 `manual`로 설정하여 활성화할 수 있습니다.

`INCREMENTAL_ROLLOUT_MODE`을 `manual`로 설정하면 GitLab이 4개의 수동 작업을 생성합니다:

1. `rollout 10%`
1. `rollout 25%`
1. `rollout 50%`
1. `rollout 100%`

백분율은 `REPLICAS` CI/CD 변수를 기반으로 하며 배포에 사용할 Pod 수를 정의합니다. 예를 들어 값이 `10`이고 `10%` 롤아웃 작업을 실행하면 애플리케이션이 Pod 1개에만 배포됩니다.

롤아웃 작업을 어떤 순서로든 실행할 수 있습니다. 축소하려면 더 낮은 백분율 작업을 다시 실행합니다.

`rollout 100%` 작업을 실행한 후 축소할 수 없으며 [배포를 롤백](../../ci/environments/deployments.md#retry-or-roll-back-a-deployment)해야 합니다.

### 점진적 롤아웃 구성 예 {#example-incremental-rollout-configurations}

`INCREMENTAL_ROLLOUT_MODE`없이 `STAGING_ENABLED`도 없이:

![증분 롤아웃 및 스테이징이 모두 비활성화된 CI/CD 워크플로우 시각화 그래프](img/rollout_staging_disabled_v11_0.png)

`INCREMENTAL_ROLLOUT_MODE`없이 `STAGING_ENABLED`와 함께:

![증분 롤아웃이 비활성화되고 스테이징이 활성화된 CI/CD 워크플로우 시각화 그래프](img/staging_enabled_v11_0.png)

`INCREMENTAL_ROLLOUT_MODE`을 `manual`로 설정하고 `STAGING_ENABLED`없이:

![증분 롤아웃이 활성화되고 스테이징이 비활성화된 CI/CD 워크플로우 시각화 그래프](img/rollout_enabled_v10_8.png)

`INCREMENTAL_ROLLOUT_MODE`을 `manual`로 설정하고 `STAGING_ENABLED`과 함께:

![증분 롤아웃 및 스테이징이 모두 활성화된 CI/CD 워크플로우 시각화 그래프](img/rollout_staging_enabled_v11_0.png)

## 프로덕션으로의 시간 제한 점진적 롤아웃 {#timed-incremental-rollout-to-production}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

시간 제한 점진적 롤아웃을 사용하여 애플리케이션을 지속적으로 배포합니다. 처음에는 몇 개의 Pod로만 시작합니다.

[프로젝트 설정](requirements.md#auto-devops-deployment-strategy)에서 시간 제한 증분 배포를 활성화하거나 `INCREMENTAL_ROLLOUT_MODE` CI/CD 변수를 `timed`로 설정하여 활성화할 수 있습니다.

`INCREMENTAL_ROLLOUT_MODE`을 `timed`로 설정하면 GitLab이 4개의 작업을 생성합니다:

1. `timed rollout 10%`
1. `timed rollout 25%`
1. `timed rollout 50%`
1. `timed rollout 100%`

작업 간에 5분 지연이 있습니다.
