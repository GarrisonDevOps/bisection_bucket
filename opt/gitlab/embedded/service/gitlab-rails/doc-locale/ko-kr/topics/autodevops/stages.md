---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Auto DevOps의 스테이지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

다음 섹션에서는 [Auto DevOps](_index.md)의 스테이지를 설명합니다. 각 스테이지가 어떻게 작동하는지 이해하기 위해 주의 깊게 읽으세요.

## Auto Build {#auto-build}

> [!note]
> GitLab Runner에서 Docker in Docker를 사용할 수 없는 경우(예: OpenShift 클러스터) Auto Build가 지원되지 않습니다. GitLab의 OpenShift 지원은 [전용 에픽](https://gitlab.com/groups/gitlab-org/-/epics/2068)에서 추적됩니다.

Auto Build는 기존 `Dockerfile` 또는 Heroku buildpack을 사용하여 애플리케이션의 빌드를 생성합니다. 결과 Docker 이미지는 [컨테이너 레지스트리](../../user/packages/container_registry/_index.md)로 푸시되며 커밋 SHA 또는 태그로 태그됩니다.

### Dockerfile을 사용한 Auto Build {#auto-build-using-a-dockerfile}

프로젝트의 리포지토리가 루트에 `Dockerfile`를 포함하면 Auto Build는 `docker build`를 사용하여 Docker 이미지를 생성합니다.

Auto Review Apps 및 Auto Deploy도 사용하고 있으며 자신의 `Dockerfile`를 제공하기로 선택한 경우 다음 중 하나를 수행해야 합니다:

- 애플리케이션을 포트 `5000`로 노출합니다. [기본 Helm 차트](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app)는 이 포트를 사용 가능한 것으로 가정합니다.
- [Auto Deploy Helm 차트 커스터마이즈](customize.md#custom-helm-chart)하여 기본값을 재정의합니다.

### Cloud Native Buildpack을 사용한 Auto Build {#auto-build-using-cloud-native-buildpacks}

Auto Build는 프로젝트의 `Dockerfile`이 있으면 이를 사용하여 애플리케이션을 빌드합니다. `Dockerfile`이 없으면 Auto Build는 [Cloud Native Buildpack](https://buildpacks.io)을 사용하여 애플리케이션을 감지하고 Docker 이미지로 빌드합니다. 이 기능은 [`pack` 명령](https://github.com/buildpacks/pack)을 사용합니다. 기본 [빌더](https://buildpacks.io/docs/for-app-developers/concepts/builder/)는 `heroku/buildpacks:22`이지만 CI/CD 변수 `AUTO_DEVOPS_BUILD_IMAGE_CNB_BUILDER`을 사용하여 다른 빌더를 선택할 수 있습니다.

각 buildpack은 Auto Build가 애플리케이션을 성공적으로 빌드하기 위해 프로젝트의 리포지토리에 특정 파일을 포함해야 합니다. 구조는 선택한 빌더와 buildpack에 따라 다릅니다. 예를 들어, Heroku 빌더(기본값)를 사용할 때 애플리케이션의 루트 디렉터리에는 애플리케이션 언어에 적합한 파일이 포함되어야 합니다:

- Python 프로젝트의 경우 `Pipfile` 또는 `requirements.txt` 파일입니다.
- Ruby 프로젝트의 경우 `Gemfile` 또는 `Gemfile.lock` 파일입니다.

다른 언어 및 프레임워크의 요구 사항은 [Heroku buildpack 문서](https://devcenter.heroku.com/articles/buildpacks#officially-supported-buildpacks)를 읽으세요.

> [!note]
> Auto Test는 여전히 Herokuish를 사용합니다. 테스트 스위트 감지는 아직 Cloud Native Buildpack 사양의 일부가 아니기 때문입니다. 자세한 내용은 [이슈 212689](https://gitlab.com/gitlab-org/gitlab/-/issues/212689)를 참조하세요.

#### 빌드 컨테이너에 볼륨 마운트 {#mount-volumes-into-the-build-container}

변수 `BUILDPACK_VOLUMES`을 사용하여 볼륨 마운트 정의를 `pack` 명령에 전달할 수 있습니다. 마운트는 `pack build`에 `--volume` 인수를 사용하여 전달됩니다. 각 볼륨 정의에는 `build pack`에서 제공하는 호스트 경로, 대상 경로, 볼륨이 쓰기 가능한지 여부, 하나 이상의 볼륨 옵션 등의 기능이 포함될 수 있습니다.

파이프 `|` 문자를 사용하여 여러 볼륨을 전달합니다. 목록의 각 항목은 `build back`에 별도의 `--volume` 인수를 사용하여 전달됩니다.

이 예에서 세 개의 볼륨이 `/etc/foo`, `/opt/foo`, `/var/opt/foo`로 컨테이너에 마운트됩니다:

```yaml
buildjob:
  variables:
    BUILDPACK_VOLUMES: /mnt/1:/etc/foo:ro|/mnt/2:/opt/foo:ro|/mnt/3:/var/opt/foo:rw
```

[`pack build` 문서](https://buildpacks.io/docs/for-platform-operators/how-to/integrate-ci/pack/cli/pack_build/)에서 볼륨 정의에 대해 자세히 알아보세요.

### Herokuish에서 Cloud Native Buildpack으로 이동 {#moving-from-herokuish-to-cloud-native-buildpacks}

Cloud Native Buildpack을 사용한 빌드는 Herokuish를 사용한 빌드와 동일한 옵션을 지원하지만 다음과 같은 주의 사항이 있습니다:

- buildpack은 Cloud Native Buildpack이어야 합니다. Heroku buildpack은 Heroku의 [`cnb-shim`](https://github.com/heroku/cnb-shim)를 사용하여 Cloud Native Buildpack으로 변환할 수 있습니다.
- `BUILDPACK_URL`은 [`pack`에서 지원하는](https://buildpacks.io/docs/app-developer-guide/specify-buildpacks/) 형식이어야 합니다.
- `/bin/herokuish` 명령은 빌드된 이미지에 없으며 `/bin/herokuish procfile exec`로 명령을 접두사로 붙이는 것은 더 이상 필요하지 않습니다(불가능함). 대신 사용자 정의 명령은 `/cnb/lifecycle/launcher`으로 접두사를 붙여 올바른 실행 환경을 수신해야 합니다.

## Auto Test {#auto-test}

Auto Test는 [Herokuish](https://github.com/gliderlabs/herokuish) 및 [Heroku buildpack](https://devcenter.heroku.com/articles/buildpacks)을 사용하여 프로젝트를 분석하여 언어 및 프레임워크를 감지함으로써 애플리케이션의 적절한 테스트를 실행합니다. 여러 언어 및 프레임워크는 자동으로 감지되지만 언어가 감지되지 않으면 [커스텀 buildpack](customize.md#custom-buildpacks)을 생성할 수 있습니다. [현재 지원되는 언어](#currently-supported-languages)를 확인하세요.

Auto Test는 애플리케이션에 이미 있는 테스트를 사용합니다. 테스트가 없으면 직접 추가해야 합니다.

<!-- vale gitlab_base.Spelling = NO -->

> [!note]
> [Auto Build](#auto-build)에서 지원하는 모든 buildpack이 Auto Test에서 지원되는 것은 아닙니다. Auto Test는 [Herokuish](https://gitlab.com/gitlab-org/gitlab/-/issues/212689), *아님* Cloud Native Buildpack을 사용하며, [Testpack API](https://devcenter.heroku.com/articles/testpack-api)를 구현하는 buildpack만 지원됩니다.

<!-- vale gitlab_base.Spelling = YES -->

Auto Test는 임시 PostgreSQL 데이터베이스를 프로비저닝하고 `DATABASE_URL`을 이를 가리키도록 설정합니다.

Auto Test 작업은 [`Jobs/Test.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Test.gitlab-ci.yml) 템플릿에 정의됩니다.

### 현재 지원되는 언어 {#currently-supported-languages}

모든 buildpack이 Auto Test를 지원하는 것은 아닙니다. 이는 비교적 새로운 향상 기능이기 때문입니다. Heroku의 [공식적으로 지원되는 모든 언어](https://devcenter.heroku.com/articles/heroku-ci#supported-languages)는 Auto Test를 지원합니다. Heroku의 Herokuish buildpack에서 지원하는 언어는 모두 Auto Test를 지원하지만, 특히 다중 buildpack은 지원하지 않습니다.

지원되는 buildpack은 다음과 같습니다:

```plaintext
- heroku-buildpack-multi
- heroku-buildpack-ruby
- heroku-buildpack-nodejs
- heroku-buildpack-clojure
- heroku-buildpack-python
- heroku-buildpack-java
- heroku-buildpack-gradle
- heroku-buildpack-scala
- heroku-buildpack-play
- heroku-buildpack-php
- heroku-buildpack-go
- buildpack-nginx
```

애플리케이션에 이전 목록에 없는 buildpack이 필요한 경우 [커스텀 buildpack](customize.md#custom-buildpacks)을 사용할 수 있습니다.

## Auto Code Quality {#auto-code-quality}

Auto Code Quality는 [Code Quality 이미지](https://gitlab.com/gitlab-org/ci-cd/codequality)를 사용하여 현재 코드에 대해 정적 분석 및 기타 코드 검사를 실행합니다. 보고서를 생성한 후 아티팩트로 업로드되며 나중에 다운로드하여 확인할 수 있습니다. 머지 리퀘스트 위젯은 [소스 및 대상 브랜치 간의 차이](../../ci/testing/code_quality.md)를 표시합니다.

## Auto SAST {#auto-sast}

정적 애플리케이션 보안 테스트(SAST)는 현재 코드에 대해 정적 분석을 실행하고 잠재적 보안 문제를 확인합니다. Auto SAST 스테이지는 [GitLab Runner](https://docs.gitlab.com/runner/) 11.5 이상이 필요합니다.

보고서를 생성한 후 아티팩트로 업로드되며 나중에 다운로드하여 확인할 수 있습니다. 머지 리퀘스트 위젯은 [Ultimate](https://about.gitlab.com/pricing/) 라이선스에서 보안 경고를 표시합니다.

자세한 내용은 [SAST](../../user/application_security/sast/_index.md)를 참조하세요.

## Auto 시크릿 검색 {#auto-secret-detection}

시크릿 검색은 [시크릿 검색 Docker 이미지](https://gitlab.com/gitlab-org/security-products/analyzers/secrets)를 사용하여 현재 코드를 스캔하고 유출된 시크릿을 확인합니다.

보고서를 생성한 후 아티팩트로 업로드되며 나중에 다운로드하여 평가할 수 있습니다. 머지 리퀘스트 위젯은 [Ultimate](https://about.gitlab.com/pricing/) 라이선스에서 보안 경고를 표시합니다.

자세한 내용은 [시크릿 검색](../../user/application_security/secret_detection/_index.md)을 참조하세요.

## Auto 종속성 검사 {#auto-dependency-scanning}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

종속성 검사는 프로젝트의 종속성을 분석하고 잠재적 보안 문제를 확인합니다. Auto 종속성 검사 스테이지는 [Ultimate](https://about.gitlab.com/pricing/) 이외의 라이선스에서는 건너뜁니다.

보고서를 생성한 후 아티팩트로 업로드되며 나중에 다운로드하여 확인할 수 있습니다. 머지 리퀘스트 위젯은 감지된 보안 경고를 표시합니다.

자세한 내용은 [종속성 검사](../../user/application_security/dependency_scanning/_index.md)를 참조하세요.

## Auto 컨테이너 검사 {#auto-container-scanning}

컨테이너에 대한 취약성 정적 분석은 [Trivy](https://aquasecurity.github.io/trivy/latest/)를 사용하여 Docker 이미지의 잠재적 보안 문제를 확인합니다. 자동 컨테이너 검사 스테이지는 [Ultimate](https://about.gitlab.com/pricing/) 이외의 라이선스에서는 건너뜁니다.

보고서를 생성한 후 아티팩트로 업로드되며 나중에 다운로드하여 확인할 수 있습니다. 머지 리퀘스트는 감지된 보안 문제를 표시합니다.

자세한 내용은 [컨테이너 검사](../../user/application_security/container_scanning/_index.md)를 참조하세요.

## Auto 검토 앱 {#auto-review-apps}

많은 프로젝트가 Kubernetes 클러스터를 사용할 수 없기 때문에 이는 선택적 단계입니다. [요구 사항](requirements.md)이 충족되지 않으면 작업은 자동으로 건너뜁니다.

[검토 앱](../../ci/review_apps/_index.md)은 브랜치의 코드를 기반으로 한 임시 애플리케이션 환경이므로 개발자, 디자이너, QA, 제품 관리자 및 기타 검토자가 검토 프로세스의 일부로 코드 변경 사항을 실제로 보고 상호 작용할 수 있습니다. Auto 검토 앱은 각 브랜치에 대해 검토 앱을 만듭니다.

Auto 검토 앱은 애플리케이션을 Kubernetes 클러스터에만 배포합니다. 사용 가능한 클러스터가 없으면 배포가 수행되지 않습니다.

검토 앱은 프로젝트 ID, 브랜치 또는 태그 이름, 고유 번호 및 Auto DevOps 기본 도메인의 조합을 기반으로 하는 고유한 URL을 가집니다(예: `13083-review-project-branch-123456.example.com`). 머지 리퀘스트 위젯은 쉬운 검색을 위해 검토 앱으로의 링크를 표시합니다. 브랜치 또는 태그가 삭제되면(예: 머지 리퀘스트 병합 후) 검토 앱도 삭제됩니다.

검토 앱은 [auto-deploy-app](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app) 차트로 Helm을 사용하여 배포되며 [커스터마이즈](customize.md#custom-helm-chart)할 수 있습니다. 애플리케이션은 환경에 대한 [Kubernetes 네임스페이스](../../user/project/clusters/deploy_to_cluster.md#deployment-variables)에 배포됩니다.

[로컬 Tiller](https://gitlab.com/gitlab-org/gitlab-foss/-/merge_requests/22036)를 사용합니다. 이전 버전의 GitLab은 프로젝트 네임스페이스에 Tiller를 설치했습니다.

> [!warning]
> 앱을 Helm 외부에서 조작해서는 안 됩니다(Kubernetes를 직접 사용). 이로 인해 Helm이 변경을 감지하지 못하고 Auto DevOps를 사용한 후속 배포에서 변경 사항을 실행 취소할 수 있습니다. 또한 무언가를 변경하고 다시 배포하여 실행 취소하려는 경우 Helm이 처음에는 변경 사항을 감지하지 못할 수 있으므로 이전 구성을 다시 적용해야 한다는 것을 인식하지 못할 수 있습니다.

## Auto DAST {#auto-dast}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

동적 애플리케이션 보안 테스트(DAST)는 인기 있는 오픈 소스 도구인 [OWASP ZAProxy](https://github.com/zaproxy/zaproxy)를 사용하여 현재 코드를 분석하고 잠재적 보안 문제를 확인합니다. Auto DAST 스테이지는 [Ultimate](https://about.gitlab.com/pricing/) 이외의 라이선스에서는 건너뜁니다.

- 기본 브랜치에서 DAST는 [대상 브랜치를 재정의](#overriding-the-dast-target)하지 않는 한 해당 목적을 위해 특별히 배포된 애플리케이션을 스캔합니다. DAST가 실행된 후 앱이 삭제됩니다.
- 기능 브랜치에서 DAST는 [검토 앱](#auto-review-apps)을 스캔합니다.

DAST 스캔이 완료된 후 보안 경고는 [보안 대시보드](../../user/application_security/security_dashboard/_index.md) 및 머지 리퀘스트 위젯에 표시됩니다.

자세한 내용은 [DAST](../../user/application_security/dast/_index.md)를 참조하세요.

### DAST 대상 재정의 {#overriding-the-dast-target}

자동 배포된 검토 앱 대신 사용자 정의 대상을 사용하려면 `DAST_WEBSITE` CI/CD 변수를 DAST가 스캔할 URL로 설정합니다.

> [!warning]
> [DAST Full Scan](../../user/application_security/dast/browser/_index.md)이 활성화되어 있으면 GitLab은 `DAST_WEBSITE`을 스테이징 또는 프로덕션 환경으로 설정하지 않을 것을 강력히 권고합니다. DAST Full Scan은 대상을 능동적으로 공격하여 애플리케이션을 다운시키고 데이터 손실 또는 손상을 초래할 수 있습니다.

### Auto DAST 건너뛰기 {#skipping-auto-dast}

DAST 작업을 건너뛸 수 있습니다:

- 모든 브랜치에서 `DAST_DISABLED` CI/CD 변수를 `"true"`로 설정합니다.
- 기본 브랜치에서만 `DAST_DISABLED_FOR_DEFAULT_BRANCH` 변수를 `"true"`로 설정합니다.
- 기능 브랜치에서만 `REVIEW_DISABLED` 변수를 `"true"`로 설정합니다. 이는 또한 검토 앱을 건너뜁니다.

## Auto 브라우저 성능 테스트 {#auto-browser-performance-testing}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Auto [브라우저 성능 테스트](../../ci/testing/browser_performance_testing.md)는 [Sitespeed.io 컨테이너](https://hub.docker.com/r/sitespeedio/sitespeed.io/)로 웹 페이지의 브라우저 성능을 측정하고, 각 페이지의 전체 성능 점수를 포함하는 JSON 보고서를 만들고, 보고서를 아티팩트로 업로드합니다. 기본적으로 검토 및 프로덕션 환경의 루트 페이지를 테스트합니다. 추가 URL을 테스트하려면 루트 디렉터리에 `.gitlab-urls.txt` 파일로 경로를 추가하고, 한 줄에 하나씩 추가합니다. 예를 들어:

```plaintext
/
/features
/direction
```

소스 및 대상 브랜치 간의 브라우저 성능 차이도 [머지 리퀘스트 위젯에 표시됩니다](../../ci/testing/browser_performance_testing.md).

## Auto 로드 성능 테스트 {#auto-load-performance-testing}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Auto [로드 성능 테스트](../../ci/testing/load_performance_testing.md)는 [k6 컨테이너](https://hub.docker.com/r/loadimpact/k6/)로 애플리케이션의 서버 성능을 측정하고, 여러 핵심 결과 메트릭을 포함하는 JSON 보고서를 만들고, 보고서를 아티팩트로 업로드합니다.

초기 설정이 필요합니다. 특정 애플리케이션에 맞게 작성된 [k6](https://k6.io/) 테스트가 필요합니다. 테스트는 또한 CI/CD 변수를 통해 환경의 동적 URL을 선택할 수 있도록 구성해야 합니다.

소스 및 대상 브랜치 간의 로드 성능 테스트 결과 차이도 [머지 리퀘스트 위젯에 표시됩니다](../../user/project/merge_requests/widgets.md).

## Auto Deploy {#auto-deploy}

Kubernetes 클러스터 외에도 [Amazon Elastic Compute Cloud(Amazon EC2)](https://aws.amazon.com/ec2/)에 배포할 수 있습니다.

Auto Deploy는 Auto DevOps의 선택적 단계입니다. [요구 사항](requirements.md)이 충족되지 않으면 작업이 건너뜁니다.

브랜치 또는 머지 리퀘스트가 프로젝트의 기본 브랜치에 병합된 후 Auto Deploy는 애플리케이션을 Kubernetes 클러스터의 `production` 환경에 배포하고, 프로젝트 이름 및 고유 프로젝트 ID를 기반으로 하는 네임스페이스(예: `project-4321`)를 사용합니다.

Auto Deploy는 기본적으로 스테이징 또는 카나리 환경에 배포를 포함하지 않지만 [Auto DevOps 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Auto-DevOps.gitlab-ci.yml)은 이를 활성화하려는 경우 이러한 작업에 대한 작업 정의를 포함합니다.

[CI/CD 변수](cicd_variables.md)를 사용하여 Pod 복제본을 자동으로 확장하고 Auto DevOps `helm upgrade` 명령에 사용자 정의 인수를 적용할 수 있습니다. 이는 [Auto Deploy Helm 차트를 커스터마이즈](customize.md#custom-helm-chart)하는 쉬운 방법입니다.

Helm은 [auto-deploy-app](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app) 차트를 사용하여 애플리케이션을 환경에 대한 [Kubernetes 네임스페이스](../../user/project/clusters/deploy_to_cluster.md#deployment-variables)에 배포합니다.

[로컬 Tiller](https://gitlab.com/gitlab-org/gitlab-foss/-/merge_requests/22036)를 사용합니다. 이전 버전의 GitLab은 프로젝트 네임스페이스에 Tiller를 설치했습니다.

> [!warning]
> 앱을 Helm 외부에서 조작해서는 안 됩니다(Kubernetes를 직접 사용). 이로 인해 Helm이 변경을 감지하지 못하고 Auto DevOps를 사용한 후속 배포에서 변경 사항을 실행 취소할 수 있습니다. 또한 무언가를 변경하고 다시 배포하여 실행 취소하려는 경우 Helm이 처음에는 변경 사항을 감지하지 못할 수 있으므로 이전 구성을 다시 적용해야 한다는 것을 인식하지 못할 수 있습니다.

### GitLab 배포 토큰 {#gitlab-deploy-tokens}

[GitLab 배포 토큰](../../user/project/deploy_tokens/_index.md#gitlab-deploy-token)은 Auto DevOps가 활성화되고 Auto DevOps 설정이 저장될 때 내부 및 비공개 프로젝트에 대해 생성됩니다. 배포 토큰을 사용하여 레지스트리에 영구적으로 액세스할 수 있습니다. GitLab 배포 토큰을 수동으로 취소한 후에는 자동으로 생성되지 않습니다.

GitLab 배포 토큰을 찾을 수 없으면 `CI_REGISTRY_PASSWORD`이 사용됩니다.

> [!note]
> `CI_REGISTRY_PASSWORD`는 배포 중에만 유효합니다. Kubernetes는 배포 중에 컨테이너 이미지를 성공적으로 가져올 수 있지만 Pod 제거 후와 같이 이미지를 다시 가져와야 하는 경우 Kubernetes는 `CI_REGISTRY_PASSWORD`를 사용하여 이미지를 가져오려고 하므로 그렇게 할 수 없습니다.

### Kubernetes 1.16+ {#kubernetes-116}

> [!warning]
> `deploymentApiVersion` 설정의 기본값이 `extensions/v1beta`에서 `apps/v1`로 변경되었습니다.

Kubernetes 1.16 이상에서는 많은 [API가 제거되었습니다](https://kubernetes.io/blog/2019/07/18/api-deprecations-in-1-16/). 여기에는 `extensions/v1beta1` 버전의 `Deployment` 지원이 포함됩니다.

Kubernetes 1.16+ 클러스터에서 Auto Deploy를 사용하려면:

1. 애플리케이션을 처음 배포하는 경우 구성이 필요하지 않습니다.
1. 인클러스터 PostgreSQL 데이터베이스가 `AUTO_DEVOPS_POSTGRES_CHANNEL`을 `1`로 설정하여 설치된 경우 [PostgreSQL 업그레이드 가이드](upgrading_postgresql.md)를 따릅니다.

> [!warning]
> [PostgreSQL 업그레이드 가이드](upgrading_postgresql.md)를 따라 `2` 버전을 선택하기 전에 데이터베이스를 백업 및 복원합니다.

### 마이그레이션 {#migrations}

프로젝트 CI/CD 변수 `DB_INITIALIZE` 및 `DB_MIGRATE`를 설정하여 애플리케이션 Pod 내에서 실행할 PostgreSQL에 대한 데이터베이스 초기화 및 마이그레이션을 구성할 수 있습니다.

존재하는 경우 `DB_INITIALIZE`은 Helm post-install 훅으로 애플리케이션 Pod 내의 셸 명령으로 실행됩니다. 일부 애플리케이션은 성공적인 데이터베이스 초기화 단계 없이 실행할 수 없으므로 GitLab은 애플리케이션 배포 없이 첫 번째 릴리스를 배포하고 데이터베이스 초기화 단계만 수행합니다. 데이터베이스 초기화가 완료된 후 GitLab은 표준으로 애플리케이션 배포를 포함하는 두 번째 릴리스를 배포합니다.

post-install 훅은 배포가 성공하면 `DB_INITIALIZE`이 그 이후로 처리되지 않음을 의미합니다.

존재하는 경우 `DB_MIGRATE`은 Helm pre-upgrade 훅으로 애플리케이션 Pod 내의 셸 명령으로 실행됩니다.

예를 들어 [Cloud Native Buildpack](#auto-build-using-cloud-native-buildpacks)으로 빌드된 Rails 애플리케이션의 경우:

- `DB_INITIALIZE`을 `RAILS_ENV=production /cnb/lifecycle/launcher bin/rails db:setup`로 설정할 수 있습니다.
- `DB_MIGRATE`을 `RAILS_ENV=production /cnb/lifecycle/launcher bin/rails db:migrate`로 설정할 수 있습니다.

리포지토리에 `Dockerfile`이 포함되지 않으면 이미지는 Cloud Native Buildpack으로 빌드되며, 애플리케이션이 실행되는 환경을 복제하려면 이러한 이미지에서 실행되는 명령 앞에 `/cnb/lifecycle/launcher`를 붙여야 합니다.

### Auto Deploy App 차트 업그레이드 {#upgrade-auto-deploy-app-chart}

[업그레이드 가이드](upgrading_auto_deploy_dependencies.md)에 따라 auto-deploy-app 차트를 업그레이드할 수 있습니다.

### 워커(Workers) {#workers}

일부 웹 애플리케이션은 "작업자 프로세스"에 대한 추가 배포를 실행해야 합니다. 예를 들어 Rails 애플리케이션은 일반적으로 이메일 전송과 같은 백그라운드 작업을 실행하기 위해 별도의 작업자 프로세스를 사용합니다.

Auto Deploy에서 사용되는 [기본 Helm 차트](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app)는 [작업자 프로세스 실행을 지원합니다](https://gitlab.com/gitlab-org/charts/auto-deploy-app/-/merge_requests/9).

작업자를 실행하려면 작업자가 포트 `5000`에서 성공적인 HTTP 응답을 예상하는 표준 상태 확인에 응답할 수 있어야 합니다. [Sidekiq](https://github.com/sidekiq/sidekiq)의 경우 [`sidekiq_alive` gem](https://rubygems.org/gems/sidekiq_alive)을 사용할 수 있습니다.

Sidekiq으로 작업하려면 배포에서 Redis 인스턴스에 액세스할 수 있어야 합니다. Auto DevOps는 이 인스턴스를 배포하지 않으므로 다음을 수행해야 합니다:

- 자신의 Redis 인스턴스를 유지 관리합니다.
- CI/CD 변수 `K8S_SECRET_REDIS_URL`을 설정합니다. 이는 이 인스턴스의 URL이며, 배포에 전달되도록 합니다.

작업자를 상태 확인에 응답하도록 구성한 후 Rails 애플리케이션의 Sidekiq 작업자를 실행합니다. [`.gitlab/auto-deploy-values.yaml` 파일](customize.md#customize-helm-chart-values)에서 다음을 설정하여 작업자를 활성화할 수 있습니다:

```yaml
workers:
  sidekiq:
    replicaCount: 1
    command:
      - /cnb/lifecycle/launcher
      - sidekiq
    preStopCommand:
      - /cnb/lifecycle/launcher
      - sidekiqctl
      - quiet
    terminationGracePeriodSeconds: 60
```

### 컨테이너에서 명령 실행 {#running-commands-in-the-container}

리포지토리에 [커스텀 Dockerfile](#auto-build-using-a-dockerfile)이 포함되지 않으면 [Auto Build](#auto-build)로 빌드된 애플리케이션은 다음과 같이 명령을 래핑해야 할 수 있습니다:

```shell
/cnb/lifecycle/launcher $COMMAND
```

명령을 래핑해야 할 수 있는 이유:

- `kubectl exec`를 사용하여 연결합니다.
- GitLab [웹 터미널](../../ci/environments/_index.md#web-terminals-deprecated)을 사용합니다.

예를 들어 애플리케이션 루트 디렉터리에서 Rails 콘솔을 시작하려면 다음을 실행합니다:

```shell
/cnb/lifecycle/launcher procfile exec bin/rails c
```

## Auto Code Intelligence {#auto-code-intelligence}

[GitLab 코드 인텔리전스](../../user/project/code_intelligence.md)는 통합 개발 환경(IDE)에 일반적인 코드 탐색 기능(유형 서명, 기호 문서 및 정의로 이동 포함)을 추가합니다. [LSIF](https://lsif.dev/)로 구동되며 Go 언어만 사용하는 Auto DevOps 프로젝트에서 사용할 수 있습니다. GitLab은 더 많은 LSIF 인덱서를 사용할 수 있게 되면 더 많은 언어에 대한 지원을 추가할 계획입니다. [코드 인텔리전스 에픽](https://gitlab.com/groups/gitlab-org/-/work_items/4212)을 따라 업데이트를 확인할 수 있습니다.

이 스테이지는 기본적으로 활성화됩니다. `CODE_INTELLIGENCE_DISABLED` CI/CD 변수를 추가하여 비활성화할 수 있습니다. [Auto DevOps 작업 비활성화](cicd_variables.md#job-skipping-variables)에 대해 자세히 알아보세요.
