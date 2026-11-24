---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Harbor
description: GitLab 프로젝트의 오픈소스 컨테이너 레지스트리로 Harbor를 구성하여 플랫폼 전체에서 아티팩트를 관리합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 프로젝트의 컨테이너 레지스트리로 Harbor를 사용할 수 있습니다.

[Harbor](https://goharbor.io/)는 Kubernetes 및 Docker와 같은 클라우드 네이티브 컴퓨팅 플랫폼 전체에서 아티팩트를 관리하는 데 도움이 되는 오픈소스 레지스트리입니다.

GitLab CI/CD와 컨테이너 이미지 리포지토리가 필요한 경우 Harbor 통합이 도움이 될 수 있습니다.

## 사전 요구 사항 {#prerequisites}

Harbor 인스턴스에서 다음을 확인합니다:

- 통합할 프로젝트가 생성되었습니다.
- 인증된 사용자는 Harbor 프로젝트에서 이미지를 가져오기, 푸시 및 편집할 수 있는 권한이 있습니다.

## GitLab 구성 {#configure-gitlab}

GitLab은 그룹 또는 프로젝트 수준에서 Harbor 프로젝트 통합을 지원합니다. GitLab에서 다음 단계를 완료하세요:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Harbor**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. Harbor 구성 정보를 제공합니다:
   - **Harbor URL**: 이 GitLab 프로젝트에 연결되는 Harbor 인스턴스의 기본 URL입니다. 예를 들어, `https://harbor.example.net`입니다.
   - **Harbor 프로젝트 이름**: Harbor 인스턴스의 프로젝트 이름입니다. 예를 들어, `testproject`입니다.
   - **사용자명**: Harbor 인스턴스의 사용자명이며, [필수 조건](#prerequisites)에서 요구 사항을 충족해야 합니다.
   - **비밀번호**: 사용자명의 패스워드입니다.

1. **변경 사항 저장**을 선택합니다.

Harbor 통합이 활성화된 후:

- 전역 변수 `$HARBOR_USERNAME`, `$HARBOR_HOST`, `$HARBOR_OCI`, `$HARBOR_PASSWORD`, `$HARBOR_URL`, 그리고 `$HARBOR_PROJECT`은 CI/CD 사용을 위해 생성됩니다.
- 프로젝트 수준 통합 설정이 그룹 수준 통합 설정을 재정의합니다.

## 보안 고려 사항 {#security-considerations}

### Harbor API에 대한 요청 보안 {#secure-your-requests-to-the-harbor-apis}

Harbor 통합을 통한 각 API 요청의 경우, Harbor API 연결을 위한 자격 증명은 `username:password` 조합을 사용합니다. 안전한 사용을 위한 제안 사항은 다음과 같습니다:

- 연결하는 Harbor API에 TLS을 사용합니다.
- 자격 증명으로 최소 권한 원칙(Harbor 액세스)을 따릅니다.
- 자격 증명에 대한 회전 정책을 수립합니다.

### CI/CD 변수 보안 {#cicd-variable-security}

`.gitlab-ci.yml` 파일에 푸시된 악의적인 코드는 `$HARBOR_PASSWORD`를 포함한 변수를 손상시킬 수 있으며 이를 제3자 서버로 전송할 수 있습니다. 자세한 내용은 [CI/CD 변수 보안](../../../ci/variables/_index.md#cicd-variable-security)을 참조하세요.

## Harbor 변수 사용 {#use-harbor-variables}

### OCI 레지스트리를 사용하여 Helm 차트 푸시 {#push-a-helm-chart-with-an-oci-registry}

Helm은 기본적으로 OCI 레지스트리를 지원합니다. OCI는 [Harbor 2.0](https://github.com/goharbor/harbor/releases/tag/v2.0.0) 이상에서 지원됩니다. Helm [블로그](https://helm.sh/blog/storing-charts-in-oci/) 및 [문서](https://helm.sh/docs/topics/registries/#enabling-oci-support)에서 OCI에 대해 자세히 알아보세요.

```yaml
helm:
  stage: helm
  image:
    name: dtzar/helm-kubectl:latest
    entrypoint: ['']
  variables:
    # Enable OCI support (not required since Helm v3.8.0)
    HELM_EXPERIMENTAL_OCI: 1
  script:
    # Log in to the Helm registry
    - helm registry login "${HARBOR_URL}" -u "${HARBOR_USERNAME}" -p "${HARBOR_PASSWORD}"
    # Package your Helm chart, which is in the `test` directory
    - helm package test
    # Your helm chart is created with <chart name>-<chart release>.tgz
    # You can push all building charts to your Harbor repository
    - helm push test-*.tgz ${HARBOR_OCI}/${HARBOR_PROJECT}
```
