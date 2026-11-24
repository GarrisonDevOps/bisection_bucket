---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 코드 기반 인프라 스캔
description: "취약성 감지, 구성 분석 및 파이프라인 통합입니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

코드 기반 인프라(IaC) 스캔은 CI/CD 파이프라인에서 실행되며 인프라 정의 파일에서 알려진 취약성을 확인합니다. 취약성을 기본 브랜치에 커밋하기 전에 파악하여 애플리케이션의 위험을 사전에 해결합니다.

IaC 스캔 분석기는 JSON 형식의 보고서를 [작업 아티팩트](../../../ci/yaml/artifacts_reports.md#artifactsreportssast)로 출력합니다.

GitLab Ultimate를 사용하면 IaC 스캔 결과도 처리되므로 다음을 수행할 수 있습니다:

- 머지 리퀘스트에서 확인합니다.
- 승인 워크플로우에서 사용합니다.
- 취약성 보고서에서 검토합니다.

## 시작하기 {#getting-started}

IaC 스캔이 처음이라면 다음 단계를 따라 프로젝트에서 활성화합니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.
- 일관된 성능을 위해 최소 4GB RAM이 필요합니다.
- Docker 또는 Kubernetes 실행기가 있는 Linux 기반 러너. GitLab.com에서 호스팅되는 러너를 사용하는 경우 Docker 또는 Kubernetes 실행기가 기본적으로 활성화됩니다.
  - Windows의 GitLab Runner는 지원되지 않습니다.
  - AMD64 이외의 CPU 아키텍처는 지원되지 않습니다.
- GitLab CI/CD 구성(`.gitlab-ci.yml`)에는 `test` 스테이지가 포함되어야 합니다. `test` 스테이지는 기본적으로 포함되지만, 스테이지를 다시 정의하면 명시적으로 추가해야 합니다.

IaC 스캔을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **빌드** > **파이프라인** 편집기로 이동합니다.
1. IaC 스캔 CI/CD 템플릿 또는 컴포넌트를 추가합니다.

   템플릿을 사용하려면 다음 줄을 추가합니다:

   ```yaml
   include:
     - template: Jobs/SAST-IaC.gitlab-ci.yml
   ```

   CI/CD 구성 요소를 사용하려면 다음 줄을 추가합니다:

   ```yaml
   include:
     - component: gitlab.com/components/sast/iac-sast@main
   ```

1. **검증** 탭을 선택한 후 **파이프라인 검증**을 선택합니다.

   **시뮬레이션이 성공적으로 완료되었습니다** 메시지는 파일이 유효함을 확인합니다.
1. **편집** 탭을 선택합니다.
1. 필드를 완성합니다:
   - 커밋 메시지.
   - 브랜치. 예를 들어, `add-iac`입니다.
1. **이 변경 사항으로 새로운 머지 리퀘스트 시작** 확인란을 선택한 후 **변경 사항 커밋**을 선택합니다.

   머지 리퀘스트 페이지가 열립니다.
1. 표준 워크플로에 따라 필드를 완성한 후 **머지 리퀘스트 생성**을 선택합니다.
1. 표준 워크플로에 따라 머지 리퀘스트를 검토하고 편집한 후 **머지**를 선택합니다.

이 시점에서 IaC 스캔이 파이프라인에서 활성화됩니다:

- IaC 스캔 작업이 모든 파이프라인에서 실행되고 KICS 분석기가 실행됩니다.
- 분석기가 프로젝트에 지원되는 IaC 파일이 있는지 확인합니다.
- 지원되는 파일이 있으면 분석기가 취약성을 스캔합니다.
- 지원되는 파일이 없으면 작업이 발견 없이 완료됩니다.

해당 작업이 파이프라인의 `test` 스테이지 아래에 표시됩니다.

[IaC 스캔 예제 프로젝트](https://gitlab.com/gitlab-org/security-products/demos/analyzer-configurations/kics/iac-getting-started)에서 작동하는 예제를 볼 수 있습니다.

### 다음 단계 {#next-steps}

IaC 스캔을 활성화한 후 다음을 수행할 수 있습니다:

- [결과 이해하기](#understanding-the-results)에 대해 더 알아봅니다
- [최적화 팁](#optimize-iac-scanning)을 검토합니다
- [더 많은 프로젝트로의 확대](#roll-out)를 계획합니다

## 결과 이해 {#understanding-the-results}

사전 요구 사항:

- 프로젝트에 대한 보안 관리자, Developer, Maintainer 또는 Owner 역할.

파이프라인에서 취약성을 검토할 수 있습니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. 파이프라인을 선택합니다.
1. **보안** 탭을 선택합니다.
1. 취약성을 선택하여 다음을 포함한 세부 정보를 확인하세요:
   - 설명:  취약성의 원인, 잠재적 영향 및 권장 수정 단계를 설명합니다.
   - 상태:  취약성이 심사되었는지 또는 해결되었는지 여부를 나타냅니다.
   - 심각도:  [심각도 수준에 대해 자세히 알아보기](../vulnerabilities/severities.md).
   - 위치:  이슈가 발견된 파일 이름과 줄 번호를 표시합니다. 파일 경로를 선택하면 코드 보기에서 해당 줄이 열립니다.
   - 스캐너:  취약성을 탐지한 분석기를 식별합니다.
   - 식별자:  취약성을 분류하는 데 사용되는 참조 목록(예: CWE 식별자 및 이를 감지한 규칙의 ID).

Ultimate에서는 보안 스캔 결과를 다운로드할 수도 있습니다:

사전 요구 사항:

- 프로젝트에 대한 보안 관리자, Developer, Maintainer 또는 Owner 역할.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. 파이프라인을 선택합니다.
1. **보안** 탭을 선택합니다.
1. 파이프라인의 **보안** 탭에서 **결과 다운로드**를 선택합니다.

자세한 내용은 [파이프라인 보안 보고서](../detect/security_scanning_results.md)를 참조하세요.

> [!note]
> 발견 사항은 피처 브랜치에서 생성됩니다. 결과가 기본 브랜치에 병합되면 취약성이 됩니다. 이 구분은 보안 태세를 평가할 때 중요합니다.

IaC 스캔 결과를 확인하는 추가 방법:

- [머지 리퀘스트 보고서](../../project/merge_requests/reports.md): 새로 도입되었거나 해결된 결과를 표시합니다.
- [머지 리퀘스트 변경 보기](../sast/_index.md#merge-request-changes-view): 변경된 줄에 대한 인라인 주석을 표시합니다.
- [취약성 보고서](../vulnerability_report/_index.md): 기본 브랜치에서 확인된 취약성을 표시합니다.

## 지원되는 언어 및 프레임워크 {#supported-languages-and-frameworks}

IaC 스캔은 다양한 IaC 구성 파일을 지원합니다. 지원되는 구성 파일이 프로젝트에서 감지되면 [KICS](https://kics.io/)를 사용하여 스캔됩니다. IaC 구성 파일의 혼합이 있는 프로젝트도 지원됩니다.

지원되는 구성 형식:

- Ansible
- AWS CloudFormation
- Azure Resource Manager

  > [!note]
  > IaC 스캔은 JSON 형식의 Azure Resource Manager 템플릿을 분석할 수 있습니다. [Bicep](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/overview)에서 템플릿을 작성하면 [Bicep CLI](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/bicep-cli)를 사용하여 Bicep 파일을 JSON으로 변환한 후 IaC 스캔이 분석할 수 있습니다.

- Dockerfile
- Google Deployment Manager
- Kubernetes
- OpenAPI
- Terraform

  KICS는 쿼리가 있는 리소스 타입에 대해서만 발견 사항을 보고합니다. KICS는 다음 공급자에 대한 Terraform 쿼리를 보유하고 있습니다:

  - Alibaba Cloud
  - AWS
  - Azure
  - Databricks
  - GitHub
  - Google Cloud
  - Kubernetes
  - NIFCLOUD
  - Tencent Cloud

  KICS는 공급자 독립적인 검사도 보유하고 있습니다. 다른 공급자의 경우 이러한 검사만 적용됩니다. 자세한 내용은 [KICS 플랫폼](https://docs.kics.io/latest/platforms/)을 참고합니다.

  > [!note]
  > 사용자 지정 레지스트리의 Terraform 모듈은 취약성에 대해 스캔되지 않습니다. 제안된 기능에 대한 자세한 내용은 [이슈 357004](https://gitlab.com/gitlab-org/gitlab/-/issues/357004)를 참고합니다.

## IaC 스캔 최적화 {#optimize-iac-scanning}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

IaC 스캔을 최적화하여 노이즈를 줄이고 관련 발견 사항에 초점을 맞출 수 있습니다:

- `sast-ruleset.toml` 파일을 사용하여 특정 규칙을 비활성화합니다.
- `sast-ruleset.toml` 파일을 사용하여 규칙 특성(심각도 등)을 재정의합니다.
- 해당 파일에서 KICS 주석을 사용하여 특정 파일의 스캔을 비활성화합니다.

IaC 스캔은 규칙 추가 또는 교체를 지원하지 않습니다. 각 분석기가 지원하는 옵션은 [규칙 사용자 지정 옵션](../sast/customize_rulesets.md#rule-customization-options)을 참고합니다.

`sast-ruleset.toml` 파일을 사용하여 규칙을 비활성화하거나 규칙 특성을 재정의합니다. 이 방법은 다음과 같은 이점을 제공합니다:

- 규칙이 비활성화될 때 기존 발견 사항을 자동으로 해결하기 위해 GitLab 취약성 관리와 통합됩니다.
- 보안 정책 결정의 버전 관리 문서입니다.
- IaC 스캔을 확대할 때 여러 프로젝트 간에 규칙 집합을 공유하는 옵션입니다.

### 규칙 집합 정의 {#ruleset-definition}

모든 IaC 스캔 규칙은 `ruleset` 섹션에 포함되어 있으며 다음이 포함됩니다:

- 규칙에 대한 `type` 필드입니다. IaC 스캔의 경우 식별자 타입은 `kics_id`입니다.
- 규칙 식별자에 대한 `value` 필드입니다. KICS 규칙 식별자는 영숫자 문자열입니다. 규칙 식별자를 찾으려면:
  - [JSON 보고서 아티팩트](#reports-json-format)에서 찾습니다.
  - [KICS 쿼리 목록](https://docs.kics.io/latest/queries/all-queries/)에서 규칙 이름을 검색하고 표시되는 영숫자 식별자를 복사합니다. 규칙 위반이 감지되면 [취약성 세부 정보 페이지](../vulnerabilities/_index.md)에 규칙 이름이 표시됩니다.

### 규칙 비활성화 {#disable-rules}

특정 IaC 스캔 규칙을 비활성화할 수 있습니다. 비활성화된 규칙으로 이전에 감지된 발견 사항은 [자동으로 해결](#automatic-vulnerability-resolution)됩니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.

분석기 규칙을 비활성화하려면:

1. 프로젝트의 루트에 `.gitlab` 디렉터리를 생성합니다(아직 없는 경우).
1. `sast-ruleset.toml` 디렉터리에 `.gitlab`라는 이름의 사용자 지정 규칙 집합 파일을 생성합니다(아직 없는 경우).
1. `ruleset` 섹션의 컨텍스트에서 `disabled` 플래그를 `true`로 설정합니다.
1. 하나 이상의 `ruleset` 하위 섹션에서 비활성화할 규칙을 나열합니다.

`sast-ruleset.toml` 파일을 기본 브랜치에 병합한 후 비활성화된 규칙의 기존 발견 사항은 [자동으로 해결](#automatic-vulnerability-resolution)됩니다.

다음 예제 `sast-ruleset.toml` 파일에서 비활성화된 규칙은 식별자의 `type`과(와) `value`을(를) 일치시켜 `kics` 분석기에 할당됩니다:

```toml
[kics]
  [[kics.ruleset]]
    disable = true
    [kics.ruleset.identifier]
      type = "kics_id"
      value = "8212e2d7-e683-49bc-bf78-d6799075c5a7"

  [[kics.ruleset]]
    disable = true
    [kics.ruleset.identifier]
      type = "kics_id"
      value = "b03a748a-542d-44f4-bb86-9199ab4fd2d5"
```

### 파일 스캔 비활성화 {#disable-scanning-of-a-file}

파일의 스캔을 완전히 또는 특정 규칙에 대해서만 비활성화하려면 해당 파일에서 [KICS 주석](https://docs.kics.io/latest/running-kics/#using_commands_on_scanned_files_as_comments)을 사용합니다.

이 기능은 일부 유형의 IaC 파일에서만 사용 가능합니다. 지원되는 파일 타입의 목록은 [KICS 문서](https://docs.kics.io/latest/running-kics/#using_commands_on_scanned_files_as_comments)를 참고합니다.

- 전체 파일의 스캔을 건너뛰려면 파일의 맨 위에 `# kics-scan ignore`을(를) 주석으로 추가합니다.
- 전체 파일에서 특정 규칙을 비활성화하려면 파일의 맨 위에 `# kics-scan disable=<kics_id>`을(를) 주석으로 추가합니다.

### 규칙 재정의 {#override-rules}

특정 IaC 스캔 규칙을 재정의하여 사용자 지정할 수 있습니다. 예를 들어 규칙에 낮은 심각도를 할당하거나 발견 사항을 수정하는 방법에 대한 자신의 문서에 연결할 수 있습니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.

규칙을 재정의하려면:

1. 프로젝트의 루트에 `.gitlab` 디렉터리를 생성합니다(아직 없는 경우).
1. `sast-ruleset.toml` 디렉터리에 `.gitlab`라는 이름의 사용자 지정 규칙 집합 파일을 생성합니다(아직 없는 경우).
1. 하나 이상의 `ruleset.identifier` 하위 섹션에서 재정의할 규칙을 나열합니다.
1. `ruleset` 섹션의 `ruleset.override` 컨텍스트에서 재정의할 키를 제공합니다. 키의 모든 조합을 재정의할 수 있습니다. 유효한 키는 다음과 같습니다:
   - description
   - message
   - name
   - severity(유효한 옵션은: Critical, High, Medium, Low, Unknown, Info)

다음 예제 `sast-ruleset.toml` 파일에서 규칙은 식별자의 `type`과(와) `value`으로 일치하고 재정의됩니다:

```toml
[kics]
  [[kics.ruleset]]
    [kics.ruleset.identifier]
      type = "kics_id"
      value = "8212e2d7-e683-49bc-bf78-d6799075c5a7"
    [kics.ruleset.override]
      description = "OVERRIDDEN description"
      message = "OVERRIDDEN message"
      name = "OVERRIDDEN name"
      severity = "Info"
```

## 오프라인 구성 {#offline-configuration}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

오프라인 환경에서는 인터넷을 통한 외부 리소스에 대한 접근이 제한되거나 간헐적입니다. 이러한 환경의 인스턴스의 경우 IaC에는 일부 구성 변경이 필요합니다. 이 섹션의 지침은 [오프라인 환경](../offline_deployments/_index.md)에 자세히 설명된 지침과 함께 완료되어야 합니다.

### GitLab Runner 구성 {#configure-gitlab-runner}

기본적으로 러너는 로컬 복사본이 있어도 GitLab 컨테이너 레지스트리에서 Docker 이미지를 가져오려고 시도합니다. Docker 이미지가 최신 상태로 유지되도록 이 기본 설정을 사용해야 합니다. 그러나 네트워크 연결이 없으면 기본 GitLab Runner `pull_policy` 변수를 변경해야 합니다.

GitLab Runner CI/CD 변수 `pull_policy`을(를) [`if-not-present`](https://docs.gitlab.com/runner/executors/docker/#using-the-if-not-present-pull-policy)로 구성합니다.

### 로컬 IaC 분석기 이미지 사용 {#use-local-iac-analyzer-image}

GitLab 컨테이너 레지스트리 대신 로컬 Docker 레지스트리에서 이미지를 가져오려면 로컬 IaC 분석기 이미지를 사용합니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.
- 로컬 오프라인 Docker 레지스트리로 Docker 이미지를 가져오는 것은 네트워크 보안 정책에 따라 다릅니다. IT 직원에게 문의하여 외부 리소스를 가져오거나 임시로 액세스하는 승인된 프로세스를 찾습니다.

로컬 IaC 분석기 이미지를 사용하려면:

1. `registry.gitlab.com`에서 기본 IaC 분석기 이미지를 [로컬 Docker 컨테이너 레지스트리](../../packages/container_registry/_index.md)로 가져옵니다:

   ```plaintext
   registry.gitlab.com/security-products/kics:6
   ```

   IaC 분석기의 이미지는 [주기적으로 업데이트](../detect/vulnerability_scanner_maintenance.md)되므로 로컬 복사본을 주기적으로 업데이트해야 합니다.

1. CI/CD 변수 `SECURE_ANALYZERS_PREFIX`을(를) 로컬 Docker 컨테이너 레지스트리로 설정합니다.

   ```yaml
   include:
     - template: Jobs/SAST-IaC.gitlab-ci.yml

   variables:
     SECURE_ANALYZERS_PREFIX: "localhost:5000/analyzers"
   ```

IaC 작업은 이제 인터넷 액세스 없이 분석기 Docker 이미지의 로컬 복사본을 사용해야 합니다.

## 특정 분석기 버전 사용 {#use-a-specific-analyzer-version}

GitLab 관리 CI/CD 템플릿은 주 버전을 지정하고 해당 주 버전의 최신 분석기 릴리스를 자동으로 가져옵니다. 경우에 따라 특정 버전을 사용해야 할 수도 있습니다. 예를 들어, 이후 릴리스에서의 회귀를 피해야 할 때가 있습니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.

특정 분석기 버전을 사용하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **빌드** > **파이프라인 편집기**를 선택합니다.
1. `SAST-IaC.gitlab-ci.yml` 템플릿을 포함하는 줄 다음에 `SAST_ANALYZER_IMAGE_TAG` CI/CD 변수를 추가합니다.

   > [!note]
   > 이 변수는 특정 작업에서만 설정합니다. 최상위 수준에서 설정하면 설정한 버전이 다른 SAST 분석기에 사용됩니다.

   태그를 다음과 같이 설정합니다:

   - `3`과 같은 주 버전입니다. 파이프라인은 이 주 버전에서 릴리스되는 모든 부 또는 패치 업데이트를 사용합니다.
   - `3.7`과 같은 부 버전입니다. 파이프라인은 이 부 버전에서 릴리스되는 모든 패치 업데이트를 사용합니다.
   - `3.7.0`과 같은 패치 버전입니다. 파이프라인은 어떠한 업데이트도 받지 않습니다.

이 예제는 IaC 분석기의 특정 부 버전을 사용합니다:

```yaml
include:
  - template: Jobs/SAST-IaC.gitlab-ci.yml

kics-iac-sast:
  variables:
    SAST_ANALYZER_IMAGE_TAG: "3.1"
```

## 지원되는 배포판 {#supported-distributions}

GitLab 스캐너는 크기 및 유지 관리성을 위해 기본 Alpine 이미지와 함께 제공됩니다.

### FIPS 활성화 이미지 사용 {#use-fips-enabled-images}

GitLab은 표준 이미지 외에도 [FIPS 활성화 Red Hat UBI](https://www.redhat.com/en/blog/introducing-red-hat-universal-base-image) 버전의 스캐너 이미지를 제공합니다.

파이프라인에서 FIPS 활성화 이미지를 사용하려면 `SAST_IMAGE_SUFFIX`을(를) `-fips`로 설정하거나 표준 태그에 `-fips` 확장명을 추가합니다.

다음 예제는 `SAST_IMAGE_SUFFIX` CI/CD 변수를 사용합니다.

```yaml
variables:
  SAST_IMAGE_SUFFIX: '-fips'

include:
  - template: Jobs/SAST-IaC.gitlab-ci.yml
```

## 자동 취약성 해결 {#automatic-vulnerability-resolution}

여전히 관련이 있는 취약성에 초점을 맞추도록 IaC 스캔은 다음과 같은 경우 자동으로 취약성을 [해결](../vulnerabilities/_index.md#vulnerability-status-values)합니다:

- 사용자가 [사전 정의된 규칙을 비활성화](#disable-rules)한 경우.
- 기본 규칙 집합에서 규칙을 제거합니다.

나중에 규칙을 다시 활성화하면 결과를 다시 심사할 수 있도록 다시 열립니다.

취약성 관리 시스템은 자동으로 취약성을 해결할 때 메모를 추가합니다.

## 보고서 JSON 형식 {#reports-json-format}

IaC 스캐너는 기존 SAST 보고서 형식으로 JSON 보고서 파일을 출력합니다. 자세한 내용은 [이 보고서의 스키마](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/sast-report-format.json)를 참고합니다.

JSON 보고서 파일은 다음에서 다운로드할 수 있습니다:

- CI/CD 파이프라인 페이지입니다.
- [`artifacts: paths`을 설정하여](../../../ci/yaml/_index.md#artifactspaths) `gl-sast-report.json`로 머지 리퀘스트의 파이프라인 탭에서 설정합니다.

자세한 내용은 [아티팩트 다운로드](../../../ci/jobs/job_artifacts.md)를 참고합니다.

## 롤아웃 {#roll-out}

한 프로젝트에 대한 IaC 스캔 결과를 검증한 후 추가 프로젝트에서 동일한 방법을 구현할 수 있습니다.

- [강제 스캔 실행](../detect/security_configuration.md#create-a-shared-configuration)을 사용하여 그룹 전체에 IaC 스캔 설정을 적용합니다.
- [원격 구성 파일 지정](../sast/customize_rulesets.md#use-a-remote-ruleset-file)으로 중앙 규칙 집합을 공유하고 재사용합니다.

## 문제 해결 {#troubleshooting}

IaC 스캔을 사용할 때 다음과 같은 문제가 발생할 수 있습니다.

### IaC 스캔 발견 사항이 `No longer detected`로 표시되는 경우가 있습니다 {#iac-scanning-findings-show-as-no-longer-detected-unexpectedly}

이전에 감지된 발견 사항이 예기치 않게 `No longer detected`로 표시되면 스캐너 업데이트 때문일 수 있습니다. 업데이트로 인해 비효율적이거나 거짓 긍정인 규칙을 비활성화할 수 있으며 발견 사항은 `No longer detected`로 표시됩니다.

### 메시지 `exec /bin/sh: exec format error` (작업 로그) {#message-exec-binsh-exec-format-error-in-job-log}

작업 로그에서 `exec /bin/sh: exec format error`라는 오류가 발생할 수 있습니다. 이 문제는 AMD64 이외의 아키텍처에서 IaC 스캔 분석기를 실행하려고 할 때 발생합니다. IaC 스캔 사전 요구 사항에 대한 자세한 내용은 [사전 요구 사항](#getting-started)을 참고합니다.
