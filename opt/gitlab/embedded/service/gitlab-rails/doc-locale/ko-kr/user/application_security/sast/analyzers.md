---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: SAST 분석기
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [GitLab Ultimate에서 GitLab Free로 이동](https://gitlab.com/groups/gitlab-org/-/epics/2098)됨 (13.3).

{{< /history >}}

SAST(정적 애플리케이션 보안 테스팅)는 분석기를 사용하여 소스 코드의 취약성을 감지합니다. 각 분석기는 [스캐너](../terminology/_index.md#scanner)(타사 코드 분석 도구)의 래퍼입니다.

분석기는 SAST가 각 분석을 위해 전용 컨테이너를 시작하는 데 사용하는 Docker 이미지로 게시됩니다. 분석기의 일관된 성능을 보장하기 위해 최소 4GB RAM을 권장합니다.

SAST 기본 이미지는 GitLab에서 유지 관리하지만 자신의 커스텀 이미지를 통합할 수도 있습니다.

각 스캐너의 경우 분석기는:

- 검사 로직을 노출합니다.
- 실행을 처리합니다.
- 출력을 [표준 형식](../terminology/_index.md#secure-report-format)으로 변환합니다.

## 공식 분석기 {#official-analyzers}

SAST는 다음의 공식 분석기를 지원합니다:

- [`gitlab-advanced-sast`](gitlab_advanced_sast.md) - 파일 간 및 함수 간 오염 분석 및 향상된 탐지 정확도를 제공합니다. Ultimate만 해당입니다.
- [`gitlab-advanced-sast-ext`](advanced_sast_swift_objc.md) - Swift 및 Objective-C에 대한 파일 간 및 함수 간 오염 분석을 제공합니다. Ultimate만 해당입니다. 베타.
- [`kubesec`](https://gitlab.com/gitlab-org/security-products/analyzers/kubesec) - Kubesec을 기반으로 합니다. 기본적으로 꺼져 있습니다. [KubeSec 분석기 활성화](_index.md#enabling-kubesec-analyzer)를 참조하세요.
- [`pmd-apex`](https://gitlab.com/gitlab-org/security-products/analyzers/pmd-apex) - Apex 언어용 규칙을 포함한 PMD를 기반으로 합니다.
- [`semgrep`](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep) - Semgrep OSS 엔진 [GitLab 관리 규칙](rules.md#semgrep-based-analyzer)을 기반으로 합니다.
- [`sobelow`](https://gitlab.com/gitlab-org/security-products/analyzers/sobelow) - Sobelow를 기반으로 합니다.
<!-- vale gitlab_base.OxfordComma = NO -->
- [`spotbugs`](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs) - Find Sec Bugs 플러그인(Ant, Gradle 및 래퍼, Grails, Maven 및 래퍼, SBT)을 포함한 SpotBugs를 기반으로 합니다.
<!-- vale gitlab_base.OxfordComma = YES -->

### 지원되는 버전 {#supported-versions}

공식 분석기는 GitLab 플랫폼과 별도로 컨테이너 이미지로 릴리스됩니다. 각 분석기 버전은 제한된 GitLab 버전 세트와 호환됩니다.

분석기 버전이 향후 GitLab 버전에서 더 이상 지원되지 않으면 이러한 변경 사항이 미리 발표됩니다. 예를 들어 [GitLab 17.0 발표](../../../update/deprecations.md#secure-analyzers-major-version-update)를 참조하세요.

지원되는 각 공식 분석기의 주요 버전은 [SAST CI/CD 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml)의 작업 정의에 반영됩니다. 이전 GitLab 버전에서 지원되는 분석기 버전을 확인하려면 [v16.11.0-ee](https://gitlab.com/gitlab-org/gitlab/-/blob/v16.11.0-ee/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml?ref_type=tags) (GitLab 16.11.0의 경우)와 같은 SAST 템플릿 파일의 과거 버전을 선택합니다.

## 지원 종료에 도달한 분석기 {#analyzers-that-have-reached-end-of-support}

다음 GitLab 분석기는 [지원 종료](../../../update/terminology.md#end-of-support) 상태에 도달했으며 업데이트를 받지 않습니다. 이들은 Semgrep 기반 분석기 [GitLab 관리 규칙](rules.md#semgrep-based-analyzer)으로 대체되었습니다.

GitLab 17.3.1 이상으로 업그레이드한 후 일회성 데이터 마이그레이션이 지원 종료에 도달한 분석기의 발견 사항을 [자동으로 해결](_index.md#automatic-vulnerability-resolution)합니다. 이는 SpotBugs를 제외한 아래 나열된 모든 분석기를 포함합니다. SpotBugs는 여전히 Groovy 코드를 스캔하기 때문입니다. 마이그레이션은 확인하거나 거부하지 않은 취약성만 해결하며, [Semgrep 기반 스캔으로 자동 변환](#transition-to-semgrep-based-scanning)된 취약성에는 영향을 주지 않습니다. 자세한 내용은 [이슈 444926](https://gitlab.com/gitlab-org/gitlab/-/issues/444926)을 참조하세요.

| 분석기                                                                                                   | 스캔된 언어                                                                      | 지원 종료 GitLab 버전                                                                 |
|------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| [Bandit](https://gitlab.com/gitlab-org/security-products/analyzers/bandit)                                 | Python                                                                                 | [15.4](../../../update/deprecations.md#sast-analyzer-consolidation-and-cicd-template-changes) |
| [Brakeman](https://gitlab.com/gitlab-org/security-products/analyzers/brakeman)                             | Ruby, Ruby on Rails 포함                                                          | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |
| [ESLint](https://gitlab.com/gitlab-org/security-products/analyzers/eslint) (React 및 Security 플러그인 포함) | JavaScript 및 TypeScript, React 포함                                             | [15.4](../../../update/deprecations.md#sast-analyzer-consolidation-and-cicd-template-changes) |
| [Flawfinder](https://gitlab.com/gitlab-org/security-products/analyzers/flawfinder)                         | C, C++                                                                                 | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |
| [gosec](https://gitlab.com/gitlab-org/security-products/analyzers/gosec)                                   | Go                                                                                     | [15.4](../../../update/deprecations.md#sast-analyzer-consolidation-and-cicd-template-changes) |
| [MobSF](https://gitlab.com/gitlab-org/security-products/analyzers/mobsf)                                   | Java 및 Kotlin (Android 애플리케이션만 해당); Objective-C (iOS 애플리케이션만 해당) | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |
| [NodeJsScan](https://gitlab.com/gitlab-org/security-products/analyzers/nodejs-scan)                        | JavaScript (Node.js만 해당)                                                              | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |
| [phpcs-security-audit](https://gitlab.com/gitlab-org/security-products/analyzers/phpcs-security-audit)     | PHP                                                                                    | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |
| [Security Code Scan](https://gitlab.com/gitlab-org/security-products/analyzers/security-code-scan)         | .NET (C#, Visual Basic 포함)                                                      | [16.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-160)         |
| [SpotBugs](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs)                             | Java만[^remains-supported-analyzer]                                                                  | [15.4](../../../update/deprecations.md#sast-analyzer-consolidation-and-cicd-template-changes) |
| [SpotBugs](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs)                             | Kotlin 및 Scala만[^remains-supported-analyzer]                                                      | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |

[^remains-supported-analyzer]: SpotBugs는 Groovy의 [지원되는 분석기](_index.md#supported-languages-and-frameworks)로 유지됩니다. Groovy 코드가 감지될 때만 활성화됩니다.

## SAST 분석기 기능 {#sast-analyzer-features}

분석기가 일반적으로 사용 가능한 것으로 간주되려면 다음 기능을 최소한 지원해야 합니다:

- [커스텀 가능한 구성](_index.md#available-cicd-variables)
- [커스텀 가능한 규칙 집합](customize_rulesets.md)
- [프로젝트 스캔](_index.md#supported-languages-and-frameworks)
- 다중 프로젝트 지원
- [오프라인 지원](_index.md#running-sast-in-an-offline-environment)
- [JSON 보고서 형식으로 결과 출력](_index.md#download-a-sast-report)
- [SELinux 지원](_index.md#running-sast-in-selinux)

## 분석 후 처리 {#post-analyzers}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

분석 후 처리 분석기는 분석기의 보고서 출력을 강화합니다. 분석 후 처리 분석기는 보고서 내용을 직접 수정하지 않습니다. 대신 다음과 같은 추가 속성으로 결과를 향상시킵니다:

- CWE입니다.
- 위치 추적 필드입니다.

## Semgrep 기반 스캔으로 전환 {#transition-to-semgrep-based-scanning}

[GitLab Advanced SAST 분석기](gitlab_advanced_sast.md) 외에도 GitLab은 [Semgrep 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep)도 제공하며, 이는 [여러 언어](_index.md#supported-languages-and-frameworks)를 지원합니다. GitLab은 분석기를 유지 관리하고 이를 위한 [탐지 규칙](rules.md)을 작성합니다. 이러한 규칙은 이전 릴리스에서 사용된 언어별 분석기를 대체합니다.

### 취약성 변환 {#vulnerability-translation}

취약성 관리 시스템은 자동으로 이전 분석기의 취약성을 새로운 Semgrep 기반 발견 사항으로 이동합니다. GitLab Advanced SAST 분석기로의 변환은 [GitLab Advanced SAST 설명서](gitlab_advanced_sast.md)를 참조하세요.

이 경우 시스템은 각 분석기의 취약성을 단일 레코드로 결합합니다.

그러나 다음과 같은 경우에는 취약성이 일치하지 않을 수 있습니다:

- 새로운 Semgrep 기반 규칙이 취약성을 다른 위치에서 또는 다른 방식으로 탐지하는 경우 (이전 분석기와 비교).
- 이전에 [SAST 분석기를 비활성화](#disable-specific-default-analyzers)한 경우입니다.

이는 각 취약성에 대해 필요한 식별자가 기록되는 것을 방지하여 자동 변환을 방해할 수 있습니다.

취약성이 일치하지 않으면:

- 원본 취약성은 취약성 보고서에서 "더 이상 탐지되지 않음"으로 표시됩니다.
- 그 후 Semgrep 기반 발견 사항을 기반으로 새로운 취약성이 생성됩니다.

## 분석기 커스텀하기 {#customize-analyzers}

[CI/CD 변수](_index.md#available-cicd-variables)를 `.gitlab-ci.yml` 파일에서 사용하여 분석기의 동작을 커스텀합니다.

### 커스텀 Docker 미러 사용 {#use-a-custom-docker-mirror}

GitLab 레지스트리 대신 커스텀 Docker 레지스트리를 사용하여 분석기 이미지를 호스팅할 수 있습니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.
- 커스텀 Docker 레지스트리는 모든 공식 분석기에 대한 이미지를 제공해야 합니다.

> [!note]
> 이 변수는 SAST의 분석기뿐만 아니라 모든 Secure 분석기에 영향을 줍니다.

GitLab이 분석기 이미지를 커스텀 Docker 레지스트리에서 다운로드하도록 하려면 `SECURE_ANALYZERS_PREFIX` CI/CD 변수로 접두사를 정의합니다.

예를 들어 다음은 SAST에 `registry.gitlab.com/security-products/semgrep` 대신 `my-docker-registry/gitlab-images/semgrep`를 끌어오도록 지시합니다:

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  SECURE_ANALYZERS_PREFIX: my-docker-registry/gitlab-images
```

### 모든 기본 분석기 비활성화 {#disable-all-default-analyzers}

[커스텀 분석기](#custom-analyzers)만 활성화하고 모든 기본 SAST 분석기를 비활성화할 수 있습니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.

모든 기본 분석기를 비활성화하려면 CI/CD 변수 `SAST_DISABLED`을(를) `"true"`로 설정하고 `.gitlab-ci.yml` 파일에서 설정합니다.

예:

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  SAST_DISABLED: "true"
```

### 특정 기본 분석기 비활성화 {#disable-specific-default-analyzers}

분석기는 감지된 소스 코드 언어에 따라 자동으로 실행됩니다. 그러나 특정 분석기를 비활성화할 수 있습니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.

특정 분석기를 비활성화하려면 CI/CD 변수 `SAST_EXCLUDED_ANALYZERS`을(를) 실행하지 않으려는 분석기를 나열하는 쉼표로 구분된 문자열로 설정합니다.

예를 들어 `spotbugs` 분석기를 비활성화하려면:

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  SAST_EXCLUDED_ANALYZERS: "spotbugs"
```

### 커스텀 분석기 {#custom-analyzers}

CI/CD 구성에서 작업을 정의하여 자신의 분석기를 제공할 수 있습니다. 기본 분석기와의 일관성을 위해 커스텀 SAST 작업에 `-sast` 접미사를 추가해야 합니다.

#### 커스텀 분석기 예시 {#example-custom-analyzer}

이 예시는 Docker 이미지 `my-docker-registry/analyzers/csharp`을(를) 기반으로 스캔 작업을 추가하는 방법을 보여줍니다. 스크립트 `/analyzer run`을(를) 실행하고 SAST 보고서 `gl-sast-report.json`을(를) 출력합니다.

`.gitlab-ci.yml` 파일에서 다음을 정의합니다:

```yaml
csharp-sast:
  image:
    name: "my-docker-registry/analyzers/csharp"
  script:
    - /analyzer run
  artifacts:
    reports:
      sast: gl-sast-report.json
```
