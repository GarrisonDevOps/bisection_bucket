---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 고급 SAST Swift 및 Objective-C 구성
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  베타

{{< /details >}}

{{< history >}}

- GitLab 19.3에서 [베타](../../../policy/development_stages_support.md#beta)로 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/16318)되었습니다.
- 점진적 스캔이 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249721)되었습니다.

{{< /history >}}

GitLab Advanced SAST는 파일 간, 함수 간 테인트 분석을 사용하여 Swift 및 Objective-C 코드를 분석하며, [GitLab Advanced SAST](gitlab_advanced_sast.md) 범위를 iOS 애플리케이션으로 확장합니다.

Swift 및 Objective-C 분석은 별도의 CI/CD 작업 `gitlab-advanced-sast-ext`로 실행되며, 자체 컨테이너 이미지로 제공됩니다. 추가 구성이 필요하지 않습니다. GitLab Advanced SAST가 활성화되면 리포지토리에 Swift (`.swift`), Objective-C (`.m`) 또는 Objective-C++ (`.mm`) 파일이 포함된 경우 작업이 실행됩니다.

## GitLab Advanced SAST Swift 및 Objective-C 분석 활성화 {#turn-on-gitlab-advanced-sast-swift-and-objective-c-analysis}

사전 요구 사항:

- [GitLab Advanced SAST 활성화](gitlab_advanced_sast.md#turn-on-gitlab-advanced-sast)하세요.

Swift 및 Objective-C 분석은 지원되는 다른 언어와 동일한 활성화 변수를 사용합니다:

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  GITLAB_ADVANCED_SAST_ENABLED: "true"
```

이 변수가 설정되고 리포지토리에 Swift 또는 Objective-C 파일이 포함되어 있으면 GitLab이 `gitlab-advanced-sast-ext` 작업을 파이프라인의 `test` 스테이지에 추가합니다.

## GitLab Advanced SAST Swift 및 Objective-C 분석 비활성화 {#turn-off-gitlab-advanced-sast-swift-and-objective-c-analysis}

다른 언어에 대해 GitLab Advanced SAST를 활성화된 상태로 유지하면서 Swift 및 Objective-C 분석을 비활성화하려면 `gitlab-advanced-sast-ext`을 `SAST_EXCLUDED_ANALYZERS` 변수에 추가하세요:

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  GITLAB_ADVANCED_SAST_ENABLED: "true"
  SAST_EXCLUDED_ANALYZERS: "gitlab-advanced-sast-ext"
```

Swift 및 Objective-C 분석을 포함한 GitLab Advanced SAST를 완전히 비활성화하려면 `GITLAB_ADVANCED_SAST_ENABLED`을 `"false"`로 설정하세요.

`GITLAB_ADVANCED_SAST_ENABLED`이 그룹 CI/CD 변수로 설정된 경우 프로젝트의 `.gitlab-ci.yml` 파일에 있는 값이 이를 재정의하지 않습니다. 그룹 변수를 재정의하려면 동일한 이름의 프로젝트 CI/CD 변수를 정의하세요. 자세한 내용은 [CI/CD 변수 우선순위](../../../ci/variables/_index.md#cicd-variable-precedence)를 참조하세요.

## 점진적 스캔 {#incremental-scanning}

점진적 스캔은 기본적으로 활성화됩니다. 분석기는 파이프라인 실행 간에 테인트 분석 저장소를 캐시한 후 코드가 변경되거나 종속성이 변경된 파일만 다시 분석하고 변경되지 않은 코드의 캐시된 결과를 재사용합니다. 이는 대부분의 코드가 커밋 간에 변경되지 않는 대규모 코드베이스에서 스캔 시간을 줄입니다.

다른 GitLab Advanced SAST 언어의 경우 동일한 기능은 [점진적 스캔](gitlab_advanced_sast.md#incremental-scanning)이며, 기본적으로 비활성화되어 있고 다른 CI/CD 변수로 구성됩니다.

`gitlab-advanced-sast-ext` 작업은 작업의 `cache:`을 사용하여 저장소를 파이프라인 전체에서 이월하며, 기본 브랜치로 폴백되는 브랜치로 키가 설정됩니다.

캐시 재사용을 위해서는 러너가 이전 캐시에 액세스할 수 있어야 합니다. 인스턴스에서 [분산 캐싱](https://docs.gitlab.com/runner/configuration/autoscale/#distributed-runners-caching)이 없는 여러 러너를 사용하는 경우 저장소를 사용할 수 없으며 분석기가 전체 스캔을 수행합니다.

### 점진적 스캔 비활성화 {#turn-off-incremental-scanning}

점진적 스캔을 비활성화하고 매번 실행할 때마다 모든 코드를 스캔하려면 `GITLAB_ADVANCED_SAST_EXT_INCREMENTAL_ENABLED` 변수를 `"false"`로 설정하세요:

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  GITLAB_ADVANCED_SAST_ENABLED: "true"
  GITLAB_ADVANCED_SAST_EXT_INCREMENTAL_ENABLED: "false"
```

### 캐시 비활성화 {#disable-the-cache}

점진적 스캔을 비활성화하면 `cache:`이 활성 상태로 유지되므로 모든 파이프라인이 여전히 저장소를 업로드 및 다운로드합니다. 저장소가 유지되므로 점진적 스캔을 다시 활성화하고 즉시 재사용할 수 있습니다.

모든 파이프라인에서 캐시 비용을 제거하려면 빈 `cache:`으로 작업을 재정의하세요:

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  GITLAB_ADVANCED_SAST_ENABLED: "true"

gitlab-advanced-sast-ext:
  cache: []
```

캐시가 비활성화되면 모든 파이프라인이 전체 스캔을 실행하고 캐시 비용을 지불하지 않습니다. 그 후 점진적 스캔을 다시 활성화하면 저장소를 준비하기 위해 한 번의 전체 스캔이 필요합니다.

## 취약성 범위 {#vulnerability-coverage}

분석기는 파일 및 함수 전체에서 신뢰할 수 없는 입력을 소스에서 취약한 싱크로 추적합니다. SQL 주입 및 민감한 정보의 일반 텍스트 전송과 같은 일반적인 약점 유형 외에도 iOS 특정 API 및 데이터 흐름을 모델링합니다:

- 신뢰할 수 없는 입력 소스로 깊은 링크 및 사용자 지정 URL 스킴입니다.
- Keychain 항목 접근성 클래스입니다.
- `UserDefaults`, 붙여넣기판 및 로컬 파일에 민감한 데이터를 저장합니다.
- WebKit 및 UIWebView 콘텐츠 로딩입니다.

분석기가 감지하는 약점 유형의 전체 목록을 보려면 [Swift 및 Objective-C CWE 범위](advanced_sast_coverage.md#swift-and-objective-c-cwe-coverage)를 참조하세요.

## FIPS 파이프라인 {#fips-pipelines}

베타 기간 동안 Swift 및 Objective-C 분석에는 FIPS 지원 이미지를 사용할 수 없습니다. 다른 분석기와 마찬가지로 FIPS 호환 이미지는 GitLab Advanced SAST 및 Semgrep 기반 분석기에만 사용할 수 있습니다.

[FIPS 지원 이미지](_index.md#fips-enabled-images)를 사용하는 파이프라인에서 `gitlab-advanced-sast-ext` 작업은 계속 실행되지만 FIPS 지원 이미지를 가져올 수 없어 실패합니다. SAST를 FIPS 호환 방식으로 사용하려면 [Swift 및 Objective-C 분석 비활성화](#turn-off-gitlab-advanced-sast-swift-and-objective-c-analysis)하세요.

## 알려진 이슈 {#known-issues}

베타 기간 동안 Swift 및 Objective-C 분석에는 다음과 같은 알려진 문제가 있습니다:

- [오프라인 환경](../offline_deployments/_index.md)은 지원되지 않습니다.
- 결과가 Semgrep 기반 SAST 분석기의 결과와 중복 제거되지 않습니다. 두 분석기가 Swift 또는 Objective-C 파일에서 동일한 취약성을 감지하면 두 결과가 모두 보고됩니다.
- [사용자 지정 규칙 집합](customize_rulesets.md)은 지원되지 않습니다.
- [차이 기반 스캔](gitlab_advanced_sast.md#diff-based-scanning)은 지원되지 않습니다.
