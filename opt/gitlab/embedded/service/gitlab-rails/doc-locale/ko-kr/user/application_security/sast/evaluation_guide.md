---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 테스트 코드베이스를 선택하고 스캔을 구성하며 결과를 해석하고 다른 보안 도구와 기능을 비교하여 GitLab SAST를 평가하는 방법을 알아봅니다.
title: GitLab SAST 평가
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

조직에서 GitLab SAST를 사용하기 전에 평가하도록 선택할 수 있습니다. 평가를 계획하고 수행할 때 다음 지침을 고려하세요.

## 중요한 개념 {#important-concepts}

GitLab SAST는 팀이 작성하는 코드의 보안을 협력하여 개선하도록 설계되었습니다. 코드를 스캔하고 결과를 보기 위해 수행하는 단계는 스캔되는 소스 코드 리포지토리를 중심으로 진행됩니다.

### 스캔 프로세스 {#scanning-process}

GitLab SAST는 프로젝트에서 발견되는 프로그래밍 언어에 따라 사용할 올바른 스캔 기술을 자동으로 선택합니다. Groovy를 제외한 모든 언어의 경우, GitLab SAST는 컴파일 또는 빌드 단계를 필요로 하지 않고 소스 코드를 직접 스캔합니다. 이를 통해 다양한 프로젝트에서 스캔을 활성화하기 더 쉬워집니다. 자세한 내용은 [지원되는 언어 및 프레임워크](_index.md#supported-languages-and-frameworks)를 참조하세요.

### 취약성이 보고되는 경우 {#when-vulnerabilities-are-reported}

GitLab SAST [분석기](analyzers.md) 및 해당 [규칙](rules.md)은 개발 및 보안 팀의 노이즈를 최소화하도록 설계되었습니다.

GitLab Advanced SAST 분석기가 취약성을 보고하는 시기에 대한 자세한 내용은 [취약성 탐지 기준](gitlab_advanced_sast.md#vulnerability-detection-criteria)을 참조하세요.

### 기타 플랫폼 기능 {#other-platform-features}

SAST는 GitLab Ultimate의 다른 보안 및 규정 준수 기능과 통합됩니다. GitLab SAST를 다른 제품과 비교하는 경우, 일부 기능이 SAST 대신 관련 GitLab 기능 영역에 포함되어 있을 수 있습니다:

- [IaC 스캔](../iac_scanning/_index.md)은 코드 기반 인프라(IaC) 정의에서 보안 문제를 스캔합니다.
- [시크릿 검색](../secret_detection/_index.md)은 코드에서 유출된 시크릿을 찾습니다.
- [보안 정책](../policies/_index.md)을 통해 스캔 실행을 강제하거나 취약성을 수정하도록 요구할 수 있습니다.
- [취약성 관리 및 보고](../vulnerability_report/_index.md)는 코드베이스에 존재하는 취약성을 관리하고 이슈 추적 시스템과 통합합니다.
- GitLab Duo [취약성 설명](../analyze/duo.md) 및 [취약성 해결](../remediate/duo.md)은 AI를 사용하여 취약성을 빠르게 수정하도록 도와줍니다.

## 테스트 코드베이스 선택 {#choose-a-test-codebase}

SAST를 테스트할 코드베이스를 선택할 때 다음을 수행해야 합니다:

- 정상적인 개발 활동에 방해가 되지 않도록 CI/CD 구성을 안전하게 수정할 수 있는 리포지토리에서 테스트하세요. SAST 스캔은 CI/CD 파이프라인에서 실행되므로 CI/CD 구성을 약간 수정하여 [SAST를 활성화](_index.md#configuration)해야 합니다.
  - 테스트를 위해 기존 리포지토리의 포크 또는 복사본을 만들 수 있습니다. 이렇게 하면 정상적인 개발을 중단할 위험 없이 테스트 환경을 설정할 수 있습니다.
- 조직의 일반적인 기술 스택과 일치하는 코드베이스를 사용하세요.
- [GitLab Advanced SAST가 지원하는](gitlab_advanced_sast.md#supported-languages) 언어를 사용하세요. GitLab Advanced SAST는 다른 [분석기](analyzers.md)보다 더 정확한 결과를 생성합니다.

테스트 프로젝트에는 GitLab Ultimate가 있어야 합니다. Ultimate만 다음과 같은 [기능](_index.md#features)을 포함합니다:

- GitLab Advanced SAST를 사용한 독점적 크로스 파일, 크로스 함수 스캔.
- 머지 리퀘스트 **리포트** 탭, 파이프라인 보안 보고서 및 기본 브랜치 취약성 보고서로 스캔 결과를 가시화하고 실행 가능하게 만듭니다.

### 벤치마크 및 예제 프로젝트 {#benchmarks-and-example-projects}

테스트를 위해 벤치마크 또는 의도적으로 취약한 애플리케이션을 사용하도록 선택하는 경우, 이러한 애플리케이션은 다음을 기억하세요:

- 특정 취약성 유형에 초점을 맞춥니다. 벤치마크의 초점은 조직이 발견 및 수정을 위해 우선하는 취약성 유형과 다를 수 있습니다.
- 특정 기술을 특정 방식으로 사용하여 조직이 소프트웨어를 구축하는 방식과 다를 수 있습니다.
- 특정 기준을 다른 기준보다 암시적으로 강조하는 방식으로 결과를 보고합니다. 예를 들어, 정확도(거짓 양성 결과 감소)를 우선시할 수 있지만 벤치마크는 재현율(거짓 음성 결과 감소)에만 따라 점수를 부여합니다.

[에픽 15296](https://gitlab.com/groups/gitlab-org/-/epics/15296)은 테스트를 위한 특정 프로젝트를 추천하는 작업을 추적합니다.

### AI 생성 테스트 코드 {#ai-generated-test-code}

SAST 테스트를 위해 AI 도구를 사용하여 취약한 코드를 만들지 않아야 합니다. AI 모델은 종종 실제로 악용 가능하지 않은 코드를 반환합니다.

예를 들어:

- AI 도구는 종종 매개변수를 받아서 민감한 컨텍스트("싱크"라고 함)에서 사용하지만 실제로 사용자 입력을 받지 않는 작은 함수를 작성합니다. 함수가 상수와 같은 프로그램 제어 값으로만 호출되는 경우 안전한 설계입니다. 사용자 입력이 먼저 새니타이징되거나 유효성 검사를 받지 않고 이러한 싱크로 흐르도록 허용되지 않으면 코드는 취약하지 않습니다.
- AI 도구는 코드를 실수로 실행하는 것을 방지하기 위해 취약성의 일부를 주석 처리할 수 있습니다.

이러한 비현실적인 예제에서 취약성을 보고하면 실제 코드에서 거짓 양성 결과가 발생합니다. GitLab SAST는 이러한 경우에 취약성을 보고하도록 설계되지 않았습니다.

## 테스트 수행 {#conduct-the-test}

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.

테스트할 코드베이스를 선택한 후 테스트를 수행할 준비가 되었습니다. 다음 단계를 따를 수 있습니다:

1. CI/CD 구성에 SAST를 추가하는 머지 리퀘스트(MR)를 생성하여 [SAST를 활성화](_index.md#configuration)합니다.
   - 더 정확한 결과를 위해 CI/CD 변수를 [GitLab Advanced SAST 켜기](gitlab_advanced_sast.md#turn-on-gitlab-advanced-sast)로 설정해야 합니다.
1. MR을 리포지토리의 기본 브랜치로 병합합니다.
1. [취약성 보고서](../vulnerability_report/_index.md)를 열어서 기본 브랜치에서 발견된 취약성을 확인하세요.
   - GitLab Advanced SAST를 사용하는 경우 [스캐너 필터](../vulnerability_report/_index.md#scanner-filter)를 사용하여 해당 스캐너의 결과만 표시할 수 있습니다.
1. 취약성 결과를 검토합니다.
   - SQL 주입 또는 경로 순회와 같이 오염된 사용자 입력을 포함하는 GitLab Advanced SAST 취약성에 대해 [코드 흐름 보기](../vulnerabilities/_index.md#vulnerability-code-flow)를 확인하세요.
   - GitLab Duo Enterprise를 사용하는 경우 취약성을 [설명](../analyze/duo.md)하거나 [수정](../remediate/duo.md)합니다.
1. 새 코드가 개발될 때 스캔이 어떻게 작동하는지 확인하려면 애플리케이션 코드를 변경하고 새로운 취약성 또는 약점을 추가하는 새 머지 리퀘스트를 만드세요.
