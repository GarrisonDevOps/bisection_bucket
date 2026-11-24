---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: SAST 규칙
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 정적 애플리케이션 보안 테스트(SAST)는 [분석기](analyzers.md) 세트를 사용하여 코드에서 잠재적 취약성을 검사합니다. 리포지토리에서 발견되는 프로그래밍 언어에 따라 실행할 분석기를 자동으로 선택합니다.

각 분석기는 코드를 처리한 다음 규칙을 사용하여 소스 코드에서 가능한 약점을 찾습니다. 분석기의 규칙은 보고하는 약점의 유형을 결정합니다.

## 규칙의 범위 {#scope-of-rules}

SAST는 보안 약점과 취약성에 중점을 둡니다. 일반적인 버그를 찾거나 전체 코드 품질이나 유지 보수성을 평가하는 것을 목표로 하지 않습니다.

GitLab은 실행 가능한 보안 약점과 취약성을 식별하는 데 중점을 두고 탐지 규칙 집합을 관리합니다. 규칙 집합은 가장 영향력 있는 취약성에 대한 광범위한 범위를 제공하면서 거짓 양성(취약성이 없는데 보고되는 취약성)을 최소화하도록 설계되었습니다.

SAST는 기본 구성에서 사용하도록 설계되었지만 필요한 경우 [탐지 규칙을 구성](#configure-rules-in-your-projects)할 수 있습니다.

## 규칙의 출처 {#source-of-rules}

SAST에서 사용하는 취약성 탐지 규칙은 사용하는 분석기, GitLab Advanced SAST 또는 Semgrep 기반 분석기에 따라 달라집니다.

### GitLab Advanced SAST {#gitlab-advanced-sast}

{{< details >}}

- 티어: Ultimate

{{< /details >}}

GitLab은 [GitLab Advanced SAST](gitlab_advanced_sast.md)용 규칙을 생성, 유지 관리 및 지원합니다. 해당 규칙은 GitLab Advanced SAST 스캔 엔진의 교차 파일, 교차 함수 분석 기능을 활용하도록 사용자 정의 제작되었습니다. GitLab Advanced SAST 규칙 집합은 오픈 소스가 아니며 다른 분석기의 규칙 집합과 동일하지 않습니다.

GitLab Advanced SAST가 탐지하는 취약성 유형에 대한 자세한 내용은 [취약성 탐지 기준](gitlab_advanced_sast.md#vulnerability-detection-criteria)을 참조하세요.

GitLab Advanced SAST에서 사용하는 모든 규칙의 목록은 [GitLab Advanced SAST 규칙](glas_rules_docs/_index.md)을 참조하세요.

### Semgrep 기반 분석기 {#semgrep-based-analyzer}

GitLab은 Semgrep 기반 GitLab SAST 분석기에서 사용되는 규칙을 생성, 유지 관리 및 지원합니다. 이 분석기는 단일 CI/CD 파이프라인 작업에서 [여러 언어](_index.md#supported-languages-and-frameworks)를 검사합니다. 다음을 결합합니다:

- Semgrep 오픈 소스 엔진입니다.
- [GitLab에서 관리하는 탐지 규칙 집합으로, `sast-rules` 프로젝트](https://gitlab.com/gitlab-org/security-products/sast-rules)에서 관리됩니다.
- [취약성 추적](_index.md#advanced-vulnerability-tracking)을 위한 GitLab 독점 기술입니다.

### 기타 분석기 {#other-analyzers}

GitLab SAST는 나머지 [지원되는 언어](_index.md#supported-languages-and-frameworks)를 검사하기 위해 다른 분석기를 사용합니다. 이러한 검사의 규칙은 각 스캐너의 업스트림 프로젝트에 정의되어 있습니다.

## 규칙 업데이트를 릴리스하는 방법 {#how-rule-updates-are-released}

GitLab은 고객 피드백과 내부 연구를 기반으로 규칙을 정기적으로 업데이트합니다. 규칙은 각 분석기의 컨테이너 이미지의 일부로 릴리스됩니다. [분석기를 특정 버전으로 수동으로 고정](_index.md#pin-analyzer-image-version)하지 않는 한 업데이트된 분석기와 규칙을 자동으로 받습니다.

분석기 및 해당 규칙은 관련 업데이트가 있는 경우 [최소 월간](../detect/vulnerability_scanner_maintenance.md) 업데이트됩니다.

### 규칙 업데이트 정책 {#rule-update-policies}

SAST 규칙 업데이트는 [주요 변경사항](../../../update/terminology.md#breaking-change)이 아닙니다. 즉, 규칙을 사전 통지 없이 추가, 제거 또는 업데이트할 수 있습니다.

그러나 규칙 변경을 더 편리하고 이해하기 쉽게 하기 위해 GitLab은 다음을 수행합니다:

- 계획되거나 완료된 [규칙 변경](#important-rule-changes)을 문서화합니다.
- Semgrep 기반 분석기의 경우 규칙이 제거된 후 [자동으로 결과를 해결](_index.md#automatic-vulnerability-resolution)합니다.
- 활동 = "더 이상 탐지되지 않음"인 취약성의 [상태를 대량으로 변경](../vulnerability_report/_index.md#change-status-of-vulnerabilities)할 수 있도록 합니다.
- 제안된 규칙 변경이 기존 취약성 레코드에 미칠 영향을 평가합니다.

## 프로젝트에서 규칙 구성 {#configure-rules-in-your-projects}

변경할 특정 이유가 있지 않은 한 기본 SAST 규칙을 사용해야 합니다. 기본 규칙 집합은 대부분의 프로젝트와 관련이 있도록 설계되었습니다.

그러나 필요한 경우 [사용되는 규칙을 사용자 정의](#apply-local-rule-preferences)하거나 [규칙 변경이 롤아웃되는 방식을 제어](#coordinate-rule-rollouts)할 수 있습니다.

### 로컬 규칙 기본 설정 적용 {#apply-local-rule-preferences}

SAST 검사에서 사용되는 규칙을 사용자 정의하려는 이유는 다음과 같을 수 있습니다:

- 조직에서 교차 사이트 스크립팅(XSS) 또는 SQL 삽입을 다른 취약성 클래스보다 먼저 해결하도록 선택하는 등 특정 취약성 클래스에 우선순위를 할당했습니다.
- 특정 규칙이 거짓 양성 결과이거나 코드베이스의 맥락에서 관련이 없다고 생각합니다.

프로젝트를 검사하는 데 사용되는 규칙을 변경하고, 심각도를 조정하거나 다른 기본 설정을 적용하려면 [규칙 집합 사용자 정의](customize_rulesets.md)를 참조하세요. 사용자 정의가 다른 사용자에게 도움이 될 것 같으면 [GitLab에 문제 보고](#report-a-problem-with-a-gitlab-sast-rule)를 고려해 보세요.

### 규칙 롤아웃 조정 {#coordinate-rule-rollouts}

규칙 변경의 롤아웃을 제어하려면 [SAST 분석기를 특정 버전으로 고정](_index.md#pin-analyzer-image-version)할 수 있습니다.

여러 프로젝트에 걸쳐 동시에 이러한 변경을 수행하려면 다음에서 변수를 설정하는 것을 고려하세요:

- [그룹 수준 CI/CD 변수](../../../ci/variables/_index.md#for-a-group)입니다.
- [검사 실행 정책](../policies/scan_execution_policies.md)의 사용자 정의 CI/CD 변수입니다.

## GitLab SAST 규칙 관련 문제 보고 {#report-a-problem-with-a-gitlab-sast-rule}
<!-- This title is intended to match common search queries users might make. -->

GitLab은 SAST에서 사용하는 규칙 집합에 대한 기여를 환영합니다. 기여는 다음을 해결할 수 있습니다:

- 거짓 양성 결과(잠재적 취약성이 잘못된 경우)입니다.
- 거짓 음성 결과(SAST가 실제로 존재하는 잠재적 취약성을 보고하지 않은 경우)입니다.
- 규칙의 이름, 심각도 등급, 설명, 안내 또는 기타 설명 콘텐츠입니다.

탐지 규칙을 모든 사용자를 위해 개선할 수 있다고 생각하면 다음을 고려해 보세요:

- [`sast-rules` 리포지토리](https://gitlab.com/gitlab-org/security-products/sast-rules)에 머지 리퀘스트를 제출하세요. 세부 정보는 [기여 지침](https://gitlab.com/gitlab-org/security-products/sast-rules#contributing)을 참조하세요.
- [`gitlab-org/gitlab` 이슈 추적기](https://gitlab.com/gitlab-org/gitlab/-/issues/)에서 이슈를 제출하세요.
  - `@gitlab-bot label ~"group::static analysis" ~"Category:SAST"`을 설명하는 댓글을 게시하여 이슈가 올바른 분류 워크플로우로 이동하도록 하세요.

## 중요한 규칙 변경 {#important-rule-changes}

GitLab은 SAST 규칙을 [정기적으로](#how-rule-updates-are-released) 업데이트합니다. 이 섹션에서는 가장 중요한 변경 사항을 강조합니다. 더 많은 세부 정보는 릴리스 공지 및 제공된 CHANGELOG 링크에서 확인할 수 있습니다.

### Semgrep 기반 분석기의 규칙 변경 {#rule-changes-in-the-semgrep-based-analyzer}

Semgrep 기반 검사를 위한 GitLab 관리 규칙 집합의 주요 변경 사항은 다음과 같습니다:

- GitLab 16.3부터 GitLab 정적 분석 및 취약성 연구 팀은 거짓 양성 결과가 너무 많거나 실행 가능한 참 양성 결과가 부족한 규칙을 제거하기 위해 노력하고 있습니다. 이러한 제거된 규칙의 기존 결과는 [자동으로 해결](_index.md#automatic-vulnerability-resolution)되며 [보안 대시보드](../security_dashboard/_index.md#project-security-dashboard)에 나타나지 않거나 [취약성 보고서](../vulnerability_report/_index.md)의 기본 보기에 나타나지 않습니다. 이 작업은 [에픽 10907](https://gitlab.com/groups/gitlab-org/-/epics/10907)에서 추적됩니다.
- GitLab 16.0부터 16.2까지 GitLab 취약성 연구 팀은 각 결과에 포함된 안내를 업데이트했습니다.
- GitLab 15.10에서 `detect-object-injection` 규칙은 [기본적으로 제거](https://gitlab.com/gitlab-org/gitlab/-/issues/373920)되었고 해당 결과는 [자동으로 해결](_index.md#automatic-vulnerability-resolution)되었습니다.

자세한 내용은 [`sast-rules`용 CHANGELOG](https://gitlab.com/gitlab-org/security-products/sast-rules/-/blob/main/CHANGELOG.md)를 참조하세요.

### 다른 분석기의 규칙 변경 {#rule-changes-in-other-analyzers}

각 [분석기](analyzers.md)의 CHANGELOG 파일을 참조하여 각 버전에 포함된 변경 사항(새로 추가되거나 업데이트된 규칙 포함)의 세부 정보를 확인하세요.
