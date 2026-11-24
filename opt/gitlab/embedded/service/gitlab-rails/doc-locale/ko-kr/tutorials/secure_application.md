---
stage: Tutorials
group: Tutorials
info: For assistance with this tutorials page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
description: 종속성 및 규정 준수 검사입니다.
title: '튜토리얼: 애플리케이션을 보호하고 규정 준수를 확인하세요'
---

GitLab은 애플리케이션에서 보안 취약점을 확인하고 규정 준수 요구 사항을 충족하는지 확인할 수 있습니다.

## 보안 기초 학습 {#learn-security-fundamentals}

여기부터 시작하여 GitLab의 보안 기본 사항을 이해합니다.

| 주제 | 설명 | 초보자용 |
|-------|-------------|--------------------|
| [GitLab Security Essentials](https://university.gitlab.com/learning-paths/gitlab-security-essentials-v100) | 이 자급식 과정에서 GitLab의 필수 보안 기능에 대해 알아봅니다. 예상 시간: 6시간입니다. | {{< icon name="star" >}}  |

## 기본 보안 탐지 설정 {#set-up-basic-security-detection}

취약점을 식별하는 기본 검사를 생성합니다.

| 주제 | 설명 | 초보자용 |
|-------|-------------|--------------------|
| [종속성 검사 설정](dependency_scanning.md) | 애플리케이션의 종속성에서 취약점을 감지하는 방법을 알아봅니다. 예상 시간: 15-20분입니다. | {{< icon name="star" >}} |
| [SBOM 방법을 사용하여 종속성 검사 설정](dependency_scanning_by_sbom.md) | SBOM 방법을 사용하여 애플리케이션의 종속성에서 취약점을 감지하는 방법을 알아봅니다. 예상 시간: 15-20분입니다. | {{< icon name="star" >}} |
| [취약점에 대한 Docker 컨테이너 검사](container_scanning/_index.md) | 컨테이너 검사 템플릿을 사용하여 프로젝트에 컨테이너 검사를 추가하는 방법을 알아봅니다. 예상 시간: 15-20분입니다. | {{< icon name="star" >}} |
| [GitLab DAST에 대한 종합 가이드](https://about.gitlab.com/blog/comprehensive-guide-to-gitlab-dast/) | 동적 애플리케이션 보안 테스트를 구성하고 검사를 수행하며 보안 정책을 구현하는 방법을 알아봅니다. 예상 시간: 15-20분입니다. | {{< icon name="star" >}} |

## 비밀 노출로부터 보호 {#protect-against-secret-exposure}

민감한 데이터가 리포지토리에 커밋되는 것을 방지합니다.

| 주제 | 설명 | 초보자용 |
|-------|-------------|--------------------|
| [비밀 푸시 보호로 프로젝트 보호](../user/application_security/secret_detection/push_protection_tutorial.md) | 프로젝트에서 비밀 푸시 보호를 활성화합니다. 예상 시간: 5-10분입니다. | {{< icon name="star" >}} |
| [프로젝트에 커밋된 비밀 감지](../user/application_security/secret_detection/pipeline/tutorial.md) | 프로젝트의 리포지토리에 커밋된 비밀을 감지하고 수정하는 방법을 알아봅니다. 예상 시간: 15-20분입니다. | {{< icon name="star" >}} |
| [커밋에서 비밀 제거](../user/application_security/secret_detection/remove_secrets_tutorial.md) | 커밋 기록에서 비밀을 제거하는 방법을 알아봅니다. 예상 시간: 15-20분입니다. | {{< icon name="star" >}} |

## 보안 정책 및 거버넌스 구현 {#implement-security-policies-and-governance}

프로젝트 전반에 보안 요구 사항을 적용합니다.

| 주제 | 설명 | 초보자용 |
|-------|-------------|--------------------|
| [검사 실행 정책 설정](scan_execution_policy/_index.md) | 프로젝트의 보안 검사를 적용하는 검사 실행 정책을 생성하는 방법을 알아봅니다. 예상 시간: 30-45분입니다. | {{< icon name="star" >}} |
| [파이프라인 실행 정책 설정](pipeline_execution_policy/_index.md) | 파이프라인의 일부로 프로젝트 전반에 보안 검사를 적용하는 파이프라인 실행 정책을 생성하는 방법을 알아봅니다. 예상 시간: 30-45분입니다. | {{< icon name="star" >}} |
| [머지 리퀘스트 승인 정책 설정](scan_result_policy/_index.md) | 검사 결과를 기반으로 조치를 취하는 머지 리퀘스트 승인 정책을 구성하는 방법을 알아봅니다. 예상 시간: 30-45분입니다. | {{< icon name="star" >}} |

## 규정 준수 및 보고 수립 {#establish-compliance-and-reporting}

규제 요구 사항을 충족하고 규정 준수 설명서를 생성합니다.

| 주제 | 설명 | 초보자용 |
|-------|-------------|--------------------|
| [GitLab 패키지 레지스트리로 소프트웨어 자산 명세서 생성](../user/packages/package_registry/tutorial_generate_sbom.md) | 그룹의 모든 프로젝트에서 SBOM을 생성하는 방법을 알아봅니다. 예상 시간: 1시간입니다. | {{< icon name="star" >}} |
| [SBOM 형식의 종속성 목록 내보내기](export_sbom.md) | 애플리케이션의 종속성을 CycloneDX SBOM 형식으로 내보내는 방법을 알아봅니다. 예상 시간: 15-20분입니다. | {{< icon name="star" >}} |
