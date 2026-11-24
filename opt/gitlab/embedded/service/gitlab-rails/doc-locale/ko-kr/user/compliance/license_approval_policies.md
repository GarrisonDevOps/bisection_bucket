---
stage: Security Risk Management
group: Security Policies
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 라이선스 승인 정책
description: 라이선스 승인 정책을 사용하여 병합 요청이 병합되기 전에 승인이 필요한 시점을 결정하는 조건을 지정하는 방법을 이해합니다. 보호된 대상 브랜치에만 적용됩니다.
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

라이선스 승인 정책을 사용하여 병합 요청이 병합되기 전에 승인이 필요한 시점을 결정하는 조건을 지정합니다.

라이선스 승인 정책은 [보호된](../project/repository/branches/protected.md) 대상 브랜치에만 적용됩니다.

다음 비디오는 이러한 정책의 개요를 제공합니다.

<div class="video-fallback">
  동영상 보기:  <a href="https://www.youtube.com/watch?v=34qBQ9t8qO8">GitLab 라이선스 승인 정책 개요</a>.
</div>
<figure class="video-container">
  <iframe src="https://www.youtube-nocookie.com/embed/34qBQ9t8qO8" frameborder="0" allowfullscreen> </iframe>
</figure>

## 새로운 라이선스 승인 정책 생성 사전 조건 {#prerequisites-to-creating-a-new-license-approval-policy}

라이선스 승인 정책은 종속성 검사 작업의 출력에 의존하여 요구 사항이 충족되었는지 확인합니다. 종속성 검사가 올바르게 구성되지 않았으므로 열린 병합 요청과 관련된 종속성 검사 작업이 실행되지 않았다면, 정책에는 요구 사항을 확인할 데이터가 없습니다. 보안 정책이 평가할 데이터가 없으면 기본적으로 실패 폐쇄 상태가 되어 병합 요청에 취약성이 포함될 수 있다고 가정합니다. `fallback_behavior` 속성으로 기본 동작을 제외하고 정책을 실패 개방으로 설정할 수 있습니다. 실패 개방 정책은 모든 잘못되고 시행할 수 없는 규칙이 차단 해제됩니다.

정책 시행을 보장하려면 대상 개발 프로젝트에서 종속성 검사를 활성화해야 합니다. 이를 달성하는 방법은 여러 가지가 있습니다:

- [검사 실행 정책](../application_security/policies/scan_execution_policies.md)을 생성하여 모든 대상 개발 프로젝트에서 종속성 검사가 실행되도록 합니다.
- 개발 팀과 협력하여 각 프로젝트의 `.gitlab-ci.yml` 파일에서 [종속성 검사](../application_security/dependency_scanning/_index.md)를 구성하거나 [보안 구성](../application_security/detect/security_configuration.md)을 사용하여 활성화합니다.

라이선스 승인 정책은 [GitLab 지원 패키지](license_scanning_of_cyclonedx_files/_index.md#supported-languages-and-package-managers)의 라이선스 정보가 필요합니다.

## 새로운 라이선스 승인 정책 생성 {#create-a-new-license-approval-policy}

라이선스 승인 정책을 생성하여 라이선스 규정 준수를 시행합니다.

라이선스 승인 정책을 생성하려면:

1. [보안 정책 프로젝트를 링크](../application_security/policies/enforcement/security_policy_projects.md#link-to-a-security-policy-project)하여 개발 그룹, 하위 그룹 또는 프로젝트에 연결합니다 (소유자 역할이 필요함).
1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **보안** > **정책**을 선택하세요.
1. 새로운 [병합 요청 승인 정책](../application_security/policies/merge_request_approval_policies.md)을 생성합니다.
1. 정책 규칙에서 **라이센스**를 선택합니다.

## 승인이 필요한 라이선스를 정의하는 기준 {#criteria-defining-which-licenses-require-approval}

다음 유형의 기준을 사용하여 어떤 라이선스가 "승인됨" 또는 "거부됨"이고 승인이 필요한지 결정할 수 있습니다.

- 명시적으로 금지된 라이선스 목록의 라이선스가 감지된 경우.
- 수용 가능한 것으로 명시적으로 나열된 라이선스를 제외한 모든 라이선스가 감지된 경우.

## 병합 요청 브랜치에서 감지된 라이선스를 기본 브랜치의 라이선스와 비교하는 기준 {#criteria-to-compare-licenses-detected-in-the-merge-request-branch-to-licenses-in-the-default-branch}

다음 유형의 기준을 사용하여 기본 브랜치에 존재하는 라이선스를 기반으로 승인이 필요한지 여부를 결정할 수 있습니다:

- 거부된 라이선스는 거부된 라이선스가 기본 브랜치에 아직 존재하지 않는 종속성의 일부인 경우에만 승인이 필요하도록 구성할 수 있습니다.
- 거부된 라이선스는 거부된 라이선스가 기본 브랜치에 이미 존재하는 모든 구성 요소에 있는 경우 승인이 필요하도록 구성할 수 있습니다.

![라이선스 승인 정책](img/license_approval_policy_v15_9.png)

라이선스 승인 정책을 위반하는 라이선스가 발견되면 병합 요청을 차단하고 개발자에게 제거하도록 지시합니다. 라이선스 승인 정책의 적격 승인자가 병합 요청을 승인하지 않는 한, `denied` 라이선스가 제거될 때까지 병합 요청을 병합할 수 없습니다.

![거부된 라이선스가 있는 병합 요청](img/denied_licenses_v15_3.png)

## 문제 해결 {#troubleshooting}

### 라이선스 승인 정책이 `unknown` 라이선스로 인해 병합 요청을 차단 {#license-approval-policies-block-merge-requests-due-to-unknown-licenses}

라이선스 승인 정책이 일부 시나리오에서 `unknown` 라이선스로 인해 병합 요청을 차단할 수 있습니다.

> [!note]
> 패키지 수준 제외는 [`licenses` 필드](../application_security/policies/merge_request_approval_policies.md#licenses_with_package_exclusion-object)의 PURL을 사용하며 `unknown` 라이선스에서는 작동하지 않습니다. `licenses` 필드는 [SPDX 라이선스 이름](https://spdx.org/licenses) 일치만 지원하며, `unknown`은(는) 유효한 SPDX 라이선스 이름이 아닙니다. PURL 제외 조건으로 거부된 `unknown` 라이선스를 구성하면, 병합 요청 승인 평가 중에 제외 조건이 무시되고 병합 요청이 계속 차단됩니다. 파이프라인 **라이센스** 탭은 제외 조건을 준수하는 것처럼 보이지만 병합 요청 승인 위젯은 그렇지 않습니다. 이러한 보기는 다른 평가 경로를 사용합니다.

이는 다음 상황 중 하나에서 발생할 수 있습니다:

- 종속성 검사 작업이 특정 구성 요소의 라이선스를 식별하지 못합니다.
- 검사 도구에서 인식하지 못하는 새로운 라이선스 또는 드문 라이선스가 사용됩니다.
- 라이선스 정보가 구성 요소의 메타데이터에서 누락되었거나 불완전합니다.

이 문제를 해결하려면:

1. 파이프라인 페이지의 **라이센스** 탭을 검토하여 어떤 구성 요소에 `unknown` 라이선스가 있는지 확인하거나, GitLab 보안 봇에서 생성한 `out-of-policy` 라이선스를 검토합니다.
1. 이러한 구성 요소를 수동으로 조사하여 실제 라이선스를 확인합니다.
1. 라이선스를 확인할 수 없거나 수용할 수 없는 경우, 영향을 받는 구성 요소를 제거하거나 교체합니다.

`unknown` 라이선스로의 병합을 임시로 허용해야 하는 경우:

1. 라이선스 승인 정책을 편집합니다.
1. `unknown`을(를) 허용된 라이선스 목록에 추가합니다.
1. 문제를 해결한 후, `unknown`을(를) 허용된 라이선스 목록에서 제거하여 적절한 라이선스 규정 준수를 유지합니다.

라이선스 규정 준수 문제를 다룰 때, 특히 `unknown` 라이선스를 처리할 때는 항상 법무팀과 상담합니다.
