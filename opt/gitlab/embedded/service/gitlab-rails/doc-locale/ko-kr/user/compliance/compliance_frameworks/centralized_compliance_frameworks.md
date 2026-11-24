---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab 인스턴스 전체에서 규정 준수 프레임워크를 한 곳에서 중앙으로 관리하는 방법을 알아봅니다.
title: 중앙 집중식 규정 준수 프레임워크
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [GitLab 18.3에서 도입](https://gitlab.com/groups/gitlab-org/-/work_items/15864)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `security_policies_csp`및 `include_csp_frameworks`로 명명됩니다. 기본적으로 활성화됩니다.
- 기능 플래그 `security_policies_csp`이 GitLab 18.5에서 [제거](https://gitlab.com/groups/gitlab-org/-/work_items/17392)되었습니다.
- GitLab 18.6에서 [일반 공개](https://gitlab.com/groups/gitlab-org/-/work_items/15864)되었습니다. `include_csp_frameworks` 기능 플래그가 제거되었습니다.

{{< /history >}}

중앙 집중식 보안 규정 준수 프레임워크 관리를 통해 GitLab 관리자는 GitLab 인스턴스의 모든 그룹 및 프로젝트에서 규정 준수 요구 사항을 중앙으로 관리하고 적용할 수 있습니다.

규정 준수 및 보안 정책(CSP) 그룹을 지정하면 모든 최상위 그룹에서 자동으로 사용 가능한 규정 준수 프레임워크를 만들 수 있습니다.

규정 준수 및 보안 정책 그룹을 지정할 때:

- 규정 준수 및 보안 정책 그룹에서 만든 모든 규정 준수 프레임워크는 인스턴스의 모든 최상위 그룹에서 사용할 수 있게 됩니다.
- 그룹 소유자는 이러한 중앙 집중식 프레임워크를 프로젝트에 할당할 수 있습니다.
- 프레임워크는 그룹별 프레임워크와 함께 표시되며, 규정 준수 및 보안 정책 그룹에서 제공되는 것을 명확하게 나타내는 표시기가 있습니다.
- 규정 준수 및 보안 정책 프레임워크는 규정 준수 및 보안 정책 그룹의 비멤버에게는 읽기 전용이므로 규정 준수 표준의 일관된 적용을 보장합니다.

프레임워크 가시성 및 권한:

- 모든 사용자는 액세스 권한이 있는 프로젝트에 적용된 프레임워크를 볼 수 있습니다.
- 그룹 멤버는 자신의 그룹에서 사용 가능한 모든 규정 준수 및 보안 정책 프레임워크를 볼 수 있습니다.
- 규정준수 센터는 규정 준수 및 보안 정책 그룹 프레임워크와 그룹별 프레임워크를 모두 표시합니다.

## 사전 요구 사항 {#prerequisites}

- 관리자여야 합니다.
- 규정 준수 및 보안 정책 그룹으로 역할할 기존 최상위 그룹입니다.
- REST API를 사용하려면(선택 사항) 관리자 액세스 권한이 있는 토큰이 필요합니다.

## 시작하기 전에 {#before-you-begin}

시작하기 전에 최상위 그룹을 규정 준수 및 보안 정책 그룹으로 지정하여 규정 준수 프레임워크를 관리할 중앙 위치로 사용합니다.

자세한 지침은 [규정 준수 및 보안 정책 그룹 지정](../../../security/compliance_security_policy_management.md#designate-a-compliance-and-security-policy-group)을 참조하세요.

## 규정 준수 및 보안 정책 그룹에서 규정 준수 프레임워크 만들기 {#create-compliance-frameworks-in-the-compliance-and-security-policy-group}

규정 준수 및 보안 정책 그룹을 지정한 후 규정 준수 프레임워크를 만듭니다:

1. 지정된 규정 준수 및 보안 정책 그룹으로 이동합니다.
1. **안전함** > **규정준수 센터**를 선택합니다.
1. 페이지에서 **프레임워크** 탭을 선택합니다.
1. **새 프레임워크**를 선택합니다.
1. 프레임워크 세부정보를 입력합니다:
   - **Name (이름)**: 프레임워크에 대한 설명적인 이름입니다.
   - **Description (설명)**: 프레임워크의 목적과 요구 사항을 설명합니다.
   - **색상**: 시각적 식별을 위한 색상을 선택합니다.
   - **요구사항**(선택 사항): 특정 컨트롤 및 요구 사항을 추가합니다.
1. **변경 사항 저장**을 선택합니다.

프레임워크는 이제 인스턴스의 모든 최상위 그룹에서 사용할 수 있습니다.

## 프레임워크 요구 사항 구성(선택 사항) {#configure-framework-requirements-optional}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

각 규정 준수 프레임워크에 대해 특정 요구 사항 및 컨트롤을 정의할 수 있습니다:

1. 규정 준수 및 보안 정책 그룹에서 프레임워크를 작성 또는 편집할 때 **요구사항** 섹션으로 이동합니다.
1. **새 요구 사항**을 선택합니다.
1. 하나 이상의 컨트롤을 추가합니다:
   - **GitLab 컨트롤**: GitLab 기능 및 설정에 대한 사전 정의된 검사입니다.
   - **외부 컨트롤**: 타사 규정 준수 도구와의 통합입니다.
1. **프레임워크에 변경 사항 저장**을 선택합니다.

사용 가능한 컨트롤에 대한 자세한 내용은 [GitLab 규정 준수 컨트롤](_index.md#gitlab-compliance-controls)을 참조하고 [지원되는 규정 준수 표준](compliance_standards.md)의 세부정보를 참조하세요.

## 프로젝트에 규정 준수 및 보안 정책 프레임워크 적용 {#apply-compliance-and-security-policy-frameworks-to-projects}

규정 준수 및 보안 정책 프레임워크를 그룹 소유자 또는 프로젝트 소유자로 프로젝트에 적용합니다.

### 그룹 소유자로서 {#as-a-group-owner}

그룹 소유자는 규정 준수 및 보안 정책 프레임워크를 자신의 프로젝트에 보고 적용할 수 있습니다. 규정 준수 및 보안 정책 프레임워크는 그룹에서 읽기 전용이며 그룹에서 편집하거나 삭제할 수 없습니다.

규정 준수 및 보안 정책 프레임워크를 그룹의 프로젝트에 적용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.
1. 페이지에서 **프로젝트** 탭을 선택합니다.
1. 규정 준수 및 보안 정책 프레임워크가 특별한 표시기와 함께 목록에 표시됩니다.
1. 규정 준수 및 보안 정책 프레임워크를 선택하여 그룹의 프로젝트에 적용합니다.

### 프로젝트 소유자로서 {#as-a-project-owner}

프로젝트에 적용되는 규정 준수 프레임워크를 확인하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **규정 준수 프레임워크** 섹션을 확장합니다.
1. 규정 준수 및 보안 정책 그룹의 프레임워크를 포함한 모든 적용된 프레임워크를 봅니다.

## 규정 준수 및 보안 정책 프레임워크 수정 {#modifying-compliance-and-security-policy-frameworks}

규정 준수 및 보안 정책 그룹에서 규정 준수 프레임워크를 수정할 때:

- 변경 사항은 모든 그룹에 즉시 반영됩니다.
- 프레임워크를 사용하는 프로젝트는 자동으로 업데이트를 상속합니다.
- 감사 이벤트는 모든 수정 사항을 추적합니다.
- 그룹 또는 프로젝트 소유자로부터 조치가 필요하지 않습니다.

## 규정 준수 및 보안 정책 프레임워크 삭제 {#deleting-compliance-and-security-policy-frameworks}

규정 준수 및 보안 정책 프레임워크를 삭제하면 GitLab은 영향을 받는 프로젝트에 대한 경고를 표시합니다.

규정 준수 및 보안 정책 프레임워크 삭제를 확인할 때:

- 프레임워크가 모든 프로젝트에서 제거됩니다.
- 감사 이벤트가 생성됩니다.
- 프레임워크는 더 이상 어떤 그룹에서도 표시되지 않습니다.

## 규정 준수 및 보안 정책 그룹 변경 {#changing-the-compliance-and-security-policy-group}

규정 준수 및 보안 정책 그룹으로 역할할 그룹을 변경해야 하는 경우:

- 이전 규정 준수 및 보안 정책 그룹의 모든 프레임워크를 사용할 수 없게 됩니다.
- 새 규정 준수 및 보안 정책 그룹의 프레임워크를 사용할 수 있게 됩니다.
- 필요한 경우 프로젝트를 새 프레임워크에 다시 할당해야 합니다.

자세한 지침은 [규정 준수 및 보안 정책 그룹 지정](../../../security/compliance_security_policy_management.md#designate-a-compliance-and-security-policy-group)을 참조하세요.

## 보안 정책과의 통합 {#integration-with-security-policies}

규정 준수 및 보안 정책 프레임워크를 보안 정책과 통합하여 규정 준수를 강화할 수 있습니다:

1. 규정 준수 및 보안 정책 그룹에서 보안 정책을 만듭니다.
1. 특정 규정 준수 프레임워크에 정책 범위를 지정합니다.
1. 이러한 프레임워크를 포함한 프로젝트는 자동으로 정책을 상속합니다.

자세한 내용은 [규정 준수 및 보안 정책 그룹의 보안 정책 관리](../../application_security/policies/enforcement/compliance_and_security_policy_groups.md)를 참조하세요.

## 문제 해결 {#troubleshooting}

중앙 집중식 규정 준수 프레임워크를 사용할 때 발생할 수 있는 문제에 대한 가능한 해결 방법입니다.

### 프레임워크가 그룹에 나타나지 않음 {#frameworks-not-appearing-in-groups}

규정 준수 및 보안 정책 프레임워크가 그룹에 표시되지 않는 경우:

1. 규정 준수 및 보안 정책 그룹이 Admin 설정에서 올바르게 지정되었는지 확인합니다.
1. 규정 준수 및 보안 정책 그룹에 프레임워크가 있는지 확인합니다.
1. 프레임워크를 볼 수 있는 적절한 권한이 있는지 확인합니다.

### 규정 준수 및 보안 정책 프레임워크를 수정할 수 없음 {#cannot-modify-compliance-and-security-policy-frameworks}

규정 준수 및 보안 정책 프레임워크는 규정 준수 및 보안 정책 그룹에서만 수정할 수 있습니다:

1. 규정 준수 및 보안 정책 그룹으로 직접 이동합니다.
1. 규정 준수 및 보안 정책 그룹에 대한 소유자 역할이 있는지 확인합니다.
1. 규정 준수 및 보안 정책 그룹의 규정준수 센터에서 변경을 수행합니다.

## 관련 항목 {#related-topics}

- [인스턴스 전체 규정 준수 및 보안 정책 관리](../../../security/compliance_security_policy_management.md)
- [규정 준수 프레임워크](_index.md)
- [규정 준수 및 보안 정책 그룹](../../application_security/policies/enforcement/compliance_and_security_policy_groups.md)
- [규정준수 센터](../compliance_center/_index.md)
