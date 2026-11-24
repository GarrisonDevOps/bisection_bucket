---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 코드 소유자를 사용하여 코드베이스의 전문가를 정의하고 파일 유형 또는 위치에 따라 검토 요구 사항을 설정합니다.
title: 코드 소유자 문제 해결
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

코드 소유자로 작업할 때 다음과 같은 문제가 발생할 수 있습니다.

코드 소유자 기능이 오류를 처리하는 방식에 대한 자세한 내용은 [오류 처리](advanced.md#error-handling)를 참조하세요.

## CODEOWNERS 파일 검증 {#validate-your-codeowners-file}

{{< history >}}

- [GitLab 17.11에서 도입됨](https://gitlab.com/groups/gitlab-org/-/epics/15598) [기능 플래그](../../../administration/feature_flags/_index.md) `accessible_code_owners_validation`로 명명됨. 기본적으로 비활성화되었습니다.
- GitLab 18.1에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/524437)되었습니다.
- GitLab 18.2에서 [정식 출시](https://gitlab.com/gitlab-org/gitlab/-/issues/549626)되었습니다. 기능 플래그 `accessible_code_owners_validation`이 제거되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

[`CODEOWNERS` 파일](_index.md#codeowners-file)을 볼 때 GitLab은 구문 및 권한 문제를 찾을 수 있도록 검증을 실행합니다. 구문 문제가 없으면 GitLab은:

- 파일에 대해 더 이상 유효성 검사기를 실행하지 않습니다.
- 파일에서 발견된 처음 200개의 고유한 사용자 및 그룹 참조에 대해 더 많은 권한 검증을 실행합니다.

작동 방식:

1. 프로젝트에 액세스할 수 있는 모든 참조를 찾습니다. 사용자 또는 그룹 참조가 추가되었지만 프로젝트 액세스 권한이 없으면 오류를 표시합니다.
1. 각 유효한 사용자 참조에 대해 사용자가 프로젝트에서 병합 요청을 승인할 수 있는 권한이 있는지 확인합니다. 사용자에게 그 권한이 없으면 오류를 표시합니다.
1. 각 유효한 그룹 참조에 대해 최대 역할 값이 개발자 이상인지 확인합니다. 개발자보다 낮은 값을 가진 각 그룹 참조에 대해 오류를 표시합니다.
1. 각 유효한 그룹 참조에 대해 그룹에 병합 요청을 승인할 수 있는 권한이 있는 사용자가 최소 한 명 이상 포함되어 있는지 확인합니다. 병합 요청을 승인할 수 있는 권한이 있는 사용자가 0명인 그룹 참조에 대해 오류를 표시합니다.

## 승인이 표시되지 않음 {#approvals-do-not-show}

[`CODEOWNERS` 파일](_index.md#codeowners-file)이 대상 브랜치에 있어야 합니다.

코드 소유자 승인 규칙은 다음과 같은 경우에 업데이트됩니다:

- 병합 요청을 생성하거나 업데이트합니다.
- 소스 브랜치에 커밋을 푸시합니다.
- 업데이트된 `CODEOWNERS` 파일을 보호된 대상 브랜치로 푸시합니다.

`CODEOWNERS` 파일을 변경한 후에도 승인이 표시되지 않으면 소스 브랜치에 새 커밋을 푸시하거나 병합 요청을 편집하여 새로 고칩니다.

## 선택사항으로 표시된 승인 {#approvals-shown-as-optional}

코드 소유자 승인 규칙은 다음 조건 중 하나라도 참이면 선택사항입니다:

- 사용자 또는 그룹이 프로젝트의 멤버가 아닙니다. 코드 소유자는 [상위 그룹에서 멤버를 상속받을 수 없습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/288851/).
- 사용자 또는 그룹이 [형식이 잘못되었거나 액세스할 수 없습니다](advanced.md#malformed-owners).
- [보호된 브랜치의 코드 소유자 승인](../repository/branches/protected.md#require-code-owner-approval)이 설정되지 않았습니다.
- 섹션이 [선택사항으로 표시](reference.md#optional-sections)되었습니다.
- 다른 [병합 요청 승인 설정](../merge_requests/approvals/settings.md)과의 충돌로 인해 승인할 수 있는 적격 코드 소유자가 없습니다.

## 승인자로 표시되지 않은 사용자 {#user-not-shown-as-possible-approver}

다음 조건 중 하나라도 참이면 사용자가 코드 소유자 병합 요청 승인 규칙의 승인자로 표시되지 않을 수 있습니다:

- 규칙이 특정 사용자가 병합 요청을 승인하는 것을 방지합니다. 프로젝트의 [병합 요청 승인](../merge_requests/approvals/settings.md#edit-merge-request-approval-settings) 설정을 확인합니다.
- 코드 소유자 그룹의 표시 여부가 비공개이고 현재 사용자가 코드 소유자 그룹의 멤버가 아닙니다.
- 특정 사용자 이름이 잘못 입력되었거나 [`CODEOWNERS`파일에 형식이 잘못되었습니다](advanced.md#malformed-owners).
- 현재 사용자는 내부 코드 소유자 그룹에 대한 권한이 없는 외부 사용자입니다.

## 승인 규칙이 유효하지 않음 {#approval-rule-is-invalid}

다음과 같은 오류가 표시될 수 있습니다:

```plaintext
Approval rule is invalid.
GitLab has approved this rule automatically to unblock the merge request.
```

이 문제는 승인 규칙이 프로젝트의 직접 멤버가 아닌 코드 소유자를 사용할 때 발생합니다.

해결 방법은 그룹 또는 사용자가 프로젝트에 초대되었는지 확인하는 것입니다.

## `CODEOWNERS` 사용자 또는 그룹 이름 변경 시 업데이트되지 않음 {#codeowners-not-updated-when-user-or-group-names-change}

사용자 또는 그룹이 이름을 변경하면 `CODEOWNERS`이 자동으로 새 이름으로 업데이트되지 않습니다. 새 이름을 입력하려면 파일을 편집해야 합니다.

SAML SSO를 사용하는 조직은 사용자가 사용자 이름을 변경하는 것을 방지하기 위해 [사용자 이름을 설정](../../../integration/saml.md#set-a-username)할 수 있습니다.

## 전역 그룹 멤버십 잠금과의 비호환성 {#incompatibility-with-global-group-memberships-locks}

코드 소유자 기능은 프로젝트에 대한 직접 그룹 멤버십이 필요합니다. 전역 그룹 멤버십 잠금이 활성화되면 그룹이 프로젝트의 직접 멤버로 초대되는 것을 방지합니다. 이는 두 기능 간의 비호환성을 만듭니다.

전역 [SAML](../../group/saml_sso/group_sync.md#global-saml-group-memberships-lock) 또는 [LDAP](../../../administration/auth/ldap/ldap_synchronization.md#global-ldap-group-memberships-lock) 그룹 멤버십 잠금이 활성화되면 그룹 또는 서브그룹을 코드 소유자로 사용할 수 없습니다.

전역 SAML 또는 LDAP 그룹 멤버십 잠금을 활성화한 경우 다음 옵션이 있습니다:

- 그룹 대신 개별 사용자를 코드 소유자로 사용합니다.
- 그룹 기반 코드 소유자 사용이 더 높은 우선 순위인 경우 전역 그룹 멤버십 잠금을 비활성화합니다.

상속된 그룹 멤버에 대한 지원은 [이슈 288851](https://gitlab.com/gitlab-org/gitlab/-/issues/288851)에서 제안되었습니다.
