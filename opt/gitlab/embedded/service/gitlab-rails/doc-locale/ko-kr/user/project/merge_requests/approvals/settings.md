---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "GitLab에서 머지 리퀘스트 승인 설정을 사용하여 승인 규칙 및 제한을 정의합니다. 옵션에는 작성자 승인 방지, 재인증 요구, 새 커밋에 대한 승인 제거가 포함됩니다."
title: 머지 리퀘스트 승인 설정
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[머지 리퀘스트 승인](_index.md) 설정을 구성하여 승인 규칙이 사용 사례를 충족하는지 확인할 수 있습니다. [승인 규칙](rules.md)을 구성할 수도 있습니다. 이 규칙은 병합되기 전에 작업을 승인해야 하는 사용자의 수와 유형을 정의합니다. 머지 리퀘스트 승인 설정은 머지 리퀘스트가 완료를 향해 이동할 때 해당 규칙을 적용하는 방법을 정의합니다.

다음 설정의 조합을 사용하여 머지 리퀘스트의 승인 제한을 구성합니다:

- [**머지 리퀘스트 작성자의 승인 방지**](#prevent-approval-by-merge-request-creator): 머지 리퀘스트의 작성자가 이를 승인하는 것을 방지합니다.
- [**커밋한 사용자의 승인 방지**](#prevent-approvals-by-users-who-add-commits): 머지 리퀘스트에 커밋을 추가하는 사용자도 이를 승인하는 것을 방지합니다.
- [**머지 리퀘스트에서 승인 규칙 편집 방지**](#prevent-editing-approval-rules-in-merge-requests): 사용자가 머지 리퀘스트에서 프로젝트 승인 규칙을 재정의하는 것을 방지합니다.
- [**승인하려면 사용자 재인증(비밀번호 또는 SAML) 필요**](#require-user-re-authentication-to-approve): 잠재적 승인자가 먼저 비밀번호 또는 SAML로 인증하도록 합니다.
- 코드 소유자 승인 제거: 머지 리퀘스트에 커밋이 추가될 때 기존 승인에 대해 발생하는 상황을 정의합니다.
  - **승인 유지**: 승인을 제거하지 않습니다.
  - [**모든 승인 제거**](#remove-all-approvals-when-commits-are-added-to-the-source-branch): 기존 승인을 모두 제거합니다.
  - [**파일이 변경된 경우 코드 소유자의 승인 제거**](#remove-approvals-by-code-owners-if-their-files-changed): 코드 소유자가 머지 리퀘스트를 승인한 후 나중에 커밋이 해당 코드 소유자가 소유한 파일을 변경하면 해당 승인이 제거됩니다.

## 머지 리퀘스트 승인 설정 편집 {#edit-merge-request-approval-settings}

단일 프로젝트에 대한 머지 리퀘스트 승인 설정을 보거나 편집하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **승인**을 확장합니다.

### 인스턴스 또는 최상위 그룹에서 설정 계단식 적용 {#cascade-settings-from-the-instance-or-top-level-group}

승인 규칙 설정의 관리를 단순화하려면 가능한 한 광범위하게 구성합니다. 구성된 설정:

- [인스턴스의 경우](../../../../administration/merge_requests_approvals.md) 인스턴스의 모든 그룹 및 프로젝트에 적용됩니다.
- [최상위 그룹의 경우](../../../group/manage.md#group-merge-request-approval-settings) 하위 그룹 및 프로젝트에 적용됩니다.

설정이 계단식으로 적용되는 방식은 구성된 위치에 따라 다릅니다:

- 인스턴스에 대해 구성된 설정은 모든 그룹 및 프로젝트에 대한 동등한 설정을 잠급니다. 그룹 또는 프로젝트에서 상속된 설정을 변경할 수 없습니다.
- 최상위 그룹에 대해 구성된 설정은 하위 그룹 및 프로젝트에 계단식으로 적용됩니다:
  - 그룹에 대해 방지 설정을 사용할 수 있으면 동등한 프로젝트 설정이 잠깁니다. 프로젝트 유지 관리자는 이를 변경할 수 없습니다.
  - 그룹에 대해 방지 설정을 사용할 수 없으면 프로젝트 유지 관리자는 개별 프로젝트에 대해 이를 구성할 수 있습니다.

## 머지 리퀘스트 작성자의 승인 방지 {#prevent-approval-by-merge-request-creator}

기본적으로 머지 리퀘스트의 작성자(작성자)는 이를 승인할 수 없습니다. 이 설정을 변경하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **머지 리퀘스트 승인** 섹션에서 **승인 설정**으로 스크롤하고 **머지 리퀘스트 작성자의 승인 방지(작성자)** 확인란을 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

머지 리퀘스트 작성자는 개별 머지 리퀘스트에서 승인 규칙을 편집하고 이 설정을 재정의할 수 있습니다. 다음 옵션 중 하나를 구성하지 않는 한:

- [기본 승인의 재정의 방지](#prevent-editing-approval-rules-in-merge-requests)(프로젝트의 경우).
- *(GitLab Self-Managed 인스턴스만 해당)* 기본 승인의 재정의 방지 [인스턴스의 경우](../../../../administration/merge_requests_approvals.md). 인스턴스에 대해 구성하면 프로젝트 또는 개별 머지 리퀘스트에서 이 설정을 편집할 수 없습니다.

## 커밋한 사용자의 승인 방지 {#prevent-approvals-by-users-who-add-commits}

기본적으로 머지 리퀘스트에 커밋한 사용자(커미터)는 여전히 이를 승인할 수 있습니다. 프로젝트(또는 인스턴스)의 커미터가 부분적으로 자신의 것인 머지 리퀘스트를 승인하는 것을 방지하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **머지 리퀘스트 승인** 섹션에서 **승인 설정**으로 스크롤하고 **커밋한 사용자의 승인 방지**를 선택합니다. 이 확인란을 선택 해제하면 관리자가 [인스턴스의 경우](../../../../administration/merge_requests_approvals.md)를 사용할 수 없게 설정했으므로 프로젝트에 대해 변경할 수 없습니다.
1. **변경 사항 저장**을 선택합니다.

[코드 소유자](../../codeowners/_index.md)가 머지 리퀘스트에 커밋하는 경우 머지 리퀘스트가 자신이 소유한 파일에 영향을 미치면 이를 승인할 수 없습니다.

자세한 내용은 [공식 Git 설명서](https://git-scm.com/book/en/v2/Git-Basics-Viewing-the-Commit-History)를 참조하세요.

> [!warning]
> 머지 리퀘스트가 원래 변경사항을 커밋한 사용자 이외의 다른 사용자에 의해 리베이스되면 커밋 기록이 새 커미터로 다시 작성됩니다. 이를 통해 이전에 머지 리퀘스트에서 변경사항을 커밋한 사용자가 이제 이를 승인할 수 있게 될 수 있습니다. 더 이상 커미터가 아니기 때문입니다.
>
> [리베이스 후 승인](../../../../topics/git/git_rebase.md#approving-after-rebase)도 참조하세요.

## 머지 리퀘스트에서 승인 규칙 편집 방지 {#prevent-editing-approval-rules-in-merge-requests}

기본적으로 사용자는 [프로젝트에 대해 생성한](rules.md) 승인 규칙을 머지 리퀘스트별로 재정의할 수 있습니다. 사용자가 머지 리퀘스트에서 승인 규칙을 변경하지 않으려면 이 설정을 사용할 수 없게 설정할 수 있습니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **머지 리퀘스트 승인** 섹션에서 **승인 설정**으로 스크롤하고 **머지 리퀘스트에서 승인 규칙 편집 방지**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

> [!note]
> 이 설정은 각 수준에서 범위가 다릅니다. 프로젝트 또는 그룹의 경우 머지 리퀘스트별 승인 규칙 재정의를 방지합니다. 프로젝트 설정의 승인 규칙 목록은 편집 가능한 상태로 유지됩니다. 프로젝트 유지 관리자가 승인 규칙 목록을 편집하는 것을 방지하려면 관리자가 인스턴스에 대해 [**프로젝트 및 머지 리퀘스트에서 승인 규칙 편집 방지**](../../../../administration/merge_requests_approvals.md)를 사용할 수 있게 설정해야 합니다. 이 필드를 변경하면 설정에 따라 모든 열린 머지 리퀘스트에 영향을 미칠 수 있습니다:

- 사용자가 이전에 승인 규칙을 편집할 수 있었고 이 동작을 사용할 수 없게 설정하면 GitLab은 모든 열린 머지 리퀘스트를 업데이트하여 승인 규칙을 적용합니다.
- 사용자가 이전에 승인 규칙을 편집할 수 없었고 승인 규칙 편집을 사용할 수 있게 설정하면 열린 머지 리퀘스트는 변경되지 않은 상태로 유지됩니다. 이는 해당 머지 리퀘스트의 승인 규칙에 이미 적용된 모든 변경사항을 유지합니다.

## 승인하려면 사용자 재인증 필요 {#require-user-re-authentication-to-approve}

{{< history >}}

- GitLab.com 그룹에 대해 SAML 인증을 사용한 재인증 요구 [GitLab 16.6에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/5981) [기능 플래그](../../../../administration/feature_flags/_index.md)와 함께 이름이 `ff_require_saml_auth_to_approve`입니다. 기본적으로 비활성화되었습니다.
- GitLab Self-Managed 인스턴스에 대해 SAML 인증을 사용한 재인증 요구 [GitLab 16.7에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/431415) [기능 플래그](../../../../administration/feature_flags/_index.md)와 함께 이름이 `ff_require_saml_auth_to_approve`입니다. 기본적으로 비활성화되었습니다.
- [`ff_require_saml_auth_to_approve`를 기본적으로 사용할 수 있게 설정함](https://gitlab.com/gitlab-org/gitlab/-/issues/431714)(GitLab 16.8에서 GitLab.com 및 GitLab Self-Managed 인스턴스의 경우).
- 기능 플래그가 GitLab 18.3에서 제거됨

{{< /history >}}

> [!flag]
> GitLab Self-Managed에서 기본적으로 SAML 인증을 사용한 재인증 요구는 사용 가능합니다. 기능을 숨기려면 관리자가 `ff_require_saml_auth_to_approve`이라는 [기능 플래그를 사용 중지](../../../../administration/feature_flags/_index.md)할 수 있습니다. GitLab.com 및 GitLab Dedicated에서는 이 기능을 사용할 수 있습니다.

잠재적 승인자가 SAML 또는 비밀번호로 먼저 인증하도록 할 수 있습니다. 이 권한은 [연방 규정 코드(CFR) 11부](https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfcfr/CFRSearch.cfm?CFRPart=11&showFR=1&subpartNode=21:1.0.1.1.8.3)에서 정의한 것과 같은 승인에 대한 전자 서명을 사용할 수 있게 합니다.

사전 요구 사항:

- 이 설정은 최상위 그룹에서만 사용 가능합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 비밀번호 인증 및 SAML 인증을 사용할 수 있게 설정합니다. 다음에 대한 자세한 내용:
   - 비밀번호 인증은 [로그인 제한 설명서](../../../../administration/settings/sign_in_restrictions.md#password-and-passkey-authentication)를 참조하세요.
   - GitLab.com 그룹에 대한 SAML 인증은 [GitLab.com 그룹에 대한 SAML SSO 설명서](../../../group/saml_sso/_index.md)를 참조하세요.
   - GitLab Self-Managed 인스턴스에 대한 SAML 인증은 [GitLab Self-Managed에 대한 SAML SSO](../../../../integration/saml.md)를 참조하세요.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **머지 리퀘스트 승인** 섹션에서 **승인 설정**으로 스크롤하고 **승인하려면 사용자 재인증(비밀번호 또는 SAML) 필요**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 소스 브랜치에 커밋이 추가될 때 모든 승인 제거 {#remove-all-approvals-when-commits-are-added-to-the-source-branch}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

기본적으로 승인 후 더 많은 변경사항을 추가하면 머지 리퀘스트의 승인이 제거됩니다.

GitLab은 [`git patch-id`](https://git-scm.com/docs/git-patch-id)를 사용하여 머지 리퀘스트의 차이점을 식별합니다. 이 값은 합리적으로 안정적이고 고유한 식별자이며 머지 리퀘스트 내에서 승인을 재설정하는 방법에 대해 더 스마트한 결정을 내릴 수 있습니다. 머지 리퀘스트에 새로운 변경사항을 푸시하면 `patch-id`이 이전 `patch-id`에 대해 평가되어 승인을 재설정할지 여부를 결정합니다. 이를 통해 GitLab은 기능 브랜치에서 `git rebase` 또는 `git merge <target>`과 같은 명령을 실행할 때 더 나은 재설정 결정을 내릴 수 있습니다.

머지 리퀘스트에 더 많은 변경사항을 추가한 후 기존 승인을 유지하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **머지 리퀘스트 승인** 섹션에서 **승인 설정**으로 스크롤하고 **모든 승인 제거** 확인란을 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

머지 리퀘스트의 생성 및 승인을 자동화하는 경우 머지 리퀘스트를 승인하기 전에 커밋이 완전히 처리되는지 확인하는 논리를 구축합니다. 이는 의도하지 않은 승인 재설정을 방지합니다. 자세한 내용은 [자동화된 승인으로 타이밍 문제 처리](../../../../api/merge_request_approvals.md#prevent-approval-resets-in-automated-merge-requests)를 참조하세요.

## 파일이 변경된 경우 코드 소유자의 승인 제거 {#remove-approvals-by-code-owners-if-their-files-changed}

새 커밋에서 파일이 변경되는 코드 소유자의 승인만 제거하려면:

사전 요구 사항:

- 프로젝트에 대한 유지 관리자 또는 소유자 역할이 있어야 합니다.

다음과 같이 설정합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **머지 리퀘스트 승인** 섹션에서 **승인 설정**으로 스크롤하고 **파일이 변경된 경우 코드 소유자의 승인 제거**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 관련 항목 {#related-topics}

- [인스턴스에 대한 머지 리퀘스트 승인 설정](../../../../administration/merge_requests_approvals.md)
- [규정 준수 센터](../../../compliance/compliance_center/_index.md)
- [머지 리퀘스트 승인 API](../../../../api/merge_request_approvals.md)
- [머지 리퀘스트 승인 설정 API](../../../../api/merge_request_approval_settings.md)
