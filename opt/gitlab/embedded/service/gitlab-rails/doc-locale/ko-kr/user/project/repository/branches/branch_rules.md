---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Git 브랜치를 이름 지정, 관리 및 보호하는 방법을 이해합니다."
title: 브랜치 규칙
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab은 개별 브랜치를 보호하기 위한 여러 방법을 제공합니다. 이러한 방법은 브랜치가 생성부터 삭제까지 감시와 품질 검사를 받도록 보장합니다:

- 프로젝트의 [기본 브랜치](default.md)에 강화된 보안 및 보호를 적용합니다.
- [보호된 브랜치](protected.md)를 구성하여:
  - 브랜치에 누가 푸시하고 병합할 수 있는지 제한합니다.
  - 사용자가 브랜치에 강제 푸시할 수 있는지 관리합니다.
  - `CODEOWNERS` 파일에 나열된 파일의 변경 사항을 브랜치에 직접 푸시할 수 있는지 관리합니다.
- [승인 규칙](../../merge_requests/approvals/rules.md#approvals-for-protected-branches)을 구성하여 검토 요구 사항을 관리하고 [보안 관련 승인](../../merge_requests/approvals/rules.md#security-approvals)을 구현합니다.
- 타사 [상태 점검](../../merge_requests/status_checks.md)과 통합하여 브랜치의 내용이 정의된 품질 기준을 충족하는지 확인합니다.

다음 방법으로 브랜치를 관리할 수 있습니다:

- GitLab 사용자 인터페이스 사용
- 명령줄에서 Git 사용
- [브랜치 API](../../../../api/branches.md) 사용

## 브랜치 규칙 보기 {#view-branch-rules}

브랜치 규칙 개요 페이지는 구성된 보호가 있는 모든 브랜치와 해당 보호 방법을 보여줍니다:

![구성된 보호가 있는 브랜치의 예](img/view_branch_protections_v15_10.png)

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

브랜치 규칙 개요 목록을 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **브랜치 규칙**을 확장하여 보호된 모든 브랜치를 봅니다.

### 브랜치 규칙 세부 정보 보기 {#view-branch-rule-details}

단일 브랜치의 브랜치 규칙 및 보호를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **브랜치 규칙**을 확장하여 보호된 모든 브랜치를 봅니다.
1. 원하는 브랜치를 식별하고 **상세 보기**를 선택합니다.

## 브랜치 규칙 생성 {#create-a-branch-rule}

{{< history >}}

- GitLab 16.8에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279), `add_branch_rules`라는 플래그 포함. 기본적으로 사용 중지됩니다.
- 기능 플래그 `add_branch_rules`이 GitLab 16.11에서 `edit_branch_rules`으로 [이름 변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279)됨. 기본적으로 사용 중지됩니다.
- **모든 브랜치** 및 **모든 보호된 브랜치** 옵션이 GitLab 17.0에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/388129).
- GitLab 17.4에서 [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/454501).
- GitLab 17.5에서 [GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/454501).
- GitLab 18.9에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/work_items/586354)하게 되었습니다. 기능 플래그 `edit_branch_rules`이 제거되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

브랜치 규칙을 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **브랜치 규칙**을(를) 펼칩니다.
1. **브랜치 규칙 추가**를 선택합니다.
1. 다음 옵션 중 하나를 선택합니다.
   - 특정 브랜치 이름 또는 패턴을 입력하려면:
     1. **브랜치 이름 또는 패턴**을 선택합니다.
     1. **브랜치 규칙 생성** 드롭다운 목록에서 브랜치 이름을 선택하거나 `*`으로 [와일드카드](protected.md#use-wildcard-rules)를 만듭니다.
   - 프로젝트의 모든 브랜치를 보호하려면:
     1. **모든 브랜치**를 선택합니다.
     1. 규칙의 세부 정보 페이지의 **머지 리퀘스트 승인** 아래에서 규칙에 필요한 승인 수를 입력합니다.
   - 보호된 것으로 이미 지정된 프로젝트의 모든 브랜치를 보호하려면:
     1. **모든 보호된 브랜치**를 선택합니다.
     1. 규칙의 세부 정보 페이지의 **머지 리퀘스트 승인** 아래에서 규칙에 필요한 승인 수를 입력합니다.

### 브랜치 규칙 보호 추가 {#add-a-branch-rule-protection}

> [!note]
> `all branches`에 사용할 수 없습니다.

새 브랜치에 보호를 추가하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **브랜치 규칙**을(를) 펼칩니다.
1. **브랜치 규칙 추가**를 선택합니다.
1. **모든 보호된 브랜치** 또는 **브랜치 이름 또는 패턴** 중 하나를 선택합니다.
1. **브랜치 규칙 생성**을 선택합니다.

### 승인 규칙 추가 {#add-an-approval-rule}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> `all branches`에 사용할 수 없습니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

머지 리퀘스트 승인 규칙을 추가하려면:

1. [브랜치 규칙 세부 정보](#view-branch-rule-details) 페이지에서 **머지 리퀘스트 승인** 섹션으로 이동합니다.
1. **승인 규칙** 섹션에서 **승인 규칙 추가**를 선택합니다.
1. 오른쪽 사이드바에서 필드를 완성합니다:
   - **규칙 이름**을 입력합니다.
   - **필요한 승인 수**에서 값(`0`-`100`)을 입력합니다.

     `0`의 값은 [규칙을 선택 사항](../../merge_requests/approvals/rules.md#configure-optional-approval-rules)으로 만들고, `0`보다 큰 숫자는 필수 규칙을 만듭니다. 필요한 최대 승인 수는 `100`입니다.
   - [승인할 수 있는](../../merge_requests/approvals/rules.md#eligible-approvers) 사용자 또는 그룹을 선택합니다.

     GitLab은 머지 리퀘스트로 변경된 파일의 이전 작성자를 기반으로 승인자를 제안합니다.
1. **변경 사항 저장**을 선택합니다.

추가 정보는 [승인 규칙](../../merge_requests/approvals/rules.md#approvals-for-protected-branches)을 참조하세요.

### squash commit 옵션 편집 {#edit-squash-commits-option}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 17.9에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181370), `branch_rule_squash_settings`라는 플래그 포함. 기본적으로 사용 중지됩니다.
- GitLab 17.10의 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/506542)되었습니다.
- GitLab 17.11에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/524860)합니다. 기능 플래그 `branch_rule_squash_settings`이 제거되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.
- GitLab Free에서 이 기능은 브랜치 규칙이 **모든 브랜치**를 대상으로 하는 경우에만 사용할 수 있습니다.
- GitLab Premium 및 GitLab Ultimate에서 이 기능은 모든 브랜치 규칙에 사용할 수 있습니다.

squash 옵션을 편집하려면:

1. [브랜치 규칙 세부 정보](#view-branch-rule-details) 페이지에서 **머지할 때 커밋 스쿼시** 섹션으로 이동합니다.
1. **편집**을 선택합니다.
1. 다음 옵션 중 하나를 선택합니다.

   - **기본값**: 브랜치 레벨 squash 설정을 제거하고 프로젝트의 기본 설정에서 상속합니다. 이 옵션은 프로젝트의 기본 설정을 정의하는 **모든 브랜치** 규칙에는 사용할 수 없습니다.
   - **허용하지 않음**: Squashing은 절대 허용되지 않으며 체크박스는 숨겨집니다.
   - **허용**: 체크박스는 표시되며 기본적으로 선택 해제되어 있습니다.
   - **권장**: 체크박스는 표시되며 기본적으로 선택되어 있습니다.
   - **요구**: Squashing은 항상 수행됩니다. 체크박스는 표시되어 선택되어 있으며 사용자는 변경할 수 없습니다.

1. **변경 사항 저장**을 선택합니다.

### 상태 점검 서비스 추가 {#add-a-status-check-service}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- `edit_branch_rules`라는 이름의 [기능 플래그](../../../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/groups/gitlab-org/-/epics/12522)되었습니다. 기본적으로 사용 중지됩니다.
- GitLab 17.4에서 [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/454501).
- GitLab 17.5에서 [GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/454501).
- GitLab 18.9에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/work_items/586354)하게 되었습니다. 기능 플래그 `edit_branch_rules`이 제거되었습니다.

{{< /history >}}

> [!note]
> `all protected branches`에 사용할 수 없습니다.

상태 점검 서비스를 추가하려면:

1. [브랜치 규칙 세부 정보](#view-branch-rule-details) 페이지에서 **상태 점검** 섹션으로 이동합니다.
1. **상태 점검 추가**를 선택합니다.
1. **서비스 이름**을 입력합니다.
1. **점검할 API** 필드에 URL을 입력합니다.

   전송 중인 머지 리퀘스트 데이터를 보호하려면 HTTPS URL을 사용해야 합니다.

![브랜치 규칙 상태 점검](img/branch_rule_status_check_v17_4.png)

자세한 내용은 [외부 상태 점검](../../merge_requests/status_checks.md)을 참조하세요.

## 브랜치 규칙 대상 편집 {#edit-a-branch-rule-target}

{{< history >}}

- GitLab 16.8에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279), `add_branch_rules`라는 플래그 포함. 기본적으로 사용 중지됩니다.
- 기능 플래그 `add_branch_rules`이 GitLab 16.11에서 `edit_branch_rules`으로 [이름 변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279)됨. 기본적으로 사용 중지됩니다.
- GitLab 17.4에서 [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/454501).
- GitLab 17.5에서 [GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/454501).
- GitLab 18.9에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/work_items/586354)하게 되었습니다. 기능 플래그 `edit_branch_rules`이 제거되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

브랜치 규칙 대상을 편집하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **브랜치 규칙**을 확장하여 보호된 모든 브랜치를 봅니다.
1. 원하는 브랜치를 식별하고 **상세 보기**를 선택합니다.
1. **규칙 타겟** 섹션에서 **편집**을 선택합니다.
1. 필요에 따라 정보를 편집합니다.
1. **업데이트**를 선택합니다.

### 브랜치 규칙 보호 편집 {#edit-a-branch-rule-protection}

브랜치 보호 컨트롤에 대한 자세한 내용은 [보호된 브랜치](protected.md)를 참조하세요.

> [!note]
> `all branches`에 사용할 수 없습니다.

## 브랜치 규칙 삭제 {#delete-a-branch-rule}

{{< history >}}

- GitLab 16.8에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279), `add_branch_rules`라는 플래그 포함. 기본적으로 사용 중지됩니다.
- 기능 플래그 `add_branch_rules`이 GitLab 16.11에서 `edit_branch_rules`으로 [이름 변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279)됨. 기본적으로 사용 중지됩니다.
- GitLab 17.4에서 [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/454501).
- GitLab 17.5에서 [GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/454501).
- GitLab 18.9에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/work_items/586354)하게 되었습니다. 기능 플래그 `edit_branch_rules`이 제거되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

브랜치 규칙을 삭제하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **브랜치 규칙**을(를) 펼칩니다.
1. 삭제하려는 규칙 옆에서 **상세 보기**를 선택합니다.
1. 오른쪽 위 모서리에서 **규칙 삭제**를 선택합니다.
1. 확인 대화에서 **브랜치 규칙 삭제**를 선택합니다.

> [!note]
> `all branches`를 대상으로 하는 규칙에는 브랜치 규칙 삭제를 사용할 수 없습니다.

## 관련 항목 {#related-topics}

- [기본 브랜치](default.md)
- [보호된 브랜치](protected.md)
- [리포지토리 보호](../protect.md)
- [브랜칭 전략](strategies/_index.md)
- [머지 리퀘스트 승인](../../merge_requests/approvals/_index.md)
