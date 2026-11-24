---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 모든 변경 사항이 검토되도록 프로젝트에서 머지 리퀘스트에 대한 선택적 또는 필수 승인을 구성합니다.
title: 머지 리퀘스트 승인
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

프로젝트의 변경 사항에 대한 검토 프로세스를 설정하려면 머지 리퀘스트 승인을 구성합니다. 변경 사항을 프로젝트에 병합하기 전에 검토되도록 합니다. 프로젝트의 필요성 및 GitLab 티어에 따라 승인을 선택적 또는 필수로 구성할 수 있습니다.

승인이 담당자 및 검토자와 어떻게 관련되는지에 대한 자세한 내용은 [담당자 및 검토자](../_index.md#assignees-and-reviewers)를 참조하세요.

- [GitLab Free](https://about.gitlab.com/pricing/)는 최소 개발자 [역할](../../../permissions.md)을 가진 모든 사용자가 머지 리퀘스트를 승인할 수 있도록 합니다. 이러한 승인은 선택적이며 승인 없이 병합되는 것을 방지하지 않습니다.
- [GitLab Premium](https://about.gitlab.com/pricing/) 및 [GitLab Ultimate](https://about.gitlab.com/pricing/)는 다음을 수행할 수 있는 더 많은 유연성을 제공합니다:

  - 필수 승인의 수 및 유형에 대한 필수 [규칙](rules.md)을 생성합니다.
  - 특정 파일의 [코드 소유자](../../codeowners/_index.md) 목록을 생성합니다.
  - 승인을 [전체 인스턴스에 대해](../../../../administration/merge_requests_approvals.md) 구성합니다.
  - [그룹 머지 리퀘스트 승인 설정](../../../group/manage.md#group-merge-request-approval-settings)을 구성합니다.

    > [!note]
    > 그룹 머지 리퀘스트 승인 설정 지원은 [에픽 4367](https://gitlab.com/groups/gitlab-org/-/work_items/4367)에서 추적됩니다.

## 승인 규칙 구성 {#configure-approval-rules}

전제 조건:

- 프로젝트에 대해 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

승인 규칙을 구성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **머지 리퀘스트**를 선택합니다.
1. **머지 리퀘스트 승인** 섹션으로 이동합니다.
1. 원하는 규칙을 설정합니다.

다음을 구성할 수도 있습니다:

- 프로젝트에 필요한 감시 및 보안 수준을 더 잘 제어하기 위한 추가 [머지 리퀘스트 승인 설정](settings.md)입니다.
- [머지 리퀘스트 승인 API](../../../../api/merge_request_approvals.md)를 사용한 머지 리퀘스트 승인 규칙입니다.

규칙 구성에 대한 자세한 내용은 [승인 규칙](rules.md)을 참조하세요.

### 필수 승인 {#required-approvals}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

필수 승인은 지정된 사용자의 코드 검토를 적용합니다. 이러한 승인이 없으면 병합할 수 없습니다.

사용 사례는 다음과 같습니다:

- 리포지토리에 병합되는 모든 코드의 검토를 적용합니다.
- 검토자 및 최소 승인 수를 지정합니다.
- 백엔드, 프론트엔드, 품질 보증, 데이터베이스 또는 문서와 같은 검토자의 범주를 지정합니다.
- [`CODEOWNERS` 파일](../../codeowners/_index.md#codeowners-file)을 사용하여 검토자를 결정합니다.
- [코드 적용 범위 감소](../../../../ci/testing/code_coverage/coverage_reporting.md#add-a-coverage-check-approval-rule)에 대한 승인을 요구합니다.
- GitLab Ultimate: 잠재적 취약점에 대해 [보안 팀 승인을 요구](../../../application_security/policies/merge_request_approval_policies.md)합니다.

## 승인 상태 보기 {#view-approval-status}

{{< history >}}

- 더 세밀한 승인자 표시가 GitLab 17.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/183058)합니다. `mr_approvers_filter_hidden_users` 기능 플래그가 제거되었습니다.

{{< /history >}}

머지 리퀘스트의 승인 상태를 보려면 머지 리퀘스트 자체 또는 프로젝트나 그룹의 머지 리퀘스트 목록을 확인합니다.

### 단일 머지 리퀘스트의 경우 {#for-a-single-merge-request}

[가능한 승인자](rules.md#eligible-approvers)는 단일 머지 리퀘스트의 승인 상태를 볼 수 있습니다.

승인 상태를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **머지 리퀘스트**를 선택하고 머지 리퀘스트을 찾습니다.
1. 머지 리퀘스트를 보려면 제목을 선택합니다.
1. 머지 리퀘스트 위젯으로 이동하여 승인 상태를 확인합니다. 이 예에서는 머지 리퀘스트를 승인할 수 있습니다:

   ![검토자가 머지 리퀘스트를 승인할 수 있는 승인 상태 섹션입니다.](img/approval_and_merge_status_v17_3.png)

위젯에는 다음 상태 중 하나가 표시됩니다:

- **승인**: 머지 리퀘스트에 더 많은 승인이 필요합니다.
- **추가로 승인합니다**: 머지 리퀘스트에 필수 승인이 있습니다.
- **승인 해지**: 이미 머지 리퀘스트를 승인했습니다.

승인이 코드 소유자 요구 사항을 충족하는지 확인하려면 **가능한 승인자 펼침** ({{< icon name="chevron-lg-down" >}})을 선택합니다.

승인자 표시 여부는 프로젝트 멤버십 및 그룹 개인정보 보호에 따라 달라집니다:

- 프로젝트 멤버는 모든 승인자를 볼 수 있습니다.
- 프로젝트 비멤버는 다음을 볼 수 있습니다:
  - 승인자가 모두 공개 그룹에 속하면 모든 승인자입니다.
  - 승인자 중 일부가 비공개 그룹에 속하면 승인자에 대한 정보가 없습니다.

### 머지 리퀘스트 목록에서 {#in-the-list-of-merge-requests}

[프로젝트나 그룹](../_index.md#view-merge-requests)의 머지 리퀘스트 목록에는 각 머지 리퀘스트의 승인 상태가 표시됩니다:

|                                       예제                                       | 설명 |
|:-----------------------------------------------------------------------------------:|-------------|
|         ![승인 누락을 나타내는 표시기입니다.](img/approvals_unsatisfied_v17_1.png)         | 필수 승인이 누락되었습니다. ({{< icon name="approval" >}}) |
|            ![충족된 승인을 나타내는 표시기입니다.](img/approvals_satisfied_v17_1.png)            | 승인이 충족되었습니다. ({{< icon name="check" >}}) |
| ![본인이 승인했음을 나타내는 표시기입니다.](img/you_approvals_satisfied_v17_1.png) | 승인이 충족되었으며, 승인자 중 한 명입니다. ({{< icon name="approval-solid" >}}) |

### 개별 검토자 상태 {#individual-reviewer-status}

각 검토자의 검토 및 승인 상태를 보려면:

1. 머지 리퀘스트를 엽니다.
1. 오른쪽 사이드바를 확인합니다.

각 검토자의 상태는 이름 옆에 표시됩니다.

- {{< icon name="dash-circle" >}} 검토 대기 중
- {{< icon name="status_running" >}} 검토 진행 중
- {{< icon name="check-circle" >}} 승인됨
- {{< icon name="comment-lines" >}} 검토자가 댓글을 작성함
- {{< icon name="status_warning" >}} 검토자가 변경을 요청함

  ![검토자가 변경을 요청했음을 나타내는 경고 상태입니다.](img/reviewer_blocks_mr_v17_3.png)

[검토 재요청](../reviews/_index.md#re-request-a-review)을 수행하려면 사용자 옆의 **검토 재요청** 아이콘 ({{< icon name="redo" >}})을 선택합니다.

## 머지 리퀘스트 승인 {#approve-a-merge-request}

가능한 승인자는 두 가지 방법으로 머지 리퀘스트를 승인할 수 있습니다:

- 머지 리퀘스트 위젯에서 **승인**을 선택합니다.
- 댓글에서 [`/approve` 빠른 작업](../../quick_actions.md#approve)을 사용합니다.

승인된 머지 리퀘스트는 검토자 목록에서 사용자 이름 옆에 녹색 확인 표시({{< icon name="check-circle-filled" >}})를 표시합니다. 머지 리퀘스트가 필수 승인을 받은 후에는 다음으로 인해 차단되지 않으면 병합할 준비가 된 것입니다:

- [머지 충돌](../conflicts.md)
- [열린 스레드](../_index.md#prevent-merge-unless-all-threads-are-resolved)
- [실패한 CI/CD 파이프라인](../auto_merge.md)

### 머지 리퀘스트 작성자 승인 방지 {#prevent-merge-request-creator-approval}

머지 리퀘스트 작성자가 자신의 작업을 승인하지 않도록 하려면 [**머지 리퀘스트 작성자의 승인 방지**](settings.md#prevent-approval-by-merge-request-creator) 설정을 활성화합니다.

### 승인 규칙 변경 {#approval-rule-changes}

[승인 규칙 재정의](settings.md#prevent-editing-approval-rules-in-merge-requests)를 활성화하면 기본 승인 규칙에 대한 변경 사항이 [대상 브랜치](rules.md#approvals-for-protected-branches) 변경을 제외하고는 기존 머지 리퀘스트에 영향을 주지 않습니다.

## 유효하지 않은 규칙 {#invalid-rules}

GitLab은 다음과 같은 경우 충족할 수 없을 때 승인 규칙을 **자동 승인**으로 표시합니다:

- 유일한 가능한 승인자가 머지 리퀘스트 작성자인 경우입니다.
- 규칙에 할당된 가능한 승인자가 없습니다.
- 필수 승인이 가능한 승인자 수를 초과합니다.

이러한 규칙은 [머지 리퀘스트 승인 정책](../../../application_security/policies/merge_request_approval_policies.md)을 통해 규칙을 생성하지 않은 한 머지 리퀘스트를 차단 해제하기 위해 자동으로 승인됩니다.

정책으로 생성된 유효하지 않은 규칙:

- **조치 필요**로 표시합니다.
- 자동으로 승인되지 않습니다.
- 영향을 받는 머지 리퀘스트를 차단합니다.

## 관련 항목 {#related-topics}

- [머지 리퀘스트 승인 API](../../../../api/merge_request_approvals.md)
- GitLab Self-Managed 인스턴스의 [인스턴스 승인 규칙](../../../../administration/merge_requests_approvals.md)
- [플래너 또는 리포터 역할이 있는 사용자의 승인 권한 활성화](rules.md#enable-approval-permissions-for-additional-users)
- [머지 리퀘스트 승인 규칙 편집 또는 재정의](rules.md#edit-or-override-merge-request-approval-rules)
