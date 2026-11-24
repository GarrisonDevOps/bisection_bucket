---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 코드 소유자를 검토자로 자동 할당하거나 추천 검토자 플로우에서 검토자 추천을 받습니다.
title: 자동 검토자 할당 및 추천
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab은 머지 리퀘스트에 대한 검토자를 할당하거나 추천할 수 있으므로 수동으로 선택할 필요가 없습니다:

- 자동 검토자 할당을 사용하여 변경된 파일의 코드 소유자를 검토자로 할당합니다.
- 추천 검토자 플로우를 사용하여 승인 규칙(코드 소유자 규칙 포함)을 기반으로 검토자 추천을 받습니다.

## 자동 검토자 할당 {#automatic-reviewer-assignment}

{{< history >}}

- `auto_assign_code_owner_reviewers`라는 이름의 [기능 플래그](../../../../administration/feature_flags/_index.md)와 함께 GitLab 18.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224175)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 19.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/239965)합니다. 기능 플래그 `auto_assign_code_owner_reviewers`이 제거되었습니다.

{{< /history >}}

자동 검토자 할당을 활성화하면 GitLab은 변경된 파일의 [코드 소유자](../../codeowners/_index.md)를 머지 리퀘스트의 검토자로 할당합니다.

전제 조건:

- 프로젝트에 `CODEOWNERS` 파일이 있어야 합니다.
- 프로젝트에 대한 Maintainer 또는 Owner 역할.

### 자동 검토자 할당 활성화 {#enable-automatic-reviewer-assignment}

프로젝트의 자동 검토자 할당을 활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **설정** > **머지 리퀘스트**를 선택합니다.
1. **자동 검토자 할당** 섹션으로 이동합니다.
1. **모든 코드 소유자를 검토자로 자동 할당**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### GitLab이 검토자를 할당하는 시기 {#when-gitlab-assigns-reviewers}

설정을 활성화한 후 GitLab은 다음의 경우에 코드 소유자를 검토자로 할당합니다.

- 머지 리퀘스트가 준비 완료 상태로 생성된 경우
- 초안 머지 리퀘스트가 준비 완료로 표시된 경우

GitLab은 머지 리퀘스트에서 변경된 파일과 일치하는 모든 코드 소유자를 할당합니다.

GitLab이 자동 할당을 건너뛰는 경우:

- 머지 리퀘스트가 초안 상태인 경우
- 머지 리퀘스트에 이미 검토자가 있는 경우. [`@GitLabDuo`](../duo_in_merge_requests.md#use-gitlab-duo-to-review-your-code)는 이 확인에서 제외됩니다.
- 머지 리퀘스트에서 변경된 파일과 일치하는 코드 소유자가 없는 경우
- 머지 리퀘스트 작성자에게 머지 리퀘스트 메타데이터를 설정할 권한이 없는 경우

## 추천 검토자 플로우 {#recommend-reviewers-flow}

{{< history >}}

- [GitLab 19.0에서 도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/236211)되었으며, [베타](../../../../policy/development_stages_support.md#beta) 프로젝트 설정으로 [기능 플래그](../../../../administration/feature_flags/_index.md)와 함께 제공됩니다(이름: `dap_powered_recommend_reviewers`). 기본적으로 비활성화되었습니다.
- GitLab 19.4에서 프로젝트 설정 대신 플로우 트리거를 사용하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/607677)되었습니다. 기능 플래그 `dap_powered_recommend_reviewers`이 제거되었습니다.
- [GitLab 19.5에서 변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257534)되어 머지 리퀘스트가 생성될 때 실행되는 트리거를 생성합니다.
- [GitLab 19.5에서 변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257235)되어 머지 리퀘스트 사이드바에서 검토자를 할당하는 대신 권장합니다.
- 기존 머지 리퀘스트에 대한 추천 요청이 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/260988)되었습니다.
- GitLab 19.5에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261192)되었습니다.

{{< /history >}}

추천 검토자 플로우는 머지 리퀘스트를 검토하기에 가장 적합한 검토자를 추천합니다. 각 승인 규칙을 충족하는 데 필요한 최소 검토자 수를 추천하며, 가용성, 작업 부하 및 시간대를 기반으로 검토자를 선택합니다.

권장 검토자가 머지 리퀘스트 사이드바에 나타나고 할당할 검토자를 선택합니다.

이 기능은 [GitLab Duo Agent Platform](../../../duo_agent_platform/_index.md)에서 실행됩니다.

이 플로우는 GitLab 19.3 이전 버전에서 사용된 **검토자 할당 전략** 프로젝트 설정을 대체합니다.

전제 조건:

- 최상위 그룹의 Owner 역할과 프로젝트의 Maintainer 또는 Owner 역할
- [GitLab Duo Agent Platform의 필수 조건](../../../duo_agent_platform/_index.md#prerequisites)입니다.
- [최상위 그룹에 대해](../../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off) **플로우 실행 허용**, **기본 플로우 허용** 및 **검토자 추천**가 활성화되어 있어야 합니다.

클릭 스루 데모는 [추천 검토자 플로우](https://click-through-demo-generator-v-2-d63870.gitlab.io/demos/recommended-reviewer-flow/)를 참조하세요.
<!-- Demo published on 2026-10-14 -->

### 플로우 사용 {#use-the-flow}

최상위 그룹에 대해 추천 검토자 플로우를 켜면 GitLab은 각 프로젝트에서 플로우 트리거를 생성합니다. 이 트리거는 머지 리퀘스트가 생성될 때 플로우를 실행합니다. 여기에는 초안으로 생성된 머지 리퀘스트와 준비된 상태로 생성된 머지 리퀘스트가 포함됩니다. 초안 머지 리퀘스트의 경우, 플로우는 준비된 상태로 표시될 때가 아닌 머지 리퀘스트가 생성될 때 검토자를 추천합니다.

이 트리거는 프로젝트의 **AI** > **트리거** 페이지에 나타나며, 여기서 끌 수 있습니다.

초안 머지 리퀘스트가 준비된 상태로 표시될 때 플로우를 실행하려면 이 트리거를 끈 다음 트리거를 생성하세요:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **AI** > **트리거**를 선택합니다.
1. **새 플로우 트리거**를 선택합니다.
1. **설명**에 트리거에 대한 설명을 입력합니다.
1. **구성 소스**가 표시되면 **플로우 또는 외부 에이전트**를 선택한 다음 플로우 목록에서 **검토자 추천**를 선택합니다.
1. **조건** 섹션에서:
   1. **조건 추가**를 선택한 다음 **이벤트에서**를 선택합니다.
   1. **이벤트** 드롭다운 목록에서 **머지 리퀘스트**를 선택합니다.
   1. **실행 시점** 드롭다운 목록에서 **준비됨으로 마킹**을 선택합니다.
   1. **이벤트 추가**를 선택합니다.
1. **플로우 트리거 만들기**를 선택합니다.

Developer 역할 이상을 가진 사용자가 초안 머지 리퀘스트를 준비 완료로 표시하면 플로우가 실행됩니다.

트리거 생성 및 편집에 대한 자세한 내용은 [트리거](../../../duo_agent_platform/triggers/_index.md)를 참조하세요.

### 기존 머지 리퀘스트에 대한 추천 요청 {#request-recommendations-for-an-existing-merge-request}

플로우를 켜기 전에 머지 리퀘스트가 존재한 경우 플로우를 수동으로 시작해야 합니다.

전제 조건:

- 프로젝트에 대한 개발자, 유지 관리자 또는 소유자 역할이 있습니다.

플로우가 실행되지 않은 머지 리퀘스트에 대한 추천을 요청하려면:

- 오른쪽 사이드바의 **검토자** > **권장** 아래에서 **생성**을 선택합니다.

**생성**은 플로우가 실행되는 동안 사용할 수 없습니다.

### 권장 검토자 할당 {#assign-a-recommended-reviewer}

플로우가 실행된 후 권장 검토자가 오른쪽 사이드바의 **권장** 섹션 아래 **검토자**에 나타나며 승인 규칙별로 그룹화됩니다. 이 섹션은 최소 하나의 추천이 있을 때 나타납니다.

플로우가 사용자를 추천한 이유와 시기를 보려면 사용자에게 마우스를 올리세요.

전제 조건:

- 프로젝트에 대한 개발자, 유지 관리자 또는 소유자 역할이 있습니다.

머지 리퀘스트에 권장 검토자를 할당하려면:

- **권장** 아래에서 할당하려는 사용자 옆에 있는 **검토자 추가**({{< icon name="plus" >}})를 선택합니다.

검토자를 할당한 후 더 이상 **권장** 섹션에 나타나지 않습니다.

플로우를 다시 실행하고 새로운 추천을 받으려면:

- **권장** 섹션에서 **권장 검토자 작업**({{< icon name="ellipsis_v" >}}) > **새로 고침**을 선택합니다.

GitLab은 머지 리퀘스트가 병합되거나 종료될 때 추천을 제거합니다.

### 예외 {#exceptions}

- 머지 리퀘스트를 생성하거나 준비된 상태로 표시하는 사람은 프로젝트에 대한 최소 개발자 역할이 있어야 합니다. 플로우는 사람이 더 낮은 역할을 가지고 있을 때 검토자를 추천하지 않습니다.

### 검토자 선택 {#reviewer-selection}

추천 검토자 플로우는 머지 리퀘스트의 필수 승인 규칙과 선택적 승인 규칙을 읽습니다. 선택적 승인 규칙은 승인 수가 0인 규칙입니다. 플로우는 선택적 **모든 구성원** 규칙과 머지 리퀘스트 승인 정책에 의해 생성된 선택적 규칙을 건너뜁니다. 현재 검토자가 아직 충족하지 않은 각 규칙에 대해 플로우는 규칙을 충족하는 데 필요한 최소 검토자 수를 추천합니다. 플로우는 이미 검토자인 사용자를 추천하지 않습니다. 각 권장 검토자에 대해 플로우는 추천의 짧은 이유를 저장합니다.

규칙에 대한 적격 승인자 중에서 선택하려면, 플로우는 각 승인자에 대해 다음을 고려합니다.

- 가용성(해당 [상태](../../../profile/_index.md#set-your-status)에 기반).
- 검토 워크로드(검토 대기 중인 열린 머지 리퀘스트의 수에 기반).
- 현지 시간(프로필의 시간대에 기반).
- 가장 최근 활동.

승인자가 없는 기본 **모든 구성원** 규칙의 경우, 플로우는 머지 리퀘스트를 승인할 수 있고 대상 브랜치로 병합할 수 있는 프로젝트의 직접 구성원 중에서 선택합니다. 어떤 역할도 대상 브랜치로 병합할 수 없는 경우, 후보는 승인할 수 있는 모든 직접 구성원입니다. 상위 그룹이나 초대된 그룹을 통해 액세스 권한을 얻은 구성원은 후보가 아니므로, 직접 구성원이 없는 프로젝트는 이 규칙에 대한 추천을 받지 못합니다.

추천은 백그라운드에서 실행되므로 권장 검토자가 나타나는 데 시간이 걸릴 수 있습니다. 플로우는 최상위 그룹에 대해 플로우를 켤 때 설정되는 [서비스 계정](../../../duo_agent_platform/flows/foundational_flows/_index.md#service-accounts)으로 실행됩니다.

## 관련 항목 {#related-topics}

- [코드 소유자](../../codeowners/_index.md)
- [머지 리퀘스트 검토](_index.md)
- [머지 리퀘스트 승인 규칙](../approvals/rules.md)
