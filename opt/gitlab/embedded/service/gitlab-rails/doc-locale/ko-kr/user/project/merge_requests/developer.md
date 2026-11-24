---
stage: Agent Foundations
group: Agent Developer
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Developer 플로우
---

{{< details >}}

- 티어:  [Free](../../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스:  GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.3에서 [베타](../../../policy/development_stages_support.md)로 도입되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `duo_workflow_in_ci`로 명명되었습니다. 기본적으로 비활성화되어 있으나, 인스턴스 또는 사용자 단위로 활성화됨.
- GitLab 18.6에서 `duo_developer_button` 플래그를 통해 명칭이 `Issue to MR`에서 `Developer Flow`로 변경되었습니다. 기본적으로 비활성화되어 있으나, 인스턴스 또는 사용자 단위로 활성화됨. 기능 플래그 `duo_workflow`도 활성화해야 하지만, 기본적으로 활성화됨.
- GitLab 18.8에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273).
- 기능 플래그 `duo_workflow_in_ci`, `duo_developer_button`, `duo_workflow`는 GitLab 18.9에서 제거됨.
- GitLab 18.10부터 GitLab.com의 Free 티어에서 GitLab Credits를 사용하여 이용 가능.
- 언급 트리거가 GitLab 18.11에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228817).
- 작업 항목 상태 변경 트리거 및 플로우를 할당할 때 워크플랜 지원이 [소개](https://gitlab.com/gitlab-org/gitlab/-/work_items/633027)되었습니다(GitLab 19.6).

{{< /history >}}

Developer 플로우는 이슈 및 머지 리퀘스트 전반에서 더 효율적으로 작업할 수 있도록 도와줍니다. Developer 플로우를 사용하여 다음을 수행할 수 있습니다.

- 이슈에서 초안 머지 리퀘스트를 생성합니다.
- 검토 피드백을 기반으로 기존 머지 리퀘스트를 반복 수정합니다.
- 구현 방식을 조사하고 파악된 내용을 토론에 게시합니다.
- 대규모 머지 리퀘스트를 더 작고 집중된 머지 리퀘스트로 분할합니다.
- 머지 충돌을 해결합니다.

Developer 플로우는 IDE에서 실행되는 [Software Development 플로우](../../../editor_extensions/software_development.md)와는 다릅니다. 자세한 내용은 [코딩 작업을 위한 플로우 선택](../../duo_agent_platform/flows/foundational_flows/_index.md#choose-a-flow-for-coding-tasks)을 참조하세요.

## 전제 조건 {#prerequisites}

- [GitLab Duo Agent Platform 사전 요구 사항](../../duo_agent_platform/_index.md#prerequisites)을 충족합니다.
- [최상위 그룹에 대해](../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off) **Allow foundational flows** 및 **Developer** 설정을 활성화해야 합니다.
- 프로젝트에 대한 Developer, Maintainer 또는 Owner 역할이 있어야 합니다.
- [서비스 계정을 허용하도록 푸시 규칙을 해야 합니다](../../duo_agent_platform/troubleshooting.md#configure-push-rules-to-allow-a-service-account).
- 프로젝트를 위해 [자체 러너를 구성](../../duo_agent_platform/flows/execution/_index.md#configure-runners-to-execute-flows)하거나 [GitLab 호스팅 러너](../../../ci/runners/hosted_runners/_index.md)를 활성화해야 합니다.

최상의 결과를 얻기 위해 Developer 플로우를 처음 사용하기 전에 [프로젝트를 설정](#set-up-your-project)하세요. `AGENTS.md` 및 `agent-config.yml` 파일을 구성하여 Developer 플로우의 결과 품질과 신뢰성을 크게 향상시킵니다.

## 프로젝트 설정 {#set-up-your-project}

Developer 플로우가 더 나은 결과를 생성할 수 있도록 다음 선택 사항 설정을 프로젝트에 구성해야 합니다.

- `AGENTS.md` 파일 추가:  테스트 명령, 린팅 규칙, 커밋 형식 및 코딩 패턴과 같은 프로젝트 규칙을 문서화합니다. Developer 플로우는 리포지토리에서 작업할 때 이 파일을 컨텍스트로 사용합니다. 자세한 내용은 [AGENTS.md 사용자 지정 파일](../../duo_agent_platform/customize/agents_md.md)을 참조하세요.
- 워크스페이스 서브에이전트 추가: Developer 플로우가 리뷰 또는 연구와 같은 집중된 작업을 위임할 수 있는 `.agents/agents/` 디렉터리에 특화된 서브에이전트를 정의합니다. 이 기능은 실험적 기능입니다. 자세한 내용은 [워크스페이스 서브에이전트](../../duo_agent_platform/customize/workspace_subagents.md)를 참조하세요.
- 실행 환경 구성:  프로젝트에 특정 도구(예: Go, Python 또는 Node.js)가 필요한 경우, `agent-config.yml` 파일로 에이전트 환경을 구성합니다. 이렇게 하지 않으면 Developer 플로우는 종속성을 설치하거나 테스트를 실행할 수 없으며, 빌드되지 않거나 실패하는 변경 사항을 생성할 가능성이 더 높습니다. 적절히 구성된 환경에서 Developer 플로우는 테스트를 실행하고 커밋하기 전에 자체 변경 사항을 확인할 수 있습니다. 자세한 내용은 [플로우 실행 구성](../../duo_agent_platform/flows/execution/_index.md)을 참조하세요.
- 모델을 선택하세요: Developer 플로우는 비용과 성능의 균형을 위해 조정된 GitLab 기본 모델을 사용합니다. 집중된 작업의 경우 더 빠른 모델이 반복 시간을 줄여주고, 복잡하고 다단계 작업의 경우 더 강력한 모델이 불완전한 계획의 위험을 줄여줍니다. 자세한 내용은 [GitLab Duo AI 모델](../../duo_agent_platform/model_selection.md)을 참조하세요.

## 플로우 사용 {#use-the-flow}

전제 조건:

- 이벤트 유형 **언급** 및 **할당**은 Developer 플로우의 트리거에서 [구성](../../duo_agent_platform/triggers/_index.md)됩니다.

### 토론에서 Duo Developer 언급 {#mention-duo-developer-in-a-discussion}

주석을 Developer 플로우에 대한 실행 가능한 작업으로 전환하려면 주석에 `@duo-developer-<namespace>`을 언급하세요. `<namespace>`을 GitLab 네임스페이스 경로로 바꿉니다(예: `gitlab-org`).

이슈 또는 머지 리퀘스트 콘텐츠 및 제공하는 컨텍스트의 양에 따라, 플로우는 다음 작업을 실행할 수 있습니다.

- 코드 변경
- 머지 리퀘스트 및 이슈 생성
- 구현 방식을 조사하고 결과를 보고하거나 그에 따라 업데이트합니다

예를 들어:

```plaintext
@duo-developer-<namespace> research approaches for implementing pagination
on the /users endpoint, then create a draft MR with the most
promising approach.
```

Developer 플로우는 해당 세션에 대한 링크로 응답합니다.

또는 진행 상황을 모니터링하려면 왼쪽 사이드바에서 **AI** > **Sessions**를 선택합니다.

### 이슈에서 머지 리퀘스트 생성 {#generate-a-merge-request-from-an-issue}

이슈에서 머지 리퀘스트를 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **Plan** > **Work items**을 선택한 다음, **Type** = **Issue**로 필터링합니다.
1. 머지 리퀘스트를 생성할 이슈를 선택합니다.
1. 이슈에서 머지 리퀘스트를 생성하려면, 다음 중 하나를 수행합니다.
   - 이슈에 Duo Developer 서비스 계정을 할당합니다.
     1. 오른쪽 사이드바의 **Assignees** 섹션에서 **Edit**을 선택합니다.
     1. `duo developer`을 입력하고 검색 결과에서 선택합니다.
   - 이슈 헤더 아래에서 **구현**을 선택합니다.
1. 진행 상황을 모니터링하려면 왼쪽 사이드바에서 **AI** > **세션**을 선택합니다.
1. 세션이 완료되면, 이슈의 **Activity** 섹션의 링크에서 머지 리퀘스트를 검토합니다.

플로우를 [워크플랜](../../work_items/workplan.md)이 있는 이슈에 할당하면 플로우가 워크플랜을 따릅니다. 설명과 워크플랜이 일치하지 않으면 플로우가 워크플랜을 따릅니다.

### 작업 항목 상태가 변경될 때 플로우 시작 {#start-the-flow-when-a-work-item-status-changes}

작업 항목이 선택한 상태로 변경되면 Developer 플로우가 작업 항목을 구현하고 머지 리퀘스트를 생성합니다. 플로우는 작업 항목의 [워크플랜](../../work_items/workplan.md)을 사양으로 사용합니다. 작업 항목에 워크플랜이 없으면 플로우가 설명을 사용합니다.

전제 조건:

- [트리거 생성](../../duo_agent_platform/triggers/_index.md#create-a-trigger) Developer 플로우를 위해 **작업 항목** 이벤트 유형과 **상태 변경됨** 작업만 포함합니다. **생성됨**도 선택하면 상태를 선택할 수 없으며, 작업 항목이 생성될 때 플로우가 시작되지 않습니다.
- 트리거에서 작업을 시작하는 상태를 선택합니다. 상태를 선택하지 않으면 완료 상태로의 변경을 포함한 모든 상태 변경이 세션을 시작합니다.

플로우를 시작하려면:

1. 작업 항목의 상태를 트리거에서 선택한 상태 중 하나로 변경합니다.
1. 진행 상황을 모니터링하려면 왼쪽 사이드바에서 **AI** > **세션**을 선택합니다.
1. 세션이 완료되면 작업 항목의 **활동** 섹션의 링크에서 머지 리퀘스트를 검토합니다. 플로우는 상태를 변경한 사용자에게 머지 리퀘스트를 할당합니다.

### Agentic Chat에서 플로우 사용 {#use-the-flow-in-agentic-chat}

{{< history >}}

- GitLab 19.2에서 `agentic_foundational_flow_tool` [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/20484)되었습니다. 기본적으로 활성화되어 있습니다.
- GitLab 19.5에서 [일반적으로 제공됩니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/605446). 기능 플래그 `agentic_foundational_flow_tool`가 제거되었습니다.

{{< /history >}}

Developer 플로우를 GitLab Duo Agentic Chat 대화에서 다양한 작업을 완료하는 데 사용할 수 있습니다. 예를 들어:

- 코딩 목표를 달성합니다. 이 목표와 관련된 이슈가 필요하지 않습니다.
- 머지 리퀘스트를 열어서 이슈를 해결합니다.

Agentic Chat 대화에서 플로우를 사용하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. GitLab Duo 사이드바에서 새로운 또는 기존 Agentic Chat 대화를 엽니다.
1. Agentic Chat에 Developer 플로우를 사용하여 작업을 완료하도록 요청하세요.

   플로우 진행 상황이 Chat 대화에 표시됩니다. 자세한 내용을 보려면 다음을 수행할 수 있습니다:
   - 대화에서 **에이전트 세션 보기**를 선택합니다.
   - 왼쪽 사이드바에서 **AI** > **세션**을 선택합니다.

### GitLab Duo CLI에서 플로우 사용 {#use-the-flow-in-the-gitlab-duo-cli}

{{< history >}}

- GitLab 19.2에서 GitLab Duo CLI의 기본 플로우로 [소개](https://gitlab.com/gitlab-org/gitlab/-/work_items/603623)되었습니다 [기능 플래그](../../../administration/feature_flags/_index.md) 이름 `duo_cli_default_flow`. 기본적으로 비활성화되었습니다.
- [GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251583)됨(GitLab 19.4).

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

전제 조건:

- GitLab Duo CLI 9.4.0 이상.

[GitLab Duo CLI](../../gitlab_duo_cli/_index.md)는 대화형 및 헤드리스 모드 모두에서 Developer 플로우를 사용합니다. 플로우는 컴퓨터 또는 CI/CD 작업 등 CLI를 실행하는 위치에서 실행되며, GitLab이 세션을 위해 시작하는 러너에서 실행되지 않습니다.

플로우를 사용하려면 다음 중 하나의 모드에서 GitLab Duo CLI를 실행합니다:

- [대화형 모드](../../gitlab_duo_cli/use.md#interactive-mode).
- [헤드리스 모드](../../gitlab_duo_cli/use.md#headless-mode).

### 이미지를 컨텍스트로 제공 {#provide-images-as-context}

{{< history >}}

- GitLab 19.5에서 [기능 플래그](../../../administration/feature_flags/_index.md) 이름 `dap_tool_image_input`로 소개되었습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

전제 조건:

- GitLab에서 관리하는 모델을 사용합니다. 직접 호스팅하는 모델은 지원되지 않습니다.
- GitLab이 러너에서 실행하는 플로우(예: Agentic Chat, 토론 또는 이슈에서 시작된)의 경우 실행 환경에 GitLab Duo CLI 9.29.0 이상이 포함되어야 합니다. GitLab 19.5.0에서는 기본 실행 이미지가 이 요구 사항을 충족하지 않습니다. GitLab 19.5.1 이상은 충족합니다.

Developer 플로우는 이미지를 읽고 작업의 컨텍스트로 사용할 수 있습니다. Agentic Chat, [GitLab Duo CLI](../../gitlab_duo_cli/use.md#provide-images-as-context) 또는 토론이나 이슈에서 시작된 플로우에서 플로우를 사용할 때 이미지를 제공할 수 있습니다. 플로우가 읽을 수 있는 항목:

- 리포지토리의 이미지 파일입니다.
- 동일한 프로젝트의 이슈, 머지 리퀘스트 또는 댓글에 첨부된 이미지입니다.

프롬프트에 이미지를 직접 업로드할 수 없습니다. 대신 이미 존재하는 이미지의 이름을 지정합니다:

- 리포지토리의 파일의 경우 파일 경로를 지정합니다. 예를 들어, `docs/architecture.png`입니다.
- 첨부의 경우 Markdown에 표시되는 대로 업로드 참조를 지정합니다. 예를 들어, `/uploads/<secret>/screenshot.png`입니다.

플로우가 이슈에서 작동할 때 해당 이슈에 첨부된 이미지도 읽을 수 있습니다.

#### 이미지 요구 사항 {#image-requirements}

이미지를 컨텍스트로 사용하려면 이미지가 다음 요구 사항을 충족해야 합니다:

- 형식: PNG, JPEG 또는 WebP 파일
- 크기: 10MB 이하
- 치수: 8,000픽셀보다 넓거나 크지 않습니다

## 모범 사례 {#best-practices}

### 명확한 컨텍스트 제공 {#provide-clear-context}

Developer 플로우는 사용자가 알려주거나 이슈, 머지 리퀘스트, Chat 대화 또는 토론 스레드의 컨텍스트에서 사용 가능한 내용만 알 수 있습니다. 인간 협력자를 돕는 것과 동일한 관행이 여기에 적용됩니다.

- 관련 파일 또는 토론에 대한 링크가 있는 명확한 문제 설명을 작성합니다.
- "완료"가 어떤 모습인지 정의하는 수용 기준을 포함합니다.
- 알려진 경우 정확한 파일 경로를 지정합니다.
- 일관성을 유지하기 위해 기존 패턴의 코드 예제를 포함합니다.
- 이슈에 스크린샷, 다이어그램 또는 목업을 첨부하거나 리포지토리에 커밋하고 요청에서 이름을 지정합니다. 자세한 내용은 [이미지를 컨텍스트로 제공](#provide-images-as-context)을 참조하세요.

### 토론에서 Duo Developer를 언급할 때 명시적 {#be-explicit-when-mentioning-duo-developer-in-discussions}

토론에서 Duo Developer를 언급할 때, 정확히 어떤 작업을 수행하고 싶은지 알려줍니다. 예를 들어:

- "`/api/users` 엔드포인트에 대한 페이지 매김을 구현하는 초안 머지 리퀘스트를 생성합니다."
- "이 머지 리퀘스트의 리뷰 피드백을 처리합니다."
- "로깅 변경 사항을 별도의 머지 리퀘스트로 분할합니다."
- "이 서비스를 gRPC로 마이그레이션하기 위한 방식을 조사하고 여기에 내 결과를 게시합니다."
- "이 머지 리퀘스트에 머지 충돌이 있습니다. 해결해 주세요."

명시적 지침이 없으면 플로우는 자체 방식을 선택하며, 이는 기대와 일치하지 않을 수 있습니다.

### 작업 집중 유지 {#keep-tasks-focused}

복잡한 작업을 더 작고, 집중된, 행동 지향적인 요청으로 분해합니다. 대규모 개방형 작업은 반복 제한에 도달할 가능성이 더 높습니다.

## 예제 {#examples}

### 머지 리퀘스트를 생성하기 위한 이슈 {#issue-for-generating-a-merge-request}

이 예제는 Developer 플로우가 머지 리퀘스트를 생성하는 데 사용할 수 있는 잘 만들어진 이슈를 보여줍니다.

```plaintext
## Description
The users endpoint currently returns all users at once,
which will cause performance issues as the user base grows.
Implement cursor-based pagination for the `/api/users` endpoint
to handle large datasets efficiently.

## Implementation plan
Add pagination to GET /users API endpoint.
Include pagination metadata in /users API response (per_page, page).
Add query parameters for per page size limit (default 5, max 20).

#### Files to modify
- `src/api/users.py` - Add pagination parameters and logic.
- `src/models/user.py` - Add pagination query method.
- `tests/api/test_users_api.py` - Add pagination tests.

## Acceptance criteria
- Accepts page and per_page query parameters (default: page=5, per_page=10).
- Limits per_page to a maximum of 20 users.
- Maintains existing response format for user objects in data array.
```

### 머지 리퀘스트 리뷰 피드백에 대해 반복 {#iterate-on-merge-request-review-feedback}

머지 리퀘스트를 검토한 후 Developer 플로우를 언급하여 피드백을 처리할 수 있습니다. 예를 들어, 특정 라인의 리뷰 의견에서:

```plaintext
@duo-developer-<namespace> move this validation logic into the `BaseService` class
in `app/services/base_service.rb` instead of duplicating it here.
```

전체 리뷰를 제출한 다음 Developer 플로우를 언급하여 모든 열린 스레드를 처리할 수도 있습니다.

```plaintext
@duo-developer-<namespace> please address the review feedback on this MR.
```

### 머지 리퀘스트 분할 {#split-a-merge-request}

머지 리퀘스트가 너무 커진 경우, Developer 플로우에 해당 부분을 별도의 머지 리퀘스트로 추출하도록 요청할 수 있습니다.

```plaintext
@duo-developer-<namespace> the logging changes in this MR are out of scope.
Split them into a separate MR.
```

### 구현 방식 조사 {#research-an-implementation-approach}

Developer 플로우에 문제를 조사하고 변경을 수행하기 전에 보고하도록 요청할 수 있습니다.

```plaintext
@duo-developer-<namespace> research whether the `PUT /api/users` endpoint also needs
rate limiting like we added to the `POST /api/users` endpoint.
Post your findings here.
```

### 이미지를 컨텍스트로 사용 {#use-images-as-context}

Developer 플로우는 리포지토리 또는 같은 프로젝트의 이슈 및 머지 리퀘스트 첨부 파일에서 이미지를 읽을 수 있습니다. 프롬프트에서 이미지의 이름을 지정합니다.

이슈에 첨부된 스크린샷에 표시된 UI 버그를 수정하도록 Developer 플로우에 요청할 수 있습니다:

```plaintext
Look at the screenshot attached to issue 1234 and fix the alignment bug it shows.
```

아키텍처 다이어그램을 설명하도록 Developer 플로우에 요청할 수 있습니다:

```plaintext
Read docs/architecture.png, explain the data flow, and identify any single points of failure.
```

화이트보드 사진을 디자인 문서로 변환하도록 Developer 플로우에 요청할 수 있습니다:

```plaintext
Read whiteboard.jpg and turn it into a design document in docs/design.md.
```

### Agentic Chat에서 Developer 플로우 사용 {#use-the-developer-flow-in-agentic-chat}

Developer 플로우를 Agentic Chat 대화에서 사용하여 다양한 작업을 완료할 수 있습니다:

- 코딩 목표를 달성하려면 다음을 입력할 수 있습니다:
  - `Use the developer flow to resolve this code review feedback.`
  - `Use the developer flow to update this dependency.`
- 머지 리퀘스트를 열어서 이슈를 해결하려면 다음을 입력할 수 있습니다:
  - `Resolve this issue.`
  - `Open a merge request to resolve this issue.`
