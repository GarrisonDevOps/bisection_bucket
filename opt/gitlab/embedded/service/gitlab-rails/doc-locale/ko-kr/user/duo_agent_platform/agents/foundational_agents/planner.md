---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Planner 에이전트
---

{{< details >}}

- 티어: [Free](../../../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [GitLab 18.6에서 베타로 도입](https://gitlab.com/gitlab-org/gitlab/-/issues/576618)되었습니다.
- GitLab 18.7에서 생성 및 편집 기능이 도입되었습니다.
- GitLab 18.8에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273)되었습니다.
- GitLab 18.10부터 GitLab.com의 Free 티어에서 GitLab Credits를 사용하여 이용 가능합니다.
- GitLab 19.0에서 할 일 관리가 도입되었습니다.
- [Orbit](https://docs.gitlab.com/orbit/) 그래프 기반 쿼리 통합이 GitLab 19.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/598775)되었습니다.
- 연결된 항목 관계(관련, 차단, 차단함)가 GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/586331)되었습니다.
- 저장된 보기에 대한 지원이 GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/592440)되었습니다.

{{< /history >}}

Planner 에이전트는 GitLab에서 제품 관리 및 계획 워크플로우를 지원하는 특수화된 AI 에이전트입니다. 업무를 더 효과적으로 생성하고 우선 순위를 정하며 추적할 수 있습니다.

Planner 에이전트는 업무 항목 계층 구조(에픽, 이슈, 작업), 마일스톤, 레이블, 가중치를 포함한 GitLab 계획 개념을 이해합니다. 업무 항목을 분석하고, 우선 순위 전략을 제안하며, 계획을 구조화하고 전달하는 데 도움을 줄 수 있습니다.

최상위 그룹과 사용자 설정에서 [Orbit](https://docs.gitlab.com/orbit/)을 활성화하면 Planner 에이전트는 지식 그래프를 사용하여 프로젝트 전체의 관계, 종속성, 과거 컨텍스트에 대한 질문에 답할 수 있습니다.

다음 사항에 도움이 필요한 경우 Planner 에이전트를 사용합니다:

- 우선 순위 지정: RICE, MoSCoW, WSJF와 같은 프레임워크를 적용하여 업무 항목의 순위를 정합니다.
- 작업 분해: 계획을 에픽, 기능, 사용자 스토리로 분해합니다.
- 콘텐츠 생성: 메모, 요구 사항 및 기타 계획 아티팩트를 작성하거나, 요청할 때 에픽, 이슈, 작업을 직접 생성합니다.
- 종속성 분석: 차단된 업무를 식별하고 항목 간의 관계를 파악합니다.
- 콘텐츠 편집: 업무 항목, 레이블, 마일스톤, 연결된 항목 관계 및 기타 속성을 업데이트합니다. 요청할 때 또는 작업을 수행하기 위해 확인을 요청한 후에 업데이트합니다.
- 할 일 관리: 업무 항목에 할 일을 추가하고 완료로 표시합니다.
- 계획 세션: 스프린트, 마일스톤 또는 분기 계획을 구성합니다.
- 상태 보고: 진행 상황, 위험 및 차단 요소의 요약을 생성합니다.
- 백로그 관리: 오래된 이슈, 중복 항목 또는 개선이 필요한 항목을 식별합니다.
- 저장된 보기: 저장된 보기의 필터와 정렬 순서를 사용하여 저장된 보기의 업무 항목을 분석합니다.
- 예상: 업무 항목에 대한 상대적 규모 또는 노력 예상을 제안합니다.
- 그래프 기반 컨텍스트: 유사한 과거 업무, 프로젝트 간 종속성, 관련 경험을 가진 기여자를 찾습니다. [Orbit](https://docs.gitlab.com/orbit/)이 필요합니다.

[issue 583008](https://gitlab.com/gitlab-org/gitlab/-/work_items/583008)에서 피드백을 남길 수 있습니다.

## Planner 에이전트 사용 {#use-the-planner-agent}

GitLab UI, VS Code, JetBrains IDE에서 Planner 에이전트를 사용할 수 있습니다.

### 최적의 결과를 위한 팁 {#tips-for-best-results}

요청으로부터 최적의 결과를 얻으려면:

- URL, 필터 기준 또는 범위와 같은 요청에 대한 컨텍스트를 제공합니다.
- 관련이 있을 때 업무 항목 유형(에픽, 이슈 또는 작업)을 지정합니다.
- 선호하는 우선 순위 지정 프레임워크가 있으면 지정합니다.
- 요약이나 업데이트를 요청할 때 의도한 대상 사용자를 지정합니다(예: 엔지니어링 팀, 리더십, 이해 관계자).
- 에이전트가 권장사항을 제시하기보다 조치를 취하도록 원할 때 "생성", "업데이트" 또는 "종료"와 같은 명시적인 동작 동사를 사용합니다.
- 에이전트의 가정이 워크플로우와 일치하지 않으면 명확히 해달라고 요청합니다.

### GitLab UI에서 {#in-the-gitlab-ui}

사전 요구 사항:

- 기본 에이전트를 [활성화](_index.md#turn-foundational-agents-on-or-off)합니다.
- 선택 사항. 그래프 기반 컨텍스트를 사용하려면 최상위 그룹과 사용자 설정에서 [Orbit을 활성화](https://docs.gitlab.com/orbit/remote/getting-started/)합니다.

GitLab UI에서 Planner 에이전트를 사용하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. GitLab Duo 사이드바에서 **새 채팅 추가**({{< icon name="pencil-square" >}})를 선택합니다.
1. 드롭다운 목록에서 **플래너**를 선택합니다.

   화면 오른쪽의 GitLab Duo 사이드바에서 Chat 대화창이 열립니다.
1. 계획 관련 질문이나 요청을 입력합니다.

### VS Code에서 {#in-vs-code}

사전 요구 사항:

- 기본 에이전트를 [활성화](_index.md#turn-foundational-agents-on-or-off)합니다.
- [GitLab for VS Code](../../../../editor_extensions/visual_studio_code/setup.md) 버전 6.57.3 이상을 설치하고 구성합니다.
- [기본 GitLab Duo 네임스페이스](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace)를 설정해야 합니다.
- 선택 사항. 그래프 기반 컨텍스트를 사용하려면 최상위 그룹과 사용자 설정에서 [Orbit을 활성화](https://docs.gitlab.com/orbit/remote/getting-started/)합니다.

VS Code에서 Planner 에이전트를 사용하려면:

1. VS Code의 왼쪽 사이드바에서 **GitLab Duo 에이전트 플랫폼**({{< icon name="duo-agentic-chat" >}})을 선택합니다.
1. **채팅** 탭을 선택합니다.
1. **새 채팅**({{< icon name="duo-chat-new" >}}) 드롭다운 목록에서 **플래너**를 선택합니다.
1. 계획 관련 질문이나 요청을 입력합니다.

### JetBrains IDE에서 {#in-jetbrains-ides}

사전 요구 사항:

- 기본 에이전트를 [활성화](_index.md#turn-foundational-agents-on-or-off)합니다.
- [GitLab Duo plugin for JetBrains IDE](../../../../editor_extensions/jetbrains_ide/setup.md) 버전 3.11.1 이상을 설치하고 구성합니다.
- [기본 GitLab Duo 네임스페이스](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace)를 설정해야 합니다.
- 선택 사항. 그래프 기반 컨텍스트를 사용하려면 최상위 그룹과 사용자 설정에서 [Orbit을 활성화](https://docs.gitlab.com/orbit/remote/getting-started/)합니다.

먼저 GitLab Duo 에이전트 플랫폼을 사용 가능하도록 설정합니다.

1. JetBrains IDE에서 **설정** > **도구** > **GitLab Duo**로 이동합니다.
1. **GitLab Duo Agent Platform** 아래에서 **GitLab Duo Agent Platform 사용으로 설정** 확인란을 선택합니다.
1. 메시지가 표시되면 IDE를 다시 시작합니다.

그런 다음 Planner 에이전트를 사용하려면:

1. JetBrains IDE의 오른쪽 도구 창 표시줄에서 **GitLab Duo 에이전트 플랫폼**({{< icon name="duo-agentic-chat" >}})을 선택합니다.
1. **채팅** 탭을 선택합니다.
1. **새 채팅**({{< icon name="duo-chat-new" >}}) 드롭다운 목록에서 **플래너**를 선택합니다.
1. 계획 관련 질문이나 요청을 입력합니다.

## 프롬프트 예시 {#example-prompts}

- 우선 순위 지정:
  - "레이블 `<label name>`이 있는 백로그에서 업무 항목의 우선 순위를 지정하는 데 도움을 주세요. RICE 프레임워크를 사용하세요."
  - "MoSCoW를 사용하여 이 업무 항목의 기능을 기준 `<criteria>`으로 분류하고 고객 영향에 따라 분류하세요: `<URL>`"
  - "이러한 업무 항목을 Q1의 전략적 가치로 순위를 정하세요: `<URLs>`"
  - "이러한 기능을 노력 대 영향 행렬을 사용하여 비교하세요: `<URLs>`"
  - "이 업무 항목에서 현재 범위에서 마감일을 맞추기 위해 제거해야 할 하위 항목은 무엇입니까? `<URL>`"
- 작업 분해:
  - "이 계획을 전달해야 할 주요 기능으로 분해하세요: `<URL>`"
  - "이 업무 항목을 구현하는 데 어떤 작업이 필요합니까? `<URL>`"
  - "이 기능의 MVP 버전은 무엇입니까? `<URL>`"
  - "이 업무 항목에서 기능의 순서를 어떻게 정할까요? `<URL>`"
  - "이 프로젝트에 대한 단계적 접근 방식을 제안하세요: `<URL>`"
- 상태 보고:
  - "이 업무 항목에 대한 상태 업데이트 및 진행 보고서를 제공하세요. 모든 하위 항목 포함: `<URL>`"
  - "이 업무 항목의 진행 상황에 대한 임원 요약을 생성하세요: `<URL>`"
  - "리더십을 위한 차단 요소 및 완화 계획을 요약하세요: `<URL>`"
  - "이 계획의 상태에 대한 이해 관계자 업데이트를 작성하세요: `<URL>`"
- 콘텐츠 생성:
  - "이 계획에 대한 메모를 작성하세요. 목표, 성공 기준, 주요 이해 관계자 포함: `<URL>`"
  - "이에 대한 기술 요구 사항 업무 항목을 작성하세요. API 요구 사항, 데이터 모델, 통합 포인트 포함: `<URL>`"
  - "이러한 업무 항목 간의 관계와 순서를 설명하는 종속성 맵 내레이션을 작성하세요: `<URLs>`"
  - "이 에픽에 대한 위험 평가를 생성하세요. 잠재적 차단 요소 및 완화 전략 식별: `<URL>`"
  - "이 업무 항목에 대한 구현 노력을 예상하세요. 개발 시간, 테스트, 잠재적 차단 요소 포함: `<URL>`"
- 종속성 분석:
  - "이 업무 항목에서 범위를 줄이기 위해 어떤 업무를 연기할까요? `<URL>`"
  - "새로운 기능에 대한 기술 부채의 우선 순위를 정하도록 도와주세요."
- 계획 세션:
  - "이러한 업무 항목을 논리적 릴리스 테마로 그룹화하세요: `<URLs>`"
  - "마감일을 놓친 업무 항목은 무엇입니까?"
- 백로그 관리:
  - "6개월 동안 업데이트되지 않은 오래된 업무 항목을 찾으세요."
  - "이 프로젝트에서 중복되거나 유사한 업무 항목을 식별하세요."
  - "나에게 할당된 업무 항목을 표시하세요."
- 저장된 보기:
  - "이 저장된 보기의 업무 항목을 요약하세요: `<URL>`"
  - "이 저장된 보기에서 할당되지 않은 업무 항목은 무엇입니까? `<URL>`"
- 콘텐츠 편집:
  - "이 업무 항목을 완료로 종료하고 새로운 회고 업무 항목을 생성하세요. 잘된 점과 개선이 필요한 점을 기록하세요: `<URL>`"
  - "이 업무 항목을 이 항목으로 차단 표시: `<URLs>`"
  - "이러한 업무 항목을 관련으로 연결: `<URLs>`"
- 할 일 관리:
  - "이 업무 항목에 대한 할 일을 추가하세요: `<URL>`"
  - "이 업무 항목의 모든 할 일을 완료로 표시하세요: `<URL>`"
- 그래프 기반 컨텍스트([Orbit](https://docs.gitlab.com/orbit/) 필요):
  - "이와 유사하면서 이미 배포된 에픽을 찾으세요: `<URL>`"
  - "과거에 이 업무 항목에 대해 유사한 계획을 어떻게 분해했습니까? `<URL>`"
  - "누군가 이미 이 아이디어와 관련된 업무를 추적하고 있습니까?"
  - "이 에픽과 관련된 영역에서 작업한 기여자는 누구입니까? `<URL>`"
  - "프로젝트 전체에서 이 업무 항목이 종속될 수 있는 다른 업무 항목은 무엇입니까? `<URL>`"

## 알려진 이슈 {#known-issues}

- 에이전트는 업무 항목을 일괄 분석할 수 있지만, 많은 수의 항목이 포함된 요청에 대해 응답 품질이 저하될 수 있습니다.
- 에이전트는 긴 토론 기록이 있는 업무 항목의 댓글에 안정적으로 접근할 수 없습니다. 약 100개 항목을 초과하는 댓글 기록이 불완전할 수 있습니다.
- 에이전트에게 업무 항목의 상태를 존재하지 않는 값으로 업데이트하도록 요청할 때, 에이전트는 변경 사항을 적용하지 않고도 업데이트가 성공했다고 잘못 보고할 수 있습니다.
