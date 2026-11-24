---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Security Analyst 에이전트
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.6에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/19659)되었습니다.
- GitLab 18.8에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273)되었습니다.

{{< /history >}}

Security Analyst 에이전트는 GitLab에서 취약성 관리 및 보안 분석 워크플로우를 지원하는 특화된 AI 어시스턴트입니다. 보안 전문 지식과 GitLab 보안 기능, 취약성 보고서, 보안 대시보드, 규정 준수 도구에 대한 깊은 이해를 결합하여 보안 발견을 효율적으로 분류, 평가 및 수정할 수 있도록 지원합니다.

다음과 같은 경우에 Security Analyst 에이전트를 사용합니다:

- 취약성 분류: 여러 스캔 유형 간에 보안 발견을 분석하고 우선 순위를 지정합니다.
- 위험 평가: 취약성의 심각도, 악용 가능성 및 비즈니스 영향을 평가합니다.
- 거짓 긍정 식별: 실제 위협과 무해한 발견을 구분합니다.
- 규정 준수 관리: 규제 요구 사항과 수정 일정을 이해합니다.
- 보안 보고: 보안 태세 및 수정 진행 상황을 요약합니다.
- 수정 계획: 보안 취약성을 해결하기 위한 실행 가능한 계획을 수립합니다.
- 보안 워크플로우 자동화: 반복적인 보안 평가 작업을 간소화합니다.

Security Analyst 에이전트는 취약성 상태, 심각도 수준 및 보안 스캐너 출력을 포함한 GitLab 특정 보안 구현을 이해합니다. EPSS 점수, CVE 데이터 및 도달 가능성 분석을 해석하여 상황별 보안 지침을 제공할 수 있습니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 개요를 보려면 [GitLab Security Analyst 에이전트 사용 방법: AI 기반 분류](https://www.youtube.com/watch?v=XqVmrsa9BnM)를 참조합니다.
<!-- Video published on 2026-02-25 -->

## Security Analyst 에이전트 사용 {#use-the-security-analyst-agent}

GitLab UI, VS Code 및 JetBrains IDE에서 Security Analyst 에이전트를 사용할 수 있습니다.

### GitLab UI에서 {#in-the-gitlab-ui}

사전 요구 사항:

- 보안 스캔이 활성화된 GitLab 프로젝트를 사용합니다.
- 기본 에이전트를 [활성화](_index.md#turn-foundational-agents-on-or-off)합니다.

GitLab UI에서 Security Analyst 에이전트를 사용하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. GitLab Duo 사이드바에서 **새 채팅 추가**({{< icon name="pencil-square" >}})를 선택합니다.
1. 드롭다운 목록에서 **보안 분석가**를 선택합니다.

   화면 오른쪽의 GitLab Duo 사이드바에서 Chat 대화창이 열립니다.
1. 보안 관련 질문이나 요청을 입력합니다. 요청에서 최상의 결과를 얻으려면:

   - 보안 요구 사항 및 위험 허용 범위에 대한 컨텍스트를 제공합니다.
   - 집중하고 있는 취약성 또는 스캔 결과 유형을 지정합니다.
   - 분석을 요청할 때 관련 프로젝트 또는 구성 요소 세부 정보를 포함합니다.
   - Security Analyst 에이전트의 권장 사항이 보안 정책과 맞지 않으면 명확히 해달라고 요청합니다.
   - 특정 발견 사항을 논의할 때 특정 취약성 ID 또는 URL을 사용합니다.

### VS Code에서 {#in-vs-code}

사전 요구 사항:

- 보안 스캔이 활성화된 GitLab 프로젝트를 사용합니다.
- 기본 에이전트를 [활성화](_index.md#turn-foundational-agents-on-or-off)합니다.
- [GitLab for VS Code](../../../../editor_extensions/visual_studio_code/setup.md) 버전 6.57.3 이상을 설치하고 구성합니다.
- [기본 GitLab Duo 네임스페이스](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace)를 설정해야 합니다.

VS Code에서 Security Analyst 에이전트를 사용하려면:

1. VS Code의 왼쪽 사이드바에서 **GitLab Duo 에이전트 플랫폼**({{< icon name="duo-agentic-chat" >}})을 선택합니다.
1. **채팅** 탭을 선택합니다.
1. **새 채팅**({{< icon name="duo-chat-new" >}}) 드롭다운 목록에서 **보안 분석가**를 선택합니다.
1. 보안 관련 질문이나 요청을 입력합니다. 요청에서 최상의 결과를 얻으려면:

   - 보안 요구 사항 및 위험 허용 범위에 대한 컨텍스트를 제공합니다.
   - 집중하고 있는 취약성 또는 스캔 결과 유형을 지정합니다.
   - 분석을 요청할 때 관련 프로젝트 또는 구성 요소 세부 정보를 포함합니다.
   - Security Analyst 에이전트의 권장 사항이 보안 정책과 맞지 않으면 명확히 해달라고 요청합니다.
   - 특정 발견 사항을 논의할 때 특정 취약성 ID 또는 URL을 사용합니다.

### JetBrains IDE에서 {#in-jetbrains-ides}

사전 요구 사항:

- 보안 스캔이 활성화된 GitLab 프로젝트를 사용합니다.
- 기본 에이전트를 [활성화](_index.md#turn-foundational-agents-on-or-off)합니다.
- [JetBrains IDE용 GitLab Duo 플러그인](../../../../editor_extensions/jetbrains_ide/setup.md) 버전 3.11.1 이상을 설치하고 구성합니다.
- [기본 GitLab Duo 네임스페이스](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace)를 설정해야 합니다.

먼저 GitLab Duo 에이전트 플랫폼을 사용 가능하도록 설정합니다.

1. JetBrains IDE에서 **설정** > **도구** > **GitLab Duo**로 이동합니다.
1. **GitLab Duo Agent Platform** 아래에서 **GitLab Duo Agent Platform 사용으로 설정** 확인란을 선택합니다.
1. 메시지가 표시되면 IDE를 다시 시작합니다.

그 다음, Security Analyst 에이전트를 사용하려면:

1. JetBrains IDE의 오른쪽 도구 창 표시줄에서 **GitLab Duo 에이전트 플랫폼**({{< icon name="duo-agentic-chat" >}})을 선택합니다.
1. **채팅** 탭을 선택합니다.
1. **새 채팅**({{< icon name="duo-chat-new" >}}) 드롭다운 목록에서 **보안 분석가**를 선택합니다.
1. 보안 관련 질문이나 요청을 입력합니다. 요청에서 최상의 결과를 얻으려면:

   - 보안 요구 사항 및 위험 허용 범위에 대한 컨텍스트를 제공합니다.
   - 집중하고 있는 취약성 또는 스캔 결과 유형을 지정합니다.
   - 분석을 요청할 때 관련 프로젝트 또는 구성 요소 세부 정보를 포함합니다.
   - Security Analyst 에이전트의 권장 사항이 보안 정책과 맞지 않으면 명확히 해달라고 요청합니다.
   - 특정 발견 사항을 논의할 때 특정 취약성 ID 또는 URL을 사용합니다.

## 프롬프트 예시 {#example-prompts}

- 취약성 분석:
  - "내 프로젝트의 모든 중대한 취약성을 표시합니다."
  - "EPSS 점수가 0.7 이상이고 도달 가능한 취약성을 나열합니다."
  - "악용 가능성에 따라 우선 순위를 정해야 할 SAST 발견 사항은 무엇입니까?"
  - "(구성 요소 이름)의 취약성이 보안에 미치는 영향을 분석합니다."
  - "이 릴리스와 이전 릴리스 간의 취약성 추세를 비교합니다."
- 위험 평가:
  - "이러한 컨테이너 스캔 발견 사항의 비즈니스 위험은 무엇입니까?"
  - "이 종속성 취약성이 당사의 사용 사례에 영향을 미치는지 평가해 주세요."
  - "신뢰 경계를 넘는 취약성의 심각도를 평가합니다."
  - "프로덕션에 가장 높은 위험을 초래하는 취약성은 무엇입니까?"
- 분류 및 관리:
  - "도달 불가능한 코드로 표시된 거짓 긍정인 모든 종속성 검사 취약성을 해제합니다."
  - "알려진 악용이 있는 모든 컨테이너 스캔 취약성을 확인합니다."
  - "신뢰 경계를 넘는 모든 취약성에 대해 심각도를 높음으로 업데이트합니다."
  - "지난 주에 해제된 취약성과 그 이유를 표시해 주세요."
  - "취약성 상태를 감지된 상태로 되돌려서 재평가합니다."
- 이슈 관리:
  - "확인된 모든 높은 심각도의 SAST 취약성에 대한 이슈를 생성하고 최근 커미터에게 할당합니다."
  - "취약성(취약성 ID)을 이슈(이슈 ID)에 연결하여 수정을 추적합니다."
  - "중요 인프라 취약성에 대한 수정 작업을 생성합니다."
  - "인증 관련 취약성을 모두 추적하는 보안 에픽을 생성합니다."
- 보고 및 규정 준수:
  - "현재 보안 태세에 대한 경영진 요약을 생성합니다."
  - "수정 진행 상황을 표시하는 규정 준수 보고서를 작성합니다."
  - "보안 검토 위원회를 위한 보안 발견 사항을 요약합니다."
  - "모든 높은 심각도 발견 사항을 해결하기 위한 타임라인을 생성합니다."
- 수정 지침:
  - "이러한 SQL 주입 취약성에 대한 수정 방법을 제안합니다."
  - "이 컨테이너 기본 이미지 취약성에 대한 권장 수정 방법은 무엇입니까?"
  - "다음 스프린트를 위한 보안 패치의 우선 순위를 정하는 데 도움을 주세요."
  - "이러한 문제를 방지하기 위한 보안 코딩 사례에 대한 지침을 제공합니다."
