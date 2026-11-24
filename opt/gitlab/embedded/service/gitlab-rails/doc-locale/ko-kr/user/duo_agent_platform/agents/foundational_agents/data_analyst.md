---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Data Analyst 에이전트
---

{{< details >}}

- 티어: [Free](../../../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.6에서 `foundational_analytics_agent`라는 [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/578342)되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab 18.7](https://gitlab.com/gitlab-org/gitlab/-/issues/583940)에서 [베타](../../../../policy/development_stages_support.md#beta) 버전으로 변경되었습니다.
- GitLab 18.7에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에 사용으로 설정](https://gitlab.com/gitlab-org/gitlab/-/issues/583940)되었습니다.
- GitLab 18.11에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/work_items/584536)되었습니다.

{{< /history >}}

Data Analyst 에이전트는 GitLab 플랫폼 전반에 걸쳐 데이터를 쿼리하고, 시각화하고, 표시할 수 있도록 도와주는 특화된 AI 어시스턴트입니다. [GitLab Query Language(GLQL)](../../../glql/_index.md)과 [Orbit](https://docs.gitlab.com/orbit/)을 사용하여 데이터를 검색하고 분석한 후, 프로젝트 및 그룹에 대한 명확하고 실행 가능한 인사이트를 제공합니다. 티어에서 사용 가능한 데이터 소스 및 필드에 대한 자세한 내용은 [GLQL 데이터 소스](../../../glql/data_sources/_index.md) 및 [Orbit 인덱싱](https://docs.gitlab.com/orbit/remote/indexing/)을 참조하세요.

다음과 같은 경우에 Data Analyst 에이전트를 사용하세요:

- 볼륨 분석: 시간 기간에 따른 머지 리퀘스트, 이슈 또는 기타 작업 항목을 계산합니다.
- 팀 성과: 팀 구성원이 수행한 작업 및 그 결과를 파악합니다.
- 추세 분석: 개발 워크플로우의 패턴을 파악합니다.
- 상태 모니터링: 프로젝트 또는 그룹 전체의 작업 항목 상태를 확인합니다.
- 작업 항목 검색: 작성자, 레이블, 마일스톤 또는 기타 조건으로 이슈, 머지 리퀘스트 또는 에픽을 찾습니다.
- GLQL 쿼리 생성: 이슈, 머지 리퀘스트, 에픽, 댓글, 위키, 스니펫 및 릴리스를 포함하여 GitLab Flavored Markdown을 지원하는 모든 곳에 포함시킬 수 있는 쿼리를 작성합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 개요는 [GitLab Duo Data Analyst 데모](https://youtu.be/9MTT2P_t-CU)를 참조하세요.

[이슈 574028](https://gitlab.com/gitlab-org/gitlab/-/issues/574028)에 피드백을 남길 수 있습니다.

## 알려진 이슈 {#known-issues}

- 에이전트는 쿼리된 데이터에 대해 간단한 집계를 수행할 수 있지만, 100개를 초과하는 항목이 있는 데이터 세트의 경우 결과가 불완전할 수 있습니다.
- GLQL은 [특정 영역](../../../glql/data_sources/_index.md)을 쿼리할 수 있지만 모든 GitLab 데이터 소스를 지원하지 않습니다.
- 에이전트는 작업 항목 또는 대시보드에 직접 출력할 수 없습니다. 그러나 생성된 GLQL 쿼리를 복사하여 GitLab Flavored Markdown을 지원하는 모든 페이지에 포함시킬 수 있습니다.

## Data Analyst 에이전트 사용 {#use-the-data-analyst-agent}

GitLab UI, VS Code 및 JetBrains IDE에서 Data Analyst 에이전트를 사용할 수 있습니다.

### GitLab UI에서 {#in-the-gitlab-ui}

사전 요구 사항:

- 기본 에이전트를 [활성화](_index.md#turn-foundational-agents-on-or-off)합니다.

GitLab UI에서 Data Analyst 에이전트를 사용하려면 다음을 수행하세요:

1. GitLab Duo 사이드바에서 **새 채팅 추가**({{< icon name="pencil-square" >}})를 선택합니다.
1. 드롭다운 목록에서 **데이터 분석가**를 선택합니다.

   화면 오른쪽의 GitLab Duo 사이드바에서 Chat 대화창이 열립니다.
1. 분석 질문 또는 요청을 입력하세요. 요청에서 최고의 결과를 얻으려면 다음을 수행하세요:

   - 데이터에 대해 질문할 때 범위(프로젝트 또는 그룹)를 지정합니다.
   - 시간 기반 분석을 위해 시간 범위를 포함합니다.
   - 관심 있는 작업 항목 유형을 구체적으로 지정합니다.

### VS Code에서 {#in-vs-code}

사전 요구 사항:

- 기본 에이전트를 [활성화](_index.md#turn-foundational-agents-on-or-off)합니다.
- [VS Code용 GitLab](../../../../editor_extensions/visual_studio_code/setup.md) 버전 6.57.3 이상을 설치하고 구성합니다.
- [기본 GitLab Duo 네임스페이스](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace)를 설정해야 합니다.

VS Code에서 Data Analyst 에이전트를 사용하려면 다음을 수행하세요:

1. VS Code의 왼쪽 사이드바에서 **GitLab Duo 에이전트 플랫폼**({{< icon name="duo-agentic-chat" >}})을 선택합니다.
1. **채팅** 탭을 선택합니다.
1. **새 채팅**({{< icon name="duo-chat-new" >}}) 드롭다운 목록에서 **데이터 분석가**를 선택합니다.
1. 분석 질문 또는 요청을 입력하세요. 요청에서 최고의 결과를 얻으려면 다음을 수행하세요:

   - 데이터에 대해 질문할 때 범위(프로젝트 또는 그룹)를 지정합니다.
   - 시간 기반 분석을 위해 시간 범위를 포함합니다.
   - 관심 있는 작업 항목 유형을 구체적으로 지정합니다.

### JetBrains IDE에서 {#in-jetbrains-ides}

사전 요구 사항:

- 기본 에이전트를 [활성화](_index.md#turn-foundational-agents-on-or-off)합니다.
- [JetBrains IDE용 GitLab Duo 플러그인](../../../../editor_extensions/jetbrains_ide/setup.md) 버전 3.24.4 이상을 설치하고 구성합니다.
- [기본 GitLab Duo 네임스페이스](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace)를 설정해야 합니다.

먼저 GitLab Duo 에이전트 플랫폼을 사용 가능하도록 설정합니다.

1. JetBrains IDE에서 **설정** > **도구** > **GitLab Duo**로 이동합니다.
1. **GitLab Duo Agent Platform** 아래에서 **GitLab Duo Agent Platform 사용으로 설정** 확인란을 선택합니다.
1. 메시지가 표시되면 IDE를 다시 시작합니다.

그런 다음 Data Analyst 에이전트를 사용하려면 다음을 수행하세요:

1. JetBrains IDE의 오른쪽 도구 창 막대에서 **GitLab Duo 에이전트 플랫폼**({{< icon name="duo-agentic-chat" >}})을 선택합니다.
1. **채팅** 탭을 선택합니다.
1. **새 채팅**({{< icon name="duo-chat-new" >}}) 드롭다운 목록에서 **데이터 분석가**를 선택합니다.
1. 분석 질문 또는 요청을 입력하세요. 요청에서 최고의 결과를 얻으려면 다음을 수행하세요:

   - 데이터에 대해 질문할 때 범위(프로젝트 또는 그룹)를 지정합니다.
   - 시간 기반 분석을 위해 시간 범위를 포함합니다.
   - 관심 있는 작업 항목 유형을 구체적으로 지정합니다.

## 프롬프트 예시 {#example-prompts}

- 볼륨 및 계산:
  - "이번 달 병합된 머지 리퀘스트는 몇 개인가요?"
  - "지난주 생성된 이슈를 계산합니다."
  - "현재 열려 있는 버그는 몇 개인가요?"
- 팀 성과:
  - "이번 달 @username이 어떤 작업을 했나요?"
  - "지난 2주간 팀 X에서 병합한 머지 리퀘스트를 표시합니다."
  - "제게 할당된 제목과 레이블이 있는 이슈 테이블을 표시합니다."
  - "작성자별로 열려 있는 머지 리퀘스트를 나열합니다."
- 상태 및 모니터링:
  - "`~priority::1` 및 `~bug` 레이블이 있는 열려 있는 이슈를 표시합니다."
  - "지연된 이슈를 표시합니다."
  - "검토 대기 중인 머지 리퀘스트는 무엇인가요?"
  - "현재 마일스톤의 이슈를 나열합니다."
- 추세 분석:
  - "지난 달 동안의 머지 리퀘스트 활동을 표시합니다."
  - "이번 분기의 버그 생성 추세는 무엇인가요?"
  - "이번 달과 지난 달의 이슈 종료율을 비교합니다."
- GLQL 쿼리 생성:
  - "제게 할당된 열려 있는 이슈에 대한 GLQL 쿼리를 작성합니다."
  - "이번주 병합된 모든 머지 리퀘스트를 표시하는 테이블을 작성합니다."
  - "팀 X의 열려 있는 작업에 대한 GLQL 임베드된 보기를 생성합니다."
  - "여러 레이블로 필터링하기 위한 GLQL 구문은 무엇인가요?"
- 작업 항목 검색:
  - "메인 브랜치를 대상으로 하는 머지 리퀘스트를 나열합니다."
  - "지난 24시간 내에 업데이트된 이슈를 찾습니다."
  - "팀 X에 할당된 열려 있는 버그를 표시합니다."
