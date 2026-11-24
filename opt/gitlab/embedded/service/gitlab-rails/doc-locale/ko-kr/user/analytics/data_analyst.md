---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Data Analyst 에이전트
---

{{< details >}}

- 티어: [Free](../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.6에서 `foundational_analytics_agent` [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/578342)되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab 18.7에서](https://gitlab.com/gitlab-org/gitlab/-/issues/583940) [베타](../../policy/development_stages_support.md#beta)로 변경되었습니다.
- GitLab 18.7에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에 사용으로 설정](https://gitlab.com/gitlab-org/gitlab/-/issues/583940)되었습니다.
- GitLab 18.11에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/work_items/584536)합니다.

{{< /history >}}

Data Analyst 에이전트는 GitLab 플랫폼 전반에서 데이터를 쿼리, 시각화 및 표시하는 데 도움이 되는 전문화된 AI 어시스턴트입니다. [GitLab Query Language (GLQL)](../glql/_index.md)과 [Orbit](https://docs.gitlab.com/orbit/)을 사용하여 데이터를 검색 및 분석한 후 프로젝트와 그룹에 대한 명확하고 실행 가능한 인사이트를 제공합니다. 사용 중인 티어에서 사용할 수 있는 데이터 소스 및 필드에 대한 정보는 [GLQL 데이터 소스](../glql/data_sources/_index.md) 및 [Orbit 인덱싱 내용](https://docs.gitlab.com/orbit/remote/indexing/)을 참조하세요.

다음 작업이 필요한 경우 Data Analyst 에이전트를 사용하세요:

- 볼륨 분석: 기간 동안의 머지 리퀘스트, 이슈 또는 기타 작업 항목 개수 계산.
- 팀 성과: 팀 구성원이 수행한 작업과 결과물 파악.
- 추세 분석: 개발 워크플로우의 패턴 파악.
- 상태 모니터링: 프로젝트 또는 그룹 전체의 작업 항목 상태 확인.
- 작업 항목 검색: 작성자, 레이블, 마일스톤 또는 기타 조건별로 이슈, 머지 리퀘스트 또는 에픽 찾기.
- GLQL 쿼리 생성: 이슈, 머지 리퀘스트, 에픽, 댓글, 위키, 스니펫 및 릴리스를 포함하여 GitLab Flavored Markdown을 지원하는 어디에나 임베드할 수 있는 쿼리 생성.

<i class="fa-youtube-play" aria-hidden="true"></i> 개요를 보려면 [GitLab Duo Data Analyst 데모](https://youtu.be/9MTT2P_t-CU)를 참조하세요.

[issue 574028](https://gitlab.com/gitlab-org/gitlab/-/issues/574028)에서 피드백을 남길 수 있습니다.

## 알려진 이슈 {#known-issues}

- 에이전트는 쿼리된 데이터에 대해 간단한 집계를 수행할 수 있지만, 100개를 초과하는 데이터 세트의 결과는 불완전할 수 있습니다.
- GLQL은 [특정 영역](../glql/data_sources/_index.md)에 대한 쿼리를 지원하지만 모든 GitLab 데이터 소스를 지원하지는 않습니다.
- 에이전트는 작업 항목 또는 대시보드로 직접 출력할 수 없습니다. 그러나 생성된 GLQL 쿼리를 복사하여 GitLab Flavored Markdown을 지원하는 모든 페이지에 임베드할 수 있습니다.

## Data Analyst 에이전트 사용 {#use-the-data-analyst-agent}

GitLab UI, VS Code 및 JetBrains IDE에서 Data Analyst 에이전트를 사용할 수 있습니다.

### GitLab UI에서 {#in-the-gitlab-ui}

전제 조건:

- 기본 에이전트를 [활성화](../duo_agent_platform/agents/foundational_agents/_index.md#turn-foundational-agents-on-or-off)합니다.

GitLab UI에서 Data Analyst 에이전트를 사용하려면:

1. GitLab Duo 사이드바에서 **새 채팅 추가**({{< icon name="pencil-square" >}})를 선택하세요.
1. 드롭다운 목록에서 **데이터 분석가**를 선택하세요.

   화면 오른쪽의 GitLab Duo 사이드바에서 Chat 대화창이 열립니다.
1. 분석 질문이나 요청을 입력하세요. 요청에서 최고의 결과를 얻으려면:

   - 데이터에 대해 질문할 때 범위(프로젝트 또는 그룹)를 지정하세요.
   - 시간 기반 분석을 위해 시간 범위를 포함하세요.
   - 관심 있는 작업 항목의 유형을 구체적으로 지정하세요.

### VS Code에서 {#in-vs-code}

전제 조건:

- 기본 에이전트를 [활성화](../duo_agent_platform/agents/foundational_agents/_index.md#turn-foundational-agents-on-or-off)합니다.
- [GitLab for VS Code](../../editor_extensions/visual_studio_code/setup.md) 버전 6.57.3 이상을 설치 및 구성하세요.
- [기본 GitLab Duo 네임스페이스](../profile/preferences.md#set-a-default-gitlab-duo-namespace)를 설정해야 합니다.

VS Code에서 Data Analyst 에이전트를 사용하려면:

1. VS Code의 왼쪽 사이드바에서 **GitLab Duo 에이전트 플랫폼**({{< icon name="duo-agentic-chat" >}})을 선택하세요.
1. **채팅** 탭을 선택합니다.
1. 메시지 상자 아래의 에이전트 드롭다운 목록에서 **데이터 분석가**를 선택하세요. [클래식 레이아웃](../gitlab_duo_chat/agentic_chat.md#change-the-layout-in-your-ide)에서 **채팅** 탭을 선택한 후 **새 채팅**({{< icon name="duo-chat-new" >}}) 드롭다운 목록에서 **데이터 분석가**를 선택하세요.
1. 분석 질문이나 요청을 입력하세요. 요청에서 최고의 결과를 얻으려면:

   - 데이터에 대해 질문할 때 범위(프로젝트 또는 그룹)를 지정하세요.
   - 시간 기반 분석을 위해 시간 범위를 포함하세요.
   - 관심 있는 작업 항목의 유형을 구체적으로 지정하세요.

### JetBrains IDE에서 {#in-jetbrains-ides}

전제 조건:

- 기본 에이전트를 [활성화](../duo_agent_platform/agents/foundational_agents/_index.md#turn-foundational-agents-on-or-off)합니다.
- [JetBrains IDE용 GitLab Duo 플러그인](../../editor_extensions/jetbrains_ide/setup.md) 버전 3.24.4 이상을 설치 및 구성하세요.
- [기본 GitLab Duo 네임스페이스](../profile/preferences.md#set-a-default-gitlab-duo-namespace)를 설정해야 합니다.

먼저 GitLab Duo 에이전트 플랫폼을 사용 가능하도록 설정합니다.

1. JetBrains IDE에서 **설정** > **도구** > **GitLab Duo**로 이동합니다.
1. **GitLab Duo Agent Platform** 아래에서 **GitLab Duo Agent Platform 사용으로 설정** 확인란을 선택합니다.
1. 메시지가 표시되면 IDE를 다시 시작합니다.

그 다음 Data Analyst 에이전트를 사용하려면:

1. JetBrains IDE의 오른쪽 도구 창 표시줄에서 **GitLab Duo 에이전트 플랫폼**({{< icon name="duo-agentic-chat" >}})을 선택하세요.
1. **채팅** 탭을 선택합니다.
1. 메시지 상자 아래의 에이전트 드롭다운 목록에서 **데이터 분석가**를 선택하세요. [클래식 레이아웃](../gitlab_duo_chat/agentic_chat.md#change-the-layout-in-your-ide)에서 **채팅** 탭을 선택한 후 **새 채팅**({{< icon name="duo-chat-new" >}}) 드롭다운 목록에서 **데이터 분석가**를 선택하세요.
1. 분석 질문이나 요청을 입력하세요. 요청에서 최고의 결과를 얻으려면:

   - 데이터에 대해 질문할 때 범위(프로젝트 또는 그룹)를 지정하세요.
   - 시간 기반 분석을 위해 시간 범위를 포함하세요.
   - 관심 있는 작업 항목의 유형을 구체적으로 지정하세요.

## 프롬프트 예시 {#example-prompts}

- 볼륨 및 개수 계산:
  - "이번 달에 병합된 머지 리퀘스트는 몇 개입니까?"
  - "지난주에 생성된 이슈를 계산하세요."
  - "현재 열려 있는 버그는 몇 개입니까?"
- 팀 성과:
  - "@username이 이번 달에 무엇을 했습니까?"
  - "지난 2주 동안 팀 X에서 병합한 머지 리퀘스트를 보여주세요."
  - "제게 할당된 제목 및 레이블이 있는 이슈 테이블을 보여주세요."
  - "작성자별로 열려 있는 머지 리퀘스트를 나열하세요."
- 상태 및 모니터링:
  - "`~priority::1` 및 `~bug` 레이블이 있는 열려 있는 이슈를 보여주세요."
  - "기한이 지난 이슈를 보여주세요."
  - "검토 대기 중인 머지 리퀘스트는 무엇입니까?"
  - "현재 마일스톤의 이슈를 나열하세요."
- 추세 분석:
  - "지난달 동안의 머지 리퀘스트 활동을 보여주세요."
  - "이번 분기의 버그 생성 추세는 어떻습니까?"
  - "이번 달과 지난달 간의 이슈 종료 비율을 비교하세요."
- GLQL 쿼리 생성:
  - "제게 할당된 열려 있는 이슈에 대한 GLQL 쿼리를 작성하세요."
  - "이번주에 병합된 모든 머지 리퀘스트를 보여주는 테이블을 만드세요."
  - "팀 X의 열려 있는 작업에 대한 GLQL 임베디드 보기를 생성하세요."
  - "여러 레이블로 필터링하는 GLQL 구문은 무엇입니까?"
- 작업 항목 검색:
  - "메인 브랜치를 대상으로 하는 머지 리퀘스트를 나열하세요."
  - "지난 24시간 동안 업데이트된 이슈를 찾으세요."
  - "팀 X에 할당된 열려 있는 버그를 보여주세요."
