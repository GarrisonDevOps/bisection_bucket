---
stage: Agent Foundations
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab Duo 기능에서 사용 가능한 컨텍스트를 이해하고 이들이 액세스할 수 있는 정보를 제어하는 방법을 알아봅니다.
title: GitLab Duo Agent Platform 컨텍스트 인식
---

GitLab Duo가 결정을 내리고 제안을 제공하는 데 도움이 되는 다양한 정보를 사용할 수 있습니다.

정보는 다음과 같이 제공될 수 있습니다:

- 항상.
- 사용자의 위치를 기반으로(탐색할 때 컨텍스트가 변경됨).
- 명시적으로 참조될 때. 예를 들어 URL, ID 또는 파일 경로를 통해 정보를 언급합니다.

## GitLab Duo Agentic Chat {#gitlab-duo-agentic-chat}

{{< history >}}

- 현재 페이지 제목 및 URL이 GitLab 18.6에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/209186)되었습니다.

{{< /history >}}

GitLab Duo Agentic Chat에 사용 가능한 컨텍스트는 다음과 같습니다.

### 항상 사용 가능 {#always-available}

- GitLab 설명서.
- 일반적인 프로그래밍 지식, 모범 사례 및 언어별 특성.
- Git에서 추적하는 프로젝트와 모든 파일.
- GitLab [Search API](../../api/search.md)(Chat이 관련 이슈 또는 머지 리퀘스트를 찾는 데 사용).
- GitLab UI에서 Chat을 사용할 때 현재 페이지 제목 및 URL.

Chat은 SDLC 데이터, [지식 그래프](../project/repository/knowledge_graph/_index.md), [MCP Clients](../gitlab_duo/model_context_protocol/mcp_clients.md) 및 [custom instructions](customize/_index.md)에서 필요한 컨텍스트를 자동으로 조회합니다.

### 위치 기반 {#based-on-location}

- IDE에서 열어 놓은 파일. 컨텍스트에 사용하고 싶지 않으면 파일을 닫을 수 있습니다.
- GitLab UI에서 현재 페이지 컨텍스트(예: 머지 리퀘스트 또는 이슈를 볼 때).

### 명시적으로 참조될 때 {#when-referenced-explicitly}

GitLab Duo Agentic Chat은 다음을 자동으로 검색하고 사용할 수 있습니다:

- 파일(프로젝트를 검색하거나 파일 경로를 제공할 때)
- 에픽
- 이슈
- 머지 리퀘스트
- CI/CD 파이프라인 및 작업 로그
- 커밋
- 작업 항목

비에이전트 Chat과 달리 에이전트 Chat은 정확한 ID 또는 URL을 지정하도록 요구하지 않고도 이러한 리소스를 검색할 수 있습니다. 예를 들어 "인증에 관한 머지 리퀘스트 찾기"를 묻고 Chat은 관련 머지 리퀘스트를 검색합니다.

### 확장 컨텍스트 {#extended-context}

- Chat을 외부 데이터 소스 및 도구에 연결하려면 [Model Context Protocol (MCP)](../gitlab_duo/model_context_protocol/_index.md)를 사용합니다.
- 프로젝트별 컨텍스트, 코딩 표준 및 팀 방식을 제공하려면 Chat, 에이전트 및 플로우에서 [custom rules](customize/custom_rules.md) 또는 [AGENTS.md](customize/agents_md.md)를 사용합니다.

## 소프트웨어 개발 플로우 {#software-development-flow}

GitLab Duo Agent Platform의 소프트웨어 개발 플로우에 사용 가능한 컨텍스트는 다음과 같습니다.

### 항상 사용 가능 {#always-available-1}

- 일반적인 프로그래밍 지식, 모범 사례 및 언어별 특성.
- Git에서 추적하는 프로젝트와 모든 파일.
- GitLab [Search API](../../api/search.md)(관련 이슈 또는 머지 리퀘스트를 찾는 데 사용됨).

### 위치 기반 {#based-on-location-1}

- IDE에서 열어 놓은 파일(컨텍스트에 사용하고 싶지 않으면 파일을 닫습니다).

### 명시적으로 참조될 때 {#when-referenced-explicitly-1}

- 파일
- 에픽
- 이슈
- 머지 리퀘스트
- 머지 리퀘스트의 파이프라인

## GitLab Duo에서 컨텍스트 제외 {#exclude-context-from-gitlab-duo}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}
{{< history >}}

- `use_duo_context_exclusion`라는 이름의 [기능 플래그](../../administration/feature_flags/_index.md)로 GitLab 18.2에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/17124)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.4에서 베타로 변경되었습니다.
- GitLab 18.5에서 기본적으로 활성화됩니다.
- GitLab 18.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/589801)합니다.

{{< /history >}}

GitLab Duo의 컨텍스트로 제외되는 프로젝트 콘텐츠를 제어할 수 있습니다. 이 기능을 사용하여 암호 및 구성 파일과 같은 민감한 정보를 보호합니다.

콘텐츠를 제외하면 모든 GitLab Duo Agent Platform 기능이 이 정보를 컨텍스트에서 제외합니다.

### GitLab Duo 컨텍스트 제외 관리 {#manage-gitlab-duo-context-exclusions}

GitLab Duo가 제외할 콘텐츠를 지정하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **GitLab Duo** 아래의 **GitLab Duo 컨텍스트 제외항목** 섹션에서 **제외 관리**를 선택합니다.
1. GitLab Duo 컨텍스트에서 제외되는 프로젝트 파일 및 디렉터리를 지정하고 **제외 저장**을 선택합니다.
1. 선택 사항. 기존 제외를 삭제하려면 적절한 제외에 대해 **삭제**({{< icon name="remove" >}})를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 알려진 이슈 {#known-issues}

[GitLab MCP server](../model_context_protocol/mcp_server.md)의 컨텍스트 제외에 대한 알려진 문제는 다음과 같습니다:

- `get_merge_request` 도구는 제외된 파일의 콘텐츠를 포함하는 커밋 차이를 반환할 수 있습니다. GitLab MCP server는 차이를 가져올 때 제외를 확인하지 않습니다.
- `add_commit` 도구에는 한 경로에서 다른 경로로 파일을 복사하는 `move` 작업이 있습니다. 소스 파일이 제외되면 제외 확인이 소스 경로에 적용되지 않습니다. 푸시 액세스 권한이 있는 에이전트는 제외된 파일을 제외되지 않은 경로로 이동한 후 해당 콘텐츠를 읽을 수 있습니다.

이러한 알려진 문제는 [issue 628141](https://gitlab.com/gitlab-org/gitlab/-/work_items/628141)에서 추적됩니다. 민감한 정보를 보호하려면 민감한 프로젝트에 액세스하는 MCP 클라이언트에 부여된 도구 및 권한을 검토합니다.
