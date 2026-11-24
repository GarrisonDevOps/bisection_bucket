---
stage: none
group: Embody
info: This page is owned by <https://handbook.gitlab.com/handbook/engineering/embody-team/>
description: AI 어시스턴트의 GitLab Observability 데이터를 Model Context Protocol 서버로 쿼리합니다.
ignore_in_report: true
title: Observability MCP 서버
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com
- 상태:  베타

{{< /details >}}

{{< history >}}

- [GitLab 19.3에서 도입되었으며](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248200) [실험](../../policy/development_stages_support.md#experiment)으로 제공됩니다.
- [실험에서](https://gitlab.com/gitlab-org/gitlab/-/work_items/632757) [베타](../../policy/development_stages_support.md#beta)로 변경되었습니다(GitLab 19.5).

{{< /history >}}

GitLab Observability는 [Model Context Protocol (MCP)](https://modelcontextprotocol.io) 서버를 제공하므로 AI 어시스턴트 및 에이전트에서 자연 언어를 사용하여 Observability 데이터를 쿼리할 수 있습니다.

연결한 후, MCP 지원 클라이언트는 원격 분석 정보에 대해 질문하고 자신의 데이터로 뒷받침된 답변을 받을 수 있습니다. 지원되는 클라이언트는 Cursor, Claude(Claude Code 및 Claude Desktop), VS Code, Codex입니다. 예를 들어:

- 지난 1시간 동안 오류율이 가장 높은 서비스는 무엇입니까?
- 체크아웃 서비스에 대한 오류 로그를 표시합니다.
- 오늘 결제 서비스의 p99 레이턴시는 얼마입니까?
- 데이터를 보고하는 서비스 목록을 표시합니다.

MCP 서버는 GitLab Observability 인스턴스에서 메트릭, 추적, 로그, 경고, 대시보드 및 서비스를 쿼리할 수 있습니다.

## 전제 조건 {#prerequisites}

- Observability는 그룹 또는 개인 프로젝트에 대해 활성화되어야 합니다. 설정 지침은 [GitLab.com에서 Observability 설정](setup_gitlab_com.md)을 참조합니다.
- 그룹의 경우, Developer, Maintainer 또는 Owner 역할이 있어야 합니다. 개인 프로젝트의 경우 Owner 역할이 있어야 합니다.
- 원격 HTTP 서버를 지원하는 MCP 클라이언트가 필요합니다.

## API 키 가져오기 {#get-your-api-key}

MCP 서버는 자체 상태 자격 증명이 없습니다. 각 사용자는 자신의 GitLab Observability API 키로 인증하고 해당 MCP 클라이언트가 모든 요청에서 이를 전송합니다. 액세스는 해당 키가 볼 수 있는 범위로 제한됩니다.

API 키를 생성하려면:

1. 맨 위 표시줄에서 **검색 또는 이동**을 선택하고 그룹 또는 개인 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **통합관찰** > **API 키**를 선택합니다.
1. 키를 생성하고 복사합니다.

> [!warning]
> API 키를 안전하게 저장합니다. 버전 제어에 커밋하지 마십시오. MCP 클라이언트의 암호 관리 또는 환경 변수 지원을 사용하십시오(사용 가능한 경우).

## MCP 엔드포인트 가져오기 {#get-your-mcp-endpoint}

1. 맨 위 표시줄에서 **검색 또는 이동**을 선택하고 그룹 또는 개인 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **통합관찰** > **설정**을 선택합니다.
1. **MCP 서버** 섹션에서 **MCP 엔드포인트**를 복사합니다.

MCP 엔드포인트는 다음 패턴을 따릅니다:

```plaintext
https://<namespace_id>.mcp.gitlab-o11y.com/mcp
```

`<namespace_id>`을(를) Observability를 활성화한 네임스페이스의 ID로 바꿉니다. 네임스페이스 ID는 그룹 ID이거나, 개인 프로젝트에서 Observability를 활성화한 경우 개인 네임스페이스 ID입니다.

## 클라이언트 연결 {#connect-a-client}

1. 복사한 엔드포인트를 사용하여 MCP 서버를 새 원격 HTTP MCP 서버로 클라이언트에 추가합니다.
1. 클라이언트가 인증을 위해 메시지를 표시할 때 생성한 API 키를 제공합니다. 클라이언트는 이를 `SIGNOZ-API-KEY` 헤더로 전송합니다.
1. 클라이언트에서 연결을 확인합니다. 예를 들어, 사용 가능한 MCP 도구를 나열한 다음 Observability 데이터에 대해 질문하기 시작합니다.

## 사용 가능한 도구 {#available-tools}

MCP 서버는 Observability 데이터를 읽고 탐색하기 위한 도구를 노출하며, 다음을 포함합니다:

- 메트릭: 나열 및 쿼리
- 로그: 검색 및 집계
- 추적: 개별 추적 및 범위 검색 및 검사
- 서비스: 나열 및 상위 작업 보기
- 경고: 경고 규칙 나열 및 검사
- 대시보드: 대시보드 및 저장된 보기 나열 및 검사

AI 어시스턴트는 질문에 답변하기 위해 적절한 도구를 선택하고 인스턴스 데이터에서 가져온 결과를 반환합니다.

## 관련 항목 {#related-topics}

- [Observability API 액세스](api_access.md)
- [GitLab Observability로 원격 분석 데이터 전송](send.md)
- [Observability 문제 해결](troubleshooting.md)
