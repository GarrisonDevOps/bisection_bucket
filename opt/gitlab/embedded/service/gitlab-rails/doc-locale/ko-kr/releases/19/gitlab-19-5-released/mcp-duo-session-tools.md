---
title: MCP 서버 GitLab Duo 에이전트 및 플로우 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools/#start_duo_session"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/21395
categories: [ Agent Tools ]
level: secondary
weight: 50
---

새로운 GitLab Duo 에이전트 및 플로우 도구를 통해 모든 MCP 클라이언트에서 GitLab Duo 에이전트 및 플로우를 호출하고 추적할 수 있습니다:

- `start_duo_session`는 세션을 시작합니다.
- `get_duo_session`은(는) 세션의 현재 상태를 읽습니다.
- `list_duo_sessions`는 세션 기록을 페이지 단위로 표시합니다.
- `list_duo_agents_and_flows`는 프로젝트에서 활성화된 GitLab Duo 에이전트 및 플로우를 나열합니다.
