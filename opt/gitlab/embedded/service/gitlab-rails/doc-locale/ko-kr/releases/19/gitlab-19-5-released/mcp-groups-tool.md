---
title: MCP 서버 그룹 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/607719
categories: [ Agent Tools ]
level: secondary
weight: 50
---

이전에는 MCP를 통해 GitLab에 연결되는 에이전트가 ID나 경로를 하드코딩하지 않고는 액세스 권한이 있는 그룹 및 하위 그룹을 검색할 수 있는 방법이 없었습니다. 새로운 `list_groups` 도구를 사용하면 에이전트가 조직의 그룹 계층을 독립적으로 탐색할 수 있으므로 식별자를 추측하는 대신 조치를 취하기 전에 올바른 그룹을 찾을 수 있습니다.
