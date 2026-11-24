---
title: "GitLab MCP 서버가 일반적으로 사용 가능합니다"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/19117
categories: [ Agent Tools ]
level: primary
weight: 10
---

GitLab의 이전 버전에서는 MCP 클라이언트가 제한된 GitLab 도구 집합에만 액세스할 수 있었습니다. 이제 GitLab MCP 서버가 일반적으로 사용 가능합니다.

MCP 서버를 사용하면 Claude Code 또는 Cursor와 같은 모든 MCP 호환 에이전트는 확장된 GitLab 도구 카탈로그, GitLab Duo Agent Platform 에이전트 및 플로우에 직접 액세스할 수 있습니다. 사용자의 에이전트는 GitLab 워크플로우의 더 많은 부분에서 작동하고 원하는 도구를 떠나지 않고도 Agent Platform 에이전트 및 플로우를 실행할 수 있습니다.
