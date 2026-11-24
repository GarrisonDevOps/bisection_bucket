---
title: MCP 서버 프로젝트 및 사용자 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/627598
categories: [ Agent Tools ]
level: secondary
weight: 50
---

새로운 프로젝트 및 사용자 도구는 에이전트에게 GitLab MCP 서버를 통해 작업을 올바르게 수행하는 데 필요한 컨텍스트를 제공합니다:

- `list_projects`은(는) 프로젝트 세부 정보를 찾아 읽습니다.
- `get_user`은(는) 할당 및 멘션을 위해 사용자 세부 정보를 조회합니다.

이전에는 에이전트가 GitLab MCP 서버를 통해 프로젝트 또는 사용자 정보를 검색할 수 있는 방법이 없었습니다.
