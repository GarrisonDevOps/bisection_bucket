---
title: 각 MCP OAuth 애플리케이션을 승인한 사용자 확인
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/605884
categories: [ AI Agents ]
level: secondary
weight: 50
---

이전에 MCP 클라이언트가 OAuth 동적 클라이언트 등록(DCR)을 사용하여 GitLab에 연결할 때, 동적으로 등록된 모든 OAuth 애플리케이션은 Admin Area에 일반적인 클라이언트 이름만으로 표시되어 어느 사용자가 특정 애플리케이션을 승인했는지 알 수 없었습니다. 이제 MCP OAuth 연결을 승인하면 사용자 이름이 자동으로 애플리케이션 이름에 추가됩니다. 예를 들어 `[Unverified Dynamic Application] kiro — authorized by @username`과 같이 표시됩니다. Admin Area에서 직접 추가 구성 없이 각 동적 OAuth 애플리케이션 뒤의 사용자를 빠르게 식별할 수 있습니다.
