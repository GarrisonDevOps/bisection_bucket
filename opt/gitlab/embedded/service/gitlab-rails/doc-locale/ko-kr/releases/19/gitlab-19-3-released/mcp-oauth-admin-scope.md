---
title: MCP OAuth 애플리케이션 사전 등록
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server#reuse-a-pre-registered-oauth-application"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/601437
categories: [ Agent Tools ]
level: secondary
weight: 50
---

이전에는 `mcp` 범위가 **운영자** 영역의 OAuth 애플리케이션 양식에서 숨겨져 있어서 Dynamic Client Registration(DCR)을 사용하지 않고는 MCP 클라이언트용 OAuth 애플리케이션을 사전 등록할 수 없었습니다. 이제 **운영자** 영역에서 직접 `mcp` 범위로 공유 OAuth 애플리케이션을 만들 수 있으므로 사용자에게 재사용 가능한 안정적인 클라이언트 ID를 제공하고 공유 네트워크에서 DCR 속도 제한을 피할 수 있습니다.
