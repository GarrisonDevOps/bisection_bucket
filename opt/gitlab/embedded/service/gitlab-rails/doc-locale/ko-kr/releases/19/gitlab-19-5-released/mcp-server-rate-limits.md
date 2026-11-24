---
title: "GitLab MCP 서버의 새로운 속도 제한"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server/#rate-limits"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22800
categories: [ Agent Tools ]
level: secondary
weight: 50
---

현재 에이전트를 MCP를 통해 GitLab에 연결하면 워크플로우가 실제로 필요한 것보다 더 빨리 다시 연결하거나 재시도하는 것을 막을 수 없으며, GitLab.com에서는 이로 인한 비용이 발생합니다. 

10월 15일부터 GitLab.com의 GitLab MCP 서버는 Free 티어에서 분당 60개의 요청으로, Premium과 Ultimate에서는 600개의 요청으로 각 사용자를 제한합니다. 모든 재연결과 재시도는 사용자의 한도에 포함됩니다. 에이전트가 속도 제한(HTTP 429) 오류를 시작하면 더 높은 티어로 업그레이드하기 전에 재연결 및 재시도 설정을 확인하세요.
