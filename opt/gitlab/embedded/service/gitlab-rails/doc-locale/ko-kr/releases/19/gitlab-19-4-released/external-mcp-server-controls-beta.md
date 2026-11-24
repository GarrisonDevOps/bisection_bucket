---
title: MCP 서버 접근 제한하기 (베타)
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: software_supply_chain_security
documentation_link: "../../../user/ai-governance/tool-governance/#block-model-context-protocol-mcp-servers"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/628378
categories: [ AI Governance ]
level: primary
weight: 50
---

이제 MCP(Model Context Protocol) 서버의 접근을 허용하거나 거부하여 접근을 제한할 수 있습니다:

- 전체 외부 MCP 서버.
- MCP 서버의 개별 도구.

이 기능은 Duo Agent Platform의 AI 에이전트가 제어되는 경계 내에서 작동하고 범위 내의 MCP 도구에만 접근하여 활동, 세션 및 작업을 수행할 수 있도록 보장합니다.

이 제어 기능은 다음을 포함하여 AI 에이전트가 실행되는 모든 곳에서 일관되게 적용됩니다:

- Agentic Chat.
- 플로우.
- IDE 및 CLI 환경.

이 기능은 현재 베타 상태이며 [이슈 #628378](https://gitlab.com/gitlab-org/gitlab/-/issues/628378)에서 피드백을 환영합니다.
