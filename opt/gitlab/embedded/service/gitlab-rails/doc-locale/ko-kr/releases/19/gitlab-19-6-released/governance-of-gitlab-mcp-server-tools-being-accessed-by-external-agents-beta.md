---
title: AI 에이전트를 위한 GitLab MCP 서버 도구 관리
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: software_supply_chain_security
documentation_link: "../../../user/ai-governance/tool-governance/#gitlab-mcp-server-tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/633490
categories: [ AI Governance ]
level: primary
weight: 50
---

이제 GitLab MCP 서버 도구를 AI 에이전트가 사용할 수 있도록 제어할 수 있으며, 연결되는 모든 클라이언트에 대해 GitLab이 적용하는 규칙이 있습니다.

최상위 그룹의 소유자는 각 도구를 다음과 같이 설정합니다:

- **항상 거부**: 도구는 완전히 차단되며 에이전트에 표시되지 않습니다.
- **항상 묻기**: 도구를 실행하기 전에 사용자가 승인해야 합니다.
- **항상 허용**: 도구가 정상적으로 실행됩니다.

이 기능은 베타 단계입니다. 피드백을 제공하려면 [이슈 633490](https://gitlab.com/gitlab-org/gitlab/-/work_items/633490)을 참조하세요.
