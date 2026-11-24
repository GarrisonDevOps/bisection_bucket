---
title: GitLab MCP 서버 도구에 대한 거버넌스
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
tier: [ Free, Premium, Ultimate ]
stage: software_supply_chain_security
documentation_link: "../../../user/ai-governance/tool-governance"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/628391
categories: [ AI Governance ]
level: primary
weight: 50
---

이전에는 [AI 에이전트 도구 거버넌스](../../../user/ai-governance/tool-governance.md) 규칙을 내부 GitLab Duo Agent Platform 도구에만 적용할 수 있었습니다. GitLab MCP 서버를 통해 GitLab Duo Agent Platform과 타사 에이전트 모두에서 사용할 수 있는 도구는 변경할 수 없는 고정 규칙을 따랐습니다.

이제 내부 GitLab Duo Agent Platform 도구와 같은 위치에서 GitLab MCP 서버 도구를 거버넌스할 수 있습니다. 이러한 도구는 그룹 및 프로젝트의 **GitLab Duo** 설정에서 내부 도구와 함께 표시되며, 여기서 각 도구의 모드를 설정할 수 있습니다:

- 읽기 전용 도구는 기본적으로 **Always Allow**로 설정되므로 팀의 업무 흐름을 방해하지 않으면서 일상적인 조회가 실행됩니다.
- 쓰기 및 삭제 도구는 기본적으로 **Always Ask**로 설정되어 에이전트가 변경하기 전에 검토자가 확인할 수 있는 체크포인트를 제공합니다.
