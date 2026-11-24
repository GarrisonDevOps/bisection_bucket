---
title: 외부 연결 에이전트(ECA)를 AI 거버넌스에 연결
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: software_supply_chain_security
documentation_link: "../../../user/ai-governance/externally-connected-agents"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/633489
categories: [ AI Governance ]
level: primary
weight: 50
---

이전에는 [AI 거버넌스 대시보드](../../../user/ai-governance/governance-dashboard.md)에서 GitLab Duo 에이전트 플랫폼 에이전트의 활동만 표시했습니다. 이를 통해 실행 중인 세션, 도구 호출, 사용된 MCP 및 사용자와 에이전트 각각의 프롬프트 입력과 출력을 포함하여 모든 에이전트 플랫폼 에이전트에 대한 완전한 가시성을 얻을 수 있었습니다.

GitLab 19.5 릴리스에서는 일회용 `glab govern setup`을(를) 수행한 후 GitLab Duo 에이전트 플랫폼 에이전트에만 국한된 거버넌스 가시성을 확장하고, GitLab CLI(`glab`)를 사용하여 Claude Code, Cursor, Codex와 같은 외부 연결 에이전트(ECA)를 GitLab AI 거버넌스에 연결할 수 있습니다.

**외부 에이전트 허용** 및 **AI 감사 이벤트**가 활성화되면 보안 및 규정 준수 팀은 GitLab Duo 에이전트 플랫폼 에이전트와 함께 GitLab 외부에서 실행되는 ECA에 대한 가시성을 얻습니다. 적격 에이전트 세션이 모두 캡처되며, 이는 세션 및 도구 호출이 AI 거버넌스 대시보드와 AI 감사 이벤트 보고서에 나타나며, 누가 실행했는지, 어느 에이전트인지, 어느 프로젝트인지, 언제인지를 포함합니다. 감사 이벤트는 감사 이벤트 스트리밍을 통해 SIEM으로 흐릅니다.

도구 출력은 실패한 도구 호출의 짧은 오류 메시지를 제외하고 전송되지 않습니다.

이 기능은 베타 단계입니다. [이슈 633489](https://gitlab.com/gitlab-org/gitlab/-/work_items/633489)에서 피드백을 공유하세요.
