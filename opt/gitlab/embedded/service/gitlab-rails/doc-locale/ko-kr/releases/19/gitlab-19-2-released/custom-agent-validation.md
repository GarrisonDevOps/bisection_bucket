---
title: 사용자 지정 에이전트 유효성 검사
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/duo_agent_platform/agents/custom"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/601986
categories: [ AI Catalog Creation ]
level: secondary
weight: 50
---

이전에는 AI 카탈로그에서 실행할 때 프롬프트가 실패하는 사용자 지정 에이전트를 저장할 수 있었습니다. 예를 들어 보안 규칙을 위반한 프롬프트는 에이전트가 사용 중일 때 조용히 아무것도 하지 않도록 했습니다.

이제 사용자 지정 에이전트를 만들거나 업데이트할 때 GitLab은 프롬프트 구성의 유효성을 검사하고 해당 에이전트를 저장하기 전에 오류에 대해 알려줍니다.
