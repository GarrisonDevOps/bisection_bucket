---
title: 일반적으로 사용 가능한 API로 플로우 트리거
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../api/duo_agent_platform_flows/#trigger-a-flow"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/607860
categories: [ Agent Tools ]
level: secondary
weight: 50
---

이전 GitLab 버전에서 CI/CD 파이프라인, 스크립트 및 기타 자동화에서 GitLab Duo Agent Platform 플로우를 트리거하기 위해 사용하는 API 엔드포인트는 실험 상태였으므로 프로덕션 환경에서 신뢰할 수 있는지 판단하기 어려웠습니다. 이제 Flows API의 [플로우 트리거 엔드포인트](../../../api/duo_agent_platform_flows.md#trigger-a-flow)가 일반적으로 사용 가능하므로 GitLab REST API 호환성 정책을 따르는 프로덕션 자동화를 구축할 수 있습니다.
