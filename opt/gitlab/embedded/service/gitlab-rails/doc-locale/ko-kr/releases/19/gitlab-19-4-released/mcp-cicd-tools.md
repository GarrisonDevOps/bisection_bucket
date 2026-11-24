---
title: MCP 서버 CI/CD 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/627598
categories: [ Agent Tools ]
level: secondary
weight: 50
---

새로운 CI/CD 도구는 에이전트가 모든 MCP 클라이언트에서 CI/CD를 트리거, 검사 및 제어할 수 있습니다:

- `save_pipeline`은(는) 도구를 전환하지 않고도 파이프라인을 실행, 재시도 또는 취소합니다.
- `get_job`은(는) 작업 메타데이터를 작업 로그와 함께 반환하므로 에이전트가 실패한 빌드의 로그를 읽고 문제를 직접 진단할 수 있습니다.

이전에는 에이전트가 MCP를 통해 파이프라인을 트리거하거나 검사할 방법이 없었습니다.
