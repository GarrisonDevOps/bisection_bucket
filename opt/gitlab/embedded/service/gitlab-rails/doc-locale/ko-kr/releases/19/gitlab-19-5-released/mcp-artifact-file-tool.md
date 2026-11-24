---
title: MCP 서버 CI/CD 아티팩트 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/issues/585022
categories: [ Agent Tools ]
level: secondary
weight: 50
---

이전에는 에이전트가 CI/CD 작업의 빌드 아티팩트 내에서 무언가를 확인해야 하는 경우 한 파일을 읽기 위해 전체 아카이브를 다운로드하고 압축을 해제해야 했습니다. 이제 `get_artifact_file` MCP 도구를 통해 에이전트가 작업의 아티팩트에서 직접 단일 파일을 읽을 수 있으며, 로그, 생성된 보고서 또는 테스트 픽스처 중 어느 것이든 가능합니다.
