---
title: MCP 서버 머지 리퀘스트 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/627598
categories: [ Agent Tools ]
level: secondary
weight: 50
---

머지 리퀘스트 도구를 사용하면 에이전트가 GitLab MCP 서버를 통해 전체 머지 리퀘스트 루프를 실행할 수 있습니다:

- `save_merge_request`은(는) 머지 리퀘스트를 열고 업데이트합니다.
- `get_merge_request`은(는) 머지 리퀘스트를 자세히 검사하며, 새로운 diff, 충돌, 승인 측면을 포함합니다.
- `save_merge_request_review`은(는) 줄 수준의 검토 의견을 남기고, 일괄 처리된 diff 의견 및 요약을 단일 호출로 제공합니다.
- `accept_merge_request`은(는) 검사가 통과하면 머지 리퀘스트를 병합하며, 승인하거나 승인을 취소할 수도 있습니다.
