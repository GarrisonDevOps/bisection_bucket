---
title: 머지 리퀘스트를 읽고 검색하기 위한 새로운 MCP 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/605878
categories: [ Agent Tools ]
level: secondary
weight: 50
---

이제 `get_merge_request`를 사용하여 머지 리퀘스트와 함께 diff, 커밋, 노트, 파이프라인 또는 논의를 단일 호출로 검색할 수 있으므로, AI 에이전트가 더 이상 MR의 전체 그림을 얻기 위해 여러 요청을 연결할 필요가 없습니다.

새로운 `list_merge_requests` 도구를 사용하여 머지 리퀘스트를 작성자, 담당자, 검토자, 상태, 레이블 또는 자유 텍스트 쿼리로 검색하고 필터링할 수도 있으므로, 워크플로우를 벗어나지 않고도 관심 있는 머지 리퀘스트를 정확하게 찾을 수 있습니다.
