---
title: MCP 서버 작업 항목 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/627598
categories: [ Agent Tools ]
level: secondary
weight: 50
---

GitLab MCP 서버는 이제 작업 항목 도구를 노출하므로 에이전트와 MCP 클라이언트가 이슈, 에픽, 작업, 인시던트, 목표 및 핵심 결과를 검색, 읽기, 생성 및 업데이트할 수 있습니다.

`get_work_item`를 사용하여 단일 항목을 깊이 있게 읽고, `list_work_items`를 사용하여 그룹 또는 프로젝트 전체를 검색하고, `save_work_item`를 사용하여 모든 작업 항목 유형을 생성하거나 업데이트할 수 있습니다.

이슈와 에픽이 작업 항목 유형이므로 `get_work_item`과 `save_work_item`는 현재 `get_issue`과 `create_issue`가 수행하는 작업을 다룹니다.

`save_note`은 에이전트가 작업 항목 또는 머지 리퀘스트에 댓글을 달고 기존 스레드 내에서 답변할 수 있도록 합니다. 이 도구의 도입으로 기존 `create_merge_request_note`과 `create_workitem_note`의 이름이 바뀝니다.
