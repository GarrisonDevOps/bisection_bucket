---
title: MCP 서버 리포지토리 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/627598
categories: [ Agent Tools ]
level: secondary
weight: 50
---

새로운 리포지토리 도구를 통해 에이전트는 프로젝트의 구조를 탐색하고, 커밋 히스토리를 읽으며, GitLab MCP 서버를 통해 변경 사항을 제안할 수 있습니다:

- `list_repository_tree`은(는) 파일 트리를 탐색합니다.
- `list_tags`은(는) 참조를 나열합니다.
- `list_releases`은(는) 게시된 릴리스를 검사합니다.
- `get_commit`은(는) 커밋의 메타데이터, diff 또는 노트를 검색합니다.
- `list_commits`은(는) 브랜치의 기록을 페이징합니다.
- `add_commit`은(는) 한 번의 호출로 하나 이상의 파일 작업을 커밋하며, 필요에 따라 특정 시작 참조 또는 소스 리포지토리에서 새 브랜치로 커밋할 수 있습니다.
- `fork_repository`은(는) 프로젝트를 포크하므로 에이전트가 업스트림 리포지토리 탐색에서 클라이언트를 떠나지 않고 변경 사항을 제안할 수 있습니다.
