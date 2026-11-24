---
title: MCP 서버 의미 검색 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250372
categories: [ Agent Tools ]
level: secondary
weight: 50
---

`semantic_code_search`이(가) 이제 `semantic_search`입니다. 이 도구는 이전 릴리스에서 변경되지 않은 정확한 기호나 파일 이름이 아닌 의미로 코드를 찾습니다. 이름 변경으로 인해 `scope` 매개변수가 추가되어 향후 릴리스에서 추가 인덱싱된 콘텐츠 유형을 동일한 도구에 포함할 수 있습니다. 현재 `scope`는 `code`만 허용합니다.

이 기여를 위해 [arun kumar](https://gitlab.com/arunsdev)에게 감사합니다!
