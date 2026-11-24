---
title: 커뮤니티에서 기여한 GitLab MCP 서버 도구
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
co_create: true
documentation_link: "../../../user/model_context_protocol/mcp_server_tools/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248155
categories: [ Agent Tools ]
level: secondary
weight: 30
---

커뮤니티 기여자들이 GitLab MCP 서버의 새로운 도구를 추가했습니다. 에이전트는 이제 `get_project`와 `list_project_members`를 사용하여 프로젝트 메타데이터 및 멤버를 읽고, `list_branches`를 사용하여 리포지토리의 브랜치를 나열하고, `list_merge_requests`를 사용하여 전체 그룹의 머지 리퀘스트를 나열할 수 있습니다. `get_duo_session`는 GitLab Duo 세션을 가져오므로 이전 실행에서 수행한 작업을 볼 수 있습니다.

이러한 도구는 19.4의 다른 새로운 GitLab MCP 서버 도구와 함께 제공되며 동일한 도구 거버넌스 아래에서 실행되므로, 이를 사용하는 에이전트는 팀에서 이미 설정한 규칙을 따릅니다.

이러한 기여를 해주신 다음 사용자들께 감사드립니다!

- [Dhairya Majmudar](https://gitlab.com/DhairyaMajmudar) ([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248155) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250316))
- [Giannis Kepas](https://gitlab.com/gkepas) ([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250430) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251379))
- [Mahaveer A](https://gitlab.com/Mahaveer1013) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252619))
