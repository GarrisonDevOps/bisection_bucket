---
title: GitLab Duo CLI 플러그인 및 마켓플레이스(실험)
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/customize/#plugins"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22497
categories: [ Duo CLI ]
level: secondary
weight: 50
---

GitLab Duo CLI는 이제 플러그인 및 플러그인 마켓플레이스를 실험으로 지원하며, GitLab Duo CLI 9.10.0에서 소개되었습니다. 플러그인은 Agent Skills, 사용자 지정 슬래시 명령어, Model Context Protocol(MCP) 서버를 단일 디렉토리로 번들링합니다. 마켓플레이스는 Git 리포지토리 또는 로컬 디렉토리에 호스팅되는 사용 가능한 플러그인의 카탈로그입니다.

GitLab Duo CLI는 처음으로 플러그인을 사용할 때 공식 `gitlab-duo-plugins` 마켓플레이스를 자동으로 등록합니다.

마켓플레이스에는 일반적인 GitLab 워크플로우를 위한 세 가지 스킬이 포함되어 있습니다:

- `mr-review`: 머지 리퀘스트를 검토하고 댓글을 게시합니다.
- `stack-changes`: 큰 로컬 변경 사항을 스택된 머지 리퀘스트 체인으로 분할합니다.
- `create-issue`: 자연어 설명에서 GitLab 이슈를 작성합니다.

스킬 중 하나를 설치하려면 `glab duo cli plugin install <plugin>@gitlab-duo-plugins` 또는 `duo plugin install <plugin>@gitlab-duo-plugins`를 실행하세요. 설정에 따라 달라집니다.

기존 커뮤니티 플러그인 생태계와의 호환성을 위해 GitLab Duo CLI는 `.claude-plugin/marketplace.json` 파일을 읽으므로 기존 Claude Code 플러그인 마켓플레이스가 GitLab Duo CLI에서 수정 없이 작동합니다.
