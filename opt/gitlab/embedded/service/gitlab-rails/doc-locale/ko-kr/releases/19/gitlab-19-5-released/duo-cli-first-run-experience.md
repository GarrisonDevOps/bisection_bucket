---
title: "GitLab Duo CLI의 개선된 첫 실행 환경"
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/use/#startup-cards"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22187
categories: [ Duo CLI ]
level: secondary
weight: 50
---

GitLab Duo CLI는 이제 터미널을 떠나지 않고 새로운 사용자가 시작할 수 있도록 도와줍니다:

- 첫 실행 시 온보딩 카드는 MCP 서버를 연결하고 GitLab 플러그인을 설치하는 데 도움이 됩니다.
- 각 새 세션은 열린 머지 리퀘스트 및 이슈에서 제안된 프롬프트로 시작됩니다. 머지 리퀘스트 프롬프트의 경우 GitLab Duo는 소스 브랜치가 존재하면 먼저 체크아웃합니다.
- 상태 표시줄에 브랜치, 프로젝트, 머지 리퀘스트, `/goal` 진행 상황 및 MCP 상태가 표시됩니다.
- 설정 화면은 토큰 생성으로 연결되며 저장하기 전에 토큰을 검증합니다.
- 프롬프트의 팁과 `/whatsnew` 명령은 새로운 기능으로 안내합니다.

전체 환경을 사용하려면 GitLab Duo CLI 9.28.0 이상으로 업데이트합니다.
