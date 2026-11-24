---
title: 기타 개선 사항
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
co_create: true
documentation_link: "../../../user/model_context_protocol/mcp_server_troubleshooting/#error-rate_limited-tool-result"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256657
categories: [ Agent Tools ]
level: secondary
weight: 80
---

이 릴리스의 기타 개선 사항은 다음과 같습니다:

- GitLab MCP 서버: 속도 제한 도구 결과가 제한 및 재시도 지연을 표시하고, `add_branch`은 브랜치 `web_url`을 반환하며, 활성화된 도구 헤더의 도구 별칭이 해결되고, 일치하지 않는 URL 및 프로젝트 ID 입력은 거부되며, `ai_workflows` 토큰은 배치에서 Blob을 읽을 수 있습니다.
- 관리 모드의 관리자는 프로젝트에 참여하지 않고도 환경에서 클러스터 에이전트를 설정할 수 있습니다.
- `CI_JOB_TAGS`과 `CI_RUNNER_TAGS`은 각 태그를 JSON으로 인코딩합니다. 푸시 옵션의 중복된 변수 키는 거부됩니다.
- Advanced SAST (Ultimate): 깊이가 20 수준까지인 C 및 C++ 파일이 스캔되며, 보고서는 아티팩트 보존 정책을 따릅니다.
- 일반 텍스트 토큰 및 SSH 키 이메일은 올바른 페이지로 연결되며, `?scopes=` 링크는 토큰 양식을 미리 채웁니다.

이러한 기여를 해주신 다음 사용자들께 감사드립니다!

- [otutukingsley](https://gitlab.com/otutukingsley)([머지 리퀘스트](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256657))
- [Jeston Singh](https://gitlab.com/sjestonsingh)([머지 리퀘스트 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255143) [머지 리퀘스트 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255111) [머지 리퀘스트 3](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255142) [머지 리퀘스트 4](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253823) [머지 리퀘스트 5](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254734) [머지 리퀘스트 6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254613))
- [ryo-whaletech](https://gitlab.com/ryo-whaletech)([머지 리퀘스트 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254573) [머지 리퀘스트 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256563) [머지 리퀘스트 3](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256718))
- [Mohamed Elsayed](https://gitlab.com/MooSayed11)([머지 리퀘스트](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256268))
- [Gerardo Navarro](https://gitlab.com/gerardo-navarro)([머지 리퀘스트](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169626))
- [Torben Buck](https://gitlab.com/torben.buck)([머지 리퀘스트 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254859) [머지 리퀘스트 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255638) [머지 리퀘스트 3](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254871))
