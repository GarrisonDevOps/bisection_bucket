---
title: GraphQL의 리포지토리 태그 및 Terraform 상태
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
co_create: true
documentation_link: "../../../api/graphql/reference/#repositorytags"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255229
categories: [ Source Code Management ]
level: secondary
weight: 40
---

GraphQL은 이제 `Repository.tags`을 노출하며, 전방 페이지 매김, 검색 및 이름, 업데이트된 날짜, 버전 순서에 대한 `TagSort` 열거형을 지원하고 페이지당 최대 100개의 태그를 제공합니다. `Repository.tags`은 GitLab 19.5의 실험입니다. `TerraformState.versions`는 상태의 버전을 최신순으로 나열합니다. 머지 리퀘스트 REST API는 이제 단일 및 목록 응답에서 `author.bot`을 반환하므로 클라이언트는 Users API에 대한 두 번째 호출 없이 봇과 서비스 계정 작성자를 구분할 수 있습니다.

이러한 기여를 해주신 다음 사용자들께 감사드립니다!

- [Jeston Singh](https://gitlab.com/sjestonsingh)([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255229) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255230))
- [Ivane Gkomarteli](https://gitlab.com/ivane_gkomarteli)([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256381))
