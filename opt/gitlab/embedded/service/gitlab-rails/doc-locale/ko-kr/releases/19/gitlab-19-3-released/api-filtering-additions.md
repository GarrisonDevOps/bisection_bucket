---
title: API를 통한 더 많은 필터링 및 관리 방법
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: foundations
co_create: true
documentation_link: "../../../api/rest/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/244359
categories: [ System Access ]
level: secondary
---

REST 및 GraphQL API에서 6가지 개선 사항을 이제 사용할 수 있습니다:

- 그룹 쿼리는 `visibilityLevel`과 `includeSubgroups`을 받아들이며, `aimed_for_deletion`으로 삭제 예정인 그룹을 필터링할 수 있습니다.
- 머지 리퀘스트 REST API는 `merged_after`과 `merged_before`를 받아들입니다.
- 성취도 수여 메시지는 수여 시점에만 설정하는 것이 아니라 수여 후에 편집할 수 있습니다.
- 관리자는 관리 토큰 API를 통해 SCIM 토큰을 재설정할 수 있습니다.
- `CI_JOB_TOKEN`은 이제 리포지토리 아카이브를 가져올 수 있으며, 소스 폴백이 더 이상 사용되지 않을 때 손상된 비공개 Composer 패키지 다운로드의 차단을 해제합니다.

이러한 기여를 해주신 다음 사용자들께 감사드립니다!

- [Colin Jacob Boby](https://gitlab.com/jcb960) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249258))
- [nagraj raikar](https://gitlab.com/nraj0408) ([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/244359) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245378))
- [Niklas van Schrick](https://gitlab.com/Taucher2003) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246614))
- [Nicholas Wittstruck](https://gitlab.com/nwittstruck) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/243804))
- [Alessandro Lai](https://gitlab.com/Alessandro.Lai) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246159))
