---
title: 리포지토리별 정확한 코드 검색 결과 필터링
stage: ai-powered
level: secondary
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed ]
documentation_link: "../../../user/search/exact_code_search/#syntax"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/488467"
categories: [ Global Search ]
weight: 20
---

이제 리포지토리별 정확한 코드 검색 결과를 필터링할 수 있습니다. `repo:` 구문을 사용하면 개별 프로젝트로 이동할 필요 없이 특정 리포지토리 또는 리포지토리 패턴으로 검색 쿼리의 범위를 직접 지정할 수 있습니다.

예를 들어 `def authenticate repo:my-group/my-project`을 검색하면 해당 리포지토리의 결과만 반환됩니다. 부분 경로 또는 패턴을 사용하여 여러 리포지토리를 일치시킬 수도 있습니다.
