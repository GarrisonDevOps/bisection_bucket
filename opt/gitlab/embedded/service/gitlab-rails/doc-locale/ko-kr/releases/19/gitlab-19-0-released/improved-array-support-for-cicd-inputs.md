---
title: CI/CD 입력에 대한 개선된 배열 지원
stage: verify
level: secondary
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
documentation_link: "../../../ci/inputs/#access-individual-array-elements"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/issues/587657"
categories: [ Pipeline Composition ]
weight: 60
---

CI/CD 입력은 이제 배열로 작업하기 위한 향상된 지원이 있습니다. 배열 인덱스 연산자 `[]`를 사용하여 배열 입력 내의 특정 요소에 액세스합니다. 이 개선 사항은 파이프라인 구성에서 더 유연하고 강력한 입력 보간 기능을 제공하여 추가 처리 단계 없이 개별 배열 항목을 직접 참조할 수 있도록 합니다.
