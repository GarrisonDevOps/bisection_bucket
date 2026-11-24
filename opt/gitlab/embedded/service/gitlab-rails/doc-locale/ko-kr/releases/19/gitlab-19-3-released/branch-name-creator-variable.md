---
title: 브랜치 이름에 브랜치를 생성한 사람의 이름을 포함할 수 있습니다
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: create
co_create: true
documentation_link: "../../../user/project/repository/branches/#configure-default-pattern-for-branch-names-from-issues"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247356
categories: [ Source Code Management ]
level: secondary
---

새로운 `%{branch_creator}` 변수를 사용하여 브랜치 이름 템플릿에 작성자를 포함할 수 있으므로, 이슈에서 생성된 브랜치는 일반적인 이름으로 폴백하지 않고 누가 브랜치를 생성했는지 식별할 수 있습니다.

이 기여에 대해 [Radek Antoniuk](https://gitlab.com/rantoniuk)에게 감사드립니다!
