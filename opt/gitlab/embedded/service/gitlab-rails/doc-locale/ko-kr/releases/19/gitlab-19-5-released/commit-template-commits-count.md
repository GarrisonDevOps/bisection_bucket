---
title: 커밋 템플릿의 커밋 수 변수
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
co_create: true
documentation_link: "../../../user/project/merge_requests/commit_templates/#supported-variables-in-commit-templates"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255231
categories: [ Code Review Workflow ]
level: secondary
weight: 50
---

이제 머지 리퀘스트 커밋 및 스쿼시 커밋 메시지 템플릿과 새로운 머지 리퀘스트 설명 템플릿에서 `%{commits_count}`을(를) 사용할 수 있습니다. 예를 들어, `%{title} (%{commits_count} commits)`는 `Bugfix (3 commits)`으로 렌더링됩니다.

이 기여를 해주신 [Jeston Singh](https://gitlab.com/sjestonsingh)님께 감사드립니다([머지 리퀘스트](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255231))!
