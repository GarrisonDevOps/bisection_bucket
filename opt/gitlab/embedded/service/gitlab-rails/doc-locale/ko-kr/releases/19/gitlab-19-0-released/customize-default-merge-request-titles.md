---
title: 기본 머지 리퀘스트 제목 사용자 지정
stage: create
level: secondary
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed ]
documentation_link: "../../../user/project/merge_requests/title_templates/"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/16080"
categories: [ Code Review Workflow ]
weight: 100
---

이전 버전의 GitLab에서는 새로운 머지 리퀘스트의 기본 제목이 소스 브랜치 또는 첫 커밋에서 제공되었으며 프로젝트 전체에서 일관된 명명 규칙을 적용할 수 없었습니다.

이제 프로젝트당 기본 머지 리퀘스트 제목 템플릿을 구성할 수 있습니다. 템플릿은 소스 브랜치, 대상 브랜치, 첫 커밋 제목, 연결된 이슈 ID, 이슈 제목 및 소스 브랜치 이름의 사람이 읽을 수 있는 버전에 대한 변수를 지원합니다. 예를 들어 템플릿 `Resolve %{issue_id} "%{issue_title}"`은 `Resolve 123 "Fix login bug"`과 같은 제목을 생성합니다. 머지 리퀘스트를 생성하기 전에 제목을 계속 편집할 수 있습니다.
