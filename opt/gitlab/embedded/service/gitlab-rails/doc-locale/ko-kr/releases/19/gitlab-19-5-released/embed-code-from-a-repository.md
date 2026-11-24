---
title: 리포지토리의 코드를 Markdown에 포함시키기
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: plan
documentation_link: "../../../user/markdown/#embed-code-from-a-repository"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/300855
categories: [ Markdown ]
level: secondary
weight: 50
---

이전 버전의 GitLab에서는 [퍼머링크](../../../user/project/repository/files/_index.md#create-permalinks)가 파일의 줄을 일반 URL로 렌더링했으므로 참조된 코드를 보기 위해 머지 리퀘스트, 이슈 또는 wiki 페이지를 떠나야 했습니다.

이제 퍼머링크는 파일 경로와 커밋이 포함된 구문 강조 스니펫으로 렌더링되므로 페이지를 떠나지 않고도 코드를 읽을 수 있습니다. 리포지토리에 대한 읽기 액세스 권한이 있는 경우에만 포함된 스니펫을 볼 수 있습니다.
