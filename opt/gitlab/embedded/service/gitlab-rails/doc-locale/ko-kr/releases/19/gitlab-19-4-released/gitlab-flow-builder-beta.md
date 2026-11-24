---
title: 사용자 지정 플로우를 위한 GitLab 플로우 빌더(베타)
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/duo_agent_platform/flows/custom/#create-a-flow"
work_item: https://gitlab.com/groups/gitlab-org/editor-extensions/-/work_items/236
categories: [ AI Catalog Creation ]
level: secondary
weight: 50
---

GitLab for VS Code 확장 프로그램에서 AI 네이티브 워크플로우를 위한 새로운 시각 편집기인 GitLab 플로우 빌더로 GitLab 프로젝트를 위한 사용자 지정 플로우를 빌드합니다. 컴포넌트(에이전트, 사용자 지정 도구, AI 작업)에서 플로우를 시각적으로 작성하거나 기본 YAML을 직접 편집합니다.

시작하려면 VS Code에서 플로우의 YAML 파일을 열고 **GitLab 플로우 빌더 열기**를 선택합니다. **실행** 버튼을 사용하여 플로우를 테스트하면 실행 콘솔이 열립니다. 플로우가 준비되면 **발행**을 선택하여 AI 카탈로그에 발행합니다.

플로우 빌더는 GitLab for VS Code 6.87.0 이상에서 베타 기능으로 사용할 수 있습니다. 시작하려면 VS Code에서 `gitlab.featureFlags.flowBuilder` 설정을 활성화합니다.
