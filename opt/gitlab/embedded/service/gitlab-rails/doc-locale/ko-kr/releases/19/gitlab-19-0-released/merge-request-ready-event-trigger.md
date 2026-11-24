---
title: 머지 리퀘스트 준비 완료 이벤트 트리거
stage: ai-powered
level: secondary
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed ]
documentation_link: "../../../user/duo_agent_platform/triggers/"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/592454"
categories: [ Duo Agent Platform ]
weight: 30
---

이제 **머지 리퀘스트 준비 완료** 이벤트에서 플로우 및 외부 에이전트를 실행하도록 구성할 수 있습니다.

초안 머지 리퀘스트가 검토 준비로 표시되면 GitLab Duo가 자동으로 플로우 또는 외부 에이전트를 실행합니다.

트리거를 구성하려면 프로젝트에서 **AI** > **트리거**로 이동하세요.

이 기능은 `merge_request_ready_flow_trigger` 기능 플래그 뒤에 있으며 기본적으로 비활성화되어 있습니다.
