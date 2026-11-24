---
title: 머지 리퀘스트 워크플로우를 위한 GitLab Duo Developer 개선 사항
stage: ai-powered
level: primary
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
documentation_link: "../../../user/project/merge_requests/developer/"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228817"
categories: [ Duo Developer ]
weight: 40
---

GitLab Duo Developer는 이제 여러 트리거 방법을 지원합니다. 이슈에 할당하고, **Generate MR**을 선택하거나, 모든 이슈 또는 MR 토론 스레드에서 `@mention`하여 피드백, 할 일 항목 및 설계 질문을 코드 변경, 후속 MR 또는 연구 요약으로 변환합니다.

`AGENTS.md`와 `agent-config.yml`이 구성되면 GitLab Duo Developer는 커밋하기 전에 테스트 및 확인을 실행합니다. 최상위 그룹 또는 인스턴스 관리자가 Developer 플로우를 활성화한 후 GitLab은 적격 프로젝트에 언급 및 할당 트리거를 자동으로 추가합니다.
