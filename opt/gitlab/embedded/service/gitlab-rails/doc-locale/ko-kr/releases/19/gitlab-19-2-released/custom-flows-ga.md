---
title: GitLab Duo 사용자 지정 플로우가 이제 일반 공개 되었습니다
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/duo_agent_platform/flows/custom"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/602415
categories: [ AI Catalog Creation ]
level: primary
weight: 10
---

사용자 지정 플로우는 GitLab 프로젝트 전체에서 복잡한 다단계 작업을 자동화하기 위해 만들고 구성하는 AI 기반 워크플로우입니다. 팀은 워크플로우 단계, 구성 요소, 트리거를 정의하여 반복적인 개발 및 운영 작업을 GitLab 이벤트에 응답하여 자동으로 실행할 수 있습니다. GitLab UI에서 플로우는 GitLab CI/CD에서 직접 실행되어 팀이 GitLab을 벗어나지 않고 일반적인 작업을 자동화할 수 있습니다.

주요 기능은 다음과 같습니다.

- 팀별 자동화를 위한 YAML 정의, 재사용 가능한 워크플로우
- 복잡한 다단계 작업을 위한 다중 에이전트 오케스트레이션
- 승인 또는 피드백을 위한 사용자 지정 인루프(HITL) 체크포인트(민감한 단계에서)
- 네이티브 GitLab 트리거(멘션, 할당, 파이프라인 이벤트, 머지 리퀘스트 수명 주기 이벤트 포함)
- 프로젝트 또는 AI 카탈로그에서 플로우 생성 및 관리
- 공개 및 비공개 가시성 제어
- 서비스 계정 및 복합 ID를 사용한 보안 실행
- 런타임 전에 구성 문제를 포착하기 위한 YAML 유효성 검사
