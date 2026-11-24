---
title: Agent Platform 원격 플로우에 대한 관리자 정의 네트워크 액세스 제어
stage: ai-powered
level: secondary
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
documentation_link: "../../../user/duo_agent_platform/environment_sandbox/#configure-a-network-policy"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/593149"
categories: [ Duo Agent Platform ]
weight: 110
---

관리자는 이제 설정에서 직접 GitLab Duo Agent Platform 원격 플로우를 위한 중앙 집중식 네트워크 정책을 정의할 수 있습니다. GitLab.com의 최상위 그룹 관리자 및 GitLab Self-Managed 및 Dedicated의 인스턴스 관리자는 프로젝트가 자동으로 상속하는 조직 전체 도메인 거부 목록 및 허용 목록을 구성할 수 있습니다. 추가 설정은 프로젝트가 승인된 도메인 목록을 맞춤형 항목으로 확장할 수 있는지 여부를 제어합니다. 정책은 모든 원격 플로우에 걸쳐 런타임에 적용되어 보안 및 플랫폼 팀에 에이전트 네트워크 이그레스에 대한 일관된 거버넌스 계층을 제공합니다.
