---
title: GitLab Duo CLI의 자동 모드
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/use/#auto-mode"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23697
categories: [ Duo CLI ]
level: secondary
weight: 50
---

GitLab Duo CLI는 새로운 자동 모드를 제공합니다. 자동 모드에서 GitLab Duo는 먼저 승인을 요청하지 않고 도구를 사용하므로 각 셸 명령, `git` 작업 또는 MCP 도구 호출에 대해 중단하지 않고 더 긴 작업이 실행됩니다.

자동 모드는 조직의 제어를 준수합니다:

- 자동 모드는 기본적으로 꺼져 있습니다. 관리자, 소유자 및 유지보수자는 인스턴스, 그룹 및 프로젝트에 대한 설정을 켤 수 있습니다. 관리자 및 그룹 소유자는 전체 인스턴스 또는 그룹에 대해 **항상 꺼짐**으로 잠글 수도 있습니다.
- 에이전트 도구 거버넌스는 여전히 적용됩니다. **항상 거부**로 설정된 도구는 계속 차단됩니다.

자동 모드를 사용하려면 GitLab Duo CLI 9.22.0 이상이 필요합니다. <kbd>Tab</kbd> 키를 눌러 `>` 프롬프트 아래의 모드가 `auto`를 표시할 때까지 진행합니다. 자동 모드는 신뢰할 수 있는 리포지토리에서만 사용하고 폐기할 수 있는 브랜치에서만 사용하세요.
