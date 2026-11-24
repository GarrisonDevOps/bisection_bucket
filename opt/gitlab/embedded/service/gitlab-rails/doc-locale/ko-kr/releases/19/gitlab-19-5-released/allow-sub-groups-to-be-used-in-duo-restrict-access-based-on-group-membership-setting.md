---
title: 서브그룹 멤버쉽으로 GitLab Duo 액세스 제한
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
stage: security_governance
documentation_link: "../../../administration/gitlab_duo/configure/access_control"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/633488
categories: [ AI Governance ]
level: primary
weight: 50
---

관리자는 이제 GitLab Duo의 [**그룹 멤버쉽에 기반하여 액세스 제한**](../../../administration/gitlab_duo/configure/access_control.md) 설정에서 최상위 그룹뿐 아니라 서브그룹을 선택할 수 있습니다. 그룹 계층 구조를 재구성하지 않고도 GitLab Duo Agent Platform 액세스를 특정 팀이나 파일럿 그룹으로 범위를 지정할 수 있습니다.

이전에는 이 설정이 최상위 그룹만 허용했습니다. 모든 사용자를 위한 단일 최상위 그룹이 있는 조직은 GitLab Duo Agent Platform 액세스를 사용자의 부분 집합으로 제한할 수 있는 지원되는 방법이 없었습니다.

이제 서브그룹을 선택하면 해당 서브그룹의 직접 멤버가 액세스를 얻습니다. 이를 통해 GitLab Duo Agent Platform 파일럿을 실행하거나 GitLab Self-Managed 및 GitLab Dedicated에서 한 번에 액세스를 한 부서씩 배포하기가 더 쉬워집니다.
