---
title: "세분화된 PAT 권한 일반 제공"
tier: [Free, Premium, Ultimate]
offering: [gitlab_com, self_managed, gitlab_dedicated]
stage: software_supply_chain_security
documentation_link: "../../../auth/tokens/fine_grained_access_tokens/"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/18554"
categories: [Permissions]
weight: 50
---

세분화된 개인 액세스 토큰(PAT)이 이제 일반 제공됩니다. 사용자가 속한 모든 프로젝트 및 그룹에 액세스 권한을 부여하는 레거시 PAT와 달리, 세분화된 PAT를 사용하면 각 토큰을 특정 리소스 및 작업으로 제한할 수 있습니다. 이렇게 하면 자동화 및 통합에 최소 권한 원칙을 더 쉽게 적용할 수 있으며, 유출되거나 손상된 토큰의 잠재적 영향을 줄일 수 있습니다.

설정을 더 쉽게 하려면 **Duo로 권한 추가** 기능을 사용하여 토큰 생성 중에 올바른 권한을 선택하세요. 기존 레거시 PAT는 이전과 같이 계속 작동합니다. 새로운 토큰의 경우, GitLab은 각 토큰이 필요한 리소스 및 작업으로만 범위가 지정되도록 세분화된 PAT를 권장합니다.

GA 릴리스를 통해 세분화된 PAT는 이제 REST API 엔드포인트에 대한 완전한 범위 지원과 가장 일반적으로 사용되는 GraphQL 유형 및 변이에 대한 범위 지원을 제공합니다.
