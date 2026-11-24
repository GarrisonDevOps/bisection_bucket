---
title: GitLab Credits 사용량 상한선이 일반 공급됩니다
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: fulfillment
documentation_link: "../../../subscriptions/gitlab_credits_dashboard/#usage-caps"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/607551
categories: [ Consumables Cost Management ]
level: secondary
---

온디맨드 사용으로 인한 초과 요금이 계획하지 않은 비용으로 발생할 수 있습니다. GitLab Credits 사용량 상한선이 이제 일반 공급됩니다. 고객 포털에서 온디맨드 크레딧에 대한 구독 수준 상한선을 설정하고, GraphQL API를 사용하여 기본 사용자당 상한선 또는 사용자당 재정의를 설정합니다. 소비량이 상한선에 도달하면 GitLab Duo Agent Platform과 같이 GitLab Credits를 소비하는 기능은 다음 청구 기간이 시작되거나 관리자가 상한선을 조정할 때까지 일시 중단됩니다. 사용 한도는 GitLab 18.11에서 `budget_caps_graphql_api` 기능 플래그 뒤에 도입되었습니다. GitLab 19.3에서 기능 플래그가 제거되었습니다.
