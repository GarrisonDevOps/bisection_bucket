---
title: GraphQL API 없이 크레딧 한도 설정
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed ]
stage: fulfillment
documentation_link: "../../../subscriptions/gitlab_credits_dashboard/#manage-credit-caps"
work_item: https://gitlab.com/gitlab-org/gitlab/-/issues/628559
categories: [ Consumables Cost Management ]
level: secondary
---

크레딧 한도는 각 사용자가 소비할 수 있는 GitLab 크레딧의 양을 제한하지만, 지금까지는 GraphQL API를 통해서만 구성할 수 있었습니다. 소수의 사용자를 위해 다른 한도를 설정하려면 뮤테이션을 수동으로 작성해야 했습니다.

새로운 **크레딧 한도** 페이지에서는 모든 사용자에게 기본적으로 적용되는 정액 한도를 설정할 수 있고, 검색 가능한 선택기를 통해 개별 사용자에 대한 사용자별 오버라이드를 추가할 수 있습니다. 이 페이지는 GitLab.com의 그룹 소유자와 GitLab Self-Managed의 관리자를 위해 **GitLab 크레딧**에서 사용할 수 있습니다. GraphQL 뮤테이션은 한도 변경을 스크립트로 작성하려는 경우 계속 작동합니다.
