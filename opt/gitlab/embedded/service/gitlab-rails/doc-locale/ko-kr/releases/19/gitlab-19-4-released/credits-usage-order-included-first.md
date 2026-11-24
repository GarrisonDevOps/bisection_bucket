---
title: 포함된 크레딧이 평가판 크레딧보다 먼저 사용됩니다
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: fulfillment
documentation_link: "../../../subscriptions/gitlab_credits/#usage-order"
work_item: https://gitlab.com/gitlab-org/customers-gitlab-com/-/issues/18961
categories: [ Consumables Cost Management ]
level: secondary
---

구독에 임시 평가판 크레딧이 있을 때 모든 사용량이 먼저 해당 공유 풀에서 출금되었습니다. 모든 사용자의 포함된 월간 크레딧은 평가판 풀이 소진될 때까지 유휴 상태로 있었다가 월말에 초기화되었습니다.

이제 GitLab은 각 사용자의 포함된 크레딧을 먼저 소비하고, 사용자가 포함된 크레딧 양을 모두 사용한 후에만 임시 평가판 크레딧의 공유 풀에서 출금합니다. 월간 약정 풀, 일회성 청구 크레딧 및 온디맨드 크레딧은 이전과 동일한 순서로 소비되므로 청구서는 영향을 받지 않습니다.
