---
title: GitLab Flex 지출 한도에 대한 조기 경고
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: fulfillment
documentation_link: "../../../subscriptions/gitlab_flex_dashboard/#usage-notifications"
work_item: https://gitlab.com/gitlab-org/customers-gitlab-com/-/issues/18962
categories: [ Consumables Cost Management ]
level: secondary
---

GitLab 19.3은 예약 임계값에 대한 이메일 알림과 상한이 설정된 기능이 제한되는 순간의 알림을 도입했습니다. 지출 한도 자체에는 조기 경고가 없었으므로 한도에 대한 첫 이메일은 사용이 이미 중단되었을 때 도착했습니다.

이제 GitLab은 기능의 온디맨드 사용량이 월간 지출 한도의 50% 또는 80%에 도달할 때 청구 계정 관리자에게 이메일을 보내며, 기능 및 한도를 크레딧으로 명시합니다. 가장 높은 임계값 초과만 전송되며, 청구 기간당 기능당 최대 1회입니다. $10 미만의 한도는 건너뛰므로 작은 한도는 불필요한 알림을 생성하지 않습니다.
