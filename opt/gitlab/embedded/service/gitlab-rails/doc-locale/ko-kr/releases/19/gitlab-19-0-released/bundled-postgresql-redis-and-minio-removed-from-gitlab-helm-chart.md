---
title: "GitLab Helm 차트에서 제거된 번들 PostgreSQL, Redis, MinIO"
stage: gitlab_delivery
level: secondary
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed ]
documentation_link: "https://docs.gitlab.com/charts/installation/migration/bundled_chart_migration/"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/590797"
categories: [ Cloud Native Installation ]
weight: 80
---

번들 Bitnami PostgreSQL, Bitnami Redis 및 MinIO 차트는 GitLab 19.0의 GitLab Helm 차트 및 GitLab Operator에서 제거되며 대체품이 없습니다. 이 구성 요소는 개념 증명 및 테스트 환경에만 사용되도록 의도되었으며 프로덕션 사용은 권장되지 않습니다. 이러한 번들 서비스 중 하나를 사용하는 인스턴스를 실행 중인 경우 GitLab 19.0으로 업그레이드하기 전에 [마이그레이션 가이드](https://docs.gitlab.com/charts/installation/migration/bundled_chart_migration/)를 따라 외부 서비스를 구성하세요.
