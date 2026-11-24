---
title: 크레딧 사용량 내보내기의 이벤트별 세부 정보
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: fulfillment
documentation_link: "../../../subscriptions/gitlab_credits_dashboard/#export-usage-data"
work_item: https://gitlab.com/gitlab-org/customers-gitlab-com/-/work_items/18963
categories: [ Consumables Cost Management ]
level: secondary
---

크레딧 사용량 내보내기는 매일 한 행씩 제공했으며, 구독이 얼마를 지출했는지는 알려주지만 무엇에 지출했는지는 알려주지 않았습니다. 크레딧을 팀, 프로젝트 또는 단일 자동화에 귀속시키는 것은 추측이었습니다.

이제 내보내기는 두 개의 CSV 파일이 포함된 ZIP 파일을 반환합니다. 기존 일일 요약과 청구 가능한 각 이벤트마다 한 행씩 포함된 이벤트별 파일입니다. 각 행에는 제품, 플로우 유형, 세션, 사용자, 네임스페이스, 프로젝트, 사용된 크레딧 및 토큰 수가 포함됩니다. 내보내기는 백그라운드에서 실행되며, GitLab은 파일이 준비되면 다운로드 링크를 이메일로 보냅니다.
