---
title: 정확한 머지 리퀘스트 보안 보고서 비교
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/project/merge_requests/reports/#security-scan-report"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/628421
categories: [ Vulnerability Management ]
---

GitLab의 이전 버전에서는 스캔에 하나의 심각도에 해당하는 25개 이상의 결과가 있으면 보안 보고서는 각 파이프라인에서 25개만 비교했습니다. 변경되지 않은 결과가 신규 또는 수정된 항목으로 표시될 수 있습니다.

이제 보고서는 심각도당 최대 1,000개의 결과를 비교하므로 신규 및 수정된 목록이 더 정확합니다.
