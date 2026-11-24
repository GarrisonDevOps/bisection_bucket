---
title: 비기본 브랜치에서 지원되는 AI 플로우
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/vulnerability_report/#tracked-ref-filter"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23297
categories: [ Vulnerability Management ]
---

이전 GitLab 버전에서는 SAST 거짓 양성 탐지, SAST 취약성 해결, Secret 거짓 양성 탐지 플로우를 기본 브랜치의 취약성에 대해서만 실행할 수 있었습니다.

이제 취약성 보고서에서 다른 추적 브랜치의 취약성에 대해 이러한 플로우를 실행하여 병합 전에 분석하고 해결할 수 있습니다.
