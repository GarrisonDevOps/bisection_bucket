---
title: 기본 브랜치가 아닌 브랜치 추적 일반 제공
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/vulnerability_report/#tracking-vulnerabilities-across-contexts"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/3430
categories: [ Vulnerability Management ]
level: primary
weight: 50
---

기본 브랜치가 아닌 브랜치 추적이 이제 일반적으로 제공됩니다. 기본 브랜치가 아닌 다른 브랜치에서 취약성을 추적할 수 있습니다. 최상의 결과를 위해 소수의 오래 유지되는 릴리스 브랜치를 대상으로 하세요. 예를 들어 특정 환경의 브랜치(`project-qa`, `project-prod`) 또는 배포 플랫폼의 브랜치(`project-iOS`, `project-android`)입니다.

이 릴리스에는 다음과 같은 기능이 포함됩니다:

- 보안 구성 페이지에서 세 개의 추가 브랜치 또는 태그를 추적합니다. 이는 기본 추적 브랜치 외에 추가되는 항목입니다.
- 취약성 보고서에서 추적된 참조로 필터링합니다.
- 프로젝트 수준 보안 대시보드에서 브랜치로 필터링합니다.
- 추적된 브랜치에서 취약성 상태를 업데이트합니다.
- 취약성 관리 정책은 각 추적 브랜치를 별도로 평가하고 해당 브랜치의 취약성만 업데이트합니다.

GitLab Self-Managed에서 추적된 참조 및 브랜치 필터에는 [고급 취약성 관리](../../../user/application_security/vulnerability_report/_index.md#advanced-vulnerability-management)가 필요합니다.
