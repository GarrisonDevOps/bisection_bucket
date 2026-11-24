---
title: 자동화된 분류 및 수정 프로필(GraphQL API)
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/configuration/security_configuration_profiles/#automated-triage-and-remediation-profile"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23191
categories: [ Vulnerability Management ]
weight: 50
---

이전 GitLab 버전에서는 각 프로젝트에 대해 개별적으로 SAST 거짓 양성 탐지, GitLab Duo 취약성 해결, 시크릿 검색 거짓 양성 탐지, 종속성 검사 자동 수정을 설정했습니다. 이제 자동화된 분류 및 수정 프로필을 그룹 또는 프로젝트에 적용하여 심각도와 실행 모드를 한 번에 설정할 수 있습니다. 사전 설정으로 시작하거나 각 플로우를 직접 구성합니다:

- 보수적: 요청 시, 높은 심각도.
- 표준: 자동, 중간 심각도 이상.
- 적극적: 자동, 모든 심각도.

프로필은 GraphQL API에서만 사용 가능하며, 최상위 그룹에 대해 기본 플로우가 켜져 있는 GitLab Duo Agent Platform이 필요합니다. 대부분의 플로우는 GitLab Credits를 소비합니다.
