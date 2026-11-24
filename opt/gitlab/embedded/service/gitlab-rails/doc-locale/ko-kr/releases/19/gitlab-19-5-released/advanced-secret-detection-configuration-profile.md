---
title: 보안 구성 프로필 사용자 지정
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/configuration/security_configuration_profiles/"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/20198
categories: [ Security Testing Configuration, Secret Detection, SAST, Software Composition Analysis ]
weight: 50
---

이제 UI에서 시크릿 검색 및 SAST 프로필을 사용자 지정할 수 있습니다. 제외된 경로, 사용자 지정 분석기 이미지, 완전한 Git 히스토리 스캔과 같은 스캔 옵션을 한 번 그룹에 대해 설정하고 모든 프로젝트에 적용합니다.

이전에는 보안 구성 프로필이 기본 설정으로 스캐너를 활성화했습니다. 기본값을 초과하는 모든 항목에는 각 프로젝트에서 `.gitlab-ci.yml`을(를) 편집하는 작업이 필요했습니다. 이제 프로필에 해당 설정도 포함됩니다.

현재 종속성 검사 프로필의 사용자 지정은 GraphQL API를 통해서만 가능합니다. UI 사용자 지정은 향후 릴리스에서 계획되어 있습니다.
