---
title: 라우팅 가능한 개인 액세스 토큰에 대한 자동 취소
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: application_security_testing
documentation_link: "../../../user/application_security/secret_detection/automatic_response"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/623418
categories: [ Secret Detection ]
---

시크릿 검색이 공개 프로젝트에서 누출된 GitLab 개인 액세스 토큰을 발견하면 자동 응답이 이를 취소합니다. GitLab 19.4 이전 버전에서는 취소가 하나의 검색 규칙만 사용하고 레거시 토큰 형식만 취소했습니다. GitLab 18.3 이후에 생성된 토큰은 라우팅 가능한 형식 또는 버전이 지정된 라우팅 가능한 형식을 사용합니다. GitLab은 이러한 토큰을 검출 및 보고했지만 취소하지 않았습니다.

GitLab 19.4 이후에서는 취소가 세 가지 GitLab 개인 액세스 토큰 검색 규칙을 모두 인식합니다:

- `gitlab_personal_access_token`
- `gitlab_personal_access_token_routable`
- `gitlab_personal_access_token_routable_versioned`

취소는 [GitLab Secret Scanning for Source Code](../../../user/application_security/secret_detection/gitlab_secret_scanner/_index.md) 및 [Gitleaks 기반 분석기](../../../user/application_security/secret_detection/pipeline/_index.md)의 결과도 포함합니다. 구성을 변경할 필요가 없습니다. 자동 응답이 활성화된 인스턴스는 이 더 광범위한 범위를 즉시 적용받습니다.
