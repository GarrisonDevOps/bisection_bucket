---
title: 상세한 CI/CD 카탈로그 구성 요소 사용 분석
stage: verify
level: secondary
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
documentation_link: "../../../ci/components/#view-component-usage-details"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/579460"
categories: [ Component Catalog ]
weight: 80
---

GitLab 카탈로그에서 CI/CD 구성 요소를 관리할 때 사용량 세부 정보는 업그레이드 관리, 규정 준수 적용 및 주요 변경 사항 전달에 매우 중요합니다. 프로젝트에서 구성 요소를 사용하고 사용 중인 버전을 알아야 합니다. 이전에는 이 정보를 사용할 수 없어 올바른 유지관리자에게 알리고, 안전하게 중단을 계획하고, 프로젝트가 최신 보안 패치로 최신 상태를 유지하도록 하기가 어려웠습니다.

카탈로그 리소스 페이지의 구성 요소 사용량 세부 정보 보기는 이제 각 구성 요소를 사용하는 정확한 프로젝트, 실행 중인 버전 및 최신 버전 또는 오래된 버전 여부를 표시합니다. 이전 버전을 사용하는 프로젝트가 맨 위에 표시되므로 아웃리치의 우선 순위를 지정하고, 보안 수정 사항의 채택을 주도하고, 조직 전체에서 순조로운 업그레이드 경로를 보장할 수 있습니다.
