---
title: 보안 구성 프로필의 종속성 검사
stage: security_risk_management
level: secondary
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
documentation_link: "../../../user/application_security/configuration/security_configuration_profiles/"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/19952"
categories: [ Security Testing Configuration ]
weight: 20
---

GitLab 18.11은 SAST 및 시크릿 검색에 대한 보안 구성 프로파일을 도입했습니다. 이제 종속성 검사도 **Dependency Scanning - Default** 프로파일과 함께 사용할 수 있습니다. 이 프로파일은 단일 CI/CD 구성 파일을 편집하지 않고도 모든 프로젝트에 표준화된 SCA 범위를 적용할 수 있는 통합 제어 표면을 제공합니다.

프로파일은 두 가지 검사 트리거를 활성화합니다.

- **머지 리퀘스트 파이프라인**: 열려 있는 머지 리퀘스트가 있는 브랜치로 새로운 커밋이 푸시될 때마다 자동으로 종속성 검사 검사를 실행합니다. 결과에는 머지 리퀘스트에 의해 도입된 새로운 취약성만 포함됩니다.
- **브랜치 파이프라인(기본값만)**: 변경 사항이 기본 브랜치로 병합되거나 푸시될 때 자동으로 실행되어 기본 브랜치의 종속성 상태를 완전히 볼 수 있습니다.
