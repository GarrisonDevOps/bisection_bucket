---
title: SBOM을 사용한 종속성 검사 일반 공개
stage: software_supply_chain_security
level: primary
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
documentation_link: "../../../user/application_security/dependency_scanning/dependency_scanning_sbom/"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/20456"
categories: [ Software Composition Analysis ]
weight: 50
---

GitLab SBOM 기반 종속성 검사기가 정식으로 출시되었습니다. Maven, Gradle 및 Python 프로젝트는 직접 선언된 종속성뿐만 아니라 과도적으로 도입된 취약한 패키지를 포함하여 전체 종속성 트리에서 취약성에 완전히 가시성을 갖습니다.

분석기에는 이제 Maven, Gradle 및 Python 프로젝트에 대한 자동 종속성 해결이 포함됩니다. 잠금 파일 또는 해결된 종속성 그래프가 없으면 분석기는 검사 전에 전체 과도적 종속성 그래프를 해결하기 위해 도구를 자동으로 호출합니다. 종속성 해결은 기본적으로 활성화되며 v2 종속성 검사 템플릿을 포함하는 것 이상의 추가 구성이 거의 또는 전혀 필요하지 않습니다.

종속성 해결이 불가능한 프로젝트의 경우 분석기는 매니페스트 검사로 폴백합니다. `pom.xml`, `requirements.txt`, `build.gradle` 및 `build.gradle.kts`를 구문 분석하여 직접 종속성을 식별합니다. 매니페스트 검사는 팀이 잠금 또는 빌드 파일 없는 프로젝트의 경우에도 취약성 보장의 시작점을 항상 얻을 수 있도록 합니다.

매니페스트 검사는 기본적으로 활성화되며 직접 종속성만 반환합니다. 전체 과도적 범위를 보려면 종속성 해결을 활성화하거나 종속성 잠금 파일 또는 그래프 내보내기를 수동으로 제공하세요.
