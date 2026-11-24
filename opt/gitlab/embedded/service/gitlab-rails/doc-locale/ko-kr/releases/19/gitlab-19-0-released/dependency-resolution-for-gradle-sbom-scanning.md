---
title: Gradle SBOM 스캔에 대한 종속성 해결
stage: software_supply_chain_security
level: secondary
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
documentation_link: "../../../user/application_security/dependency_scanning/dependency_scanning_sbom/#dependency-resolution"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/590734"
categories: [ Software Composition Analysis ]
weight: 30
---

SBOM을 사용한 GitLab 종속성 검사는 이제 Gradle 프로젝트에 대한 종속성 그래프(`gradle.graph.txt`)를 자동으로 생성합니다. 이전에 Gradle 종속성 검사에서는 빌드의 일부로 종속성 그래프를 수동으로 생성해야 했습니다. 이제 그래프 파일을 사용할 수 없으면 분석기가 자동으로 하나를 생성하여 Gradle을 사용하는 Java 및 Kotlin 프로젝트에 대한 이 수동 단계를 제거합니다.
