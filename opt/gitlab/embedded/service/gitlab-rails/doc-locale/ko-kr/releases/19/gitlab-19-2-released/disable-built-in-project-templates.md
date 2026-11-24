---
title: 기본 제공 프로젝트 템플릿 비활성화
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
documentation_link: "../../../administration/project_templates#built-in-project-templates"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/21356
categories: [ Source Code Management ]
level: secondary
weight: 50
---

조직이 사용자 정의 프로젝트 템플릿을 사용하는 경우, 기본 제공 공급업체 템플릿은 템플릿 선택 환경에서 불필요한 정보를 추가할 수 있으며, 경우에 따라 서버 측 훅 또는 다른 리포지토리 컨트롤을 우회할 수 있습니다.

관리자는 이제 **운영자** 영역에서 기본 제공 프로젝트 템플릿을 전역으로 비활성화하거나, 하위 그룹 수준에서 비활성화할 수 있습니다. 설정이 자동으로 전파되므로 각 그룹마다 개별적으로 구성할 필요가 없습니다. 관리자는 설정값을 적용하여 그룹이나 하위 그룹에서 이를 재정의할 수 없도록 할 수 있습니다. 인스턴스 및 그룹 설정은 REST 및 GraphQL API를 통해서도 관리할 수 있습니다. GitLab.com에서는 그룹 수준의 설정만 사용할 수 있습니다.
