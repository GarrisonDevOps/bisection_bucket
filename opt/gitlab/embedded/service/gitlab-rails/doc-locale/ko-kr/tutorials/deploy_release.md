---
stage: Tutorials
group: Tutorials
info: For assistance with this tutorials page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
description: 배포 프로세스 및 대상입니다.
title: '튜토리얼: 애플리케이션 배포 및 릴리스'
---

## 패키지 및 컨테이너 관리 {#manage-packages-and-containers}

패키지 및 컨테이너 레지스트리를 사용하여 아티팩트를 관리하는 방법을 알아봅니다.

| 주제 | 설명 | 초보자에게 적합 |
|-------|-------------|--------------------|
| [GitLab 패키지 및 릴리스 함수](https://university.gitlab.com/courses/gitlab-package-and-release-functions) | 자체 속도로 진행할 수 있는 이 과정에서 레지스트리 및 릴리스 기능의 기본 사항을 알아봅니다. 예상 시간: 15~20분입니다. | {{< icon name="star" >}} |
| [CI/CD를 사용하여 패키지를 자동으로 빌드하고 게시](../user/packages/pypi_repository/auto_publish_tutorial.md) | PyPI 패키지를 패키지 레지스트리에 자동으로 빌드, 테스트 및 게시하는 방법을 알아봅니다. 예상 시간: 15~20분입니다. | {{< icon name="star" >}} |
| [엔터프라이즈 규모의 패키지 레지스트리 구조화](../user/packages/package_registry/enterprise_structure_tutorial.md) | 규모에 맞게 패키지를 업로드, 관리 및 사용하도록 조직을 설정합니다. 예상 시간: 30-45분. | |
| [GitLab CI/CD를 사용하여 Python 패키지 빌드 및 서명](../user/packages/package_registry/pypi_cosign_tutorial.md)  | GitLab CI/CD 및 Sigstore Cosign을 사용하여 Python 패키지를 위한 보안 파이프라인을 빌드하는 방법을 알아봅니다. 예상 시간: 30-45분. | |
| [빌드 출처 데이터로 컨테이너 이미지에 주석 달기](../user/packages/container_registry/cosign_tutorial.md) | Cosign을 사용하여 컨테이너 이미지를 빌드, 서명 및 주석 달기 프로세스를 자동화하는 방법을 알아봅니다. 예상 시간: 30-45분. | |
| [Amazon ECR에서 GitLab으로 컨테이너 이미지 마이그레이션](../user/packages/container_registry/migrate_containers_ecr_tutorial.md) | Amazon Elastic Container Registry(ECR)에서 GitLab 컨테이너 레지스트리로의 컨테이너 이미지 일괄 마이그레이션을 자동화합니다. 예상 시간: 30-45분. | |

## 정적 웹사이트 게시 {#publish-a-static-website}

GitLab Pages를 사용하여 프로젝트에서 직접 정적 웹사이트를 게시합니다.

| 주제 | 설명 | 초보자에게 적합 |
|-------|-------------|--------------------|
| [CI/CD 템플릿에서 Pages 웹사이트 생성](../user/project/pages/getting_started/pages_ci_cd_template.md) | 인기 있는 Static Site Generator(SSG)용 CI/CD 템플릿을 사용하여 프로젝트용 Pages 웹사이트를 빠르게 생성합니다. 예상 시간: 5~10분입니다. | {{< icon name="star" >}} |
| [처음부터 Pages 웹사이트 생성](../user/project/pages/getting_started/pages_from_scratch.md) | 빈 프로젝트에서 Pages 웹사이트의 모든 구성 요소를 생성합니다. 예상 시간: 30-45분. | |
| [GitLab을 사용하여 Hugo 사이트 빌드, 테스트 및 배포](hugo/_index.md) | CI/CD 템플릿과 GitLab Pages를 사용하여 Hugo 사이트를 생성합니다. 예상 시간: 30-45분. | {{< icon name="star" >}} |
