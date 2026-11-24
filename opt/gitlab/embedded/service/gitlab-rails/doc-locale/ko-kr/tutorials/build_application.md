---
stage: Tutorials
group: Tutorials
info: For assistance with this tutorials page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments-to-other-projects-and-subjects>.
description: CI/CD 기본 사항 및 예제입니다.
title: '튜토리얼: 애플리케이션 구축'
---

## CI/CD 파이프라인 학습 {#learn-about-cicd-pipelines}

CI/CD 파이프라인을 사용하여 자동으로 코드를 빌드, 테스트 및 배포합니다.

| 주제 | 설명 | 초보자에게 좋음 |
|-------|-------------|--------------------|
| [첫 GitLab CI/CD 파이프라인 생성 및 실행](../ci/quick_start/_index.md) | `.gitlab-ci.yml` 파일을 생성하고 파이프라인을 시작합니다. 예상 시간: 15-20분입니다. | {{< icon name="star" >}} |
| [복잡한 파이프라인 생성](../ci/quick_start/tutorial.md) | 점점 더 복잡한 파이프라인을 구축하여 가장 일반적으로 사용되는 GitLab CI/CD 키워드에 대해 학습합니다. 예상 시간: 30-45분입니다. |  |
| <i class="fa-youtube-play" aria-hidden="true"></i> [시작하기: CI/CD](https://www.youtube.com/watch?v=sIegJaLy2ug) 학습 (9분 2초) | `.gitlab-ci.yml` 파일 및 사용 방식에 대해 알아봅니다. | {{< icon name="star" >}} |
| [GitLab CI 기본 사항](https://university.gitlab.com/learn/learning-path/gitlab-ci-fundamentals) | 이 자율 진행식 과정에서 GitLab CI/CD에 대해 학습하고 파이프라인을 구축합니다. 예상 시간: 3시간입니다. | {{< icon name="star" >}} |
| <i class="fa-youtube-play" aria-hidden="true"></i> [CI 심화 학습](https://www.youtube.com/watch?v=ZVUbmVac-m8&list=PL05JrBw4t0KorkxIFgZGnzzxjZRCGROt_&index=27) (22분 51초) | 파이프라인 및 지속적 통합 개념을 더 자세히 살펴봅니다. | |
| [GitLab 파이프라인을 생성하여 Google Artifact Registry로 푸시](create_gitlab_pipeline_push_to_google_artifact_registry/_index.md) | GitLab을 Google Cloud와 연결하고 파이프라인을 생성하여 Artifact Registry로 이미지를 푸시하는 방법을 알아봅니다. 예상 시간: 30-45분입니다. | |
| [CI/CD 예제 찾기](../ci/examples/_index.md)  | 이러한 예제를 사용하여 사용 사례에 맞게 CI/CD를 설정합니다. | |
| <i class="fa-youtube-play" aria-hidden="true"></i> [CI/CD 규칙 이해](https://www.youtube.com/watch?v=QjQc-zeL16Q) (8분 56초) |  CI/CD 규칙 사용 방법에 대해 자세히 알아봅니다. | |
| [Auto DevOps를 사용하여 애플리케이션 배포](../topics/autodevops/cloud_deployments/auto_devops_with_gke.md)  | 애플리케이션을 Google Kubernetes Engine(GKE)에 배포합니다. 예상 시간: 1시간입니다. | |
| [OpenShift에서 GitLab Runner Operator를 사용하여 루트리스 컨테이너에서 Buildah 사용](../ci/docker/buildah_rootless_tutorial.md)  | OpenShift에서 GitLab Runner Operator를 설정하여 루트리스 컨테이너에서 Buildah를 사용하여 Docker 이미지를 빌드하는 방법을 알아봅니다. 예상 시간: 30-45분입니다. | |

## GitLab Runner 구성 {#configure-gitlab-runner}

러너를 설정하여 파이프라인에서 작업을 실행합니다.

| 주제 | 설명 | 초보자에게 좋음 |
|-------|-------------|--------------------|
| [자신의 프로젝트 러너 생성, 등록 및 실행](create_register_first_runner/_index.md) | 프로젝트에서 작업을 실행하는 프로젝트 러너를 생성하고 등록하는 방법의 기본 사항을 알아봅니다. 예상 시간: 15-20분입니다. | {{< icon name="star" >}} |
| [Google Kubernetes Engine을 사용하도록 GitLab Runner 구성](configure_gitlab_runner_to_use_gke/_index.md) | GKE를 사용하여 작업을 실행하도록 GitLab Runner를 구성하는 방법을 알아봅니다. 예상 시간: 30-45분입니다. | |
| [러너 생성 및 등록 자동화](automate_runner_creation/_index.md) | 인증된 사용자로 러너 생성을 자동화하여 러너 플릿을 최적화하는 방법을 알아봅니다. 예상 시간: 15-20분입니다. | |
| [Google Cloud 통합 설정](set_up_gitlab_google_integration/_index.md) | Google Cloud를 GitLab과 통합하고 GitLab Runner를 설정하여 Google Cloud에서 작업을 실행하는 방법을 알아봅니다. 예상 시간: 30-45분입니다. | |

## 모바일 DevOps 도구 사용 {#use-mobile-devops-tools}

Android 및 iOS용 모바일 앱을 빌드, 서명 및 릴리스합니다.

| 주제 | 설명 | 초보자에게 좋음 |
|-------|-------------|--------------------|
| [GitLab Mobile DevOps로 Android 앱 빌드](../ci/mobile_devops/mobile_devops_tutorial_android.md) | CI/CD 파이프라인을 사용하여 Android 모바일 앱을 빌드하는 방법을 알아봅니다. 예상 시간: 30-45분입니다. | |
| [GitLab Mobile DevOps를 사용하여 iOS 앱 빌드](../ci/mobile_devops/mobile_devops_tutorial_ios.md) | CI/CD 파이프라인을 사용하여 iOS 모바일 앱을 빌드하는 방법을 알아봅니다. 예상 시간: 30-45분입니다. | |
