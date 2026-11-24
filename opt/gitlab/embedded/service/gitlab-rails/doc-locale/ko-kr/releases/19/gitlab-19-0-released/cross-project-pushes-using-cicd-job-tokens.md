---
title: CI/CD 작업 토큰을 사용한 크로스 프로젝트 푸시
stage: verify
level: secondary
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
documentation_link: "../../../ci/jobs/ci_job_token/#allow-cross-project-git-push-requests-from-allowlisted-projects"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/issues/479907"
categories: [ Continuous Integration (CI) ]
weight: 120
---

이전 버전의 GitLab에서는 CI/CD 작업 토큰(`CI_JOB_TOKEN`)을 사용하여 파이프라인이 실행되는 동일한 리포지토리로만 푸시할 수 있었습니다. 교차 프로젝트 푸시에는 개인 액세스 토큰 또는 배포 토큰이 필요했습니다.

이제 다음 경우에 작업 토큰을 사용하여 다른 프로젝트로 푸시할 수 있습니다.

1. 대상 프로젝트가 옵트인합니다.
1. 파이프라인을 시작하는 사용자는 대상 프로젝트에서 최소 Developer 역할을 가지고 있습니다.

이 기능은 `allow_push_to_allowlisted_projects` 기능 플래그 뒤에 있으며 GitLab 19.0에서 기본적으로 비활성화되어 있습니다. 관리자에게 이를 활성화하도록 요청하세요.
