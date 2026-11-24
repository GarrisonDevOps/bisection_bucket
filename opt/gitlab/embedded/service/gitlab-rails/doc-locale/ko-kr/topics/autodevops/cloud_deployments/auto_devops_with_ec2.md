---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Auto DevOps를 사용하여 EC2에 배포
---

[Auto DevOps](../_index.md)를 사용하여 EC2에 배포하려면:

1. [AWS 자격 증명을 CI/CD 변수로](../../../ci/cloud_deployment/_index.md#authenticate-gitlab-with-aws) 정의합니다.
1. `.gitlab-ci.yml` 파일에서 `Auto-Devops.gitlab-ci.yml` 템플릿을 참조합니다.
1. `build` 스테이지에 대한 `build_artifact` 이름의 작업을 정의합니다. 예를 들어:

   ```yaml
   # .gitlab-ci.yml

   include:
     - template: Auto-DevOps.gitlab-ci.yml

   variables:
     AUTO_DEVOPS_PLATFORM_TARGET: EC2

   build_artifact:
     stage: build
     script:
       - <your build script goes here>
     artifacts:
       paths:
         - <built artifact>
   ```

<i class="fa-youtube-play" aria-hidden="true"></i> 이 프로세스의 동영상 가이드를 보려면 [Auto Deploy to EC2](https://www.youtube.com/watch?v=4B-qSwKnacA)를 확인하세요.
