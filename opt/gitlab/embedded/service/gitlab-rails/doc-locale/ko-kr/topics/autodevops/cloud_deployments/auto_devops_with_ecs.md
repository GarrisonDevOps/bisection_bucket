---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 자동 DevOps를 사용하여 Amazon ECS에 배포
---

Kubernetes를 사용하는 대신 AWS ECS를 배포 플랫폼으로 선택할 수 있습니다.

자동 DevOps를 AWS ECS로 시작하려면 특정 CI/CD 변수를 추가해야 합니다. 이를 위해 다음 단계를 따르세요:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **자동 DevOps**를 확장합니다.
1. `AUTO_DEVOPS_PLATFORM_TARGET` 변수를 추가하여 자동 DevOps 배포 중에 대상으로 지정할 AWS 플랫폼을 지정합니다. 다음 값 중 하나를 사용하세요:
   - `FARGATE` 타겟팅하는 서비스가 FARGATE 시작 유형이어야 하는 경우입니다.
   - `ECS` ECS에 배포할 때 시작 유형 확인을 실행하지 않는 경우입니다.

파이프라인을 트리거할 때 자동 DevOps가 활성화되어 있고 [AWS 자격 증명을 변수로 올바르게 입력](../../../ci/cloud_deployment/_index.md#authenticate-gitlab-with-aws)했다면 애플리케이션이 AWS ECS에 배포됩니다.

유효한 `AUTO_DEVOPS_PLATFORM_TARGET` 변수와 프로젝트에 연결된 Kubernetes 클러스터가 모두 있으면 Kubernetes로의 배포만 실행됩니다.

> [!warning]
> `AUTO_DEVOPS_PLATFORM_TARGET` 변수를 `ECS`으로 설정하면 [`Jobs/Deploy/ECS.gitlab-ci.yml` 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Deploy/ECS.gitlab-ci.yml)에 정의된 작업을 트리거합니다. 그러나 이를 단독으로 [포함](../../../ci/yaml/_index.md#includetemplate)하는 것은 권장되지 않습니다. 이 템플릿은 자동 DevOps 전용으로 사용하도록 설계되었습니다. 단독으로 포함되면 예기치 않게 변경되어 파이프라인이 실패할 수 있습니다. 또한 이 템플릿 내의 작업 이름도 변경될 수 있습니다. 자신의 파이프라인에서 이러한 작업의 이름을 재정의하지 마세요. 이름이 변경되면 재정의가 작동 중지되기 때문입니다.
