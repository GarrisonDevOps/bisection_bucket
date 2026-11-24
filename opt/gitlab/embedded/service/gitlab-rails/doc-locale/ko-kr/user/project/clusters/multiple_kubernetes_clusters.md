---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 클러스터 인증서를 사용하는 프로젝트당 여러 클러스터(지원 중단됨)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> 단일 프로젝트의 여러 Kubernetes 클러스터를 **클러스터 인증서와 함께** 사용하는 기능은 GitLab 14.5에서 [더 이상 사용되지 않습니다](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8). GitLab에 클러스터를 연결하려면 [GitLab Kubernetes 에이전트](../../clusters/agent/_index.md)를 사용하세요.

여러 개의 Kubernetes 클러스터를 프로젝트와 연결할 수 있습니다. 이 방법으로 개발, 스테이징, 프로덕션 등 다양한 환경을 위해 서로 다른 클러스터를 사용할 수 있습니다. 처음과 마찬가지로 다른 클러스터를 추가하고, 새 클러스터를 나머지와 구별할 수 있도록 [환경 범위를 설정](#setting-the-environment-scope)해야 합니다.

## 환경 범위 설정 {#setting-the-environment-scope}

프로젝트에 여러 개의 Kubernetes 클러스터를 추가할 때는 환경 범위를 사용하여 이들을 구별해야 합니다. 환경 범위는 [환경](../../../ci/environments/_index.md)과 클러스터를 연결하며, [환경별 CI/CD 변수](../../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable)가 작동하는 방식과 비슷합니다.

기본 환경 범위는 `*`이며, 이는 모든 작업이 해당 환경에 관계없이 해당 클러스터를 사용한다는 의미입니다. 각 범위는 프로젝트의 단일 클러스터에서만 사용할 수 있으며, 그렇지 않으면 유효성 검사 오류가 발생합니다. 또한 환경 키워드가 설정되지 않은 작업은 어떤 클러스터에도 액세스할 수 없습니다.

예를 들어, 프로젝트에 다음과 같은 Kubernetes 클러스터가 있을 수 있습니다:

| 클러스터     | 환경 범위 |
| ----------- | ----------------- |
| 개발 | `*`               |
| 프로덕션  | `production`      |

다음 환경이 `.gitlab-ci.yml` 파일에 설정됩니다:

```yaml
stages:
  - test
  - deploy

test:
  stage: test
  script: sh test

deploy to staging:
  stage: deploy
  script: make deploy
  environment:
    name: staging
    url: https://staging.example.com/

deploy to production:
  stage: deploy
  script: make deploy
  environment:
    name: production
    url: https://example.com/
```

결과:

- Development 클러스터 세부 정보는 `deploy to staging` 작업에서 사용할 수 있습니다.
- 프로덕션 클러스터 세부 정보는 `deploy to production` 작업에서 사용할 수 있습니다.
- `test` 작업은 환경을 정의하지 않으므로 클러스터 세부 정보를 사용할 수 없습니다.
