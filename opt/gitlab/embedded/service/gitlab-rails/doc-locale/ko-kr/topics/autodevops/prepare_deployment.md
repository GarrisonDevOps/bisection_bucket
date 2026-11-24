---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 배포를 위한 Auto DevOps 준비
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

기본 도메인과 배포 전략을 설정하지 않고 Auto DevOps를 활성화하면 GitLab이 애플리케이션을 직접 배포할 수 없습니다. 따라서 Auto DevOps를 활성화하기 전에 전략을 준비해야 합니다.

## 배포 전략 {#deployment-strategy}

Auto DevOps를 사용하여 애플리케이션을 배포할 때 사용 요구사항에 가장 적합한 [지속적 배포 전략](../../ci/_index.md)을 선택합니다:

| 배포 전략                                                     | 설정 | 방법론 |
|-------------------------------------------------------------------------|-------|-------------|
| **프로덕션 환경에 지속적인 배포**                                 | 기본 브랜치가 프로덕션에 지속적으로 배포되는 [Auto Deploy](stages.md#auto-deploy)를 활성화합니다. | 프로덕션 환경에 지속적인 배포|
| **점진적(incremental) 롤아웃을 사용하여 프로덕션 환경에 지속적 배포** | [`INCREMENTAL_ROLLOUT_MODE`](cicd_variables.md#timed-incremental-rollout-to-production) 변수를 `timed`로 설정합니다. | 롤아웃 간 5분의 지연 시간을 두고 프로덕션에 지속적으로 배포합니다. |
| **스테이징 환경에 자동 배포, 프로덕션 환경에 수동 배포**    | [`STAGING_ENABLED`](cicd_variables.md#deploy-policy-for-staging-and-production-environments)를 `1`로 설정하고 [`INCREMENTAL_ROLLOUT_MODE`](cicd_variables.md#incremental-rollout-to-production)를 `manual`로 설정합니다. | 기본 브랜치는 스테이징에 지속적으로 배포되고 프로덕션에 지속적으로 제공됩니다. |

Auto DevOps를 활성화할 때 또는 나중에 배포 방법을 선택할 수 있습니다:

1. GitLab에서 프로젝트의 **설정** > **CI/CD** > **자동 DevOps**로 이동합니다.
1. 배포 전략을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

> [!note]
> [블루-그린 배포](../../ci/environments/incremental_rollouts.md#blue-green-deployment) 기법을 사용하여 가동 중지 시간과 위험을 최소화합니다.

## Auto DevOps 기본 도메인 {#auto-devops-base-domain}

Auto DevOps 기본 도메인은 [Auto Review Apps](stages.md#auto-review-apps)와 [Auto Deploy](stages.md#auto-deploy)를 사용하는 데 필요합니다.

기본 도메인을 정의하려면 다음 중 하나를 수행합니다:

- 프로젝트, 그룹 또는 인스턴스에서 클러스터 설정으로 이동하여 여기에 추가합니다.
- 프로젝트 또는 그룹에서 환경 변수로 추가합니다: `KUBE_INGRESS_BASE_DOMAIN`.
- 인스턴스에서 **운영자** 영역으로 이동한 다음 **설정** > **CI/CD** > **Continuous Integration and Delivery**로 이동하여 여기에 추가합니다.

기본 도메인 변수 `KUBE_INGRESS_BASE_DOMAIN`는 다른 환경 [변수](../../ci/variables/_index.md#cicd-variable-precedence)와 동일한 우선순위 순서를 따릅니다.

프로젝트 및 그룹에서 기본 도메인을 지정하지 않으면 Auto DevOps는 인스턴스 전체 **Auto DevOps 도메인**을 사용합니다.

Auto DevOps는 기본 도메인과 일치하는 와일드카드 DNS `A` 레코드가 필요합니다. `example.com`의 기본 도메인의 경우 다음과 같은 DNS 항목이 필요합니다:

```plaintext
*.example.com   3600     A     10.0.2.2
```

이 경우 배포된 애플리케이션은 `example.com`에서 제공되며 `10.0.2.2`는 로드 밸런서(일반적으로 NGINX)의 IP 주소입니다([요구사항 참조](requirements.md)). DNS 레코드 설정은 이 문서의 범위를 벗어나므로 DNS 공급자에게 문의하여 정보를 확인합니다.

또는 설정 없이 자동 와일드카드 DNS를 제공하는 [nip.io](https://nip.io)와 같은 무료 공개 서비스를 사용할 수 있습니다. [nip.io](https://nip.io)의 경우 Auto DevOps 기본 도메인을 `10.0.2.2.nip.io`로 설정합니다.

설정을 완료한 후 모든 요청이 로드 밸런서에 도달하고 로드 밸런서가 애플리케이션을 실행하는 Kubernetes 포드로 요청을 라우팅합니다.
