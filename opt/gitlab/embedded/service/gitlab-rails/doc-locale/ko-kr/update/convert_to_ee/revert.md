---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 엔터프라이즈 에디션에서 커뮤니티 에디션으로 되돌리기
---

엔터프라이즈 에디션(EE) 인스턴스를 커뮤니티 에디션(CE)으로 되돌릴 수 있지만, 먼저 다음을 수행해야 합니다:

1. EE 전용 인증 메커니즘을 비활성화합니다.
1. 데이터베이스에서 EE 전용 통합을 제거합니다.
1. 환경 범위를 사용하는 구성을 조정합니다.

## EE 전용 인증 메커니즘 끄기 {#turn-off-ee-only-authentication-mechanisms}

Kerberos는 EE 인스턴스에서만 사용할 수 있습니다. 다음을 수행해야 합니다.

- 되돌리기 전에 이러한 메커니즘을 끕니다.
- 사용자에게 다른 인증 방법을 제공합니다.

## 데이터베이스에서 EE 전용 통합 제거 {#remove-ee-only-integrations-from-the-database}

이러한 통합은 EE 코드베이스에서만 사용할 수 있습니다:

- [GitHub](../../user/project/integrations/github.md)
- [Git Guardian](../../user/project/integrations/git_guardian.md)
- [Google Artifact Management](../../user/project/integrations/google_artifact_management.md)
- [Google Cloud IAM](../../integration/google_cloud_iam.md)

CE로 다운그레이드하면 다음과 같은 오류가 발생할 수 있습니다:

```plaintext
Completed 500 Internal Server Error in 497ms (ActiveRecord: 32.2ms)

ActionView::Template::Error (The single-table inheritance mechanism failed to locate the subclass: 'Integrations::Github'. This
error is raised because the column 'type_new' is reserved for storing the class in case of inheritance. Please rename this
column if you didn't intend it to be used for storing the inheritance class or overwrite Integration.inheritance_column to
use another column for that information.)
```

오류 메시지의 `subclass`은(는) 다음 중 하나일 수 있습니다:

- `Integrations::Github`
- `Integrations::GitGuardian`
- `Integrations::GoogleCloudPlatform::ArtifactRegistry`
- `Integrations::GoogleCloudPlatform::WorkloadIdentityFederation`

모든 통합은 보유한 모든 프로젝트에 대해 자동으로 생성됩니다. 이 오류를 방지하려면 데이터베이스에서 모든 EE 전용 통합 레코드를 제거해야 합니다.

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

```shell
sudo gitlab-rails runner "Integration.where(type_new: ['Integrations::Github']).delete_all"
sudo gitlab-rails runner "Integration.where(type_new: ['Integrations::GitGuardian']).delete_all"
sudo gitlab-rails runner "Integration.where(type_new: ['Integrations::GoogleCloudPlatform::ArtifactRegistry']).delete_all"
sudo gitlab-rails runner "Integration.where(type_new: ['Integrations::GoogleCloudPlatform::WorkloadIdentityFederation']).delete_all"
```

{{< /tab >}}

{{< tab title="Self-compiled(소스)" >}}

```shell
bundle exec rails runner "Integration.where(type_new: ['Integrations::Github']).delete_all" production
bundle exec rails runner "Integration.where(type_new: ['Integrations::GitGuardian']).delete_all" production
bundle exec rails runner "Integration.where(type_new: ['Integrations::GoogleCloudPlatform::ArtifactRegistry']).delete_all" production
bundle exec rails runner "Integration.where(type_new: ['Integrations::GoogleCloudPlatform::WorkloadIdentityFederation']).delete_all" production
```

{{< /tab >}}

{{< /tabs >}}

## 환경 범위를 사용하는 구성 조정 {#adjust-configuration-that-uses-environment-scopes}

[환경 범위](../../user/group/clusters/_index.md#environment-scopes)를 사용하는 경우, 특히 구성 변수가 동일한 키를 공유하지만 다른 범위를 가진 경우 구성을 조정해야 할 수 있습니다. 환경 범위는 CE에서 완전히 무시됩니다.

동일한 키를 공유하지만 다른 범위를 가진 구성 변수의 경우, 특정 환경에서 예상하지 못한 변수를 실수로 얻을 수 있습니다. 이 경우 올바른 변수가 있는지 확인하세요.

데이터는 전환 과정에서 완전히 보존되므로 EE로 변경하고 동작을 복원할 수 있습니다.

## CE로 되돌리기 {#revert-to-ce}

필요한 단계를 수행한 후 GitLab 인스턴스를 CE로 되돌릴 수 있습니다.

모든 종속성이 최신 상태인지 확인하려면 올바른 [업데이트 가이드](../_index.md)를 따르세요.

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

[배포판용 설치 지침](../../install/package/_index.md#supported-platforms)을(를) 따라 커뮤니티 에디션 패키지를 설치합니다.

{{< /tab >}}

{{< tab title="Self-compiled(소스)" >}}

1. GitLab 설치의 현재 Git 원격을 CE Git 원격으로 바꿉니다.
1. 최신 변경 사항을 가져오고 최신 안정 브랜치를 확인합니다. 예를 들어:

   ```shell
   git remote set-url origin git@gitlab.com:gitlab-org/gitlab-foss.git
   git fetch --all
   git checkout 17-8-stable
   ```

{{< /tab >}}

{{< /tabs >}}

## 문제 해결 {#troubleshooting}

이 섹션에는 발생할 수 있는 문제에 대한 가능한 해결 방법이 포함되어 있습니다.

### 오류: `Cookbook gitlab-ee not found` {#error-cookbook-gitlab-ee-not-found}

GitLab EE 인스턴스에서 GitLab CE용 Linux 패키지를 설치할 때 `Cookbook gitlab-ee not found` 오류가 발생할 수 있습니다. 이 이슈를 해결하려면:

1. `gitlab-ee` 쿡북을 제거합니다:

   ```shell
   sudo rm -rf /opt/gitlab/embedded/cookbooks/cache/cookbooks/gitlab-ee
   ```

1. GitLab CE를 다시 설치합니다.
1. 모든 서비스가 실행 중인지 확인합니다:

   ```shell
   sudo gitlab-ctl status
   ```

   그렇지 않으면 GitLab을 다시 시작합니다:

   ```shell
   sudo gitlab-ctl restart
   ```
