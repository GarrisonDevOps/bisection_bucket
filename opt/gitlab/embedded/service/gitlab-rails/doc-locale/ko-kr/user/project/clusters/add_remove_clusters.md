---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 클러스터 인증서를 사용하여 클러스터 추가(더 이상 지원되지 않음)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 14.0에서 [지원 중단](https://gitlab.com/gitlab-org/gitlab/-/issues/327908)되었습니다. 새 클러스터를 만들고 관리하려면 [코드 기반 인프라](../../infrastructure/iac/_index.md)를 사용하세요.

## 클러스터 비활성화 {#disable-a-cluster}

클러스터 인증서를 사용하여 기존 클러스터에 성공적으로 연결하면 GitLab에 대한 클러스터 연결이 활성화됩니다. 비활성화하려면:

1. 다음으로 이동합니다:
   - 프로젝트의 {{< icon name="cloud-gear" >}} **운영** > **Kubernetes 클러스터** 페이지(프로젝트 수준 클러스터).
   - 그룹의 {{< icon name="cloud-gear" >}} **Kubernetes** 페이지(그룹 수준 클러스터).
   - **운영자** 영역의 **Kubernetes** 페이지(인스턴스 수준 클러스터).
1. 비활성화할 클러스터의 이름을 선택합니다.
1. **GitLab 통합**을 끕니다(회색).
1. **변경 사항 저장**을 선택합니다.

## 클러스터 제거 {#remove-a-cluster}

클러스터 통합을 제거하면 클러스터 자체가 아닌 GitLab에 대한 클러스터 관계만 제거합니다. 클러스터 자체를 제거하려면 클러스터의 GKE 또는 EKS 대시보드로 이동하여 해당 UI에서 제거하거나 `kubectl`를 사용합니다.

GitLab과의 통합을 제거하려면 프로젝트 또는 그룹에 대한 유지 관리자 또는 소유자 역할이 필요합니다.

클러스터 통합을 제거할 때 두 가지 옵션이 있습니다:

- **통합 제거**: Kubernetes 통합만 제거합니다.
- **통합 및 리소스 제거**: 클러스터 통합 및 네임스페이스, 역할, 바인딩 등과 같은 모든 GitLab 클러스터 관련 리소스를 제거합니다.

Kubernetes 클러스터 통합을 제거하려면:

1. 클러스터 세부 정보 페이지로 이동합니다.
1. **고급 설정** 탭을 선택합니다.
1. **통합 제거** 또는 **통합 및 리소스 제거**를 선택합니다.

### Rails 콘솔을 사용하여 클러스터 제거 {#remove-clusters-by-using-the-rails-console}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Rails 콘솔 세션 시작](../../../administration/operations/rails_console.md#starting-a-rails-console-session)합니다.

클러스터를 찾으려면:

``` ruby
cluster = Clusters::Cluster.find(1)
cluster = Clusters::Cluster.find_by(name: 'cluster_name')
```

관련 리소스를 제거하지 않고 클러스터를 삭제하려면:

```ruby
# Find users who have administrator access
user = User.find_by(username: 'admin_user')

# Find the cluster with the ID
cluster = Clusters::Cluster.find(1)

# Delete the cluster
Clusters::DestroyService.new(user).execute(cluster)
```
