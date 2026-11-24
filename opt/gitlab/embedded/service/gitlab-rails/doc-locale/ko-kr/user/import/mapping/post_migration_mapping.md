---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 마이그레이션 후 기여도 및 멤버십 매핑
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 17.4에서 직접 전송을 위해 [도입되었으며](https://gitlab.com/gitlab-org/gitlab/-/issues/443557) [기능 플래그](../../../administration/feature_flags/_index.md)는 `importer_user_mapping`및 `bulk_import_importer_user_mapping`입니다. 기본적으로 비활성화되었습니다.
- GitLab 17.6에서 [Gitea](https://gitlab.com/gitlab-org/gitlab/-/issues/467084)를 위해 [기능 플래그](../../../administration/feature_flags/_index.md)는 `importer_user_mapping`및 `gitea_user_mapping`이고, [GitHub](https://gitlab.com/gitlab-org/gitlab/-/issues/466355)을 위해 플래그는 `importer_user_mapping` 및 `github_user_mapping`입니다. 기본적으로 비활성화되었습니다.
- GitLab 17.7에서 Bitbucket Server를 위해 [도입되었으며](https://gitlab.com/gitlab-org/gitlab/-/issues/466356) [기능 플래그](../../../administration/feature_flags/_index.md)는 `importer_user_mapping` 및 `bitbucket_server_user_mapping`입니다. 기본적으로 비활성화되었습니다.
- GitLab 17.7에서 직접 전송을 위해 [GitLab.com 및 GitLab Self-Managed에서 활성화되었습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/472735).
- GitLab 17.7에서 [Bitbucket Server](https://gitlab.com/gitlab-org/gitlab/-/issues/509897), [Gitea](https://gitlab.com/gitlab-org/gitlab/-/issues/498390), [GitHub](https://gitlab.com/gitlab-org/gitlab/-/issues/499993)을 위해 GitLab.com에서 활성화되었습니다.
- GitLab 17.8에서 [Bitbucket Server](https://gitlab.com/gitlab-org/gitlab/-/issues/509897), [Gitea](https://gitlab.com/gitlab-org/gitlab/-/issues/498390), [GitHub](https://gitlab.com/gitlab-org/gitlab/-/issues/499993)을 위해 GitLab Self-Managed에서 활성화되었습니다.
- 개인 네임스페이스로 가져올 때 개인 네임스페이스 소유자에게 기여도를 다시 할당하는 것이 GitLab 18.3에서 [도입되었으며](https://gitlab.com/gitlab-org/gitlab/-/issues/525342) [기능 플래그](../../../administration/feature_flags/_index.md)는 `user_mapping_to_personal_namespace_owner`입니다. 기본적으로 비활성화되었습니다.
- GitLab 18.4에서 직접 전송을 위해 [일반적으로 사용 가능합니다](https://gitlab.com/gitlab-org/gitlab/-/issues/508945). 기능 플래그 `bulk_import_importer_user_mapping`이 제거되었습니다.
- 서비스 계정, 프로젝트 봇, 그룹 봇에 기여도를 다시 할당하는 것이 GitLab 18.5에서 [도입되었으며](https://gitlab.com/gitlab-org/gitlab/-/issues/573124) [기능 플래그](../../../administration/feature_flags/_index.md)는 `user_mapping_service_account_and_bots`입니다. 기본적으로 활성화됩니다.
- GitLab 18.6에서 Gitea를 위해 [일반적으로 사용 가능합니다](https://gitlab.com/gitlab-org/gitlab/-/issues/512211). 기능 플래그 `gitea_user_mapping`이 제거되었습니다.
- 개인 네임스페이스로 가져올 때 개인 네임스페이스 소유자에게 기여도를 다시 할당하는 것이 GitLab 18.6에서 [일반적으로 사용 가능합니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/211626). 기능 플래그 `user_mapping_to_personal_namespace_owner`이 제거되었습니다.
- `github_user_mapping` 기능 플래그이 GitLab 18.8에서 [제거되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/216778).
- `user_mapping_service_account_and_bots` 기능 플래그이 GitLab 18.10에서 [제거되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/223142).

{{< /history >}}

마이그레이션 후 매핑을 사용하면 소스 인스턴스의 사용자 기여도 및 멤버십이 목적지 인스턴스의 실제 사용자가 아닌 플레이스홀더 사용자에게 처음에 할당됩니다.

실제 사용자에게의 할당을 연기할 수 있으므로 가져오기를 검토하고 기여도를 올바른 사용자에게 다시 할당할 시간이 있습니다. 이 프로세스는 정확한 attribution을 보장하면서 매핑 프로세스에 대한 제어를 유지합니다.

마이그레이션 후 사용자 기여도 및 멤버십 매핑은 다음에서의 마이그레이션에 대해 기본적으로 사용 가능합니다:

- [직접 전송을 사용할 때 GitLab](../../group/import/_index.md)
- [GitHub](../../project/import/github.md)
- [Bitbucket Server](../bitbucket_server.md)
- [Gitea](../gitea.md)

프로젝트를 [개인 네임스페이스](../../namespace/_index.md#types-of-namespaces)로 가져올 때 사용자 기여도 매핑 및 멤버십 매핑은 지원되지 않으며 모든 기여도는 개인 네임스페이스 소유자에게 할당됩니다. 이러한 기여도는 다시 할당할 수 없습니다.

## 사전 요구 사항 {#prerequisites}

- [사용자 제한](#placeholder-user-limits)에 따라 사용자 수를 계획합니다.
- GitLab.com으로 가져오는 경우 유료 네임스페이스를 설정합니다.
- GitLab.com으로 가져오고 [GitLab.com 그룹을 위한 SAML SSO](../../group/saml_sso/_index.md)를 사용하는 경우 모든 사용자가 SAML 신원을 GitLab.com 계정에 연결했는지 확인합니다.

## 마이그레이션 후 매핑 워크플로우 {#post-migration-mapping-workflow}

마이그레이션 후 매핑을 사용할 때 GitLab은 가져온 모든 멤버십 및 기여도를 [플레이스홀더 사용자](#placeholder-users)에게 매핑합니다. 플레이스홀더 사용자는 목적지 인스턴스에 동일한 이메일 주소를 가진 사용자가 있더라도 생성됩니다. 목적지 인스턴스에서 기여도를 다시 할당할 때까지 모든 기여도는 플레이스홀더 사용자와 연관됩니다.

가져오기가 완료되고 결과를 검토한 후 다음과 같이 매핑을 업데이트할 수 있습니다:

- 목적지 인스턴스의 기존 사용자에게 멤버십 및 기여도를 다시 할당합니다. 소스 및 목적지 인스턴스에서 다른 이메일 주소를 가진 사용자에 대한 멤버십 및 기여도를 매핑할 수 있습니다.
- 목적지 인스턴스에서 새 사용자를 만들고 멤버십 및 기여도를 다시 할당합니다.

역사적 context를 보존하기 위해 특정 기여도를 플레이스홀더 사용자에게 할당된 상태로 유지할 수도 있습니다.

목적지 인스턴스의 사용자에게 기여도를 다시 할당할 때 사용자는 다음 중 하나를 수행할 수 있습니다:

- 다시 할당을 수락합니다. 다시 할당 프로세스는 몇 분 정도 걸릴 수 있습니다. 동일한 소스 인스턴스에서 목적지 인스턴스의 동일한 최상위 그룹 또는 subgroup으로의 후속 가져오기에서 기여도는 자동으로 사용자에게 매핑됩니다.
- 다시 할당을 거부합니다.

## 엔터프라이즈 사용자 {#enterprise-users}

{{< history >}}

- GitLab 18.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/510673)되었습니다.

{{< /history >}}

최상위 그룹에 최소 하나의 [엔터프라이즈 사용자](../../enterprise_user/_index.md)가 있는 경우 조직의 엔터프라이즈 사용자에게만 기여도를 다시 할당할 수 있습니다.

이는 조직 외부 사용자에게 실수로 다시 할당할 수 없음을 의미합니다.

## 삭제된 사용자 {#deleted-users}

이제 삭제된 사용자가 수행한 소스 인스턴스의 기여도는 목적지 인스턴스의 [ghost 사용자](../../../administration/internal_users.md)에게 매핑되며, 다음의 경우를 제외합니다:

- 기여도가 소스 인스턴스의 삭제된 사용자에게서 올바르게 분리되지 않았습니다.
- Bitbucket Server에서 마이그레이션합니다.

## 플레이스홀더 사용자 {#placeholder-users}

기여도 및 멤버십 매핑을 사용하면 목적지 인스턴스의 사용자에게 기여도 및 멤버십을 즉시 할당하지 않습니다. 대신 가져온 기여도 또는 멤버십이 있는 활성, 비활성 또는 봇 사용자에 대해 플레이스홀더 사용자가 생성됩니다.

기여도 및 멤버십은 처음에 이러한 플레이스홀더 사용자에게 할당되며 가져오기 후 목적지 인스턴스의 기존 사용자에게 다시 할당할 수 있습니다.

다시 할당될 때까지 기여도는 플레이스홀더와 연관됩니다. 플레이스홀더 멤버십은 멤버 목록에 표시되지 않습니다.

플레이스홀더 사용자는 라이선스 제한에 포함되지 않습니다.

### 예외 {#exceptions}

플레이스홀더 사용자는 다음과 같은 시나리오에서는 생성되지 않습니다:

- 삭제된 사용자의 기여도로 [Gitea](../gitea.md)에서 프로젝트를 가져오고 있습니다. 이러한 사용자의 기여도는 프로젝트를 가져온 사용자에게 매핑됩니다.
- [플레이스홀더 사용자 제한](#placeholder-user-limits)을 초과했습니다. 새로운 사용자의 기여도는 가져오기 사용자에게 매핑됩니다.

### 플레이스홀더 사용자 속성 {#placeholder-user-attributes}

플레이스홀더 사용자는 일반 사용자와 다르며 다음을 수행할 수 없습니다:

- 로그인합니다.
- 모든 작업을 수행합니다. 예를 들어 파이프라인을 실행합니다.
- 이슈 및 머지 리퀘스트의 담당자 또는 검토자로 제안에 표시됩니다.
- 프로젝트 및 그룹의 멤버가 됩니다.

소스 인스턴스의 사용자와의 연결을 유지하기 위해 플레이스홀더 사용자는 다음을 가집니다:

- 새로운 플레이스홀더 사용자가 필요한지 결정하기 위해 가져오기 프로세스에 사용되는 고유 identifier(`source_user_id`)입니다.
- 소스 hostname 또는 domain(`source_hostname`)입니다.
- 기여도의 다시 할당에 도움이 되는 소스 사용자의 name(`source_name`)입니다.
- 기여도의 다시 할당 중에 그룹 소유자를 용이하게 하기 위한 소스 사용자의 username(`source_username`)입니다.
- 플레이스홀더를 생성한 importer를 구분하기 위한 import type(`import_type`)입니다.
- 마이그레이션 추적을 위해 local time에서 소스 사용자가 생성된 시간의 timestamp(`created_at`) ([GitLab 17.10에서 도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/507297))입니다.

역사적 context를 보존하기 위해 플레이스홀더 사용자 name 및 username은 소스 사용자 name 및 username에서 파생됩니다:

- 플레이스홀더 사용자의 name은 `Placeholder <source user name>`입니다.
- 플레이스홀더 사용자의 username은 `%{source_username}_placeholder_user_%{incremental_number}`입니다.

### 플레이스홀더 사용자 보기 {#view-placeholder-users}

사전 요구 사항:

- 그룹의 Owner 역할이 있어야 합니다.

플레이스홀더 사용자는 그룹 또는 프로젝트를 가져오는 동안 목적지 인스턴스에 생성됩니다. 최상위 그룹 및 해당 subgroup으로의 가져오기 중에 생성된 플레이스홀더 사용자를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 수준에 있어야 합니다.
1. 왼쪽 sidebar에서 **관리** > **멤버**를 선택합니다.
1. **플레이스홀더** 탭을 선택합니다.

### 플레이스홀더 사용자 필터링 {#filter-for-placeholder-users}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 17.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/521974)되었습니다.

{{< /history >}}

사전 요구 사항:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

플레이스홀더 사용자는 그룹 또는 프로젝트를 가져오는 동안 목적지 인스턴스에 생성됩니다. 전체 인스턴스에 대한 가져오기 중에 생성된 플레이스홀더 사용자를 필터링하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **개요** > **사용자**를 선택합니다.
1. 검색 상자에서 사용자를 **type**으로 필터링합니다.

### 플레이스홀더 사용자 생성 {#creating-placeholder-users}

플레이스홀더 사용자는 가져오기 소스당 및 최상위 그룹당 생성됩니다:

- 동일한 프로젝트를 목적지 인스턴스의 동일한 최상위 그룹으로 두 번 가져오는 경우 두 번째 가져오기는 첫 번째 가져오기와 동일한 플레이스홀더 사용자를 사용합니다.
- 동일한 프로젝트를 두 번 가져오지만 목적지 인스턴스의 다른 최상위 그룹으로 가져오는 경우 두 번째 가져오기는 해당 최상위 그룹 아래에 새로운 플레이스홀더 사용자를 생성합니다.

> [!note]
> 플레이스홀더 사용자는 최상위 그룹과만 연관됩니다. subgroup 또는 프로젝트를 삭제하면 해당 플레이스홀더 사용자는 더 이상 최상위 그룹의 기여도를 참조하지 않습니다. 테스트할 때는 designated top-level group을 사용해야 합니다. 플레이스홀더 사용자 삭제는 [issue 519391](https://gitlab.com/gitlab-org/gitlab/-/issues/519391) 및 [issue 537340](https://gitlab.com/gitlab-org/gitlab/-/issues/537340)에서 제안됩니다.

사용자가 [다시 할당을 수락](reassignment.md#accept-contribution-reassignment)하면 동일한 소스 인스턴스에서 목적지 인스턴스의 동일한 최상위 그룹 또는 subgroup으로의 후속 가져오기는 플레이스홀더 사용자를 생성하지 않습니다. 대신 기여도는 자동으로 사용자에게 매핑됩니다.

### 플레이스홀더 사용자 삭제 {#placeholder-user-deletion}

{{< history >}}

- GitLab 18.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/473256)되었습니다.

{{< /history >}}

플레이스홀더 사용자를 포함하는 최상위 그룹을 삭제하면 이러한 사용자는 자동으로 제거 예정으로 예약됩니다. 이 프로세스를 완료하는 데 다소 시간이 걸릴 수 있습니다. 그러나 플레이스홀더 사용자가 다른 프로젝트 또는 그룹과도 연관되어 있으면 시스템에 남아있습니다.

> [!note]
> 플레이스홀더 사용자를 삭제하는 다른 방법은 없지만 개선 지원이 [issue 519391](https://gitlab.com/gitlab-org/gitlab/-/issues/519391) 및 [issue 537340](https://gitlab.com/gitlab-org/gitlab/-/issues/537340)에서 제안됩니다.

### 플레이스홀더 사용자 제한 {#placeholder-user-limits}

GitLab.com으로 가져오는 경우 플레이스홀더 사용자는 목적지 인스턴스의 최상위 그룹당 제한됩니다. 제한은 플랜 및 seat count에 따라 다릅니다. 플레이스홀더 사용자는 라이선스 제한에 포함되지 않습니다.

| GitLab.com 플랜          | Seat 수 | 최상위 그룹의 플레이스홀더 사용자 제한 |
|:-------------------------|:----------------|:------------------------------------------|
| Free 및 모든 trial       | 모든 수량      | 200                                       |
| Premium                  | < 100           | 500                                       |
| Premium                  | 101-500         | 2000                                      |
| Premium                  | 501 - 1000      | 4000                                      |
| Premium                  | > 1000          | 6000                                      |
| Ultimate 및 오픈 소스 | < 100           | 1000                                      |
| Ultimate 및 오픈 소스 | 101-500         | 4000                                      |
| Ultimate 및 오픈 소스 | 501 - 1000      | 6000                                      |
| Ultimate 및 오픈 소스 | > 1000          | 8000                                      |

GitLab Self-Managed 및 GitLab Dedicated의 경우 기본적으로 플레이스홀더 제한이 적용되지 않습니다. GitLab administrator는 인스턴스에서 [플레이스홀더 제한을 설정](../../../administration/instance_limits.md#import-placeholder-user-limits)할 수 있습니다.

현재 플레이스홀더 사용자 사용 및 제한을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 수준에 있어야 합니다.
1. **설정** > **사용 할당량**을 선택합니다.
1. **가져오기** 탭을 선택합니다.

필요한 플레이스홀더 사용자 수를 미리 결정할 수 없습니다.

플레이스홀더 사용자 제한에 도달하면 모든 기여도는 `Import User`라는 단일 non-functional 사용자에게 할당됩니다. `Import User`에 할당된 기여도는 중복 제거될 수 있으며 일부 기여도는 가져오기 중에 생성되지 않을 수 있습니다. 예를 들어, 머지 리퀘스트 approver의 여러 승인이 `Import User`에 할당된 경우 첫 번째 승인만 생성되고 나머지는 무시됩니다. 중복 제거될 수 있는 기여도는 다음과 같습니다:

- 승인 규칙
- Emoji reactions
- 이슈 담당자
- 멤버십
- 머지 리퀘스트 승인, 담당자, 및 검토자
- Push, 머지 리퀘스트, 및 deploy 접근 수준

모든 변경은 시스템 note를 생성하며, 이는 플레이스홀더 사용자 제한의 영향을 받지 않습니다.

## Alternative 매핑 방법 {#alternative-mapping-method}

마이그레이션 후 매핑의 alternative는 마이그레이션 중에 매핑하는 방법입니다. 이 방법은 권장되지 않으며 발견된 모든 문제는 수정될 가능성이 낮습니다.

Alternative 매핑 방법은:

- GitLab Self-Managed로의 마이그레이션에만 사용 가능합니다.
- 적용 가능한 `*_user_mapping` 기능 플래그를 비활성화하는 것을 포함하여 마이그레이션 전에 일부 준비가 필요합니다.
- 다음에서의 마이그레이션에 사용 가능합니다:
  - GitHub입니다.
  - Bitbucket Server입니다.
  - Gitea(GitLab 18.5 이상)입니다.

자세한 내용은 각 importer에 대한 alternative 매핑 방법 설명서를 참조합니다.
