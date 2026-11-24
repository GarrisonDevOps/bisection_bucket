---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 직접 전송을 사용하여 그룹 및 프로젝트 마이그레이션
description: "직접 전송을 사용하여 GitLab 인스턴스 간에 그룹 및 프로젝트를 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

직접 전송을 사용하여 GitLab 그룹 및 프로젝트를 마이그레이션하려면:

1. [필수 조건](#prerequisites)을 충족하는지 확인합니다.
1. [사용자 기여도](../../import/mapping/post_migration_mapping.md) 및 [사용자 멤버십](#user-membership-mapping) 매핑을 검토합니다.
1. [소스 GitLab 인스턴스 연결](#connect-the-source-gitlab-instance).
1. [가져올 그룹 및 프로젝트 선택](#select-the-groups-and-projects-to-import)하고 마이그레이션을 시작합니다.
1. [가져오기 결과 검토](#review-results-of-the-import).

문제가 발생한 경우 다음을 수행할 수 있습니다:

1. 마이그레이션을 [취소](#cancel-a-running-migration)하거나 [다시 시도](#retry-failed-or-partially-successful-migrations)합니다.
1. [문제 해결 설명서](troubleshooting.md)를 참조합니다.

## 사전 요구 사항 {#prerequisites}

{{< history >}}

- 대상 인스턴스에서 충돌을 피하기 위해 마일스톤 제목 이름 바꾸기가 GitLab 18.6.7 이상, 18.7.5 이상, 18.8.5 이상에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/221447)되었습니다.

{{< /history >}}

직접 전송을 사용하여 마이그레이션하기 전에 다음 필수 조건을 참조합니다.

### 네트워크 및 스토리지 공간 {#network-and-storage-space}

- 인스턴스 또는 GitLab.com 간의 네트워크 연결이 HTTPS를 지원해야 합니다.
- 방화벽이 소스 및 대상 GitLab 인스턴스 간의 연결을 차단하면 안 됩니다.
- 소스 및 대상 GitLab 인스턴스에는 `/tmp` 디렉터리에 충분한 여유 공간이 있어야 전송된 프로젝트 및 그룹의 아카이브를 생성하고 추출할 수 있습니다.

### 버전 {#versions}

성공적이고 효율적인 마이그레이션 가능성을 최대화하려면:

- 소스 및 대상 인스턴스를 모두 GitLab 16.8 이상으로 업그레이드합니다. 자세한 내용은 [에픽 9036](https://gitlab.com/groups/gitlab-org/-/epics/9036)을 참조합니다.
- 버그 수정 및 기타 개선 사항을 위해 가능한 한 최신 버전 간에 마이그레이션합니다.

소스 및 대상 인스턴스의 버전이 같지 않은 경우 소스 인스턴스는 대상 인스턴스보다 2개 이상의 [마이너](../../../policy/maintenance.md#versioning) 버전 이전 버전이 아니어야 합니다. 이 요구사항은 GitLab.com에서 GitLab Dedicated로의 마이그레이션에는 적용되지 않습니다.

### 구성 {#configuration}

- [Sidekiq이 올바르게 구성](../../../administration/sidekiq/configuration_for_imports.md)되었는지 확인합니다.
- 두 GitLab 인스턴스 모두에서 직접 전송을 통한 그룹 마이그레이션이 인스턴스 관리자에 의해 [애플리케이션 설정에서 활성화](../../../administration/settings/import_and_export_settings.md#enable-migration-of-groups-and-projects-by-direct-transfer)되어야 합니다.
- 소스 GitLab 인스턴스에 대해 `api` 범위가 있는 [개인 액세스 토큰](../../profile/personal_access_tokens.md)이 있어야 합니다.
- 소스 및 대상 인스턴스에 필요한 권한이 있어야 합니다. 다음의 경우:
  - 대부분의 사용자는 다음이 필요합니다:
    - 마이그레이션할 소스 그룹에서 소유자 역할입니다.
    - 해당 네임스페이스에서 [서브그룹을 생성](../subgroups/_index.md#create-a-subgroup)할 수 있는 대상 네임스페이스의 역할입니다.
  - 필요한 역할이 없는 두 인스턴스의 관리자는 [API](../../../api/bulk_imports.md#start-a-group-or-project-migration)를 사용하여 가져오기를 시작할 수 있습니다.
- 프로젝트 스니펫을 가져오려면 스니펫이 [소스 프로젝트에서 활성화](../../snippets.md#change-default-visibility-of-snippets)되어 있는지 확인합니다.
- 객체 스토리지에 저장된 항목을 가져오려면 다음 중 하나를 수행해야 합니다:
  - [`proxy_download` 구성](../../../administration/object_storage.md#configure-the-common-parameters)합니다.
  - 대상 GitLab 인스턴스가 소스 GitLab 인스턴스의 객체 스토리지에 액세스할 수 있는지 확인합니다.
- 소스 인스턴스 또는 그룹에 **프로젝트를 생성하는 데 필요한 기본 최소 역할**이 **아무도 없음**으로 설정된 경우 프로젝트가 있는 그룹을 가져올 수 없습니다. 필요한 경우 이 설정을 변경할 수 있습니다:
  - [전체 인스턴스](../../../administration/settings/visibility_and_access_controls.md#define-which-roles-can-create-projects)의 경우입니다.
  - [특정 그룹](../_index.md#specify-who-can-add-projects-to-a-group)의 경우입니다.
- 대상 네임스페이스 내에서 [기존 마일스톤과 일치](../../project/milestones/_index.md#milestone-title-rules)하는 제목을 가진 가져온 마일스톤은 가져올 때 제목이 업데이트됩니다. 새 제목에는 고유한 접미사가 추가됩니다(예: `18.0`는 `18.0
  (imported-3d-1770206299)`가 됩니다). 이를 방지하려면 직접 전송을 시작하기 전에 소스 그룹 또는 프로젝트에서 마일스톤의 이름을 바꿉니다.
- 다음 중 하나를 확인합니다:
  - 소스 및 대상 네임스페이스는 동일한 조직에 속합니다.
  - 소스 및 대상 네임스페이스가 서로 다른 조직에 속하는 경우 어느 조직도 격리된 것으로 표시되지 않습니다.

## 사용자 멤버십 매핑 {#user-membership-mapping}

{{< history >}}

- 상속된 멤버 매핑이 GitLab 17.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/458834)되었습니다.
- 사용자 멤버십을 처음에 자리 표시자 사용자로 매핑하는 것이 GitLab 17.3에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/12378)되었으며 `bulk_import_importer_user_mapping`라는 [기능 플래그](../../../administration/feature_flags/_index.md)를 사용합니다. 기본적으로 비활성화되었습니다.
- 사용자 멤버십을 처음에 자리 표시자 사용자로 매핑하는 것이 GitLab 17.5에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/478054)되었습니다.
- 사용자 멤버십을 처음에 자리 표시자 사용자로 매핑하는 것이 GitLab 17.7에서 [GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/478054)되었습니다.
- 사용자 멤버십을 처음에 자리 표시자 사용자로 매핑하는 것이 GitLab 18.4에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/508945)되었습니다. `bulk_import_importer_user_mapping` 기능 플래그가 제거되었습니다.

{{< /history >}}

마이그레이션 중에는 사용자가 생성되지 않습니다. 대신, 소스 인스턴스의 사용자 멤버십이 대상 인스턴스의 사용자로 매핑됩니다. 사용자 멤버십에 대한 매핑 유형은 소스 인스턴스의 [멤버십 유형](../../project/members/_index.md#membership-types)에 따라 다릅니다:

- 가져온 멤버십은 처음에 [자리 표시자 사용자](../../import/mapping/post_migration_mapping.md#placeholder-users)로 매핑됩니다.
- 직접 멤버십은 대상 인스턴스에서 직접 멤버십으로 매핑됩니다.
- 상속된 멤버십은 대상 인스턴스에서 상속된 멤버십으로 매핑됩니다.
- 공유 멤버십은 사용자가 기존 공유 멤버십을 가지지 않는 한 대상 인스턴스에서 직접 멤버십으로 매핑됩니다. 공유 멤버십 매핑에 대한 전체 지원이 [이슈 458345](https://gitlab.com/gitlab-org/gitlab/-/issues/458345)에서 제안됩니다.

[GitLab 18.4 이상](https://gitlab.com/gitlab-org/gitlab/-/issues/559224)에서는 기존 그룹에 직접 프로젝트를 가져오면서 직접 멤버십을 생성할 때 [**이 그룹의 프로젝트에 사용자를 추가할 수 없습니다.** 설정](../access_and_permissions.md#prevent-members-from-being-added-to-projects-in-a-group)이 준수됩니다.

[상속된 및 공유](../../project/members/_index.md#membership-types) 멤버십을 매핑할 때, 사용자가 매핑 중인 역할보다 [높은 역할](../../permissions.md#roles)을 가진 대상 네임스페이스에서 기존 멤버십을 가진 경우 멤버십이 직접 멤버십으로 매핑됩니다. 이렇게 하면 멤버가 권한이 상승되는 것을 방지합니다.

> [!note]
> 공유 멤버십 매핑에 영향을 미치는 [알려진 이슈](_index.md#known-issues)가 있습니다.

### 대상 인스턴스에서 사용자 구성 {#configure-users-on-destination-instance}

GitLab이 소스 및 대상 인스턴스 간에 사용자 및 해당 기여도를 올바르게 매핑하도록 하려면:

1. 대상 GitLab 인스턴스에서 필요한 사용자를 생성합니다. 관리자 액세스가 필요하므로 GitLab Self-Managed 인스턴스에서만 API를 사용하여 사용자를 생성할 수 있습니다. GitLab.com 또는 GitLab Self-Managed로 마이그레이션할 때 다음을 수행할 수 있습니다:
   - 사용자를 수동으로 생성합니다.
   - 기존 [SAML SSO 공급자](../saml_sso/_index.md)를 설정하거나 사용하고 [SCIM](../saml_sso/scim_setup.md)을 통해 지원되는 SAML SSO 그룹의 사용자 동기화를 활용합니다. [확인된 이메일 도메인으로 GitLab 사용자 계정 확인을 무시](../saml_sso/_index.md#bypass-user-email-confirmation-with-verified-domains)할 수 있습니다.
1. 사용자가 소스 GitLab 인스턴스에서 [공개 이메일](../../profile/_index.md#set-your-public-email)을 가지고 있고 대상 GitLab 인스턴스에서 확인된 이메일 주소와 일치하는지 확인합니다. 대부분의 사용자는 이메일 주소 확인을 요청하는 이메일을 수신합니다.
1. 사용자가 이미 대상 인스턴스에 존재하고 [GitLab.com 그룹용 SAML SSO](../saml_sso/_index.md)를 사용하는 경우 모든 사용자가 [SAML 신원을 GitLab.com 계정에 연결](../saml_sso/_index.md#link-saml-to-your-existing-gitlabcom-account)해야 합니다.

GitLab UI 또는 API에서 사용자에 대해 공개 이메일 주소를 자동으로 설정하는 방법은 없습니다. 많은 사용자 계정을 공개 이메일 주소로 설정해야 하는 경우 가능한 해결 방법에 대해 [이슈 284495](https://gitlab.com/gitlab-org/gitlab/-/issues/284495#note_1910159855)를 참조합니다.

## 소스 GitLab 인스턴스 연결 {#connect-the-source-gitlab-instance}

대상 GitLab 인스턴스에서 가져올 그룹을 만들고 소스 GitLab 인스턴스를 연결합니다:

1. 다음 중 하나를 생성합니다:
   - 새 그룹입니다. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 그룹**을 선택합니다. 그런 다음 **그룹 가져오기**를 선택합니다.
   - 새 서브그룹입니다. 기존 그룹 페이지에서 다음 중 하나를 선택합니다:
     - **하위그룹 생성**을 선택합니다.
     - 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 하위 그룹**을 선택합니다. 그런 다음 **기존 그룹 가져오기** 링크를 선택합니다.
1. GitLab 인스턴스의 기본 URL을 입력합니다.
1. 소스 GitLab 인스턴스에 대해 [개인 액세스 토큰](../../profile/personal_access_tokens.md)을 입력합니다.
1. **인스턴스 연결**을 선택합니다.

## 가져올 그룹 및 프로젝트 선택 {#select-the-groups-and-projects-to-import}

{{< history >}}

- **사용자 멤버십 가져오기** 확인란이 GitLab 17.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/477734)되었습니다.

{{< /history >}}

소스 GitLab 인스턴스에 대한 액세스 권한을 부여한 후 GitLab 그룹 가져오기 페이지로 리디렉션됩니다. 여기서 소유자 역할이 있는 연결된 소스 인스턴스의 최상위 그룹 목록을 볼 수 있습니다.

소스 인스턴스에서 모든 사용자 멤버십을 가져오지 않으려면 **사용자 멤버십 가져오기** 확인란이 선택 해제되어 있는지 확인합니다. 예를 들어, 소스 인스턴스에 200명의 멤버가 있지만 50명의 멤버만 가져올 수도 있습니다. 가져오기가 완료된 후 그룹 및 프로젝트에 더 많은 멤버를 추가할 수 있습니다.

1. 기본적으로 제안된 그룹 네임스페이스는 소스 인스턴스에 존재하는 이름과 일치하지만 권한에 따라 가져오기를 진행하기 전에 이러한 이름을 편집하도록 선택할 수 있습니다. 그룹 및 프로젝트 경로는 [명명 규칙](../../reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs)을 준수해야 하며 가져오기 실패를 방지하기 위해 필요한 경우 정규화됩니다.
1. 가져올 그룹 옆에서 다음 중 하나를 선택합니다:
   - **프로젝트와 함께 가져오기**. 사용할 수 없는 경우 [필수 조건](#prerequisites)을 참조합니다.
   - **프로젝트 없이 가져오기**.
1. **상태** 열에 각 그룹의 가져오기 상태가 표시됩니다. 페이지를 열어 두면 실시간으로 업데이트됩니다.
1. 그룹을 가져온 후 GitLab 경로를 선택하여 GitLab URL을 엽니다.

## 가져오기 결과 검토 {#review-results-of-the-import}

{{< history >}}

- GitLab 17.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/443492)된 **가져옴** 배지는 디자인, 에픽, 이슈, 머지 리퀘스트, 노트(시스템 노트 및 댓글), 스니펫 및 사용자 프로필 활동이 가져와졌음을 나타냅니다.

{{< /history >}}

가져오기 결과를 검토하려면:

1. [그룹 가져오기 기록 페이지](#group-import-history)로 이동합니다.
1. 실패한 가져오기의 세부 정보를 보려면 **실패함** 또는 **부분적으로 완료됨** 상태의 가져오기에서 **오류 표시** 링크를 선택합니다.
1. 가져오기 상태가 **부분적으로 완료됨** 또는 **완료**인 경우 어떤 항목이 가져와졌고 어떤 항목이 가져와지지 않았는지 확인하려면 **상세 보기**를 선택합니다.

GitLab UI의 일부 항목에서 **가져옴** 배지를 보면 항목이 가져와졌음을 알 수 있습니다.

## 그룹 가져오기 기록 {#group-import-history}

직접 전송으로 마이그레이션한 모든 그룹을 그룹 가져오기 기록 페이지에 나열된 대로 볼 수 있습니다. 이 목록에는 다음이 포함됩니다:

- 소스 그룹의 경로입니다.
- 대상 그룹의 경로입니다.
- 각 가져오기의 시작 날짜입니다.
- 각 가져오기의 상태입니다.
- 오류가 발생한 경우 오류 세부 정보입니다.

그룹 가져오기 기록을 보려면:

1. GitLab에 로그인합니다.
1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 그룹**을 선택합니다.
1. **그룹 가져오기**를 선택합니다.
1. 오른쪽 위 모서리에서 **가져오기 기록 보기**를 선택합니다.
1. 특정 가져오기에 오류가 있는 경우 **오류 표시**를 선택하여 세부 정보를 확인합니다.

## 실행 중인 마이그레이션 취소 {#cancel-a-running-migration}

필요한 경우 REST API 또는 Rails 콘솔을 사용하여 실행 중인 마이그레이션을 취소할 수 있습니다.

### REST API로 취소 {#cancel-with-the-rest-api}

REST API로 실행 중인 마이그레이션을 취소하는 방법에 대한 정보는 [마이그레이션 취소](../../../api/bulk_imports.md#cancel-a-migration)를 참조합니다.

### Rails 콘솔로 취소 {#cancel-with-a-rails-console}

Rails 콘솔로 실행 중인 마이그레이션을 취소하려면:

1. 대상 GitLab 인스턴스에서 [Rails 콘솔 세션](../../../administration/operations/rails_console.md#starting-a-rails-console-session)을 시작합니다.
1. 다음 명령을 실행하여 마지막 가져오기를 찾습니다. `USER_ID`을 가져오기를 시작한 사용자의 사용자 ID로 바꿉니다:

   ```ruby
   bulk_import = BulkImport.where(user_id: USER_ID).last
   ```

1. 다음 명령을 실행하여 가져오기 및 관련된 모든 항목을 실패하도록 합니다:

   ```ruby
   bulk_import.entities.each do |entity|
     entity.trackers.each do |tracker|
       tracker.batches.each(&:fail_op!)
     end
     entity.trackers.each(&:fail_op!)
     entity.fail_op!
   end
   bulk_import.fail_op!
   ```

`bulk_import` 취소는 소스 인스턴스에서 프로젝트를 내보내는 작업자를 중지하지 않지만 대상 인스턴스가 다음을 수행하지 못하게 합니다:

- 소스 인스턴스에 더 많은 프로젝트를 내보내도록 요청합니다.
- 다양한 확인 및 정보를 위해 소스 인스턴스에 다른 API 호출을 만듭니다.

## 실패했거나 부분적으로 성공한 마이그레이션 재시도 {#retry-failed-or-partially-successful-migrations}

마이그레이션이 실패하거나 부분적으로 성공했지만 항목이 누락된 경우 마이그레이션을 다시 시도할 수 있습니다. 최상위 그룹 및 모든 서브그룹과 프로젝트의 마이그레이션을 재시도하거나 특정 서브그룹 또는 프로젝트를 재시도하려면 GitLab UI 또는 [직접 전송을 통한 그룹 및 프로젝트 마이그레이션 API](../../../api/bulk_imports.md)를 사용합니다.
