---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 기여도 및 멤버십 재할당
---

최상위 그룹의 Owner 역할을 가진 사용자는 플레이스홀더 사용자로부터 기여도 및 멤버십을 기존 활성 비봇 사용자에게 재할당할 수 있습니다. 대상 인스턴스에서 최상위 그룹의 Owner 역할을 가진 사용자는 다음을 수행할 수 있습니다:

- 기여도 및 멤버십 재할당에 대해 [UI에서](#request-reassignment-in-ui) 또는 [CSV 파일을 통해](#request-reassignment-by-using-a-csv-file) 검토하도록 사용자에게 요청합니다. 플레이스홀더 사용자의 수가 많은 경우 CSV 파일을 사용해야 합니다. 두 경우 모두 사용자는 재할당을 수락하거나 거부하도록 이메일로 요청을 받습니다. 선택한 사용자가 [재할당 요청을 수락](#accept-contribution-reassignment)한 후에만 재할당이 시작됩니다.
- 기여도 및 멤버십을 재할당하지 않고 [플레이스홀더 사용자에게 할당된 상태로 유지](#keep-as-placeholder)하도록 선택합니다.

GitLab Self-Managed 및 GitLab Dedicated에서 관리자는 기여도 및 멤버십을 활성 및 비활성 비봇 사용자에게 확인 없이 즉시 재할당할 수 있습니다. 자세한 내용은 [관리자가 플레이스홀더 사용자를 재할당할 때 확인 건너뛰기](../../../administration/settings/import_and_export_settings.md#skip-confirmation-when-administrators-reassign-placeholder-users)를 참조하세요. 기여도 및 멤버십을 관리자에게 재할당하려면 [관리자에게 기여도 매핑 허용](../../../administration/settings/import_and_export_settings.md#allow-contribution-mapping-to-administrators)을 참조하세요.

## 플레이스홀더 사용자를 재할당할 때 확인 건너뛰기 {#bypass-confirmation-when-reassigning-placeholder-users}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- GitLab.com에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/544024) GitLab 18.1에서 `group_owner_placeholder_confirmation_bypass` 기능 플래그를 사용합니다. 기본적으로 비활성화되었습니다.
- GitLab.com에서 [활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/548946) GitLab 18.4에서.
- GitLab.com에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/569771) GitLab 18.7에서. 기능 플래그 `group_owner_placeholder_confirmation_bypass`이 제거되었습니다.

{{< /history >}}

사전 요구 사항:

- 그룹의 Owner 역할이 있어야 합니다.

[엔터프라이즈 사용자](../../enterprise_user/_index.md)에 대한 확인을 건너뛰려면 플레이스홀더를 재할당할 때:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 수준에 있어야 합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **플레이스홀더 사용자 확인** 아래에서 **사용자 확인 없이 엔터프라이즈 사용자에게 플레이스홀더를 재할당합니다** 체크박스를 선택합니다.
1. **사용자 확인을 복원해야 할 때**에서 사용자 확인 건너뛰기의 종료 날짜를 선택합니다. 기본값은 1일입니다.
1. **변경 사항 저장**을 선택합니다.

### 여러 플레이스홀더 사용자로부터 기여도 재할당 {#reassigning-contributions-from-multiple-placeholder-users}

단일 플레이스홀더 사용자에게 초기에 할당된 모든 기여도를 대상 인스턴스의 단일 활성 일반 사용자, 서비스 계정, 프로젝트 봇 및 그룹 봇에게 재할당할 수 있습니다. 단일 플레이스홀더 사용자에게 할당된 기여도를 여러 사용자에게 나눌 수 없습니다.

플레이스홀더 사용자가 다음에서 오는 경우 여러 플레이스홀더 사용자의 기여도를 대상 인스턴스의 같은 사용자에게 재할당할 수 있습니다:

- 다른 소스 인스턴스
- 같은 소스 인스턴스이며 대상 인스턴스의 다른 최상위 그룹으로 가져옵니다

할당된 사용자가 재할당 요청을 수락하기 전에 비활성화되면 보류 중인 재할당은 사용자가 수락할 때까지 사용자에게 연결된 상태로 유지됩니다.

재할당 요청을 받은 사용자는 다음을 수행할 수 있습니다:

- [요청 수락](#accept-contribution-reassignment) 플레이스홀더 사용자에게 이전에 할당된 모든 기여도 및 멤버십은 수락한 사용자에게 다시 할당됩니다. 이 프로세스는 기여도 수에 따라 몇 분 정도 걸릴 수 있습니다.
- [요청 거부](#reject-contribution-reassignment) 또는 스팸으로 보고합니다. 이 옵션은 재할당 요청 이메일에서 사용 가능합니다.

서비스 계정, 프로젝트 봇 및 그룹 봇에게 기여도를 재할당하면 재할당 요청이 자동으로 승인됩니다.

같은 최상위 그룹으로의 후속 가져오기에서 같은 소스 사용자에 속하는 기여도 및 멤버십은 해당 소스 사용자에 대한 재할당을 이전에 수락한 사용자에게 자동으로 매핑됩니다.

GitLab Self-Managed 및 GitLab Dedicated에서 관리자는 기여도 및 멤버십을 활성 및 비활성 비봇 사용자에게 확인 없이 즉시 재할당할 수 있습니다. 자세한 내용은 [관리자가 플레이스홀더 사용자를 재할당할 때 확인 건너뛰기](../../../administration/settings/import_and_export_settings.md#skip-confirmation-when-administrators-reassign-placeholder-users)를 참조하세요. 기여도 및 멤버십을 관리자에게 재할당하려면 [관리자에게 기여도 매핑 허용](../../../administration/settings/import_and_export_settings.md#allow-contribution-mapping-to-administrators)을 참조하세요.

### 재할당 완료 {#completing-the-reassignment}

다음을 수행하기 전에 재할당 프로세스를 완전히 완료해야 합니다:

- [같은 GitLab 인스턴스에서 가져온 그룹 이동](../../group/manage.md#transfer-a-group)
- [가져온 프로젝트를 다른 그룹으로 이동](../../project/working_with_projects.md#transfer-a-project)
- 가져온 이슈를 복제합니다.
- 가져온 이슈를 에픽으로 승격합니다.

프로세스가 완료되지 않으면 플레이스홀더 사용자에게 할당된 기여도를 실제 사용자에게 재할당할 수 없으며 플레이스홀더 사용자와 연결된 상태로 유지됩니다.

### 보안 고려 사항 {#security-considerations}

기여도 및 멤버십 재할당은 실행 취소할 수 없으므로 시작하기 전에 모든 것을 신중하게 확인하세요.

기여도 및 멤버십을 잘못된 사용자에게 재할당하면 보안 위협이 됩니다. 왜냐하면 사용자가 그룹의 멤버가 되기 때문입니다. 따라서 보면 안 되는 정보를 볼 수 있습니다.

관리자 액세스 권한이 있는 사용자에게 기여도를 재할당하는 것은 기본적으로 비활성화되어 있지만 [활성화](../../../administration/settings/import_and_export_settings.md#allow-contribution-mapping-to-administrators)할 수 있습니다.

#### 멤버십 보안 고려 사항 {#membership-security-considerations}

GitLab 권한 모델 때문에 그룹 또는 프로젝트가 기존 상위 그룹으로 가져와지면 상위 그룹의 멤버는 가져온 그룹 또는 프로젝트의 [상속된 멤버십](../../project/members/_index.md#membership-types)을 받습니다.

가져온 그룹 또는 프로젝트의 기존 상속된 멤버십을 이미 가진 사용자를 기여도 및 멤버십 재할당에 대해 선택하면 멤버십이 재할당되는 방식에 영향을 미칠 수 있습니다.

GitLab은 자식 프로젝트 또는 그룹의 멤버십이 상속된 멤버십보다 낮은 역할을 갖는 것을 허용하지 않습니다. 할당된 사용자의 가져온 멤버십이 기존 상속된 멤버십보다 낮은 역할을 가지면 가져온 멤버십은 사용자에게 재할당되지 않습니다.

이로 인해 가져온 그룹 또는 프로젝트에 대한 멤버십이 소스보다 높아집니다.

### UI에서 재할당 요청 {#request-reassignment-in-ui}

사전 요구 사항:

- 그룹의 Owner 역할이 있어야 합니다.

최상위 그룹에서 기여도 및 멤버십을 재할당할 수 있습니다. 기여도 및 멤버십 재할당을 요청하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 수준에 있어야 합니다.
1. 왼쪽 sidebar에서 **관리** > **멤버**를 선택합니다.
1. **플레이스홀더** 탭을 선택합니다.
1. **재할당 대기 중** 하위 탭으로 이동하면 플레이스홀더가 테이블에 표시됩니다.
1. 각 플레이스홀더에 대해 테이블 열 **플레이스홀더 사용자** 및 **소스**에서 정보를 검토합니다.
1. **다음으로 플레이스홀더 재지정** 열에서 드롭다운 목록에서 사용자를 선택합니다.
1. **재할당**을 선택합니다.

한 명의 플레이스홀더 사용자의 기여도만 대상 인스턴스의 활성 비봇 사용자에게 재할당할 수 있습니다.

사용자가 재할당을 수락하기 전에 [요청을 취소](#cancel-reassignment-request)할 수 있습니다.

GitLab Self-Managed 및 GitLab Dedicated에서 관리자는 기여도 및 멤버십을 활성 및 비활성 비봇 사용자에게 확인 없이 즉시 재할당할 수 있습니다. 자세한 내용은 [관리자가 플레이스홀더 사용자를 재할당할 때 확인 건너뛰기](../../../administration/settings/import_and_export_settings.md#skip-confirmation-when-administrators-reassign-placeholder-users)를 참조하세요. 기여도 및 멤버십을 관리자에게 재할당하려면 [관리자에게 기여도 매핑 허용](../../../administration/settings/import_and_export_settings.md#allow-contribution-mapping-to-administrators)을 참조하세요.

### CSV 파일을 사용하여 재할당 요청 {#request-reassignment-by-using-a-csv-file}

{{< history >}}

- GitLab 17.10에서 `importer_user_mapping_reassignment_csv`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/455901)되었습니다. 기본적으로 활성화됩니다.
- GitLab 18.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/478022)하게 되었습니다. 기능 플래그 `importer_user_mapping_reassignment_csv`이 제거되었습니다.

{{< /history >}}

사전 요구 사항:

- 그룹의 Owner 역할이 있어야 합니다.

플레이스홀더 사용자가 많은 경우 CSV 파일을 사용하여 기여도 및 멤버십을 재할당할 수 있습니다. 다음 정보로 미리 작성된 CSV 템플릿을 다운로드할 수 있습니다. 예를 들어:

| 소스 호스트          | 가져오기 유형 | 소스 사용자 식별자 | 소스 사용자 이름 | 소스 사용자명 |
|----------------------|-------------|------------------------|------------------|-----------------|
| `gitlab.example.com` | `gitlab`    | `alice`                | `Alice Coder`    | `a.coder`       |

**소스 호스트**, **가져오기 유형** 또는 **소스 사용자 식별자**를 업데이트하지 마세요. 이 정보는 완료된 CSV 파일을 업로드한 후 해당 데이터베이스 레코드를 찾습니다. **소스 사용자 이름** 및 **소스 사용자명**은 소스 사용자를 식별하며 CSV 파일을 업로드한 후에는 사용되지 않습니다.

CSV 파일의 모든 행을 업데이트할 필요는 없습니다. **GitLab 사용자명** 또는 **GitLab 공개 이메일**이 있는 행만 처리됩니다. 다른 모든 행은 건너뜁니다.

CSV 파일을 사용하여 기여도 및 멤버십 재할당을 요청하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 sidebar에서 **관리** > **멤버**를 선택합니다.
1. **플레이스홀더** 탭을 선택합니다.
1. **CSV를 사용하여 재할당**을 선택합니다.
1. 미리 작성된 CSV 템플릿을 다운로드합니다.
1. **GitLab 사용자명** 또는 **GitLab 공개 이메일**에 대상 인스턴스의 GitLab 사용자의 사용자명 또는 공개 이메일 주소를 입력합니다. 인스턴스 관리자는 확인된 이메일 주소가 있는 사용자를 재할당할 수 있습니다.
1. 완료된 CSV 파일을 업로드합니다.
1. **재할당**을 선택합니다.

각 활성 비봇 사용자에게 단일 플레이스홀더 사용자의 기여도만 할당할 수 있습니다. 사용자는 [재할당한 기여도를 검토하고 수락](#accept-contribution-reassignment)하도록 이메일을 받습니다. 사용자가 검토하기 전에 [재할당 요청을 취소](#cancel-reassignment-request)할 수 있습니다.

GitLab Self-Managed 및 GitLab Dedicated에서 관리자는 기여도 및 멤버십을 활성 및 비활성 비봇 사용자에게 확인 없이 즉시 재할당할 수 있습니다. 자세한 내용은 [관리자가 플레이스홀더 사용자를 재할당할 때 확인 건너뛰기](../../../administration/settings/import_and_export_settings.md#skip-confirmation-when-administrators-reassign-placeholder-users)를 참조하세요. 기여도 및 멤버십을 관리자에게 재할당하려면 [관리자에게 기여도 매핑 허용](../../../administration/settings/import_and_export_settings.md#allow-contribution-mapping-to-administrators)을 참조하세요.

기여도를 재할당한 후 GitLab은 다음 항목 개수를 포함하는 이메일을 보냅니다:

- 성공적으로 처리된 행
- 처리되지 않은 행
- 건너뛴 행

행이 성공적으로 처리되지 않으면 이메일에는 더 자세한 결과가 있는 CSV 파일이 있습니다.

UI를 사용하지 않고 플레이스홀더 사용자를 대량으로 재할당하려면 [그룹 플레이스홀더 재할당 API](../../../api/group_placeholder_reassignments.md)를 참조하세요.

### 플레이스홀더로 유지 {#keep-as-placeholder}

{{< history >}}

- GitLab 18.5에서 [변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/535431), 작업을 실행 취소할 수 있습니다.

{{< /history >}}

대상 인스턴스의 사용자에게 기여도 및 멤버십을 재할당하지 않을 수도 있습니다. 예를 들어 소스 인스턴스에 기여한 전 직원이 있을 수 있지만 대상 인스턴스에는 사용자로 존재하지 않습니다.

이 경우 플레이스홀더 사용자에게 할당된 기여도를 유지할 수 있습니다. 플레이스홀더 사용자는 멤버십 정보를 유지하지 않습니다. 왜냐하면 [프로젝트 또는 그룹의 멤버가 될 수 없기 때문](post_migration_mapping.md#placeholder-user-attributes)입니다.

플레이스홀더 사용자의 이름과 사용자명이 소스 사용자의 이름과 사용자명과 유사하므로 많은 과거 정보를 유지할 수 있습니다.

플레이스홀더 사용자에게 할당된 기여도를 한 번에 하나씩 또는 대량으로 유지할 수 있습니다. 대량으로 기여도를 재할당하면 전체 네임스페이스 및 다음 [재할당 상태](#view-and-filter-by-reassignment-status)를 가진 사용자가 영향을 받습니다:

- `Not started`
- `Rejected`

플레이스홀더 사용자를 한 번에 하나씩 유지하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 수준에 있어야 합니다.
1. 왼쪽 sidebar에서 **관리** > **멤버**를 선택합니다.
1. **플레이스홀더** 탭을 선택합니다.
1. **재할당 대기 중** 하위 탭으로 이동하면 플레이스홀더가 테이블에 표시됩니다.
1. **플레이스홀더 사용자** 및 **소스** 열을 검토하여 유지하려는 플레이스홀더 사용자를 찾습니다.
1. **다음으로 플레이스홀더 재지정** 열에서 **재할당 안 함**을 선택합니다.
1. **확인**을 선택합니다.

플레이스홀더 사용자를 대량으로 유지하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 수준에 있어야 합니다.
1. 왼쪽 sidebar에서 **관리** > **멤버**를 선택합니다.
1. **플레이스홀더** 탭을 선택합니다.
1. 목록 위에서 세로 줄임표({{< icon name="ellipsis_v" >}}) > **모두 플레이스홀더로 유지**를 선택합니다.
1. 확인 대화에서 **확인**을 선택합니다.

작업을 실행 취소하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 수준에 있어야 합니다.
1. 왼쪽 sidebar에서 **관리** > **멤버**를 선택합니다.
1. **플레이스홀더** 탭을 선택합니다.
1. **재할당됨** 하위 탭으로 이동하면 플레이스홀더가 테이블에 표시됩니다.
1. 올바른 행에서 **취소**를 선택합니다.

### 재할당 요청 취소 {#cancel-reassignment-request}

사용자가 재할당 요청을 수락하기 전에 요청을 취소할 수 있습니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 수준에 있어야 합니다.
1. 왼쪽 sidebar에서 **관리** > **멤버**를 선택합니다.
1. **플레이스홀더** 탭을 선택합니다.
1. **재할당 대기 중** 하위 탭으로 이동하면 플레이스홀더가 테이블에 표시됩니다.
1. 올바른 행에서 **취소**를 선택합니다.

### 보류 중인 재할당 요청에 대해 사용자에게 다시 알림 {#notify-user-again-about-pending-reassignment-requests}

사용자가 재할당 요청에 작동하지 않으면 다른 이메일을 보내 다시 알림을 전송할 수 있습니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 수준에 있어야 합니다.
1. 왼쪽 sidebar에서 **관리** > **멤버**를 선택합니다.
1. **플레이스홀더** 탭을 선택합니다.
1. **재할당 대기 중** 하위 탭으로 이동하면 플레이스홀더가 테이블에 표시됩니다.
1. 올바른 행에서 **알림**을 선택합니다.

### 재할당 상태로 보기 및 필터링 {#view-and-filter-by-reassignment-status}

모든 플레이스홀더 사용자의 재할당 상태를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 수준에 있어야 합니다.
1. 왼쪽 sidebar에서 **관리** > **멤버**를 선택합니다.
1. **플레이스홀더** 탭을 선택합니다.
1. **재할당 대기 중** 하위 탭으로 이동하면 플레이스홀더가 테이블에 표시됩니다.
1. **재할당 상태** 열에서 각 플레이스홀더 사용자의 상태를 확인합니다.

**재할당 대기 중** 탭에서 가능한 상태는:

- `Not started` - 재할당이 시작되지 않았습니다.
- `Pending approval` - 재할당이 사용자 승인 대기 중입니다.
- `Reassigning` - 재할당이 진행 중입니다.
- `Rejected` - 재할당이 사용자에 의해 거부되었습니다.
- `Failed` - 재할당이 실패했습니다.

**재할당됨** 탭에서 가능한 상태는:

- `Success` - 재할당이 성공했습니다.
- `Kept as placeholder` - 플레이스홀더 사용자가 영구적으로 만들어졌습니다.

기본적으로 테이블은 플레이스홀더 사용자 이름으로 사전순으로 정렬됩니다. 재할당 상태별로 테이블을 정렬할 수도 있습니다.

## 기여도 재할당 확인 {#confirm-contribution-reassignment}

[**관리자가 플레이스홀더 사용자를 재할당할 때 확인 건너뛰기**](../../../administration/settings/import_and_export_settings.md#skip-confirmation-when-administrators-reassign-placeholder-users)가 활성화된 경우:

- 관리자는 사용자 확인 없이 기여도를 즉시 재할당할 수 있습니다.
- 관리자는 활성 및 비활성 비봇 사용자에게 기여도를 재할당할 수 있습니다.
- 기여도가 재할당되었음을 알려주는 이메일을 받습니다.

이 설정이 활성화되지 않으면 재할당을 [수락](#accept-contribution-reassignment)하거나 [거부](#reject-contribution-reassignment)할 수 있습니다.

### 기여도 재할당 수락 {#accept-contribution-reassignment}

가져오기 프로세스가 진행되었으며 본인에게 기여도 재할당을 확인하도록 요청하는 이메일을 받을 수 있습니다.

이 가져오기 프로세스에 대해 알고 있었다면 재할당 세부 정보를 여전히 매우 신중하게 검토해야 합니다. 이메일에 나열된 세부 정보는:

- **가져온 위치** \- 가져온 내용이 출처하는 플랫폼입니다. 예를 들어 GitLab의 다른 인스턴스, GitHub 또는 Bitbucket입니다.
- **원본 사용자** \- 소스 플랫폼의 사용자 이름과 사용자명입니다. 해당 플랫폼의 본인 이름과 사용자명일 수 있습니다.
- **가져온 대상** \- 새 플랫폼의 이름으로 GitLab 인스턴스만 가능합니다.
- **재할당 대상** \- GitLab 인스턴스의 전체 이름과 사용자명입니다.
- **재할당 수행자** \- 가져오기를 수행한 동료 또는 관리자의 전체 이름과 사용자명입니다.

### 기여도 재할당 거부 {#reject-contribution-reassignment}

본인에게 기여도 재할당을 확인하도록 요청하는 이메일을 받았는데 이 정보를 인식하지 못하거나 오류를 발견한 경우:

1. 전혀 진행하지 않거나 기여도 재할당을 거부합니다.
1. 신뢰할 수 있는 동료 또는 관리자와 대화합니다.

### 보안 고려 사항 {#security-considerations-1}

모든 재할당 요청의 재할당 세부 정보를 매우 신중하게 검토해야 합니다. 신뢰할 수 있는 동료 또는 관리자에게 이 프로세스에 대해 이미 알지 못한 경우 각별히 주의하세요.

의심이 있는 모든 재할당을 수락하는 대신:

1. 이메일에 조치하지 마세요.
1. 신뢰할 수 있는 동료 또는 관리자와 대화합니다.

알고 있고 신뢰하는 사용자로부터만 재할당을 수락하세요. 기여도의 재할당은 영구적이며 실행 취소할 수 없습니다. 재할당을 수락하면 기여도가 부정확하게 본인에게 할당될 수 있습니다.

기여도 재할당 프로세스는 GitLab에서 **재할당 승인**을 선택하여 재할당 요청을 수락한 후에만 시작됩니다. 이 프로세스는 이메일의 링크를 선택하여 시작되지 않습니다.
