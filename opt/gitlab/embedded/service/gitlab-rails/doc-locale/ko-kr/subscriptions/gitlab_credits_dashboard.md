---
stage: Fulfillment
group: Utilization
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 크레딧 사용량을 확인하고 관리합니다.
title: GitLab Credits 대시보드
---

{{< details >}}

- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.7에서 도입되었습니다.
- 결과 정렬 기능은 GitLab 18.10에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21008)되었습니다.

{{< /history >}}

GitLab Credits 대시보드는 GitLab Credits 사용량에 대한 정보를 표시합니다. 대시보드를 사용하여 크레딧 소비를 모니터링하고 추세를 추적하며 사용 패턴을 파악하세요.

크레딧 소비를 관리하는 데 도움이 되도록 GitLab은 청구 계정에 연결된 Customers Portal 사용자에게 다음 정보를 이메일로 보냅니다:

- 월간 크레딧 사용량 요약
- 크레딧 사용량이 임계값의 50%, 80%, 100%에 도달했을 때에 알림

고객 포털 및 GitLab에서 대시보드에 액세스할 수 있습니다. GitLab Dedicated에서는 대시보드가 Customers Portal과 인스턴스 관리자에게 제공됩니다. 그룹 수준 및 개인 크레딧 사용량 보기는 GitLab.com에서만 제공됩니다.

> [!note]
> 사용량 데이터는 실시간으로 표시되지 않습니다. 데이터는 주기적으로 대시보드와 동기화되므로, 사용량 데이터는 실제 소비 후 몇 시간 이내에 표시됩니다. 즉, 대시보드에 최근 사용량이 표시되지만 지난 몇 시간 동안 수행된 작업은 반영되지 않을 수 있습니다.

## 고객 포털에서 {#in-customers-portal}

고객 포털의 GitLab Credits 대시보드는 사용량 및 비용에 대한 가장 자세한 정보를 제공합니다.

대시보드에서 '사용한 크레딧'은 사용 가능한 크레딧에서 차감된 수치를 나타냅니다. 초과 사용량(온디맨드 크레딧)의 경우 사용된 크레딧은 사용 청구 약관에 동의한 경우 나중에 지불할 온디맨드 사용량을 나타냅니다.

대시보드에는 주요 지표의 요약 카드가 표시됩니다.

- 이번 달 사용량: 이번 달에 사용된 총 GitLab Credits (월간 약정이 있는 경우)
- 포함된 크레딧: 구독에 포함된 총 크레딧 (월간 약정이 있는 경우)
- 약정된 크레딧: 월별 약정 풀의 크레딧(해당하는 경우)
- 월간 면제: 면제 혜택 중 남은 크레딧 (해당하는 경우)
- 온디맨드 사용량: 포함된 크레딧 및 약정된 금액을 초과하여 소비된 크레딧입니다. 온디맨드 크레딧 전액을 상쇄할 만큼 충분한 면제 크레딧이 있는 경우 GitLab Credits 대시보드는 **온디맨드** 카드를 숨기고 대신 **월별 면제** 카드를 표시합니다.
- 사용 제어 상태: 사용자별 크레딧 상한에 도달하여 개별 사용자의 Agent Platform 액세스가 차단되었는지 여부입니다.

## GitLab에서 {#in-gitlab}

{{< history >}}

- GitLab 19.1에서 Secrets Manager 사용량을 도입했습니다.

{{< /history >}}

> [!note]
> 보안 리뷰 플로우와 같은 일부 사전 출시 기능은 청구 가능하며 GitLab Credits 요금의 대상입니다.

GitLab 내의 GitLab Credits 대시보드는 조직의 크레딧 사용에 대한 운영 가시성을 제공합니다. 대시보드를 사용하여 어떤 사용자, 그룹 또는 프로젝트가 사용량을 발생시키는지 파악하고 리소스 할당에 대해 합리적 의사결정을 내리세요.

대시보드에는 다음 정보가 표시됩니다.

- **조직 사용량**:  총 크레딧 사용량(청구 및 비청구), 활성 사용자, 일일 크레딧 평균, GitLab 인스턴스 또는 그룹 전체의 일일 사용량 피크
- **총 크레딧 사용량**: 모든 제품에 대한 일일 청구 및 비청구 크레딧 사용량으로 누적 막대 차트로 표시됩니다.
- **사용자별 사용량**: 각 사용자별 사용 크레딧 수
- **사용자 드릴다운 보기**:  각 사용자별 개별 사용량 이벤트(각 크레딧 기반 기능의 세션 상세 정보로 연결)
- **제품별 사용량**: 크레딧 기반 기능에 사용된 크레딧 수 및 총 크레딧의 백분율

> [!note]
> [GitLab Secrets Manager](../ci/secrets/secrets_manager/_index.md)가 베타 버전인 동안 GitLab에서는 사용에 대한 요금을 청구하지 않습니다. Secrets Manager는 크레딧 대시보드에 표시되지만 베타 기간이 끝날 때까지 사용 데이터를 표시하지 않습니다.

### 비청구 사용량 {#non-billable-usage}

{{< history >}}

- GitLab 19.5에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/23876)되었습니다.

{{< /history >}}

비청구 사용량은 GitLab이 청구하지 않는 크레딧 소비입니다. **총 크레딧 사용량** 차트는 다음을 표시합니다:

- **청구 가능**: 사용된 청구 가능한 크레딧 수
- **비청구**: 사용된 비청구 크레딧 수로 선택한 기간에 비청구 사용량이 포함되는 경우에만 표시됩니다.
- **누적 막대**: **청구 사용량** 및 **비청구 사용량** 이유를 별개 계열로 하여 사용된 일일 크레딧

차트는 다음과 같은 비청구 사용량 계열을 표시합니다:

| 계열 | 설명 |
|--------|-------------|
| **비청구 사용량(홍보)** | 프로모션으로 보장되는 사용량입니다. |
| **비청구 사용량(베타)** | 아직 청구 가능하지 않은 기능의 사용량입니다. |
| **비청구 사용량(기타)** | 다른 이유로 청구되지 않은 사용량입니다. |

차트는 선택한 기간의 사용량 이유만 표시합니다. 비청구 사용량 데이터를 일시적으로 사용할 수 없는 경우 차트는 청구 가능한 사용량만 표시합니다.

## GitLab Credits 대시보드 보기 {#view-the-gitlab-credits-dashboard}

{{< history >}}

- 과거 사용 기간 선택 기능은 GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/customers-gitlab-com/-/work_items/15910)되었습니다.

{{< /history >}}

{{< tabs >}}

{{< tab title="고객 포털" >}}

전제 조건:

- 상세 사용량 정보를 보려면 청구 계정 관리자여야 합니다.

1. [고객 포털](https://customers.gitlab.com/)에 로그인합니다.
1. 구독 카드에서 **GitLab Credits 대시보드**를 선택합니다.
1. 선택사항. 이전 월의 사용량을 보려면 **사용량 기간** 드롭다운 목록에서 원하는 기간을 선택합니다.
1. 선택사항. **사용자** 또는 **총 사용한 크레딧** 열을 선택하여 결과를 정렬합니다.

{{< /tab >}}

{{< tab title="GitLab.com" >}}

전제 조건:

- 그룹에 대한 소유자 역할이 있어야 합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. **설정** > **GitLab Credits**를 선택합니다.
1. 선택사항. **사용자** 또는 **총 사용한 크레딧** 열을 선택하여 결과를 정렬합니다.

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

전제 조건:

- 관리자여야 합니다.
- 인스턴스가 GitLab과 구독 데이터를 동기화할 수 있어야 합니다.

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Credits**를 선택합니다.
1. 선택사항. **사용자** 또는 **총 사용한 크레딧** 열을 선택하여 결과를 정렬합니다.

{{< /tab >}}

{{< /tabs >}}

기본적으로 개별 사용자 데이터는 GitLab Credits 대시보드에 표시되지 않습니다. 데이터를 표시하려면 [그룹](../user/group/manage.md#display-gitlab-credits-user-data) 또는 [인스턴스](../administration/settings/visibility_and_access_controls.md#display-gitlab-credits-user-data)에 대해 이 설정을 사용해야 합니다.

## 사람이 아닌 주체의 사용량 {#non-human-subject-usage}

{{< history >}}

- GitLab 19.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/596238)되었습니다.

{{< /history >}}

크레딧 소비는 실제 사용자 또는 사람이 아닌 주체(예: SAST False Positive Detection 플로우와 같은 AI 기능)에 의해 트리거될 수 있습니다.

크레딧 소진 위치를 파악하는 데 도움이 되도록, GitLab Credits 대시보드의 **사용자별 사용량** 탭에는 사람이 아닌 주체를 나타내는 행 옆에 **자동화된 플로우** 배지가 표시됩니다. 배지가 없는 행은 실제 사용자를 나타냅니다.

**자동화된 플로우** 배지의 표시는 **GitLab Credits 사용자 데이터 표시** 설정에 의해 제어되며, [그룹](../user/group/manage.md#display-gitlab-credits-user-data) 및 [인스턴스](../administration/settings/visibility_and_access_controls.md#display-gitlab-credits-user-data)에서 사용할 수 있습니다.

## 사용량 상한 {#usage-caps}

{{< history >}}

- `budget_caps_graphql_api`라는 이름의 [기능 플래그로](../administration/feature_flags/_index.md) GitLab 18.11에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/19881)되었습니다. 기본적으로 사용으로 설정됩니다.
- GitLab 19.3에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/work_items/607551)되었습니다. 기능 플래그 `budget_caps_graphql_api`이 제거되었습니다.

{{< /history >}}

예상치 못한 초과 요금을 방지하기 위해 구독 및 사용자 수준에서 월간 GitLab Credits 상한을 설정할 수 있습니다. 크레딧 소비가 구성된 한도에 도달하면 다음 청구 기간이 시작될 때까지 또는 관리자가 한도를 조정하거나 비활성화할 때까지 크레딧 기반 기능에 대한 액세스가 자동으로 일시 중단됩니다.

다음 상한 유형을 사용할 수 있습니다.

| 상한 유형 | 적용 대상 | 합산되는 크레딧 소스 | 관리 수단 |
|---|---|---|---|
| 구독 상한 | 구독의 모든 사용자 | 온디맨드만 | 고객 포털 |
| 정액 사용자 상한 | 개별 사용자(기본 제한) | 인간 주체 사용량에 대한 모두 | 사용자 인터페이스, GraphQL API |
| 사용자별 재정의 | 포함된 크레딧을 포함한 특정 사용자의 총 사용량입니다. 정액 상한을 무시합니다. 따라서 사용자는 포함된 할당량 또는 상한 중 더 높은 양까지 소비할 수 있습니다. | 인간 주체 사용량에 대한 모두 | 사용자 인터페이스, GraphQL API |

현재 청구 기간의 온디맨드 사용량이 구성된 한도에 도달하거나 초과하면 해당 구독 또는 인스턴스의 모든 사용자에 대해 모든 크레딧 기반 기능이 일시 중단되고 GitLab은 청구 계정 관리자에게 이메일 알림을 보냅니다. 사용자 수준 상한의 경우, 상한에 도달한 개별 사용자만 이용이 중단됩니다.

정액 사용자 상한과 사용자별 재정의 상한은 사용자의 포함된 할당량 초과 사용량에 적용됩니다. 사용자는 여전히 포함된 크레딧을 보유하지만 사용량이 상한에 도달한 후에도 계속 포함된 크레딧을 소비할 수 있습니다. 상한은 사용자의 포함된 크레딧이 소진된 후에만 적용됩니다.

상한에 도달한 사용자는 상한이 상향 조정되거나 다음 청구 기간이 시작될 때까지 Agent Platform 기능에 액세스할 수 없습니다.

사용량 카운터는 각 청구 기간이 시작될 때 자동으로 초기화됩니다. 상한 값은 변경되지 않는 한 청구 기간이 바뀌어도 계속 유지됩니다.

상한은 사용 가능한 최신 사용량 데이터를 기준으로 적용됩니다. 데이터가 실시간으로 반영되지 않으므로, 제한 조치가 발효되기 전에 약간의 추가 GitLab Credits 사용이 발생할 수 있습니다.

상한은 사용자가 포함된 GitLab Credits를 소비하는 것을 방지하지 않습니다. 적용은 사용자별로 시작되며 해당 사용자의 포함된 할당량이 소진된 후에만 시작됩니다. 이 시점까지는 `0`의 상한을 포함하여 상한 값에 관계없이 사용자는 전체 GitLab Duo Agent Platform 액세스 권한을 유지합니다.

포함된 잔액에 관계없이 모든 GitLab Credits 소비를 즉시 중지하려면 [영향을 받는 사용자로부터 GitLab Duo 사용자 제거](subscription-add-ons.md#assign-and-remove-gitlab-duo-seats-in-bulk)하거나 네임스페이스에 대해 [GitLab Duo 끄기](../user/gitlab_duo/turn_on_off.md#turn-gitlab-duo-on-or-off)를 수행합니다. 사용자 제거 및 재할당을 자동화하려면 [`userAddOnAssignmentRemove`](../api/graphql/reference/_index.md#mutationuseraddonassignmentremove) 및 [`userAddOnAssignmentCreate`](../api/graphql/reference/_index.md#mutationuseraddonassignmentcreate) GraphQL 변형을 사용합니다.

상한 값이 적용되는 방식은 상한 유형에 따라 다릅니다.

- **구독 수준 상한**은 온디맨드 사용량에만 적용됩니다. 상한은 구독 전체에서 온디맨드 사용량에 대해 모든 사용자의 포함된 크레딧 위에 허용되는 양입니다.
- **사용자별 한도**는 사용자가 직접 트리거한 사용량을 포함하여 사용자의 포함된 크레딧을 포함한 총 사용량에 적용됩니다. 따라서 사용자는 포함된 할당량 또는 상한 중 더 높은 양까지 소비할 수 있습니다.

> [!note]
> 서비스 계정에서 실행되는 [GitLab Duo Agent Platform 플로우](../user/duo_agent_platform/_index.md)의 사용량은 사용자가 아닌 네임스페이스에 청구되며 사용자의 정액 한도 또는 사용자별 오버라이드에 계산되지 않습니다. 이 사용량은 여전히 사용자의 **사용된 총 크레딧**에 나타날 수 있으므로 표시된 사용량이 한도를 초과할 수 있지만 사용자가 차단되지는 않습니다. 이 사용량을 제한하려면 구독 수준 한도를 설정하거나 사용자의 GitLab Duo 사용자를 제거합니다.

GitLab Duo Agent Platform을 사용할 수 있는 사용자를 제어하려면 그룹 멤버십을 기준으로 [GitLab Duo에 대한 액세스 제한](../administration/gitlab_duo/configure/access_control.md#restrict-access-to-gitlab-duo)합니다. 액세스 제어는 기능 액세스를 변경하고 크레딧 사용을 변경하지 않으며 그룹 수준 크레딧 한도를 설정하지 않습니다.

### 예제 {#examples}

구독 수준 상한의 경우 각각 100개의 포함된 GitLab Credits가 있는 10명의 사용자가 있는 구독을 고려하세요. 청구 계정 관리자가 구독 수준 온디맨드 상한을 `0`(으)로 설정합니다.

- 포함된 크레딧 100개를 모두 사용한 사용자는 추가 사용량이 온디맨드가 되기 때문에 즉시(다음 적용 검사 시) Agent Platform 기능에서 차단됩니다.
- 포함된 크레딧 중 40개만 사용한 사용자는 계속해서 Agent Platform 기능을 사용할 수 있으며 남은 포함된 크레딧 60개를 소비할 수 있습니다. `0` 상한은 아직 이들에게 적용되지 않습니다.

사용자별 상한의 경우 24개의 포함된 GitLab Credits를 보유한 사용자를 고려하세요.

- 사용자별 상한 `50`의 경우 사용자는 포함된 할당량 26개 크레딧을 넘어 총 50개의 크레딧 후에 차단됩니다.
- 사용자별 상한 `10`의 경우 사용자는 포함된 할당량이 소진될 때 즉 24개의 크레딧 후에 차단됩니다.

### 구독 수준 사용 상한 설정 {#set-a-subscription-level-usage-cap}

전제 조건:

- 청구 계정 관리자여야 합니다.

1. [고객 포털](https://customers.gitlab.com/)에 로그인합니다.
1. 구독 카드에서 **GitLab Credits 대시보드**를 선택합니다.
1. **사용 제어**를 선택합니다.
1. **온디맨드 크레딧 상항** 패널에서 **온디맨드 크레딧 상한 설정** 토글을 켭니다.
1. 청구 기간당 허용되는 최대 온디맨드 GitLab Credits 수량을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

현재 청구 기간에 대해 이미 보고된 총 온디맨드 사용량보다 낮게 상한을 설정하면, 다음 적용 여부 확인 시 즉시 상한에 도달한 것으로 간주됩니다.

상한을 사용 중지하려면 **온디맨드 크레딧 상한 설정** 토글을 끕니다. 사용 중지하면 구독 수준의 온디맨드 GitLab Credits 상한이 적용되지 않으며, 동작 방식은 기존의 청구 방식으로 되돌아갑니다.

GraphQL API를 사용하여 [사용 상한을 확인](../api/graphql/reference/_index.md#gitlabsubscriptionbudgetcaps)하거나 [정액 사용자 수준 상항](../api/graphql/reference/_index.md#mutationupsertflatusercap) 또는 [사용자별 재정의 상한](../api/graphql/reference/_index.md#mutationupsertuserbudgetcapoverrides)을 설정할 수 있습니다.

### 크레딧 한도 관리 {#manage-credit-caps}

{{< history >}}

- GitLab 19.4에서 `credit_caps_ui` [기능 플래그](../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/628559)되었습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

크레딧 한도를 관리하려면:

{{< tabs >}}

{{< tab title="GitLab.com" >}}

전제 조건:

- 그룹의 Owner 역할.

1. 상단 바에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. **설정** > **GitLab Credits**를 선택합니다.
1. **크레딧 한도**를 선택합니다.

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Credits**를 선택합니다.
1. **크레딧 한도**를 선택합니다.

{{< /tab >}}

{{< /tabs >}}

**크레딧 한도** 페이지에서 다음을 설정할 수 있습니다:

- **정액 사용자 한도**: 구독의 모든 사용자에 대한 기본 크레딧 한도입니다.
- **사용자별 한도 오버라이드**: 정액 사용자 한도를 오버라이드하는 개별 사용자의 특정 한도입니다.

#### 정액 사용자 한도 설정 {#set-a-flat-user-cap}

기본적으로 모든 사용자에게 적용되는 정액 사용자 한도를 설정하려면:

1. 사용자가 청구 기간당 소비할 수 있는 최대 GitLab Credits 수를 입력합니다.
1. 토글을 켜서 적용을 활성화합니다.
1. **저장**을 선택합니다.

#### 사용자별 한도 오버라이드 설정 {#set-per-user-cap-overrides}

개별 사용자의 한도 오버라이드를 추가, 업데이트 및 해제할 수 있습니다.

오버라이드를 추가하려면:

1. **오버라이드 추가**를 선택합니다.
1. 한 명 이상의 사용자를 선택합니다.
1. 한도 값을 설정하고 **활성화** 토글을 켜거나 끕니다.
1. **저장**을 선택합니다.

오버라이드를 업데이트하려면:

1. **사용자별 한도 오버라이드** 아래에서 사용자의 한도 값을 조정하고 **활성화** 토글을 켜거나 끕니다.
1. **저장**을 선택합니다.

오버라이드를 해제하려면:

1. **사용자별 한도 오버라이드** 아래에서 사용자의 **활성화** 토글을 끕니다.
1. **저장**을 선택합니다.

#### 오버라이드 대량 업데이트 {#bulk-update-overrides}

{{< history >}}

- [GitLab 19.5에 도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257651) [기능 플래그](../administration/feature_flags/_index.md) `credit_caps_bulk_update`을(를) 사용하여. 기본적으로 사용으로 설정됩니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

대량 업데이트를 사용하여 한 번에 많은 사용자의 오버라이드를 추가하거나 변경합니다.

기존 오버라이드 목록에 병합되는 CSV 사용자 목록을 붙여넣어 새 레코드를 추가하거나 기존 레코드를 업데이트할 수 있습니다.

입력은 쉼표로 구분된 세 개의 열을 허용합니다:

| 열 | 형식 | 허용되는 값 |
|--------|------|-----------------|
| `username` | 문자열 | `@` 접두사 없는 GitLab 사용자 이름(예: `jsmith`, `@jsmith` 아님) |
| `cap` | 숫자 | 음수가 아닌 숫자입니다. 소수 값에 대해 `.`을(를) 소수점 구분 기호로 사용합니다(예: `0`, `500`, `1000.5`). |
| `enabled` | 부울 | `true`, `True`, `TRUE`, `false`, `False`, `FALSE` |

첫 번째 줄에 선택적 헤더 행을 추가할 수 있습니다. 헤더 행은 `username,cap,enabled`이어야 하며 대소문자를 구분하지 않습니다. 검증이 실패하거나 사용자 이름을 찾을 수 없으면 전체 업데이트가 거부되고 변경 사항이 저장되지 않습니다.

헤더 행이 있는 예:

```plaintext
username,cap,enabled
sidney.jones,500,true
zhang.wei,1000.5,True
alex.garcia,250,false
```

헤더 행이 없는 예:

```plaintext
sidney.jones,500,true
zhang.wei,1000.5,True
alex.garcia,250,false
```

사용자별 한도 오버라이드를 대량 업데이트하려면:

1. **사용자별 한도 오버라이드** 아래에서 **대량 업데이트**를 선택합니다.
1. 모달에서 CSV 목록을 붙여넣습니다.
1. **저장**을 선택합니다.

## 사용 제어 상태 {#usage-control-status}

{{< history >}}

- GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/594635)되었습니다.

{{< /history >}}

사용자별 크레딧 상한이 사용으로 설정되면, GitLab Credits 대시보드의 **사용자별 사용량** 탭에 **사용량 제어 상태** 열이 표시됩니다. 이 열은 각 사용자가 크레딧 기반 기능에 액세스할 수 있는지 또는 크레딧 한도에 도달하여 차단되었는지를 보여줍니다.

**사용량 컨트롤 상태** 열은 GitLab이 사용자에게 한도를 적용할 때만 **차단된 사용량** 상태를 표시합니다. GitLab은 사용자의 포함된 크레딧이 소진된 후에 상한을 적용합니다. 한도에 도달했지만 포함된 크레딧이 여전히 있는 사용자는 포함된 크레딧을 계속 사용할 수 있으므로 **보통 사용량** 상태입니다.

이 열에는 다음 상태 중 하나가 표시됩니다.

| 상태 | 설명 |
|--------|-------------|
| **보통 사용량** | 사용자가 크레딧 상한에 도달하지 않았거나 상한에 도달했지만 여전히 포함된 크레딧이 있으며 GitLab Duo Agent Platform 기능을 사용할 수 있습니다. |
| **차단된 사용량** | 사용자가 포함된 크레딧을 소진하고 사용자별 한도에 도달했습니다. 한도는 구독의 모든 사용자에 대해 설정된 정액 사용자 한도이거나 특정 사용자를 위해 설정된 사용자별 오버라이드 한도입니다. |

대시보드는 어느 유형의 한도가 사용자를 차단했는지 표시하지 않습니다. 한도 유형을 확인하려면 [GraphQL API](../api/graphql/reference/_index.md#gitlabsubscriptionusageblockedstatus)를 사용합니다.

**사용량 컨트롤 상태** 열은 사용자별 한도만 표시합니다. 구독 수준 온디맨드 한도는 전체 구독에 적용되며 개별 사용자에게는 적용되지 않으며 이 열에 나열되지 않습니다.

상태는 사용자가 직접 트리거한 사용량만 반영합니다. **자동 플로우** 배지가 있는 행은 비인간 주체를 나타내며 사용자별 한도가 적용되지 않으므로 **차단된 사용량**을 표시하지 않습니다.

### 크레딧 상한에 도달한 사용자 차단 해제 {#unblock-a-user-who-reached-their-credit-cap}

사용자별 재정의 GraphQL API를 사용하여 차단된 사용자의 액세스 권한을 복원할 수 있습니다.

사용자의 차단을 해제하려면 다음 중 하나를 수행합니다.

- 상한 늘리기: 사용자의 사용량이 새로운 제한치 미만이 되도록 더 높은 사용자별 재정의 상한을 설정합니다.
- 상한 제거:  사용자별 재정의 설정을 삭제하여 해당 사용자가 더 이상 개별 상한의 적용을 받지 않도록 합니다.

한도를 업데이트한 후 사용자의 상태가 **보통 사용량**으로 변경되고 크레딧 기반 기능을 다시 사용할 수 있습니다.

## 사용자 크레딧 사용량 상세 정보 보기 {#view-user-credit-usage-details}

{{< history >}}

- GitLab Duo Agent Platform 세션 상세 정보 링크 기능은 GitLab 18.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/579139)되었습니다.

{{< /history >}}

드릴다운 보기에서 사용자의 개별 사용 이벤트를 확인하려면 다음을 수행합니다.

1. GitLab Credits 대시보드에서 **사용자별 사용량** 탭을 선택합니다.
1. **사용자** 열에서 확인하려는 사용자를 선택합니다.
1. 세션 상세 정보를 확인하려면 **작업** 열에서 확인하려는 작업을 선택합니다.

> [!note]
> 세션 링크는 프로젝트에서 발생하고 세션 ID가 연결된 GitLab Duo Agent Platform 사용 이벤트에 대해서만 제공됩니다. 그룹에서 발생한 사용 이벤트, 레거시 이벤트 및 Agent Platform 외부 작업에는 링크가 제공되지 않습니다.

## 사용량 데이터 내보내기 {#export-usage-data}

{{< history >}}

- GitLab 18.10에서 [도입](https://gitlab.com/gitlab-org/customers-gitlab-com/-/work_items/14504)되었습니다.
- [GitLab 19.4에서 도입된](https://gitlab.com/gitlab-org/customers-gitlab-com/-/work_items/18963) 이벤트별 상세 파일이 있는 백그라운드 내보내기입니다.

{{< /history >}}

Customers Portal에서 구독의 크레딧 사용 데이터를 내보낼 수 있습니다. 내보내기는 백그라운드에서 실행되고 GitLab은 결과를 다운로드할 수 있는 링크를 이메일로 보냅니다. 다운로드 링크는 7일 후 만료됩니다.

다운로드는 두 개의 CSV 파일을 포함하는 ZIP 파일입니다:

- 선택한 기간의 각 날짜에 사용된 사용량 이벤트 및 크레딧을 나열하는 일일 요약 파일입니다.
- 각 청구 가능한 이벤트에 대해 제품, 플로우 유형, 세션, 사용자 ID, 네임스페이스, 프로젝트, 사용된 크레딧 및 토큰 개수를 포함하는 한 행씩 있는 이벤트별 파일입니다.

각 내보내기는 최대 31일 기간을 포함합니다.

전제 조건:

- 청구 계정 관리자여야 합니다.

1. [고객 포털](https://customers.gitlab.com/)에 로그인합니다.
1. 구독 카드에서 **GitLab Credits 대시보드**를 선택합니다.
1. **사용량 기간** 드롭다운 목록에서 데이터를 내보낼 기간을 선택합니다.
1. **사용량 데이터 내보내기**를 선택합니다.

## GitLab Credits 사용량 보기 {#view-your-gitlab-credits-usage}

{{< details >}}

- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- GitLab 19.5에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/22817)되었습니다.

{{< /history >}}

최상위 그룹의 **GitLab Credits 사용량** 페이지에서 소비하는 GitLab Credits를 추적할 수 있습니다. 대시보드는 크레딧 소비만 보고합니다. 남은 크레딧이나 크레딧 한도를 표시하지 않습니다.

**GitLab Credits 사용량**은 다음을 표시합니다:

- 현재 청구 기간의 사용량입니다.
- 선택한 날짜 범위 및 제품에 대한 일일 크레딧 소비 차트입니다.
- **총 사용량**: 선택한 날짜 범위 및 제품에서 사용된 총 크레딧 수입니다.
- **일일 평균 사용량**: 선택한 날짜 범위 및 제품에 대해 하루에 사용된 평균 크레딧 수입니다.
- **일일 사용량 피크**: 선택한 날짜 범위 및 제품에 대해 하루에 소비된 최대 크레딧 수입니다.

전제 조건:

- GitLab Credits를 포함하는 구독이 있는 최상위 그룹의 멤버여야 합니다.

GitLab Credits 사용량을 보려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Credits**를 선택합니다.
1. 여러 그룹의 멤버인 경우 **그룹** 드롭다운 목록에서 최상위 그룹을 선택합니다.
1. 선택사항. **날짜 범위** 드롭다운 목록에서 사용량을 보려는 날짜 범위를 선택합니다. 기본값은 현재 달입니다.
1. 선택사항. **제품** 드롭다운 목록에서 포함할 제품을 선택합니다.
