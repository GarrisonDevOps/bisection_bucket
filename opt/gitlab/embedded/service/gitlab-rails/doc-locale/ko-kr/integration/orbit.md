---
stage: Orbit
group: Context Systems
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Orbit
description: GitLab Self-Managed 및 GitLab Dedicated용 GitLab Orbit을 구성합니다.
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

## 무료 평가판 시작 {#start-a-free-trial}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- [GitLab 19.5에 도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/260183). 기능 플래그 `orbit_trial`으로 비활성화된 상태로 실행됩니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트용으로 사용 가능하지만 프로덕션 사용을 위한 준비가 되어 있지 않습니다.

최상위 그룹이 아직 Orbit으로 라이선스되지 않은 경우 무료 평가판을 시작할 수 있습니다. 평가판은 그룹에 Orbit용 무료 GitLab Credits를 제공합니다. 평가판 기준을 충족하지 않는 그룹에는 대신 **영업팀에 문의** 옵션이 표시됩니다.

전제 조건:

- 최상위 그룹에 대한 Owner 역할이 있어야 합니다.
- 그룹이 평가판 기준을 충족해야 합니다.

무료 평가판을 시작하려면:

1. 왼쪽 사이드바에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. **설정 > GitLab Orbit**을 선택합니다.
1. **GitLab Orbit 켜기** 토글을 켭니다.
1. 확인 대화상자에서 **GitLab Orbit 켜기**를 선택합니다.

평가판을 시작하면 Orbit이 그룹에 대해 켜지고 그룹, 하위 그룹 및 프로젝트를 인덱싱합니다. 인덱싱은 최대 몇 시간이 소요될 수 있습니다.

평가판은 그 그룹에만 적용됩니다. Orbit만 평가판 크레딧을 사용할 수 있습니다. 평가판이 끝나거나 크레딧이 소진되면 Orbit이 일시 중지됩니다. Orbit을 계속 사용하려면 영업팀에 문의하세요.

## 인스턴스에 대한 무료 평가판 시작 {#start-a-free-trial-for-the-instance}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [GitLab 19.6에 도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261678). 기능 플래그 `orbit_trial` 및 `orbit_promo_access_gate`으로 비활성화된 상태로 실행됩니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그에 의해 제어됩니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트용으로 사용 가능하지만 프로덕션 사용을 위한 준비가 되어 있지 않습니다.

인스턴스가 Orbit 베타 단계에 있지 않고 Orbit을 구매하지 않은 경우 관리자는 인스턴스에 대한 무료 평가판을 시작할 수 있습니다. 평가판은 인스턴스에 Orbit용 무료 GitLab Credits를 제공하며, 모든 최상위 그룹이 이를 공유합니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.
- 인스턴스에는 온라인 클라우드 라이선스가 있어야 합니다.
- 인스턴스가 평가판 기준을 충족해야 합니다.

인스턴스에 대한 무료 평가판을 시작하려면:

1. 왼쪽 사이드바 맨 아래에서 **운영자**를 선택합니다.
1. **GitLab Orbit**을 선택합니다.
1. **평가판 시작**을 선택합니다.
1. 확인 대화상자에서 **평가판 시작**을 선택합니다.

Orbit 대시보드의 **개요** 탭에서 평가판을 시작할 수도 있습니다. 맵 위의 카드에서 **GitLab Orbit 설정으로 이동**을 선택한 다음 **운영자** Orbit 페이지의 단계를 따릅니다.

귀하와 최상위 그룹의 소유자는 평가판 전후에 그룹에 대해 Orbit을 켤 수 있습니다. 평가판 크레딧은 Orbit 쿼리에 대한 비용을 지불합니다.

평가판이 끝나거나 크레딧이 소진되면 Orbit은 그룹을 인덱싱하지만 Orbit 쿼리는 중지됩니다. Orbit 쿼리를 다시 실행하려면 영업팀에 문의하세요.

## 그룹에 대해 Orbit을 켜거나 끕니다 {#turn-orbit-on-or-off-for-your-groups}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/orbit/knowledge-graph/-/work_items/1364)되었습니다.

{{< /history >}}

**상태** 탭에는 Orbit 상태 및 인덱스 상태가 포함된 최상위 그룹이 나열됩니다. Orbit이 인덱싱 중인 그룹의 경우 정보 아이콘({{< icon name="information-o" >}})을 선택하여 각 영역의 인덱스 상태를 확인합니다.

전제 조건:

- Orbit을 켜거나 끄려면 최상위 그룹에 대한 소유자 역할이 있어야 합니다.

그룹에 대해 Orbit을 켜거나 끄려면:

1. 왼쪽 사이드바에서 **귀하의 작업**을 선택합니다.
1. **GitLab Orbit**을 선택합니다.
1. **상태** 탭을 선택합니다.
1. 그룹을 선택합니다.
1. **조치** > **GitLab Orbit 켜기** 또는 **조치** > **GitLab Orbit 끄기**를 선택합니다.
1. 확인 대화상자에서 **GitLab Orbit 켜기** 또는 **GitLab Orbit 끄기**를 선택합니다.

GitLab.com에서 적격 그룹에 대해 Orbit을 켜면 해당 그룹의 무료 평가판이 시작됩니다. 확인 대화상자에는 각 그룹이 받는 평가판이 표시됩니다. GitLab Self-Managed 및 GitLab Dedicated에서 인스턴스의 무료 평가판 중에 확인 대화상자에 평가판의 종료 날짜가 표시됩니다.

GitLab Self-Managed 및 GitLab Dedicated에서는 무료 평가판이나 구매 없이 그룹에 대해 Orbit을 켤 수 있습니다. Orbit은 그룹을 인덱싱하고 **상태** 탭에 인덱스 상태가 표시됩니다. `orbit_promo_access_gate` 기능 플래그가 활성화되면 인스턴스에서 Orbit 쿼리를 실행하려면 무료 평가판이나 구매가 필요합니다. 그때까지 **개요** 탭에는 그룹의 항목 개수가 표시되고 맵 위의 카드에는 인스턴스가 Orbit 쿼리를 받는 방법이 표시됩니다. 무료 평가판을 시작할 수 있는 인스턴스의 관리자는 카드에서 **GitLab Orbit 설정으로 이동**을 봅니다. **쿼리 편집기** 탭에는 Orbit 쿼리를 가져오는 방법이 표시됩니다. 인스턴스의 무료 평가판이 끝난 후에도 더 많은 그룹에 대해 Orbit을 켤 수 있습니다.

## GitLab Duo 기본값의 Orbit {#orbit-in-gitlab-duo-default}

{{< history >}}

- [GitLab 19.5에 도입됨](https://gitlab.com/gitlab-org/orbit/knowledge-graph/-/work_items/1319).

{{< /history >}}

GitLab Duo의 Orbit은 기본적으로 켜져 있습니다. 사용자는 기본 설정에서 사용할 Orbit 기반 기능을 선택합니다.

GitLab.com에서는 Orbit이 켜져 있는 최상위 그룹의 구성원에게 GitLab Duo의 Orbit이 켜져 있습니다. GitLab Self-Managed 및 GitLab Dedicated에서 관리자는 인스턴스 전체 스위치를 설정하며 인스턴스는 Orbit 기능이 있는 라이선스를 보유해야 합니다.

Orbit 가용성, 라이선싱 및 네임스페이스 등록 요구 사항은 계속 적용됩니다.

### 인스턴스에 대해 GitLab Duo에서 Orbit 끄기 {#turn-off-orbit-in-gitlab-duo-for-the-instance}

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.
- 인스턴스는 Orbit 기능이 있는 라이선스를 보유해야 합니다.

인스턴스의 모든 사용자에 대해 GitLab Duo에서 Orbit을 끄려면:

1. 왼쪽 사이드바 맨 아래에서 **운영자**를 선택합니다.
1. **GitLab Orbit**을 선택합니다.
1. **GitLab Duo에서 GitLab Orbit 켜기** 토글을 끕니다.

토글을 변경하면 설정이 저장됩니다.

## 최상위 그룹 네임스페이스 자동으로 인덱싱 {#index-top-level-group-namespaces-automatically}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/606375)되었습니다.

{{< /history >}}

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.
- 인스턴스는 Orbit 기능이 있는 라이선스를 보유해야 합니다.

기존 및 새로운 최상위 그룹 네임스페이스를 자동으로 인덱싱하려면:

1. 왼쪽 사이드바 맨 아래에서 **운영자**를 선택합니다.
1. **GitLab Orbit**을 선택합니다.
1. **모든 최상위 그룹에 대해 GitLab Orbit 자동으로 켜기** 토글을 켭니다.
1. **모든 최상위 그룹에 대해 켜기**를 선택합니다.

설정을 켜면 GitLab은 백그라운드 작업을 대기열에 넣습니다. 작업은 아직 등록되지 않았거나 관리자가 제외한 최상위 그룹 네임스페이스를 등록합니다. 등록은 즉시가 아니라 곧 이후에 발생합니다. 시간당 백그라운드 작업은 새로 생성된 최상위 그룹을 등록하고 제외된 그룹의 등록을 제거합니다. 시간당 작업은 직접 데이터베이스 변경 후 안전망 역할을 합니다. 이러한 변경 사항은 최대 1시간이 걸릴 수 있습니다. 개인 네임스페이스는 등록되지 않습니다.

작업은 무료 평가판이나 구매 없이 그룹을 등록합니다. `orbit_promo_access_gate` 기능 플래그가 활성화되고 인스턴스의 무료 평가판이 종료되면 작업은 인스턴스가 Orbit을 구매한 경우에만 그룹을 등록합니다.

**모든 최상위 그룹에 대해 GitLab Orbit 자동으로 켜기**를 끄면 기존의 제외되지 않은 등록은 유지됩니다. 백그라운드 작업은 설정을 다시 켤 때까지 새로운 최상위 그룹을 등록하지 않습니다.

### 자동 인덱싱에서 최상위 그룹 제외 {#exclude-top-level-groups-from-automatic-indexing}

관리자는 자동 인덱싱 활성화 여부와 관계없이 제외를 관리할 수 있습니다:

1. 왼쪽 사이드바 맨 아래에서 **운영자**를 선택합니다.
1. **GitLab Orbit**을 선택합니다.
1. **최상위 그룹**에서 제외할 그룹을 선택합니다.
1. **조치** > **자동 인덱싱에서 제외**를 선택합니다.
1. 선택한 그룹에 대해 Orbit이 켜져 있으면 **제외**를 선택하여 확인합니다.

제외된 그룹은 자동으로 등록되지 않습니다. 제외된 그룹이 이미 인덱싱된 경우 시간당 백그라운드 작업은 해당 등록 및 인덱스를 제거합니다. 자동 등록을 다시 허용하려면 그룹을 선택한 다음 **조치** > **제외 제거**를 선택합니다. 제외된 그룹에 대해 Orbit을 켜려면 먼저 제외를 제거합니다.

> [!note]
> 이 설정은 GitLab.com에 영향을 주지 않습니다.

## Orbit 속도 제한 구성 {#configure-orbit-rate-limits}

{{< history >}}

- [GitLab 19.6](https://gitlab.com/gitlab-org/orbit/knowledge-graph/-/work_items/476)에서 도입되었습니다.

{{< /history >}}

Orbit은 각 사용자가 1분에 수행할 수 있는 요청 수를 제한합니다. 사용자가 제한을 초과하면 GitLab은 요청을 거부합니다. REST API는 `429 Too Many Requests` 오류를 반환합니다.

| 한도           | 기본값 | 적용 대상 |
|-----------------|---------|------------|
| 쿼리         | 60      | REST API 및 MCP의 Orbit 쿼리, 컨텍스트, grep 및 스킬 요청 그리고 `query_graph` 명령입니다. |
| 인덱싱 상태 | 30      | UI 및 GraphQL API의 Orbit 인덱싱 상태 요청입니다. |
| 항목 개수     | 30      | UI 및 GraphQL API의 Orbit 항목 개수 요청입니다. |

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

Orbit 속도 제한을 구성하려면:

1. 오른쪽 상단 모서리에서 {{< ui text="운영자" >}}를 선택합니다.
1. 왼쪽 사이드바에서 {{< ui text="설정" >}} > {{< ui text="네트워크" >}}를 선택합니다.
1. {{< ui text="GitLab Orbit 속도 제한" >}}을 확장합니다.
1. 필드를 완성합니다. 제한을 끄려면 `0`로 설정합니다.
1. 선택사항. {{< ui text="속도 제한에서 제외할 사용자" >}}에서 많은 쿼리를 보내는 봇 사용자 등 Orbit 속도 제한이 없는 사용자 이름을 입력합니다. 최대 100개의 사용자 이름을 입력할 수 있습니다.
1. {{< ui text="변경사항 저장" >}}을 선택합니다.

[애플리케이션 설정 API](../api/settings.md)로도 이러한 제한을 설정할 수 있습니다.

Orbit grep 요청은 [검색 속도 제한](../administration/instance_limits.md#search-rate-limit)으로도 계산됩니다. 해당 제한에서 사용자를 제외하려면 사용자를 {{< ui text="속도 제한에서 제외할 사용자" >}} ({{< ui text="설정" >}} > {{< ui text="네트워크" >}} > {{< ui text="검색 속도 제한" >}})에 추가합니다.

## Orbit 상태 보기 {#view-orbit-status}

Orbit 구성 및 인덱싱 상태를 보려면 다음을 실행합니다:

```shell
sudo gitlab-rake gitlab:orbit:info
```
