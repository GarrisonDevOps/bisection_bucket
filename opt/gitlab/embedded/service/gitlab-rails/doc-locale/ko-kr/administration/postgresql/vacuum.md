---
stage: Data Access
group: Database Health
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: PostgreSQL autovacuum 튜닝
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

이 페이지를 사용하여 PostgreSQL autovacuum을 튜닝하고 일반적인 autovacuum 문제를 해결할 수 있습니다.

## Autovacuum 작동 방식 {#how-autovacuum-works}

PostgreSQL은 [다중 버전 동시성 제어(MVCC)](https://www.postgresql.org/docs/current/mvcc-intro.html)를 사용합니다. 행을 업데이트하거나 삭제할 때 PostgreSQL은 이전 행 버전을 즉시 제거하지 않습니다. 대신 PostgreSQL은 이전 버전을 dead로 표시하고 실행 중인 트랜잭션이 더 이상 볼 수 없을 때까지 유지합니다. Autovacuum은 이러한 dead 행 버전(dead tuple이라고도 함)을 제거하는 백그라운드 프로세스입니다. 점유하는 공간을 재확보하고, 플래너 통계를 업데이트하며, 가시성 맵을 유지합니다.

Autovacuum은 데이터베이스 상태에 매우 중요합니다. 이것이 없으면 dead 행이 테이블 및 인덱스 bloat으로 누적됩니다. Bloat은 쿼리 속도를 저하시키고, 디스크 공간을 낭비하며, 백업 및 유지 관리 시간을 증가시킵니다. Autovacuum은 또한 [트랜잭션 ID 래핑](https://www.postgresql.org/docs/current/routine-vacuuming.html#VACUUM-FOR-WRAPAROUND)을 방지하여 데이터베이스가 쓰기를 수락하지 않도록 합니다.

### Autovacuum이 실행되는 시기 {#when-autovacuum-runs}

Autovacuum은 각 테이블을 주기적으로 확인하고 dead tuple 수가 이 임계값을 초과할 때 vacuum을 실행합니다:

```plaintext
autovacuum_vacuum_threshold + autovacuum_vacuum_scale_factor × number_of_live_tuples
```

기본적으로 PostgreSQL은 `autovacuum_vacuum_scale_factor`을(를) `0.2`로 설정합니다. PostgreSQL은 행의 20%가 dead가 된 후에만 테이블을 vacuum합니다. 대형 테이블의 경우 20%는 많은 수의 dead tuple입니다. Autovacuum이 작동하기 전에 테이블이 오랫동안 bloat됩니다. 이 지연을 줄이기 위해 GitLab Linux 패키지 설치는 `autovacuum_vacuum_scale_factor`을(를) `0.02`(2%)로 기본적으로 낮춥니다. 가장 크거나 가장 자주 업데이트되는 테이블은 여전히 더 낮은 테이블별 값이 필요할 수 있습니다. [대형 테이블 개별 튜닝](#tune-large-tables-individually)을(를) 참조하세요.

## 권장 autovacuum 설정 {#recommended-autovacuum-settings}

GitLab Linux 패키지 설치는 대부분의 워크로드에 적합한 autovacuum 기본값으로 제공됩니다. [모니터링](#monitor-autovacuum)에서 autovacuum이 dead tuple을 따라잡을 수 없음을 나타낼 때 이 설정을 변경합니다. 목표는 autovacuum이 워크로드가 생성하는 만큼 빠르게 dead tuple을 재확보하도록 하면서 데이터베이스에 I/O를 제공하지 않도록 하는 것입니다.

가장 큰 영향을 주는 변경 사항은 일반적으로 `autovacuum_vacuum_cost_limit`을(를) 높이고, `autovacuum_max_workers`을(를) 높이고, 가장 큰 테이블의 스케일 팩터를 낮추는 것입니다. 이 섹션의 값을 시작점으로 취급하고 자신의 워크로드와 대조하여 검증합니다.

### 클러스터 전체 설정 {#cluster-wide-settings}

GitLab Linux 패키지 설치의 경우 `/etc/gitlab/gitlab.rb`에서 클러스터 전체 값을 설정한 다음 `sudo gitlab-ctl reconfigure`을(를) 실행합니다.

```ruby
postgresql['autovacuum_max_workers'] = "<value>"
postgresql['autovacuum_vacuum_cost_limit'] = "<value>"
postgresql['autovacuum_vacuum_cost_delay'] = "<value>"
postgresql['maintenance_work_mem'] = "<value>"
```

[외부 PostgreSQL 인스턴스](external.md)의 경우 `postgresql.conf`에서 동일한 매개변수를 설정한 다음 PostgreSQL을 다시 로드합니다:

```ini
autovacuum_max_workers = <value>
autovacuum_vacuum_cost_limit = <value>
autovacuum_vacuum_cost_delay = <value>
maintenance_work_mem = <value>
autovacuum_work_mem = <value>
```

`SELECT pg_reload_conf();`을(를) 사용하거나 서비스를 다시 로드하여 PostgreSQL을 다시 로드합니다. 두 설치 유형 모두에서 `autovacuum_max_workers`와 같은 설정은 완전한 PostgreSQL 재시작이 필요합니다. 다시 로드 또는 재구성으로는 충분하지 않습니다.

다음 설정은 autovacuum이 따라잡는지 여부에 가장 큰 영향을 미칩니다:

| 설정                          | 권장값           | 설명                                                                                                                                                                                                                                                                                                                                                 |
|----------------------------------|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `autovacuum_max_workers`         | vCPU 수의 약 25% | 동시에 실행되는 autovacuum 프로세스의 최대 개수입니다. 기본값은 종종 대형의 다중 코어 데이터베이스 호스트에 너무 낮습니다. 각 워커는 메모리 및 I/O 로드를 추가합니다.                                                                                                                                                                                  |
| `autovacuum_vacuum_scale_factor` | `0.01`에서 `0.02`            | autovacuum이 실행되기 전에 dead여야 하는 테이블 행의 분수입니다. GitLab은 PostgreSQL 기본값을 `0.02`로 낮춥니다. 크고 자주 업데이트되는 테이블에서는 더 낮추세요. [대형 테이블 개별 튜닝](#tune-large-tables-individually)을(를) 참조하세요.                                                                                                          |
| `autovacuum_vacuum_cost_limit`   | SSD의 경우 800                 | Autovacuum이 일시 중지되기 전에 누적하는 I/O 비용입니다. `-1`로 설정하면 `vacuum_cost_limit`의 값을 상속합니다. 해당 값은 최신 SSD 기반 스토리지의 처리량보다 훨씬 낮습니다. 명시적으로 설정합니다. 이를 높이는 것은 종종 가장 큰 영향을 미치는 변경 사항입니다.                                                                                                         |
| `autovacuum_vacuum_cost_delay`   | 2ms                        | Autovacuum이 비용 제한에 도달한 후 일시 중지하는 시간입니다. 이를 낮춰 autovacuum을 더 공격적으로 만듭니다. `0`로 설정하지 마세요. [피해야 할 설정](#settings-to-avoid)을(를) 참조하세요.                                                                                                                                                                                      |
| `maintenance_work_mem`           | 1GB ~ 2GB                | 인덱스 생성과 같은 유지 관리 작업을 위한 메모리입니다. 각 autovacuum 워커는 `autovacuum_work_mem`이(가) `-1`일 때 dead tuple을 추적하는 데 이 정도의 메모리를 사용합니다. 낮은 값은 워커가 큰 테이블에서 인덱스를 반복적으로 스캔하도록 합니다. 사용 가능한 RAM과 워커 수에 맞게 크기를 조정합니다.                                                                   |
| `autovacuum_work_mem`            | 512MB                      | 각 autovacuum 워커가 dead tuple을 추적하는 데 사용하는 메모리입니다. `-1`로 설정하면 워커는 `maintenance_work_mem`을(를) 상속합니다. 총 autovacuum 메모리는 워커 수에 따라 크기가 조정됩니다. PostgreSQL 17에서는 이 메모리의 1GB 상한을 제거했습니다. 워커 수를 높일 때 명시적으로 바운드합니다. Linux 패키지 설치는 `gitlab.rb`에서 이 매개변수를 설정할 수 없습니다. |
| `autovacuum_naptime`             | 몇 초(선택 사항)    | Autovacuum이 데이터베이스 확인 사이에 기다리는 시간입니다. 빠른 변경이 있는 데이터베이스의 경우 autovacuum이 더 빠르게 응답하도록 이를 낮추세요.                                                                                                                                                                                                                                  |

### 대형 테이블 개별 튜닝 {#tune-large-tables-individually}

낮은 클러스터 전체 스케일 팩터에도 불구하고 가장 큰 테이블도 bloat될 수 있습니다. 이러한 테이블의 경우 PostgreSQL에서 직접 더 낮은 테이블별 스케일 팩터 또는 임계값을 설정합니다. 약 `0.01`(1%)의 스케일 팩터는 매우 크고 자주 업데이트되는 테이블에서 일반적입니다:

```sql
ALTER TABLE <table_name> SET (autovacuum_vacuum_scale_factor = 0.01);
```

테이블별 설정은 해당 테이블에만 클러스터 전체 값을 재정의합니다. [모니터링](#monitor-autovacuum)을(를) 사용하여 뒤처지는 테이블을 찾고 프로덕션이 아닌 환경에서 먼저 변경 사항을 테스트합니다.

### 피해야 할 설정 {#settings-to-avoid}

> [!warning]
> Autovacuum을 비활성화하지 마세요(`autovacuum = off`). Autovacuum이 없으면 dead tuple이 누적됩니다. 그러면 데이터베이스가 트랜잭션 ID 래핑으로 이동합니다. 래핑은 데이터베이스가 쓰기를 수락하지 않도록 합니다.

다음 구성을 피하세요:

- `autovacuum_vacuum_cost_delay = 0`은(는) I/O 제한을 제거합니다. Autovacuum은 일시 중지하지 않고 실행되며 디스크 I/O를 포화시킬 수 있습니다. 쿼리가 느려집니다.
- 가장 큰 테이블의 기본 스케일 팩터입니다. 이러한 테이블은 너무 드물게 vacuum됩니다. 대신 더 낮은 테이블별 값을 설정하세요.
- `-1` 상속을 `autovacuum_vacuum_cost_limit`에 의존합니다. 유효한 값은 다른 설정에 있으므로 간과할 수 있습니다. 명시적으로 설정합니다.

## Autovacuum 모니터링 {#monitor-autovacuum}

### 데이터베이스 진단 페이지 {#database-diagnostics-page}

{{< history >}}

- Vacuum 작업이 GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/239928)되었습니다.
- Autovacuum 설정 및 발견사항이 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/242428)되었습니다.
- 테이블별 재정의 및 스케일 팩터 위험이 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245561)되었습니다.

{{< /history >}}

데이터베이스 진단 페이지는 각 데이터베이스의 vacuum 작업 및 autovacuum 설정을 보여줍니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

페이지를 보려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **모니터링** > **데이터베이스 진단**을 선택합니다.

페이지의 두 섹션이 autovacuum과 관련이 있습니다. 각 섹션에는 설치의 각 데이터베이스에 대한 카드가 하나씩 있습니다.

**Vacuum 정보** 섹션에는 **Vacuum 작업** 패널이 포함되어 있습니다. 이 패널은 현재 실행 중인 각 vacuum에 대해 한 행을 포함합니다. 열은 Table, Type, Running for, Phase, Heap scanned, Indexes processed, Dead tuples, Index passes, Delay time입니다. 행은 다음 배지를 가질 수 있습니다:

- **랩어라운드 방지**: vacuum이 트랜잭션 ID 래핑을 방지하고 있습니다. 이 vacuum은 자동으로 취소되지 않습니다. 종료하지 마세요. 만약 그렇게 하면 데이터베이스가 데이터를 보호하기 위해 종료될 수 있습니다.
- **장기 실행중**: vacuum이 6시간 이상 실행되었습니다. 큰 테이블은 이 정도의 시간이 걸릴 수 있지만 완료되지 않은 vacuum은 차단되거나 리소스 부족 상태일 수 있습니다.
- **메모리 압력**: vacuum이 하나 이상의 인덱스 패스가 필요했습니다. Dead tuple 저장소가 heap 스캔을 완료하기 전에 가득 찼습니다. `maintenance_work_mem` 또는 `autovacuum_work_mem`을(를) 높입니다.

**Autovacuum 구성** 섹션에는 다음 패널이 포함되어 있습니다:

- **유효한 설정**: 데이터베이스가 실제로 사용하는 autovacuum 설정으로 `pg_settings`에서 읽습니다. **상태** 열은 검사에서 발견한 각 구성 오류를 표시합니다. `autovacuum_vacuum_cost_limit`이(가) `-1`일 때 패널은 `vacuum_cost_limit`에서 상속하는 유효한 제한을 표시합니다.
- **테이블별 재정의**: 저장 매개변수에서 autovacuum 매개변수를 설정하는 테이블입니다. 패널은 각 테이블의 크기, 예상 행 수 및 재정의를 보여줍니다. Autovacuum을 비활성화하는 테이블은 **Autovacuum 비활성화됨** 배지를 포함합니다. 패널은 최대 50개 테이블을 나열하며 autovacuum을 비활성화하는 테이블이 먼저 표시됩니다. 테이블에 재정의가 없을 때 패널은 숨겨집니다.
- **스케일 팩터 위험**: 실제 스케일 팩터가 여전히 높은 큰 테이블입니다. 검사에서 이러한 테이블을 찾지 못하면 패널이 숨겨집니다.

일부 발견사항은 단일 설정이 아닌 테이블을 의미합니다. 이러한 발견사항은 패널 위에 경고로 표시됩니다. 각 발견사항 뒤의 조건을 알아보려면 [Autovacuum 발견사항](#autovacuum-findings)을(를) 참조하세요.

> [!note]
> **Vacuum 작업** 패널에는 PostgreSQL 17 이상이 필요합니다. 이전 버전의 경우 패널이 비어 있습니다. Delay time 열에는 PostgreSQL 18 이상이 필요합니다. Type 및 Running for 열과 **랩어라운드 방지** 배지는 다른 백엔드의 작업을 읽을 수 있는 데이터베이스 역할이 필요합니다. `pg_monitor`의 역할 멤버십을 부여합니다. 이 멤버십이 없으면 진행 열은 여전히 작동하지만 Type, Running for, Anti-wraparound 필드에는 `Not available`이(가) 표시됩니다.

두 섹션 모두 1차 데이터베이스에서 읽습니다. autovacuum은 여기서만 실행되기 때문입니다.

### 콘솔에서 진단 보고 {#report-diagnostics-on-the-console}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251254)되었습니다.
- 단일 검사에 대한 작업이 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251735)되었습니다.
- 단일 검사에 대한 메뉴가 GitLab 19.5에서 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257133)되어 제거되었습니다.
- 플래너 통계 검사가 GitLab 19.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/265314)되었습니다.

{{< /history >}}

UI에 액세스할 수 없거나 스크립트에서 보고서를 원할 때 Rake 작업을 사용합니다.

Linux 패키지 설치의 경우:

```shell
sudo gitlab-rake gitlab:db:diagnostics
```

기본적으로 작업은 모든 데이터베이스에 보고합니다. 데이터베이스를 선택하려면 해당 이름을 전달합니다:

```shell
sudo gitlab-rake "gitlab:db:diagnostics[main,ci]"
```

하나의 검사만 실행하려면 자체 작업을 사용합니다. 작업은 동일한 데이터베이스 이름을 수락합니다:

```shell
sudo gitlab-rake "gitlab:db:diagnostics:autovacuum_settings[main,ci]"
sudo gitlab-rake "gitlab:db:diagnostics:planner_statistics[main,ci]"
```

보고서는 먼저 요약을 출력한 다음 각 검사에 대한 섹션을 출력합니다. **Autovacuum 설정** 섹션은 각 데이터베이스에 대한 발견사항, 유효한 설정, 테이블별 재정의 및 스케일 팩터 위험을 나열합니다.

**플래너 통계** 섹션은 PostgreSQL이 분석하거나 vacuum한 적이 없는 10MiB 이상의 테이블과 통계가 예상 간격의 2배 이상 오래된 분할된 테이블을 나열합니다. PostgreSQL 18 이전의 PostgreSQL 주 버전 업그레이드 후 통계가 누락되었으며, autovacuum은 분할된 테이블을 분석하지 않습니다. 복원 후 섹션은 분할된 테이블만 보고합니다: 인덱스 구축은 다른 복원된 테이블의 행 수를 기록하지만 열 통계도 없습니다. [플래너 통계 발견사항](#planner-statistics-findings)을(를) 참조하세요.

작업은 오류를 발견할 때 상태 `1`으로 종료되므로 모니터링 작업이 종료 코드를 사용할 수 있습니다.

터미널에서 작업이 하나 이상의 검사를 실행할 때 각 섹션을 열기 위한 메뉴를 표시합니다. 한 번의 검사를 실행하거나 출력을 파이프 또는 리디렉션할 때 작업은 전체 보고서를 출력합니다.

> [!note]
> Rake 작업은 vacuum 작업을 표시하지 않습니다. Vacuum 작업은 [데이터베이스 진단 페이지](#database-diagnostics-page)에서만 사용할 수 있습니다.

### Autovacuum 발견사항 {#autovacuum-findings}

데이터베이스 진단 페이지와 Rake 작업은 동일한 검사를 사용합니다. 둘 다 동일한 발견사항을 보고합니다. 첫 번째 5개의 발견사항은 각각 하나의 설정을 의미하며 **상태** 열의 **유효한 설정** 패널에 나타납니다. 마지막 2개는 테이블을 의미하며 경고로 표시됩니다.

| 발견사항             | 설정                          | 심각도 | 보고되는 시기                                                                                                                                                                                                                                                                                                                                             | 작업                                                                                                                                                                                                                  |
|---------------------|----------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Disabled (비활성화됨)            | `autovacuum`                     | 오류    | `autovacuum`이(가) `off`입니다. Dead tuple은 자동으로 재확보되지 않습니다. 이는 bloat과 결국 트랜잭션 ID 래핑의 위험이 있습니다.                                                                                                                                                                                                                          | Autovacuum을 활성화합니다. [피해야 할 설정](#settings-to-avoid)을 참조하세요.                                                                                                                                                        |
| 제한 비활성화됨 | `autovacuum_vacuum_cost_delay`   | 오류    | 비용 지연은 `0`입니다. Autovacuum은 전체 속도로 실행됩니다. 이것은 쓰기 폭주 및 복제 지연을 유발할 수 있습니다.                                                                                                                                                                                                                                               | 0이 아닌 지연을 설정합니다. [피해야 할 설정](#settings-to-avoid)을 참조하세요.                                                                                                                                                      |
| 낮음                 | `autovacuum_max_workers`         | 경고  | 3개 미만의 워커가 구성되어 있습니다. 이는 큰 데이터베이스 또는 분해된 데이터베이스의 경우 너무 적을 수 있습니다.                                                                                                                                                                                                                                                          | 워커 수를 높입니다. [클러스터 전체 설정](#cluster-wide-settings)을(를) 참조하세요.                                                                                                                                            |
| 낮음                 | `autovacuum_vacuum_cost_limit`   | 경고  | 유효한 제한은 `200` 이하입니다. 해당 제한은 최신 스토리지의 경우 너무 낮을 가능성이 높습니다. 검사는 설정이 `-1`일 때 `vacuum_cost_limit`에서 상속한 값을 사용합니다. Linux 패키지 설치는 기본적으로 `-1`을(를) 제공합니다. `vacuum_cost_limit`의 PostgreSQL 기본값은 `200`입니다. 따라서 이 발견사항은 기본 Linux 패키지 설치에서 나타납니다. | 제한을 명시적으로 설정합니다. [클러스터 전체 설정](#cluster-wide-settings)을(를) 참조하세요.                                                                                                                                          |
| 상속됨           | `autovacuum_work_mem`            | 경고  | 설정이 `-1`입니다. 각 워커는 `maintenance_work_mem`을(를) 상속합니다.                                                                                                                                                                                                                                                                                         | 각 워커가 사용하는 메모리를 바운드하도록 명시적으로 설정합니다. Linux 패키지 설치는 `gitlab.rb`에서 이 매개변수를 설정할 수 없습니다. 대신 `maintenance_work_mem`을(를) 튜닝하세요. [클러스터 전체 설정](#cluster-wide-settings)을(를) 참조하세요. |
| 테이블 비활성화됨     | 테이블별 `autovacuum_enabled`   | 오류    | 하나 이상의 테이블이 저장 매개변수에서 `autovacuum_enabled = false`을(를) 설정합니다. 해당 dead tuple은 자동으로 재확보되지 않습니다. **테이블별 재정의** 패널은 각 이러한 테이블을 표시합니다.                                                                                                                                                            | 각 테이블에 대해 `ALTER TABLE <table_name> RESET (autovacuum_enabled);`을(를) 사용하여 autovacuum을 다시 활성화합니다.                                                                                                                     |
| 스케일 팩터 위험   | `autovacuum_vacuum_scale_factor` | 경고  | 클러스터 전체 스케일 팩터는 `0.1` 이상이며, 20개의 가장 큰 테이블 중 하나는 10GiB 이상이고 스케일 팩터가 실제로 `0.1` 이상입니다. Linux 패키지 설치는 `0.02`을(를) 제공합니다. 따라서 이 발견사항은 주로 PostgreSQL의 기본값인 `0.2`을(를) 유지하는 외부 PostgreSQL 인스턴스에서 나타납니다.                                             | 클러스터 전체 스케일 팩터를 낮추거나 나열된 테이블에서 테이블별 값을 설정합니다. [대형 테이블 개별 튜닝](#tune-large-tables-individually)을(를) 참조하세요.                                                              |

실제 스케일 팩터는 설정된 경우 테이블별 재정의이고, 그렇지 않으면 클러스터 전체 값입니다. 테이블별 `autovacuum_vacuum_threshold`은(는) 테이블을 면제하지 않습니다. 검사는 autovacuum이 비활성화된 테이블을 건너뜁니다.

> [!note]
> 검사는 명확한 구성 오류만 보고합니다. 검사는 또한 [권장 autovacuum 설정](#recommended-autovacuum-settings)의 값보다 낮은 임계값을 사용합니다. 설정이 검사를 통과할 수 있지만 워크로드에는 여전히 너무 낮을 수 있습니다. 예를 들어 3개의 autovacuum 워커는 검사를 통과하지만 많은 vCPU를 가진 호스트의 경우 낮습니다.

### 플래너 통계 발견사항 {#planner-statistics-findings}

Rake 작업은 2개의 발견사항을 보고합니다. 둘 다 인덱스 없이 heap 크기로 측정되는 10MiB 이상의 테이블을 의미합니다.

| 발견사항            | 심각도 | 보고되는 시기                                                                                                                                                                                                                                                                                                           | 작업                                                                                                                                                                                                                                                                                             |
|--------------------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 통계 누락 | 오류    | PostgreSQL이 테이블을 분석하거나 vacuum하지 않았거나 분할된 테이블을 분석하지 않아 이에 대한 쿼리를 계획할 통계가 없습니다. 이는 PostgreSQL 18 이전의 PostgreSQL 주 버전 업그레이드 후의 상태입니다. 검사는 100개의 가장 큰 이러한 테이블을 보고 최대 50개를 나열합니다. 100개 모두가 10MiB 이상일 때 발견사항은 "최소 100"이라고 말합니다. | `statement_timeout`이(가) `0`으로 설정된 세션에서 각 테이블에서 `ANALYZE`을(를) 실행합니다. 분할된 테이블의 `ANALYZE`은(는) 해당 파티션도 포함합니다. 발견사항이 "최소 100"이라고 말할 때 전체 데이터베이스를 포함하려면 테이블 이름 없이 `ANALYZE`을(를) 실행합니다.                                                 |
| 통계 오래됨   | 경고  | 분할된 테이블이 예상 간격의 2배 이상 전에 마지막으로 분석되었습니다. **간격** 열은 그 간격을 보여줍니다: GitLab이 테이블을 분석하는 일정이거나 GitLab이 분석하지 않는 분할된 테이블의 경우 1주입니다.                                                                           | `statement_timeout`이(가) `0`으로 설정된 세션에서 테이블에서 `ANALYZE`을(를) 실행합니다. GitLab이 일정에 따라 분석하는 테이블의 경우 `postgres_dynamic_partitions_manager` cron 작업이 실행되는지 확인하세요.                                                                                                   |

### Dead tuple 및 freeze age 확인 {#check-dead-tuples-and-freeze-age}

데이터베이스 진단 페이지와 Rake 작업 모두 테이블별 dead tuple 또는 freeze age를 보고하지 않습니다. 대신 해당 정보에 대해 데이터베이스를 쿼리합니다. Linux 패키지 설치에서 다음으로 연결합니다:

```shell
sudo gitlab-psql
```

가장 많은 dead tuple을 가진 테이블을 찾고 autovacuum이 마지막으로 처리한 시기:

```sql
SELECT schemaname, relname, n_live_tup, n_dead_tup, last_autovacuum, last_autoanalyze
FROM pg_stat_user_tables
WHERE n_dead_tup > 0
ORDER BY n_dead_tup DESC
LIMIT 20;
```

`n_dead_tup` 수가 증가하고 `last_autovacuum`이(가) 오래되었거나 비어 있으면 autovacuum이 해당 테이블을 따라잡을 수 없음을 의미합니다. [테이블을 따라잡을 수 없는 Autovacuum](#autovacuum-cannot-keep-up-with-a-table)을(를) 참조하세요.

각 테이블의 freeze age를 찾으려면:

```sql
SELECT n.nspname AS schema_name, c.relname AS table_name, age(c.relfrozenxid) AS xid_age
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'm')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY xid_age DESC
LIMIT 20;
```

`xid_age`은(는) PostgreSQL이 테이블을 마지막으로 freeze한 후 실행된 트랜잭션을 카운트합니다. `autovacuum_freeze_max_age`에 대해 비교합니다. **유효한 설정** 패널은 이 값을 보고합니다. 테이블이 이 값을 통과하면 PostgreSQL은 이에 대한 anti-wraparound autovacuum을 시작합니다. 계속 증가하는 freeze age는 autovacuum이 행을 충분히 빠르게 freeze할 수 없음을 의미합니다. [트랜잭션 ID 래핑이 접근 중입니다](#transaction-id-wraparound-is-approaching)를 참조하세요.

## 일반적인 문제 해결 {#troubleshoot-common-issues}

### 테이블을 따라잡을 수 없는 Autovacuum {#autovacuum-cannot-keep-up-with-a-table}

테이블은 autovacuum이 제거하는 것보다 빠르게 dead tuple을 누적합니다. Dead tuple 수가 계속 증가하고, 테이블이 bloat되며, 이에 대한 쿼리가 느려집니다. 이 문제에는 두 가지 일반적인 원인이 있습니다:

- 높은 변경 속도입니다. 데이터베이스 마이그레이션이거나 행을 자주 업데이트하는 엔드포인트가 autovacuum이 이를 지우는 것보다 빠르게 dead tuple을 생성합니다.
- 클러스터 전체 설정을 사용하는 바쁜 테이블입니다. 크고 자주 업데이트되는 테이블은 종종 자신의 autovacuum 설정이 필요합니다.

어떤 테이블이 뒤처지는지 찾으려면 각 테이블에 대한 dead tuple 수와 autovacuum이 마지막으로 실행한 시간을 확인합니다. [Autovacuum 모니터링](#monitor-autovacuum)을(를) 참조하세요. 문제를 해결하려면:

- 더 낮은 테이블별 스케일 팩터 또는 임계값을 설정합니다. 자세한 내용은 [대형 테이블 개별 튜닝](#tune-large-tables-individually)을(를) 참조하세요.
- `autovacuum_vacuum_cost_limit` 및 `autovacuum_max_workers`을(를) 높입니다. 자세한 내용은 [권장 autovacuum 설정](#recommended-autovacuum-settings)을(를) 참조하세요.
- 마이그레이션이나 애플리케이션 변경이 churn의 원인이면 일시 중지하거나 되돌립니다.

### 트랜잭션 ID 래핑이 접근 중입니다 {#transaction-id-wraparound-is-approaching}

PostgreSQL은 각 트랜잭션에 ID(XID)를 할당합니다. 가장 오래된 unfrozen XID가 나이가 들면서 PostgreSQL은 anti-wraparound autovacuum을 실행하여 오래된 행을 freeze합니다. 이러한 vacuum이 완료될 수 없으면 데이터베이스가 결국 데이터를 보호하기 위해 쓰기 수락을 중지합니다.

이 위험을 추적하려면 각 데이터베이스 및 테이블의 freeze age를 모니터링합니다. [Autovacuum 모니터링](#monitor-autovacuum)을(를) 참조하세요. 계속 증가하는 freeze age는 autovacuum이 행을 충분히 빠르게 freeze할 수 없음을 의미합니다.

이를 해결하려면 autovacuum이 실행되고 차단되지 않았는지 확인합니다. [테이블을 따라잡을 수 없는 Autovacuum](#autovacuum-cannot-keep-up-with-a-table)을(를) 참조하세요. 데이터베이스가 이미 쓰기 수락을 중지한 경우 [래핑 데이터 손실을 피하기 위해 명령을 수락하지 않는 데이터베이스](../troubleshooting/postgresql.md#database-is-not-accepting-commands-to-avoid-wraparound-data-loss)의 복구 단계를 따릅니다.

### Autovacuum이 너무 많은 리소스를 사용합니다 {#autovacuum-uses-too-many-resources}

Autovacuum은 다른 쿼리를 저하시킬 수 있는 I/O 트래픽을 생성합니다. PostgreSQL은 비용 기반 지연으로 이 트래픽을 제한합니다. 지연은 모든 실행 중인 autovacuum 워커 간에 균형을 이룹니다. 총 I/O 영향은 실행 중인 워커 수에 관계없이 거의 동일하게 유지됩니다.

다른 쿼리에 미치는 영향을 줄이려면 `autovacuum_vacuum_cost_delay`을(를) 높여서 워커가 더 자주 일시 중지하도록 합니다. 더 높은 지연은 vacuum을 느리게 합니다. dead tuple을 계속 따라가야 할 필요성에 대해 이를 균형 있게 조정합니다. 지연을 `0`으로 설정하지 마세요. 이것은 제한을 완전히 제거합니다. 자세한 내용은 [피해야 할 설정](#settings-to-avoid)을(를) 참조하세요.
