---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 다운타임 없이 다중 노드 인스턴스 업그레이드
description: 다운타임 없이 Linux 패키지 기반 다중 노드를 업그레이드합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

다운타임 없이 다중 노드 GitLab 환경을 업그레이드하는 프로세스는 [업그레이드 순서](#upgrade-order)에 따라 각 노드를 순차적으로 진행합니다. 로드 밸런서와 HA 메커니즘이 각 노드의 다운을 적절히 처리합니다.

다운타임 없이 업그레이드를 시작하기 전에 [다운타임 옵션을 검토하세요](downtime_options.md).

## 시작하기 전에 {#before-you-start}

분산 애플리케이션의 경우 업그레이드의 일부로 다운타임을 없애기는 상당히 어렵습니다. 설명서는 HA [참조 아키텍처](../administration/reference_architectures/_index.md)에 대해 테스트되었으며 실질적으로 관찰할 수 있는 다운타임이 없는 결과가 나왔습니다. 다만 특정 시스템 구성에 따라 결과가 달라질 수 있습니다.

추가 신뢰성을 위해 일부 고객은 특정 로드 밸런서 또는 인프라 기능을 사용하여 노드를 수동으로 드레인하는 등 추가 기술을 사용하여 성공했습니다. 이러한 기술은 기본 인프라 기능에 크게 의존합니다.

추가 정보는 GitLab 담당자 또는 [지원 팀](https://support.gitlab.com/)에 문의하세요.

### 요구사항 {#requirements}

다운타임 없는 업그레이드 프로세스는 다음과 같이 구성된 로드 밸런싱 및 사용 가능한 HA 메커니즘이 있는 Linux 패키지로 구축된 다중 노드 GitLab 환경이 필요합니다:

- GitLab 애플리케이션 노드용으로 구성된 외부 로드 밸런서(상태 확인이 [준비 완료](../administration/monitoring/health_check.md#readiness) (`/-/readiness`) 엔드포인트에 대해 활성화됨).
- PgBouncer 및 Praefect 구성 요소용으로 구성된 내부 로드 밸런서(TCP 상태 확인이 활성화됨).
- Consul, Postgres 및 Redis 구성 요소가 있는 경우 HA 메커니즘을 구성합니다.
  - HA 방식으로 배포되지 않은 이러한 구성 요소는 다운타임과 함께 별도로 업그레이드해야 합니다.
  - 데이터베이스의 경우 [Linux 패키지는 main GitLab 데이터베이스에 대해서만 HA를 지원합니다](https://gitlab.com/groups/gitlab-org/-/work_items/7814). [Praefect 데이터베이스](#upgrade-gitaly-cluster-praefect-nodes)와 같은 다른 데이터베이스의 경우 HA를 달성하고 이후에 다운타임을 피하기 위해 타사 데이터베이스 솔루션이 필요합니다.

다운타임 없는 업그레이드를 위해서는 다음을 수행해야 합니다:

- 한 번에 하나의 마이너 릴리스를 업그레이드합니다. `16.1`에서 `16.2`로, `16.3`로는 아닙니다. 릴리스를 건너뛰면 데이터베이스 수정이 잘못된 순서로 실행될 수 있으며 [데이터베이스 스키마가 손상된 상태로 남을 수 있습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/321542).
- 배포 후 마이그레이션을 사용합니다.

### 고려 사항 {#considerations}

다운타임 없는 업그레이드를 고려할 때 다음을 알아두세요:

- 대부분의 경우 패치 릴리스가 최신 버전이 아닌 경우 패치 릴리스에서 다음 마이너 릴리스로 안전하게 업그레이드할 수 있습니다. 예를 들어 `16.3.2`에서 `16.4.1`로 업그레이드하는 것은 `16.3.3`이 릴리스되었더라도 안전해야 합니다. [버전별 업그레이드 노트](versions/_index.md)를 확인하고 [업그레이드 경로](upgrade_paths.md)와 관련하여 필요한 업그레이드 중지 사항을 인식해야 합니다:
  - [GitLab 19 업그레이드 노트](versions/gitlab_19_changes.md)
  - [GitLab 18 업그레이드 노트](versions/gitlab_18_changes.md)
  - [GitLab 17 업그레이드 노트](versions/gitlab_17_changes.md)
  - [GitLab 16 업그레이드 노트](versions/gitlab_16_changes.md)
  - [GitLab 15 업그레이드 노트](versions/gitlab_15_changes.md)
- 일부 릴리스에는 배경 마이그레이션이 포함될 수 있습니다. 이러한 마이그레이션은 Sidekiq에 의해 배경에서 수행되며 종종 데이터 마이그레이션에 사용됩니다. 배경 마이그레이션은 월간 릴리스에서만 추가됩니다.
  - 특정 주요 또는 마이너 릴리스에는 완료해야 할 배경 마이그레이션 세트가 필요할 수 있습니다. 이것이 다운타임을 필요로 하지는 않지만(이전 조건이 충족되는 경우) 각 주요 또는 마이너 릴리스 업그레이드 사이에 배경 마이그레이션이 완료될 때까지 대기해야 합니다.
  - `background_migration` 큐의 작업을 처리할 수 있는 Sidekiq 워커의 수를 늘려 이러한 마이그레이션을 완료하는 데 필요한 시간을 줄일 수 있습니다. 이 큐의 크기를 확인하려면 [업그레이드 전에 배경 마이그레이션 확인](background_migrations.md)합니다.
- 다운타임 없는 업그레이드는 우아한 다시 로드 메커니즘 때문에 [Gitaly](#upgrade-gitaly-nodes)에 대해 수행할 수 있습니다. [Gitaly Cluster(Praefect)](#upgrade-gitaly-cluster-praefect-nodes) 구성 요소도 다운타임 없이 직접 업그레이드할 수 있습니다. 그러나 Linux 패키지는 Praefect 데이터베이스에 대해 HA 또는 다운타임 없는 지원을 제공하지 않습니다. 다운타임을 피하기 위해 타사 데이터베이스 솔루션이 필요합니다.
- [PostgreSQL 주요 버전 업그레이드](../administration/postgresql/replication_and_failover.md#near-zero-downtime-upgrade-of-postgresql-in-a-patroni-cluster)는 별도의 프로세스이며 다운타임 없는 업그레이드에 포함되지 않습니다. 더 작은 업그레이드는 포함됩니다.
- 다운타임 없는 업그레이드는 Linux 패키지로 배포한 주목할 만한 GitLab 구성 요소에 대해 지원됩니다. AWS RDS의 PostgreSQL 또는 GCP Memorystore의 Redis와 같이 지원되는 타사 서비스를 통해 선택 구성 요소를 배포한 경우 해당 서비스의 업그레이드는 표준 프로세스에 따라 별도로 수행해야 합니다.
- 일반적인 지침으로, 데이터양이 많을수록 업그레이드를 완료하는 데 더 많은 시간이 필요합니다. 테스트에서 10GB보다 작은 데이터베이스는 일반적으로 1시간 이상 걸리지 않아야 하지만 결과는 다를 수 있습니다.

### 업그레이드 순서 {#upgrade-order}

다운타임 없이 업그레이드할 구성 요소의 순서에 대해서는 역순 접근 방식을 사용해야 합니다:

1. 상태 저장 백엔드
1. 백엔드 종속 항목
1. 프론트엔드

배포 순서를 변경할 수 있지만 GitLab 애플리케이션 코드(예: Rails 및 Sidekiq)를 실행하는 구성 요소를 함께 배포해야 합니다. 가능하면 이러한 구성 요소가 주요 릴리스의 버전 업그레이드에 도입된 변경 사항에 대한 종속성이 없기 때문에 지원 인프라를 별도로 업그레이드합니다.

GitLab 구성 요소를 다음 순서로 업그레이드해야 합니다:

1. Consul
1. PostgreSQL
1. PgBouncer
1. Redis
1. Gitaly
1. Praefect
1. Rails
1. Sidekiq

## Consul, PostgreSQL, PgBouncer 및 Redis 노드 업그레이드 {#upgrade-consul-postgresql-pgbouncer-and-redis-nodes}

[Consul](../administration/consul.md), [PostgreSQL](../administration/postgresql/replication_and_failover.md), [PgBouncer](../administration/postgresql/pgbouncer.md) 및 [Redis](../administration/redis/replication_and_failover.md) 구성 요소는 모두 다운타임 없이 업그레이드하기 위한 동일한 기본 프로세스를 따릅니다.

각 구성 요소의 노드에서 업그레이드를 수행하려면:

1. `/etc/gitlab/skip-auto-reconfigure`에 빈 파일을 생성합니다. 이는 `gitlab-ctl reconfigure` 실행을 방지합니다. 이는 기본적으로 자동으로 GitLab을 중지하고, 모든 데이터베이스 마이그레이션을 실행하며, GitLab을 다시 시작합니다:

   ```shell
   sudo touch /etc/gitlab/skip-auto-reconfigure
   ```

1. [Linux 패키지를 사용하여 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 노드를 업그레이드합니다.
1. 최신 코드를 설정하려면 다시 구성하고 다시 시작합니다:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

   {{< tabs >}}

   {{< tab title="PostgreSQL 노드만 해당" >}}

   Consul 클라이언트를 먼저 다시 시작한 다음 다른 모든 서비스를 다시 시작하여 PostgreSQL 장애 조치가 우아하게 발생하도록 합니다:

   ```shell
   sudo gitlab-ctl restart consul
   sudo gitlab-ctl restart-except consul
   ```

   {{< /tab >}}

   {{< tab title="다른 모든 구성 요소 노드" >}}

   ```shell
   sudo gitlab-ctl restart
   ```

   {{< /tab >}}

   {{< /tabs >}}

## Gitaly 노드 업그레이드 {#upgrade-gitaly-nodes}

[Gitaly](../administration/gitaly/_index.md)는 업그레이드할 때와 동일한 핵심 프로세스를 따르지만 Gitaly 프로세스 자체는 재시작되지 않으며 가장 빠른 기회에 우아하게 다시 로드하기 위한 기본 제공 프로세스가 있다는 주요 차이점이 있습니다. 다른 구성 요소는 여전히 다시 시작해야 합니다.

이 프로세스는 Gitaly Sharded 및 Cluster 설정 모두에 적용됩니다. 각 Gitaly 노드에서 업그레이드를 수행하려면 다음 단계를 순차적으로 실행합니다:

1. `/etc/gitlab/skip-auto-reconfigure`에 빈 파일을 생성합니다. 이는 `gitlab-ctl reconfigure` 실행을 방지합니다. 이는 기본적으로 자동으로 GitLab을 중지하고, 모든 데이터베이스 마이그레이션을 실행하며, GitLab을 다시 시작합니다:

   ```shell
   sudo touch /etc/gitlab/skip-auto-reconfigure
   ```

1. [Linux 패키지를 사용하여 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 노드를 업그레이드합니다.
1. `reconfigure` 명령을 실행하여 최신 코드를 설정하고 Gitaly에 다음 기회에 우아하게 다시 로드하도록 지시합니다:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

1. Gitaly가 배포된 다른 구성 요소를 우아하게 다시 로드하는 동안에도 여전히 다시 시작해야 합니다:

   ```shell
   # Get a list of what other components have been deployed beside Gitaly
   sudo gitlab-ctl status

   # Restart each component except Gitaly. Example given for Consul, Node Exporter and Logrotate
   sudo gitlab-ctl restart consul node-exporter logrotate
   ```

### Gitaly Cluster(Praefect) 노드 업그레이드 {#upgrade-gitaly-cluster-praefect-nodes}

> [!note]
> 이 섹션은 Praefect 구성 요소에만 중점을 두고 있으며 [필요한 PostgreSQL 데이터베이스](../administration/gitaly/praefect/configure.md#postgresql)는 아닙니다. [GitLab Linux 패키지는 HA를 제공하지 않으며](https://gitlab.com/groups/gitlab-org/-/work_items/7814) 따라서 Praefect 데이터베이스에 대해서도 다운타임 없는 지원을 제공하지 않습니다. 다운타임을 피하기 위해 타사 데이터베이스 솔루션이 필요합니다.

Gitaly Cluster(Praefect) 설정의 경우 우아한 다시 로드를 사용하여 유사한 방식으로 Praefect를 배포하고 업그레이드해야 합니다.

> [!note]
> 업그레이드 프로세스는 새 Praefect 프로세스로의 우아한 인계를 시도합니다. 업그레이드 전에 시작한 기존의 장기 실행 Git 요청은 이 인계가 발생할 때 결국 삭제될 수 있습니다.

Gitaly Cluster(Praefect)를 사용하는 인스턴스를 업그레이드할 때 이 순서대로 구성 요소를 업그레이드합니다:

1. Praefect PostgreSQL 데이터베이스. Linux 패키지는 이 데이터베이스에 대해 HA를 제공하지 않으므로 타사 HA 데이터베이스 솔루션을 사용하지 않는 한 이 단계에서는 다운타임이 필요합니다.
1. Gitaly 노드. [Gitaly 업그레이드 단계](#upgrade-gitaly-nodes)를 사용하여 이러한 항목을 순차적으로 업그레이드합니다.
1. Praefect 노드. 아래에 설명된 대로 업그레이드합니다. 이는 데이터베이스 마이그레이션을 실행하는 배포 노드로 지정된 하나의 노드가 있습니다.

Praefect도 기존 데이터를 업그레이드하기 위해 데이터베이스 마이그레이션을 수행해야 합니다. 충돌을 피하기 위해 마이그레이션은 하나의 Praefect 노드에서만 실행해야 합니다. 이를 수행하려면 **Praefect 배포 노드**를 지정하여 마이그레이션을 실행합니다:

1. **Praefect 배포 노드**에서:
   1. `/etc/gitlab/skip-auto-reconfigure`에 빈 파일을 생성합니다. 이는 `gitlab-ctl reconfigure` 실행을 방지합니다. 이는 기본적으로 자동으로 GitLab을 중지하고, 모든 데이터베이스 마이그레이션을 실행하며, GitLab을 다시 시작합니다:

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. [Linux 패키지를 사용하여 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 노드를 업그레이드합니다.
   1. `praefect['auto_migrate'] = true`이 `/etc/gitlab/gitlab.rb`에 설정되어 있는지 확인하여 데이터베이스 마이그레이션이 실행되도록 합니다.
   1. `reconfigure` 명령을 실행하여 최신 코드를 설정하고, Praefect 데이터베이스 마이그레이션을 적용하고, 우아하게 다시 시작합니다:

      ```shell
      sudo gitlab-ctl reconfigure
      ```

   1. 계속 진행하기 전에 모든 Praefect 데이터베이스 마이그레이션이 적용되었는지 확인합니다:

      ```shell
      sudo -u git -- /opt/gitlab/embedded/bin/praefect -config /var/opt/gitlab/praefect/config.toml sql-migrate-status
      ```

      모든 마이그레이션이 적용됨으로 표시되어야 합니다. 이것이 확인될 때까지 남은 Praefect 노드로 진행하지 마십시오.

1. 모든 **남은 Praefect 노드**에서:
   1. `/etc/gitlab/skip-auto-reconfigure`에 빈 파일을 생성합니다. 이는 `gitlab-ctl reconfigure` 실행을 방지합니다. 이는 기본적으로 자동으로 GitLab을 중지하고, 모든 데이터베이스 마이그레이션을 실행하며, GitLab을 다시 시작합니다:

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. [Linux 패키지를 사용하여 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 노드를 업그레이드합니다.
   1. `praefect['auto_migrate'] = false`이 `/etc/gitlab/gitlab.rb`에 설정되어 있는지 확인하여 `reconfigure`가 자동으로 데이터베이스 마이그레이션을 실행하지 않도록 합니다.
   1. `reconfigure` 명령을 실행하여 최신 코드를 설정하고 우아하게 다시 시작합니다:

      ```shell
      sudo gitlab-ctl reconfigure
      ```

1. Praefect가 우아하게 다시 로드되는 동안 배포된 다른 구성 요소도 여전히 다시 시작해야 합니다. 모든 **Praefect 노드**에서:

   ```shell
   # Get a list of what other components have been deployed beside Praefect
   sudo gitlab-ctl status

   # Restart each component except Praefect. Example given for Consul, Node Exporter and Logrotate
   sudo gitlab-ctl restart consul node-exporter logrotate
   ```

## GitLab 애플리케이션(Rails) 노드 업그레이드 {#upgrade-gitlab-application-rails-nodes}

웹 서버로서의 Rails는 주로 [Puma](../administration/operations/puma.md), Workhorse 및 NGINX로 구성됩니다.

이러한 각 구성 요소는 라이브 업그레이드를 수행할 때 다양한 동작을 합니다. Puma는 우아한 다시 로드를 허용할 수 있지만 Workhorse는 그렇지 않습니다. 가장 좋은 방법은 로드 밸런서를 사용하는 것과 같은 다른 수단을 통해 노드를 우아하게 드레인하는 것입니다. 노드에서 NGINX를 사용하여 우아한 종료 기능을 통해 이를 수행할 수도 있습니다. 이 섹션에서는 NGINX 접근 방식을 설명합니다.

앞의 내용 외에 Rails는 주요 데이터베이스 마이그레이션을 실행해야 하는 위치입니다. Praefect와 마찬가지로 배포 노드를 사용하는 것이 가장 좋은 방법입니다. PgBouncer가 현재 사용 중인 경우 Rails가 마이그레이션을 실행하려고 할 때 조언 잠금을 사용하여 같은 데이터베이스에서 실행되는 동시 마이그레이션을 방지하므로 이를 우회해야 합니다. 이러한 잠금은 트랜잭션 전체에서 공유되지 않으므로 `ActiveRecord::ConcurrentMigrationError` 및 기타 문제가 발생하여 트랜잭션 풀링 모드에서 PgBouncer를 사용하여 데이터베이스 마이그레이션을 실행할 때 발생합니다.

1. **Rails 배포 노드**에서:
   1. 노드의 트래픽을 우아하게 드레인합니다. 이를 수행하는 방법은 여러 가지가 있지만 한 가지 방법은 NGINX를 사용하여 `QUIT` 신호를 보낸 다음 서비스를 중지하는 것입니다. 예를 들어 다음 셸 스크립트를 사용하여 이를 수행할 수 있습니다:

      ```shell
      # Send QUIT to NGINX master process to drain and exit
      NGINX_PID=$(cat /var/opt/gitlab/nginx/nginx.pid)
      kill -QUIT $NGINX_PID

      # Wait for drain to complete
      while kill -0 $NGINX_PID 2>/dev/null; do sleep 1; done

      # Stop NGINX service to prevent automatic restarts
      gitlab-ctl stop nginx
      ```

   1. `/etc/gitlab/skip-auto-reconfigure`에 빈 파일을 생성합니다. 이는 `gitlab-ctl reconfigure` 실행을 방지합니다. 이는 기본적으로 자동으로 GitLab을 중지하고, 모든 데이터베이스 마이그레이션을 실행하며, GitLab을 다시 시작합니다:

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 GitLab을 업그레이드합니다.
   1. `gitlab_rails['auto_migrate'] = true`을 `/etc/gitlab/gitlab.rb` 구성 파일에 설정하여 정기적인 마이그레이션을 실행하도록 구성합니다.
      - 배포 노드가 PgBouncer를 통해 데이터베이스에 도달하는 경우 [이를 우회](../administration/postgresql/pgbouncer.md#procedure-for-bypassing-pgbouncer)하고 마이그레이션을 실행하기 전에 데이터베이스 리더에 직접 연결해야 합니다.
      - 데이터베이스 리더를 찾으려면 모든 데이터베이스 노드에서 다음 명령을 실행합니다:

        ```shell
        sudo gitlab-ctl patroni members
        ```

   1. 정기적인 마이그레이션을 실행하고 최신 코드를 설정합니다:

      ```shell
      sudo SKIP_POST_DEPLOYMENT_MIGRATIONS=true gitlab-ctl reconfigure
      ```

   1. 이 노드를 현재 상태로 두었다가 나중에 배포 후 마이그레이션을 실행하러 돌아갑니다.
1. 모든 **다른 Rails 노드**에서 순차적으로:
   1. 노드의 트래픽을 우아하게 드레인합니다. 이를 수행하는 방법은 여러 가지가 있지만 한 가지 방법은 NGINX를 사용하여 `QUIT` 신호를 보낸 다음 서비스를 중지하는 것입니다. 예를 들어 다음 셸 스크립트를 사용하여 이를 수행할 수 있습니다:

      ```shell
      # Send QUIT to NGINX master process to drain and exit
      NGINX_PID=$(cat /var/opt/gitlab/nginx/nginx.pid)
      kill -QUIT $NGINX_PID

      # Wait for drain to complete
      while kill -0 $NGINX_PID 2>/dev/null; do sleep 1; done

      # Stop NGINX service to prevent automatic restarts
      gitlab-ctl stop nginx
      ```

   1. `/etc/gitlab/skip-auto-reconfigure`에 빈 파일을 생성합니다. 이는 `gitlab-ctl reconfigure` 실행을 방지합니다. 이는 기본적으로 자동으로 GitLab을 중지하고, 모든 데이터베이스 마이그레이션을 실행하며, GitLab을 다시 시작합니다:

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 GitLab을 업그레이드합니다.
   1. `gitlab_rails['auto_migrate'] = false`이 `/etc/gitlab/gitlab.rb`에 설정되어 있는지 확인하여 `reconfigure`가 자동으로 데이터베이스 마이그레이션을 실행하지 않도록 합니다.
   1. `reconfigure` 명령을 실행하여 최신 코드를 설정하고 다시 시작합니다:

      ```shell
      sudo gitlab-ctl reconfigure
      sudo gitlab-ctl restart
      ```

1. **Rails 배포 노드**에서 배포 후 마이그레이션을 실행합니다:
   1. 배포 노드가 여전히 데이터베이스 리더를 직접 가리키고 있는지 확인합니다. 노드가 PgBouncer를 통해 데이터베이스에 도달하는 경우 [이를 우회](../administration/postgresql/pgbouncer.md#procedure-for-bypassing-pgbouncer)하고 마이그레이션을 실행하기 전에 데이터베이스 리더에 직접 연결해야 합니다. 데이터베이스 리더를 찾으려면 모든 데이터베이스 노드에서 다음 명령을 실행합니다:

      ```shell
      sudo gitlab-ctl patroni members
      ```

   1. 배포 후 마이그레이션을 실행합니다:

      ```shell
      sudo gitlab-rake gitlab:db:configure
      ```

      이 작업은 또한 ClickHouse 마이그레이션을 실행하고 스키마를 로드하여 데이터베이스의 상태를 기반으로 데이터베이스를 구성합니다.

   1. `gitlab_rails['auto_migrate'] = false`을 `/etc/gitlab/gitlab.rb` 구성 파일에 설정하여 구성을 정상으로 돌립니다. PgBouncer를 사용하는 경우 데이터베이스 구성을 다시 가리키도록 설정해야 합니다.
   1. 다시 한 번 다시 구성을 실행하여 정상 구성을 다시 적용하고 다시 시작합니다:

      ```shell
      sudo gitlab-ctl reconfigure
      sudo gitlab-ctl restart
      ```

## Sidekiq 노드 업그레이드 {#upgrade-sidekiq-nodes}

[Sidekiq](../administration/sidekiq/_index.md)는 다운타임 없이 업그레이드하기 위해 다른 항목과 동일한 기본 프로세스를 따릅니다.

각 구성 요소 노드에서 업그레이드를 수행하려면 다음 단계를 순차적으로 실행합니다:

1. `/etc/gitlab/skip-auto-reconfigure`에 빈 파일을 생성합니다. 이는 `gitlab-ctl reconfigure` 실행을 방지합니다. 이는 기본적으로 자동으로 GitLab을 중지하고, 모든 데이터베이스 마이그레이션을 실행하며, GitLab을 다시 시작합니다:

   ```shell
   sudo touch /etc/gitlab/skip-auto-reconfigure
   ```

1. [Linux 패키지를 사용하여 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 노드를 업그레이드합니다.
1. `reconfigure` 명령을 실행하여 최신 코드를 설정하고 다시 시작합니다:

   ```shell
   sudo gitlab-ctl reconfigure
   sudo gitlab-ctl restart
   ```

## 다중 노드 Geo 인스턴스 업그레이드 {#upgrade-multi-node-geo-instances}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

이 섹션에서는 Geo를 사용하여 라이브 GitLab 환경 배포를 업그레이드하는 데 필요한 단계를 설명합니다.

전반적으로 접근 방식은 일반적인 프로세스와 대체로 유사하며 각 보조 사이트에 필요한 추가 단계가 있습니다. 필요한 순서는 기본을 먼저 업그레이드한 다음 보조를 업그레이드하는 것입니다. 모든 보조가 업데이트된 후 기본에서 배포 후 마이그레이션을 실행해야 합니다.

> [!note]
> 동일한 [요구 사항](#requirements) 및 [고려 사항](#considerations)이 Geo를 사용하여 라이브 GitLab 환경을 업그레이드하는 데 적용됩니다.

### 기본 사이트 {#primary-site}

기본 사이트의 업그레이드 프로세스는 모든 보조가 업데이트된 후 배포 후 마이그레이션을 실행하지 않는다는 점을 제외하고는 일반 프로세스와 동일합니다.

기본 사이트에 대해 설명된 대로 동일한 단계를 실행하지만 Rails 노드 단계에서 배포 후 마이그레이션 실행에서 중지합니다.

### 보조 사이트 {#secondary-sites}

보조 사이트의 업그레이드 프로세스는 Rails 노드를 제외한 일반 프로세스와 동일한 단계를 따릅니다. 업그레이드 프로세스는 기본 및 보조 사이트의 경우 동일합니다. 그러나 보조 사이트의 Rails 노드에 대해 다음 추가 단계를 수행해야 합니다.

#### Rails {#rails}

1. **Rails 배포 노드**에서:
   1. 노드의 트래픽을 우아하게 드레인합니다. 이를 수행하는 방법은 여러 가지가 있지만 한 가지 방법은 NGINX를 사용하여 `QUIT` 신호를 보낸 다음 서비스를 중지하는 것입니다. 예를 들어 다음 셸 스크립트를 사용하여 이를 수행할 수 있습니다:

      ```shell
      # Send QUIT to NGINX master process to drain and exit
      NGINX_PID=$(cat /var/opt/gitlab/nginx/nginx.pid)
      kill -QUIT $NGINX_PID

      # Wait for drain to complete
      while kill -0 $NGINX_PID 2>/dev/null; do sleep 1; done

      # Stop NGINX service to prevent automatic restarts
      gitlab-ctl stop nginx
      ```

   1. Geo Log Cursor 프로세스를 중지하여 다른 노드로 장애 조치되도록 합니다:

      ```shell
      gitlab-ctl stop geo-logcursor
      ```

   1. `/etc/gitlab/skip-auto-reconfigure`에 빈 파일을 생성합니다. 이는 `gitlab-ctl reconfigure` 실행을 방지합니다. 이는 기본적으로 자동으로 GitLab을 중지하고, 모든 데이터베이스 마이그레이션을 실행하며, GitLab을 다시 시작합니다:

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 GitLab을 업그레이드합니다.
   1. `/etc/gitlab/gitlab-secrets.json` 파일을 기본 사이트 Rails 노드에서 보조 사이트 Rails 노드로 복사합니다(다른 경우). 파일은 사이트의 모든 노드에서 동일해야 합니다.
   1. `gitlab_rails['auto_migrate'] = false` 및 `geo_secondary['auto_migrate'] = false`을 `/etc/gitlab/gitlab.rb` 구성 파일에 설정하여 자동으로 실행되도록 구성된 마이그레이션이 없는지 확인합니다.
   1. `reconfigure` 명령을 실행하여 최신 코드를 설정하고 다시 시작합니다:

      ```shell
      sudo gitlab-ctl reconfigure
      sudo gitlab-ctl restart
      ```

   1. 정기적인 Geo 추적 마이그레이션을 실행하고 최신 코드를 설정합니다:

      ```shell
      sudo SKIP_POST_DEPLOYMENT_MIGRATIONS=true gitlab-rake db:migrate:geo
      ```

1. 모든 **다른 Rails 노드**에서 순차적으로:
   1. 노드의 트래픽을 우아하게 드레인합니다. 이를 수행하는 방법은 여러 가지가 있지만 한 가지 방법은 NGINX를 사용하여 `QUIT` 신호를 보낸 다음 서비스를 중지하는 것입니다. 예를 들어 다음 셸 스크립트를 사용하여 이를 수행할 수 있습니다:

      ```shell
      # Send QUIT to NGINX master process to drain and exit
      NGINX_PID=$(cat /var/opt/gitlab/nginx/nginx.pid)
      kill -QUIT $NGINX_PID

      # Wait for drain to complete
      while kill -0 $NGINX_PID 2>/dev/null; do sleep 1; done

      # Stop NGINX service to prevent automatic restarts
      gitlab-ctl stop nginx
      ```

   1. Geo Log Cursor 프로세스를 중지하여 다른 노드로 장애 조치되도록 합니다:

      ```shell
      gitlab-ctl stop geo-logcursor
      ```

   1. `/etc/gitlab/skip-auto-reconfigure`에 빈 파일을 생성합니다. 이는 `gitlab-ctl reconfigure` 실행을 방지합니다. 이는 기본적으로 자동으로 GitLab을 중지하고, 모든 데이터베이스 마이그레이션을 실행하며, GitLab을 다시 시작합니다:

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 GitLab을 업그레이드합니다.
   1. `gitlab_rails['auto_migrate'] = false` 및 `geo_secondary['auto_migrate'] = false`을 `/etc/gitlab/gitlab.rb` 구성 파일에 설정하여 자동으로 실행되도록 구성된 마이그레이션이 없는지 확인합니다.
   1. `reconfigure` 명령을 실행하여 최신 코드를 설정하고 다시 시작합니다:

      ```shell
      sudo gitlab-ctl reconfigure
      sudo gitlab-ctl restart
      ```

#### Sidekiq {#sidekiq}

주요 프로세스를 따르면 이제 남은 것은 Sidekiq을 업그레이드하는 것입니다.

Sidekiq을 [주요 섹션에 설명된 것과 동일한 방식](#sidekiq)으로 업그레이드합니다.

### 배포 후 마이그레이션 {#post-deployment-migrations}

마지막으로 기본 사이트로 돌아가 배포 후 마이그레이션을 실행하여 업그레이드를 완료합니다:

1. 기본 사이트의 **Rails 배포 노드**에서 배포 후 마이그레이션을 실행합니다:

   1. 배포 노드가 여전히 데이터베이스 리더를 직접 가리키고 있는지 확인합니다. 노드가 PgBouncer를 통해 데이터베이스에 도달하는 경우 [이를 우회](../administration/postgresql/pgbouncer.md#procedure-for-bypassing-pgbouncer)하고 마이그레이션을 실행하기 전에 데이터베이스 리더에 직접 연결해야 합니다. 데이터베이스 리더를 찾으려면 모든 데이터베이스 노드에서 다음 명령을 실행합니다:

      ```shell
      sudo gitlab-ctl patroni members
      ```

   1. 배포 후 마이그레이션을 실행합니다:

      ```shell
      sudo gitlab-rake gitlab:db:configure
      ```

   1. Geo 구성 및 종속성 확인

      ```shell
      sudo gitlab-rake gitlab:geo:check
      ```

   1. `gitlab_rails['auto_migrate'] = false`을 `/etc/gitlab/gitlab.rb` 구성 파일에 설정하여 구성을 정상으로 돌립니다. PgBouncer를 사용하는 경우 데이터베이스 구성을 다시 가리키도록 설정해야 합니다.
   1. 다시 한 번 다시 구성을 실행하여 정상 구성을 다시 적용하고 다시 시작합니다:

      ```shell
      sudo gitlab-ctl reconfigure
      sudo gitlab-ctl restart
      ```

1. 보조 사이트의 **Rails 배포 노드**에서 배포 후 Geo 추적 마이그레이션을 실행합니다:
   1. 배포 후 Geo 추적 마이그레이션을 실행합니다:

      ```shell
      sudo gitlab-rake db:migrate:geo
      ```

   1. Geo 상태 확인:

       ```shell
       sudo gitlab-rake gitlab:geo:status
       ```
