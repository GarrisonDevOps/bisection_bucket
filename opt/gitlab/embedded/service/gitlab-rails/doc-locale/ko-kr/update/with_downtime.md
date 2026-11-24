---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 다운타임을 사용하여 다중 노드 인스턴스 업그레이드
description: 다운타임을 사용하여 다중 노드 Linux 패키지 기반 또는 클라우드 네이티브 인스턴스를 업그레이드합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

다운타임을 사용하여 다중 노드 GitLab 인스턴스를 업그레이드하려면:

1. GitLab 애플리케이션을 종료합니다.
1. Consul 서버를 업그레이드합니다.
1. Gitaly, Rails, PostgreSQL, Redis, 그리고 PgBouncer를 임의의 순서로 업그레이드합니다. 클라우드 플랫폼에서 PostgreSQL 또는 Redis를 사용하고 업그레이드가 필요한 경우 이 지침을 클라우드 공급자의 지침으로 대체합니다.
1. GitLab 애플리케이션(Sidekiq, Puma)을 업그레이드하고 애플리케이션을 시작합니다.

다운타임 업그레이드를 시작하기 전에 [다운타임 옵션을 고려](downtime_options.md)하세요.

## GitLab 애플리케이션 종료 {#shut-down-the-gitlab-application}

업그레이드하기 전에 GitLab 애플리케이션을 종료하여 데이터베이스에 대한 쓰기를 중지해야 합니다. 프로세스는 [설치 방법](../administration/reference_architectures/_index.md)에 따라 다릅니다.

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

이 프로세스를 실행하는 모든 서버에서 Puma 및 Sidekiq을 종료합니다:

```shell
sudo gitlab-ctl stop sidekiq
sudo gitlab-ctl stop puma
```

{{< /tab >}}

{{< tab title="Helm 차트(Kubernetes)" >}}

[Helm chart](../administration/reference_architectures/_index.md#cloud-native-hybrid) 인스턴스의 경우:

1. 후속 재시작을 위해 데이터베이스 클라이언트의 현재 복제본 수를 기록합니다:

```shell
kubectl get deploy -n <namespace> -l release=<helm release name> -l 'app in (prometheus,webservice,sidekiq)' -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.replicas}{"\n"}{end}'
```

1. 데이터베이스의 클라이언트를 중지합니다:

```shell
kubectl scale deploy -n <namespace> -l release=<helm release name> -l 'app in (prometheus,webservice,sidekiq)' --replicas=0
```

{{< /tab >}}

{{< /tabs >}}

## Consul 노드 업그레이드 {#upgrade-the-consul-nodes}

[Consul 노드 업그레이드](../administration/consul.md#upgrade-the-consul-nodes) 지침을 따릅니다. 요약하면:

1. Consul 노드가 모두 정상 상태인지 확인합니다.
1. [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 모든 Consul 서버를 업그레이드합니다.
1. 한 번에 한 노드씩 모든 GitLab 서비스를 재시작합니다:

   ```shell
   sudo gitlab-ctl restart
   ```

Consul 클러스터 프로세스가 자신의 서버에 있지 않을 수 있으며 Redis HA 또는 Patroni 같은 다른 서비스와 공유될 수 있습니다. 이 경우 해당 서버를 업그레이드할 때:

- 한 번에 한 서버씩만 서비스를 재시작합니다.
- 서비스를 업그레이드하거나 재시작하기 전에 Consul 클러스터가 정상 상태인지 확인합니다.

## Gitaly 및 Gitaly Cluster (Praefect) 업그레이드 {#upgrade-gitaly-and-gitaly-cluster-praefect}

Gitaly Cluster (Praefect)의 일부가 아닌 Gitaly 서버의 경우 [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 서버를 업그레이드합니다. 여러 Gitaly 샤드가 있는 경우 Gitaly 서버를 임의의 순서로 업그레이드할 수 있습니다.

Gitaly Cluster (Praefect)를 실행 중인 경우 구성 요소를 다음 순서로 업그레이드해야 합니다:

1. Praefect PostgreSQL 데이터베이스. 다음을 사용하는 경우:
   - Linux 패키지의 경우 이 단계는 Git 작업에 대한 다운타임이 필요합니다.
   - 타사 HA 데이터베이스 솔루션의 경우 이 단계는 다운타임 없이 수행할 수 있습니다.
1. Gitaly 노드. [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 순차적으로 업그레이드합니다.
1. Praefect 노드. [Praefect 업그레이드 단계](zero_downtime.md#upgrade-gitaly-cluster-praefect-nodes)를 따르고 하나의 노드를 데이터베이스 마이그레이션을 실행할 배포 노드로 지정합니다.

### Amazon Machine Images 사용 {#when-using-amazon-machine-images}

AWS에서 Amazon Machine Images (AMIs)를 사용하는 경우 AMI 재배포 프로세스를 사용하여 Gitaly 노드를 업그레이드할 수 있습니다. 이 프로세스를 사용하려면 [Elastic network interfaces (ENIs)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html)를 사용해야 합니다. Gitaly Cluster (Praefect)는 서버 호스트명으로 Git 리포지토리의 복제본을 추적합니다. ENI는 인스턴스를 재배포할 때 프라이빗 DNS 이름이 동일하게 유지되도록 할 수 있습니다. 노드가 새 호스트명으로 재배포되는 경우 스토리지가 동일하더라도 Gitaly Cluster (Praefect)는 작동할 수 없습니다.

ENI를 사용하지 않는 경우 Linux 패키지를 사용하여 Gitaly 노드를 업그레이드해야 합니다.

AMI 재배포 프로세스를 사용하여 Gitaly Cluster (Praefect) 노드를 업그레이드하려면:

1. AMI 재배포 프로세스는 `gitlab-ctl reconfigure`를 포함해야 합니다. AMI에서 `praefect['auto_migrate'] = false`를 설정하여 모든 노드가 이 설정을 적용받도록 합니다. 이 설정은 `reconfigure`이 데이터베이스 마이그레이션을 자동으로 실행하지 않도록 방지합니다.
1. 업그레이드된 이미지로 재배포할 첫 번째 노드가 배포 노드여야 합니다.
1. 배포된 후 `praefect['auto_migrate'] = true`을 `gitlab.rb`에서 설정하고 `gitlab-ctl reconfigure`으로 적용합니다.
1. 이 명령은 데이터베이스 마이그레이션을 실행합니다.
1. 다른 Gitaly Cluster (Praefect) 노드를 재배포합니다.

## PostgreSQL 노드 업그레이드 {#upgrade-the-postgresql-nodes}

Patroni (HA PostgreSQL) 구성을 사용 중인 경우 이 섹션을 건너뛰고 대신 [Patroni 노드 업그레이드](#upgrade-patroni-nodes) 단계를 따릅니다.

클러스터되지 않은 PostgreSQL 서버의 경우:

1. [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 서버를 업그레이드합니다.
1. 업그레이드 프로세스는 바이너리가 업그레이드될 때 PostgreSQL을 재시작하지 않으므로 새 버전을 로드하려면 재시작합니다:

   ```shell
   sudo gitlab-ctl restart
   ```

### Patroni 노드 업그레이드 {#upgrade-patroni-nodes}

Patroni는 PostgreSQL을 통한 고가용성을 달성하는 데 사용됩니다.

PostgreSQL 주 버전 업그레이드가 필요한 경우 [주 버전 프로세스를 따릅니다](../administration/postgresql/replication_and_failover.md#upgrading-postgresql-major-version-in-a-patroni-cluster).

다른 모든 버전의 업그레이드 프로세스는 먼저 모든 복제본에서 수행됩니다. 복제본이 업그레이드되면 업그레이드된 복제본 중 하나로 리더에서 클러스터 페일오버가 발생합니다. 이 프로세스는 하나의 페일오버만 필요하도록 보장하며 완료되면 새 리더가 업그레이드됩니다.

Patroni 노드를 업그레이드하려면:

1. 리더 및 복제본 노드를 식별하고 [클러스터가 정상 상태인지 확인](../administration/postgresql/replication_and_failover.md#check-replication-status)합니다. 데이터베이스 노드에서 다음을 실행합니다:

   ```shell
   sudo gitlab-ctl patroni members
   ```

1. [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 복제본 노드 중 하나를 업그레이드합니다.
1. 새 버전을 로드하려면 재시작합니다:

   ```shell
   sudo gitlab-ctl restart
   ```

1. [클러스터가 정상 상태인지 확인](../administration/postgresql/replication_and_failover.md#check-replication-status)합니다.
1. 다른 복제본에 대해 업그레이드, 재시작 및 상태 확인 단계를 반복합니다.
1. 복제본과 동일한 Linux 패키지 업그레이드를 따라 리더 노드를 업그레이드합니다.
1. 새 버전을 로드하고 클러스터 페일오버를 트리거하기 위해 리더 노드의 모든 서비스를 재시작합니다:

   ```shell
   sudo gitlab-ctl restart
   ```

1. [클러스터가 정상 상태인지 확인](../administration/postgresql/replication_and_failover.md#check-replication-status)합니다

## PgBouncer 노드 업그레이드 {#upgrade-the-pgbouncer-nodes}

GitLab 애플리케이션(Rails) 노드에서 PgBouncer를 실행하는 경우 PgBouncer는 애플리케이션 서버 업그레이드의 일부로 업그레이드됩니다. 그렇지 않으면 [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 PgBouncer 노드를 업그레이드합니다.

## Redis 노드 업그레이드 {#upgrade-the-redis-node}

독립 실행형 Redis 서버를 업그레이드하려면 [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)합니다.

### Redis HA (Sentinel 사용) 업그레이드 {#upgrade-redis-ha-using-sentinel}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

Redis HA를 사용하는 경우 [무중단 지침](zero_downtime.md)을 따라 Redis HA 클러스터를 업그레이드합니다.

## GitLab 애플리케이션(Rails) 노드 업그레이드 {#upgrade-the-gitlab-application-rails-nodes}

[참조 아키텍처](../administration/reference_architectures/_index.md)에서 이는 _Rails 노드_입니다. 이들은 첫 번째 단계에서 종료된 Puma 프로세스를 실행합니다. 이 노드들을 업그레이드하는 프로세스는 설치 방법에 따라 다릅니다.

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

모든 Puma 및 Sidekiq 프로세스는 이전에 종료되었습니다. 각 GitLab 애플리케이션(Rails) 노드에서:

1. `/etc/gitlab/skip-auto-reconfigure`이 존재하지 않는지 확인합니다.
1. Puma와 Sidekiq이 실행 중이 아닌지 확인합니다:

   ```shell
   ps -ef | egrep 'puma: | puma | sidekiq '
   ```

하나의 Rails 노드를 _배포 노드_로 선택하여 모든 데이터베이스 마이그레이션을 실행할 책임을 집니다. 배포 노드에서:

1. 서버가 정상적인 마이그레이션을 허용하도록 구성되어 있는지 확인합니다. `/etc/gitlab/gitlab.rb`이 `gitlab_rails['auto_migrate'] = false`를 포함하지 않는지 확인합니다. `gitlab_rails['auto_migrate'] = true`로 구체적으로 설정하거나 기본 동작(`true`)의 경우 생략합니다.
1. PgBouncer를 사용하는 경우 마이그레이션을 실행하기 전에 PgBouncer를 우회하고 PostgreSQL에 직접 연결해야 합니다.

   Rails는 마이그레이션을 실행할 때 자문 잠금을 사용하여 동일한 데이터베이스에서 동시 마이그레이션이 실행되지 않도록 방지합니다. 이러한 잠금은 트랜잭션 간에 공유되지 않으므로 트랜잭션 풀링 모드에서 PgBouncer를 사용하여 데이터베이스 마이그레이션을 실행할 때 `ActiveRecord::ConcurrentMigrationError` 오류 및 기타 문제가 발생합니다.

   1. Patroni를 실행 중인 경우 리더 노드를 찾습니다. 데이터베이스 노드에서 실행합니다:

      ```shell
      sudo gitlab-ctl patroni members
      ```

   1. 배포 노드에서 `gitlab.rb`을 업데이트합니다. `gitlab_rails['db_host']`와 `gitlab_rails['db_port']`를 다음 중 하나로 변경합니다:

      - 데이터베이스 서버의 호스트 및 포트(클러스터되지 않은 PostgreSQL).
      - Patroni를 실행하는 경우 클러스터 리더의 호스트 및 포트.
   1. 변경 사항을 적용합니다:

      ```shell
      sudo gitlab-ctl reconfigure
      ```

1. [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 GitLab을 업그레이드합니다.
1. 데이터베이스 마이그레이션이 성공적으로 완료되었는지 확인하려면 다음을 실행합니다:

   ```shell
   sudo gitlab-rake db:migrate:status
   ```

   모든 마이그레이션이 완료될 때까지 나머지 Rails 노드를 업그레이드하지 마십시오.

1. PgBouncer를 우회하기 위해 배포 노드에서 `gitlab.rb`을 수정한 경우:
   1. 배포 노드에서 `gitlab.rb`을 업데이트합니다. `gitlab_rails['db_host']`와 `gitlab_rails['db_port']`를 PgBouncer 설정으로 다시 변경합니다.
   1. 변경 사항을 적용합니다:

      ```shell
      sudo gitlab-ctl reconfigure
      ```

1. 모든 서비스가 업그레이드된 버전을 실행하고 있으며 (해당하는 경우) PgBouncer를 사용하여 데이터베이스에 액세스하도록 하려면 배포 노드의 모든 서비스를 재시작합니다:

   ```shell
   sudo gitlab-ctl restart
   ```

다음으로 다른 모든 Puma 및 Sidekiq 노드를 업그레이드합니다. `gitlab_rails['auto_migrate']` 설정은 이 노드의 `gitlab.rb`에서 아무 값으로나 설정할 수 있습니다.

이들은 병렬로 업그레이드할 수 있습니다:

1. [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하여 GitLab을 업그레이드합니다.
1. 모든 서비스가 재시작되었는지 확인합니다:

   ```shell
   sudo gitlab-ctl restart
   ```

{{< /tab >}}

{{< tab title="Helm 차트(Kubernetes)" >}}

모든 상태 유지 구성 요소가 업그레이드된 후 [GitLab chart 업그레이드 단계](https://docs.gitlab.com/charts/installation/upgrade/)를 따라 상태 비저장 구성 요소(Webservice, Sidekiq, 기타 지원 서비스)를 업그레이드합니다.

GitLab chart 업그레이드를 수행한 후 데이터베이스 클라이언트를 다시 시작합니다:

```shell
kubectl scale deploy -lapp=sidekiq,release=<helm release name> -n <namespace> --replicas=<value>
kubectl scale deploy -lapp=webservice,release=<helm release name> -n <namespace> --replicas=<value>
kubectl scale deploy -lapp=prometheus,release=<helm release name> -n <namespace> --replicas=<value>
```

{{< /tab >}}

{{< /tabs >}}

## 모니터 노드 업그레이드 {#upgrade-the-monitor-node}

Prometheus를 독립 실행형 모니터링 노드로 구성했을 수 있습니다. 예를 들어 [60 RPS 또는 3,000 사용자 참조 아키텍처 구성](../administration/reference_architectures/3k_users.md#configure-prometheus)의 일부로 구성할 수 있습니다.

모니터 노드를 업그레이드하려면 [Linux 패키지로 업그레이드](package/_index.md#upgrade-with-the-linux-package)하세요.
