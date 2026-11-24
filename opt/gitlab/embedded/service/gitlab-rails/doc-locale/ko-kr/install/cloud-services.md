---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab 구성 요소에 관리형 클라우드 서비스를 사용하기 위한 지침입니다.
title: GitLab 구성 요소에 클라우드 서비스 사용
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

PostgreSQL, Redis/Valkey 및 객체 스토리지를 직접 관리하는 대신 관리형 클라우드 공급자 서비스를 사용할 수 있습니다.

> [!note]
> GitLab Helm 차트를 사용한 클라우드 네이티브 배포의 경우 외부 PostgreSQL 및 Redis/Valkey 서비스가 필요합니다. 이러한 구성 요소는 차트에 번들로 포함되지 않습니다.

## 관리형 클라우드 PostgreSQL {#use-managed-cloud-postgresql}

[지원되는 버전](requirements.md#postgresql)을 실행하는 외부 PostgreSQL 서비스를 사용합니다. 설정 지침은 [외부 PostgreSQL 데이터베이스 사용](../administration/postgresql/external.md)을 참고하세요.

완전한 PostgreSQL 배포만 지원됩니다. PostgreSQL 와이어 프로토콜을 구현하지만 완전한 PostgreSQL 배포가 아닌 서비스(예: [Amazon Aurora](https://aws.amazon.com/rds/aurora/) 및 [Google AlloyDB](https://cloud.google.com/alloydb))는 GitLab과 호환되지 않습니다.

알려진 작동하는 서비스는 다음과 같습니다:

- [Google Cloud SQL](https://cloud.google.com/sql/docs/postgres/high-availability#normal)
- [Amazon RDS](https://aws.amazon.com/rds/)
- [Azure Database for PostgreSQL Flexible Server](https://azure.microsoft.com/en-gb/products/postgresql/)

### 성능 및 고가용성 {#performance-and-high-availability}

대규모 환경의 경우 읽기 복제본을 사용하여 [데이터베이스 로드 밸런싱](../administration/postgresql/database_load_balancing.md)을 활성화합니다. 복제본 수를 동등한 Linux 패키지 배포에 사용되는 수와 일치시킵니다. 읽기 복제본을 사용할 때 모든 복제본 노드에 `hot_standby_feedback = on`이 있는지 확인하여 복제 지연 누적을 방지합니다.

GCP Cloud SQL을 대규모 환경에서 사용할 경우 최적의 성능을 위해 [Enterprise Plus 에디션](https://cloud.google.com/sql/docs/editions-intro)을 사용합니다.

> [!note]
> GCP Cloud SQL은 `statement_timeout`을 데이터베이스 플래그로 지원하지 않습니다. 대신 데이터베이스 또는 사용자별로 설정합니다: `ALTER DATABASE gitlab SET statement_timeout = '60s';`

### GitLab Geo {#gitlab-geo}

[GitLab Geo](../administration/geo/_index.md)는 기본 사이트와 보조 사이트 간의 교차 지역 PostgreSQL 복제가 필요합니다. 모든 관리형 데이터베이스 서비스가 이를 지원하는 것은 아닙니다.

알려진 제한 사항:

- Amazon RDS Multi-AZ DB 클러스터: 교차 지역 복제는 지원되지 않습니다. 대신 [RDS Multi-AZ DB 인스턴스](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZSingleStandby.html)를 교차 지역 읽기 복제본과 함께 사용합니다.
- GCP Cloud SQL: Geo의 읽기 복제본은 동일한 VPC 및 동일한 GCP 프로젝트 내에서만 생성할 수 있습니다. 다른 프로젝트의 보조 사이트의 경우 Cloud SQL은 복제본을 직접 생성할 수 없습니다. [PostgreSQL 논리적 복제를 수동으로 구성](https://cloud.google.com/sql/docs/postgres/replication/configure-external-replica)하고 [GitLab Geo 외부 PostgreSQL 설정](../administration/geo/setup/external_database.md)을 따릅니다.

### 연결 풀링 {#connection-pooling}

워크로드에 PostgreSQL이 직접 처리하는 것 이상의 추가 연결 풀링이 필요한 경우 자체 PgBouncer 인스턴스를 배포합니다. PgBouncer를 다음과 같이 구성합니다:

- 데이터베이스 서비스가 지원하는 인증 방법(예: [`auth_file`](https://www.pgbouncer.org/config.html#auth_file))을 사용합니다.
- [트랜잭션 풀링 모드](../administration/postgresql/pgbouncer.md#pooling-mode)에서 실행합니다.

Linux 패키지의 번들 PgBouncer를 사용하지 마십시오. 번들 PgBouncer는 [Linux 패키지로 관리되는 PostgreSQL에서만 지원](../administration/postgresql/pgbouncer.md#authentication)됩니다.

다음 공급자 관리형 풀링 솔루션은 권장되지 않습니다:

- AWS RDS Proxy: GitLab과 함께 사용하도록 검증되지 않았습니다.
- Azure Database for PostgreSQL PgBouncer: 단일 스레드이며 관찰 능력이 제한적입니다. 부하 시 병목 현상을 유발할 수 있습니다.

## 관리형 클라우드 Redis 및 Valkey 사용 {#use-managed-cloud-redis-and-valkey}

[지원되는 버전](requirements.md#redis-or-valkey)을 실행하는 외부 Redis 또는 Valkey 서비스를 사용합니다. 설정 지침은 [관리형 서비스인 Redis](../administration/redis/replication_and_failover_external.md#redis-as-a-managed-service-in-a-cloud-provider)를 참고하세요.

서비스는 다음을 지원해야 합니다:

- Redis Cluster 모드가 아닌 독립형(기본 복제본 포함) 모드
- 복제를 통한 고가용성
- 구성 가능한 [제거 정책](../administration/redis/replication_and_failover_external.md#setting-the-eviction-policy)

> [!note]
> 서버리스 Redis 및 Valkey 변형은 지원되지 않습니다.

알려진 작동하는 서비스는 다음과 같습니다:

- [Google Memorystore](https://cloud.google.com/memorystore)
- [Amazon ElastiCache for Valkey](https://aws.amazon.com/elasticache/)

> [!note]
> AWS에서 ElastiCache for Valkey 7.2를 사용합니다. ElastiCache for Redis 7.2는 AWS에서 사용할 수 없습니다. ElastiCache for Redis 7.1은 Redis 7.0 OSS를 기반으로 하며 새 배포에는 권장되지 않습니다. [Azure Cache for Redis](https://azure.microsoft.com/en-gb/products/cache) 및 [Azure Managed Redis](https://azure.microsoft.com/en-gb/products/managed-redis) 모두 현재 Redis 7.2 또는 지원되는 Valkey 버전을 제공하지 않습니다. Azure 배포의 경우 가상 머신에서 Redis 또는 Valkey를 자체 관리합니다.

대규모 환경의 경우 캐시 및 지속적 데이터에 대해 별도의 Redis 인스턴스를 실행합니다. Redis는 단일 스레드이며 단일 공유 인스턴스는 규모에 따라 병목 현상이 됩니다.

## 관리형 클라우드 객체 스토리지 사용 {#use-managed-cloud-object-storage}

S3 호환 객체 스토리지 서비스를 사용합니다. 테스트된 공급자 및 구성 세부 정보의 전체 목록은 [객체 스토리지](../administration/object_storage.md)를 참고하세요.
