---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Conseils pour l'utilisation de services cloud managés pour les composants GitLab."
title: Utiliser des services cloud pour les composants GitLab
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Au lieu de gérer PostgreSQL, Redis/Valkey et le stockage d'objets vous-même, vous pouvez utiliser des services de fournisseur cloud managés à la place.

> [!note]
> Pour les déploiements cloud-native utilisant le chart Helm GitLab, les services PostgreSQL et Redis/Valkey externes sont obligatoires. Ces composants ne sont pas inclus dans le chart.

## Utiliser PostgreSQL cloud managé {#use-managed-cloud-postgresql}

Utilisez un service PostgreSQL externe exécutant une [version prise en charge](requirements.md#postgresql). Pour les instructions de configuration, consultez [l'utilisation d'une base de données PostgreSQL externe](../administration/postgresql/external.md).

Seuls les déploiements PostgreSQL complets sont pris en charge. Les services qui implémentent le protocole réseau PostgreSQL mais ne constituent pas des déploiements PostgreSQL complets, tels que [Amazon Aurora](https://aws.amazon.com/rds/aurora/) et [Google AlloyDB](https://cloud.google.com/alloydb), sont incompatibles avec GitLab.

Les services dont le fonctionnement est avéré incluent :

- [Google Cloud SQL](https://cloud.google.com/sql/docs/postgres/high-availability#normal)
- [Amazon RDS](https://aws.amazon.com/rds/)
- [Azure Database pour PostgreSQL Flexible Server](https://azure.microsoft.com/en-gb/products/postgresql/)

### Performances et haute disponibilité {#performance-and-high-availability}

Pour les environnements de plus grande taille, activez [l'équilibrage de charge de base de données](../administration/postgresql/database_load_balancing.md) avec des réplicas en lecture. Faites correspondre le nombre de réplicas à ceux utilisés dans les déploiements équivalents de packages Linux. Lorsque vous utilisez des réplicas en lecture, assurez-vous que tous les nœuds réplicas ont `hot_standby_feedback = on` pour éviter l'accumulation du décalage de réplication.

Pour GCP Cloud SQL dans les environnements de plus grande taille, utilisez l'[édition Enterprise Plus](https://cloud.google.com/sql/docs/editions-intro) pour des performances optimales.

> [!note]
> GCP Cloud SQL ne prend pas en charge `statement_timeout` en tant qu'indicateur de base de données. Définissez-le par base de données ou par utilisateur à la place : `ALTER DATABASE gitlab SET statement_timeout = '60s';`

### GitLab Geo {#gitlab-geo}

[GitLab Geo](../administration/geo/_index.md) nécessite une réplication PostgreSQL inter-régions entre les sites principal et secondaire. Tous les services de base de données managés ne prennent pas en charge cette fonctionnalité.

Limitations connues :

- Cluster Amazon RDS Multi-AZ DB : la réplication inter-régions n'est pas prise en charge. Utilisez plutôt une [instance RDS Multi-AZ DB](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZSingleStandby.html) standard avec un réplica en lecture inter-régions.
- GCP Cloud SQL : les réplicas en lecture pour Geo ne peuvent être créés que dans le même VPC et le même projet GCP. Pour les sites secondaires dans un projet différent, Cloud SQL ne peut pas créer le réplica directement. Configurez la [réplication logique PostgreSQL manuellement](https://cloud.google.com/sql/docs/postgres/replication/configure-external-replica), puis suivez la [configuration PostgreSQL externe de GitLab Geo](../administration/geo/setup/external_database.md).

### Regroupement de connexions {#connection-pooling}

Si votre charge de travail nécessite un regroupement de connexions supplémentaire au-delà de ce que PostgreSQL gère directement, déployez votre propre instance PgBouncer. Configurez PgBouncer pour :

- Utiliser une méthode d'authentification prise en charge par votre service de base de données, telle que [`auth_file`](https://www.pgbouncer.org/config.html#auth_file).
- S'exécuter en [mode de regroupement par transaction](../administration/postgresql/pgbouncer.md#pooling-mode).

N'utilisez pas le PgBouncer inclus dans le package Linux. Le PgBouncer inclus est [pris en charge uniquement avec PostgreSQL géré par le package Linux](../administration/postgresql/pgbouncer.md#authentication).

Les solutions de regroupement managées par les fournisseurs suivantes ne sont pas recommandées :

- AWS RDS Proxy : non validé pour une utilisation avec GitLab.
- Azure Database pour PostgreSQL PgBouncer : monothread avec une observabilité limitée. Peut provoquer des goulots d'étranglement sous charge.

## Utiliser Redis et Valkey cloud managés {#use-managed-cloud-redis-and-valkey}

Utilisez un service Redis ou Valkey externe exécutant une [version prise en charge](requirements.md#redis-or-valkey). Pour les instructions de configuration, consultez [Redis en tant que service managé](../administration/redis/replication_and_failover_external.md#redis-as-a-managed-service-in-a-cloud-provider).

Le service doit prendre en charge :

- Le mode autonome (primaire avec réplica), et non le mode Redis Cluster
- La haute disponibilité par réplication
- Une [politique d'éviction](../administration/redis/replication_and_failover_external.md#setting-the-eviction-policy) configurable

> [!note]
> Les variantes Redis et Valkey sans serveur ne sont pas prises en charge.

Les services dont le fonctionnement est avéré incluent :

- [Google Memorystore](https://cloud.google.com/memorystore)
- [Amazon ElastiCache pour Valkey](https://aws.amazon.com/elasticache/)

> [!note]
> Sur AWS, utilisez ElastiCache pour Valkey 7.2. ElastiCache pour Redis 7.2 n'est pas disponible sur AWS. ElastiCache pour Redis 7.1 est basé sur Redis 7.0 OSS et n'est pas recommandé pour les nouveaux déploiements. Ni [Azure Cache pour Redis](https://azure.microsoft.com/en-gb/products/cache) ni [Azure Managed Redis](https://azure.microsoft.com/en-gb/products/managed-redis) n'offrent actuellement Redis 7.2 ou une version Valkey prise en charge. Pour les déploiements Azure, gérez vous-même Redis ou Valkey sur une machine virtuelle.

Pour les environnements de plus grande taille, exécutez des instances Redis séparées pour le cache et les données persistantes. Redis est monothread et une instance partagée unique devient un goulot d'étranglement à grande échelle.

## Utiliser le stockage d'objets cloud managé {#use-managed-cloud-object-storage}

Utilisez tout service de stockage d'objets compatible S3. Pour la liste complète des fournisseurs testés et les détails de configuration, consultez [le stockage d'objets](../administration/object_storage.md).
