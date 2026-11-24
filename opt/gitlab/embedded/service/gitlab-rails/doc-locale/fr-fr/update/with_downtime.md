---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Mettre à niveau une instance multi-nœuds avec temps d'arrêt"
description: "Mettre à niveau une instance multi-nœuds basée sur un package Linux ou native du cloud avec temps d'arrêt."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Pour mettre à niveau une instance GitLab multi-nœuds avec temps d'arrêt :

1. Arrêtez l'application GitLab.
1. Mettez à niveau les serveurs Consul.
1. Mettez à niveau Gitaly, Rails, PostgreSQL, Redis et PgBouncer dans n'importe quel ordre. Si vous utilisez PostgreSQL ou Redis depuis votre plateforme cloud et que des mises à niveau sont requises, remplacez ces instructions par celles de votre fournisseur cloud.
1. Mettez à niveau l'application GitLab (Sidekiq, Puma) et démarrez l'application.

Avant de commencer une mise à niveau avec temps d'arrêt, [examinez vos options de temps d'arrêt](downtime_options.md).

## Arrêter l'application GitLab {#shut-down-the-gitlab-application}

Avant la mise à niveau, vous devez arrêter les écritures dans la base de données en arrêtant l'application GitLab. Le processus est différent selon votre [méthode d'installation](../administration/reference_architectures/_index.md).

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

Arrêtez Puma et Sidekiq sur tous les serveurs exécutant ces processus :

```shell
sudo gitlab-ctl stop sidekiq
sudo gitlab-ctl stop puma
```

{{< /tab >}}

{{< tab title="Chart Helm (Kubernetes)" >}}

Pour les instances [chart Helm](../administration/reference_architectures/_index.md#cloud-native-hybrid) :

1. Notez le nombre actuel de réplicas pour les clients de base de données pour le redémarrage ultérieur :

```shell
kubectl get deploy -n <namespace> -l release=<helm release name> -l 'app in (prometheus,webservice,sidekiq)' -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.replicas}{"\n"}{end}'
```

1. Arrêtez les clients de la base de données :

```shell
kubectl scale deploy -n <namespace> -l release=<helm release name> -l 'app in (prometheus,webservice,sidekiq)' --replicas=0
```

{{< /tab >}}

{{< /tabs >}}

## Mettre à niveau les nœuds Consul {#upgrade-the-consul-nodes}

Suivez les instructions pour [mettre à niveau les nœuds Consul](../administration/consul.md#upgrade-the-consul-nodes). En résumé :

1. Vérifiez que tous les nœuds Consul sont sains.
1. Mettez à niveau tous les serveurs Consul en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
1. Redémarrez tous les services GitLab sur un nœud à la fois :

   ```shell
   sudo gitlab-ctl restart
   ```

Les processus de votre cluster Consul ne sont peut-être pas sur leurs propres serveurs et sont partagés avec un autre service tel que Redis HA ou Patroni. Dans ce cas, lors de la mise à niveau de ces serveurs :

- Redémarrez les services sur un seul serveur à la fois.
- Vérifiez que le cluster Consul est sain avant de mettre à niveau ou de redémarrer les services.

## Mettre à niveau Gitaly et Gitaly Cluster (Praefect) {#upgrade-gitaly-and-gitaly-cluster-praefect}

Pour les serveurs Gitaly qui ne font pas partie de Gitaly Cluster (Praefect), mettez à niveau le serveur en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package). Si vous avez plusieurs shards Gitaly, vous pouvez mettre à niveau les serveurs Gitaly dans n'importe quel ordre.

Si vous exécutez Gitaly Cluster (Praefect), les composants doivent être mis à niveau dans l'ordre suivant :

1. Base de données PostgreSQL de Praefect. Si vous utilisez :
   - Le package Linux, cette étape nécessite un temps d'arrêt pour les opérations Git.
   - Une solution de base de données HA tierce, cette étape peut être effectuée sans temps d'arrêt.
1. Nœuds Gitaly. Effectuez la mise à niveau de manière séquentielle en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
1. Nœuds Praefect. Suivez les [étapes de mise à niveau de Praefect](zero_downtime.md#upgrade-gitaly-cluster-praefect-nodes), en désignant un nœud comme nœud de déploiement pour exécuter les migrations de base de données.

### Lors de l'utilisation d'Amazon Machine Images {#when-using-amazon-machine-images}

Si vous utilisez des Amazon Machine Images (AMI) sur AWS, vous pouvez mettre à niveau les nœuds Gitaly à l'aide d'un processus de redéploiement AMI. Pour utiliser ce processus, vous devez utiliser des [interfaces réseau élastiques (ENI)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html). Gitaly Cluster (Praefect) suit les réplicas des dépôts Git par le nom d'hôte du serveur. Les ENI peuvent garantir que le nom DNS privé reste le même lorsque l'instance est redéployée. Si les nœuds sont redéployés avec de nouveaux noms d'hôte, même si le stockage est identique, Gitaly Cluster (Praefect) ne peut pas fonctionner.

Si vous n'utilisez pas d'ENI, vous devez mettre à niveau les nœuds Gitaly à l'aide du package Linux.

Pour mettre à niveau les nœuds Gitaly Cluster (Praefect) à l'aide d'un processus de redéploiement AMI :

1. Le processus de redéploiement AMI doit inclure `gitlab-ctl reconfigure`. Définissez `praefect['auto_migrate'] = false` sur l'AMI afin que tous les nœuds appliquent ce paramètre. Ce paramètre empêche `reconfigure` d'exécuter automatiquement les migrations de base de données.
1. Le premier nœud à être redéployé avec l'image mise à niveau doit être votre nœud de déploiement.
1. Une fois déployé, définissez `praefect['auto_migrate'] = true` dans `gitlab.rb` et appliquez avec `gitlab-ctl reconfigure`.
1. Cette commande exécute les migrations de base de données.
1. Redéployez vos autres nœuds Gitaly Cluster (Praefect).

## Mettre à niveau les nœuds PostgreSQL {#upgrade-the-postgresql-nodes}

Si vous utilisez une configuration Patroni (HA PostgreSQL), ignorez cette section et suivez les étapes de la section [Mettre à niveau les nœuds Patroni](#upgrade-patroni-nodes) à la place.

Pour les serveurs PostgreSQL non clusterisés :

1. Mettez à niveau le serveur en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
1. Étant donné que le processus de mise à niveau ne redémarre pas PostgreSQL lorsque les binaires sont mis à niveau, redémarrez pour charger la nouvelle version :

   ```shell
   sudo gitlab-ctl restart
   ```

### Mettre à niveau les nœuds Patroni {#upgrade-patroni-nodes}

Patroni est utilisé pour assurer la haute disponibilité avec PostgreSQL.

Si une mise à niveau de version majeure de PostgreSQL est requise, [suivez le processus de version majeure](../administration/postgresql/replication_and_failover.md#upgrading-postgresql-major-version-in-a-patroni-cluster).

Le processus de mise à niveau pour toutes les autres versions est d'abord effectué sur tous les réplicas. Une fois les réplicas mis à niveau, un basculement de cluster se produit du leader vers l'un des réplicas mis à niveau. Ce processus garantit qu'un seul basculement est nécessaire et, une fois terminé, le nouveau leader est mis à niveau.

Pour mettre à niveau les nœuds Patroni :

1. Identifiez les nœuds leader et réplica, et [vérifiez que le cluster est sain](../administration/postgresql/replication_and_failover.md#check-replication-status). Sur un nœud de base de données, exécutez :

   ```shell
   sudo gitlab-ctl patroni members
   ```

1. Mettez à niveau l'un des nœuds réplicas en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
1. Redémarrez pour charger la nouvelle version :

   ```shell
   sudo gitlab-ctl restart
   ```

1. [Vérifiez que le cluster est sain](../administration/postgresql/replication_and_failover.md#check-replication-status).
1. Répétez les étapes de mise à niveau, de redémarrage et de vérification de l'état pour les autres réplicas.
1. Mettez à niveau le nœud leader en suivant la même procédure de mise à niveau du package Linux que pour les réplicas.
1. Redémarrez tous les services sur le nœud leader pour charger la nouvelle version et déclencher également un basculement de cluster :

   ```shell
   sudo gitlab-ctl restart
   ```

1. [Vérifiez que le cluster est sain](../administration/postgresql/replication_and_failover.md#check-replication-status)

## Mettre à niveau les nœuds PgBouncer {#upgrade-the-pgbouncer-nodes}

Si vous exécutez PgBouncer sur vos nœuds d'application GitLab (Rails), PgBouncer est mis à niveau dans le cadre de la mise à niveau du serveur d'application. Sinon, mettez à niveau les nœuds PgBouncer en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).

## Mettre à niveau le nœud Redis {#upgrade-the-redis-node}

Pour mettre à niveau un serveur Redis autonome, [effectuez la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).

### Mettre à niveau Redis HA (avec Sentinel) {#upgrade-redis-ha-using-sentinel}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Si vous utilisez Redis HA, suivez [les instructions de mise à niveau sans temps d'arrêt](zero_downtime.md) pour mettre à niveau votre cluster Redis HA.

## Mettre à niveau les nœuds de l'application GitLab (Rails) {#upgrade-the-gitlab-application-rails-nodes}

Dans les [architectures de référence](../administration/reference_architectures/_index.md), ce sont les _nœuds Rails_. Ils exécutent les processus Puma qui ont été arrêtés lors de la première étape. Le processus de mise à niveau de ces nœuds dépend de votre méthode d'installation.

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

Tous les processus Puma et Sidekiq ont été précédemment arrêtés. Sur chaque nœud d'application GitLab (Rails) :

1. Vérifiez que `/etc/gitlab/skip-auto-reconfigure` n'existe pas.
1. Vérifiez que Puma et Sidekiq ne sont pas en cours d'exécution :

   ```shell
   ps -ef | egrep 'puma: | puma | sidekiq '
   ```

Sélectionnez un nœud Rails comme _nœud de déploiement_, responsable de l'exécution de toutes les migrations de base de données. Sur le nœud de déploiement :

1. Assurez-vous que le serveur est configuré pour autoriser les migrations régulières. Vérifiez que `/etc/gitlab/gitlab.rb` ne contient pas `gitlab_rails['auto_migrate'] = false`. Définissez-le spécifiquement sur `gitlab_rails['auto_migrate'] = true` ou omettez-le pour le comportement par défaut (`true`).
1. Si vous utilisez PgBouncer, vous devez contourner PgBouncer et vous connecter directement à PostgreSQL avant d'exécuter les migrations.

   Rails utilise un verrou consultatif lors de l'exécution d'une migration pour empêcher les migrations simultanées de s'exécuter sur la même base de données. Ces verrous ne sont pas partagés entre les transactions, ce qui entraîne des erreurs `ActiveRecord::ConcurrentMigrationError` et d'autres problèmes lors de l'exécution des migrations de base de données avec PgBouncer en mode de regroupement de transactions.

   1. Si vous exécutez Patroni, trouvez le nœud leader. Exécutez sur un nœud de base de données :

      ```shell
      sudo gitlab-ctl patroni members
      ```

   1. Mettez à jour `gitlab.rb` sur le nœud de déploiement. Changez `gitlab_rails['db_host']` et `gitlab_rails['db_port']` vers l'une des options suivantes :

      - L'hôte et le port de votre serveur de base de données (PostgreSQL non clusterisé).
      - L'hôte et le port de votre leader de cluster si vous exécutez Patroni.
   1. Appliquez les modifications :

      ```shell
      sudo gitlab-ctl reconfigure
      ```

1. Mettez à niveau GitLab en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
1. Vérifiez que les migrations de base de données se sont terminées avec succès en exécutant :

   ```shell
   sudo gitlab-rake db:migrate:status
   ```

   Ne mettez pas à niveau les nœuds Rails restants avant que toutes les migrations soient terminées.

1. Si vous avez modifié `gitlab.rb` sur le nœud de déploiement pour contourner PgBouncer :
   1. Mettez à jour `gitlab.rb` sur le nœud de déploiement. Rétablissez `gitlab_rails['db_host']` et `gitlab_rails['db_port']` à vos paramètres PgBouncer.
   1. Appliquez les modifications :

      ```shell
      sudo gitlab-ctl reconfigure
      ```

1. Pour vous assurer que tous les services exécutent la version mise à niveau et (le cas échéant) accèdent à la base de données via PgBouncer, redémarrez tous les services sur le nœud de déploiement :

   ```shell
   sudo gitlab-ctl restart
   ```

Ensuite, mettez à niveau tous les autres nœuds Puma et Sidekiq. Le paramètre `gitlab_rails['auto_migrate']` peut être défini sur n'importe quelle valeur dans `gitlab.rb` sur ces nœuds.

Ils peuvent être mis à niveau en parallèle :

1. Mettez à niveau GitLab en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
1. Assurez-vous que tous les services sont redémarrés :

   ```shell
   sudo gitlab-ctl restart
   ```

{{< /tab >}}

{{< tab title="Chart Helm (Kubernetes)" >}}

Une fois tous les composants avec état mis à niveau, suivez les [étapes de mise à niveau du chart GitLab](https://docs.gitlab.com/charts/installation/upgrade/) pour mettre à niveau les composants sans état (Webservice, Sidekiq, autres services de support).

Après avoir effectué la mise à niveau du chart GitLab, reprenez les clients de base de données :

```shell
kubectl scale deploy -lapp=sidekiq,release=<helm release name> -n <namespace> --replicas=<value>
kubectl scale deploy -lapp=webservice,release=<helm release name> -n <namespace> --replicas=<value>
kubectl scale deploy -lapp=prometheus,release=<helm release name> -n <namespace> --replicas=<value>
```

{{< /tab >}}

{{< /tabs >}}

## Mettre à niveau le nœud de surveillance {#upgrade-the-monitor-node}

Vous avez peut-être configuré Prometheus pour agir comme un nœud de surveillance autonome. Par exemple, dans le cadre de la [configuration d'une architecture de référence à 60 RPS ou 3 000 utilisateurs](../administration/reference_architectures/3k_users.md#configure-prometheus).

Pour mettre à niveau le nœud de surveillance, [effectuez la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
