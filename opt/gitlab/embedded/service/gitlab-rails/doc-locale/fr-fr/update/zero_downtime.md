---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Mettre à niveau une instance multi-nœuds sans interruption de service
description: Mettre à niveau une instance multi-nœuds basée sur le package Linux sans interruption de service.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Le processus de mise à niveau d'un environnement GitLab multi-nœuds sans interruption de service consiste à parcourir séquentiellement chaque nœud conformément à l'[ordre de mise à niveau](#upgrade-order). Les équilibreurs de charge et les mécanismes de haute disponibilité gèrent en conséquence l'arrêt de chaque nœud.

Avant de commencer une mise à niveau sans interruption de service, [examinez vos options d'interruption de service](downtime_options.md).

## Avant de commencer {#before-you-start}

Atteindre une continuité de service totale dans le cadre d'une mise à niveau est particulièrement difficile pour toute application distribuée. La documentation a été testée telle quelle par rapport à nos [architectures de référence](../administration/reference_architectures/_index.md) HA et n'a entraîné pratiquement aucune interruption de service observable. Notez cependant que les résultats peuvent varier selon la composition spécifique de votre système.

Pour plus de fiabilité, certains clients ont eu recours à d'autres techniques, comme le drainage manuel des nœuds à l'aide de fonctionnalités spécifiques de l'équilibreur de charge ou de l'infrastructure. Ces techniques dépendent fortement des capacités de l'infrastructure sous-jacente.

Pour toute information supplémentaire, contactez votre représentant GitLab ou l'[équipe d'assistance](https://support.gitlab.com/).

### Prérequis {#requirements}

Le processus de mise à niveau sans interruption de service nécessite un environnement GitLab multi-nœuds basé sur le package Linux, avec un équilibrage de charge et des mécanismes de haute disponibilité configurés comme suit :

- Équilibreur de charge externe configuré pour les nœuds d'application GitLab avec les vérifications d'état activées sur l'endpoint de [disponibilité](../administration/monitoring/health_check.md#readiness) (`/-/readiness`).
- Équilibreur de charge interne configuré pour les composants PgBouncer et Praefect, avec les vérifications d'état TCP activées.
- Mécanismes de haute disponibilité configurés pour les composants Consul, Postgres et Redis, le cas échéant.
  - Tout composant non déployé en mode haute disponibilité doit être mis à niveau séparément avec une interruption de service.
  - Pour les bases de données, le [package Linux prend en charge la haute disponibilité uniquement pour la base de données GitLab principale](https://gitlab.com/groups/gitlab-org/-/work_items/7814). Pour toute autre base de données, comme la [base de données Praefect](#upgrade-gitaly-cluster-praefect-nodes), une solution de base de données tierce est requise pour atteindre la haute disponibilité et, par conséquent, éviter toute interruption de service.

Pour les mises à niveau sans interruption de service, vous devez :

- Mettre à niveau une release mineure à la fois. Ainsi, passez de `16.1` à `16.2`, et non à `16.3`. Si vous sautez des releases, les modifications de base de données risquent d'être exécutées dans le mauvais ordre [et de laisser le schéma de base de données dans un état défaillant](https://gitlab.com/gitlab-org/gitlab/-/issues/321542).
- Utiliser les migrations post-déploiement.

### Considérations {#considerations}

Lorsque vous envisagez une mise à niveau sans interruption de service, tenez compte des points suivants :

- La plupart du temps, vous pouvez mettre à niveau en toute sécurité d'une release de correctif vers la release mineure suivante si la release de correctif n'est pas la plus récente. Par exemple, la mise à niveau de `16.3.2` vers `16.4.1` devrait être sûre même si `16.3.3` a été publiée. Vous devriez vérifier les [notes de mise à niveau spécifiques à la version](versions/_index.md) correspondant à votre [chemin de mise à niveau](upgrade_paths.md) et tenir compte des arrêts de mise à niveau obligatoires :
  - [Notes de mise à niveau GitLab 19](versions/gitlab_19_changes.md)
  - [Notes de mise à niveau GitLab 18](versions/gitlab_18_changes.md)
  - [Notes de mise à niveau GitLab 17](versions/gitlab_17_changes.md)
  - [Notes de mise à niveau GitLab 16](versions/gitlab_16_changes.md)
  - [Notes de mise à niveau GitLab 15](versions/gitlab_15_changes.md)
- Certaines releases peuvent inclure des migrations en arrière-plan. Ces migrations sont effectuées en arrière-plan par Sidekiq et sont souvent utilisées pour migrer des données. Les migrations en arrière-plan ne sont ajoutées que dans les releases mensuelles.
  - Certaines releases majeures ou mineures peuvent nécessiter qu'un ensemble de migrations en arrière-plan soit terminé. Bien que cela ne nécessite pas d'interruption de service (si les conditions précédentes sont remplies), vous devez attendre que les migrations en arrière-plan soient terminées entre chaque mise à niveau de release majeure ou mineure.
  - Le temps nécessaire pour effectuer ces migrations peut être réduit en augmentant le nombre de workers Sidekiq pouvant traiter des jobs dans la file d'attente `background_migration`. Pour connaître la taille de cette file d'attente, [vérifiez les migrations en arrière-plan avant la mise à niveau](background_migrations.md).
- Les mises à niveau sans interruption de service peuvent être effectuées pour [Gitaly](#upgrade-gitaly-nodes) grâce à un mécanisme de rechargement progressif. Le composant [Gitaly Cluster (Praefect)](#upgrade-gitaly-cluster-praefect-nodes) peut également être mis à niveau directement sans interruption de service. Cependant, le package Linux ne prend pas en charge la haute disponibilité ni la continuité de service pour la base de données Praefect. Une solution de base de données tierce est requise pour éviter toute interruption de service.
- Les [mises à niveau de version majeure PostgreSQL](../administration/postgresql/replication_and_failover.md#near-zero-downtime-upgrade-of-postgresql-in-a-patroni-cluster) constituent un processus distinct et ne sont pas couvertes par les mises à niveau sans interruption de service. Les mises à niveau mineures sont couvertes.
- Les mises à niveau sans interruption de service sont prises en charge pour les composants GitLab déployés avec le package Linux. Si vous avez déployé certains composants via un service tiers pris en charge, tel que PostgreSQL dans AWS RDS ou Redis dans GCP Memorystore, les mises à niveau de ces services doivent être effectuées séparément conformément à leurs processus standard.
- En règle générale, plus le volume de données est important, plus la mise à niveau prend du temps. Lors des tests, toute base de données inférieure à 10 Go ne devrait généralement pas prendre plus d'une heure, mais les résultats peuvent varier.

### Ordre de mise à niveau {#upgrade-order}

Vous devez adopter une approche de l'arrière vers l'avant pour déterminer l'ordre des composants à mettre à niveau sans interruption de service :

1. Backends avec état
1. Dépendances des backends
1. Frontends

Bien que vous puissiez modifier l'ordre de déploiement, vous devriez déployer ensemble les composants exécutant le code de l'application GitLab (par exemple, Rails et Sidekiq). Si possible, mettez à niveau séparément l'infrastructure de support, car ces composants ne dépendent pas des modifications introduites lors d'une mise à niveau de version pour une release majeure.

Vous devriez mettre à niveau les composants GitLab dans l'ordre suivant :

1. Consul
1. PostgreSQL
1. PgBouncer
1. Redis
1. Gitaly
1. Praefect
1. Rails
1. Sidekiq

## Mettre à niveau les nœuds Consul, PostgreSQL, PgBouncer et Redis {#upgrade-consul-postgresql-pgbouncer-and-redis-nodes}

Les composants [Consul](../administration/consul.md), [PostgreSQL](../administration/postgresql/replication_and_failover.md), [PgBouncer](../administration/postgresql/pgbouncer.md) et [Redis](../administration/redis/replication_and_failover.md) suivent tous le même processus sous-jacent pour la mise à niveau sans interruption de service.

Sur le nœud de chaque composant pour effectuer la mise à niveau :

1. Créez un fichier vide dans `/etc/gitlab/skip-auto-reconfigure`. Cela empêche les mises à niveau d'exécuter `gitlab-ctl reconfigure`, qui par défaut arrête automatiquement GitLab, exécute toutes les migrations de base de données et redémarre GitLab :

   ```shell
   sudo touch /etc/gitlab/skip-auto-reconfigure
   ```

1. Mettez à niveau le nœud en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
1. Reconfigurez et redémarrez pour mettre en place le code le plus récent :

   ```shell
   sudo gitlab-ctl reconfigure
   ```

   {{< tabs >}}

   {{< tab title="Pour les nœuds PostgreSQL uniquement" >}}

   Redémarrez d'abord le client Consul, puis redémarrez tous les autres services pour garantir que le basculement PostgreSQL se déroule correctement :

   ```shell
   sudo gitlab-ctl restart consul
   sudo gitlab-ctl restart-except consul
   ```

   {{< /tab >}}

   {{< tab title="Pour tous les autres nœuds de composants" >}}

   ```shell
   sudo gitlab-ctl restart
   ```

   {{< /tab >}}

   {{< /tabs >}}

## Mettre à niveau les nœuds Gitaly {#upgrade-gitaly-nodes}

[Gitaly](../administration/gitaly/_index.md) suit le même processus de base lors de la mise à niveau, à une différence clé près : le processus Gitaly lui-même n'est pas redémarré, car il dispose d'un mécanisme intégré pour effectuer un rechargement progressif à la première occasion. Les autres composants doivent tout de même être redémarrés.

Ce processus s'applique aux configurations Gitaly Sharded et Cluster. Effectuez les étapes suivantes séquentiellement sur chaque nœud Gitaly pour réaliser la mise à niveau :

1. Créez un fichier vide dans `/etc/gitlab/skip-auto-reconfigure`. Cela empêche les mises à niveau d'exécuter `gitlab-ctl reconfigure`, qui par défaut arrête automatiquement GitLab, exécute toutes les migrations de base de données et redémarre GitLab :

   ```shell
   sudo touch /etc/gitlab/skip-auto-reconfigure
   ```

1. Mettez à niveau le nœud en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
1. Exécutez la commande `reconfigure` pour mettre en place le code le plus récent et demander à Gitaly d'effectuer un rechargement progressif à la prochaine occasion :

   ```shell
   sudo gitlab-ctl reconfigure
   ```

1. Enfin, pendant que Gitaly effectue un rechargement progressif, tous les autres composants déployés nécessitent tout de même un redémarrage :

   ```shell
   # Get a list of what other components have been deployed beside Gitaly
   sudo gitlab-ctl status

   # Restart each component except Gitaly. Example given for Consul, Node Exporter and Logrotate
   sudo gitlab-ctl restart consul node-exporter logrotate
   ```

### Mettre à niveau les nœuds Gitaly Cluster (Praefect) {#upgrade-gitaly-cluster-praefect-nodes}

> [!note]
> Cette section se concentre exclusivement sur le composant Praefect, et non sur sa [base de données PostgreSQL requise](../administration/gitaly/praefect/configure.md#postgresql). Le [package Linux GitLab ne prend pas en charge la haute disponibilité](https://gitlab.com/groups/gitlab-org/-/work_items/7814) et, par conséquent, la continuité de service pour la base de données Praefect. Une solution de base de données tierce est requise pour éviter toute interruption de service.

Pour les configurations Gitaly Cluster (Praefect), vous devez déployer et mettre à niveau Praefect de manière similaire, en utilisant un rechargement progressif.

> [!note]
> Le processus de mise à niveau tente d'effectuer un transfert progressif vers un nouveau processus Praefect. Les requêtes Git de longue durée démarrées avant la mise à niveau peuvent finalement être abandonnées lors de ce transfert.

Lors de la mise à niveau d'une instance utilisant Gitaly Cluster (Praefect), mettez à niveau les composants dans cet ordre :

1. Base de données PostgreSQL de Praefect. Le package Linux ne prend pas en charge la haute disponibilité pour cette base de données. Cette étape nécessite donc une interruption de service, sauf si vous utilisez une solution de base de données haute disponibilité tierce.
1. Nœuds Gitaly. Mettez-les à niveau séquentiellement en suivant les [étapes de mise à niveau Gitaly](#upgrade-gitaly-nodes).
1. Nœuds Praefect. Effectuez la mise à niveau comme décrit ci-dessous, avec un nœud désigné comme nœud de déploiement exécutant les migrations de base de données.

Praefect doit également effectuer des migrations de base de données pour mettre à niveau les données existantes. Pour éviter les conflits, les migrations ne doivent s'exécuter que sur un seul nœud Praefect. Pour ce faire, désignez un **nœud de déploiement Praefect** qui exécute les migrations :

1. Sur le **nœud de déploiement Praefect** :
   1. Créez un fichier vide dans `/etc/gitlab/skip-auto-reconfigure`. Cela empêche les mises à niveau d'exécuter `gitlab-ctl reconfigure`, qui par défaut arrête automatiquement GitLab, exécute toutes les migrations de base de données et redémarre GitLab :

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. Mettez à niveau le nœud en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
   1. Assurez-vous que `praefect['auto_migrate'] = true` est défini dans `/etc/gitlab/gitlab.rb` afin que les migrations de base de données s'exécutent.
   1. Exécutez la commande `reconfigure` pour mettre en place le code le plus récent, appliquer les migrations de la base de données Praefect et redémarrer progressivement :

      ```shell
      sudo gitlab-ctl reconfigure
      ```

   1. Vérifiez que toutes les migrations de la base de données Praefect ont été appliquées avant de continuer :

      ```shell
      sudo -u git -- /opt/gitlab/embedded/bin/praefect -config /var/opt/gitlab/praefect/config.toml sql-migrate-status
      ```

      Toutes les migrations doivent apparaître comme appliquées. Ne passez pas aux nœuds Praefect restants tant que cela n'est pas confirmé.

1. Sur tous les **nœuds Praefect restants** :
   1. Créez un fichier vide dans `/etc/gitlab/skip-auto-reconfigure`. Cela empêche les mises à niveau d'exécuter `gitlab-ctl reconfigure`, qui par défaut arrête automatiquement GitLab, exécute toutes les migrations de base de données et redémarre GitLab :

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. Mettez à niveau le nœud en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
   1. Assurez-vous que `praefect['auto_migrate'] = false` est défini dans `/etc/gitlab/gitlab.rb` pour empêcher `reconfigure` d'exécuter automatiquement les migrations de base de données.
   1. Exécutez la commande `reconfigure` pour mettre en place le code le plus récent et redémarrer progressivement :

      ```shell
      sudo gitlab-ctl reconfigure
      ```

1. Enfin, pendant que Praefect effectue un rechargement progressif, tous les autres composants déployés nécessitent tout de même un redémarrage. Sur tous les **nœuds Praefect** :

   ```shell
   # Get a list of what other components have been deployed beside Praefect
   sudo gitlab-ctl status

   # Restart each component except Praefect. Example given for Consul, Node Exporter and Logrotate
   sudo gitlab-ctl restart consul node-exporter logrotate
   ```

## Mettre à niveau les nœuds de l'application GitLab (Rails) {#upgrade-gitlab-application-rails-nodes}

Rails, en tant que serveur web, est principalement composé de [Puma](../administration/operations/puma.md), Workhorse et NGINX.

Chacun de ces composants a un comportement différent lors d'une mise à niveau en direct. Bien que Puma puisse permettre un rechargement progressif, Workhorse ne le permet pas. La meilleure approche consiste à drainer le nœud progressivement par d'autres moyens, par exemple en utilisant votre équilibreur de charge. Vous pouvez également le faire en utilisant NGINX sur le nœud via sa fonctionnalité d'arrêt progressif. Cette section explique l'approche NGINX.

En plus de ce qui précède, Rails est l'endroit où les migrations principales de la base de données doivent être exécutées. Comme pour Praefect, la meilleure approche consiste à utiliser le nœud de déploiement. Si PgBouncer est actuellement utilisé, il doit également être contourné, car Rails utilise un verrou consultatif lors de l'exécution d'une migration pour empêcher l'exécution simultanée de migrations sur la même base de données. Ces verrous ne sont pas partagés entre les transactions, ce qui entraîne `ActiveRecord::ConcurrentMigrationError` et d'autres problèmes lors de l'exécution de migrations de base de données avec PgBouncer en mode de regroupement de transactions.

1. Sur le **nœud de déploiement Rails** :
   1. Drainer le trafic du nœud progressivement. Vous pouvez procéder de différentes manières, mais une approche consiste à utiliser NGINX en lui envoyant un signal `QUIT` puis en arrêtant le service. À titre d'exemple, vous pouvez utiliser le script shell suivant :

      ```shell
      # Send QUIT to NGINX master process to drain and exit
      NGINX_PID=$(cat /var/opt/gitlab/nginx/nginx.pid)
      kill -QUIT $NGINX_PID

      # Wait for drain to complete
      while kill -0 $NGINX_PID 2>/dev/null; do sleep 1; done

      # Stop NGINX service to prevent automatic restarts
      gitlab-ctl stop nginx
      ```

   1. Créez un fichier vide dans `/etc/gitlab/skip-auto-reconfigure`. Cela empêche les mises à niveau d'exécuter `gitlab-ctl reconfigure`, qui par défaut arrête automatiquement GitLab, exécute toutes les migrations de base de données et redémarre GitLab :

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. Mettez à niveau GitLab en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
   1. Configurez l'exécution des migrations régulières en définissant `gitlab_rails['auto_migrate'] = true` dans le fichier de configuration `/etc/gitlab/gitlab.rb`.
      - Si le nœud de déploiement passe par PgBouncer pour atteindre la base de données, vous devez [le contourner](../administration/postgresql/pgbouncer.md#procedure-for-bypassing-pgbouncer) et vous connecter directement au leader de la base de données avant d'exécuter les migrations.
      - Pour trouver le leader de la base de données, exécutez la commande suivante sur n'importe quel nœud de base de données :

        ```shell
        sudo gitlab-ctl patroni members
        ```

   1. Exécutez les migrations régulières et mettez en place le code le plus récent :

      ```shell
      sudo SKIP_POST_DEPLOYMENT_MIGRATIONS=true gitlab-ctl reconfigure
      ```

   1. Laissez ce nœud tel quel pour l'instant, car vous reviendrez exécuter les migrations post-déploiement ultérieurement.
1. Sur chaque **autre nœud Rails** séquentiellement :
   1. Drainer le trafic du nœud progressivement. Vous pouvez procéder de différentes manières, mais une approche consiste à utiliser NGINX en lui envoyant un signal `QUIT` puis en arrêtant le service. À titre d'exemple, vous pouvez utiliser le script shell suivant :

      ```shell
      # Send QUIT to NGINX master process to drain and exit
      NGINX_PID=$(cat /var/opt/gitlab/nginx/nginx.pid)
      kill -QUIT $NGINX_PID

      # Wait for drain to complete
      while kill -0 $NGINX_PID 2>/dev/null; do sleep 1; done

      # Stop NGINX service to prevent automatic restarts
      gitlab-ctl stop nginx
      ```

   1. Créez un fichier vide dans `/etc/gitlab/skip-auto-reconfigure`. Cela empêche les mises à niveau d'exécuter `gitlab-ctl reconfigure`, qui par défaut arrête automatiquement GitLab, exécute toutes les migrations de base de données et redémarre GitLab :

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. Mettez à niveau GitLab en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
   1. Assurez-vous que `gitlab_rails['auto_migrate'] = false` est défini dans `/etc/gitlab/gitlab.rb` pour empêcher `reconfigure` d'exécuter automatiquement les migrations de base de données.
   1. Exécutez la commande `reconfigure` pour mettre en place le code le plus récent et redémarrer :

      ```shell
      sudo gitlab-ctl reconfigure
      sudo gitlab-ctl restart
      ```

1. Sur le **nœud de déploiement Rails**, exécutez les migrations post-déploiement :
   1. Assurez-vous que le nœud de déploiement pointe toujours directement vers le leader de la base de données. Si le nœud passe par PgBouncer pour atteindre la base de données, vous devez [le contourner](../administration/postgresql/pgbouncer.md#procedure-for-bypassing-pgbouncer) et vous connecter directement au leader de la base de données avant d'exécuter les migrations. Pour trouver le leader de la base de données, exécutez la commande suivante sur n'importe quel nœud de base de données :

      ```shell
      sudo gitlab-ctl patroni members
      ```

   1. Exécutez les migrations post-déploiement :

      ```shell
      sudo gitlab-rake gitlab:db:configure
      ```

      Cette tâche exécute également les migrations ClickHouse et configure la base de données en fonction de son état en chargeant le schéma.

   1. Rétablissez la configuration normale en définissant `gitlab_rails['auto_migrate'] = false` dans le fichier de configuration `/etc/gitlab/gitlab.rb`. Si PgBouncer est utilisé, assurez-vous de reconfigurer la base de données pour qu'elle pointe à nouveau vers celui-ci.
   1. Effectuez à nouveau la reconfiguration pour réappliquer la configuration normale et redémarrer :

      ```shell
      sudo gitlab-ctl reconfigure
      sudo gitlab-ctl restart
      ```

## Mettre à niveau les nœuds Sidekiq {#upgrade-sidekiq-nodes}

[Sidekiq](../administration/sidekiq/_index.md) suit le même processus sous-jacent que les autres composants pour la mise à niveau sans interruption de service.

Effectuez les étapes suivantes séquentiellement sur chaque nœud de composant pour réaliser la mise à niveau :

1. Créez un fichier vide dans `/etc/gitlab/skip-auto-reconfigure`. Cela empêche les mises à niveau d'exécuter `gitlab-ctl reconfigure`, qui par défaut arrête automatiquement GitLab, exécute toutes les migrations de base de données et redémarre GitLab :

   ```shell
   sudo touch /etc/gitlab/skip-auto-reconfigure
   ```

1. Mettez à niveau le nœud en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
1. Exécutez la commande `reconfigure` pour mettre en place le code le plus récent et redémarrer :

   ```shell
   sudo gitlab-ctl reconfigure
   sudo gitlab-ctl restart
   ```

## Mettre à niveau les instances Geo multi-nœuds {#upgrade-multi-node-geo-instances}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Cette section décrit les étapes requises pour mettre à niveau un environnement GitLab en production avec Geo.

Dans l'ensemble, l'approche est largement similaire au processus normal, avec quelques étapes supplémentaires requises pour chaque site secondaire. L'ordre requis est de mettre à niveau le site principal en premier, puis les sites secondaires. Vous devez également exécuter toutes les migrations post-déploiement sur le site principal après la mise à niveau de tous les sites secondaires.

> [!note]
> Les mêmes [exigences](#requirements) et [considérations](#considerations) s'appliquent pour la mise à niveau d'un environnement GitLab en production avec Geo.

### Site principal {#primary-site}

Le processus de mise à niveau du site principal est identique au processus normal, à une exception près : ne pas exécuter les migrations post-déploiement tant que tous les sites secondaires n'ont pas été mis à jour.

Suivez les mêmes étapes pour le site principal comme décrit, mais arrêtez-vous à l'étape du nœud Rails consistant à exécuter les migrations post-déploiement.

### Sites secondaires {#secondary-sites}

Le processus de mise à niveau des sites secondaires suit les mêmes étapes que le processus normal, à l'exception des nœuds Rails. Le processus de mise à niveau est identique pour les sites principal et secondaires. Cependant, vous devez effectuer les étapes supplémentaires suivantes pour les nœuds Rails sur les sites secondaires.

#### Rails {#rails}

1. Sur le **nœud de déploiement Rails** :
   1. Drainer le trafic du nœud progressivement. Vous pouvez procéder de différentes manières, mais une approche consiste à utiliser NGINX en lui envoyant un signal `QUIT` puis en arrêtant le service. À titre d'exemple, vous pouvez utiliser le script shell suivant :

      ```shell
      # Send QUIT to NGINX master process to drain and exit
      NGINX_PID=$(cat /var/opt/gitlab/nginx/nginx.pid)
      kill -QUIT $NGINX_PID

      # Wait for drain to complete
      while kill -0 $NGINX_PID 2>/dev/null; do sleep 1; done

      # Stop NGINX service to prevent automatic restarts
      gitlab-ctl stop nginx
      ```

   1. Arrêtez le processus Geo Log Cursor pour vous assurer qu'il bascule vers un autre nœud :

      ```shell
      gitlab-ctl stop geo-logcursor
      ```

   1. Créez un fichier vide dans `/etc/gitlab/skip-auto-reconfigure`. Cela empêche les mises à niveau d'exécuter `gitlab-ctl reconfigure`, qui par défaut arrête automatiquement GitLab, exécute toutes les migrations de base de données et redémarre GitLab :

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. Mettez à niveau GitLab en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
   1. Copiez le fichier `/etc/gitlab/gitlab-secrets.json` depuis le nœud Rails du site principal vers le nœud Rails du site secondaire s'ils sont différents. Le fichier doit être identique sur tous les nœuds d'un site.
   1. Assurez-vous qu'aucune migration n'est configurée pour s'exécuter automatiquement en définissant `gitlab_rails['auto_migrate'] = false` et `geo_secondary['auto_migrate'] = false` dans le fichier de configuration `/etc/gitlab/gitlab.rb`.
   1. Exécutez la commande `reconfigure` pour mettre en place le code le plus récent et redémarrer :

      ```shell
      sudo gitlab-ctl reconfigure
      sudo gitlab-ctl restart
      ```

   1. Exécutez les migrations Geo Tracking régulières et mettez en place le code le plus récent :

      ```shell
      sudo SKIP_POST_DEPLOYMENT_MIGRATIONS=true gitlab-rake db:migrate:geo
      ```

1. Sur chaque **autre nœud Rails** séquentiellement :
   1. Drainer le trafic du nœud progressivement. Vous pouvez procéder de différentes manières, mais une approche consiste à utiliser NGINX en lui envoyant un signal `QUIT` puis en arrêtant le service. À titre d'exemple, vous pouvez utiliser le script shell suivant :

      ```shell
      # Send QUIT to NGINX master process to drain and exit
      NGINX_PID=$(cat /var/opt/gitlab/nginx/nginx.pid)
      kill -QUIT $NGINX_PID

      # Wait for drain to complete
      while kill -0 $NGINX_PID 2>/dev/null; do sleep 1; done

      # Stop NGINX service to prevent automatic restarts
      gitlab-ctl stop nginx
      ```

   1. Arrêtez le processus Geo Log Cursor pour vous assurer qu'il bascule vers un autre nœud :

      ```shell
      gitlab-ctl stop geo-logcursor
      ```

   1. Créez un fichier vide dans `/etc/gitlab/skip-auto-reconfigure`. Cela empêche les mises à niveau d'exécuter `gitlab-ctl reconfigure`, qui par défaut arrête automatiquement GitLab, exécute toutes les migrations de base de données et redémarre GitLab :

      ```shell
      sudo touch /etc/gitlab/skip-auto-reconfigure
      ```

   1. Mettez à niveau GitLab en [effectuant la mise à niveau avec le package Linux](package/_index.md#upgrade-with-the-linux-package).
   1. Assurez-vous qu'aucune migration n'est configurée pour s'exécuter automatiquement en définissant `gitlab_rails['auto_migrate'] = false` et `geo_secondary['auto_migrate'] = false` dans le fichier de configuration `/etc/gitlab/gitlab.rb`.
   1. Exécutez la commande `reconfigure` pour mettre en place le code le plus récent et redémarrer :

      ```shell
      sudo gitlab-ctl reconfigure
      sudo gitlab-ctl restart
      ```

#### Sidekiq {#sidekiq}

Une fois le processus principal terminé, il ne reste plus qu'à mettre à niveau Sidekiq.

Mettez à niveau Sidekiq [de la même manière que décrit dans la section principale](#sidekiq).

### Migrations post-déploiement {#post-deployment-migrations}

Enfin, revenez au site principal et terminez la mise à niveau en exécutant les migrations post-déploiement :

1. Sur le **nœud de déploiement Rails** du site principal, exécutez les migrations post-déploiement :

   1. Assurez-vous que le nœud de déploiement pointe toujours directement vers le leader de la base de données. Si le nœud passe par PgBouncer pour atteindre la base de données, vous devez [le contourner](../administration/postgresql/pgbouncer.md#procedure-for-bypassing-pgbouncer) et vous connecter directement au leader de la base de données avant d'exécuter les migrations. Pour trouver le leader de la base de données, exécutez la commande suivante sur n'importe quel nœud de base de données :

      ```shell
      sudo gitlab-ctl patroni members
      ```

   1. Exécutez les migrations post-déploiement :

      ```shell
      sudo gitlab-rake gitlab:db:configure
      ```

   1. Vérifiez la configuration et les dépendances Geo

      ```shell
      sudo gitlab-rake gitlab:geo:check
      ```

   1. Rétablissez la configuration normale en définissant `gitlab_rails['auto_migrate'] = false` dans le fichier de configuration `/etc/gitlab/gitlab.rb`. Si PgBouncer est utilisé, assurez-vous de reconfigurer la base de données pour qu'elle pointe à nouveau vers celui-ci.
   1. Effectuez à nouveau la reconfiguration pour réappliquer la configuration normale et redémarrer :

      ```shell
      sudo gitlab-ctl reconfigure
      sudo gitlab-ctl restart
      ```

1. Sur le **nœud de déploiement Rails** du site secondaire, exécutez les migrations Geo Tracking post-déploiement :
   1. Exécutez les migrations Geo Tracking post-déploiement :

      ```shell
      sudo gitlab-rake db:migrate:geo
      ```

   1. Vérifiez le statut Geo :

       ```shell
       sudo gitlab-rake gitlab:geo:status
       ```
