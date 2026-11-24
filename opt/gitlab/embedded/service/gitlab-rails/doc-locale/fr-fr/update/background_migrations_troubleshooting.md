---
stage: Data Access
group: Database Frameworks
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Résoudre les problèmes de migrations en arrière-plan
description: Solutions pour les problèmes liés aux migrations en arrière-plan.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

<!-- Linked from `lib/gitlab/database/migrations/batched_background_migration_helpers.rb` -->

## Échec des migrations de base de données en raison d'une migration en arrière-plan par lots non terminée {#database-migrations-failing-because-of-batched-background-migration-not-finished}

Lors de la mise à jour vers la version 14.2 ou ultérieure de GitLab, les migrations de base de données peuvent échouer avec un message similaire à :

```plaintext
StandardError: An error has occurred, all later migrations canceled:

Expected batched background migration for the given configuration to be marked as 'finished', but it is 'active':
  {:job_class_name=>"CopyColumnUsingBackgroundMigrationJob",
   :table_name=>"push_event_payloads",
   :column_name=>"event_id",
   :job_arguments=>[["event_id"],
   ["event_id_convert_to_bigint"]]
  }
```

Pour résoudre cette erreur :

- Si vous avez suivi les [instructions de mise à niveau spécifiques à la version 14.2](https://archives.docs.gitlab.com/17.3/ee/update/versions/gitlab_14_changes.html#1420), [terminez manuellement la migration en arrière-plan par lots](background_migrations.md#finish-a-failed-migration-manually).
- Si vous n'avez pas suivi ces instructions, vous devez soit :
  - [Effectuer un rollback et mettre à niveau](#roll-back-and-follow-the-required-upgrade-path) via l'une des versions requises avant de passer à la version 14.2+.
  - [Avancer](#roll-forward-and-finish-the-migrations-on-the-upgraded-version), en restant sur la version actuelle et en vous assurant manuellement que les migrations par lots se terminent correctement.

### Effectuer un rollback et suivre le chemin de mise à niveau requis {#roll-back-and-follow-the-required-upgrade-path}

Pour effectuer un rollback et suivre le chemin de mise à niveau requis :

1. [Effectuez un rollback et restaurez la version précédemment installée](../administration/backup_restore/_index.md).
1. Mettez à niveau vers la version 14.0.5 ou 14.1 avant de passer à la version 14.2+.
1. [Vérifiez le statut](background_migrations.md#check-the-status-of-batched-background-migrations) des migrations en arrière-plan par lots et assurez-vous qu'elles sont toutes marquées comme terminées avant de tenter à nouveau la mise à niveau. Si certaines restent marquées comme actives, [terminez-les manuellement](background_migrations.md#finish-a-failed-migration-manually).

### Avancer et terminer les migrations sur la version mise à niveau {#roll-forward-and-finish-the-migrations-on-the-upgraded-version}

Le processus pour avancer dépend de si un temps d'arrêt est requis ou non.

#### Pour un déploiement avec temps d'arrêt {#for-a-deployment-with-downtime}

L'exécution de toutes les migrations en arrière-plan par lots peut prendre un temps considérable selon la taille de votre installation GitLab.

1. [Vérifiez le statut](background_migrations.md#check-the-status-of-batched-background-migrations) des migrations en arrière-plan par lots dans la base de données, puis [exécutez-les manuellement](background_migrations.md#finish-a-failed-migration-manually) avec les arguments appropriés jusqu'à ce que la requête de statut ne retourne aucune ligne.
1. Lorsque le statut de toutes les migrations est marqué comme terminé, réexécutez les migrations pour votre installation.
1. [Terminez les migrations de base de données](../administration/raketasks/maintenance.md#run-incomplete-database-migrations) de votre mise à niveau GitLab :

   ```plaintext
   sudo gitlab-rake db:migrate
   ```

1. Exécutez une reconfiguration :

   ```plaintext
   sudo gitlab-ctl reconfigure
   ```

1. Finalisez la mise à niveau pour votre installation.

#### Pour un déploiement sans temps d'arrêt {#for-a-no-downtime-deployment}

Étant donné que les migrations en échec sont des migrations post-déploiement, vous pouvez rester sur une instance en cours d'exécution de la version mise à niveau et attendre que les migrations en arrière-plan par lots se terminent.

1. [Vérifiez le statut](background_migrations.md#check-the-status-of-batched-background-migrations) de la migration en arrière-plan par lots à partir du message d'erreur, et assurez-vous qu'elle est listée comme terminée. Si la migration est toujours active, soit :
   - Attendez qu'elle soit terminée.
   - [Terminez-la manuellement](background_migrations.md#finish-a-failed-migration-manually).
1. Réexécutez les migrations pour votre installation afin que les migrations post-déploiement restantes se terminent.

## Les migrations de recherche avancée sont bloquées {#advanced-search-migrations-are-stuck}

Pour les migrations de recherche avancée bloquées dans des problèmes en attente, [relancez les migrations interrompues](../integration/advanced_search/elasticsearch.md#retry-a-halted-migration).

Si vous mettez à niveau GitLab avant que toutes les migrations de recherche avancée en attente soient terminées, les migrations en attente qui ont été supprimées dans la nouvelle version ne peuvent pas être exécutées ni relancées. Dans ce cas, vous devez [recréer votre index à partir de zéro](../integration/elasticsearch/troubleshooting/indexing.md#last-resort-to-recreate-an-index).

## Erreur : `Elasticsearch version not compatible` {#error-elasticsearch-version-not-compatible}

Si la version d'Elasticsearch ou d'OpenSearch n'est pas compatible avec GitLab, l'indexation est mise en pause pour éviter toute perte de données et ce message est consigné dans [`elasticsearch.log`](../administration/logs/_index.md#elasticsearchlog).

Pour résoudre ce problème, [assurez-vous que votre version d'Elasticsearch ou d'OpenSearch est compatible avec GitLab](../integration/advanced_search/elasticsearch.md#version-compatibility).

Si vous utilisez une version compatible, [reprenez l'indexation](../integration/advanced_search/elasticsearch.md#resume-indexing).
