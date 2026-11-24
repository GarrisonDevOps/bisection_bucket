---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Notes de mise à niveau GitLab 15
---

<!-- vale gitlab_base.OutdatedVersions = NO-->

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Cette page contient des informations de mise à niveau pour les versions mineures et les correctifs de GitLab 15. Veillez à consulter ces instructions pour :

- Votre type d'installation.
- Toutes les versions comprises entre votre version actuelle et votre version cible.

Pour obtenir des informations supplémentaires sur les installations avec chart Helm, consultez [les notes de mise à niveau du chart Helm](https://docs.gitlab.com/charts/releases/).

## 15.11.1 {#15111}

- De nombreux [importateurs de groupes et de projets](../../user/import/_index.md) nécessitent désormais le rôle Maintainer au lieu du seul rôle Developer. Pour plus d'informations, consultez la documentation de chaque importateur que vous utilisez.

## 15.11.0 {#15110}

- Effectuez la mise à niveau vers la version de correctif 15.11.3 ou une version ultérieure. Cela permet d'éviter le [ticket 408304](https://gitlab.com/gitlab-org/gitlab/-/issues/408304) lors de la mise à niveau depuis la version 15.5.0 ou une version antérieure.
- En règle générale, les sauvegardes dans les environnements utilisant PgBouncer doivent [contourner PgBouncer en définissant des variables préfixées par `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion de base de données standard via PgBouncer au lieu de la connexion directe définie dans le remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Releases concernées** :

  | Versions mineures concernées | Versions de correctif concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations avec le paquet Linux {#linux-package-installations}

Dans GitLab 15.11, PostgreSQL sera automatiquement mis à niveau vers la version 13.x, sauf dans les cas suivants :

- Vous exécutez la base de données en haute disponibilité avec Patroni.
- Vos nœuds de base de données font partie d'une configuration GitLab Geo.
- Vous avez spécifiquement [refusé](https://docs.gitlab.com/omnibus/settings/database/#opt-out-of-automatic-postgresql-upgrades) la mise à niveau automatique de PostgreSQL.
- Vous avez `postgresql['version'] = 12` dans votre `/etc/gitlab/gitlab.rb`.

Les installations tolérantes aux pannes et Geo prennent en charge les mises à niveau manuelles vers PostgreSQL 13\. Consultez [PostgreSQL packagé déployé dans un cluster HA/Geo](https://docs.gitlab.com/omnibus/settings/database/#packaged-postgresql-deployed-in-an-hageo-cluster).

### Installations Geo {#geo-installations}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- Certaines importations de projets n'initialisent pas les dépôts wiki lors de la création du projet. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#wiki-repositories-not-initialized-on-project-creation).
- `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13. Consultez [les détails et la solution de contournement](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13).

#### `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13 {#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13}

| Versions mineures concernées | Versions de correctif concernées | Corrigé dans |
|-------------------------|-------------------------|----------|
| 15.2 - 15.10            | Tous                     | Aucune     |
| 15.11                   | 15.11.0 - 15.11.11      | 15.11.12 et versions ultérieures |

Un [bug](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7841) dans l'outil intégré `pg-upgrade` empêche la mise à niveau de la base de données PostgreSQL intégrée vers la version 13. Cela laisse le site secondaire dans un état défaillant et empêche la mise à niveau de l'installation Geo vers GitLab 16.x ([la prise en charge de PostgreSQL 12 a été supprimée dans la version 16.0](../deprecations.md#postgresql-12-deprecated) et les versions ultérieures). Ce problème se produit sur les sites secondaires utilisant le logiciel PostgreSQL intégré, qui exécutent à la fois la base de données Rails principale secondaire et la base de données de suivi sur le même nœud. Une [solution de contournement](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7841#workaround) manuelle existe si vous ne pouvez pas effectuer la mise à niveau vers la version 15.11.12 ou une version ultérieure.

## 15.11.x {#1511x}

- Un [bug](https://gitlab.com/gitlab-org/gitlab/-/issues/411604) peut entraîner l'attribution aux nouveaux utilisateurs LDAP se connectant pour la première fois d'un nom d'utilisateur basé sur leur adresse e-mail plutôt que sur leur attribut de nom d'utilisateur LDAP. Une solution de contournement manuelle consiste à définir `gitlab_rails['omniauth_auto_link_ldap_user'] = true`, ou à effectuer une mise à niveau vers GitLab 16.1 ou une version ultérieure dans laquelle le bug a été corrigé.

## 15.10.5 {#15105}

- Un [bug avec les Elastic Indexer Cron Workers](https://gitlab.com/gitlab-org/gitlab/-/issues/408214) peut entraîner une saturation dans Sidekiq.
  - Lorsque ce problème se produit, les fusions de merge requests, les pipelines, les notifications Slack et d'autres événements ne sont pas créés ou prennent beaucoup de temps à se produire.
  - Ce problème peut ne pas se manifester immédiatement, car il peut s'écouler jusqu'à une semaine avant que Sidekiq soit suffisamment saturé.
  - Elasticsearch n'a pas besoin d'être activé pour que cela se produise.
  - Pour résoudre ce problème, effectuez une mise à niveau vers la version 15.11 ou utilisez la solution de contournement décrite dans le ticket.
- De nombreux [importateurs de groupes et de projets](../../user/import/_index.md) nécessitent désormais le rôle Maintainer au lieu du seul rôle Developer. Pour plus d'informations, consultez la documentation de chaque importateur que vous utilisez.

## 15.10.0 {#15100}

- Un [bug avec les Elastic Indexer Cron Workers](https://gitlab.com/gitlab-org/gitlab/-/issues/408214) peut entraîner une saturation dans Sidekiq.
  - Lorsque ce problème se produit, les fusions de merge requests, les pipelines, les notifications Slack et d'autres événements ne sont pas créés ou prennent beaucoup de temps à se produire.
  - Ce problème peut ne pas se manifester immédiatement, car il peut s'écouler jusqu'à une semaine avant que Sidekiq soit suffisamment saturé.
  - Elasticsearch n'a pas besoin d'être activé pour que cela se produise.
  - Pour résoudre ce problème, effectuez une mise à niveau vers la version 15.11 ou utilisez la solution de contournement décrite dans le ticket.
- Un [bug avec la réindexation sans interruption de service](https://gitlab.com/gitlab-org/gitlab/-/issues/422938) peut provoquer une erreur `Couldn't load task status` lors de la réindexation. Vous pouvez également obtenir une erreur `sliceId must be greater than 0 but was [-1]` sur l'hôte Elasticsearch. Pour contourner le problème, envisagez de [réindexer depuis le début](../../integration/elasticsearch/troubleshooting/indexing.md#last-resort-to-recreate-an-index) ou d'effectuer une mise à niveau vers GitLab 16.3.
- La configuration de Gitaly change considérablement pour les instances de paquets Linux dans GitLab 16.0. Vous pouvez commencer à migrer vers la nouvelle structure dans GitLab 15.10, la rétrocompatibilité étant maintenue jusqu'à la sortie de GitLab 16.0. [En savoir plus sur ce changement](gitlab_16_changes.md#gitaly-configuration-structure-change).
- Vous pouvez rencontrer l'erreur suivante lors de la mise à niveau vers GitLab 15.10 ou une version ultérieure :

  ```shell
  STDOUT: rake aborted!
  StandardError: An error has occurred, all later migrations canceled:
  PG::CheckViolation: ERROR:  check constraint "check_70f294ef54" is violated by some row
  ```

  Cette erreur est causée par une [migration en arrière-plan par lots introduite dans GitLab 15.8](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/107701) qui n'a pas été finalisée avant GitLab 15.10. Pour résoudre cette erreur :

  1. Exécutez l'instruction SQL suivante à l'aide de la console de base de données (`sudo gitlab-psql` pour les installations de paquets Linux) :

     ```sql
     UPDATE oauth_access_tokens SET expires_in = '7200' WHERE expires_in IS NULL;
     ```

  1. [Réexécutez les migrations de base de données](../../administration/raketasks/maintenance.md#run-incomplete-database-migrations).
- Vous pouvez également rencontrer l'erreur suivante lors de la mise à niveau vers GitLab 15.10 ou une version ultérieure :

  ```shell
  "exception.class": "ActiveRecord::StatementInvalid",
  "exception.message": "PG::SyntaxError: ERROR:  zero-length delimited identifier at or near \"\"\"\"\nLINE 1: ...COALESCE(\"lock_version\", 0) + 1 WHERE \"ci_builds\".\"\" IN (SEL...\n
  ```

  Cette erreur est causée par une [migration en arrière-plan par lots introduite dans GitLab 14.9](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/81410) qui n'a pas été finalisée avant la mise à niveau vers GitLab 15.10 ou une version ultérieure. Pour résoudre cette erreur, vous pouvez [marquer la migration comme terminée](../background_migrations.md#mark-a-failed-migration-finished) en toute sécurité :

  ```ruby
  # Start the rails console

  connection = Ci::ApplicationRecord.connection

  Gitlab::Database::SharedModel.using_connection(connection) do
    migration = Gitlab::Database::BackgroundMigration::BatchedMigration.find_for_configuration(
      Gitlab::Database.gitlab_schemas_for_connection(connection), 'NullifyOrphanRunnerIdOnCiBuilds', :ci_builds, :id, [])

    # mark all jobs completed
    migration.batched_jobs.update_all(status: Gitlab::Database::BackgroundMigration::BatchedJob.state_machine.states[:succeeded].value)
    migration.update_attribute(:status, Gitlab::Database::BackgroundMigration::BatchedMigration.state_machine.states[:finished].value)
  end
  ```

  Pour plus d'informations, consultez le [ticket 415724](https://gitlab.com/gitlab-org/gitlab/-/issues/415724).

- Un [bug avec la configuration Terraform](https://gitlab.com/gitlab-org/gitlab/-/issues/348453) a provoqué le maintien de l'état Terraform même lorsque `gitlab_rails['terraform_state_enabled']` était défini sur `false` dans le fichier de configuration `gitlab.rb`. Ce bug ayant été corrigé dans GitLab 15.10, la mise à niveau vers GitLab 15.10 peut perturber les projets qui utilisent la fonctionnalité [état Terraform](../../administration/terraform_state.md) si elle est désactivée dans la configuration `gitlab.rb`. Si vous avez configuré `gitlab_rails['terraform_state_enabled'] = false` dans votre `gitlab.rb`, vérifiez si des projets utilisent la fonctionnalité d'état Terraform. Pour vérifier :
  1. Lisez l'avertissement de la [console Rails](../../administration/operations/rails_console.md).
  1. Démarrez une [session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session).
  1. Exécutez la commande `Terraform::State.pluck(:project_id)`. Cette commande renvoie un tableau de tous les ID de projets ayant un état Terraform.
  1. Accédez à chaque projet et collaborez avec les parties prenantes si nécessaire pour déterminer si la fonctionnalité d'état Terraform est utilisée activement. Si l'état Terraform n'est plus nécessaire, vous pouvez suivre les étapes pour [supprimer un fichier d'état](../../user/infrastructure/iac/terraform_state.md#remove-a-state-file).

### Installations Geo {#geo-installations-1}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13. Consultez [les détails et la solution de contournement](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13).
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

## 15.9.0 {#1590}

- Un [bug avec les Elastic Indexer Cron Workers](https://gitlab.com/gitlab-org/gitlab/-/issues/408214) peut entraîner une saturation dans Sidekiq.
  - Lorsque ce problème se produit, les fusions de merge requests, les pipelines, les notifications Slack et d'autres événements ne sont pas créés ou prennent beaucoup de temps à se produire.
  - Ce problème peut ne pas se manifester immédiatement, car il peut s'écouler jusqu'à une semaine avant que Sidekiq soit suffisamment saturé.
  - Elasticsearch n'a pas besoin d'être activé pour que cela se produise.
  - Pour résoudre ce problème, effectuez une mise à niveau vers la version 15.11 ou utilisez la solution de contournement décrite dans le ticket.
- Un bug avec la [migration de recherche avancée `BackfillTraversalIdsToBlobsAndWikiBlobs`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/107730) peut entraîner la saturation du cluster Elasticsearch.
  - Lorsque ce problème se produit, les recherches peuvent devenir lentes et les mises à jour du cluster Elasticsearch peuvent prendre beaucoup de temps à se terminer.
  - Pour résoudre ce problème, effectuez une mise à niveau vers GitLab 15.10 pour [réduire la taille des lots de migration](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/113719).
- Effectuez la mise à niveau vers la version de correctif 15.9.3 ou une version ultérieure. Cela fournit des correctifs pour deux bugs de migration de base de données :
  - Les versions de correctif 15.9.0, 15.9.1 et 15.9.2 présentent un bug pouvant entraîner une perte de données à partir des champs de profil utilisateur `linkedin`, `twitter`, `skype`, `website_url`, `location` et `organization`. Pour plus d'informations, consultez le [ticket 393216](https://gitlab.com/gitlab-org/gitlab/-/issues/393216).
  - Le deuxième [correctif de bug](https://gitlab.com/gitlab-org/gitlab/-/issues/394760) garantit qu'il est possible d'effectuer une mise à niveau directement depuis la version 15.4.x.
- Dans le cadre de [l'effort de partitionnement CI](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/ci_data_decay/pipeline_partitioning/), une [nouvelle clé étrangère](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/107547) a été ajoutée à `ci_builds_needs`. Sur les instances GitLab avec des tables CI volumineuses, l'ajout de cette contrainte peut prendre plus de temps que d'habitude.
- Le [comportement de suppression de métadonnées non valides](../../administration/gitaly/praefect/configure.md#enable-deletions) du vérificateur de métadonnées de Praefect est désormais activé par défaut.

  Le vérificateur de métadonnées traite les enregistrements de répliques dans la base de données Praefect et vérifie que les répliques existent bien sur les nœuds Gitaly. Si la réplique n'existe pas, son enregistrement de métadonnées est supprimé. Cela permet à Praefect de corriger les situations où une réplique dispose d'un enregistrement de métadonnées indiquant qu'elle est opérationnelle, alors qu'en réalité elle n'existe pas sur le disque. Après la suppression de l'enregistrement de métadonnées, le réconciliateur de Praefect planifie un job de réplication pour recréer la réplique.

  En raison de problèmes passés avec la logique de gestion des états, il peut exister des enregistrements de métadonnées non valides dans la base de données. Ces enregistrements peuvent exister, par exemple, en raison de suppressions incomplètes de dépôts ou de renommages partiellement effectués. Le vérificateur supprime ces enregistrements de répliques obsolètes des dépôts concernés. Ces dépôts peuvent apparaître comme indisponibles dans les métriques et dans la sous-commande `praefect dataloss` en raison de la suppression des enregistrements de répliques. Si vous rencontrez de tels dépôts, supprimez le dépôt à l'aide de `praefect remove-repository` pour supprimer les enregistrements restants du dépôt.

  Vous pouvez trouver des dépôts avec des enregistrements de métadonnées non valides à partir de GitLab 15.0 et versions ultérieures en recherchant les enregistrements de journaux générés par le vérificateur. [En savoir plus sur la vérification des dépôts et pour voir un exemple d'entrée de journal](../../administration/gitaly/praefect/configure.md#repository-verification).
- La configuration de Praefect change considérablement pour les instances de paquets Linux dans GitLab 16.0. Vous pouvez commencer à migrer vers la nouvelle structure dans GitLab 15.9, la rétrocompatibilité étant maintenue jusqu'à la sortie de GitLab 16.0. [En savoir plus sur ce changement](gitlab_16_changes.md#praefect-configuration-structure-change).

### Installations compilées manuellement {#self-compiled-installations}

- Pour les **installations compilées manuellement (depuis les sources)**, avec l'ajout de `gitlab-sshd`, les en-têtes Kerberos sont nécessaires pour compiler GitLab Shell.

  ```shell
  sudo apt install libkrb5-dev
  ```

### Installations Geo {#geo-installations-2}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13. Consultez [les détails et la solution de contournement](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13).
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

## 15.8.2 {#1582}

### Installations Geo {#geo-installations-3}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.8.1 {#1581}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-4}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.8.0 {#1580}

- Git 2.38.0 ou une version ultérieure est requis par Gitaly. Pour les installations compilées manuellement, vous devez utiliser la [version de Git fournie par Gitaly](../../install/self_compiled/_index.md#git).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-5}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13. Consultez [les détails et la solution de contournement](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13).
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

## 15.7.6 {#1576}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-6}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.7.5 {#1575}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-7}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.7.4 {#1574}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-8}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.7.3 {#1573}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-9}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.7.2 {#1572}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-10}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- [Les événements push du registre de conteneurs sont rejetés](https://gitlab.com/gitlab-org/gitlab/-/issues/386389) par le point de terminaison `/api/v4/container_registry_event/events`, ce qui fait que les sites secondaires Geo ne sont pas informés des mises à jour des images du registre de conteneurs et ne répliquent pas par la suite les mises à niveau. Par conséquent, les sites secondaires peuvent contenir des images de conteneurs obsolètes après un basculement. Cela affecte les versions 15.6.0 - 15.6.6 et 15.7.0 - 15.7.2. Si vous utilisez Geo avec des dépôts de conteneurs, il est conseillé d'effectuer une mise à niveau vers GitLab 15.6.7, 15.7.3 ou 15.8.0 qui contiennent un correctif pour ce problème et d'éviter une perte de données potentielle après un basculement.
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.7.1 {#1571}

- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-11}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- [Les événements push du registre de conteneurs sont rejetés](https://gitlab.com/gitlab-org/gitlab/-/issues/386389) par le point de terminaison `/api/v4/container_registry_event/events`, ce qui fait que les sites secondaires Geo ne sont pas informés des mises à jour des images du registre de conteneurs et ne répliquent pas par la suite les mises à jour. Par conséquent, les sites secondaires peuvent contenir des images de conteneurs obsolètes après un basculement. Cela affecte les versions 15.6.0 - 15.6.6 et 15.7.0 - 15.7.2. Si vous utilisez Geo avec des dépôts de conteneurs, il est conseillé d'effectuer une mise à niveau vers GitLab 15.6.7, 15.7.3 ou 15.8.0 qui contiennent un correctif pour ce problème et d'éviter une perte de données potentielle après un basculement.
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.7.0 {#1570}

- Cette version valide une contrainte `NOT NULL DB` sur la colonne `issues.work_item_type_id`. Pour effectuer la mise à niveau vers cette version, aucun enregistrement avec un `NULL` `work_item_type_id` ne doit exister dans la table `issues`. Il existe plusieurs migrations en arrière-plan `BackfillWorkItemTypeIdForIssues` qui seront finalisées avec la migration post-déploiement `EnsureWorkItemTypeBackfillMigrationFinished`.
- GitLab 15.4.0 a introduit une [migration en arrière-plan par lots](../background_migrations.md#check-for-pending-database-background-migrations) pour [remplir les valeurs `namespace_id` dans la table des tickets](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/91921). Cette migration peut prendre plusieurs heures ou jours pour se terminer sur des instances GitLab plus volumineuses. Assurez-vous que la migration s'est terminée avec succès avant d'effectuer la mise à niveau vers la version 15.7.0.
- Une contrainte de base de données est ajoutée, spécifiant que la colonne `namespace_id` de la table des tickets ne contient pas de valeurs `NULL`.

  - Si la migration en arrière-plan par lots `namespace_id` de la version 15.4 a échoué (voir l'élément précédent), la mise à niveau vers la version 15.7 échoue avec une erreur de migration de base de données.

  - Sur les instances GitLab avec des tables de tickets volumineuses, la validation de cette contrainte peut prolonger la durée de la mise à niveau. Toutes les modifications de base de données doivent être effectuées dans un délai d'une heure :

    ```plaintext
    FATAL: Mixlib::ShellOut::CommandTimeout: rails_migration[gitlab-rails]
    [..]
    Mixlib::ShellOut::CommandTimeout: Command timed out after 3600s:
    ```

    Une solution de contournement existe pour [effectuer manuellement la modification des données et la mise à niveau](../package/package_troubleshooting.md#error-command-timed-out-after-3600s).
- La valeur par défaut de Sidekiq `max_concurrency` a été modifiée à 20. Elle est désormais cohérente avec les valeurs par défaut de notre documentation et de notre produit.

  Par exemple, auparavant :

  - Valeur par défaut de l'installation du paquet Linux (`sidekiq['max_concurrency']`) : 50
  - Valeur par défaut de l'installation compilée manuellement : 50
  - Valeur par défaut du chart Helm (`gitlab.sidekiq.concurrency`) : 25

  Les architectures de référence utilisent toujours une valeur par défaut de 10, car cette valeur est définie spécifiquement pour ces configurations.

  Les sites ayant configuré `max_concurrency` ne seront pas affectés par cette modification. [En savoir plus sur le paramètre de concurrence Sidekiq](../../administration/sidekiq/extra_sidekiq_processes.md#concurrency).
- GitLab Runner 15.7.0 a introduit un changement incompatible qui affecte les jobs CI/CD : [Gérer correctement l'expansion des variables de fichier de job](https://gitlab.com/gitlab-org/gitlab-runner/-/merge_requests/3613). Auparavant, les variables définies dans un job qui référençaient des [variables de type fichier](../../ci/variables/_index.md#use-file-type-cicd-variables) étaient développées avec la valeur de la variable fichier (son contenu). Ce comportement ne respectait pas les règles habituelles d'expansion des variables shell. Il existait également un risque que des secrets ou des informations sensibles soient divulgués si la variable fichier et son contenu étaient affichés. Par exemple, s'ils étaient affichés dans une sortie echo. Pour plus d'informations, consultez [Comprendre le changement d'expansion des variables de type fichier dans GitLab 15.7](https://about.gitlab.com/blog/impact-of-the-file-type-variable-change-15-7/).
- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

### Installations Geo {#geo-installations-12}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13. Consultez [les détails et la solution de contournement](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13).
- [Les événements push du registre de conteneurs sont rejetés](https://gitlab.com/gitlab-org/gitlab/-/issues/386389) par le point de terminaison `/api/v4/container_registry_event/events`, ce qui fait que les sites secondaires Geo ne sont pas informés des mises à jour des images du registre de conteneurs et ne répliquent pas par la suite les mises à jour. Par conséquent, les sites secondaires peuvent contenir des images de conteneurs obsolètes après un basculement. Cela affecte les versions 15.6.0 - 15.6.6 et 15.7.0 - 15.7.2. Si vous utilisez Geo avec des dépôts de conteneurs, il est conseillé d'effectuer une mise à niveau vers GitLab 15.6.7, 15.7.3 ou 15.8.0 qui contiennent un correctif pour ce problème et d'éviter une perte de données potentielle après un basculement.
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.6.7 {#1567}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-13}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.6.6 {#1566}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-14}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- [Les événements push du registre de conteneurs sont rejetés](https://gitlab.com/gitlab-org/gitlab/-/issues/386389) par le point de terminaison `/api/v4/container_registry_event/events`, ce qui fait que les sites secondaires Geo ne sont pas informés des mises à jour des images du registre de conteneurs et ne répliquent pas par la suite les mises à jour. Par conséquent, les sites secondaires peuvent contenir des images de conteneurs obsolètes après un basculement. Cela affecte les versions 15.6.0 - 15.6.6 et 15.7.0 - 15.7.2. Si vous utilisez Geo avec des dépôts de conteneurs, il est conseillé d'effectuer une mise à niveau vers GitLab 15.6.7, 15.7.3 ou 15.8.0 qui contiennent un correctif pour ce problème et d'éviter une perte de données potentielle après un basculement.
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.

## 15.6.5 {#1565}

### Installations Geo {#geo-installations-15}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- [Les événements push du registre de conteneurs sont rejetés](https://gitlab.com/gitlab-org/gitlab/-/issues/386389) par le point de terminaison `/api/v4/container_registry_event/events`, ce qui fait que les sites secondaires Geo ne sont pas informés des mises à jour des images du registre de conteneurs et ne répliquent pas par la suite les mises à jour. Par conséquent, les sites secondaires peuvent contenir des images de conteneurs obsolètes après un basculement. Cela affecte les versions 15.6.0 - 15.6.6 et 15.7.0 - 15.7.2. Si vous utilisez Geo avec des dépôts de conteneurs, il est conseillé d'effectuer une mise à niveau vers GitLab 15.6.7, 15.7.3 ou 15.8.0 qui contiennent un correctif pour ce problème et d'éviter une perte de données potentielle après un basculement.
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.6.4 {#1564}

### Installations Geo {#geo-installations-16}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- [Les événements push du registre de conteneurs sont rejetés](https://gitlab.com/gitlab-org/gitlab/-/issues/386389) par le point de terminaison `/api/v4/container_registry_event/events`, ce qui fait que les sites secondaires Geo ne sont pas informés des mises à jour des images du registre de conteneurs et ne répliquent pas par la suite les mises à jour. Par conséquent, les sites secondaires peuvent contenir des images de conteneurs obsolètes après un basculement. Cela affecte les versions 15.6.0 - 15.6.6 et 15.7.0 - 15.7.2. Si vous utilisez Geo avec des dépôts de conteneurs, il est conseillé d'effectuer une mise à niveau vers GitLab 15.6.7, 15.7.3 ou 15.8.0 qui contiennent un correctif pour ce problème et d'éviter une perte de données potentielle après un basculement.
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.6.3 {#1563}

### Installations Geo {#geo-installations-17}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- [Les événements push du registre de conteneurs sont rejetés](https://gitlab.com/gitlab-org/gitlab/-/issues/386389) par le point de terminaison `/api/v4/container_registry_event/events`, ce qui fait que les sites secondaires Geo ne sont pas informés des mises à jour des images du registre de conteneurs et ne répliquent pas par la suite les mises à jour. Par conséquent, les sites secondaires peuvent contenir des images de conteneurs obsolètes après un basculement. Cela affecte les versions 15.6.0 - 15.6.6 et 15.7.0 - 15.7.2. Si vous utilisez Geo avec des dépôts de conteneurs, il est conseillé d'effectuer une mise à niveau vers GitLab 15.6.7, 15.7.3 ou 15.8.0 qui contiennent un correctif pour ce problème et d'éviter une perte de données potentielle après un basculement.
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.
- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.6.2 {#1562}

### Installations Geo {#geo-installations-18}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- [Les événements push du registre de conteneurs sont rejetés](https://gitlab.com/gitlab-org/gitlab/-/issues/386389) par le point de terminaison `/api/v4/container_registry_event/events`, ce qui fait que les sites secondaires Geo ne sont pas informés des mises à jour des images du registre de conteneurs et ne répliquent pas par la suite les mises à jour. Par conséquent, les sites secondaires peuvent contenir des images de conteneurs obsolètes après un basculement. Cela affecte les versions 15.6.0 - 15.6.6 et 15.7.0 - 15.7.2. Si vous utilisez Geo avec des dépôts de conteneurs, il est conseillé d'effectuer une mise à niveau vers GitLab 15.6.7, 15.7.3 ou 15.8.0 qui contiennent un correctif pour ce problème et d'éviter une perte de données potentielle après un basculement.
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.
- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.6.1 {#1561}

### Installations Geo {#geo-installations-19}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- [Les événements push du registre de conteneurs sont rejetés](https://gitlab.com/gitlab-org/gitlab/-/issues/386389) par le point de terminaison `/api/v4/container_registry_event/events`, ce qui fait que les sites secondaires Geo ne sont pas informés des mises à jour des images du registre de conteneurs et ne répliquent pas par la suite les mises à jour. Par conséquent, les sites secondaires peuvent contenir des images de conteneurs obsolètes après un basculement. Cela affecte les versions 15.6.0 - 15.6.6 et 15.7.0 - 15.7.2. Si vous utilisez Geo avec des dépôts de conteneurs, il est conseillé d'effectuer une mise à niveau vers GitLab 15.6.7, 15.7.3 ou 15.8.0 qui contiennent un correctif pour ce problème et d'éviter une perte de données potentielle après un basculement.
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.
- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.6.0 {#1560}

- Vous devez utiliser l'une des [versions PostgreSQL officiellement prises en charge](../../administration/package_information/postgresql_versions.md). Certaines migrations de base de données peuvent entraîner des problèmes de stabilité et de performances avec les anciennes versions de PostgreSQL.
- Git 2.37.0 ou une version ultérieure est requis par Gitaly. Pour les installations compilées manuellement, vous devez utiliser la [version de Git fournie par Gitaly](../../install/self_compiled/_index.md#git).
- Une modification de base de données visant à modifier le comportement de quatre index échoue sur les instances où ces index n'existent pas :

  ```plaintext
  Caused by:
  PG::UndefinedTable: ERROR:  relation "index_issues_on_title_trigram" does not exist
  ```

  Les trois autres index sont : `index_merge_requests_on_title_trigram`, `index_merge_requests_on_description_trigram` et `index_issues_on_description_trigram`.

  Ce problème a été [corrigé dans GitLab 15.7](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/105375) et rétroporté vers GitLab 15.6.2. Le problème peut également être contourné : [consultez la procédure de création de ces index](https://gitlab.com/gitlab-org/gitlab/-/issues/378343#note_1199863087).

### Installations avec le paquet Linux {#linux-package-installations-1}

Dans GitLab 15.6, les [versions PostgreSQL livrées avec les paquets `omnibus-gitlab`](../../administration/package_information/postgresql_versions.md) ont été mises à niveau vers 12.12 et 13.8. Sauf [refus explicite](https://docs.gitlab.com/omnibus/settings/database/#automatic-restart-when-the-postgresql-version-changes), cela peut entraîner un redémarrage automatique du service PostgreSQL et potentiellement provoquer une interruption de service.

### Installations Geo {#geo-installations-20}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13. Consultez [les détails et la solution de contournement](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13).
- [Les événements push du registre de conteneurs sont rejetés](https://gitlab.com/gitlab-org/gitlab/-/issues/386389) par le point de terminaison `/api/v4/container_registry_event/events`, ce qui fait que les sites secondaires Geo ne sont pas informés des mises à jour des images du registre de conteneurs et ne répliquent pas par la suite les mises à jour. Par conséquent, les sites secondaires peuvent contenir des images de conteneurs obsolètes après un basculement. Cela affecte les versions 15.6.0 - 15.6.6 et 15.7.0 - 15.7.2. Si vous utilisez Geo avec des dépôts de conteneurs, il est conseillé d'effectuer une mise à niveau vers GitLab 15.6.7, 15.7.3 ou 15.8.0 qui contiennent un correctif pour ce problème et d'éviter une perte de données potentielle après un basculement.
- Nous avons découvert un problème où [la réplication et la vérification des projets et des wikis ne suivaient pas](https://gitlab.com/gitlab-org/gitlab/-/issues/387980) sur un petit nombre d'installations Geo. Votre installation peut être affectée si vous constatez que certains projets ou wikis restent en permanence à l'état « En file d'attente » pour la vérification. Cela peut entraîner une perte de données après un basculement.
  - Versions concernées : versions GitLab 15.6.x, 15.7.x et 15.8.0 - 15.8.2.
  - Versions contenant le correctif : GitLab 15.8.3 et versions ultérieures.
- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

## 15.5.5 {#1555}

- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.5.4 {#1554}

- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.5.3 {#1553}

- GitLab 15.4.0 a introduit une [règle de routage Sidekiq](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules) par défaut qui achemine tous les jobs vers la file d'attente `default`. Pour les instances utilisant des [sélecteurs de file d'attente](https://archives.docs.gitlab.com/17.0/ee/administration/sidekiq/processing_specific_job_classes.html#queue-selectors-deprecated), cela entraîne des [problèmes de performances](https://gitlab.com/gitlab-com/gl-infra/scalability/-/issues/1991), car certains processus Sidekiq sont inactifs.
  - La règle de routage par défaut a été annulée dans la version 15.5.4\. La mise à niveau vers cette version ou une version ultérieure rétablira le comportement précédent.
  - Si une instance GitLab écoute désormais uniquement la file d'attente `default` (ce qui n'est pas recommandé actuellement), il sera nécessaire de rajouter cette règle de routage dans `/etc/gitlab/gitlab.rb` :

    ```ruby
    sidekiq['routing_rules'] = [['*', 'default']]
    ```

- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.5.2 {#1552}

- GitLab 15.4.0 a introduit une [règle de routage Sidekiq](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules) par défaut qui achemine tous les jobs vers la file d'attente `default`. Pour les instances utilisant des [sélecteurs de file d'attente](https://archives.docs.gitlab.com/17.0/ee/administration/sidekiq/processing_specific_job_classes.html#queue-selectors-deprecated), cela entraîne des [problèmes de performances](https://gitlab.com/gitlab-com/gl-infra/scalability/-/issues/1991), car certains processus Sidekiq sont inactifs.
  - La règle de routage par défaut a été annulée dans la version 15.5.4\. La mise à niveau vers cette version ou une version ultérieure rétablira le comportement précédent.
  - Si une instance GitLab écoute désormais uniquement la file d'attente `default` (ce qui n'est pas recommandé actuellement), il sera nécessaire de rajouter cette règle de routage dans `/etc/gitlab/gitlab.rb` :

    ```ruby
    sidekiq['routing_rules'] = [['*', 'default']]
    ```

- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.5.1 {#1551}

- GitLab 15.4.0 a introduit une [règle de routage Sidekiq](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules) par défaut qui achemine tous les jobs vers la file d'attente `default`. Pour les instances utilisant des [sélecteurs de file d'attente](https://archives.docs.gitlab.com/17.0/ee/administration/sidekiq/processing_specific_job_classes.html#queue-selectors-deprecated), cela entraîne des [problèmes de performances](https://gitlab.com/gitlab-com/gl-infra/scalability/-/issues/1991), car certains processus Sidekiq sont inactifs.
  - La règle de routage par défaut a été annulée dans la version 15.5.4\. La mise à niveau vers cette version ou une version ultérieure rétablira le comportement précédent.
  - Si une instance GitLab écoute désormais uniquement la file d'attente `default` (ce qui n'est pas recommandé actuellement), il sera nécessaire de rajouter cette règle de routage dans `/etc/gitlab/gitlab.rb` :

    ```ruby
    sidekiq['routing_rules'] = [['*', 'default']]
    ```

- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.5.0 {#1550}

- GitLab 15.4.0 a introduit une [règle de routage Sidekiq](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules) par défaut qui achemine tous les jobs vers la file d'attente `default`. Pour les instances utilisant des [sélecteurs de file d'attente](https://archives.docs.gitlab.com/17.0/ee/administration/sidekiq/processing_specific_job_classes.html#queueselectors-deprecated), cela entraîne des [problèmes de performances](https://gitlab.com/gitlab-com/gl-infra/scalability/-/issues/1991), car certains processus Sidekiq sont inactifs.
  - La règle de routage par défaut a été annulée dans la version 15.5.4\. La mise à niveau vers cette version ou une version ultérieure rétablira le comportement précédent.
  - Si une instance GitLab écoute désormais uniquement la file d'attente `default` (ce qui n'est pas recommandé actuellement), il sera nécessaire de rajouter cette règle de routage dans `/etc/gitlab/gitlab.rb` :

    ```ruby
    sidekiq['routing_rules'] = [['*', 'default']]
    ```

- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

### Installations Geo {#geo-installations-21}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13. Consultez [les détails et la solution de contournement](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13).
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

## 15.4.6 {#1546}

- La [variable d'environnement personnalisée](https://docs.gitlab.com/omnibus/settings/environment-variables.md) `no_proxy` dans le paquet Linux (Omnibus) peut ne pas fonctionner correctement en raison d'un bug dans la [version de cURL](https://github.com/curl/curl/issues/10122) incluse avec GitLab 15.4.6. Ce problème entraîne l'ignorance de tous les domaines génériques (comme `.example.com`), à l'exception du dernier répertorié dans la variable `no_proxy`. Pour contourner ce problème, vous pouvez déplacer votre domaine générique à la fin de la liste ou effectuer une mise à niveau vers une [version ultérieure avec un cURL corrigé](https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/).
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.4.5 {#1545}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.4.4 {#1544}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.4.3 {#1543}

- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.4.2 {#1542}

- Un [problème de mise en cache de licence](https://gitlab.com/gitlab-org/gitlab/-/issues/376706) empêche certaines fonctionnalités premium de GitLab de fonctionner correctement si vous ajoutez une nouvelle licence. Solutions de contournement pour ce problème :
  - Redémarrez tous les nœuds Rails, Sidekiq et Gitaly après avoir appliqué une nouvelle licence. Cela vide les caches de licence pertinents et permet à toutes les fonctionnalités premium de fonctionner correctement.
  - Mettez à niveau vers une version non affectée par ce problème. Les chemins de mise à niveau suivants sont disponibles pour les versions affectées :
    - 15.2.5 --> 15.3.5
    - 15.3.0 - 15.3.4 --> 15.3.5
    - 15.4.1 --> 15.4.3
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.4.1 {#1541}

- Un [problème de mise en cache de licence](https://gitlab.com/gitlab-org/gitlab/-/issues/376706) empêche certaines fonctionnalités premium de GitLab de fonctionner correctement si vous ajoutez une nouvelle licence. Solutions de contournement pour ce problème :
  - Redémarrez tous les nœuds Rails, Sidekiq et Gitaly après avoir appliqué une nouvelle licence. Cela vide les caches de licence pertinents et permet à toutes les fonctionnalités premium de fonctionner correctement.
  - Mettez à niveau vers une version non affectée par ce problème. Les chemins de mise à niveau suivants sont disponibles pour les versions affectées :
    - 15.2.5 --> 15.3.5
    - 15.3.0 - 15.3.4 --> 15.3.5
    - 15.4.1 --> 15.4.3
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.

## 15.4.0 {#1540}

- GitLab 15.4.0 inclut une [migration en arrière-plan par lots](../background_migrations.md#check-for-pending-database-background-migrations) pour [supprimer les valeurs incorrectes de `expire_at` dans la table `ci_job_artifacts`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/89318). Cette migration peut prendre des heures ou des jours pour s'effectuer sur des instances GitLab de grande taille.
- Par défaut, les nœuds Gitaly et Praefect utilisent le serveur de temps à `pool.ntp.org`. Si votre instance ne peut pas se connecter à `pool.ntp.org`, [configurez la variable `NTP_HOST`](../../administration/gitaly/praefect/configure.md#customize-time-server-setting) ; sinon, des erreurs `ntp: read udp ... i/o timeout` peuvent apparaître dans les journaux et dans la sortie de `gitlab-rake gitlab:gitaly:check`. Cependant, si les horloges des hôtes Gitaly sont synchronisées, ces erreurs peuvent être ignorées.
- GitLab 15.4.0 a introduit une [règle de routage Sidekiq](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules) par défaut qui achemine tous les jobs vers la file d'attente `default`. Pour les instances utilisant des [sélecteurs de file d'attente](https://archives.docs.gitlab.com/17.0/ee/administration/sidekiq/processing_specific_job_classes.html#queue-selectors-deprecated), cela entraîne des [problèmes de performances](https://gitlab.com/gitlab-com/gl-infra/scalability/-/issues/1991), car certains processus Sidekiq sont inactifs.
  - La règle de routage par défaut a été annulée dans la version 15.4.5 ; ainsi, la mise à niveau vers cette version ou une version ultérieure rétablira le comportement précédent.
  - Si une instance GitLab écoute désormais uniquement la file d'attente `default` (ce qui n'est pas recommandé actuellement), il sera nécessaire de rajouter cette règle de routage dans `/etc/gitlab/gitlab.rb` :

    ```ruby
    sidekiq['routing_rules'] = [['*', 'default']]
    ```

- La structure de `/etc/gitlab/gitlab-secrets.json` a été modifiée dans [GitLab 15.4](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/6310), et une nouvelle configuration a été ajoutée aux sections `gitlab_pages`, `grafana` et `mattermost`. Dans un environnement haute disponibilité ou GitLab Geo, les secrets doivent être identiques sur tous les nœuds. Si vous synchronisez manuellement le fichier des secrets entre les nœuds, ou si vous spécifiez manuellement des secrets dans `/etc/gitlab/gitlab.rb`, assurez-vous que `/etc/gitlab/gitlab-secrets.json` est identique sur tous les nœuds.
- GitLab 15.4.0 a introduit une [migration en arrière-plan par lots](../background_migrations.md#check-for-pending-database-background-migrations) pour [remplir les valeurs `namespace_id` dans la table des tickets](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/91921). Cette migration peut prendre plusieurs heures ou jours pour se terminer sur des instances GitLab plus volumineuses. Assurez-vous que la migration s'est effectuée avec succès avant de mettre à niveau vers la version 15.7.0 ou ultérieure.
- En raison d'[un bug introduit dans GitLab 15.4](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155), si un ou plusieurs dépôts Git dans le cluster Gitaly (Praefect) sont [indisponibles](../../administration/gitaly/praefect/recovery.md#unavailable-repositories), les [vérifications de dépôts](../../administration/repository_checks.md) et la [réplication et vérification Geo](../../administration/geo/_index.md) cessent de s'exécuter pour tous les dépôts de projets ou de wikis de projets dans le cluster Gitaly (Praefect) concerné. Le bug a été corrigé en [annulant la modification dans GitLab 15.9.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/110823). Avant de mettre à niveau vers cette version, vérifiez si vous avez des dépôts « indisponibles ». Consultez [le ticket du bug](https://gitlab.com/gitlab-org/gitlab/-/work_items/390155) pour plus d'informations.
- Une page de connexion repensée est activée par défaut dans GitLab 15.4 et versions ultérieures, avec des améliorations incluses dans les versions suivantes. Pour plus d'informations, consultez l'[epic 8557](https://gitlab.com/groups/gitlab-org/-/work_items/8557). Elle peut être désactivée avec un feature flag. Démarrez [une console Rails](../../administration/operations/rails_console.md) et exécutez :

  ```ruby
  Feature.disable(:restyle_login_page)
  ```

### Installations Geo {#geo-installations-22}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13. Consultez [les détails et la solution de contournement](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13).
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

## 15.3.4 {#1534}

Un [problème de mise en cache de licence](https://gitlab.com/gitlab-org/gitlab/-/issues/376706) empêche certaines fonctionnalités premium de GitLab de fonctionner correctement si vous ajoutez une nouvelle licence. Solutions de contournement pour ce problème :

- Redémarrez tous les nœuds Rails, Sidekiq et Gitaly après avoir appliqué une nouvelle licence. Cela vide les caches de licence pertinents et permet à toutes les fonctionnalités premium de fonctionner correctement.
- Mettez à niveau vers une version non affectée par ce problème. Les chemins de mise à niveau suivants sont disponibles pour les versions affectées :
  - 15.2.5 --> 15.3.5
  - 15.3.0 - 15.3.4 --> 15.3.5
  - 15.4.1 --> 15.4.3

## 15.3.3 {#1533}

- Dans GitLab 15.3.3, le type de l'attribut `access_level` de l'API [SAML Group Links](../../api/saml.md#saml-group-links) a été modifié en `integer`. Consultez [la documentation de l'API](../../api/group_members.md).
- Un [problème de mise en cache de licence](https://gitlab.com/gitlab-org/gitlab/-/issues/376706) empêche certaines fonctionnalités premium de GitLab de fonctionner correctement si vous ajoutez une nouvelle licence. Solutions de contournement pour ce problème :

  - Redémarrez tous les nœuds Rails, Sidekiq et Gitaly après avoir appliqué une nouvelle licence. Cela vide les caches de licence pertinents et permet à toutes les fonctionnalités premium de fonctionner correctement.
  - Mettez à niveau vers une version non affectée par ce problème. Les chemins de mise à niveau suivants sont disponibles pour les versions affectées :
    - 15.2.5 --> 15.3.5
    - 15.3.0 - 15.3.4 --> 15.3.5
    - 15.4.1 --> 15.4.3

## 15.3.2 {#1532}

Un [problème de mise en cache de licence](https://gitlab.com/gitlab-org/gitlab/-/issues/376706) empêche certaines fonctionnalités premium de GitLab de fonctionner correctement si vous ajoutez une nouvelle licence. Solutions de contournement pour ce problème :

- Redémarrez tous les nœuds Rails, Sidekiq et Gitaly après avoir appliqué une nouvelle licence. Cela vide les caches de licence pertinents et permet à toutes les fonctionnalités premium de fonctionner correctement.
- Mettez à niveau vers une version non affectée par ce problème. Les chemins de mise à niveau suivants sont disponibles pour les versions affectées :
  - 15.2.5 --> 15.3.5
  - 15.3.0 - 15.3.4 --> 15.3.5
  - 15.4.1 --> 15.4.3

## 15.3.1 {#1531}

Un [problème de mise en cache de licence](https://gitlab.com/gitlab-org/gitlab/-/issues/376706) empêche certaines fonctionnalités premium de GitLab de fonctionner correctement si vous ajoutez une nouvelle licence. Solutions de contournement pour ce problème :

- Redémarrez tous les nœuds Rails, Sidekiq et Gitaly après avoir appliqué une nouvelle licence. Cela vide les caches de licence pertinents et permet à toutes les fonctionnalités premium de fonctionner correctement.
- Mettez à niveau vers une version non affectée par ce problème. Les chemins de mise à niveau suivants sont disponibles pour les versions affectées :
  - 15.2.5 --> 15.3.5
  - 15.3.0 - 15.3.4 --> 15.3.5
  - 15.4.1 --> 15.4.3

## 15.3.0 {#1530}

- Les nouveaux dépôts Git créés dans le cluster Gitaly (Praefect) n'utilisent plus le chemin de stockage `@hashed`. Les hooks serveur des nouveaux dépôts doivent être copiés vers un emplacement différent. Praefect génère désormais des chemins de réplique à l'usage du cluster Gitaly. Cette modification est un prérequis pour que le cluster Gitaly (Praefect) puisse créer, supprimer et renommer des dépôts Git de manière atomique.

  Pour identifier le chemin de réplique, [interrogez les métadonnées du dépôt Praefect](../../administration/gitaly/praefect/troubleshooting.md#view-repository-metadata) et transmettez le chemin de stockage `@hashed` à `-relative-path`.

  Grâce à ces informations, vous pouvez installer correctement les [hooks serveur](../../administration/server_hooks.md).

- Un [problème de mise en cache de licence](https://gitlab.com/gitlab-org/gitlab/-/issues/376706) empêche certaines fonctionnalités premium de GitLab de fonctionner correctement si vous ajoutez une nouvelle licence. Solutions de contournement pour ce problème :

  - Redémarrez tous les nœuds Rails, Sidekiq et Gitaly après avoir appliqué une nouvelle licence. Cela vide les caches de licence pertinents et permet à toutes les fonctionnalités premium de fonctionner correctement.
  - Mettez à niveau vers une version non affectée par ce problème. Les chemins de mise à niveau suivants sont disponibles pour les versions affectées :
    - 15.2.5 --> 15.3.5
    - 15.3.0 - 15.3.4 --> 15.3.5
    - 15.4.1 --> 15.4.3

### Installations Geo {#geo-installations-23}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13. Consultez [les détails et la solution de contournement](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13).
- Les transferts LFS peuvent être redirigés vers le site principal depuis le site secondaire en cours de session. Consultez [les détails et la solution de contournement](#lfs-transfers-redirect-to-primary-from-secondary-site-mid-session).
- Suppression incorrecte des fichiers LFS du stockage d'objets sur les sites secondaires Geo. Consultez [les détails et la solution de contournement](#incorrect-object-storage-lfs-file-deletion-on-secondary-sites).

#### Les transferts LFS sont redirigés vers le site principal depuis le site secondaire en cours de session {#lfs-transfers-redirect-to-primary-from-secondary-site-mid-session}

| Versions mineures concernées | Versions de correctif concernées | Corrigé dans |
|-------------------------|-------------------------|----------|
| 15.1                    | Tous                     | Aucune     |
| 15.2                    | Tous                     | Aucune     |
| 15.3                    | 15.3.0 - 15.3.2         | 15.3.3 et versions ultérieures |

Les transferts LFS peuvent [être redirigés vers le site principal depuis le site secondaire en cours de session](https://gitlab.com/gitlab-org/gitlab/-/issues/371571), entraînant l'échec des requêtes de pull et de clonage dans GitLab 15.1.0 à 15.3.2 lorsque le [proxy Geo](../../administration/geo/secondary_proxy/_index.md) est activé. Le proxy Geo est activé par défaut dans GitLab 15.1 et versions ultérieures.

Ce problème est résolu dans GitLab 15.3.3 ; par conséquent, les clients ayant la configuration suivante doivent mettre à niveau vers la version 15.3.3 ou ultérieure :

- LFS est activé.
- Les objets LFS sont répliqués sur les sites Geo.
- Les dépôts sont récupérés via un site secondaire Geo.
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

#### Suppression incorrecte des fichiers LFS du stockage d'objets sur les sites secondaires {#incorrect-object-storage-lfs-file-deletion-on-secondary-sites}

| Versions mineures concernées | Versions de correctif concernées | Corrigé dans |
|-------------------------|-------------------------|----------|
| 15.0                    | Tous                     | Aucune     |
| 15.1                    | Tous                     | Aucune     |
| 15.2                    | Tous                     | Aucune     |
| 15.3                    | 15.3.0 - 15.3.2         | 15.3.3 et versions ultérieures |

[La suppression incorrecte de fichiers du stockage d'objets sur les sites secondaires Geo](https://gitlab.com/gitlab-org/gitlab/-/issues/371397) peut se produire dans GitLab 15.0.0 à 15.3.2 dans les situations suivantes :

- La réplication du stockage d'objets gérée par GitLab est désactivée, et des objets LFS sont créés lors de l'importation d'un projet avec le stockage d'objets activé.
- La réplication gérée par GitLab pour synchroniser le stockage d'objets est activée puis désactivée.

Ce problème est résolu dans la version 15.3.3. Les clients qui ont à la fois LFS activé et des objets LFS répliqués sur les sites Geo doivent mettre à niveau directement vers la version 15.3.3 afin de réduire le risque de perte de données sur les sites secondaires.

## 15.2.5 {#1525}

Un [problème de mise en cache de licence](https://gitlab.com/gitlab-org/gitlab/-/issues/376706) empêche certaines fonctionnalités premium de GitLab de fonctionner correctement si vous ajoutez une nouvelle licence. Solutions de contournement pour ce problème :

- Redémarrez tous les nœuds Rails, Sidekiq et Gitaly après avoir appliqué une nouvelle licence. Cela vide les caches de licence pertinents et permet à toutes les fonctionnalités premium de fonctionner correctement.
- Mettez à niveau vers une version non affectée par ce problème. Les chemins de mise à niveau suivants sont disponibles pour les versions affectées :
  - 15.2.5 --> 15.3.5
  - 15.3.0 - 15.3.4 --> 15.3.5
  - 15.4.1 --> 15.4.3

## 15.2.0 {#1520}

- Les installations GitLab comportant plusieurs nœuds web doivent être [mises à niveau vers la version 15.1](#1510) avant de passer à la version 15.2 (et ultérieures), en raison d'une modification de la configuration Rails pouvant entraîner une génération incohérente des clés ETag.
- Certains workers Sidekiq ont été renommés dans cette version. Pour éviter toute interruption, [exécutez les tâches Rake pour migrer les jobs en attente](../../administration/sidekiq/sidekiq_job_migration.md#migrate-queued-and-future-jobs) avant de démarrer la mise à niveau vers GitLab 15.2.0.
- Gitaly exécute désormais ses binaires dans un [emplacement d'exécution](https://gitlab.com/gitlab-org/gitaly/-/merge_requests/4670). Par défaut, sur les instances du package Linux, ce chemin est `/var/opt/gitlab/gitaly/run/`. Si cet emplacement est monté avec `noexec`, les merge requests génèrent l'erreur suivante :

  ```plaintext
  fork/exec /var/opt/gitlab/gitaly/run/gitaly-<nnnn>/gitaly-git2go-v15: permission denied
  ```

  Pour résoudre ce problème, supprimez l'option `noexec` du montage du système de fichiers. Une alternative consiste à modifier le répertoire d'exécution de Gitaly :

  1. Ajoutez `gitaly['runtime_dir'] = '<PATH_WITH_EXEC_PERM>'` dans `/etc/gitlab/gitlab.rb` et spécifiez un emplacement sans l'option `noexec` définie.
  1. Exécutez `sudo gitlab-ctl reconfigure`.

### Installations Geo {#geo-installations-24}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- `pg_upgrade` ne parvient pas à mettre à niveau la base de données PostreSQL intégrée vers la version 13. Consultez [les détails et la solution de contournement](#pg_upgrade-fails-to-upgrade-the-bundled-postregsql-database-to-version-13).
- Les transferts LFS peuvent être redirigés vers le site principal depuis le site secondaire en cours de session. Consultez [les détails et la solution de contournement](#lfs-transfers-redirect-to-primary-from-secondary-site-mid-session).
- Suppression incorrecte des fichiers LFS du stockage d'objets sur les sites secondaires Geo. Consultez [les détails et la solution de contournement](#incorrect-object-storage-lfs-file-deletion-on-secondary-sites).
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

## 15.1.0 {#1510}

- Dans GitLab 15.1.0, nous passons Rails `ActiveSupport::Digest` à l'utilisation de SHA256 au lieu de MD5. Cela affecte la génération des clés ETag pour les ressources telles que les téléchargements de fichiers Snippet bruts. Pour garantir une génération cohérente des clés ETag sur plusieurs nœuds web lors de la mise à niveau, tous les serveurs doivent d'abord être mis à niveau vers la version 15.1.6 avant de passer à la version 15.2.0 ou ultérieure :

  1. Assurez-vous que tous les nœuds web GitLab exécutent GitLab 15.1.6.
  1. Si vous exécutez [GitLab sur Kubernetes](https://docs.gitlab.com/charts/installation/) à l'aide du chart Helm GitLab cloud native, assurez-vous que tous les pods Webservice exécutent GitLab 15.1.Z :

     ```shell
     kubectl get pods -l app=webservice -o custom-columns=webservice-image:{.spec.containers[0].image},workhorse-image:{.spec.containers[1].image}
     ```

  1. [Activez le feature flag `active_support_hash_digest_sha256`](../../administration/feature_flags/_index.md#how-to-enable-and-disable-features-behind-flags) pour faire passer `ActiveSupport::Digest` à l'utilisation de SHA256 :

     1. [Démarrez la console Rails](../../administration/operations/rails_console.md)
     1. Activez le feature flag :

        ```ruby
        Feature.enable(:active_support_hash_digest_sha256)
        ```

  1. Ensuite seulement, continuez la mise à niveau vers les versions ultérieures de GitLab.
- Les requêtes non authentifiées vers le [champ GraphQL `ciConfig`](../../api/graphql/reference/queries.md#ciconfig) ne sont plus prises en charge. Avant de mettre à niveau vers GitLab 15.1, ajoutez un [jeton d'accès](../../api/rest/authentication.md) à vos requêtes. L'utilisateur créant le jeton doit avoir l'[autorisation](../../user/permissions.md) de créer des pipelines dans le projet.

### Installations Geo {#geo-installations-25}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- Le [proxy Geo](../../administration/geo/secondary_proxy/_index.md) a été [activé par défaut pour différentes URL](https://gitlab.com/gitlab-org/gitlab/-/issues/346112) dans la version 15.1. Cela peut constituer un changement incompatible. Si nécessaire, vous pouvez [désactiver le proxy Geo](../../administration/geo/secondary_proxy/_index.md#disable-secondary-site-http-proxying). Si vous utilisez SAML avec différentes URL, vous devez modifier votre configuration SAML et votre configuration de fournisseur d'identité. Pour plus d'informations, consultez la [documentation Geo avec authentification unique (SSO)](../../administration/geo/replication/single_sign_on.md).
- Les transferts LFS peuvent être redirigés vers le site principal depuis le site secondaire en cours de session. Consultez [les détails et la solution de contournement](#lfs-transfers-redirect-to-primary-from-secondary-site-mid-session).
- Suppression incorrecte des fichiers LFS du stockage d'objets sur les sites secondaires Geo. Consultez [les détails et la solution de contournement](#incorrect-object-storage-lfs-file-deletion-on-secondary-sites).
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](gitlab_16_changes.md#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

## 15.0.0 {#1500}

- Elasticsearch 6.8 [n'est plus pris en charge](../../integration/advanced_search/elasticsearch.md#version-compatibility). Avant de mettre à niveau vers GitLab 15.0, [mettez à niveau Elasticsearch vers une version 7.x](../../integration/advanced_search/elasticsearch.md#upgrade-to-a-new-elasticsearch-version).
- Si vous exécutez GitLab avec un PostgreSQL externe, notamment AWS RDS, assurez-vous de mettre à niveau PostgreSQL vers des niveaux de correctif d'au moins 12.7 ou 13.3 avant de mettre à niveau vers GitLab 14.8 ou une version ultérieure.

  [Dans la version 14.8](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/75511) pour GitLab Enterprise Edition et [dans la version 15.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/87983) pour GitLab Community Edition, une fonctionnalité GitLab appelée Loose Foreign Keys a été activée.

  Après son activation, nous avons reçu des signalements de redémarrages PostgreSQL non planifiés causés par un bug du moteur de base de données qui provoque une erreur de segmentation.

  Pour plus d'informations, consultez le [ticket 364763](https://gitlab.com/gitlab-org/gitlab/-/issues/364763).

- L'utilisation de compartiments S3 chiffrés avec une configuration spécifique au stockage n'est plus prise en charge depuis la [suppression du support de `background_upload`](../deprecations.md#background-upload-for-object-storage).
- L'[intégration Kubernetes basée sur des certificats (OBSOLÈTE)](../../user/infrastructure/clusters/_index.md#certificate-based-kubernetes-integration-deprecated) est désactivée par défaut, mais vous pouvez la réactiver via le [feature flag `certificate_based_clusters`](../../administration/feature_flags/_index.md#how-to-enable-and-disable-features-behind-flags) jusqu'à GitLab 16.0.
- Lorsque vous utilisez le projet GitLab Helm Chart avec un `serviceAccount` personnalisé, assurez-vous qu'il dispose des autorisations `get` et `list` pour les ressources `serviceAccount` et `secret`.
- Le [feature flag](../../administration/feature_flags/_index.md#enable-or-disable-the-feature) `FF_GITLAB_REGISTRY_HELPER_IMAGE` est supprimé et les images d'aide sont toujours extraites du GitLab Registry.

### Installations avec le paquet Linux {#linux-package-installations-2}

- Le paramètre [`custom_hooks_dir`](../../administration/server_hooks.md#create-global-server-hooks-for-all-repositories) pour configurer les hooks serveur globaux est désormais configuré dans Gitaly. L'implémentation précédente dans GitLab Shell a été supprimée dans GitLab 15.0. Avec cette modification, les hooks serveur globaux sont stockés uniquement dans un sous-répertoire portant le nom du type de hook. Les hooks serveur globaux ne peuvent plus être un seul fichier hook à la racine du répertoire des hooks personnalisés. Par exemple, vous devez utiliser `<custom_hooks_dir>/<hook_name>.d/*` plutôt que `<custom_hooks_dir>/<hook_name>`.
  - Utilisez `gitaly['custom_hooks_dir']` dans `gitlab.rb` pour les instances du package Linux. Ceci remplace `gitlab_shell['custom_hooks_dir']`.
- PostgreSQL 13.6 est fourni comme version par défaut pour les nouvelles installations et 12.10 pour les mises à niveau. Vous pouvez mettre à niveau manuellement vers PostgreSQL 13.6 en suivant la [documentation de mise à niveau](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server) avec :

  ```shell
  sudo gitlab-ctl pg-upgrade -V 13
  ```

  Tant que PostgreSQL 12 n'est pas supprimé, vous pouvez [épingler la version de PostgreSQL](https://docs.gitlab.com/omnibus/settings/database/#pin-the-packaged-postgresql-version-fresh-installs-only) si nécessaire pour des raisons de compatibilité ou d'environnement de test.

  [Les installations tolérantes aux pannes et Geo nécessitent des étapes et une planification supplémentaires](../../administration/postgresql/replication_and_failover.md#upgrading-postgresql-major-version-in-a-patroni-cluster).

  En raison de modifications structurelles sous-jacentes, le processus PostgreSQL en cours d'exécution doit être redémarré lors de sa mise à niveau avant d'exécuter les migrations de base de données. Si le redémarrage automatique est ignoré, vous devez exécuter la commande suivante avant l'exécution des migrations :

  ```shell
  # If using PostgreSQL
  sudo gitlab-ctl restart postgresql

  # If using Patroni for Database replication
  sudo gitlab-ctl restart patroni
  ```

  Si PostgreSQL n'est pas redémarré, vous risquez de rencontrer des [erreurs liées au chargement des bibliothèques](https://docs.gitlab.com/omnibus/settings/database/#could-not-load-library-plpgsqlso).

- À partir de GitLab 15.0, les services `postgresql` et `geo-postgresql` sont automatiquement redémarrés lors d'un changement de version de PostgreSQL. Le redémarrage des services PostgreSQL entraîne une interruption de service due à l'indisponibilité temporaire de la base de données pour les opérations. Bien que ce redémarrage soit obligatoire pour le bon fonctionnement des services de base de données, vous pouvez souhaiter davantage de contrôle sur le moment du redémarrage de PostgreSQL. À cette fin, vous pouvez choisir d'ignorer les redémarrages automatiques dans le cadre de `gitlab-ctl reconfigure` et de redémarrer les services manuellement.

  Pour ignorer les redémarrages automatiques dans le cadre de la mise à niveau vers GitLab 15.0, effectuez les étapes suivantes avant la mise à niveau :

  1. Modifiez `/etc/gitlab/gitlab.rb` et ajoutez la ligne suivante :

     ```ruby
     # For PostgreSQL/Patroni
     postgresql['auto_restart_on_version_change'] = false

     # For Geo PostgreSQL
     geo_postgresql['auto_restart_on_version_change'] = false
     ```

  1. Reconfigurez GitLab :

     ```shell
     sudo gitlab-ctl reconfigure
     ```

  > [!note]
  > Il est obligatoire de redémarrer PostgreSQL lors d'un changement de version sous-jacente, afin d'éviter des erreurs telles que [celle liée au chargement des bibliothèques nécessaires](https://docs.gitlab.com/omnibus/settings/database/#could-not-load-library-plpgsqlso) pouvant entraîner une interruption de service. Ainsi, si vous ignorez les redémarrages automatiques en utilisant la méthode précédente, assurez-vous de redémarrer les services manuellement avant de mettre à niveau vers GitLab 15.0.

- À partir de GitLab 15.0, le chiffrement SSL `AES256-GCM-SHA384` ne sera pas autorisé par NGINX par défaut. Si vous utilisez l'[AWS Classic Load Balancer](https://docs.aws.amazon.com/en_en/elasticloadbalancing/latest/classic/elb-ssl-security-policy.html#ssl-ciphers) et avez besoin de ce chiffrement, vous pouvez le rajouter à la liste d'autorisation. Pour ajouter le chiffrement SSL à la liste d'autorisation :

  1. Modifiez `/etc/gitlab/gitlab.rb` et ajoutez la ligne suivante :

     ```ruby
     nginx['ssl_ciphers'] = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:AES256-GCM-SHA384"
     ```

  1. Reconfigurez GitLab :

     ```shell
     sudo gitlab-ctl reconfigure
     ```

- La prise en charge du chemin de socket interne pour Gitaly est supprimée. Dans GitLab 14.10, Gitaly a introduit un nouveau répertoire contenant toutes les données d'exécution nécessaires à son bon fonctionnement. Ce nouveau répertoire remplace l'ancien répertoire de socket interne ; par conséquent, l'utilisation de `gitaly['internal_socket_dir']` a été dépréciée au profit de `gitaly['runtime_dir']`.

  L'ancienne configuration `gitaly['internal_socket_dir']` a été supprimée dans cette version.

- Les paramètres de chargement en arrière-plan pour le stockage d'objets sont supprimés. Le stockage d'objets utilise désormais de préférence les chargements directs.

  Les clés suivantes ne sont plus prises en charge dans `/etc/gitlab/gitlab.rb` :

  - `gitlab_rails['artifacts_object_store_direct_upload']`
  - `gitlab_rails['artifacts_object_store_background_upload']`
  - `gitlab_rails['external_diffs_object_store_direct_upload']`
  - `gitlab_rails['external_diffs_object_store_background_upload']`
  - `gitlab_rails['lfs_object_store_direct_upload']`
  - `gitlab_rails['lfs_object_store_background_upload']`
  - `gitlab_rails['uploads_object_store_direct_upload']`
  - `gitlab_rails['uploads_object_store_background_upload']`
  - `gitlab_rails['packages_object_store_direct_upload']`
  - `gitlab_rails['packages_object_store_background_upload']`
  - `gitlab_rails['dependency_proxy_object_store_direct_upload']`
  - `gitlab_rails['dependency_proxy_object_store_background_upload']`

### Installations compilées manuellement {#self-compiled-installations-1}

- La prise en charge de plusieurs bases de données a été ajoutée à GitLab. Pour les **installations compilées manuellement (à partir des sources)**, `config/database.yml` doit inclure un nom de base de données dans la configuration de base de données. La `main: database` doit être en premier. Si une syntaxe invalide ou dépréciée est utilisée, une erreur est générée lors du démarrage de l'application :

  ```plaintext
  ERROR: This installation of GitLab uses unsupported 'config/database.yml'.
  The main: database needs to be defined as a first configuration item instead of primary. (RuntimeError)
  ```

  Auparavant, le fichier `config/database.yml` se présentait comme suit :

  ```yaml
  production:
    adapter: postgresql
    encoding: unicode
    database: gitlabhq_production
    ...
  ```

  À partir de GitLab 15.0, il doit définir une base de données `main` en premier :

  ```yaml
  production:
    main:
      adapter: postgresql
      encoding: unicode
      database: gitlabhq_production
      ...
  ```

### Installations Geo {#geo-installations-26}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

- Suppression incorrecte des fichiers LFS du stockage d'objets sur les sites secondaires Geo. Consultez [les détails et la solution de contournement](#incorrect-object-storage-lfs-file-deletion-on-secondary-sites).
