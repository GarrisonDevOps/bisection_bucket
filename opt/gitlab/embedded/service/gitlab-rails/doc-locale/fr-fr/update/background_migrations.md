---
stage: Data Access
group: Database Frameworks
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Vérifier les migrations avant la mise à niveau
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

## Gérer les migrations en arrière-plan avec des tâches Rake {#manage-background-migrations-with-rake-tasks}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/191722) dans GitLab 18.5.
- [Amélioré](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/211674) dans GitLab 18.7.
- [Amélioré](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/222806) dans GitLab 18.9.

{{< /history >}}

GitLab fournit un ensemble de tâches Rake pour gérer les migrations en arrière-plan depuis la ligne de commande. Ces tâches sont particulièrement utiles pour les administrateurs GitLab Self-Managed qui doivent gérer les migrations en arrière-plan lorsque l'interface utilisateur d'administration n'est pas disponible, par exemple lors de mises à niveau avec temps d'arrêt ou de fenêtres de maintenance.

Toutes les tâches Rake fonctionnent sur l'ensemble des bases de données (main et ci) et utilisent un format d'identifiant de migration unifié : `{database}_{id}`. Par exemple, `main_85` fait référence à la migration d'identifiant 85 dans la base de données principale, et `ci_10` fait référence à la migration d'identifiant 10 dans la base de données ci.

Pour les migrations actives, la colonne `progress` inclut une estimation du temps restant lorsqu'elle est disponible (par exemple, `42.50% (estimated time remaining: 5 minutes)`).

### Lister toutes les migrations en arrière-plan {#list-all-background-migrations}

Pour afficher toutes les migrations en arrière-plan par lots sur l'ensemble des bases de données :

{{< tabs >}}

{{< tab title="GitLab 18.9 et versions ultérieures" >}}

```shell
sudo gitlab-rake gitlab:background_migrations:list
```

Exemple de résultat :

```plaintext
id      | table_name                       | job_class_name                                | status    | progress
--------|----------------------------------|-----------------------------------------------|-----------|----------------------------------------------------------
main_1  | namespace_settings               | UpdateRequireDpopForManageApiEndpointsToFalse | finished  | 100.00%
main_2  | resource_iteration_events        | BackfillResourceIterationEventsNamespaceId    | finalized | 100.00%
main_3  | identities                       | DeleteTwitterIdentities                       | finalized | 100.00%
main_4  | software_license_policies        | BackfillLicensesOutsideSpdxCatalogue          | finalized | 100.00%
main_5  | security_policies                | BackfillPipelineExecutionPoliciesMetadata     | active    | 42.50% (estimated time remaining: 5 minutes)
ci_1    | ci_runners                       | MarkAdminBotRunnersAsHosted                   | finalized | 100.00%
ci_2    | p_ci_build_trace_metadata        | BackfillUpsertedCiBuildTraceMetadataProjectId | finalized | 100.00%
ci_3    | ci_runners                       | BackfillOrganizationIdOnCiRunners             | active    | 78.30% (estimated time remaining: about 1 hour)
```

{{< /tab >}}

{{< tab title="GitLab 18.8 et versions antérieures" >}}

```shell
sudo gitlab-rake gitlab:background_migrations:status
```

{{< /tab >}}

{{< /tabs >}}

### Afficher les détails d'une migration {#show-migration-details}

Pour afficher des informations détaillées sur une migration spécifique :

```shell
sudo gitlab-rake gitlab:background_migrations:show[<migration_id>]
```

Par exemple :

```shell
sudo gitlab-rake gitlab:background_migrations:show[ci_1]
```

Exemple de résultat :

```plaintext
id                       | ci_1
created_at               | 2025-05-06 22:40:08 UTC
updated_at               | 2025-08-20 22:29:07 UTC
min_value                | 1
max_value                | 30
batch_size               | 1000
sub_batch_size           | 100
interval                 | 120
status                   | finalized
job_class_name           | MarkAdminBotRunnersAsHosted
batch_class_name         | PrimaryKeyBatchingStrategy
table_name               | ci_runners
column_name              | id
job_arguments            | []
total_tuple_count        |
pause_ms                 | 100
max_batch_size           |
started_at               | 2025-05-06 22:40:08 UTC
on_hold_until            |
gitlab_schema            | gitlab_ci
finished_at              | 2025-05-06 22:40:13 UTC
queued_migration_version | 20250505095336
min_cursor               |
max_cursor               |
```

### Mettre en pause une migration {#pause-a-migration}

Pour mettre en pause une migration en arrière-plan active :

```shell
sudo gitlab-rake gitlab:background_migrations:pause[<migration_id>]
```

Par exemple :

```shell
sudo gitlab-rake gitlab:background_migrations:pause[main_85]
```

> [!note]
> Vous pouvez uniquement mettre en pause les migrations dont le statut est `active`. Toute tentative de mise en pause d'une migration dans un autre état génère une erreur.

### Reprendre une migration {#resume-a-migration}

Pour reprendre une migration en arrière-plan mise en pause :

```shell
sudo gitlab-rake gitlab:background_migrations:resume[<migration_id>]
```

Par exemple :

```shell
sudo gitlab-rake gitlab:background_migrations:resume[main_85]
```

> [!note]
> Vous pouvez uniquement reprendre les migrations dont le statut est `paused`. Toute tentative de reprise d'une migration dans un autre état génère une erreur.

### Exécuter une migration {#execute-a-migration}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/211674) dans GitLab 18.7.

{{< /history >}}

> [!warning]
> Cette tâche exécute la migration de manière synchrone au premier plan. La migration s'exécute jusqu'à son achèvement ou son échec. Cette opération peut prendre un temps considérable pour les migrations volumineuses et peut avoir un impact sur les performances de la base de données. Utilisez cette tâche pendant les fenêtres de maintenance dans la mesure du possible.

Pour exécuter immédiatement une migration en arrière-plan spécifique :

```shell
sudo gitlab-rake gitlab:background_migrations:execute[<migration_id>]
```

Par exemple :

```shell
sudo gitlab-rake gitlab:background_migrations:execute[ci_10]
```

Exemple de résultat :

```plaintext
Are you sure you want to execute this migration? yes
Executing background migration `ci_10`...
Done.
```

La tâche demande une confirmation avant l'exécution. Si la migration ne parvient pas à s'exécuter jusqu'à son terme, vérifiez le statut de la migration avec `gitlab:background_migrations:show[<migration_id>]` pour plus de détails.

### Exécuter toutes les migrations {#execute-all-migrations}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/211674) dans GitLab 18.7.

{{< /history >}}

> [!warning]
> Cette tâche exécute toutes les migrations non terminées de manière synchrone au premier plan. Cette opération peut prendre très longtemps et avoir un impact significatif sur les performances de la base de données. N'utilisez cette tâche que pendant les fenêtres de maintenance planifiées. La tâche continue même si des migrations individuelles échouent, mais signale les échecs dans la sortie.

Pour exécuter toutes les migrations en arrière-plan non terminées sur l'ensemble des bases de données :

```shell
sudo gitlab-rake gitlab:background_migrations:execute_all
```

Exemple de résultat :

<!--
The following codeblock uses extra spaces to avoid the Vale ReferenceLinks test.
Do not remove the two-space nesting.
-->

  ```plaintext
  Are you sure you want to execute all unfinished migrations? yes
  [main] Executing 6 background migrations...
  [main_85]: Start.
  [main_85]: Done.
  [main_86]: Start.
  [main_86]: Done.
  [main_87]: Start.
  [main_87]: Done.
  [main_88]: Start.
  [main_88]: Done.
  [main_89]: Start.
  [main_89]: Done.
  [main_90]: Start.
  [main_90]: Done.
  [ci] Executing 3 background migrations...
  [ci_8]: Start.
  [ci_8]: Done.
  [ci_9]: Start.
  [ci_9]: Done.
  [ci_10]: Start.
  [ci_10]: Done.
  ```

La tâche :

- Demande une confirmation avant l'exécution.
- Traite les migrations dans l'ordre par identifiant.
- Signale le statut de chaque migration à mesure qu'elle se termine.
- Continue à traiter les migrations restantes même si certaines échouent.

### Attendre la fin de toutes les migrations {#wait-for-all-migrations-to-finish}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258378) dans GitLab 19.5.

{{< /history >}}

Pour bloquer l'exécution jusqu'à ce que toutes les migrations en arrière-plan par lots non terminées sur l'ensemble des bases de données soient terminées :

```shell
sudo gitlab-rake gitlab:background_migrations:wait
```

Exemple de résultat :

```plaintext
Waiting for batched background migrations to finish, checking every 30s...
Still waiting on 1 batched background migration(s):
Database: main
  active | BackfillPipelineExecutionPoliciesMetadata,security_policies,id,[]
All batched background migrations have finished.
```

Cette tâche est destinée à l'automatisation, par exemple pour conditionner une mise à niveau sans temps d'arrêt à la fin des migrations de la version actuelle avant de démarrer la mise à niveau suivante. Contrairement à [Exécuter toutes les migrations](#execute-all-migrations), elle n'exécute pas les migrations elle-même. Elle se contente d'interroger leur statut pendant que le planificateur les traite.

La tâche :

- Vérifie chaque base de données configurée (`main`, `ci`, etc.).
- Interroge jusqu'à ce qu'aucune migration ne reste dans un état `paused`, `active` ou `finalizing`, puis se termine avec le code `0`.
- Se termine avec un statut non nul si une migration est dans l'état `failed`, car l'attente ne peut pas la résoudre. Résolvez-les d'abord avec [Résoudre les migrations en arrière-plan par lots en échec](#resolve-failed-batched-background-migrations).

Pour contrôler la fréquence d'interrogation de la tâche, définissez la variable d'environnement `BATCHED_MIGRATIONS_WAIT_INTERVAL_SECONDS` sur un entier positif (valeur par défaut : `30`) :

```shell
sudo BATCHED_MIGRATIONS_WAIT_INTERVAL_SECONDS=60 gitlab-rake gitlab:background_migrations:wait
```

La tâche n'a pas de délai d'expiration interne. Limitez le temps d'attente total depuis l'appelant, par exemple avec `timeout` ou un délai limite de job.

La tâche ne capture pas les erreurs de base de données transitoires. En cas d'échec, réexécutez la tâche dans son intégralité.

## Vérifier les migrations en arrière-plan en attente dans la base de données {#check-for-pending-database-background-migrations}

{{< history >}}

- Feature [flag](../administration/feature_flags/_index.md) `execute_batched_migrations_on_schedule` [activé par défaut](https://gitlab.com/gitlab-org/gitlab/-/issues/329511) dans GitLab 13.12.
- Pour GitLab Self-Managed, les administrateurs peuvent choisir de le désactiver.

{{< /history >}}

Pour mettre à jour les tables de la base de données par lots, GitLab peut utiliser des migrations en arrière-plan par lots. Ces migrations sont créées par les développeurs GitLab et s'exécutent automatiquement lors de la mise à niveau. Cependant, ces migrations ont une portée limitée afin de faciliter la migration de certaines colonnes de base de données de type `integer` vers `bigint`, ce qui est nécessaire pour éviter le dépassement des entiers pour certaines tables.

Les migrations en arrière-plan par lots sont gérées par Sidekiq et s'exécutent de manière isolée, de sorte qu'une instance peut rester opérationnelle pendant le traitement des migrations. Cependant, les performances peuvent se dégrader sur les instances de grande taille fortement sollicitées pendant l'exécution des migrations en arrière-plan par lots. Vous devez [surveiller activement le statut Sidekiq](../administration/admin_area.md#background-jobs) jusqu'à ce que toutes les migrations soient terminées.

Pour réduire le temps nécessaire à l'exécution de ces migrations, augmentez le nombre de [workers Sidekiq](../administration/sidekiq/extra_sidekiq_processes.md) pouvant traiter les jobs dans la file d'attente `background_migration`.

### Vérifier le statut des migrations en arrière-plan par lots {#check-the-status-of-batched-background-migrations}

Vous pouvez vérifier le statut des migrations en arrière-plan par lots dans l'interface utilisateur de GitLab, ou en interrogeant directement la base de données. Avant de mettre à niveau GitLab, toutes les migrations doivent avoir le statut `Finished`.

Si les migrations ne sont pas terminées et que vous tentez de mettre à niveau GitLab, vous pourriez voir cette erreur :

```plaintext
Expected batched background migration for the given configuration to be marked
as 'finished', but it is 'active':
```

Si vous obtenez cette erreur, [examinez les options](background_migrations_troubleshooting.md#database-migrations-failing-because-of-batched-background-migration-not-finished) pour savoir comment exécuter les migrations en arrière-plan par lots nécessaires à la mise à niveau de GitLab.

#### Depuis l'interface utilisateur de GitLab {#from-the-gitlab-ui}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

Pour vérifier le statut des migrations en arrière-plan par lots :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Surveillance** > **Migrations en arrière-plan**.
1. Sélectionnez **En file d'attente** ou **Finalisation** pour voir les migrations incomplètes, et **Échec** pour les migrations en échec.

Si une migration affiche **Progression indisponible**, GitLab n'a pas pu estimer la taille de la table lors de la mise en file d'attente de la migration et ne peut donc pas calculer un pourcentage. Si le statut est **Actif**, la migration s'exécute normalement.

#### Depuis la base de données {#from-the-database}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

Pour interroger directement la base de données afin d'obtenir le statut des migrations en arrière-plan par lots :

1. Connectez-vous à une invite `psql`, conformément aux instructions propres à la méthode d'installation de votre instance. Par exemple, `sudo gitlab-psql` pour les installations avec le package Linux.
1. Pour afficher les détails des migrations en arrière-plan par lots incomplètes, exécutez cette requête dans la session `psql` :

   ```sql
   SELECT
     job_class_name,
     table_name,
     column_name,
     job_arguments
   FROM batched_background_migrations
   WHERE status NOT IN(3, 6);
   ```

Vous pouvez également encapsuler la requête avec `gitlab-psql -c "<QUERY>"` pour vérifier le statut des migrations en arrière-plan par lots :

```shell
gitlab-psql -c "SELECT job_class_name, table_name, column_name, job_arguments FROM batched_background_migrations WHERE status NOT IN(3, 6);"
```

Si la requête renvoie zéro ligne, toutes les migrations en arrière-plan par lots sont terminées.

### Activer ou désactiver les fonctionnalités avancées {#enable-or-disable-advanced-features}

Les migrations en arrière-plan par lots proposent des feature flags qui vous permettent de personnaliser les migrations ou de les mettre entièrement en pause. Ces feature flags ne doivent être désactivés que par des utilisateurs expérimentés qui comprennent les risques associés.

#### Mettre en pause les migrations en arrière-plan par lots {#pause-batched-background-migrations}

> [!warning]
> Il peut exister [des risques lors de la désactivation de fonctionnalités publiées](../administration/feature_flags/_index.md#risks-when-disabling-released-features). Consultez l'historique de chaque fonctionnalité pour plus de détails.

Pour mettre en pause une migration en arrière-plan par lots en cours, désactivez la fonctionnalité de migrations en arrière-plan par lots. La désactivation de la fonctionnalité termine le lot de migrations en cours, puis attend de démarrer le lot suivant jusqu'à ce que la fonctionnalité soit réactivée.

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

Utilisez les requêtes de base de données suivantes pour voir l'état de la migration en arrière-plan par lots en cours :

1. Obtenez l'identifiant de la migration en cours d'exécution :

   ```sql
   SELECT
    id,
    job_class_name,
    table_name,
    column_name,
    job_arguments
   FROM batched_background_migrations
   WHERE status NOT IN(3, 6);
   ```

1. Exécutez cette requête en remplaçant `XX` par l'identifiant obtenu à l'étape précédente, pour voir le statut de la migration :

   ```sql
   SELECT
    started_at,
    finished_at,
    finished_at - started_at AS duration,
    min_value,
    max_value,
    batch_size,
    sub_batch_size
   FROM batched_background_migration_jobs
   WHERE batched_background_migration_id = XX
   ORDER BY id DESC
   limit 10;
   ```

1. Exécutez la requête plusieurs fois en l'espace de quelques minutes pour vous assurer qu'aucune nouvelle ligne n'a été ajoutée. Si aucune nouvelle ligne n'a été ajoutée, la migration a été mise en pause.
1. Après avoir confirmé que la migration est en pause, redémarrez la migration (en utilisant la commande `enable` mentionnée précédemment) pour poursuivre le traitement du lot lorsque vous êtes prêt. Sur les instances de grande taille, les migrations en arrière-plan peuvent prendre jusqu'à 48 heures pour terminer chaque lot.

#### Optimisation automatique de la taille des lots {#automatic-batch-size-optimization}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/60133) dans GitLab 13.2 [avec un feature flag](../administration/feature_flags/_index.md) nommé `optimize_batched_migrations`. Activés par défaut.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/204173) dans GitLab 18.4. Le feature flag `optimize_batched_migrations` a été supprimé.

{{< /history >}}

> [!warning]
> Il peut exister [des risques lors de la désactivation de fonctionnalités publiées](../administration/feature_flags/_index.md#risks-when-disabling-released-features). Consultez l'historique de cette fonctionnalité pour plus de détails.

Pour maximiser le débit des migrations en arrière-plan par lots (en termes de nombre de tuples mis à jour par unité de temps), les tailles de lot sont automatiquement ajustées en fonction du temps nécessaire à l'exécution des lots précédents.

#### Exécution en parallèle {#parallel-execution}

Pour accélérer l'exécution des migrations en arrière-plan par lots, deux migrations sont exécutées simultanément.

[Les administrateurs GitLab ayant accès à la console Rails de GitLab](../administration/feature_flags/_index.md) peuvent modifier le nombre de migrations en arrière-plan par lots exécutées en parallèle :

```ruby
ApplicationSetting.update_all(database_max_running_batched_background_migrations: 4)
```

### Résoudre les migrations en arrière-plan par lots en échec {#resolve-failed-batched-background-migrations}

Si une migration en arrière-plan par lots échoue, [corrigez-la et relancez-la](#fix-and-retry-the-migration). Si la migration continue d'échouer avec une erreur, au choix :

- [Terminer manuellement la migration en échec](#finish-a-failed-migration-manually)
- [Marquer la migration en échec comme terminée](#mark-a-failed-migration-finished)

#### Corriger et relancer la migration {#fix-and-retry-the-migration}

Toutes les migrations en arrière-plan par lots en échec doivent être résolues pour effectuer une mise à niveau vers une version plus récente de GitLab. Si vous [vérifiez le statut](#check-the-status-of-batched-background-migrations) des migrations en arrière-plan par lots, certaines migrations peuvent s'afficher dans l'onglet **Échec** avec un statut **en échec** :

![Tableau des migrations en arrière-plan par lots en échec.](img/batched_background_migrations_failed_v14_3.png)

Pour déterminer la cause de l'échec de la migration en arrière-plan par lots, consultez les journaux d'erreurs ou les informations d'erreur dans l'interface utilisateur.

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Surveillance** > **Migrations en arrière-plan**.
1. Sélectionnez l'onglet **Échec**. Cette vue affiche la liste des migrations en arrière-plan par lots en échec.
1. Sélectionnez la **Migration** en échec pour voir les paramètres de la migration et les jobs ayant échoué.
1. Sous **Job ayant échoué**, sélectionnez chaque **ID** pour voir pourquoi le job a échoué.

Si vous êtes client GitLab, envisagez d'ouvrir une [demande d'assistance](https://support.gitlab.com/hc/en-us/requests/new) pour comprendre pourquoi les migrations en arrière-plan par lots ont échoué.

Pour corriger le problème, vous pouvez relancer la migration en échec.

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Surveillance** > **Migrations en arrière-plan**.
1. Sélectionnez l'onglet **Échec**. Cette vue affiche la liste des migrations en arrière-plan par lots en échec.
1. Sélectionnez une migration en arrière-plan par lots en échec à relancer en cliquant sur le bouton de reprise ({{< icon name="retry" >}}).

Pour surveiller les migrations en arrière-plan par lots relancées, vous pouvez [vérifier le statut des migrations en arrière-plan par lots](#check-the-status-of-batched-background-migrations) à intervalles réguliers.

#### Terminer manuellement une migration en échec {#finish-a-failed-migration-manually}

Pour terminer manuellement une migration en arrière-plan par lots ayant échoué avec une erreur, utilisez les informations des journaux d'erreurs ou de la base de données :

{{< tabs >}}

{{< tab title="À partir des journaux d'erreurs" >}}

1. Consultez les journaux d'erreurs et recherchez un message d'erreur `An error has occurred, all later migrations canceled`, comme celui-ci :

   ```plaintext
   StandardError: An error has occurred, all later migrations canceled:

   Expected batched background migration for the given configuration to be marked as
   'finished', but it is 'active':
     {:job_class_name=>"CopyColumnUsingBackgroundMigrationJob",
      :table_name=>"push_event_payloads",
      :column_name=>"event_id",
      :job_arguments=>[["event_id"],
      ["event_id_convert_to_bigint"]]
     }
   ```

1. Exécutez la commande suivante en remplaçant les valeurs entre chevrons par les arguments appropriés :

   ```shell
   sudo gitlab-rake gitlab:background_migrations:finalize[<job_class_name>,<table_name>,<column_name>,'<job_arguments>']
   ```

   Lorsque vous traitez plusieurs arguments, par exemple `[["id"],["id_convert_to_bigint"]]`, échappez la virgule entre chaque argument avec une barre oblique inverse ` \ ` pour éviter une erreur de caractère invalide. Par exemple, pour terminer la migration de l'étape précédente :

   ```shell
   sudo gitlab-rake gitlab:background_migrations:finalize[CopyColumnUsingBackgroundMigrationJob,push_event_payloads,event_id,'[["event_id"]\, ["event_id_convert_to_bigint"]]']
   ```

{{< /tab >}}

{{< tab title="À partir de la base de données" >}}

1. [Vérifiez le statut](#check-the-status-of-batched-background-migrations) de la migration dans la base de données.
1. Utilisez les résultats de la requête pour construire une commande de migration en remplaçant les valeurs entre chevrons par les arguments appropriés :

   ```shell
   sudo gitlab-rake gitlab:background_migrations:finalize[<job_class_name>,<table_name>,<column_name>,'<job_arguments>']
   ```

   Par exemple, si la requête renvoie ces données :

   - `job_class_name` : `CopyColumnUsingBackgroundMigrationJob`
   - `table_name` : `events`
   - `column_name` : `id`
   - `job_arguments` : `[["id"], ["id_convert_to_bigint"]]`

   Lorsque vous traitez plusieurs arguments, par exemple `[["id"],["id_convert_to_bigint"]]`, échappez la virgule entre chaque argument avec une barre oblique inverse ` \ ` pour éviter une erreur de caractère invalide. Chaque virgule dans la valeur du paramètre `job_arguments` doit être échappée avec une barre oblique inverse.

   Par exemple :

   ```shell
   sudo gitlab-rake gitlab:background_migrations:finalize[CopyColumnUsingBackgroundMigrationJob,ci_builds,id,'[["id"\, "stage_id"]\,["id_convert_to_bigint"\,"stage_id_convert_to_bigint"]]']
   ```

{{< /tab >}}

{{< /tabs >}}

#### Marquer une migration en échec comme terminée {#mark-a-failed-migration-finished}

> [!warning]
> [Contactez l'assistance GitLab](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#contact-support) avant d'utiliser ces instructions. Cette action peut entraîner une perte de données et provoquer des défaillances de votre instance difficiles à résoudre.

Il peut arriver que la migration en arrière-plan échoue : lors d'un saut entre trop nombreuses versions de mise à niveau, ou en cas de modifications de schéma de base de données rétrocompatibles. (Pour un exemple, voir [ticket 393216](https://gitlab.com/gitlab-org/gitlab/-/issues/393216)). Les migrations en arrière-plan en échec empêchent toute mise à niveau ultérieure de l'application.

Lorsque la migration en arrière-plan est jugée « sûre » à ignorer, la migration peut être marquée manuellement comme terminée :

> [!warning]
> Assurez-vous de créer une sauvegarde avant de continuer.

```ruby
# Start the rails console

connection = ApplicationRecord.connection # or Ci::ApplicationRecord.connection, depending on which DB was the migration scheduled

Gitlab::Database::SharedModel.using_connection(connection) do
  migration = Gitlab::Database::BackgroundMigration::BatchedMigration.find_for_configuration(
    Gitlab::Database.gitlab_schemas_for_connection(connection),
    'BackfillUserDetailsFields',
    :users,
    :id,
    []
  )

  # mark all jobs completed
  migration.batched_jobs.update_all(status: Gitlab::Database::BackgroundMigration::BatchedJob.state_machine.states['succeeded'].value)
  migration.update_attribute(:status, Gitlab::Database::BackgroundMigration::BatchedMigration.state_machine.states[:finished].value)
end
```

### Exécuter toutes les migrations en arrière-plan de manière synchrone {#run-all-background-migrations-synchronously}

Il peut arriver que vous souhaitiez forcer l'exécution des migrations en arrière-plan au premier plan pendant une fenêtre de maintenance.

Ce script peut expirer ou se terminer avant que toutes les migrations ne soient exécutées. Vous pouvez l'exécuter à nouveau jusqu'à ce que toutes les migrations soient terminées.

```ruby
# Start the rails console

databases = ActiveRecord::Tasks::DatabaseTasks.setup_initial_database_yaml

Gitlab::Database.database_base_models.each do |database_name, model|
  Gitlab::Database::SharedModel.using_connection(model.connection) do
    Gitlab::Database::BackgroundMigration::BatchedMigration.with_status([:paused, :active]).find_each(batch_size: 100) do |migration|
      puts "#{database_name}: Finalizing migration #{migration.job_class_name} (ID: #{migration.id})... "
      Gitlab::Database::BackgroundMigration::BatchedMigrationRunner.finalize(
        migration.job_class_name,
        migration.table_name,
        migration.column_name,
        Gitlab::Json.parse(migration.job_arguments),
        connection: model.connection
      )
      puts("done!\n")
    end
  end
end
```

## Afficher les journaux des migrations en arrière-plan par lots {#view-batched-background-migration-logs}

Lors du dépannage des migrations en arrière-plan par lots, vous pouvez consulter les journaux d'exécution détaillés à plusieurs endroits.

### Journaux Sidekiq {#sidekiq-logs}

Les [journaux Sidekiq](../administration/logs/_index.md#sidekiq-logs) indiquent quand les jobs `Database::BatchedBackgroundMigrationWorker` sont exécutés. Ces journaux indiquent l'exécution des jobs mais n'identifient pas la migration spécifique en cours d'exécution.

### Journaux d'application {#application-logs}

Pour identifier la migration en arrière-plan par lots en cours d'exécution, consultez les [journaux d'application](../administration/logs/_index.md#application_jsonlog). Les journaux d'application contiennent des informations détaillées, notamment :

- Le nom de classe de la migration en arrière-plan par lots spécifique (`job_class_name`)
- Les transitions d'état (en attente, en cours d'exécution, et réussi ou en échec)

### Tracer l'exécution d'une migration {#trace-a-migration-execution}

Pour tracer une migration en arrière-plan par lots spécifique :

1. Trouvez `correlation_id` dans l'entrée du journal Sidekiq pour `Database::BatchedBackgroundMigrationWorker`.
1. Recherchez dans les journaux d'application avec ce `correlation_id` pour voir les transitions d'état détaillées.

Exemple d'entrée de journal d'application :

```json
{
  "severity": "INFO",
  "time": "2025-08-27T22:52:07.806Z",
  "meta.caller_id": "Database::BatchedBackgroundMigration::MainExecutionWorker",
  "correlation_id": "74d0295cbe4bb6147230a7d481fb0f8a",
  "message": "BatchedJob transition",
  "batched_job_id": 725,
  "previous_state": "pending",
  "new_state": "running",
  "batched_migration_id": 638,
  "job_class_name": "BackfillSentNotificationsAfterPartition",
  "job_arguments": []
},
{
  "severity": "INFO",
  "time": "2025-08-27T22:52:14.293Z",
  "meta.caller_id": "Database::BatchedBackgroundMigration::MainExecutionWorker",
  "correlation_id": "74d0295cbe4bb6147230a7d481fb0f8a",
  "message": "BatchedJob transition",
  "batched_job_id": 725,
  "previous_state": "running",
  "new_state": "succeeded",
  "batched_migration_id": 638,
  "job_class_name": "BackfillSentNotificationsAfterPartition",
  "job_arguments": []
}
```

## Vérifier les migrations de recherche avancée en attente {#check-for-pending-advanced-search-migrations}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Cette section ne s'applique que si vous avez activé l'[intégration Elasticsearch](../integration/advanced_search/elasticsearch.md). Les releases majeures exigent que toutes les [migrations de recherche avancée](../integration/advanced_search/elasticsearch.md#advanced-search-migrations) soient terminées à partir de la release mineure la plus récente de votre version actuelle avant la mise à niveau vers la version majeure. Vous pouvez trouver les migrations en attente en exécutant la commande suivante.

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

```shell
sudo gitlab-rake gitlab:elastic:list_pending_migrations
```

{{< /tab >}}

{{< tab title="Auto-compilée (source)" >}}

```shell
cd /home/git/gitlab
sudo -u git -H bundle exec rake gitlab:elastic:list_pending_migrations
```

{{< /tab >}}

{{< /tabs >}}

Si l'indexation de la recherche avancée est activée, [la tâche Rake `gitlab:check`](../integration/advanced_search/elasticsearch.md#all-migrations-must-be-finished-before-doing-a-major-upgrade) indique également si des migrations de recherche avancée sont en attente, et combien. La vérification signale uniquement le statut et n'interrompt pas une mise à niveau ; vous devez donc lire la sortie et agir en conséquence.

Si vous suivez un chemin de mise à niveau long avec de nombreuses migrations en attente, vous pouvez configurer **Remettre en file d'attente les workers d'indexation** et **Nombre de shards pour l'indexation non codée** pour accélérer l'indexation. Une autre option consiste à ignorer les migrations en attente et à [réindexer l'instance](../integration/advanced_search/elasticsearch.md#index-the-instance) après avoir mis à niveau GitLab vers la version cible. Vous pouvez également désactiver la recherche avancée pendant ce processus avec le paramètre [**Recherche avancée**](../integration/advanced_search/elasticsearch.md#advanced-search-configuration).

> [!warning]
> L'indexation de grandes instances comporte des risques. Pour plus d'informations, voir [indexer efficacement les grandes instances](../integration/advanced_search/elasticsearch.md#index-large-instances-efficiently).
