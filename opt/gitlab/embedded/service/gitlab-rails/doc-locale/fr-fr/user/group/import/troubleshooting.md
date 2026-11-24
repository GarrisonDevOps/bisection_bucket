---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Résolution des problèmes de migrations par transfert direct
description: "Résolution des problèmes de migrations par transfert direct GitLab à l'aide des commandes de la console Rails, des solutions d'erreurs et des conseils de configuration."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Dans une [session de console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session), vous pouvez trouver les messages d'échec ou d'erreur pour la tentative d'importation de groupe en utilisant :

```ruby
# Get relevant import records
import = BulkImports::Entity.where(namespace_id: Group.id).map(&:bulk_import).last

# Alternative lookup by user
import = BulkImport.where(user_id: User.find(...)).last

# Get list of import entities. Each entity represents either a group or a project
entities = import.entities

# Get a list of entity failures
entities.map(&:failures).flatten

# Alternative failure lookup by status
entities.where(status: [-1]).pluck(:destination_name, :destination_namespace, :status)
```

Vous pouvez également voir toutes les entités migrées avec les échecs qui leur sont associés à l'aide d'un [point de terminaison API](../../../api/bulk_imports.md#list-all-group-or-project-migration-entities).

## Les migrations sont lentes ou expirent {#migrations-are-slow-or-timing-out}

Si vous rencontrez des migrations très lentes ou des [expirations](../../../administration/instance_limits.md#direct-transfer-migration) durant les migrations, utilisez ces stratégies pour réduire la durée des migrations.

### Ajouter des workers Sidekiq à l'instance de destination {#add-sidekiq-workers-to-the-destination-instance}

Si vous effectuez une migration vers une instance GitLab Self-Managed, pour accélérer les migrations, vous pouvez ajouter des workers Sidekiq à l'instance de destination. Lors de l'augmentation du nombre de workers Sidekiq, vous devez tenir compte des éléments suivants :

- Une seule migration par transfert direct migre cinq groupes ou projets à la fois, quel que soit le nombre de workers Sidekiq disponibles sur l'instance de destination.
- L'instance de destination doit avoir la capacité de traiter davantage de jobs simultanés. Dans ce cas, l'ajout de workers Sidekiq supplémentaires peut réduire le temps nécessaire à l'importation de chaque groupe ou projet.

Pour plus d'informations sur la façon d'ajouter des workers Sidekiq à l'instance de destination, consultez [Configuration de Sidekiq pour les importations](../../../administration/sidekiq/configuration_for_imports.md).

### Démarrer des migrations séparées {#start-separate-migrations}

Vous pouvez rencontrer des retards et des expirations potentielles si l'instance source ne dispose pas des ressources nécessaires pour exporter cinq groupes en parallèle. Lorsque l'instance source manque de ressources, l'instance de destination doit attendre que les données exportées soient disponibles.

Pour réduire les retards causés par les exportations parallèles, démarrez une migration séparée pour chaque groupe plutôt que tous les groupes et projets en même temps. Étant donné que l'interface GitLab ne peut migrer que les groupes principaux, vous pourriez avoir besoin d'utiliser l'API pour migrer les projets dans leurs sous-groupes.

## Importations obsolètes {#stale-imports}

Les migrations peuvent se bloquer ou se terminer avec un statut `timeout` en raison de problèmes sur l'instance source ou de destination. Pour résoudre ces problèmes, inspectez les journaux des instances source et de destination.

### Instance source {#source-instance}

Sur l'instance source, les importations obsolètes sont souvent dues à une utilisation excessive de la mémoire, ce qui peut redémarrer les processus Sidekiq et interrompre les jobs d'exportation. L'instance de destination peut attendre les fichiers d'exportation jusqu'à ce que la migration expire.

Pour vérifier si les relations de [groupe](../../../api/group_relations_export.md#retrieve-the-status-of-an-export) ou de [projet](../../../api/project_relations_export.md#retrieve-the-status-of-an-export) ont été exportées avec succès, exécutez la commande suivante :

```shell
curl --request GET --location "https://example.gitlab.com/api/v4/projects/:ID/export_relations/status" \
--header "PRIVATE-TOKEN: <your_access_token>"
```

Si une {{< glossary-tooltip text="relation" >}} a un statut autre que `1`, la relation n'a pas été exportée avec succès et le problème se trouve sur l'instance source.

Vous pouvez également exécuter la commande suivante pour rechercher les jobs d'exportation interrompus. Gardez à l'esprit que les journaux Sidekiq peuvent être alternés après les redémarrages ; veillez donc à vérifier également les journaux alternés.

```shell
grep `BulkImports::RelationBatchExportWorker` sidekiq.log | grep "interrupted_count"
```

Si les redémarrages de Sidekiq sont à l'origine du problème :

- Configurez un processus Sidekiq séparé pour les jobs d'exportation. Pour plus d'informations, consultez [Configuration de Sidekiq pour l'importation](../../../administration/sidekiq/configuration_for_imports.md). Si le problème persiste, réduisez la simultanéité de Sidekiq pour limiter le nombre de jobs traités simultanément.
- Augmenter les limites de mémoire Sidekiq : si votre instance dispose de mémoire disponible, [augmentez la limite RSS maximale](../../../administration/sidekiq/sidekiq_memory_killer.md#configuring-the-limits) pour les processus Sidekiq. Par exemple, vous pouvez augmenter la limite de 2 Go à 3 Go pour éviter les redémarrages fréquents.
- Augmenter le nombre maximal d'interruptions : pour autoriser davantage d'interruptions avant qu'un job échoue, vous pouvez augmenter le nombre maximal d'interruptions pour [`BulkImports::RelationBatchExportWorker`](https://gitlab.com/gitlab-org/gitlab/-/blob/b8e11d267cdd4a00807984f98a9d8d8cfa51602e/app/workers/bulk_imports/relation_batch_export_worker.rb#L4) :

  1. Ajoutez la configuration suivante pour augmenter la limite à `20` (la valeur par défaut est `3`) :

     ```ruby
     sidekiq_options max_retries_after_interruption: 20
     ```

  1. Redémarrez Sidekiq pour que les modifications prennent effet.

Vous pouvez maintenant déclencher une nouvelle migration ou utiliser l'[API d'exportation des relations de projet](../../../api/project_relations_export.md#schedule-a-new-export-for-a-project) pour déclencher manuellement l'exportation. Vérifiez le [statut de l'exportation](../../../api/project_relations_export.md#retrieve-the-status-of-an-export) pour voir si les relations sont exportées avec succès.

Par exemple, pour déclencher l'exportation d'un projet spécifique, exécutez la commande suivante :

```shell
curl --request POST --location "https://example.gitlab.com/api/v4/projects/:ID/export_relations" \
--header "PRIVATE-TOKEN: <your_access_token>" \
--form 'batched="true"'
```

### Instance de destination {#destination-instance}

Dans de rares cas, l'instance de destination peut ne pas réussir à migrer un groupe ou un projet. Pour plus d'informations, consultez [le ticket 498720](https://gitlab.com/gitlab-org/gitlab/-/issues/498720).

Pour résoudre ce problème, migrez les groupes ou projets qui ont échoué en utilisant l'[API d'importation](../../../api/import.md). Avec cette API, vous pouvez migrer des groupes et des projets spécifiques individuellement.

## Autres erreurs `404` {#other-404-errors}

Vous pouvez recevoir d'autres erreurs `404` lors de l'importation d'un groupe, par exemple :

```json
"exception_message": "Unsuccessful response 404 from [FILTERED] Bo...",
"exception_class": "BulkImports::NetworkError",
```

Cette erreur indique un problème lors du transfert depuis l'instance source. Pour résoudre ce problème, vérifiez que vous avez satisfait aux [prérequis](direct_transfer_migrations.md#prerequisites) sur l'instance source.

## Noms de chemin de groupe ou de projet non concordants {#mismatched-group-or-project-path-names}

Si un chemin de groupe ou de projet source n'est pas conforme aux [règles de nommage](../../reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs), le chemin est normalisé pour s'assurer qu'il est valide. Par exemple, `Destination-Project-Path` est normalisé en `destination-project-path`.

## Erreur : `command exited with error code 15 and Unable to save [FILTERED] into [FILTERED]` {#error-command-exited-with-error-code-15-and-unable-to-save-filtered-into-filtered}

Vous pouvez recevoir l'erreur `command exited with error code 15 and Unable to save [FILTERED] into [FILTERED]` dans les journaux lors de la migration de projets par transfert direct. Si vous recevez cette erreur, vous pouvez l'ignorer en toute sécurité. GitLab réessaie la commande qui s'est terminée.

## Erreur : `Batch export [batch_number] from source instance failed` {#error-batch-export-batch_number-from-source-instance-failed}

Sur l'instance de destination, vous pouvez rencontrer l'erreur suivante :

```plaintext
Batch export [batch_number] from source instance failed: [source instance error]
```

Cette erreur se produit lorsque l'instance source ne parvient pas à exporter certains enregistrements. Les raisons les plus courantes sont :

- Espace disque insuffisant
- Interruptions multiples des jobs Sidekiq en raison d'une mémoire insuffisante
- Expiration d'instruction de base de données

Pour résoudre ce problème :

1. Identifiez et corrigez le problème sur l'instance source.
1. Supprimez le projet ou groupe partiellement importé de l'instance de destination et lancez une nouvelle importation.

Pour plus d'informations sur les relations et les lots qui n'ont pas pu être exportés, utilisez les points de terminaison de l'API de statut d'exportation pour les [projets](../../../api/project_relations_export.md#retrieve-the-status-of-an-export) et les [groupes](../../../api/group_relations_export.md#retrieve-the-status-of-an-export) sur l'instance source.

## Erreur : `duplicate key value violates unique constraint` {#error-duplicate-key-value-violates-unique-constraint}

Lors de l'importation d'enregistrements, vous pouvez obtenir l'erreur suivante :

```plaintext
PG::UniqueViolation: ERROR:  duplicate key value violates unique constraint
```

Cette erreur peut se produire dans les cas suivants :

- Un worker Sidekiq traitant l'importation redémarre en raison d'une utilisation élevée de la mémoire ou du CPU. Pour réduire les problèmes de ressources Sidekiq lors de l'importation :
  - Optimisez la [configuration de Sidekiq pour les importations](../../../administration/sidekiq/configuration_for_imports.md).
  - Limitez le nombre de jobs simultanés dans le [paramètre d'application](../../../api/settings.md) `bulk_import_concurrent_pipeline_batch_limit`.
- Vous [consolidez des groupes ou des projets provenant de différents groupes sources dans un seul groupe de destination](_index.md#known-issues). Lorsque des epics de différents groupes sources ont le même ID interne (qui est unique uniquement dans un seul groupe), leur importation dans un seul groupe de destination provoque des conflits. Ce conflit génère des erreurs `PG::UniqueViolation: ERROR:  duplicate key value violates unique constraint` faisant référence à `index_issues_on_namespace_id_iid_unique` ou `index_epics_on_group_id_and_iid`.

## Erreur : `Import::BulkImports::FileDownloadStrategy::ServiceError Invalid content type` {#error-importbulkimportsfiledownloadstrategyserviceerror-invalid-content-type}

Lors de l'utilisation du transfert direct entre des instances GitLab, vous pouvez rencontrer l'erreur suivante :

```plaintext
Import::BulkImports::FileDownloadStrategy::ServiceError Invalid content type
```

Cette erreur est liée à la façon dont le trafic réseau est acheminé entre les instances. Si un type de contenu autre que `application/gzip` est renvoyé, vos requêtes réseau pourraient contourner GitLab Workhorse.

Pour résoudre ce problème :

- Vérifiez que votre Ingress est configuré pour acheminer le trafic via GitLab Workhorse sur le port `8181` plutôt que directement vers Puma.
- Envisagez d'activer les [téléchargements proxy](../../../administration/object_storage.md#proxy-download) pour le stockage d'objets.

## Titres de jalons avec le suffixe `(imported-xx-datetime)` {#milestone-titles-appended-with-imported-xx-datetime}

Lors de l'importation d'un groupe, si des titres de jalons de groupe et de projet [entrent en conflit avec des titres existants](../../project/milestones/_index.md#milestone-title-rules) dans l'espace de nommage de destination, les jalons importés ont un suffixe unique ajouté à leur titre. Par exemple, `18.0 (imported-3d-1770206299)`.

Pour identifier ces jalons, recherchez dans le fichier `log/importer.log` sur l'instance de destination les éléments suivants :

```plaintext
Updating milestone title - source title used by existing group or project milestone
```

L'entrée du journal inclut :

- `importable_id` : L'ID du groupe en cours d'importation.
- `milestone_title` : le titre du jalon en cours de renommage.
- `existing_group_id` ou `existing_project_id` : L'ID du groupe ou du projet qui contient le jalon existant.

Grâce à ces informations, vous pouvez localiser le jalon et mettre à jour le titre selon vos préférences.

## Erreur : `Destination belongs to a different organization than the current one` {#error-destination-belongs-to-a-different-organization-than-the-current-one}

Les migrations par transfert direct échouent lorsque les espaces de nommage source et de destination appartiennent à des organisations différentes et que l'une ou l'autre organisation est marquée comme isolée.

Pour résoudre cette erreur, migrez vers un espace de nommage de destination appartenant à votre organisation actuelle. Pour plus d'informations, consultez [le ticket 595674](https://gitlab.com/gitlab-org/gitlab/-/issues/595674).

## Le transfert direct échoue lorsqu'un fichier téléchargé dépasse la taille maximale de téléchargement {#direct-transfer-fails-when-a-downloaded-file-exceeds-the-maximum-download-file-size}

Le transfert direct échoue lorsqu'un fichier téléchargé depuis l'instance source est plus volumineux que la taille maximale de téléchargement, qui est de 5 Gio par défaut. Le transfert direct exporte la plupart des données en petits lots, de sorte que la plupart des fichiers ne dépassent pas cette limite. Seules les relations `repository`, `lfs` et `uploads` sont susceptibles de la dépasser.

Sur GitLab Self-Managed et GitLab Dedicated, un administrateur peut augmenter la [taille maximale de téléchargement des fichiers](../../../administration/settings/import_and_export_settings.md#maximum-download-file-size-for-imports-by-direct-or-offline-transfer).

Sur GitLab.com, la limite est fixe et ne peut pas être augmentée. Pour migrer un projet qui dépasse la limite, réduisez la taille de la relation concernée avant de procéder à la migration :

- `repository` : réécrivez l'historique Git pour supprimer les fichiers volumineux. Cette action modifie tous les SHA des commits. Pour plus d'informations, consultez [les méthodes pour réduire la taille du dépôt](../../project/repository/repository_size.md#methods-to-reduce-repository-size).
- `lfs` : migrez le projet, puis envoyez manuellement les objets LFS manquants vers la destination. Pour plus d'informations, consultez [Les objets LFS sont manquants lors du push](../../../topics/git/lfs/troubleshooting.md#lfs-objects-are-missing-on-push).
- `uploads` : aucune solution de contournement n'est disponible. Pour plus d'informations, consultez [le ticket 526344](https://gitlab.com/gitlab-org/gitlab/-/issues/526344).
