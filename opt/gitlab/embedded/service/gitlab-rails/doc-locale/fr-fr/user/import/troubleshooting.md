---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Dépannage
---

{{< details >}}

Édition : Gratuite, Premium, Ultimate Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lors de la migration vers GitLab, vous pouvez rencontrer les problèmes suivants.

## Des branches sont manquantes dans le dépôt importé {#imported-repository-is-missing-branches}

Si un dépôt importé ne contient pas toutes les branches du dépôt source :

1. Définissez la [variable d'environnement](../../administration/logs/_index.md#override-default-log-level) `IMPORT_DEBUG=true`.
1. Relancez l'importation avec un [nom de groupe, de sous-groupe ou de projet différent](https://about.gitlab.com/releases/2023/02/22/gitlab-15-9-released/#re-import-projects-from-external-providers).
1. Si certaines branches sont toujours manquantes, inspectez [`importer.log`](../../administration/logs/_index.md#importerlog) (par exemple, avec [`jq`](../../administration/logs/log_parsing.md#parsing-gitlab-railsimporterlog)).

## Exception : `Error Importing repository - No such file or directory @ rb_sysopen - (filename)` {#exception-error-importing-repository---no-such-file-or-directory--rb_sysopen---filename}

Cette erreur se produit si vous tentez d'importer un fichier téléchargé `tar.gz` du code source d'un dépôt.

Les importations nécessitent un fichier d'[export GitLab](../project/settings/import_export.md#export-a-project-and-its-data), et pas seulement un fichier de téléchargement du dépôt.

## Diagnostic des importations prolongées ou échouées {#diagnosing-prolonged-or-failed-imports}

Si vous rencontrez des délais prolongés ou des échecs lors d'importations basées sur des fichiers, notamment celles utilisant S3, les éléments suivants peuvent aider à identifier la cause du problème :

- [Vérifier les étapes d'importation](#check-import-status)
- [Examiner les journaux](#review-logs)
- [Identifier les problèmes courants](#identify-common-issues)

### Vérifier le statut de l'importation {#check-import-status}

Vérifiez le statut de l'importation :

1. Utilisez l'API GitLab pour vérifier le [statut de l'importation](../../api/project_import_export.md#retrieve-the-status-of-a-project-import) du projet concerné.
1. Examinez la réponse pour détecter tout message d'erreur ou information de statut, en particulier les valeurs `status` et `import_error`.
1. Notez le `correlation_id` dans la réponse, car il est essentiel pour la résolution des problèmes.

### Examiner les journaux {#review-logs}

Recherchez dans les journaux les informations pertinentes :

Pour les instances GitLab Self-Managed :

1. Consultez les [journaux Sidekiq](../../administration/logs/_index.md#sidekiqlog) et les [journaux `exceptions_json`](../../administration/logs/_index.md#exceptions_jsonlog).
1. Recherchez les entrées relatives à `RepositoryImportWorker` et à l'ID de corrélation obtenu lors de la [vérification du statut de l'importation](#check-import-status).
1. Recherchez les champs tels que `job_status`, `interrupted_count` et `exception`.

Pour GitLab.com (membres de l'équipe GitLab uniquement) :

1. Utilisez [Kibana](https://log.gprd.gitlab.net/) pour rechercher dans les journaux Sidekiq avec des requêtes telles que :

   Cible : `pubsub-sidekiq-inf-gprd*`

   ```plaintext
   json.class: "RepositoryImportWorker" AND json.correlation_id.keyword: "<CORRELATION_ID>"
   ```

   ou

   ```plaintext
   json.class: "RepositoryImportWorker" AND json.meta.project: "<project.full_path>"
   ```

1. Recherchez les mêmes champs que ceux mentionnés pour les instances GitLab Self-Managed.

### Identifier les problèmes courants {#identify-common-issues}

Comparez les informations collectées dans les [journaux examinés](#review-logs) avec les problèmes courants suivants :

- Jobs interrompus : si vous constatez une valeur élevée pour `interrupted_count` ou un `job_status` indiquant un échec, le job d'importation a peut-être été interrompu plusieurs fois et placé dans une file morte.
- Connectivité S3 : pour les importations utilisant S3, vérifiez la présence de messages d'erreur liés à S3 dans les journaux.
- Dépôt volumineux : si le dépôt est très volumineux, l'importation peut expirer. Dans ce cas, envisagez d'utiliser le [transfert direct](../group/import/_index.md).

## Base de connaissances du support {#support-knowledge-base}

Si vous rencontrez toujours des problèmes, consultez la [base de connaissances du support GitLab](https://support.gitlab.com/hc/en-us/).
