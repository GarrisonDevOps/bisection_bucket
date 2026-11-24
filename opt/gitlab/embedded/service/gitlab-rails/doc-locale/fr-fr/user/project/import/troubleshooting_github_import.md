---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Résoudre les problèmes de migration GitHub
description: "Résolution des problèmes d'importation GitHub, notamment les processus échoués, les préfixes manquants et les erreurs liées aux grands projets."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lors de l'importation d'un projet de GitHub vers GitLab, vous pouvez rencontrer les problèmes suivants.

## Reprendre manuellement un processus d'importation précédemment échoué {#manually-continue-a-previously-failed-import-process}

Dans certains cas, le processus d'importation GitHub peut échouer à importer le dépôt. Cela amène GitLab à abandonner le processus d'importation du projet et nécessite que le dépôt soit importé manuellement. Les administrateurs peuvent importer manuellement le dépôt pour un processus d'importation ayant échoué :

1. Ouvrez une console Rails.
1. Exécutez la série de commandes suivante dans la console :

   ```ruby
   project_id = <PROJECT_ID>
   github_access_token =  <GITHUB_ACCESS_TOKEN>
   github_repository_path = '<GROUP>/<REPOSITORY>'

   github_repository_url = "https://#{github_access_token}@github.com/#{github_repository_path}.git"

   # Find project by ID
   project = Project.find(project_id)
   # Set import URL and credentials
   project.import_url = github_repository_url
   project.import_type = 'github'
   project.import_source = github_repository_path
   project.save!
   # Create an import state if the project was created manually and not from a failed import
   project.create_import_state if project.import_state.blank?
   # Set state to start
   project.import_state.force_start

   # Optional: If your import had certain optional stages selected or a timeout strategy
   # set, you can reset them here. Below is an example.
   # The params follow the format documented in the API:
   # https://docs.gitlab.com/api/import/#import-repository-from-github
   Gitlab::GithubImport::Settings
   .new(project)
   .write(
     timeout_strategy: "optimistic",
     optional_stages: {
       attachments_import: true,
       collaborators_import: true
     }
   )

   # Trigger import from second step
   Gitlab::GithubImport::Stage::ImportRepositoryWorker.perform_async(project.id)
   ```

## Échec de l'importation en raison d'un préfixe manquant {#import-fails-due-to-missing-prefix}

Vous pouvez obtenir une erreur indiquant `Import failed due to a GitHub error: (HTTP 406)`.

Ce problème survient car le préfixe de chemin `api/v3` a été supprimé de l'outil d'importation GitHub. Cela s'est produit parce que l'outil d'importation a cessé d'utiliser le `Gitlab::LegacyGithubImport::Client`. Ce client ajoutait automatiquement le préfixe `api/v3` lors des importations depuis une URL GitHub Enterprise.

Pour contourner cette erreur, [ajoutez le préfixe `api/v3`](https://gitlab.com/gitlab-org/gitlab/-/issues/438358#note_1978902725) lors de l'importation depuis une URL GitHub Enterprise.

## Erreurs lors de l'importation de projets volumineux {#errors-when-importing-large-projects}

L'outil d'importation GitHub peut rencontrer des erreurs lors de l'importation de projets volumineux.

### Commentaires manquants {#missing-comments}

L'API GitHub impose une limite qui empêche l'importation de plus d'environ 30 000 notes ou notes de diff. Lorsque cette limite est atteinte, l'API GitHub renvoie à la place l'erreur suivante :

```plaintext
In order to keep the API fast for everyone, pagination is limited for this resource. Check the rel=last link relation in the Link response header to see how far back you can traverse.
```

Cette erreur ne peut se produire que pour les importations de projets sur GitLab 19.3 et versions antérieures lorsque l'option **Utiliser la méthode alternative d'importation des commentaires** n'est pas sélectionnée. Cette erreur ne peut pas se produire pour les importations de projets configurées sur GitLab 19.4 et versions ultérieures, car cette méthode est toujours activée.

## Sujets connexes {#related-topics}

- [Paramètres d'importation et d'exportation](../../../administration/settings/import_and_export_settings.md).
- [Configuration de Sidekiq pour les importations](../../../administration/sidekiq/configuration_for_imports.md).
- [Exécution de plusieurs processus Sidekiq](../../../administration/sidekiq/extra_sidekiq_processes.md).
- [Traitement de classes de jobs spécifiques](../../../administration/sidekiq/processing_specific_job_classes.md).
