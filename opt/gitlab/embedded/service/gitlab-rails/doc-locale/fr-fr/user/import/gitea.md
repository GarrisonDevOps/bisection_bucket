---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Migrer depuis Gitea
description: "Migrer depuis Gitea vers GitLab."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Possibilité d'importer des projets dont le chemin contient un `.` [ajoutée](https://gitlab.com/gitlab-org/gitlab/-/issues/434175) dans GitLab 16.11.
- Un badge **Importé** sur certains éléments importés [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/461208) dans GitLab 17.2.
- [Modification sur GitLab.com](https://gitlab.com/groups/gitlab-org/-/work_items/14667) vers le [mappage des contributions des utilisateurs et des membres après la migration](mapping/post_migration_mapping.md) dans GitLab 17.8.
- Mappage des contributions des utilisateurs et des membres après la migration [activé sur GitLab.com et GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/176675) dans GitLab 17.8.

{{< /history >}}

Importez vos projets depuis Gitea vers GitLab.

L'outil d'importation Gitea importe un sous-ensemble d'éléments depuis Gitea.

| Élément Gitea                    | Importé |
|:------------------------------|:---------|
| Description du dépôt        | {{< yes >}} |
| Données du dépôt Git           | {{< yes >}} |
| Les tickets                        | {{< yes >}} |
| Pull requests                 | {{< yes >}} |
| Les jalons                    | {{< yes >}} |
| Labels                        | {{< yes >}} |
| Commentaires de diff des pull requests |          |

## Workflow de l'outil d'importation {#importer-workflow}

L'outil d'importation Gitea prend en charge le mappage après migration des contributions des utilisateurs pour GitLab.com et GitLab Self-Managed. L'outil d'importation prend également en charge une [méthode alternative](#alternative-method-of-mapping) de mappage.

Lors de l'importation :

- L'accès public au dépôt est conservé. Si un dépôt est privé dans Gitea, il est également créé comme privé dans GitLab.
- Les tickets, les merge requests et les commentaires importés comportent un badge **Importé** dans GitLab.
- Gitea n'étant pas un fournisseur OAuth, l'auteur ou le responsable ne peut pas être mappé aux utilisateurs de votre instance GitLab. Le créateur du projet (généralement l'utilisateur qui a lancé le processus d'importation) est alors défini comme auteur. Pour les tickets, vous pouvez toujours voir l'auteur Gitea d'origine.
- GitLab ne crée pas automatiquement les espaces de nommage ou les groupes qui n'existent pas, et ne bascule pas vers votre espace de nommage personnel si le nom de l'espace de nommage ou du groupe est déjà pris.

## Prérequis {#prerequisites}

- Gitea version 1.0.0 ou ultérieure.
- Vous devez activer la [source d'importation Gitea](../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources) ou demander à votre administrateur GitLab de l'activer. Activé par défaut sur GitLab.com.
- Le rôle Maintainer ou Owner sur le groupe de destination vers lequel effectuer l'importation.

## Importer vos dépôts Gitea {#import-your-gitea-repositories}

Lors de l'importation, vous créez un jeton d'accès personnel et effectuez une autorisation unique avec Gitea pour accorder à GitLab l'accès à vos dépôts.

Pour importer vos dépôts Gitea :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Pour démarrer le processus d'autorisation de l'importation, sélectionnez **Gitea**.
1. Accédez à `https://your-gitea-instance/user/settings/applications`. Remplacez `your-gitea-instance` par le nom d'hôte de votre instance Gitea.
1. Sélectionnez **Generate New Token**.
1. Saisissez une description du jeton.
1. Sélectionnez **Generate Token**.
1. Copiez le hachage du jeton.
1. Retournez dans GitLab et fournissez le jeton à l'outil d'importation Gitea.
1. Sélectionnez **Lister vos dépôts Gitea** et attendez que GitLab lise les informations de vos dépôts. Une fois l'opération terminée, GitLab affiche la page de l'outil d'importation pour sélectionner les dépôts à importer. À partir de là, vous pouvez consulter les statuts d'importation de vos dépôts Gitea :

   - Ceux qui sont en cours d'importation affichent un statut démarré.
   - Ceux qui ont déjà été importés avec succès sont en vert avec un statut terminé.
   - Ceux qui ne sont pas encore importés ont **Importer** sur le côté droit du tableau.
   - Ceux qui sont déjà importés ont **Réimporter** sur le côté droit du tableau.

1. Pour terminer l'importation des dépôts Gitea, vous pouvez :

   - Importer tous vos projets Gitea en une seule fois. Dans le coin supérieur gauche, sélectionnez **Importer tous les projets**.
   - Importer uniquement les projets sélectionnés en filtrant les projets par nom. Si vous appliquez un filtre, **Importer tous les projets** importe uniquement les projets sélectionnés.
   - Choisissez un nom différent pour le projet et un espace de nommage différent si vous disposez des privilèges nécessaires.

## Méthode alternative de mappage {#alternative-method-of-mapping}

Dans GitLab 18.5 et versions antérieures, vous pouvez désactiver le feature flag `gitea_user_mapping` pour utiliser la méthode alternative de mappage des contributions des utilisateurs pour les importations.

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Cette fonctionnalité n'est pas recommandée et n'est pas disponible pour :
>
> - Les migrations vers GitLab.com.
> - Les migrations vers GitLab Self-Managed et GitLab Dedicated 18.6 et versions ultérieures.
>
> Les problèmes détectés dans cette méthode de mappage ont peu de chances d'être corrigés. Utilisez plutôt la [méthode post-migration](mapping/post_migration_mapping.md) qui ne présente pas ces limitations.
>
> Pour plus d'informations, consultez le [ticket 512211](https://gitlab.com/gitlab-org/gitlab/-/work_items/512211).

Avec cette méthode, les contributions des utilisateurs sont attribuées par défaut au créateur du projet (généralement l'utilisateur qui a lancé le processus d'importation).

## Sujets connexes {#related-topics}

- [Paramètres d'importation et d'exportation](../../administration/settings/import_and_export_settings.md).
- [Configuration de Sidekiq pour les importations](../../administration/sidekiq/configuration_for_imports.md).
- [Exécution de plusieurs processus Sidekiq](../../administration/sidekiq/extra_sidekiq_processes.md).
- [Traitement de classes de jobs spécifiques](../../administration/sidekiq/processing_specific_job_classes.md).
