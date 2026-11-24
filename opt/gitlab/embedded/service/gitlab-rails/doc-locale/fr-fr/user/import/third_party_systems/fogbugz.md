---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Migrer depuis FogBugz
description: "Migrer de FogBugz vers GitLab."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Importez votre projet FogBugz dans GitLab.

L'importateur FogBugz importe l'ensemble de vos tickets et commentaires avec les numéros de ticket et les horodatages d'origine. Vous pouvez mapper les utilisateurs FogBugz aux utilisateurs GitLab.

## Prérequis {#prerequisites}

- [Source d'import FogBugz](../../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources) activée. Si elle n'est pas activée, demandez à votre administrateur GitLab de l'activer. La source d'import FogBugz est activée par défaut sur GitLab.com.
- Le rôle Maintainer ou Owner sur le groupe de destination vers lequel importer.

## Importer un projet depuis FogBugz {#import-project-from-fogbugz}

Pour importer votre projet depuis FogBugz :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Importer un projet**.
1. Sélectionnez **FogBugz**.
1. Saisissez votre URL FogBugz, votre adresse e-mail et votre mot de passe.
1. Créez un mappage entre les utilisateurs FogBugz et les utilisateurs GitLab. Pour chaque utilisateur FogBugz :
   - Pour mapper un compte FogBugz à un nom complet, sans le mapper à un compte GitLab, laissez le champ de texte **Utilisateur GitLab** vide. Ce mappage ajoute le nom complet de l'utilisateur à la description de tous les tickets et commentaires, mais attribue les tickets et les commentaires au créateur du projet.
   - Pour mapper un compte FogBugz à un compte GitLab, dans **Utilisateur GitLab**, sélectionnez l'utilisateur GitLab auquel vous souhaitez associer les tickets et les commentaires.
1. Lorsque tous les utilisateurs sont mappés, sélectionnez **Passer à l'étape suivante**.
1. Pour importer un projet :
   - Pour la première fois : sélectionnez **Importer**.
   - À nouveau : sélectionnez **Réimporter**. Spécifiez un nouveau nom et sélectionnez à nouveau **Réimporter**. La réimportation crée une nouvelle copie du projet source.
1. Une fois l'import terminé, sélectionnez le lien pour accéder au tableau de bord du projet. Suivez les instructions pour pousser votre dépôt existant.

## Sujets connexes {#related-topics}

- [Paramètres d'import et d'export](../../../administration/settings/import_and_export_settings.md).
- [Configuration Sidekiq pour les imports](../../../administration/sidekiq/configuration_for_imports.md).
- [Exécution de plusieurs processus Sidekiq](../../../administration/sidekiq/extra_sidekiq_processes.md).
- [Traitement de classes de job spécifiques](../../../administration/sidekiq/processing_specific_job_classes.md).
