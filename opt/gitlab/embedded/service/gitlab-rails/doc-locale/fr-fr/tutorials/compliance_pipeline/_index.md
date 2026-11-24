---
stage: Software Supply Chain Security
group: Compliance
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments-to-other-projects-and-subjects>.
title: 'Tutoriel : créer un pipeline de conformité (obsolète)'
---

<!--- start_remove The following content will be removed on remove_date: '2027-05-25' -->

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/159841) dans GitLab 17.3 et est prévue pour suppression dans la version 20.0. Utilisez plutôt le [type de politique d'exécution de pipeline](../../user/application_security/policies/pipeline_execution_policies.md). Ce changement est un changement cassant. Pour plus d'informations, consultez le [guide de migration](../../user/compliance/compliance_pipelines.md#pipeline-execution-policies-migration).

<!-- vale gitlab_base.FutureTense = NO -->

Vous pouvez utiliser les [pipelines de conformité](../../user/compliance/compliance_pipelines.md) pour vous assurer que des jobs spécifiques liés à la conformité sont exécutés sur les pipelines de tous les projets d'un groupe. Les pipelines de conformité sont appliqués aux projets via des [cadres de conformité](../../user/compliance/compliance_frameworks/_index.md).

Dans ce tutoriel, vous allez :

1. Créer un [nouveau groupe](#create-a-new-group).
1. Créer un [nouveau projet pour la configuration du pipeline de conformité](#create-a-new-compliance-pipeline-project).
1. Configurer un [cadre de conformité](#configure-compliance-framework) à appliquer à d'autres projets.
1. Créer un [nouveau projet et appliquer le cadre de conformité](#create-a-new-project-and-apply-the-compliance-framework) à celui-ci.
1. Combiner la [configuration du pipeline de conformité et la configuration du pipeline standard](#combine-pipeline-configurations).

## Avant de commencer {#before-you-begin}

- Vous devez disposer de l'autorisation de créer de nouveaux groupes principaux.

## Créer un nouveau groupe {#create-a-new-group}

Les cadres de conformité sont configurés dans les groupes principaux. Dans ce tutoriel, vous créez un groupe principal qui :

- Contient deux projets :
  - Le projet de pipeline de conformité pour stocker la configuration du pipeline de conformité.
  - Un autre projet qui doit exécuter un job dans son pipeline, tel que défini par la configuration du pipeline de conformité.
- Dispose du cadre de conformité à appliquer aux projets.

Pour créer le nouveau groupe :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) puis **Nouveau groupe**.
1. Sélectionnez **Créer un groupe**.
1. Dans le champ **Nom du groupe**, saisissez `Tutorial group`.
1. Sélectionnez **Créer un groupe**.

## Créer un nouveau projet de pipeline de conformité {#create-a-new-compliance-pipeline-project}

Vous êtes maintenant prêt à créer un projet de pipeline de conformité. Ce projet contient la [configuration du pipeline de conformité](../../user/compliance/compliance_pipelines.md#example-configuration) à appliquer à tous les projets auxquels le cadre de conformité est appliqué.

Pour créer le projet de pipeline de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le groupe `Tutorial group`.
1. Sélectionnez **Nouveau projet**.
1. Sélectionnez **Créer un projet vide**.
1. Dans le champ **Nom du projet**, saisissez `Tutorial compliance project`.
1. Sélectionnez **Créer le projet**.

Pour ajouter la configuration du pipeline de conformité à `Tutorial compliance project` :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet `Tutorial compliance project`.
1. Sélectionnez **Version** > **Éditeur de pipeline**.
1. Sélectionnez **Configurer le pipeline**.
1. Dans l'éditeur de pipeline, remplacez la configuration par défaut par :

   ```yaml
   ---
   compliance-job:
     script:
       - echo "Running compliance job required for every project in this group..."
   ```

1. Sélectionnez **Valider les modifications**.

## Configurer le cadre de conformité {#configure-compliance-framework}

Le cadre de conformité est configuré dans le [nouveau groupe](#create-a-new-group).

Pour configurer le cadre de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le groupe `Tutorial group`.
1. Sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Frameworks**.
1. Sélectionnez **Nouveau framework**.
1. Dans le champ **Nom**, saisissez `Tutorial compliance framework`.
1. Dans le champ **Description**, saisissez `Compliance framework for tutorial`.
1. Dans le champ **Configuration du pipeline de conformité (facultatif)**, saisissez `.gitlab-ci.yml@tutorial-group/tutorial-compliance-project`.
1. Dans le champ **Couleur d'arrière‐plan**, sélectionnez la couleur de votre choix.
1. Sélectionnez **Ajouter un cadriciel**.

Pour plus de commodité, définissez le nouveau cadre de conformité comme cadre par défaut pour tous les nouveaux projets du groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le groupe `Tutorial group`.
1. Sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Frameworks**.
1. Sélectionnez `Tutorial compliance framework` puis **Modifier le framework**.
1. Sélectionnez **Définir par défaut**.
1. Sélectionnez **Enregistrer les modifications**.

## Créer un nouveau projet et appliquer le cadre de conformité {#create-a-new-project-and-apply-the-compliance-framework}

Votre cadre de conformité est prêt. Vous pouvez maintenant créer des projets dans le groupe, et ceux-ci exécuteront automatiquement la configuration du pipeline de conformité dans leurs pipelines.

Pour créer un nouveau projet pour exécuter la configuration du pipeline de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le groupe `Tutorial group`.
1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) puis **Nouveau projet/dépôt**.
1. Sélectionnez **Créer un projet vide**.
1. Dans le champ **Nom du projet**, saisissez `Tutorial project`.
1. Sélectionnez **Créer le projet**.

Sur la page du projet, notez que le label `Tutorial compliance framework` apparaît, car il a été défini comme cadre de conformité par défaut pour le groupe.

Sans aucune autre configuration de pipeline, `Tutorial project` peut exécuter les jobs définis dans la configuration du pipeline de conformité dans `Tutorial compliance project`.

Pour exécuter la configuration du pipeline de conformité dans `Tutorial project` :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet `Tutorial project`.
1. Sélectionnez **Version** > **Pipelines**.
1. Sélectionnez **Nouveau pipeline**.
1. Sur la page **Nouveau pipeline**, sélectionnez **Exécuter le pipeline**.

Notez que le pipeline exécute un job appelé `compliance-job` dans une étape **test**. Beau travail, vous avez exécuté votre premier job de conformité !

## Combiner les configurations de pipeline {#combine-pipeline-configurations}

Si vous souhaitez que les projets exécutent leurs propres jobs ainsi que les jobs du pipeline de conformité, vous devez combiner la configuration du pipeline de conformité et la configuration du pipeline standard du projet.

Pour combiner les configurations de pipeline, vous devez définir la configuration du pipeline standard, puis mettre à jour la configuration du pipeline de conformité pour y faire référence.

Pour créer la configuration du pipeline standard :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet `Tutorial project`.
1. Sélectionnez **Version** > **Éditeur de pipeline**.
1. Sélectionnez **Configurer le pipeline**.
1. Dans l'éditeur de pipeline, remplacez la configuration par défaut par :

   ```yaml
   ---
   project-job:
     script:
       - echo "Running project job..."
   ```

1. Sélectionnez **Valider les modifications**.

Pour combiner la nouvelle configuration du pipeline de projet avec la configuration du pipeline de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet `Tutorial compliance project`.
1. Sélectionnez **Version** > **Éditeur de pipeline**.
1. Dans la configuration existante, ajoutez :

   ```yaml
   include:
     - project: 'tutorial-group/tutorial-project'
       file: '.gitlab-ci.yml'
    ```

1. Sélectionnez **Valider les modifications**.

Pour confirmer que la configuration du pipeline standard est combinée avec la configuration du pipeline de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet `Tutorial project`.
1. Sélectionnez **Version** > **Pipelines**.
1. Sélectionnez **Nouveau pipeline**.
1. Sur la page **Nouveau pipeline**, sélectionnez **Exécuter le pipeline**.

Notez que le pipeline exécute deux jobs dans une étape **test** :

- `compliance-job`.
- `project-job`.

Félicitations, vous avez créé et configuré un pipeline de conformité !

Consultez d'autres [exemples de configurations de pipeline de conformité](../../user/compliance/compliance_pipelines.md#example-configuration).

<!--- end_remove -->
