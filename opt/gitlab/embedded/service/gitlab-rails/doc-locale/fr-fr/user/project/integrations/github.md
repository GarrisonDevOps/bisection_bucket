---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitHub
description: Envoyer les mises à jour du statut du pipeline CI/CD GitLab à GitHub.
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez mettre à jour GitHub avec les mises à jour du statut du pipeline depuis GitLab. L'intégration GitHub peut vous aider si vous utilisez GitLab pour CI/CD.

![Mise à jour du statut du pipeline sur GitHub](img/github_status_check_pipeline_update_v10_6.png)

Cette intégration de projet est distincte de l'[intégration GitHub à l'échelle de l'instance](../import/github.md#mirror-a-repository-and-share-pipeline-status) et est automatiquement configurée lorsque vous importez un [projet GitHub](../../../integration/github.md).

## Configurer l'intégration {#configure-the-integration}

Cette intégration nécessite un [jeton d'API GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) avec l'accès `repo:status` accordé.

Effectuez ces étapes sur GitHub :

1. Accédez à votre page **Jetons d'accès personnel** à l'adresse <https://github.com/settings/tokens>.
1. Sélectionnez **Generate new token**.
1. Sous **Note**, saisissez un nom pour le nouveau jeton.
1. Assurez-vous que `repo:status` est sélectionné et sélectionnez **Générer un jeton**.
1. Copiez le jeton généré pour l'utiliser dans GitLab.

Effectuez ces étapes dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **GitHub**.
1. Assurez-vous que la case **Actif** est cochée.
1. Dans **Jeton**, collez le jeton que vous avez généré sur GitHub.
1. Dans **URL du dépôt**, saisissez le chemin vers votre projet sur GitHub, par exemple `https://github.com/username/repository`.
1. Facultatif. Pour désactiver les [noms de vérification de l'état statique](#static-or-dynamic-status-check-names), décochez la case **Activer les noms de vérification de l'état statique**.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

Après avoir configuré l'intégration, consultez [Pipelines pour les pull requests externes](../../../ci/ci_cd_for_external_repos/_index.md#pipelines-for-external-pull-requests) pour configurer les pipelines à exécuter pour les pull requests ouvertes.

### Noms de vérification de l'état statique ou dynamique {#static-or-dynamic-status-check-names}

Un nom de vérification de l'état peut être statique ou dynamique :

- **Statique** : le nom d'hôte de votre instance GitLab est ajouté au nom de vérification de l'état.

- **Dynamique** : le nom de la branche est ajouté au nom de vérification de l'état.

L'option **Activer les noms de vérification de l'état statique** vous permet de configurer les vérifications de statut requises dans GitHub, qui nécessitent un nom cohérent (statique) pour fonctionner correctement.

Si vous [désactivez cette option](#configure-the-integration), GitLab utilise à la place des noms de vérification de l'état dynamiques.
