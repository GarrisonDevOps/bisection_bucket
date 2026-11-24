---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Espace de travail Confluence
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Utilisez un espace de travail Confluence Cloud comme wiki de votre projet.

Cette intégration ajoute un lien vers un wiki Confluence à la place du [wiki GitLab](../wiki/_index.md). GitLab n'affiche pas votre contenu Confluence.

Lorsque vous activez l'intégration :

- Un nouvel élément de menu est ajouté dans la barre latérale gauche : **Forfait** > **Confluence**. Il renvoie vers votre wiki Confluence.
- L'élément de menu **Forfait** > **Wiki** est masqué.

  Pour accéder au wiki GitLab du projet, utilisez son URL : `<example_project_URL>/-/wikis/home`. Pour faire réapparaître l'élément de menu **Forfait** > **Wiki**, désactivez cette intégration.

La création d'une intégration plus complète avec Confluence Cloud est suivie dans l'[epic 3629](https://gitlab.com/groups/gitlab-org/-/epics/3629).

## Configurer l'intégration {#set-up-the-integration}

Cette intégration peut être activée pour un projet ou pour tous les projets d'un groupe ou d'une instance.

### Pour votre projet ou tous les projets d'un groupe {#for-your-project-or-all-projects-in-a-group}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.
- Vous devez utiliser une URL Confluence Cloud (`https://example.atlassian.net/wiki/`).

Pour configurer l'intégration pour votre projet ou groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. En regard de **Espace de travail Confluence**, sélectionnez **Configurer**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Dans **URL de l'espace de travail Confluence**, saisissez l'URL de votre espace de travail Confluence.
1. Sélectionnez **Enregistrer les modifications**.

Si l'intégration a été activée pour le groupe, vous pouvez tout de même la désactiver pour des projets individuels.

### Pour tous les projets de l'instance {#for-all-projects-on-the-instance}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.
- Vous devez utiliser une URL Confluence Cloud (`https://example.atlassian.net/wiki/`).

Pour configurer l'intégration pour votre instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. En regard de **Espace de travail Confluence**, sélectionnez **Configurer**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Dans **URL de l'espace de travail Confluence**, saisissez l'URL de votre espace de travail Confluence.
1. Sélectionnez **Enregistrer les modifications**.

## Accéder à votre espace de travail Confluence depuis GitLab {#access-your-confluence-workspace-from-gitlab}

Prérequis :

- Vous devez configurer l'intégration [pour votre projet ou groupe](#for-your-project-or-all-projects-in-a-group), ou [pour votre instance](#for-all-projects-on-the-instance).

Pour accéder à votre espace de travail Confluence depuis un projet GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Confluence**.
1. Sélectionnez **Accéder à Confluence**.
