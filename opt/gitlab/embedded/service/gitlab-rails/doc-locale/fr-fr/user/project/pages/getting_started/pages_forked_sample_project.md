---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Créer un site web GitLab Pages à partir d'un exemple de projet dupliqué"
description: Créez un site web GitLab Pages en dupliquant un exemple de projet de générateur de sites statiques.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab fournit [des exemples de projets pour les générateurs de sites statiques (SSG) les plus populaires](https://gitlab.com/pages). Vous pouvez dupliquer l'un des exemples de projets et exécuter le pipeline CI/CD pour générer un site web Pages.

Dupliquez un exemple de projet lorsque vous souhaitez tester GitLab Pages ou démarrer un nouveau projet déjà configuré pour générer un site Pages.

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez un [tutoriel vidéo](https://www.youtube.com/watch?v=TWqh9MtT4Bg) sur le fonctionnement de cette fonctionnalité.

Pour dupliquer un exemple de projet et créer un site web Pages :

1. Consultez les exemples de projets en accédant au groupe [GitLab Pages examples](https://gitlab.com/pages).
1. Sélectionnez le nom du projet que vous souhaitez [dupliquer](../../repository/forking_workflow.md#create-a-fork).
1. Dans le coin supérieur droit, sélectionnez **Bifurcation**, puis choisissez un espace de nommage vers lequel dupliquer.
1. Pour votre projet, dans la barre latérale gauche, sélectionnez **Version** > **Pipelines**, puis **Nouveau pipeline**. GitLab CI/CD compile et déploie votre site.

Le déploiement du site peut prendre environ 30 minutes. Une fois le pipeline terminé, accédez à **Déployer** > **Pages** pour trouver le lien vers votre site web Pages.

Pour chaque modification envoyée vers votre dépôt, GitLab CI/CD exécute un nouveau pipeline qui publie immédiatement vos modifications sur le site Pages.

## Supprimer la relation de bifurcation {#remove-the-fork-relationship}

Si vous souhaitez contribuer au projet dont vous avez effectué la duplication, vous pouvez conserver la relation de duplication. Sinon :

1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Paramètres avancés**.
1. Sélectionnez **Supprimer la relation de bifurcation**.

## Modifier l'URL {#change-the-url}

Vous pouvez modifier l'URL pour qu'elle corresponde à votre espace de nommage. Si votre site Pages est hébergé sur GitLab.com, vous pouvez le renommer en `<namespace>.gitlab.io`, où `<namespace>` est votre espace de nommage GitLab (celui que vous avez choisi lors de la duplication du projet).

1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Paramètres avancés**.
1. Dans **Changer le chemin**, mettez à jour le chemin vers `<namespace>.gitlab.io`.

   Par exemple, si l'URL de votre projet est `gitlab.com/gitlab-tests/jekyll`, votre espace de nommage est `gitlab-tests`.

   Si vous définissez le chemin du dépôt sur `gitlab-tests.gitlab.io`, l'URL résultante de votre site web Pages est `https://gitlab-tests.gitlab.io`.

   ![Modifier le chemin du dépôt](img/change_path_v12_10.png)

1. Ouvrez votre fichier de configuration SSG et modifiez l'[URL de base](../getting_started_part_one.md#urls-and-base-urls) de `"project-name"` vers `""`. Le paramètre de nom de projet varie selon le SSG et peut ne pas figurer dans le fichier de configuration.

## Sujets connexes {#related-topics}

- [Télécharger les artefacts de job](../../../../ci/jobs/job_artifacts.md#download-job-artifacts)
