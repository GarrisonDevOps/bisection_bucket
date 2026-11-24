---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Créer un site web GitLab Pages à partir d'un modèle CI/CD"
description: Créez un site web GitLab Pages avec un modèle CI/CD pour un générateur de site statique.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab fournit des modèles `.gitlab-ci.yml` pour les générateurs de sites statiques (SSG) les plus populaires. Vous pouvez créer votre propre fichier `.gitlab-ci.yml` à partir de l'un de ces modèles et exécuter le pipeline CI/CD pour générer un site web Pages.

Utilisez un modèle `.gitlab-ci.yml` lorsque vous avez un projet existant auquel vous souhaitez ajouter un site Pages.

Votre dépôt GitLab doit contenir des fichiers spécifiques à un SSG ou du HTML simple. Une fois ces étapes terminées, vous devrez peut-être effectuer une configuration supplémentaire pour que le site Pages se génère correctement.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la liste déroulante **Ajouter** ({{< icon name="plus" >}}), sélectionnez **Nouveau fichier**.
1. Dans la zone de texte **Nom du fichier**, saisissez `.gitlab-ci.yml`. Une liste déroulante apparaît à droite de la zone de texte.
1. Dans la liste déroulante **Appliquer un modèle**, dans la section **Pages**, sélectionnez le nom de votre SSG. Pour le HTML simple, sélectionnez **HTML**.
1. Dans la zone de texte **Message de commit**, saisissez le message de commit.
1. Sélectionnez **Valider les modifications**.

Si tout est configuré correctement, le déploiement du site peut prendre environ 30 minutes.

Pour afficher le pipeline, accédez à **Version** > **Pipelines**.

Lorsque le pipeline est terminé, accédez à **Déployer** > **Pages** pour trouver le lien vers votre site web Pages.

Pour chaque modification envoyée vers votre dépôt, GitLab CI/CD exécute un nouveau pipeline qui publie immédiatement vos modifications sur le site Pages.

Pour afficher le HTML et les autres ressources créées pour le site, [téléchargez les artefacts de job](../../../../ci/jobs/job_artifacts.md#download-job-artifacts).
