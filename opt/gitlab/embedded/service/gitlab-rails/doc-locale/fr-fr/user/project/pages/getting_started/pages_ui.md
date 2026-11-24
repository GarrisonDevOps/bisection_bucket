---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Créer un déploiement GitLab Pages pour un site statique
description: "Déployez un site statique ou une application basée sur un framework vers GitLab Pages à l'aide d'un formulaire d'interface utilisateur guidé."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Créez un déploiement GitLab Pages pour convertir votre site statique ou votre framework en un site web hébergé sur GitLab. Via un formulaire étape par étape, GitLab :

- Génère une configuration CI/CD personnalisée en fonction de la configuration de votre projet.
- Crée un fichier `.gitlab-ci.yml` configuré pour les déploiements GitLab Pages.
- Soumet les modifications via une merge request pour votre révision.
- Déploie votre site web automatiquement lorsque la merge request est mergée.

Avec l'interface utilisateur Pages, vous pouvez déployer un site statique ou une application basée sur un framework.

## Prérequis {#prerequisites}

- Votre application doit [générer des fichiers dans le dossier `public`](../public_folder.md). Si vous créez ce dossier durant le pipeline de build, vous n'avez pas besoin de le committer dans Git.

  > [!warning]
  > Cette étape est importante. Assurez-vous que vos fichiers se trouvent dans un dossier `public` à la racine.

- Vous devez disposer d'un projet qui :
  - Génère des sites statiques ou une application monopage (SPA) rendue côté client, comme [Eleventy](https://www.11ty.dev), [Astro](https://astro.build), ou [Jekyll](https://jekyllrb.com).
  - Contient un framework configuré pour une sortie statique, comme [Next.js](https://nextjs.org), [Nuxt](https://nuxt.com), ou [SvelteKit](https://kit.svelte.dev).
- GitLab Pages doit être activé pour le projet. (Pour l'activer, accédez à **Paramètres** > **Général**, développez **Visibilité, fonctionnalités du projet, autorisations**, et activez le bouton bascule **Pages**.)

## Créer le déploiement Pages {#create-the-pages-deployment}

Pour finaliser la configuration et générer un déploiement GitLab Pages :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Pages**.

   Un formulaire **Get Started with Pages** s'affiche. Si ce formulaire n'est pas disponible, consultez la section [Dépannage](#if-the-get-started-with-pages-form-is-not-available).
1. Pour **Étape 1**, saisissez un nom d'image. Vous pouvez également [définir un dossier personnalisé à déployer avec Pages](../introduction.md#customize-the-default-folder).
1. Sélectionnez **Suivant**.
1. Pour **Étape 2**, saisissez vos étapes d'installation. Si le processus de build de votre framework n'a pas besoin de l'une des commandes de build fournies, vous pouvez :
   - Ignorer l'étape en sélectionnant **Suivant**.
   - Saisir `:` (la commande bash « ne rien faire ») si vous souhaitez tout de même intégrer le code standard de cette étape dans votre fichier `.gitlab-ci.yml`.
1. Sélectionnez **Suivant**.
1. Pour **Étape 3**, saisissez les scripts indiquant comment builder votre application.
1. Sélectionnez **Suivant**.
1. Facultatif. Modifiez le fichier `.gitlab-ci.yml` généré selon vos besoins.
1. Pour **Étape 4**, ajoutez un message de commit et sélectionnez **Commit**. Ce commit déclenche votre premier déploiement GitLab Pages.

Pour afficher le pipeline en cours d'exécution, accédez à **Version** > **Pipelines**. Lorsque le pipeline réussit, votre site Pages est déployé et accessible.

Pour afficher les artéfacts créés lors du déploiement, consultez le job et, sur le côté droit, sélectionnez **Télécharger les artéfacts**.

## Afficher l'URL de déploiement {#view-deployment-url}

Une fois votre pipeline terminé avec succès :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Pages**.
1. Dans **Déploiements**, vous pouvez afficher l'URL de votre déploiement actif.
1. Pour visiter votre site GitLab Pages déployé, sélectionnez l'URL.

> [!note]
> Il peut s'écouler quelques minutes avant que votre site ne soit disponible après la fin du pipeline.

## Dépannage {#troubleshooting}

### Si le formulaire `Get Started with Pages` n'est pas disponible {#if-the-get-started-with-pages-form-is-not-available}

Le formulaire `Get Started with Pages` n'est pas disponible si vous :

- Avez déjà déployé un site GitLab Pages auparavant.
- Avez commité `.gitlab-ci.yml` via les formulaires au moins une fois.

Pour résoudre ce problème :

- Si le message **En attente de la fin du pipeline Pages** s'affiche, sélectionnez **Recommencer** pour relancer le formulaire.
- Si votre projet a déjà déployé GitLab Pages avec succès, [mettez manuellement à jour](pages_from_scratch.md) votre fichier `.gitlab-ci.yml`.
