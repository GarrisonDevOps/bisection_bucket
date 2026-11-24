---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Registre Harbor
description: Intégrez un registre de conteneurs Harbor à votre projet ou groupe GitLab.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- **Registre Harbor** [déplacé](https://gitlab.com/gitlab-org/gitlab/-/issues/439494) de la section de menu **Opération** vers **Déployer** dans GitLab 17.0.

{{< /history >}}

Vous pouvez intégrer le [registre de conteneurs Harbor](../../project/integrations/harbor.md) dans GitLab et utiliser Harbor comme registre de conteneurs pour votre projet GitLab afin de stocker des images.

## Afficher le registre Harbor {#view-the-harbor-registry}

Vous pouvez afficher le registre Harbor pour un projet ou un groupe.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre Harbor**.

Vous pouvez rechercher, trier et filtrer les images sur cette page. Vous pouvez partager une vue filtrée en copiant l'URL depuis votre navigateur.

Au niveau du projet, dans le coin supérieur droit, vous pouvez voir **Commandes CLI** où vous pouvez copier les commandes correspondantes pour vous connecter, créer des images et pousser des images. **Commandes CLI** n'est pas affiché au niveau du groupe.

> [!note]
> Les paramètres par défaut de l'intégration Harbor au niveau du projet sont hérités du niveau du groupe.

## Utiliser des images du registre Harbor {#use-images-from-the-harbor-registry}

Pour télécharger et exécuter une image Harbor hébergée dans le registre Harbor de GitLab :

1. Copiez le lien vers votre image de conteneur :
   1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
   1. Sélectionnez **Déployer** > **Registre Harbor** et trouvez l'image souhaitée.
   1. Sélectionnez l'icône **Copier** à côté du nom de l'image.

1. Utilisez la commande pour exécuter l'image de conteneur souhaitée.

## Afficher les tags d'un artefact spécifique {#view-the-tags-of-a-specific-artifact}

Pour afficher la liste des tags associés à un artefact spécifique :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Accédez à **Déployer** > **Registre Harbor**.
1. Sélectionnez le nom de l'image pour afficher ses artefacts.
1. Sélectionnez l'artefact souhaité.

La liste des tags s'affiche. Vous pouvez voir le nombre de tags et la date de publication.

Vous pouvez également copier l'URL du tag et l'utiliser pour extraire l'artefact correspondant.

## Créer et pousser des images à l'aide de commandes {#build-and-push-images-by-using-commands}

Pour créer et pousser vers le registre Harbor :

1. Authentifiez-vous auprès du registre Harbor.
1. Exécutez la commande pour créer ou pousser.

Pour afficher ces commandes :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre Harbor**.
1. Sélectionnez **Commandes CLI**.

## Désactiver le registre Harbor pour un projet {#disable-the-harbor-registry-for-a-project}

Pour supprimer le registre Harbor d'un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Harbor** sous **Intégrations actives**.
1. Sous **Activer l'intégration**, décochez la case **Actif**.
1. Sélectionnez **Enregistrer les modifications**.

L'entrée **Déployer** > **Registre Harbor** est supprimée de la barre latérale.
