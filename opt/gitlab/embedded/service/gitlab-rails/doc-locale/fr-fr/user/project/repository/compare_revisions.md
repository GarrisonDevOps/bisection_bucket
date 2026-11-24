---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Comparez les branches, les tags et les commits pour afficher les différences entre les révisions d'un dépôt."
title: Comparer les révisions
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Utilisez **Comparer les révisions** pour afficher la liste des commits et des fichiers modifiés entre les révisions.

Vous pouvez comparer :

- Une branche à une autre branche.
- Un tag à une branche ou à un tag.
- Un commit à un autre commit ou à une branche.

## Méthodes de comparaison {#compare-methods}

GitLab propose deux méthodes pour comparer les révisions :

- **Uniquement les modifications entrantes de la source** (par défaut) : affiche les différences par rapport à la source après le dernier commit commun aux deux révisions. Cette méthode exclut les modifications sans rapport apportées à la cible après la création de la source. Utilisez cette méthode pour afficher uniquement les modifications introduites par la révision source.

  Cette méthode utilise la commande Git `git diff <from>...<to>`. Elle compare depuis la base de fusion (le commit ancêtre commun) jusqu'à la cible, au lieu de comparer directement les commits réels.

- **Inclure les modifications apportées à la cible après sa création** : affiche toutes les différences entre les deux révisions, y compris les modifications apportées à la source et à la cible. Utilisez cette méthode pour afficher la différence complète entre deux points de l'historique de votre dépôt.

  Cette méthode utilise la commande Git `git diff <from> <to>`. Elle compare directement les commits réels, en affichant toutes les modifications entre eux.

## Comparer des branches, des tags ou des commits {#compare-branches-tags-or-commits}

Pour comparer des révisions :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Comparer les révisions**.
1. Sélectionnez la révision **Source** :

   - Pour rechercher une branche, saisissez le nom de la branche. Les correspondances exactes sont affichées en premier.
   - Pour rechercher un tag, saisissez le nom du tag.
   - Pour rechercher un commit, saisissez le SHA du commit.
   - Pour affiner votre recherche avec des opérateurs :
     - `^` correspond au début du nom : `^feat` correspond à `feat/user-authentication`.
     - `$` correspond à la fin du nom : `widget$` correspond à `feat/search-box-widget`.
     - `*` correspond à l'aide d'un caractère générique : `branch*cache*` correspond à `fix/branch-search-cache-expiration`.
     - Vous pouvez combiner des opérateurs : `^chore/*migration$` correspond à `chore/user-data-migration`.

1. Sélectionnez le dépôt et la révision **Cible**.
1. Sous **Afficher les modifications**, sélectionnez **Uniquement les modifications entrantes de la source** (par défaut) ou **Inclure les modifications apportées à la cible après sa création**.
1. Sélectionnez **Comparer**.
1. Facultatif. Pour inverser la **Source** et la **Cible**, sélectionnez **Échanger les révisions** ({{< icon name="substitute" >}}).

La page de comparaison affiche la liste des commits et des fichiers modifiés entre les révisions.

## Afficher dans l'environnement {#view-on-environment}

Vous pouvez prévisualiser les fichiers directement dans leur environnement déployé lors de la comparaison des révisions.

Prérequis :

- Avoir des [route maps](../../../ci/review_apps/_index.md#route-maps) configurées pour votre projet.
- Avoir les fichiers que vous souhaitez prévisualiser inclus dans votre configuration de route maps.
- Un environnement accessible.

Pour prévisualiser un fichier dans son environnement déployé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Comparer les révisions**.
1. Sélectionnez les branches ou les commits **Source** et **Cible** que vous souhaitez comparer.
1. Dans la vue de diff du fichier, repérez un fichier inclus dans votre configuration de route maps.
1. Sélectionnez le menu **Plus d'actions** ({{< icon name="ellipsis_v" >}}) pour le fichier.
1. Sélectionnez **Afficher dans [nom de l'environnement]**.

Le fichier s'ouvre dans un nouvel onglet, affichant son apparence dans l'environnement déployé.

## Sujets connexes {#related-topics}

- [Branches](branches/_index.md)
- [Tags](tags/_index.md)
- [Commits](commits/_index.md)
- [Commandes Git](../../../topics/git/commands.md)
