---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Comment défaire des commits ou des merge requests dans un projet GitLab.
title: Défaire des modifications
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Des erreurs surviennent dans le code. Le contrôle de version permet de corriger ces erreurs en les annulant.

Lorsque vous défaites un commit, vous créez un nouveau commit (un commit de retour) qui annule la mauvaise modification, plutôt que d'effacer l'existence du problème de l'historique de votre projet. Les commits de retour fournissent une piste d'audit claire, plutôt qu'une lacune à l'emplacement du commit précédent. Le commit de retour suit les contrôles d'accès et les processus de votre projet, et :

- Supprime les lignes ajoutées dans le commit d'origine.
- Restaure les lignes supprimées dans le commit d'origine.
- Restaure les lignes modifiées dans le commit d'origine dans leur état précédent.

Les retours ne se limitent pas aux seuls commits. Si la mauvaise modification s'étend sur plusieurs commits, envisagez de défaire toutes les modifications de la merge request, plutôt que de défaire commit par commit. Cette approche fournit une piste d'audit plus claire.

## Défaire une merge request {#revert-a-merge-request}

Après la fusion d'une merge request, vous pouvez défaire toutes les modifications de la merge request.

Prérequis :

- Vous devez disposer d'un rôle pour le projet qui vous permet de modifier les merge requests et d'ajouter du code au dépôt.
- Votre projet doit utiliser la [méthode de fusion](methods/_index.md#fast-forward-merge) **Merge Commit**, définie dans les **Paramètres** > **Requêtes de fusion** de votre projet.

  Vous pouvez défaire des commits avancés rapidement depuis l'interface GitLab si :

  - Les commits sont squashés, ou
  - La merge request contient un seul commit.

Pour plus d'informations, consultez le [ticket 22236](https://gitlab.com/gitlab-org/gitlab/-/issues/22236).

Pour défaire la merge request `Example` :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Dans le menu secondaire, sélectionnez **Fusionnées** et sélectionnez votre merge request (ici, `Example`).
1. Faites défiler jusqu'à la zone des rapports de merge request et trouvez le rapport affichant les informations **Fusionné par**.
1. Sélectionnez **Défaire**.
1. Dans **Défaire dans la branche**, sélectionnez la branche dans laquelle défaire vos modifications.
1. Pour défaire immédiatement, sans merge request :
   1. Décochez **Démarrer une nouvelle merge request**.
   1. Sélectionnez **Défaire**, et le retour de `Example` est terminé.
1. Pour examiner le retour dans une nouvelle merge request plutôt que de défaire immédiatement, sélectionnez **Démarrer une nouvelle merge request**, puis :
   1. Remplissez les champs de votre merge request de retour, puis sélectionnez **Créer une requête de fusion**.
   1. Lorsque la merge request est fusionnée, le retour de `Example` est terminé.

## Défaire un commit {#revert-a-commit}

Vous pouvez défaire n'importe quel commit d'un dépôt vers :

- La branche actuelle.
- Une nouvelle merge request.

Prérequis :

- Votre rôle pour le projet doit vous permettre de modifier les merge requests et d'ajouter du code au dépôt.
- Le commit ne doit pas avoir déjà été annulé, car l'option **Défaire** n'est pas affichée dans ce cas.

Pour cela :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Si vous connaissez la merge request qui contient le commit :
   1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**, puis sélectionnez votre merge request.
   1. Sélectionnez **Validation**, puis sélectionnez le titre du commit que vous souhaitez défaire. Cela affiche le commit dans le contexte de votre merge request.
   1. Sous le menu secondaire, GitLab affiche le message **Affichage du commit `00001111`**, où `00001111` est le hachage du commit. Sélectionnez le hachage du commit pour afficher la page du commit.
1. Si vous ne connaissez pas la merge request dont provient le commit :
   1. Dans la barre latérale gauche, sélectionnez **Code** > **Commits**.
   1. Sélectionnez le titre du commit pour afficher les informations complètes sur le commit.
1. Dans le coin supérieur droit, sélectionnez **Options**, puis sélectionnez **Défaire**.
1. Dans **Défaire dans la branche**, sélectionnez la branche dans laquelle défaire vos modifications.
1. Pour défaire immédiatement, sans merge request :
   1. Décochez **Démarrer une nouvelle merge request**.
   1. Sélectionnez **Défaire**.
1. Pour examiner le retour dans une nouvelle merge request plutôt que de défaire immédiatement, sélectionnez **Démarrer une nouvelle merge request**, puis :
   1. Remplissez les champs de votre merge request de retour, puis sélectionnez **Créer une requête de fusion**.
   1. Lorsque la merge request est fusionnée, le retour du commit est terminé.

### Défaire un commit de fusion vers un commit parent différent {#revert-a-merge-commit-to-a-different-parent-commit}

Lorsque vous défaites un commit de fusion, la branche vers laquelle vous avez fusionné (souvent `main`) est toujours le premier parent. Pour défaire un commit de fusion vers un parent différent, vous devez défaire le commit depuis la ligne de commande ; consultez [défaire et annuler des modifications avec Git](../../../topics/git/undo.md#revert-a-merge-commit-to-a-different-parent).

## Expurger du texte d'un dépôt {#redact-text-from-repository}

Pour plus d'informations sur l'[expurgation de texte](../repository/repository_size.md#redact-text-from-repository) d'un dépôt et d'autres techniques de suppression de données, consultez la [taille du dépôt](../repository/repository_size.md).

## Sujets connexes {#related-topics}

- [Documentation officielle de `git revert`](https://git-scm.com/docs/git-revert)
- [Annuler des modifications avec Git](../../../topics/git/undo.md)
- [Défaire un commit](../../../api/commits.md#revert-a-commit) avec l'API Commits
- Comment les journaux des modifications [gèrent les commits annulés](../changelogs.md#reverted-commit-handling)
