---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Comprendre comment lire l'affichage des commits dans une merge request."
title: Commits
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Un commit enregistre et envoie les modifications du code source vers le [dépôt](../repository/_index.md). Pour plus d'informations, voir [l'enregistrement des modifications dans le dépôt](https://git-scm.com/book/en/v2/Git-Basics-Recording-Changes-to-the-Repository).

## Valider des modifications à l'aide de la ligne de commande {#commit-changes-using-the-command-line}

Lorsque vous utilisez la ligne de commande, utilisez [`git commit`](../../../topics/git/commands.md#git-commit). Vous pouvez ajouter plusieurs commits avant de pousser vos modifications.

- Message de commit :

  Un message de commit identifie ce qui est modifié et pourquoi. Utilisez des messages descriptifs pour clarifier les modifications. Dans GitLab, vous pouvez ajouter des mots-clés au message de commit pour effectuer l'une des actions suivantes :

  - Déclencher un pipeline GitLab CI/CD :

    Si le projet est configuré avec [GitLab CI/CD](../../../ci/_index.md), vous déclenchez un pipeline par push, et non par commit.

  - Ignorer des pipelines :

    Ajoutez le mot-clé [`ci skip`](../../../ci/pipelines/_index.md#skip-a-pipeline) à votre message de commit pour que GitLab CI/CD ignore le pipeline.

  - Créer des liens croisés entre tickets et merge requests :

    Utilisez les [liens croisés](../issues/crosslinking_issues.md#from-commit-messages) pour assurer le suivi des parties liées de votre workflow. Si vous mentionnez un ticket ou une merge request dans un message de commit, ils sont affichés dans leur fil de discussion respectif.

- Sélectionner un commit par cherry-pick :

  Dans GitLab, vous pouvez [sélectionner un commit par cherry-pick](cherry_pick_changes.md#cherry-pick-a-single-commit) depuis l'interface.

- Annuler un commit :

  [Annuler un commit](revert_changes.md#revert-a-commit) depuis l'interface vers une branche sélectionnée.

- Signer un commit :

  Renforcez la sécurité en [signant vos commits](../repository/signed_commits/_index.md).

Pour plus d'informations, voir [indexer, valider et pousser des modifications](../../../topics/git/commit.md).

## Commits de merge request {#merge-request-commits}

Chaque merge request dispose d'un historique des commits effectués sur la branche source après la création de la merge request.

Ces commits sont affichés dans l'onglet **Validation** de la merge request. Depuis cet onglet, vous pouvez consulter les messages de commit et copier le SHA d'un commit lorsque vous avez besoin d'effectuer un [cherry-pick des modifications](cherry_pick_changes.md).

### Afficher les commits dans une merge request {#view-commits-in-a-merge-request}

Pour afficher les commits inclus dans une merge request :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**, puis sélectionnez votre merge request.
1. Pour afficher la liste des commits de la merge request, du plus récent au plus ancien, sélectionnez **Validation**. Pour en savoir plus sur le commit, sélectionnez **Afficher ou masquer la description du commit** ({{< icon name="ellipsis_h" >}}) sur n'importe quel commit.
1. Pour afficher les modifications du commit, sélectionnez le titre du lien du commit.
1. Pour afficher d'autres commits dans la merge request, vous pouvez :

   - Sélectionnez **Préc.** ou **Suivant**.
   - Utiliser des raccourcis clavier : <kbd>X</kbd> (commit précédent) et <kbd>C</kbd> (commit suivant).

Si votre merge request s'appuie sur une merge request précédente, vous aurez peut-être besoin d'[inclure davantage de commits pour le contexte](#show-commits-from-previous-merge-requests).

### Afficher les commits des merge requests précédentes {#show-commits-from-previous-merge-requests}

Lorsque vous révisez une merge request, vous pouvez avoir besoin d'informations provenant de commits précédents pour mieux comprendre les commits que vous êtes en train d'examiner. Vous pourriez avoir besoin de plus de contexte si une autre merge request :

- A modifié des fichiers que votre merge request actuelle ne modifie pas, de sorte que ces fichiers n'apparaissent pas dans le diff de votre merge request actuelle.
- A modifié des fichiers que vous modifiez dans votre merge request actuelle, et vous avez besoin de voir la progression du travail.

Pour ajouter des commits précédemment fusionnés à une merge request afin d'obtenir plus de contexte :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**, puis sélectionnez votre merge request.
1. Sélectionnez **Validation**.
1. Faites défiler jusqu'à la fin de la liste des commits, puis sélectionnez **Ajouter les validations précédemment fusionnées**.
1. Sélectionnez les commits que vous souhaitez ajouter.
1. Sélectionnez **Enregistrer les modifications**.

Les commits précédemment fusionnés sont désignés sous le nom de **Context Commits** dans l'[API des commits de contexte des merge requests](../../../api/merge_request_context_commits.md).

### Ajouter un commentaire à un commit {#add-a-comment-to-a-commit}

> [!warning]
> Les fils de discussion créés de cette façon sont perdus si l'ID du commit change après un push forcé.

Pour ajouter une discussion à un commit spécifique :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Commits**.
1. Sous les commits, dans le champ **Commentaire**, saisissez un commentaire.
1. Enregistrez votre commentaire en tant que commentaire autonome ou fil de discussion :
   - Pour ajouter un commentaire, sélectionnez **Commentaire**.
   - Pour démarrer un fil de discussion, sélectionnez la flèche vers le bas ({{< icon name="chevron-down" >}}), puis sélectionnez **Démarrer un fil de conversation**.

### Afficher les diffs entre les commits {#view-diffs-between-commits}

Pour afficher les modifications entre des commits précédemment fusionnés :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**, puis sélectionnez votre merge request.
1. Sélectionnez **Modifications**.
1. À côté de **Comparer** ({{< icon name="file-tree" >}}), sélectionnez les commits à comparer :

   ![Commits précédemment fusionnés](img/previously_merged_commits_v16_0.png)

Si vous avez choisi d'ajouter des commits précédemment fusionnés pour le contexte, ces commits sont également affichés dans la liste.

### Trouver la merge request qui a introduit une modification {#find-the-merge-request-that-introduced-a-change}

Lorsque vous consultez la page de détails d'un commit, GitLab affiche des liens vers une ou plusieurs merge requests contenant ce commit.

Ce comportement s'applique uniquement aux commits figurant dans la version la plus récente d'une merge request. Si les commits étaient dans une merge request et ont été retirés par rebase de cette merge request, les commits ne sont pas liés.
