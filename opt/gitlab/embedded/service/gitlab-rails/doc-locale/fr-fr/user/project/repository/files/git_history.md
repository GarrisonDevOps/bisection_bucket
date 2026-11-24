---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Comment consulter l'historique Git d'un fichier dans GitLab."
title: Historique des fichiers Git
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'historique de fichiers Git fournit des informations sur l'historique des commits associés à un fichier :

![Une liste de 3 commits pour un fichier unique, avec le commit le plus récent marqué comme « Vérifiée ».](img/file_history_output_v17_2.png)

Chaque commit affiche :

- La date du commit. GitLab regroupe tous les commits effectués le même jour.
- L'avatar de l'utilisateur ou de l'utilisatrice.
- Le nom de l'utilisateur ou de l'utilisatrice. Survolez le nom pour afficher l'intitulé de poste, la localisation, l'heure locale et le message de statut actuel de l'utilisateur ou de l'utilisatrice.
- La date du commit, au format relatif (temps écoulé). Pour afficher la date et l'heure précises du commit, survolez la date.
- Si le [commit est signé](../signed_commits/_index.md), un badge **Vérifié**.
- Le SHA du commit. GitLab affiche les 8 premiers caractères. Sélectionnez **Copier le SHA de la validation** ({{< icon name="copy-to-clipboard" >}}) pour copier le SHA complet.
- Un lien pour parcourir ({{< icon name="folder-open" >}}) le fichier tel qu'il apparaissait au moment de ce commit.

GitLab récupère le nom d'utilisateur et les informations d'e-mail depuis la [configuration Git](https://git-scm.com/book/en/v2/Customizing-Git-Git-Configuration) du contributeur ou de la contributrice lors de la création d'un commit.

## Afficher l'historique Git d'un fichier {#view-a-files-git-history}

Pour consulter l'historique Git d'un fichier dans l'interface utilisateur :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Dépôt**.
1. Accédez au fichier souhaité dans le dépôt.
1. Dans le dernier bloc de commit, sélectionnez **Historique**.

## Limiter la plage de résultats de l'historique {#limit-history-range-of-results}

Lorsque vous consultez l'historique de fichiers anciens ou de fichiers comportant de nombreux commits, vous pouvez limiter les résultats de recherche par date. Limiter les dates pour les commits permet de corriger les [délais d'expiration des requêtes d'historique de commits](https://gitlab.com/gitlab-org/gitaly/-/issues/5426) dans les dépôts très volumineux.

Dans l'interface GitLab, modifiez l'URL. Incluez ces paramètres au format `YYYY-MM-DD` (les dates sont interprétées en UTC) :

- `committed_before`
- `committed_after`

Séparez chaque paire clé-valeur dans la chaîne de requête avec une esperluette (`&`), comme ceci :

```plaintext
?ref_type=heads&committed_after=2023-05-15&committed_before=2023-11-22
```

L'URL complète vers la plage de commits se présente comme suit :

```plaintext
https://gitlab.com/gitlab-org/gitlab/-/commits/master/CONTRIBUTING.md?ref_type=heads&committed_after=2023-05-15&committed_before=2023-11-22
```

## Sujets connexes {#related-topics}

- [Git blame](git_blame.md)
- [Commandes Git courantes](../../../../topics/git/commands.md)
- [Gestion des fichiers avec Git](../../../../topics/git/file_management.md)
- [Navigateur d'arborescence de fichiers](file_tree_browser.md)
