---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Ajoutez, commitez et poussez un fichier vers votre dépôt Git en utilisant la ligne de commande."
title: Ajouter des fichiers à votre branche
---

Utilisez Git pour ajouter des fichiers à une branche dans votre dépôt local. Cette action crée un instantané du fichier pour votre prochain commit et lance le suivi par contrôle de version. Lorsque vous ajoutez des fichiers avec Git, vous :

- Préparez le contenu pour le suivi par contrôle de version.
- Créez un enregistrement des ajouts et des modifications de fichiers.
- Conservez l'historique des fichiers pour référence ultérieure.
- Rendez les fichiers du projet disponibles pour la collaboration en équipe.

## Ajouter des fichiers à un dépôt Git {#add-files-to-a-git-repository}

Pour ajouter un nouveau fichier depuis la ligne de commande :

1. Ouvrez un terminal.
1. Naviguez dans les répertoires jusqu'à atteindre le dossier de votre projet.

   ```shell
   cd my-project
   ```

1. Choisissez une branche Git sur laquelle travailler.
   - Pour créer une branche :

     ```shell
     git checkout -b <branchname>
     ```

   - Pour basculer vers une branche existante :

     ```shell
     git checkout <branchname>
     ```

1. Copiez le fichier que vous souhaitez ajouter dans le répertoire où vous voulez l'ajouter.
1. Confirmez que votre fichier se trouve dans le répertoire :
   - Windows : `dir`
   - Tous les autres systèmes d'exploitation : `ls`

   Le nom du fichier devrait s'afficher.
1. Vérifiez le statut du fichier :

   ```shell
   git status
   ```

   Le nom du fichier devrait apparaître en rouge. Le fichier est présent dans votre système de fichiers, mais Git n'en assure pas encore le suivi.
1. Demandez à Git de suivre le fichier :

   ```shell
   git add <filename>
   ```

1. Vérifiez à nouveau le statut du fichier :

   ```shell
   git status
   ```

   Le nom du fichier devrait apparaître en vert. Le fichier est indexé (suivi localement) par Git, mais n'a pas encore été [commité et poussé](commit.md).

## Ajouter un fichier au dernier commit {#add-a-file-to-the-last-commit}

Pour ajouter des modifications d'un fichier au dernier commit plutôt qu'à un nouveau commit, modifiez le commit existant :

```shell
git add <filename>
git commit --amend
```

Si vous ne souhaitez pas modifier le message de commit, ajoutez `--no-edit` à la commande `commit`.

## Sujets connexes {#related-topics}

- [Ajouter un fichier depuis l'interface utilisateur](../../user/project/repository/_index.md#add-a-file-from-the-ui)
- [Ajouter un fichier depuis le Web IDE](../../user/project/repository/web_editor.md#upload-a-file)
- [Signer les commits](../../user/project/repository/signed_commits/gpg.md)
