---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Remiser des modifications
---

Utilisez `git stash` lorsque vous souhaitez changer de branche mais que vous avez des modifications non commitées qui ne sont pas prêtes à être commitées.

## Créer des entrées de stash {#create-stash-entries}

Par défaut, `git stash` stocke les modifications suivies dans votre répertoire de travail ainsi que toutes les modifications indexées. Vous pouvez utiliser des options pour contrôler les modifications à inclure.

- Pour remiser les modifications suivies :

  ```shell
  git stash
  ```

- Pour remiser les modifications avec un message :

  ```shell
  git stash push -m "describe your changes here"
  ```

- Pour remiser les modifications tout en conservant les modifications indexées dans votre répertoire de travail :

  ```shell
  git stash push -k
  ```

  L'option `-k` (`--keep-index`) remise vos modifications tout en les conservant dans le répertoire de travail. Utilisez cette option lorsque vous souhaitez sauvegarder temporairement des modifications tout en continuant à travailler dessus.
- Pour remiser les modifications et inclure les fichiers non suivis :

  ```shell
  git stash push -u
  ```

  L'option `-u` (`--include-untracked`) remise également les fichiers que Git ne suit pas encore. Sans cette option, les nouveaux fichiers qui n'ont pas été commités restent dans votre répertoire de travail.
- Pour remiser uniquement les modifications indexées :

  ```shell
  git stash push -S
  ```

  L'option `-S` (`--staged`) remise uniquement les modifications qui sont indexées. Utilisez cette option lorsque vous souhaitez sauvegarder les modifications indexées tout en continuant à travailler sur les modifications non indexées.

## Appliquer des entrées de stash {#apply-stash-entries}

Si vous effectuez de nombreuses modifications après avoir remisé votre travail, des conflits peuvent survenir lorsque vous appliquez le stash. Vous devez résoudre ces conflits avant que les modifications puissent être appliquées.

- Pour appliquer l'entrée de stash la plus récente et la conserver dans le stash :

  ```shell
  git stash apply
  ```

- Pour appliquer une entrée de stash spécifique :

  ```shell
  git stash apply stash@{3}
  ```

- Pour appliquer l'entrée de stash la plus récente et la supprimer du stash :

  ```shell
  git stash pop
  ```

## Afficher les entrées de stash {#view-stash-entries}

- Pour afficher toutes les entrées de stash :

  ```shell
  git stash list
  ```

- Pour afficher les entrées de stash avec plus de détails :

  ```shell
  git stash list --stat
  ```

## Supprimer des entrées de stash {#delete-stash-entries}

- Pour supprimer l'entrée de stash la plus récente :

  ```shell
  git stash drop
  ```

- Pour supprimer une entrée de stash spécifique :

  ```shell
  git stash drop <name>
  ```

- Pour supprimer toutes les entrées de stash :

  ```shell
  git stash clear
  ```

## Exemple : créer et appliquer une entrée de stash {#example-create-and-apply-a-stash-entry}

Pour vous entraîner à utiliser le stash Git :

1. Modifiez un fichier dans un dépôt Git.
1. Remisez la modification :

   ```shell
   git stash push -m "Saving changes from edit"
   ```

1. Affichez la liste du stash :

   ```shell
   git stash list
   ```

1. Confirmez qu'il n'y a aucune modification en attente :

   ```shell
   git status
   ```

1. Appliquez les modifications remisées et supprimez l'entrée du stash :

   ```shell
   git stash pop
   ```

1. Affichez la liste du stash pour confirmer que l'entrée a été supprimée :

   ```shell
   git stash list
   ```

## Sujets connexes {#related-topics}

- [Documentation officielle de Git stash](https://git-scm.com/docs/git-stash)
