---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Un guide de référence des commandes Git couramment utilisées pour gérer le code, les branches, les commits et l'historique du dépôt, avec des exemples et les bonnes pratiques."
title: Commandes Git courantes
---

Les commandes Git vous font gagner du temps tout au long de votre workflow de développement. Cette page de référence contient les commandes fréquemment utilisées pour les tâches courantes telles que les modifications de code, la gestion des branches et l'examen de l'historique. Chaque section de commande fournit la syntaxe exacte, des exemples pratiques et des liens vers de la documentation supplémentaire.

## `git add` {#git-add}

Utilisez `git add` pour ajouter des fichiers à la zone de staging.

```shell
git add <file_path>
```

Vous pouvez indexer récursivement les modifications depuis le répertoire de travail actuel avec `git add .`, ou indexer toutes les modifications dans le dépôt Git avec `git add --all`.

Pour plus d'informations, consultez [ajouter des fichiers à votre branche](add_files.md).

## `git blame` {#git-blame}

Utilisez `git blame` pour signaler quels utilisateurs ont modifié quelles parties d'un fichier.

```shell
git blame <file_name>
```

Vous pouvez utiliser `git blame -L <line_start>,<line_end>` pour vérifier une plage de lignes spécifique.

Pour plus d'informations, consultez [Git file blame](../../user/project/repository/files/git_blame.md).

### Exemple {#example}

Pour vérifier quel utilisateur a modifié en dernier la ligne cinq de `example.txt` :

```shell
$ git blame -L 5,5 example.txt
123abc (Zhang Wei 2021-07-04 12:23:04 +0000 5)
```

## `git bisect` {#git-bisect}

Utilisez `git bisect` pour effectuer une recherche binaire afin de trouver le commit ayant introduit un bug.

Commencez par identifier un commit « mauvais » (contenant le bug) et un commit « bon » (ne contenant pas le bug).

```shell
git bisect start
git bisect bad                 # Current version is bad
git bisect good v2.6.13-rc2    # v2.6.13-rc2 is known to be good
```

`git bisect` sélectionne ensuite un commit entre les deux points et vous demande d'identifier si le commit est « bon » ou « mauvais » avec `git bisect good` ou `git bisect bad`. Répétez le processus jusqu'à ce que le commit soit trouvé.

## `git checkout` {#git-checkout}

Utilisez `git checkout` pour basculer vers une branche spécifique.

```shell
git checkout <branch_name>
```

Pour créer une nouvelle branche et y basculer, utilisez `git checkout -b <branch_name>`.

Pour plus d'informations, consultez [créer une branche Git pour vos modifications](branch.md).

## `git clone` {#git-clone}

Utilisez `git clone` pour copier un dépôt Git existant.

```shell
git clone <repository>
```

Pour plus d'informations, consultez [cloner un dépôt Git sur votre ordinateur local](clone.md).

## `git commit` {#git-commit}

Utilisez `git commit` pour committer les modifications indexées dans le dépôt.

```shell
git commit -m "<commit_message>"
```

Si le message de commit contient une ligne vide, la première ligne devient le sujet du commit tandis que le reste devient le corps du commit. Utilisez le sujet pour résumer brièvement une modification, et le corps du commit pour fournir des détails supplémentaires.

Pour plus d'informations, consultez [indexer, committer et pousser des modifications](commit.md).

## `git commit --amend` {#git-commit---amend}

Utilisez `git commit --amend` pour modifier le commit le plus récent.

```shell
git commit --amend
```

## `git diff` {#git-diff}

Utilisez `git diff` pour afficher les différences entre vos modifications locales non indexées et la dernière version que vous avez clonée ou tirée.

```shell
git diff
```

Vous pouvez afficher la différence (ou diff) entre vos modifications locales et la version la plus récente d'une branche. Consultez un diff pour comprendre vos modifications locales avant de les committer dans la branche.

Pour comparer vos modifications par rapport à une branche spécifique, exécutez :

```shell
git diff <branch>
```

Dans la sortie :

- Les lignes avec des ajouts commencent par un plus (`+`) et s'affichent en vert.
- Les lignes avec des suppressions ou des modifications commencent par un moins (`-`) et s'affichent en rouge.

## `git init` {#git-init}

Utilisez `git init` pour initialiser un répertoire afin que Git le suive comme un dépôt.

```shell
git init
```

Un fichier `.git` contenant des fichiers de configuration et de journaux est ajouté au répertoire. Vous ne devez pas modifier directement le fichier `.git`.

La branche par défaut est définie sur `main`. Vous pouvez modifier le nom de la branche par défaut avec `git branch -m <branch_name>`, ou l'initialiser avec `git init -b <branch_name>`.

## `git pull` {#git-pull}

Utilisez `git pull` pour récupérer toutes les modifications effectuées par les utilisateurs depuis la dernière fois que vous avez cloné ou tiré le projet.

```shell
git pull <optional_remote> <branch_name>
```

## `git push` {#git-push}

Utilisez `git push` pour mettre à jour les références distantes.

```shell
git push
```

Pour plus d'informations, consultez [indexer, committer et pousser des modifications](commit.md).

## `git reflog` {#git-reflog}

Utilisez `git reflog` pour afficher une liste des modifications apportées aux journaux de référence Git.

```shell
git reflog
```

Par défaut, `git reflog` affiche une liste des modifications apportées à `HEAD`.

Pour plus d'informations, consultez [annuler des modifications](undo.md).

## `git remote add` {#git-remote-add}

Utilisez `git remote add` pour indiquer à Git quel dépôt distant dans GitLab est lié à un répertoire local.

```shell
git remote add <remote_name> <repository_url>
```

Lorsque vous clonez un dépôt, par défaut le dépôt source est associé au nom distant `origin`.

Pour plus d'informations sur la configuration de remotes supplémentaires, consultez [les duplications](../../user/project/repository/forking_workflow.md).

## `git log` {#git-log}

Utilisez `git log` pour afficher une liste de commits dans l'ordre chronologique.

```shell
git log
```

## `git show` {#git-show}

Utilisez `git show` pour afficher des informations sur un objet dans Git.

### Exemple {#example-1}

Pour voir sur quel commit `HEAD` pointe :

```shell
$ git show HEAD
commit ab123c (HEAD -> main, origin/main, origin/HEAD)
```

## `git merge` {#git-merge}

Utilisez `git merge` pour combiner les modifications d'une branche avec une autre.

Pour plus d'informations sur une alternative à `git merge`, consultez [rebaser pour résoudre les conflits de merge](git_rebase.md).

### Exemple {#example-2}

Pour appliquer les modifications de `feature_branch` à la `target_branch` :

```shell
git checkout target_branch
git merge feature_branch
```

## `git rebase` {#git-rebase}

Utilisez `git rebase` pour réécrire l'historique des commits d'une branche.

```shell
git rebase <branch_name>
```

Vous pouvez utiliser `git rebase` pour [résoudre les conflits de merge](git_rebase.md).

Dans la plupart des cas, vous souhaitez rebaser par rapport à la branche par défaut.

## `git reset` {#git-reset}

Utilisez `git reset` pour annuler un commit, rembobiner l'historique des commits et reprendre à partir d'un commit antérieur.

```shell
git reset
```

Pour plus d'informations, consultez [annuler des modifications](undo.md).

## `git status` {#git-status}

Utilisez `git status` pour afficher le statut du répertoire de travail et des fichiers indexés.

```shell
git status
```

Lorsque vous ajoutez, modifiez ou supprimez des fichiers, Git peut vous afficher les modifications.
