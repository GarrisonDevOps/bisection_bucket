---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Créer une branche Git pour vos modifications
---

Une branche est une copie des fichiers du dépôt au moment où vous créez la branche. Vous pouvez travailler dans votre branche sans affecter les autres branches. Lorsque vous êtes prêt à ajouter vos modifications à la base de code principale, vous pouvez fusionner votre branche dans la branche par défaut, par exemple `main`.

Utilisez des branches dans les cas suivants :

- Vous souhaitez ajouter du code à un projet, mais vous n'êtes pas sûr qu'il fonctionne correctement.
- Vous collaborez sur le projet avec d'autres personnes et ne souhaitez pas que vos travaux se mélangent.

## Créer une branche {#create-a-branch}

Pour créer une branche :

```shell
git checkout -b <name-of-branch>
```

GitLab applique des [règles de nommage des branches](../../user/project/repository/branches/_index.md#name-your-branch) pour éviter les problèmes et propose des [modèles de nommage des branches](../../user/project/repository/branches/_index.md#prefix-branch-names-with-a-number) pour simplifier la création de merge requests.

## Basculer vers une branche {#switch-to-a-branch}

Tout le travail dans Git s'effectue dans une branche. Vous pouvez basculer entre les branches pour voir l'état des fichiers et travailler dans cette branche.

Pour basculer vers une branche existante :

```shell
git checkout <name-of-branch>
```

Par exemple, pour passer à la branche `main` :

```shell
git checkout main
```

## Maintenir une branche à jour {#keep-a-branch-up-to-date}

Votre branche n'inclut pas automatiquement les modifications fusionnées dans la branche par défaut depuis d'autres branches. Pour inclure les modifications fusionnées après la création de votre branche, vous devez mettre à jour votre branche manuellement.

Pour mettre à jour votre branche avec les dernières modifications de la branche par défaut, vous pouvez :

- Pour [rebaser](git_rebase.md) votre branche sur la branche par défaut, exécutez :

  ```shell
  git rebase
  ```

  Utilisez cette commande lorsque vous souhaitez que vos modifications apparaissent dans les logs Git après les modifications de la branche par défaut.

- Pour fusionner la branche par défaut dans votre branche, exécutez :

  ```shell
  git pull <remote-name> <default-branch-name>
  ```

  Utilisez cette commande lorsque vous souhaitez que vos modifications apparaissent dans les logs Git dans l'ordre chronologique avec les modifications de la branche par défaut, ou si vous partagez votre branche avec d'autres personnes. Si vous n'êtes pas sûr de la valeur correcte pour `<remote-name>`, exécutez : `git remote`.

## Sujets connexes {#related-topics}

- [Branches](../../user/project/repository/branches/_index.md)
- [Tags](../../user/project/repository/tags/_index.md)
