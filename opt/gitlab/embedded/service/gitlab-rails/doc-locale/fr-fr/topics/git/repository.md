---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Pour supprimer les fichiers volumineux indésirables d'un dépôt Git et réduire sa taille de stockage, utilisez la commande filter-repo."
title: Réduire la taille du dépôt
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

La taille d'un dépôt Git peut avoir un impact significatif sur les performances et les coûts de stockage. Elle peut différer légèrement d'une instance à l'autre en raison de la compression, de la maintenance et d'autres facteurs.

Pour plus d'informations sur la taille du dépôt, consultez :

- [Taille du dépôt](../../user/project/repository/repository_size.md)
  - [Calcul de la taille du dépôt](../../user/project/repository/repository_size.md#size-calculation)
  - [Limites de taille et de stockage](../../user/project/repository/repository_size.md#size-and-storage-limits)
  - [Méthodes de l'interface GitLab pour réduire la taille du dépôt](../../user/project/repository/repository_size.md#methods-to-reduce-repository-size)

## Purger les fichiers de l'historique du dépôt {#purge-files-from-repository-history}

Utilisez cette méthode pour supprimer les fichiers volumineux de l'intégralité de l'historique Git.

Cette méthode n'est pas adaptée à la suppression de données sensibles telles que des mots de passe ou des clés de votre dépôt. Les informations relatives aux commits, y compris le contenu des fichiers, sont mises en cache dans la base de données et restent visibles même après leur suppression du dépôt. Pour supprimer des données sensibles, utilisez la méthode décrite dans [supprimer des blobs](../../user/project/repository/repository_size.md#remove-blobs).

Prérequis :

- Vous devez installer [`git filter-repo`](https://github.com/newren/git-filter-repo/blob/main/INSTALL.md).
- Facultatif. Installez [`git-sizer`](https://github.com/github/git-sizer#getting-started).

> [!warning]
> La purge des fichiers est une opération destructive. Avant de continuer, assurez-vous de disposer d'une sauvegarde du dépôt.

Pour purger les fichiers d'un dépôt GitLab :

1. [Exportez le projet](../../user/project/settings/import_export.md#export-a-project-and-its-data) qui contient une copie de votre dépôt, puis téléchargez-le.

   - Pour les projets volumineux, vous pouvez utiliser l'[API d'export des relations de projet](../../api/project_relations_export.md).

1. Décompressez et extrayez la sauvegarde :

   ```shell
   tar xzf project-backup.tar.gz
   ```

1. Clonez le dépôt en utilisant les options `--bare` et `--mirror` :

   ```shell
   git clone --bare --mirror /path/to/project.bundle
   ```

1. Accédez au répertoire `project.git` :

   ```shell
   cd project.git
   ```

1. Mettez à jour l'URL distante :

   ```shell
   git remote set-url origin https://gitlab.example.com/<namespace>/<project_name>.git
   ```

1. Analysez le dépôt à l'aide de `git filter-repo` ou de `git-sizer` :

   - `git filter-repo` :

     ```shell
     git filter-repo --analyze
     head filter-repo/analysis/*-{all,deleted}-sizes.txt
     ```

   - `git-sizer` :

     ```shell
     git-sizer
     ```

1. Purgez l'historique de votre dépôt à l'aide de l'une des options `git filter-repo` suivantes :

   - `--path` et `--invert-paths` pour purger des fichiers spécifiques :

     ```shell
     git filter-repo --path path/to/file.ext --invert-paths
     ```

   - `--strip-blobs-bigger-than` pour purger tous les fichiers dont la taille est supérieure à, par exemple, 10 Mo :

     ```shell
     git filter-repo --strip-blobs-bigger-than 10M
     ```

   Pour plus d'exemples, consultez la [documentation de `git filter-repo`](https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html#EXAMPLES).

1. Sauvegardez le fichier `commit-map` :

   ```shell
   cp filter-repo/commit-map ./_filter_repo_commit_map_$(date +%s)
   ```

1. Désactivez l'indicateur mirror :

   ```shell
    git config --unset remote.origin.mirror
   ```

1. Effectuez un push forcé des modifications :

   ```shell
   git push origin --force 'refs/heads/*'
   git push origin --force 'refs/tags/*'
   git push origin --force 'refs/replace/*'
   ```

   Pour plus d'informations sur les références, consultez les références Git utilisées par Gitaly.

   > [!note]
   > Cette étape échoue pour les [branches protégées](../../user/project/repository/branches/protected.md) et les [tags protégés](../../user/project/protected_tags.md). Pour continuer, supprimez temporairement les protections.
1. Attendez au moins 30 minutes avant de passer à l'étape suivante.
1. Exécutez le processus de [nettoyage du dépôt](../../user/project/repository/repository_size.md#clean-up-repository). Ce processus ne nettoie que les objets datant de plus de 30 minutes. Pour plus d'informations, consultez [espace non libéré après le nettoyage](../../user/project/repository/repository_size.md#space-not-being-freed-after-cleanup).
