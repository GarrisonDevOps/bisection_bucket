---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Dupliquez un dépôt Git lorsque vous souhaitez contribuer des modifications à un dépôt amont sur lequel vous n'avez pas les droits de contribution directe."
title: Mettre à jour un fork
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Une duplication est une copie personnelle du dépôt et de toutes ses branches, que vous créez dans un espace de nommage de votre choix. Vous pouvez utiliser des duplications pour proposer des modifications à un autre projet auquel vous n'avez pas accès. Pour plus d'informations, consultez [les workflows de duplication](../../user/project/repository/forking_workflow.md).

Vous pouvez également mettre à jour une duplication via [l'interface utilisateur GitLab](../../user/project/repository/forking_workflow.md#from-the-ui).

Prérequis :

- Vous devez [télécharger et installer le client Git](how_to_install_git/_index.md) sur votre machine locale.
- Vous devez [créer une duplication](../../user/project/repository/forking_workflow.md#create-a-fork) du dépôt que vous souhaitez mettre à jour.

Pour mettre à jour votre duplication depuis la ligne de commande :

1. Vérifiez si un dépôt distant `upstream` est configuré pour votre duplication :

   1. Clonez votre duplication localement, si ce n'est pas déjà fait. Pour plus d'informations, consultez [cloner un dépôt](clone.md).
   1. Affichez les dépôts distants configurés pour votre duplication :

      ```shell
      git remote -v
      ```

   1. Si votre duplication ne dispose pas d'un dépôt distant pointant vers le dépôt d'origine, utilisez l'un de ces exemples pour configurer un dépôt distant appelé upstream :

      ```shell
      # Set any repository as your upstream after editing <upstream_url>
      git remote add upstream <upstream_url>

      # Set the main GitLab repository as your upstream
      git remote add upstream https://gitlab.com/gitlab-org/gitlab.git
      ```

1. Mettez à jour votre duplication :

   1. Dans votre copie locale, extrayez la [branche par défaut](../../user/project/repository/branches/default.md). Remplacez `main` par le nom de votre branche par défaut :

      ```shell
      git checkout main
      ```

      > [!note]
      > Si Git identifie des modifications non indexées, [commitez-les ou remisez-les](commit.md) avant de continuer.

   1. Récupérez les modifications depuis le dépôt amont :

      ```shell
      git fetch upstream
      ```

   1. Intégrez les modifications dans votre duplication. Remplacez `main` par le nom de la branche que vous mettez à jour :

      ```shell
      git pull upstream main
      ```

   1. Poussez les modifications vers votre dépôt de duplication sur le serveur :

      ```shell
      git push origin main
      ```

## Collaborer entre duplications {#collaborate-across-forks}

GitLab facilite la collaboration entre les responsables du projet amont et les propriétaires de duplications. Pour plus d'informations, consultez :

- [Collaborer sur des merge requests entre duplications](../../user/project/merge_requests/allow_collaboration.md)
  - [Autoriser les commits des membres amont](../../user/project/merge_requests/allow_collaboration.md#allow-commits-from-upstream-members)
  - [Empêcher les commits des membres amont](../../user/project/merge_requests/allow_collaboration.md#prevent-commits-from-upstream-members)

### Pousser vers une duplication en tant que membre amont {#push-to-a-fork-as-an-upstream-member}

Vous pouvez pousser directement vers la branche du dépôt dupliqué si :

- L'auteur de la merge request a activé les contributions des membres amont.
- Vous disposez du rôle Developer, Maintainer ou Owner pour le projet amont.

Dans l'exemple suivant :

- L'URL du dépôt dupliqué est `git@gitlab.com:contributor/forked-project.git`.
- La branche de la merge request est `fork-branch`.

Pour modifier ou ajouter un commit à la merge request du contributeur :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez à **Code** > **Requêtes de fusion** et trouvez la merge request.
1. Dans le coin supérieur droit, sélectionnez **Code**, puis sélectionnez **Extraire la branche**.
1. Dans la boîte de dialogue, sélectionnez **Copier** ({{< icon name="copy-to-clipboard" >}}).
1. Dans votre terminal, accédez à la version clonée du dépôt et collez les commandes. Par exemple :

   ```shell
   git fetch "git@gitlab.com:contributor/forked-project.git" 'fork-branch'
   git checkout -b 'contributor/fork-branch' FETCH_HEAD
   ```

   Ces commandes récupèrent la branche depuis le projet dupliqué et créent une branche locale sur laquelle vous pouvez travailler.
1. Apportez vos modifications à la copie locale de la branche, puis commitez-les.
1. Poussez vos modifications locales vers le projet dupliqué. La commande suivante pousse la branche locale `contributor/fork-branch` vers la branche `fork-branch` du dépôt `git@gitlab.com:contributor/forked-project.git` :

   ```shell
   git push git@gitlab.com:contributor/forked-project.git contributor/fork-branch:fork-branch
   ```

   Si vous avez modifié ou écrasé des commits, vous devez utiliser `git push --force`. Procédez avec précaution, car cette commande réécrit l'historique des commits.

   ```shell
   git push --force git@gitlab.com:contributor/forked-project.git contributor/fork-branch:fork-branch
   ```

   Le deux-points (`:`) spécifie la branche source et la branche de destination. La syntaxe est la suivante :

   ```shell
   git push <forked_repository_git_url> <local_branch>:<fork_branch>
   ```

## Sujets connexes {#related-topics}

- [Workflows de duplication](../../user/project/repository/forking_workflow.md)
  - [Créer une duplication](../../user/project/repository/forking_workflow.md#create-a-fork)
  - [Dissocier une duplication](../../user/project/repository/forking_workflow.md#unlink-a-fork)
- [Collaborer sur des merge requests entre duplications](../../user/project/merge_requests/allow_collaboration.md)
- [Merge requests](../../user/project/merge_requests/_index.md)
