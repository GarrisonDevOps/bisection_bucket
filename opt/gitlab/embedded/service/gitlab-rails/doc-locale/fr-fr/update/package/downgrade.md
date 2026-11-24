---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Revenir à des versions antérieures de GitLab
description: Restaurez des instances de package Linux ou Docker à des versions antérieures.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Vous pouvez revenir à des versions antérieures d'instances GitLab qui ont été installées à l'aide du package Linux ou de Docker.

Lors d'un retour en arrière, vous devez prendre en compte les [modifications spécifiques à la version](../versions/_index.md) qui sont survenues lors de votre précédente mise à niveau.

## Prérequis {#prerequisites}

Étant donné que vous devez annuler les modifications du schéma de base de données (migrations) effectuées lors de la mise à niveau de l'instance, vous devez disposer de :

- Au minimum, une sauvegarde de base de données créée sous la version et l'édition exactes vers lesquelles vous effectuez le retour en arrière.
- Idéalement, une [archive de sauvegarde complète](../../administration/backup_restore/_index.md) de cette version et édition exactes vers lesquelles vous effectuez le retour en arrière.

## Restaurer une instance de package Linux {#roll-back-a-linux-package-instance}

Pour effectuer un retour en arrière d'une instance de package Linux vers une version antérieure de GitLab :

1. Arrêtez GitLab et supprimez le package actuel :

   ```shell
   # If running Puma
   sudo gitlab-ctl stop puma

   # Stop sidekiq
   sudo gitlab-ctl stop sidekiq

   # If on Ubuntu: remove the current package
   sudo dpkg -r gitlab-ee

   # If on Centos: remove the current package
   sudo yum remove gitlab-ee
   ```

1. Identifiez la version de GitLab vers laquelle vous souhaitez effectuer le retour en arrière :

   ```shell
   # (Replace with gitlab-ce if you have GitLab FOSS installed)

   # Ubuntu
   sudo apt-cache madison gitlab-ee

   # CentOS:
   sudo yum --showduplicates list gitlab-ee
   ```

1. Effectuez le retour en arrière de GitLab vers la version souhaitée (par exemple, vers GitLab 19.2.1) :

   ```shell
   # (Replace with gitlab-ce if you have GitLab FOSS installed)

   # Ubuntu
   sudo apt install gitlab-ee=19.2.1-ee.0

   # CentOS:
   sudo yum install gitlab-ee-19.2.1-ee.0.el8
   ```

1. Reconfigurez GitLab :

   ```shell
   sudo gitlab-ctl reconfigure
   ```

1. [Restaurez GitLab](../../administration/backup_restore/restore_gitlab.md#restore-for-linux-package-installations) pour terminer le retour en arrière.

## Restaurer une instance Docker {#roll-back-a-docker-instance}

La restauration écrase l'intégralité du contenu plus récent de la base de données GitLab avec l'état antérieur. Un retour en arrière n'est recommandé que lorsque cela est nécessaire. Par exemple, si des tests post-mise à niveau révèlent des problèmes qui ne peuvent pas être résolus rapidement.

> [!warning]
> Vous devez disposer au minimum d'une sauvegarde de base de données créée avec la version et l'édition exactes vers lesquelles vous effectuez le retour en arrière. La sauvegarde est nécessaire pour annuler les modifications du schéma (migrations) effectuées lors de la mise à niveau.

Pour effectuer un retour en arrière de GitLab peu après une mise à niveau :

1. Suivez la procédure de mise à niveau en [spécifiant une version antérieure](../../install/docker/installation.md#find-the-gitlab-version-and-edition-to-use) à celle que vous avez installée.
1. Restaurez la [sauvegarde de base de données que vous avez effectuée](../../install/docker/backup.md#create-a-database-backup) avant la mise à niveau.

   - [Suivez les étapes de restauration pour les images Docker](../../administration/backup_restore/restore_gitlab.md#restore-for-docker-image-and-gitlab-helm-chart-installations), notamment l'arrêt de Puma et Sidekiq. Seule la base de données doit être restaurée. Ajoutez donc `SKIP=artifacts,repositories,registry,uploads,builds,pages,lfs,packages,terraform_state` aux arguments de ligne de commande de `gitlab-backup restore`.
