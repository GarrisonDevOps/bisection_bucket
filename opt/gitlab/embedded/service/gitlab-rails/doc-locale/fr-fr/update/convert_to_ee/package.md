---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Convertir une instance CE de package Linux en EE
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Vous pouvez convertir une instance de package Linux existante de la Community Edition (CE) vers l'Enterprise Edition (EE). Pour convertir l'instance, vous installez le package Linux EE par-dessus l'instance CE.

Vous n'avez pas besoin de la même version de CE pour passer à EE. Par exemple, la migration de CE 18.0 vers EE 18.1 devrait fonctionner. Cependant, il est recommandé de passer à la même version (par exemple, de CE 18.1 à EE 18.1).

> [!warning]
> Après avoir converti de EE vers CE, ne revenez pas à CE si vous prévoyez de repasser à EE. Le retour à CE peut entraîner des problèmes de base de données [problèmes de base de données](package_troubleshooting.md#500-error-when-accessing-project-repository-settings) pouvant nécessiter l'intervention du Support.

## Convertir de CE en EE {#convert-from-ce-to-ee}

Pour convertir une instance CE de package Linux en EE :

1. Effectuez une [sauvegarde GitLab](../../administration/backup_restore/backup_gitlab.md).
1. Trouvez la version de GitLab installée :

   {{< tabs >}}

   {{< tab title="Debian/Ubuntu" >}}

   ```shell
   sudo apt-cache policy gitlab-ce | grep Installed
   ```

   Notez la version retournée.

   {{< /tab >}}

   {{< tab title="CentOS/RHEL" >}}

   ```shell
   sudo rpm -q gitlab-ce
   ```

   Notez la version retournée.

   {{< /tab >}}

   {{< /tabs >}}

1. Ajoutez le `gitlab-ee` [dépôt Apt ou Yum](https://packages.gitlab.com/ui/browse/gitlab/gitlab-ee). Ces commandes détectent votre version de système d'exploitation et configurent automatiquement le dépôt.

   {{< tabs >}}

   {{< tab title="Debian/Ubuntu" >}}

   ```shell
   curl --silent "https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.deb.sh" | sudo bash
   ```

   {{< /tab >}}

   {{< tab title="CentOS/RHEL" >}}

   ```shell
   curl --silent "https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.rpm.sh" | sudo bash
   ```

   {{< /tab >}}

   {{< /tabs >}}

   Pour utiliser `dpkg` ou `rpm` au lieu de `apt-get` ou `yum`, suivez les instructions de [mise à niveau avec un package téléchargé](../package/_index.md#upgrade-with-a-downloaded-package).

1. Installez le package Linux `gitlab-ee`. L'installation désinstalle automatiquement le package `gitlab-ce` de votre GitLab.

   {{< tabs >}}

   {{< tab title="Debian/Ubuntu" >}}

   ```shell
   ## Make sure the repositories are up-to-date
   sudo apt-get update

   ## Install the package using the version you wrote down from step 1
   sudo apt-get install gitlab-ee=18.1.0-ee.0

   ## Reconfigure GitLab
   sudo gitlab-ctl reconfigure
   ```

   {{< /tab >}}

   {{< tab title="CentOS/RHEL" >}}

   ```shell
   ## Install the package using the version you wrote down from step 1
   sudo yum install gitlab-ee-18.1.0-ee.0.el9.x86_64

   ## Reconfigure GitLab
   sudo gitlab-ctl reconfigure
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. [Ajoutez votre licence](../../administration/license.md) pour activer l'Enterprise Edition.
1. Confirmez que GitLab fonctionne comme prévu, puis vous pouvez supprimer l'ancien dépôt de la Community Edition :

   {{< tabs >}}

   {{< tab title="Debian/Ubuntu" >}}

   ```shell
   sudo rm /etc/apt/sources.list.d/gitlab_gitlab-ce.list
   ```

   {{< /tab >}}

   {{< tab title="CentOS/RHEL" >}}

   ```shell
   sudo rm /etc/yum.repos.d/gitlab_gitlab-ce.repo
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. Facultatif. [Configurez l'intégration Elasticsearch](../../integration/advanced_search/elasticsearch.md) pour activer la [recherche avancée](../../user/search/advanced_search.md).

C'est tout ! Vous pouvez désormais utiliser GitLab Enterprise Edition ! Pour passer à une version plus récente, suivez les instructions de [Mise à niveau des instances de package Linux](_index.md).

## Revenir à CE {#revert-back-to-ce}

Pour plus d'informations sur le retour d'une instance EE vers CE, consultez [comment revenir de EE à CE](revert.md).
