---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Résolution des problèmes liés à la mise à niveau d'une instance de package Linux"
description: "Solutions aux problèmes rencontrés lors de la mise à niveau d'une instance de package Linux."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Pour faciliter la résolution des problèmes, exécutez les commandes suivantes.

```shell
sudo gitlab-ctl status
sudo gitlab-rake gitlab:check SANITIZE=true
```

Pour plus d'informations sur :

- L'utilisation de `gitlab-ctl` pour la maintenance, consultez [Commandes de maintenance](https://docs.gitlab.com/omnibus/maintenance/).
- L'utilisation de `gitlab-rake` pour la vérification de la configuration, consultez [Vérifier la configuration de GitLab](../../administration/raketasks/maintenance.md#check-gitlab-configuration).

## Aucune nouvelle version trouvée après la mise à niveau du système d'exploitation {#no-new-version-found-after-upgrading-operating-system}

Des mises à niveau du système d'exploitation sont parfois requises avant de mettre à niveau GitLab. Lors de la mise à niveau d'un système d'exploitation, vous devrez peut-être également mettre à jour l'URL source du package GitLab dans la configuration du gestionnaire de packages de votre système d'exploitation.

Si votre gestionnaire de packages ne trouve aucune mise à niveau disponible alors que des mises à niveau devraient l'être, ajoutez de nouveau le dépôt de packages GitLab. Pour plus d'informations, consultez les informations relatives à [l'installation de GitLab à l'aide du package Linux](../../install/package/_index.md).

Les futures mises à niveau de GitLab sont récupérées en fonction de votre système d'exploitation mis à niveau.

## Erreurs 500 avec le message `PG::UndefinedColumn: ERROR:..` dans les journaux {#500-errors-with-pgundefinedcolumn-error-message-in-logs}

Après une mise à niveau, si vous commencez à recevoir des erreurs `500` dans les journaux affichant des messages similaires à `PG::UndefinedColumn: ERROR:...`, ces erreurs peuvent être causées par l'un des éléments suivants :

- Les [migrations de base de données](../background_migrations.md) ne sont pas terminées. Attendez que les migrations soient terminées.
- Les migrations de base de données sont terminées, mais GitLab doit charger le nouveau schéma. Pour charger le nouveau schéma, [redémarrez GitLab](../../administration/restart_gitlab.md).

## Erreur : impossible de se connecter à l'API GitLab interne {#error-failed-to-connect-to-the-internal-gitlab-api}

Si vous recevez l'erreur `Failed to connect to the internal GitLab API` sur un serveur GitLab Pages distinct, consultez le [dépannage de l'administration de GitLab Pages](../../administration/pages/troubleshooting.md#failed-to-connect-to-the-internal-gitlab-api)

## Une erreur s'est produite lors de la vérification de la signature {#an-error-occurred-during-the-signature-verification}

Si vous recevez cette erreur lors de l'exécution de `apt-get update` :

```plaintext
An error occurred during the signature verification
```

Mettez à jour la clé GPG du serveur de packages GitLab avec cette commande :

```shell
[ -x /usr/bin/apt-key ] &&
    [ -s /etc/apt/trusted.gpg ] &&
    apt-key --keyring /etc/apt/trusted.gpg del packages@gitlab.com
curl --fail --silent --show-error \
     --output /etc/apt/trusted.gpg.d/gitlab.asc \
     --url "https://packages.gitlab.com/gpg.key"
apt-get update
```

## Erreur : `Command timed out after 3600s` {#error-command-timed-out-after-3600s}

Si les modifications du schéma et des données de la base de données (migrations de base de données) nécessitent plus d'une heure d'exécution, les mises à niveau échouent avec une erreur `timed out` :

```plaintext
FATAL: Mixlib::ShellOut::CommandTimeout: rails_migration[gitlab-rails] (gitlab::database_migrations line 51)
had an error: Mixlib::ShellOut::CommandTimeout: bash[migrate gitlab-rails database]
(/opt/gitlab/embedded/cookbooks/cache/cookbooks/gitlab/resources/rails_migration.rb line 16)
had an error: Mixlib::ShellOut::CommandTimeout: Command timed out after 3600s:
```

Pour corriger cette erreur :

1. Exécutez les migrations de base de données restantes :

   ```shell
   sudo gitlab-rake db:migrate
   ```

   Cette commande peut prendre beaucoup de temps à s'exécuter. Utilisez `screen` ou tout autre mécanisme pour vous assurer que le programme n'est pas interrompu si votre session SSH se déconnecte.

1. Finalisez la mise à niveau :

   ```shell
   sudo gitlab-ctl reconfigure
   ```

1. Rechargez à chaud les services `puma` et `sidekiq` :

   ```shell
   sudo gitlab-ctl hup puma
   sudo gitlab-ctl restart sidekiq
   ```

## Fichiers d'assets manquants {#missing-asset-files}

Après une mise à niveau, GitLab peut ne pas servir correctement les assets tels que :

- Images
- JavaScript
- Feuilles de style

GitLab peut générer des erreurs 500, ou l'interface web peut ne pas s'afficher correctement.

Dans un environnement GitLab à grande échelle, si un serveur web derrière le load balancer présente ce problème, il se produit de manière intermittente.

La [tâche Rake pour recompiler](../../administration/raketasks/maintenance.md#precompile-the-assets) les assets ne s'applique pas à une installation par package Linux qui utilise des assets précompilés depuis `/opt/gitlab/embedded/service/gitlab-rails/public/assets`.

Les sections suivantes décrivent les causes possibles et les solutions.

### Anciens processus {#old-processes}

La cause la plus probable des anciens processus est qu'un ancien processus Puma est en cours d'exécution. Un ancien processus Puma peut demander aux clients de requêter des fichiers d'assets d'une release précédente de GitLab. Comme les fichiers n'existent plus, des erreurs HTTP 404 sont renvoyées.

Un redémarrage est la meilleure façon de s'assurer que ces anciens processus Puma ne sont plus en cours d'exécution. Vous pouvez également :

1. Arrêtez Puma :

   ```shell
   gitlab-ctl stop puma
   ```

1. Vérifiez s'il reste des processus Puma et supprimez-les :

   ```shell
   ps -ef | egrep 'puma[: ]'
   kill <processid>
   ```

1. Vérifiez avec `ps` que les processus Puma ont arrêté de s'exécuter.
1. Démarrez Puma

   ```shell
   gitlab-ctl start puma
   ```

### Fichiers sprockets en double {#duplicate-sprockets-files}

Les fichiers d'assets compilés ont des noms de fichiers uniques dans chaque release. Les fichiers sprockets fournissent un mappage entre les noms de fichiers dans le code de l'application et les noms de fichiers uniques.

```plaintext
/opt/gitlab/embedded/service/gitlab-rails/public/assets/.sprockets-manifest*.json
```

Assurez-vous qu'il n'y a qu'un seul fichier sprockets. [Rails utilise le premier](https://github.com/rails/sprockets-rails/blob/118ce60b1ffeb7a85640661b014cd2ee3c4e3e56/lib/sprockets/railtie.rb#L201).

Une vérification des fichiers sprockets en double s'exécute lors des mises à niveau du package Linux :

```plaintext
GitLab discovered stale file(s) from the previous install that need to be cleaned up.
The following files need to be removed:

/opt/gitlab/embedded/service/gitlab-rails/public/assets/.sprockets-manifest-e16fdb7dd73cfdd64ed9c2cc0e35718a.json
```

Les options pour résoudre ce problème sont les suivantes :

- Si vous avez la sortie de la mise à niveau du package, supprimez les fichiers spécifiés. Redémarrez ensuite Puma :

  ```shell
  gitlab-ctl restart puma
  ```

- Si vous n'avez pas le message, effectuez une réinstallation pour le générer à nouveau. Pour plus d'informations, consultez [Installation incomplète](#incomplete-installation).
- Supprimez tous les fichiers sprockets, puis suivez les instructions pour une [installation incomplète](#incomplete-installation).

### Installation incomplète {#incomplete-installation}

Une installation incomplète pourrait être la cause des problèmes de fichiers d'assets manquants.

Vérifiez le package pour déterminer si c'est le problème :

- Pour les distributions Debian :

  ```shell
  apt-get install debsums
  debsums -c gitlab-ee
  ```

- Pour les distributions Red Hat/SUSE (RPM) :

  ```shell
  rpm -V gitlab-ee
  ```

Pour réinstaller le package afin de corriger une installation incomplète :

1. Vérifiez la version installée :

   - Pour les distributions Debian :

     ```shell
     apt --installed list gitlab-ee
     ```

   - Pour les distributions Red Hat/SUSE (RPM) :

     ```shell
     rpm -qa gitlab-ee
     ```

1. Réinstallez le package en spécifiant la version installée. Par exemple, la version 14.4.0 Enterprise Edition :

   - Pour les distributions Debian :

     ```shell
     apt-get install --reinstall gitlab-ee=14.4.0-ee.0
     ```

   - Pour les distributions Red Hat/SUSE (RPM) :

     ```shell
     yum reinstall gitlab-ee-14.4.0
     ```

### Support Gzip de NGINX désactivé {#nginx-gzip-support-disabled}

Vérifiez si `nginx['gzip_enabled']` a été désactivé :

```shell
grep gzip /etc/gitlab/gitlab.rb
```

Cela peut empêcher certains assets d'être servis. [En savoir plus](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/6087#note_558194395) dans l'un des tickets associés.

## Erreur ActiveRecord::LockWaitTimeout, nouvelle tentative après une pause {#activerecordlockwaittimeout-error-retrying-after-sleep}

Dans de rares cas, Sidekiq est occupé et verrouille la table que les migrations tentent de modifier. Pour résoudre ce problème :

1. Mettez GitLab en mode lecture seule.
1. Arrêtez Sidekiq :

   ```shell
   gitlab-ctl stop sidekiq
   ```

## Erreur de vérification de signature GPG : signature GPG incorrecte {#gpg-signature-verification-error-bad-gpg-signature}

Vous pouvez recevoir l'erreur suivante lors de l'exécution de `yum update` ou de `dnf update` :

```plaintext
Error: Failed to download metadata for repo 'gitlab_gitlab-ee-source': repomd.xml GPG signature verification error: Bad GPG signature
```

Pour résoudre ce problème :

1. Exécutez `dnf clean all`.
1. [Récupérez les dernières clés de signature](https://docs.gitlab.com/omnibus/update/package_signatures/?tab=CentOS%2FOpenSUSE%2FSLES#fetch-latest-signing-key).
1. Tentez à nouveau la mise à niveau.

Si l'erreur persiste même après `dnf clean all`, supprimez manuellement le répertoire de cache du dépôt affecté. Dans cet exemple :

1. Supprimez `/var/cache/dnf/gitlab_gitlab-ee-source`.
1. Exécutez `dnf makecache`.
