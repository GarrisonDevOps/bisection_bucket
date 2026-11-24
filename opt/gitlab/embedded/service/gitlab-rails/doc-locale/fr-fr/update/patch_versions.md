---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Mettre à jour les instances auto-compilées avec des versions de correctif
description: Mettre à jour une instance auto-compilée à nœud unique avec une version de correctif.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Mettre à jour une instance auto-compilée avec une version de correctif.

## Prérequis {#prerequisites}

Avant de procéder à la mise à jour :

1. Vous devez [lire les informations requises et effectuer les étapes nécessaires](plan_your_upgrade.md).
1. [Sauvegardez](../administration/backup_restore/_index.md) votre instance auto-compilée.

## Mettre à jour une instance auto-compilée avec une version de correctif {#update-a-self-compiled-instance-with-a-patch-version}

Pour mettre à jour une instance auto-compilée avec une version de correctif :

1. Envisagez d'[activer le mode maintenance](../administration/maintenance_mode/_index.md) pendant la mise à jour.
1. Mettez en pause [les pipelines CI/CD et les jobs en cours d'exécution](plan_your_upgrade.md#pause-cicd-pipelines-and-jobs).
1. [Mettez à niveau GitLab Runner](https://docs.gitlab.com/runner/install/) vers la même version que votre version cible de GitLab.
1. Mettez à jour GitLab en suivant les instructions de cette page.

Après la mise à jour :

1. Réactivez [les pipelines CI/CD et les jobs en cours d'exécution](plan_your_upgrade.md#pause-cicd-pipelines-and-jobs).
1. Si activé, [désactivez le mode maintenance](../administration/maintenance_mode/_index.md#disable-maintenance-mode).
1. Exécutez les [vérifications de l'état](plan_your_upgrade.md#run-upgrade-health-checks).

### Arrêter le serveur GitLab {#stop-gitlab-server}

Pour arrêter le serveur GitLab :

```shell
# For systems running systemd
sudo systemctl stop gitlab.target

# For systems running SysV init
sudo service gitlab stop
```

### Obtenir le code le plus récent pour la branche stable {#get-latest-code-for-the-stable-branch}

Dans les commandes suivantes, remplacez `LATEST_TAG` par le tag GitLab vers lequel effectuer la mise à jour. Par exemple, `v8.0.3`.

1. Vérifiez votre version actuelle :

   ```shell
   cat VERSION
   ```

1. Obtenez la liste de tous les tags disponibles :

   ```shell
   git tag -l 'v*.[0-9]' --sort='v:refname'
   ```

1. Choisissez une version de correctif pour votre version majeure et mineure actuelle.
1. Extrayez le code de la version de correctif à utiliser :

   ```shell
   cd /home/git/gitlab

   sudo -u git -H git fetch --all
   sudo -u git -H git checkout -- Gemfile.lock db/structure.sql locale
   sudo -u git -H git checkout LATEST_TAG -b LATEST_TAG
   ```

### Installer les bibliothèques et exécuter les migrations {#install-libraries-and-run-migrations}

Pour installer les bibliothèques et exécuter les migrations, exécutez les commandes suivantes :

```shell
cd /home/git/gitlab

# If you haven't done so during installation or a previous upgrade already
sudo -u git -H bundle config set --local deployment 'true'
sudo -u git -H bundle config set --local without 'development test kerberos'

# Update gems
sudo -u git -H bundle install

# Optional: clean up old gems
sudo -u git -H bundle clean

# Run database migrations
sudo -u git -H bundle exec rake db:migrate RAILS_ENV=production

# Clean up assets and cache
sudo -u git -H bundle exec rake yarn:install gitlab:assets:clean gitlab:assets:compile cache:clear RAILS_ENV=production NODE_ENV=production NODE_OPTIONS="--max_old_space_size=4096"
```

### Mettre à jour GitLab Workhorse vers la nouvelle version de correctif {#update-gitlab-workhorse-to-the-new-patch-version}

Pour mettre à jour GitLab Workhorse vers la nouvelle version de correctif :

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake "gitlab:workhorse:install[/home/git/gitlab-workhorse]" RAILS_ENV=production
```

### Mettre à jour Gitaly vers la nouvelle version de correctif {#update-gitaly-to-the-new-patch-version}

Pour mettre à jour Gitaly vers la nouvelle version de correctif :

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake "gitlab:gitaly:install[/home/git/gitaly,/home/git/repositories]" RAILS_ENV=production
```

### Mettre à jour GitLab Shell vers la nouvelle version de correctif {#update-gitlab-shell-to-the-new-patch-version}

Pour mettre à jour GitLab Shell vers la nouvelle version de correctif :

```shell
cd /home/git/gitlab-shell

sudo -u git -H git fetch --all --tags
sudo -u git -H git checkout v$(</home/git/gitlab/GITLAB_SHELL_VERSION) -b v$(</home/git/gitlab/GITLAB_SHELL_VERSION)
sudo -u git -H make build
```

### Mettre à jour GitLab Pages vers la nouvelle version de correctif (si nécessaire) {#update-gitlab-pages-to-the-new-patch-version-if-required}

Si vous utilisez GitLab Pages, mettez à jour GitLab Pages vers la nouvelle version de correctif :

```shell
cd /home/git/gitlab-pages

sudo -u git -H git fetch --all --tags
sudo -u git -H git checkout v$(</home/git/gitlab/GITLAB_PAGES_VERSION)
sudo -u git -H make
```

### Installer ou mettre à jour `gitlab-elasticsearch-indexer` {#install-or-update-gitlab-elasticsearch-indexer}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Pour installer ou mettre à jour `gitlab-elasticsearch-indexer`, suivez les [instructions d'installation](../integration/advanced_search/elasticsearch.md#install-an-elasticsearch-or-aws-opensearch-cluster).

### Démarrer GitLab {#start-gitlab}

Pour démarrer GitLab, exécutez les commandes suivantes :

```shell
# For systems running systemd
sudo systemctl start gitlab.target
sudo systemctl restart nginx.service

# For systems running SysV init
sudo service gitlab start
sudo service nginx restart
```

### Vérifier GitLab et son environnement {#check-gitlab-and-its-environment}

Pour vérifier si GitLab et son environnement sont correctement configurés, exécutez :

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake gitlab:env:info RAILS_ENV=production
```

Pour vous assurer de n'avoir rien manqué, effectuez une vérification plus approfondie avec :

```shell
sudo -u git -H bundle exec rake gitlab:check RAILS_ENV=production
```

### Vérifier que les migrations en arrière-plan sont terminées {#make-sure-background-migrations-are-finished}

[Vérifiez le statut des migrations en arrière-plan](background_migrations.md) et assurez-vous qu'elles sont terminées.
