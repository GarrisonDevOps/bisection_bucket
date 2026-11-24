---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Mettre à niveau les instances compilées manuellement
description: Mettre à niveau une instance compilée manuellement à nœud unique.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Mettez à niveau une instance compilée manuellement vers une version ultérieure de GitLab.

## Prérequis {#prerequisites}

Avant de procéder à la mise à niveau :

1. Vous devez [lire les informations requises et effectuer les étapes requises](plan_your_upgrade.md).
1. Consultez les [prérequis logiciels](../install/self_compiled/_index.md#software-requirements) pour Ruby, Node.js, Go et PostgreSQL.

## Mettre à niveau une instance compilée manuellement {#upgrade-a-self-compiled-instance}

Pour mettre à niveau une instance compilée manuellement :

1. Envisagez d'[activer le mode maintenance](../administration/maintenance_mode/_index.md) pendant la mise à niveau.
1. Mettez en pause les [pipelines CI/CD et jobs en cours d'exécution](plan_your_upgrade.md#pause-cicd-pipelines-and-jobs).
1. [Mettez à niveau GitLab Runner](https://docs.gitlab.com/runner/install/) vers la même version que votre version cible de GitLab.
1. Mettez à niveau GitLab en suivant les instructions de cette page.

Après la mise à niveau :

1. Réactivez les [pipelines CI/CD et jobs en cours d'exécution](plan_your_upgrade.md#pause-cicd-pipelines-and-jobs).
1. Si activé, [désactivez le mode maintenance](../administration/maintenance_mode/_index.md#disable-maintenance-mode).
1. Exécutez les [vérifications de l'état de la mise à niveau](plan_your_upgrade.md#run-upgrade-health-checks).

### Créer une sauvegarde {#create-a-backup}

Prérequis :

- Vérifiez que `rsync` est installé.

Pour créer une sauvegarde :

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake gitlab:backup:create RAILS_ENV=production
```

### Arrêter GitLab {#stop-gitlab}

Pour arrêter GitLab :

```shell
# For systems running systemd
sudo systemctl stop gitlab.target

# For systems running SysV init
sudo service gitlab stop
```

### Mettre à jour Ruby {#update-ruby}

Si une version plus récente de Ruby est requise, vous devez mettre à jour Ruby :

1. Pour vérifier quelle version de Ruby vous avez, exécutez :

   ```shell
   ruby -v
   ```

1. Pour les instructions de mise à jour vers des versions plus récentes de Ruby, consultez les [instructions d'installation de Ruby](https://www.ruby-lang.org/en/documentation/installation/).

### Mettre à jour Node.js {#update-nodejs}

Si une version plus récente de Node.js est requise, vous devez mettre à jour Node.js :

1. Pour vérifier quelle version de Node.js vous avez, exécutez :

   ```shell
   node -v
   ```

1. Pour les instructions de mise à jour vers des versions plus récentes de Node.js, consultez les [instructions de téléchargement de Node.js](https://nodejs.org/en/download).

GitLab nécessite également Yarn `>= v1.10.0` pour gérer les dépendances JavaScript. Pour plus d'informations, consultez le [site web de Yarn](https://classic.yarnpkg.com/en/docs/install).

### Mettre à jour Go {#update-go}

Si une version plus récente de Go est requise, vous devez mettre à jour Go :

1. Pour vérifier quelle version de Go vous avez, exécutez :

   ```shell
   go version
   ```

1. Pour les instructions de mise à jour vers des versions plus récentes de Go, consultez les [instructions d'installation de Go](https://go.dev/doc/install).

### Mettre à jour Git {#update-git}

Vous devez utiliser la version de Git fournie par Gitaly. Pour plus d'informations, consultez les [instructions d'installation GitLab pour Git](../install/self_compiled/_index.md#git).

### Mettre à jour PostgreSQL {#update-postgresql}

Si une version plus récente de PostgreSQL est requise, vous devez mettre à jour PostgreSQL :

1. Pour vérifier quelle version de PostgreSQL vous avez, exécutez :

   ```shell
   pg_ctl --version
   ```

1. Pour les instructions de mise à jour vers des versions plus récentes de PostgreSQL, consultez la [documentation de mise à niveau de PostgreSQL](https://www.postgresql.org/docs/16/upgrading.html).
1. Vérifiez que vous disposez des [extensions PostgreSQL](../install/requirements.md#postgresql) requises.

### Mettre à jour la base de code GitLab {#update-the-gitlab-codebase}

Pour mettre à jour votre clone de la base de code GitLab :

1. Récupérez les métadonnées du dépôt :

   ```shell
   cd /home/git/gitlab

   sudo -u git -H git fetch --all --prune
   sudo -u git -H git checkout -- Gemfile.lock db/structure.sql locale
   ```

1. Extrayez la branche correspondant à la version vers laquelle vous souhaitez effectuer la mise à niveau :

   {{< tabs >}}

   {{< tab title="GitLab Enterprise Edition" >}}

   ```shell
   cd /home/git/gitlab

   sudo -u git -H git checkout <BRANCH-ee>
   ```

   {{< /tab >}}

   {{< tab title="GitLab Community Edition" >}}

   ```shell
   cd /home/git/gitlab

   sudo -u git -H git checkout <BRANCH>
   ```

   {{< /tab >}}

   {{< /tabs >}}

### Mettre à jour les fichiers de configuration {#update-configuration-files}

Les mises à niveau de GitLab peuvent nécessiter des mises à jour de la configuration suivante :

- `gitlab.yml`
- `database.yml`
- NGINX (ou Apache)
- SMTP
- systemd
- SysV

Les sections suivantes expliquent comment déterminer si des mises à jour de configuration sont requises.

#### Nouvelle configuration pour `gitlab.yml` {#new-configuration-for-gitlabyml}

De nouvelles options de configuration peuvent être disponibles pour [`gitlab.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/config/gitlab.yml.example).

1. Affichez les nouvelles configurations possibles :

   ```shell
   cd /home/git/gitlab
   git diff origin/PREVIOUS_BRANCH:config/gitlab.yml.example origin/BRANCH:config/gitlab.yml.example
   ```

1. Appliquez manuellement la nouvelle configuration à votre `gitlab.yml` actuel.

#### Nouvelle configuration pour `database.yml` {#new-configuration-for-databaseyml}

De nouvelles options de configuration peuvent être disponibles pour [`database.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/config/database.yml.postgresql).

1. Affichez les nouvelles configurations possibles :

   ```shell
   cd /home/git/gitlab
   git diff origin/PREVIOUS_BRANCH:config/database.yml.postgresql origin/BRANCH:config/database.yml.postgresql
   ```

1. Appliquez manuellement la nouvelle configuration à votre `database.yml` actuel.

#### Nouvelle configuration pour NGINX ou Apache {#new-configuration-for-nginx-or-apache}

Vérifiez que vous êtes toujours à jour avec les dernières modifications de configuration NGINX :

```shell
cd /home/git/gitlab

# For HTTPS configurations
git diff origin/PREVIOUS_BRANCH:lib/support/nginx/gitlab-ssl origin/BRANCH:lib/support/nginx/gitlab-ssl

# For HTTP configurations
git diff origin/PREVIOUS_BRANCH:lib/support/nginx/gitlab origin/BRANCH:lib/support/nginx/gitlab
```

L'application GitLab ne définit plus Strict-Transport-Security dans votre installation. Vous devez l'activer dans votre configuration NGINX pour continuer à l'utiliser.

Si vous utilisez Apache à la place de NGINX, consultez les [modèles Apache](https://gitlab.com/gitlab-org/gitlab-recipes/tree/master/web-server/apache) mis à jour. Apache ne prenant pas en charge les upstreams derrière les sockets Unix, vous devez laisser GitLab Workhorse écouter sur un port TCP en utilisant [`/etc/default/gitlab`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/support/init.d/gitlab.default.example#L38).

#### Configuration SMTP {#smtp-configuration}

Si vous utilisez SMTP pour envoyer des e-mails, vous devez ajouter la ligne suivante à `config/initializers/smtp_settings.rb` :

```ruby
ActionMailer::Base.delivery_method = :smtp
```

Consultez [`smtp_settings.rb.sample`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/config/initializers/smtp_settings.rb.sample#L13) pour un exemple.

#### Configurer les unités systemd {#configure-systemd-units}

1. Vérifiez si les unités systemd ont été mises à jour :

   ```shell
   cd /home/git/gitlab

   git diff origin/PREVIOUS_BRANCH:lib/support/systemd origin/BRANCH:lib/support/systemd
   ```

1. Copiez-les :

   ```shell
   sudo mkdir -p /usr/local/lib/systemd/system
   sudo cp lib/support/systemd/* /usr/local/lib/systemd/system/
   sudo systemctl daemon-reload
   ```

#### Configurer le script init SysV {#configure-sysv-init-script}

De nouvelles options de configuration peuvent être disponibles pour [`gitlab.default.example`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/support/init.d/gitlab.default.example).

1. Affichez les nouvelles configurations possibles :

   ```shell
   cd /home/git/gitlab

   git diff origin/PREVIOUS_BRANCH:lib/support/init.d/gitlab.default.example origin/BRANCH:lib/support/init.d/gitlab.default.example
   ```

1. Appliquez-les manuellement à votre `/etc/default/gitlab` actuel.

Vérifiez que vous êtes toujours à jour avec les dernières modifications du script init :

```shell
cd /home/git/gitlab

sudo cp lib/support/init.d/gitlab /etc/init.d/gitlab
```

Si vous utilisez le script init sur un système exécutant systemd comme init, parce que vous n'avez pas encore migré vers les unités systemd natives, exécutez :

```shell
sudo systemctl daemon-reload
```

### Installer les bibliothèques et exécuter les migrations {#install-libraries-and-run-migrations}

Pour installer les bibliothèques et exécuter les migrations :

1. Installez les bibliothèques nécessaires :

   ```shell
   cd /home/git/gitlab

   # If you haven't done so during installation or a previous upgrade already
   sudo -u git -H bundle config set --local deployment 'true'
   sudo -u git -H bundle config set --local without 'development test kerberos'

   # Update gems
   sudo -u git -H bundle install

   # Optional: clean up old gems
   sudo -u git -H bundle clean
   ```

1. Exécutez les migrations :

   ```shell
   # Run database migrations
   sudo -u git -H bundle exec rake db:migrate RAILS_ENV=production

   # Update node dependencies and recompile assets
   sudo -u git -H bundle exec rake yarn:install gitlab:assets:clean gitlab:assets:compile RAILS_ENV=production NODE_ENV=production NODE_OPTIONS="--max_old_space_size=4096"

   # Clean up cache
   sudo -u git -H bundle exec rake cache:clear RAILS_ENV=production
   ```

### Mettre à jour GitLab Shell {#update-gitlab-shell}

Pour mettre à jour GitLab Shell, exécutez ces commandes :

```shell
cd /home/git/gitlab-shell

sudo -u git -H git fetch --all --tags --prune
sudo -u git -H git checkout v$(</home/git/gitlab/GITLAB_SHELL_VERSION)
sudo -u git -H make build
```

### Mettre à jour GitLab Workhorse {#update-gitlab-workhorse}

Pour installer et compiler GitLab Workhorse, exécutez ces commandes :

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake "gitlab:workhorse:install[/home/git/gitlab-workhorse]" RAILS_ENV=production
```

### Mettre à jour Gitaly {#update-gitaly}

Mettez à niveau les serveurs Gitaly vers la version plus récente avant de mettre à niveau le serveur d'application. Cela empêche le client gRPC du serveur d'application d'envoyer des RPC que l'ancienne version de Gitaly ne prend pas en charge.

Si Gitaly est situé sur son propre serveur, ou si vous utilisez Gitaly Cluster (Praefect), consultez [Mises à niveau sans interruption de service](zero_downtime.md).

Pendant le processus de compilation, Gitaly [compile et intègre les binaires Git](https://gitlab.com/gitlab-org/gitaly/-/issues/6089), ce qui nécessite des dépendances supplémentaires.

```shell
# Install dependencies
sudo apt-get install -y libcurl4-openssl-dev libexpat1-dev gettext libz-dev libssl-dev libpcre2-dev build-essential

# Fetch Gitaly source with Git and compile with Go
cd /home/git/gitlab
sudo -u git -H bundle exec rake "gitlab:gitaly:install[/home/git/gitaly,/home/git/repositories]" RAILS_ENV=production
```

### Mettre à jour GitLab Pages {#update-gitlab-pages}

Pour installer et compiler GitLab Pages :

```shell
cd /home/git/gitlab-pages

sudo -u git -H git fetch --all --tags --prune
sudo -u git -H git checkout v$(</home/git/gitlab/GITLAB_PAGES_VERSION)
sudo -u git -H make
```

### Étapes post-mise à niveau {#post-upgrade-steps}

Une fois la mise à niveau effectuée :

1. [Démarrez GitLab et NGINX](#start-gitlab-and-nginx).
1. [Vérifiez le statut de GitLab](#check-gitlab-status).

#### Démarrer GitLab et NGINX {#start-gitlab-and-nginx}

Pour démarrer GitLab et NGINX :

```shell
# For systems running systemd
sudo systemctl start gitlab.target
sudo systemctl restart nginx.service

# For systems running SysV init
sudo service gitlab start
sudo service nginx restart
```

#### Vérifier le statut de GitLab {#check-gitlab-status}

Pour vérifier le statut de GitLab :

1. Vérifiez que GitLab et son environnement sont configurés correctement :

   ```shell
   cd /home/git/gitlab
   sudo -u git -H bundle exec rake gitlab:env:info RAILS_ENV=production
   ```

1. Pour vous assurer de n'avoir rien manqué, effectuez une vérification plus approfondie :

   ```shell
   cd /home/git/gitlab

   sudo -u git -H bundle exec rake gitlab:check RAILS_ENV=production
   ```

Si tous les éléments sont en vert, félicitations, la mise à niveau est terminée !

## Dépannage {#troubleshooting}

Si vous rencontrez des problèmes pendant la mise à niveau, essayez quelques-unes des étapes des sections suivantes.

### Revenir à la version précédente du code {#revert-the-code-to-the-previous-version}

Pour revenir à une version précédente, vous devez suivre les guides de mise à niveau correspondant à cette version précédente.

Par exemple, si vous avez effectué une mise à niveau vers GitLab 19.2 et souhaitez revenir à la version 19.1, suivez les guides de mise à niveau de la version 19.0 vers la version 19.1.

Lors du retour à la version précédente :

- Vous ne devez pas suivre les guides de migration de base de données, car la sauvegarde a déjà été migrée vers la version précédente.
- Si vous avez exécuté des migrations de base de données, vous devez restaurer une sauvegarde après le retour à la version précédente. La version du code doit être compatible avec la version du schéma utilisée. L'ancien schéma se trouve dans la sauvegarde.

### Restaurer depuis une sauvegarde {#restore-from-a-backup}

Pour restaurer depuis une sauvegarde :

```shell
cd /home/git/gitlab

sudo -u git -H bundle exec rake gitlab:backup:restore RAILS_ENV=production
```

Si vous disposez de plusieurs fichiers de sauvegarde `*.tar`, ajoutez `BACKUP=timestamp_of_backup` au bloc de code précédent.
