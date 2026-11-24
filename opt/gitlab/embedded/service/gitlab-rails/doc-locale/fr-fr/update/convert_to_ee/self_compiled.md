---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Convertir une instance CE auto-compilée en EE
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Vous pouvez convertir une instance auto-compilée existante de la Community Edition (CE) vers la Enterprise Edition (EE).

Ces instructions supposent que vous disposez d'une installation auto-compilée de GitLab CE correctement configurée et testée.

## Convertir de CE en EE {#convert-from-ce-to-ee}

Dans les instructions suivantes, remplacez :

- `EE_BRANCH` par la branche EE correspondant à la version que vous utilisez. Les noms des branches EE utilisent le format `major-minor-stable-ee`. Par exemple, `17-7-stable-ee`.
- `CE_BRANCH` par la branche de la Community Edition. Les noms des branches CE utilisent le format `major-minor-stable`. Par exemple, `17-7-stable`.

### Sauvegarde {#backup}

Pour sauvegarder GitLab :

```shell
cd /home/git/gitlab
sudo -u git -H bundle exec rake gitlab:backup:create RAILS_ENV=production
```

### Arrêter le serveur GitLab {#stop-gitlab-server}

Pour arrêter le serveur GitLab :

```shell
sudo service gitlab stop
```

### Obtenir le code EE {#get-the-ee-code}

Pour obtenir le code EE :

```shell
cd /home/git/gitlab
sudo -u git -H git remote add -f ee https://gitlab.com/gitlab-org/gitlab.git
sudo -u git -H git checkout EE_BRANCH
```

### Installer les bibliothèques et exécuter les migrations {#install-libraries-and-run-migrations}

Pour installer les bibliothèques et exécuter les migrations :

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

# Update node dependencies and recompile assets
sudo -u git -H bundle exec rake yarn:install gitlab:assets:clean gitlab:assets:compile RAILS_ENV=production NODE_ENV=production NODE_OPTIONS="--max_old_space_size=4096"

# Clean up cache
sudo -u git -H bundle exec rake cache:clear RAILS_ENV=production
```

### Installer `gitlab-elasticsearch-indexer` {#install-gitlab-elasticsearch-indexer}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Pour installer `gitlab-elasticsearch-indexer`, suivez les [instructions d'installation](../../integration/advanced_search/elasticsearch.md#install-an-elasticsearch-or-aws-opensearch-cluster).

### Démarrer l'application {#start-the-application}

Pour démarrer l'application :

```shell
sudo service gitlab start
sudo service nginx restart
```

### Vérifier le statut de l'application {#check-application-status}

Vérifiez que GitLab et son environnement sont correctement configurés :

```shell
sudo -u git -H bundle exec rake gitlab:env:info RAILS_ENV=production
```

Pour vous assurer de n'avoir rien manqué, effectuez une vérification plus approfondie :

```shell
sudo -u git -H bundle exec rake gitlab:check RAILS_ENV=production
```

Si tous les éléments sont en vert, la mise à niveau est terminée, félicitations !

## Revenir à CE {#revert-back-to-ce}

Si vous rencontrez des problèmes lors de la conversion vers EE et souhaitez revenir à CE :

1. Rétablissez le code à la version précédente :

   ```shell
   cd /home/git/gitlab
   sudo -u git -H git checkout CE_BRANCH
   ```

1. Restaurez à partir de la sauvegarde :

   ```shell
   cd /home/git/gitlab
   sudo -u git -H bundle exec rake gitlab:backup:restore RAILS_ENV=production
   ```

Pour en savoir plus sur le retour d'une instance EE vers CE, consultez [comment revenir de EE à CE](revert.md)).
