---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Notes de mise à niveau GitLab 17
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Cette page contient des informations de mise à niveau pour les versions mineures et les versions correctives de GitLab 17. Veillez à consulter ces instructions pour :

- Votre type d'installation.
- Toutes les versions comprises entre votre version actuelle et votre version cible.

Pour plus d'informations sur les installations avec le chart Helm, consultez [les notes de mise à niveau du chart Helm 8.0](https://docs.gitlab.com/charts/releases/8_0/).

## Problèmes à prendre en compte lors de la mise à niveau {#issues-to-be-aware-of-when-upgrading}

Lors de la mise à niveau depuis certaines versions de GitLab, vous devez être conscient de certains problèmes pouvant affecter votre mise à niveau.

### Depuis GitLab 16.11 {#from-gitlab-1611}

Lors de la mise à niveau depuis GitLab 16.11 :

- La migration en arrière-plan `AlterWebhookDeletedAuditEvent: audit_events` peut prendre plusieurs heures. Vous pouvez en savoir plus dans la [merge request 161320](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/161320).
- Vous devez supprimer les références à la clé [Grafana intégré désormais déprécié](../deprecations.md#bundled-grafana-deprecated-and-disabled) de `gitlab.rb` avant de procéder à la mise à niveau vers GitLab 17.0 ou une version ultérieure. Après la mise à niveau, toute référence à la clé dans `gitlab.rb` entraînera l'échec de `gitlab-ctl reconfigure`.
- Vous devriez [migrer vers le nouveau workflow d'enregistrement des runners](../../ci/runners/new_creation_workflow.md) avant de procéder à la mise à niveau vers GitLab 17.0.

  Dans GitLab 16.0, nous avons introduit un nouveau workflow de création de runners utilisant des jetons d'authentification pour les enregistrer. L'ancien workflow utilisant des jetons d'enregistrement est désormais désactivé par défaut dans GitLab 17.0 et sa suppression est prévue dans GitLab 20.0. Si des jetons d'enregistrement sont encore utilisés, la mise à niveau vers GitLab 17.0 entraînera l'échec de l'enregistrement des runners.
- Les stockages Gitaly ne peuvent plus partager le même chemin que dans cet exemple :

  ```ruby
  gitaly['configuration'] = {
    storage: [
      {
         name: 'default',
         path: '/var/opt/gitlab/git-data/repositories',
      },
      {
         name: 'duplicate-path',
         path: '/var/opt/gitlab/git-data/repositories',
      },
    ],
  }
  ```

  Dans cet exemple, le stockage `duplicate-path` doit être supprimé ou déplacé vers un nouveau chemin. Si vous avez plusieurs nœuds Gitaly, vous devez vous assurer que seul le stockage correspondant à ce nœud est répertorié dans le fichier `gitlab.rb` de ce nœud.

  Si le stockage est supprimé du fichier `gitlab.rb` d'un nœud, tous les projets qui lui sont associés doivent voir leur stockage mis à jour dans la base de données GitLab. Vous pouvez mettre à jour leur stockage via la console Rails. Par exemple :

  ```shell
  $ sudo gitlab-rails console
  Project.where(repository_storage: 'duplicate-path').update_all(repository_storage: 'default')
  ```

- Échecs de migration lors de la mise à niveau depuis GitLab 16.x directement vers GitLab 17.1.0 ou 17.1.1. Ce bug a été corrigé avec GitLab 17.1.2. La mise à niveau depuis GitLab 16.x directement vers la version 17.1.2 ne provoque pas ces problèmes.

  En raison d'un bug dans GitLab 17.1.0 et 17.1.1 où la complétion d'un job en arrière-plan n'était pas correctement imposée, des échecs peuvent survenir lors d'une mise à niveau directe vers GitLab 17.1.0 et 17.1.1. L'erreur lors de la migration de la mise à niveau ressemble à ce qui suit :

  ```shell
  main: == [advisory_lock_connection] object_id: 55460, pg_backend_pid: 8714
  main: == 20240531173207 ValidateNotNullCheckConstraintOnEpicsIssueId: migrating =====
  main: -- execute("SET statement_timeout TO 0")
  main:    -> 0.0004s
  main: -- execute("ALTER TABLE epics VALIDATE CONSTRAINT check_450724d1bb;")
  main: -- execute("RESET statement_timeout")
  main: == [advisory_lock_connection] object_id: 55460, pg_backend_pid: 8714
  STDERR:
  ```

  Pour effectuer la mise à niveau, choisissez l'une des options suivantes :

  - Mettez à niveau vers GitLab 17.0 et attendez que toutes les migrations en arrière-plan soient terminées.
  - Mettez à niveau vers GitLab 17.1, puis exécutez manuellement le job en arrière-plan et la migration en exécutant la commande suivante :

    ```shell
    sudo gitlab-rake gitlab:background_migrations:finalize[BackfillEpicBasicFieldsToWorkItemRecord,epics,id,'[null]']
    ```

  Vous devriez maintenant pouvoir terminer les migrations dans GitLab 17.1 et finaliser la mise à niveau.

- Un [problème connu](https://gitlab.com/gitlab-org/gitlab/-/issues/476542) dans les versions de Git livrées avec GitLab 17.0.x et GitLab 17.1.x provoque une augmentation notable de l'utilisation du CPU sous charge. La cause principale de cette régression a été résolue dans les versions de Git livrées avec GitLab 17.2\. Pour les systèmes soumis à des pics de charge importants, vous devriez donc effectuer la mise à niveau vers GitLab 17.2.

#### Installations avec le paquet Linux {#linux-package-installations}

Des informations spécifiques s'appliquent aux installations via le package Linux :

- Les binaires pour PostgreSQL 13 ont été supprimés.

  Avant la mise à niveau, vous devez vous assurer que votre installation utilise [PostgreSQL 14](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server).
- Les packages ne sont plus créés pour Ubuntu 18.04

  Assurez-vous que votre système d'exploitation a été mis à niveau vers Ubuntu 20.04 ou une version ultérieure avant de tenter de mettre à niveau GitLab.

#### Jetons d'accès sans expiration {#non-expiring-access-tokens}

Les jetons d'accès sans date d'expiration sont valides indéfiniment, ce qui constitue un risque de sécurité en cas de divulgation.

Lorsque vous effectuez une mise à niveau vers GitLab 16.0 ou une version ultérieure, tout jeton d'accès [personnel](../../user/profile/personal_access_tokens.md), [de projet](../../user/project/settings/project_access_tokens.md) ou [de groupe](../../user/group/settings/group_access_tokens.md) sans date d'expiration reçoit automatiquement une date d'expiration fixée à un an à compter de la date de mise à niveau.

Avant l'application de cette date d'expiration automatique, vous devez effectuer les actions suivantes pour minimiser les perturbations :

1. [Identifiez les jetons d'accès sans date d'expiration](../../administration/raketasks/tokens/_index.md#find-tokens-the-rake-tasks-do-not-report).
1. [Attribuez une date d'expiration à ces jetons](../../administration/raketasks/tokens/_index.md#extend-expiration-dates).

Pour plus d'informations, consultez :

- [La documentation sur les dépréciations et suppressions](../deprecations.md#non-expiring-access-tokens).
- [Le ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/369122).

### Depuis GitLab 17.0 et versions antérieures {#from-gitlab-170-and-earlier}

Pour les installations via le package Linux, avant de procéder à la mise à niveau vers GitLab 17.1 ou une version ultérieure, vous devez supprimer les références à la clé [Grafana intégré désormais déprécié](../deprecations.md#bundled-grafana-deprecated-and-disabled) (`grafana[]`) dans `/etc/gitlab/gitlab.rb`. Après la mise à niveau, toute référence à cette clé dans `/etc/gitlab/gitlab.rb` peut entraîner des dysfonctionnements, [comme le widget de merge request](https://support.gitlab.com/hc/en-us/articles/19677647414812-Error-after-upgrade-Unable-to-load-the-merge-request-widget).

Pour plus d'informations, consultez les tickets suivants :

- [Supprimer l'attribut Grafana et les messages de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8200).
- [Déprécier Grafana et le désactiver comme changement cassant](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7772).

### Depuis GitLab 17.1 et versions antérieures {#from-gitlab-171-and-earlier}

Lors de la mise à niveau depuis GitLab 17.1 et versions antérieures :

- Si vous utilisez GitLab Duo et que vous effectuez une mise à niveau vers GitLab 17.2.3 ou une version antérieure, vous devez effectuer les deux actions suivantes :
  - Resynchronisez votre licence.
  - Redémarrez le serveur après la mise à niveau.
- Si vous utilisez GitLab Duo et que vous effectuez une mise à niveau vers GitLab 17.2.4 ou une version ultérieure, vous devez effectuer l'une des actions suivantes :
  - Resynchronisez votre licence.
  - Attendez la prochaine synchronisation de licence planifiée, qui intervient toutes les 24 heures.

Après avoir effectué la mise à niveau vers GitLab 17.2.4 ou une version ultérieure, ces étapes ne sont pas requises pour les futures mises à niveau.

Pour plus d'informations, consultez le [ticket 480328](https://gitlab.com/gitlab-org/gitlab/-/issues/480328).

### Depuis GitLab 17.3 {#from-gitlab-173}

Échecs de migration lors de la mise à niveau depuis GitLab 17.3.

Lors de la mise à niveau de la version 17.3 vers la version 17.4, il y a une légère chance de rencontrer une erreur. Au cours du processus de migration, un message d'erreur similaire au suivant peut s'afficher :

```shell
main: == [advisory_lock_connection] object_id: 127900, pg_backend_pid: 76263
main: == 20240812040748 AddUniqueConstraintToRemoteDevelopmentAgentConfigs: migrating
main: -- transaction_open?(nil)
main:    -> 0.0000s
main: -- view_exists?(:postgres_partitions)
main:    -> 0.0181s
main: -- index_exists?(:remote_development_agent_configs, :cluster_agent_id, {:name=>"index_remote_development_agent_configs_on_unique_agent_id", :unique=>true, :algorithm=>:concurrently})
main:    -> 0.0026s
main: -- execute("SET statement_timeout TO 0")
main:    -> 0.0004s
main: -- add_index(:remote_development_agent_configs, :cluster_agent_id, {:name=>"index_remote_development_agent_configs_on_unique_agent_id", :unique=>true, :algorithm=>:concurrently})
main: -- execute("RESET statement_timeout")
main:    -> 0.0002s
main: == [advisory_lock_connection] object_id: 127900, pg_backend_pid: 76263
rake aborted!
StandardError: An error has occurred, all later migrations canceled:

PG::UniqueViolation: ERROR:  could not create unique index "index_remote_development_agent_configs_on_unique_agent_id"
DETAIL:  Key (cluster_agent_id)=(1000141) is duplicated.
```

Cette erreur se produit parce que la migration ajoute une contrainte d'unicité sur la colonne `cluster_agent_id` de la table `remote_development_agent_configs`, mais des entrées en double sont encore présentes. La migration précédente est censée supprimer ces doublons, mais dans de rares cas, de nouveaux doublons peuvent être insérés entre les deux migrations.

Pour résoudre ce problème en toute sécurité, suivez ces étapes :

1. Ouvrez la console Rails sur laquelle les migrations sont exécutées.
1. Exécutez le script suivant dans la console Rails.
1. Relancez les migrations ; elles devraient se terminer avec succès.

```ruby
# Get the IDs to keep for each cluster_agent_id; if there are duplicates, only the row with the latest updated_at will be kept.
latest_ids = ::RemoteDevelopment::RemoteDevelopmentAgentConfig.select("DISTINCT ON (cluster_agent_id) id")
  .order("cluster_agent_id, updated_at DESC")
  .map(&:id)

# Get the list of remote_development_agent_configs to be removed.
agent_configs_to_remove = ::RemoteDevelopment::RemoteDevelopmentAgentConfig.where.not(id: latest_ids)

# Delete all duplicated agent_configs.
agent_configs_to_remove.delete_all
```

### Depuis GitLab 17.4 {#from-gitlab-174}

Échec de migration du job en arrière-plan lors de la mise à niveau de la version 17.4 vers la version 17.5.

Lors de la mise à niveau de la version 17.4 vers la version 17.5, une erreur peut apparaître dans les jobs Sidekiq liée à une migration de données en arrière-plan supprimée. Le message d'erreur ressemble à ceci : `uninitialized constant Gitlab::BackgroundMigration::SetProjectVulnerabilityCount`.

Cette erreur finira par disparaître d'elle-même, mais vous pouvez aussi exécuter le script suivant dans la console Rails pour ne plus la voir :

```ruby
Gitlab::Database::BackgroundMigration::BatchedMigration.for_configuration(
  :gitlab_main, 'SetProjectVulnerabilityCount', :project_settings, :project_id, []
).delete_all
```

### Depuis GitLab 17.5 {#from-gitlab-175}

Échecs de migration lors de la mise à niveau depuis GitLab 17.5.

Lors de la mise à niveau de la version 17.5 vers la version 17.6, il y a une légère chance de rencontrer une erreur. Au cours du processus de migration, un message d'erreur similaire au suivant peut s'afficher :

```shell
rake aborted!
StandardError: An error has occurred, all later migrations canceled:

PG::CheckViolation: ERROR: new row for relation "ci_deleted_objects" violates check constraint "check_98f90d6c53"
```

Cette erreur se produit parce que la migration tente de mettre à jour certaines lignes de la table `ci_deleted_objects` afin qu'elles soient traitées, mais il peut s'agir d'anciens enregistrements dont une valeur requise par une contrainte de vérification est manquante.

Pour résoudre ce problème en toute sécurité, suivez ces étapes :

1. Exécutez uniquement la migration suivante pour corriger les enregistrements affectés par la contrainte de vérification.
1. Relancez les migrations ; elles devraient se terminer avec succès.

   ```shell
   gitlab-rake db:migrate:up:ci VERSION=20241028085044
   ```

## Mises à niveau vers la version 17.11.0 {#upgrades-to-17110}

- Pour éviter un [problème connu](https://gitlab.com/gitlab-org/gitlab/-/issues/537325) qui provoque l'exécution prolongée d'une migration de base de données avec une utilisation excessive du CPU, mettez à niveau vers GitLab 17.11.3 ou une version ultérieure.

### Nouveaux secrets de chiffrement {#new-encryption-secrets}

Dans GitLab 17.8, trois nouveaux secrets ont été ajoutés pour prendre en charge le nouveau framework de chiffrement (dont l'utilisation a débuté en version 17.9) :

- `active_record_encryption_primary_key`
- `active_record_encryption_deterministic_key`
- `active_record_encryption_key_derivation_salt`

Si vous disposez d'une configuration multi-nœuds, vous devez [vous assurer que ces secrets sont identiques sur tous les nœuds](#unify-new-encryption-secrets).

### Installations Geo 17.11.0 {#geo-installations-17110}

- Les versions 17.11 à 18.1 de GitLab présentent un problème connu où les opérations Git proxysées depuis un site Geo secondaire échouent avec des erreurs HTTP 500. Pour résoudre ce problème, effectuez la mise à niveau vers GitLab 17.11.5 ou une version ultérieure.

## Mises à niveau vers la version 17.10.0 {#upgrades-to-17100}

- Tags de runner manquants lors de la mise à niveau vers GitLab 17.10, voir le [ticket 524402](https://gitlab.com/gitlab-org/gitlab/-/issues/524402). La mise à niveau préalable vers GitLab 17.6 permet d'éviter ce problème. Le bug est corrigé dans GitLab 17.11.

  **Versions affectées** :

  | Versions mineures affectées | Versions correctives affectées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 17.8                    |  17.8.0 - 17.8.6        | 17.8.7   |
  | 17.9                    |  17.9.0 - 17.9.4        | 17.9.5   |
  | 17.10                   |  17.10.0 - 17.10.4      | 17.10.5  |

  Lors de la mise à niveau depuis la version 17.5 vers une version antérieure aux versions correctives mentionnées dans le tableau, il existe un risque que la table des tags de runner devienne vide.

  Exécutez la requête PostgreSQL suivante sur la base de données `ci` pour vérifier la table des tags de runner et déterminer si vous êtes concerné :

  ```sql
  SELECT 'OK, ci_runner_taggings is populated.' FROM ci_runner_taggings LIMIT 1;
  ```

  Si la requête renvoie un résultat vide au lieu de `OK, ci_runner_taggings is populated.`, consultez la [solution de contournement](https://gitlab.com/gitlab-org/gitlab/-/issues/524402#workaround) dans le ticket associé.

### Nouveaux secrets de chiffrement {#new-encryption-secrets-1}

Dans GitLab 17.8, trois nouveaux secrets ont été ajoutés pour prendre en charge le nouveau framework de chiffrement (dont l'utilisation a débuté en version 17.9) :

- `active_record_encryption_primary_key`
- `active_record_encryption_deterministic_key`
- `active_record_encryption_key_derivation_salt`

Si vous disposez d'une configuration multi-nœuds, vous devez [vous assurer que ces secrets sont identiques sur tous les nœuds](#unify-new-encryption-secrets).

### Installations Geo 17.10.0 {#geo-installations-17100}

- Les versions 17.10 à 18.1 de GitLab présentent un problème connu où les opérations Git proxysées depuis un site Geo secondaire échouent avec des erreurs HTTP 500. Pour résoudre ce problème, effectuez la mise à niveau vers GitLab 17.11.5 ou une version ultérieure.

## Mises à niveau vers la version 17.9.0 {#upgrades-to-1790}

- Tags de runner manquants lors de la mise à niveau vers GitLab 17.9, voir le [ticket 524402](https://gitlab.com/gitlab-org/gitlab/-/issues/524402). La mise à niveau préalable vers GitLab 17.6 permet d'éviter ce problème. Le bug est corrigé dans GitLab 17.11.

  **Versions affectées** :

  | Versions mineures affectées | Versions correctives affectées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 17.8                    |  17.8.0 - 17.8.6        | 17.8.7   |
  | 17.9                    |  17.9.0 - 17.9.4        | 17.9.5   |
  | 17.10                   |  17.10.0 - 17.10.4      | 17.10.5  |

  Lors de la mise à niveau depuis la version 17.5 vers une version antérieure aux versions correctives mentionnées dans le tableau, il existe un risque que la table des tags de runner devienne vide.

  Exécutez la requête PostgreSQL suivante sur la base de données `ci` pour vérifier la table des tags de runner et déterminer si vous êtes concerné :

  ```sql
  SELECT 'OK, ci_runner_taggings is populated.' FROM ci_runner_taggings LIMIT 1;
  ```

  Si la requête renvoie un résultat vide au lieu de `OK, ci_runner_taggings is populated.`, consultez la [solution de contournement](https://gitlab.com/gitlab-org/gitlab/-/issues/524402#workaround) dans le ticket associé.

### Nouveaux secrets de chiffrement {#new-encryption-secrets-2}

Dans GitLab 17.8, trois nouveaux secrets ont été ajoutés pour prendre en charge le nouveau framework de chiffrement (dont l'utilisation a débuté en version 17.9) :

- `active_record_encryption_primary_key`
- `active_record_encryption_deterministic_key`
- `active_record_encryption_key_derivation_salt`

Si vous disposez d'une configuration multi-nœuds, vous devez [vous assurer que ces secrets sont identiques sur tous les nœuds](#unify-new-encryption-secrets).

## Mises à niveau vers la version 17.8.0 {#upgrades-to-1780}

- Échecs de migration lors de la mise à niveau vers GitLab 17.8.

  Lors de la mise à niveau vers la version 17.8, il y a une légère chance de rencontrer une erreur. Au cours du processus de migration, un message d'erreur similaire au suivant peut s'afficher :

  ```shell
  ERROR:  duplicate key value violates unique constraint "work_item_types_pkey"
  DETAIL:  Key (id)=(1) already exists.
  ```

  La migration produisant l'erreur serait `db/post_migrate/20241218223002_fix_work_item_types_id_column_values.rb`.

  Cette erreur se produit parce que, dans certains cas, les enregistrements de la table `work_item_types` n'ont pas été créés dans la base de données dans le même ordre que celui dans lequel ils ont été ajoutés à l'application.

  Pour résoudre ce problème en toute sécurité, suivez ces étapes :

  1. N'effectuez cette opération que si vous avez rencontré cette erreur lors d'une tentative de mise à niveau vers la version 17.8. Exécutez la requête SQL suivante dans votre base de données `gitlab_main` :

      ```sql
      UPDATE work_item_types set id = (id * 10);
      ```

  1. Relancez la migration ayant échoué. Elle devrait maintenant réussir.

- Tags de runner manquants lors de la mise à niveau vers GitLab 17.8, voir le [ticket 524402](https://gitlab.com/gitlab-org/gitlab/-/issues/524402).

  La mise à niveau préalable vers GitLab 17.6 permet d'éviter ce problème. Le bug est corrigé dans GitLab 17.11.

  **Versions affectées** :

  | Versions mineures affectées | Versions correctives affectées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 17.8                    |  17.8.0 - 17.8.6        | 17.8.7   |
  | 17.9                    |  17.9.0 - 17.9.4        | 17.9.5   |
  | 17.10                   |  17.10.0 - 17.10.4      | 17.10.5  |

  Lors de la mise à niveau depuis la version 17.5 vers une version antérieure aux versions correctives mentionnées dans le tableau, il existe un risque que la table des tags de runner devienne vide.

  Exécutez la requête PostgreSQL suivante sur la base de données `ci` pour vérifier la table des tags de runner et déterminer si vous êtes concerné :

  ```sql
  SELECT 'OK, ci_runner_taggings is populated.' FROM ci_runner_taggings LIMIT 1;
  ```

  Si la requête renvoie un résultat vide au lieu de `OK, ci_runner_taggings is populated.`, consultez la [solution de contournement](https://gitlab.com/gitlab-org/gitlab/-/issues/524402#workaround) dans le ticket associé.

### Nouveaux secrets de chiffrement {#new-encryption-secrets-3}

Dans GitLab 17.8, trois nouveaux secrets ont été ajoutés pour prendre en charge le nouveau framework de chiffrement (dont l'utilisation a débuté en version 17.9) :

- `active_record_encryption_primary_key`
- `active_record_encryption_deterministic_key`
- `active_record_encryption_key_derivation_salt`

Si vous disposez d'une configuration multi-nœuds, vous devez [vous assurer que ces secrets sont identiques sur tous les nœuds](#unify-new-encryption-secrets).

### Modification du serveur d'agents GitLab pour Kubernetes {#change-to-the-gitlab-agent-server-for-kubernetes}

Dans GitLab 17.8.0, le serveur d'agents GitLab pour Kubernetes (KAS) ne démarre pas avec les paramètres par défaut sur le package GitLab Linux (Omnibus) et les installations Docker.

Pour résoudre ce problème, modifiez `/etc/gitlab/gitlab.rb` :

```ruby
gitlab_kas['env'] = { 'OWN_PRIVATE_API_URL' => 'grpc://127.0.0.1:8155' }
```

Les installations multi-nœuds doivent utiliser les paramètres décrits dans la [documentation](../../administration/clusters/kas.md).

### Modification des transferts vers le stockage d'objets S3 dans Workhorse {#change-to-s3-object-storage-uploads-in-workhorse}

Les transferts vers le stockage d'objets S3 dans Workhorse utilisent désormais exclusivement [AWS SDK v2 for Go](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/164597). Le feature flag `workhorse_use_aws_sdk_v2` a été supprimé. Le SDK AWS v2 [définit `Accept-Encoding: identity` et l'inclut en tant qu'en-tête signé](https://github.com/aws/aws-sdk-go-v2/issues/2848). Cependant, certains services proxy, comme Cloudflare, [modifient cet en-tête, ce qui provoque une erreur de non-correspondance de signature](https://gitlab.com/gitlab-org/gitlab/-/issues/492973#note_2312726631). Si vous constatez des [erreurs SignatureDoesNotMatch](https://repost.aws/knowledge-center/s3-presigned-url-signature-mismatch), assurez-vous que votre serveur proxy ne modifie pas ou ne supprime pas les en-têtes HTTP signés.

### Mise à niveau de la version 17.5 vers la version 17.8 {#175-to-178-upgrade}

- Lors de la mise à niveau depuis GitLab 17.5 vers la version 17.8, la migration en arrière-plan échoue lors d'une insertion ou d'une mise à jour dans la table `group_type_ci_runner_machines`.

  Dans l'interface utilisateur, le chemin de migration `BackfillCiRunnerMachinesPartitionedTable: ci_runner_machines` affiche la progression `0.00%` et le statut `failed`. L'erreur correspondante dans les journaux inclut une erreur de contrainte de clé étrangère.

  ```shell
  ERROR:  insert or update on table "group_type_ci_runner_machines_" violates foreign key constraint "fk_rails_"
  ```

  Pour résoudre cette erreur, initialisez la migration depuis l'interface utilisateur.

## Mises à niveau vers la version 17.7.0 {#upgrades-to-1770}

- Git 2.47.0 ou une version ultérieure est requis par Gitaly. Pour les installations compilées depuis les sources, vous devez utiliser la [version de Git fournie par Gitaly](../../install/self_compiled/_index.md#git).
- Les packages FIPS Linux utilisent désormais le Libgcrypt du système, à l'exception des packages FIPS Linux pour AmazonLinux 2. Les versions précédentes des packages FIPS Linux utilisaient le même Libgcrypt que les packages Linux standard, ce qui constituait un bug. Pour plus d'informations, consultez la documentation de développement GitLab sur FIPS.
- Les packages Linux `gitlab-runner` ont extrait `gitlab-runner-helper-images` en tant que nouvelle dépendance requise. Si vous installez manuellement les packages `gitlab-runner` pour les mises à niveau, veillez également à [télécharger les images helper manuellement](https://docs.gitlab.com/runner/install/linux-manually/#download).

### Mise à niveau vers OpenSSL 3 {#openssl-3-upgrade}

> [!note]
> Avant de procéder à la mise à niveau vers GitLab 17.7, utilisez le [guide OpenSSL 3](https://docs.gitlab.com/omnibus/settings/ssl/openssl_3/) pour identifier et évaluer la compatibilité de vos intégrations externes.

- Le package Linux met à niveau OpenSSL de la version v1.1.1w vers la version v3.0.0.
- Cloud Native GitLab (CNG) a déjà effectué la mise à niveau vers OpenSSL 3 dans GitLab 16.7.0. Si vous utilisez Cloud Native GitLab, aucune action n'est nécessaire. Cependant, les installations [Cloud Native Hybrid](../../administration/reference_architectures/_index.md#infrastructure-and-services) utilisent les packages Linux pour les composants avec état, comme Gitaly. Pour ces composants, vous devrez vérifier les versions TLS, les chiffrements et les certificats utilisés afin de vous assurer de leur compatibilité avec les modifications du niveau de sécurité décrites dans la discussion suivante.

Avec la mise à niveau vers OpenSSL 3 :

- GitLab requiert TLS 1.2 ou une version supérieure pour toutes les connexions TLS entrantes et sortantes.
- Les certificats TLS/SSL doivent présenter au moins 112 bits de sécurité. Les clés RSA, DSA et DH de moins de 2048 bits, ainsi que les clés ECC de moins de 224 bits sont interdites.

Les services plus anciens, tels que les serveurs LDAP et Webhook, peuvent encore utiliser TLS 1.1. Cependant, TLS 1.0 et 1.1 ont atteint leur fin de vie et ne sont plus considérés comme sécurisés. GitLab ne parviendra pas à se connecter aux services utilisant TLS 1.0 ou 1.1 et affichera un message d'erreur `no protocols available`.

De plus, OpenSSL 3 a rehaussé le [niveau de sécurité par défaut du niveau 1 au niveau 2](https://docs.openssl.org/3.0/man3/SSL_CTX_set_security_level/#default-callback-behaviour), portant le nombre minimal de bits de sécurité de 80 à 112. Par conséquent, les certificats signés avec des clés RSA et DSA de moins de 2048 bits et des clés ECC de moins de 224 bits sont interdits.

GitLab ne parviendra pas à se connecter à un service utilisant un certificat signé avec un nombre de bits insuffisant et affichera un message d'erreur `certificate key too weak`. Pour plus d'informations, consultez les [exigences relatives aux certificats](../../security/tls_support.md#certificate-requirements).

Tous les composants livrés avec le package Linux sont compatibles avec OpenSSL 3. Par conséquent, vous devez uniquement vérifier les services et intégrations qui ne font pas partie du package GitLab et sont considérés comme [« externes »](https://docs.gitlab.com/omnibus/settings/ssl/openssl_3/#identifying-external-integrations).

Les clés SSH ne sont pas affectées par cette mise à niveau. OpenSSL définit les exigences de sécurité pour TLS, et non pour SSH. [OpenSSH](https://www.openssh.org/) et [`gitlab-sshd`](../../administration/operations/gitlab_sshd.md) disposent de leurs propres paramètres de configuration pour les algorithmes cryptographiques autorisés.

Consultez la [documentation GitLab sur la sécurisation de votre installation](../../security/_index.md) pour plus de détails.

## Mises à niveau vers la version 17.5.0 {#upgrades-to-1750}

> [!note]
> La mise à niveau vers OpenSSL 3 a été reportée à GitLab 17.7.0.

- L'accès au stockage d'objets S3 pour le cache distribué GitLab Runner est désormais géré par le [SDK AWS v2 for Go](https://gitlab.com/gitlab-org/gitlab-runner/-/merge_requests/4987) au lieu du client MinIO. Vous pouvez réactiver le client MinIO en définissant le feature flag `FF_USE_LEGACY_S3_CACHE_ADAPTER` de [GitLab Runner](https://docs.gitlab.com/runner/configuration/feature-flags/) sur `true`.
- Le jeton utilisé par Gitaly pour s'authentifier auprès de GitLab dispose désormais de [son propre paramètre](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8688). Cela signifie que Gitaly n'a plus besoin des recettes GitLab Rails et Shell pour s'exécuter et renseigner le fichier secret par défaut dans le répertoire shell, et peut disposer de son propre fichier secret. Certains environnements personnalisés peuvent nécessiter de [mettre à jour leur configuration d'authentification](../../administration/gitaly/configure_gitaly.md#configure-authentication) pour éviter les incohérences de secrets.

## Mises à niveau vers la version 17.4.0 {#upgrades-to-1740}

- À partir de GitLab 17.4, les nouvelles installations GitLab ont un schéma de base de données différent concernant les colonnes d'ID.
  - Toutes les colonnes d'ID entières précédentes (32 bits) (par exemple les colonnes `id`, `%_id`, `%_ids`) sont désormais créées en tant que `bigint` (64 bits).
  - Les installations existantes migreront de 32 bits vers 64 bits en termes d'entiers dans les versions ultérieures, lorsque des migrations de base de données seront publiées pour effectuer ce changement.
  - Si vous créez un nouvel environnement GitLab pour tester les mises à niveau, installez GitLab 17.3 ou une version antérieure pour obtenir les mêmes types d'entiers que vos environnements existants. Vous pouvez ensuite effectuer une mise à niveau vers des versions ultérieures pour exécuter les mêmes migrations de base de données que vos environnements existants. Cela n'est pas nécessaire si vous effectuez une restauration depuis une sauvegarde vers le nouvel environnement, car la restauration de la base de données supprime la définition du schéma de base de données existant et utilise la définition stockée dans la sauvegarde.
- Git 2.46.0 ou une version ultérieure est requis par Gitaly. Pour les installations compilées depuis les sources, vous devez utiliser la [version de Git fournie par Gitaly](../../install/self_compiled/_index.md#git).
- Les transferts vers le stockage d'objets S3 dans Workhorse sont désormais gérés par défaut via le [SDK AWS v2 for Go](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/164597). Si vous rencontrez des problèmes avec les transferts vers le stockage d'objets S3, vous pouvez rétrograder vers la version v1 en désactivant le [feature flag](../../administration/feature_flags/_index.md#enable-or-disable-the-feature) `workhorse_use_aws_sdk_v2`.
- Lors de la mise à niveau vers GitLab 17.4, une application OAuth est générée pour le Web IDE. Si la configuration de l'URL externe de votre serveur GitLab dans le fichier `GitLab.rb` contient des lettres majuscules, le Web IDE peut ne pas se charger. Pour résoudre ce problème, consultez [Mettre à jour l'URL de rappel OAuth](../../user/project/web_ide/_index.md#update-the-oauth-callback-url).
- Conformément à la [RFC 7540](https://datatracker.ietf.org/doc/html/rfc7540#section-3.3), Gitaly et Praefect rejettent les connexions TLS ne prenant pas en charge ALPN. Si vous utilisez un équilibreur de charge devant Praefect avec TLS activé, vous pouvez rencontrer des erreurs `FAIL: 14:connections to all backends failing` si ALPN n'est pas utilisé. Vous pouvez désactiver cette application en définissant `GRPC_ENFORCE_ALPN_ENABLED=false` dans l'environnement Praefect. Avec le package Linux, modifiez `/etc/gitlab/gitlab.rb` :

  ```ruby
  praefect['env'] = { 'GRPC_ENFORCE_ALPN_ENABLED' => 'false' }
  ```

  Exécutez ensuite `gitlab-ctl reconfigure`.

  L'application de l'ALPN a de nouveau été désactivée dans [GitLab 17.5.5 et d'autres versions](../../administration/gitaly/praefect/configure.md#alpn-enforcement). La mise à niveau vers l'une de ces versions supprime la nécessité de définir `GRPC_ENFORCE_ALPN_ENABLED`.

## Mises à niveau vers la version 17.3.0 {#upgrades-to-1730}

- Git 2.45.0 ou une version ultérieure est requis par Gitaly. Pour les installations compilées depuis les sources, vous devez utiliser la [version de Git fournie par Gitaly](../../install/self_compiled/_index.md#git).

### Installations Geo 17.3.0 {#geo-installations-1730}

- Les pages de détails de réplication Geo pour un site secondaire semblent vides même si la réplication Geo fonctionne, voir le [ticket 468509](https://gitlab.com/gitlab-org/gitlab/-/issues/468509). Il n'existe pas de solution de contournement connue. Le bug est corrigé dans GitLab 17.4.

  **Versions affectées** :

  | Versions mineures affectées | Versions correctives affectées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  16.11.5 - 16.11.10     | Aucune     |
  | 17.0                    |  Tous                    | 17.0.7   |
  | 17.1                    |  Tous                    | 17.1.7   |
  | 17.2                    |  Tous                    | 17.2.5   |
  | 17.3                    |  Tous                    | 17.3.1   |

## Mises à niveau vers la version 17.2.1 {#upgrades-to-1721}

- Les mises à niveau vers GitLab 17.2.1 peuvent échouer en raison de [séquences inconnues dans la base de données](https://gitlab.com/gitlab-org/gitlab/-/issues/474293). Ce problème a été corrigé dans GitLab 17.2.2.
- Les mises à niveau vers [GitLab 17.2.1 peuvent échouer avec l'erreur](https://gitlab.com/gitlab-org/gitlab/-/issues/473337) :

  ```plaintext
  PG::DependentObjectsStillExist: ERROR: cannot drop desired object(s) because other objects depend on them
  ```

  Comme [décrit dans ce ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/474525#note_2045274993), ce problème de propriété de séquence de base de données a été corrigé dans GitLab 17.2.1. Cependant, vous pourriez rencontrer ce problème si les migrations dans la version 17.2.0 ne se sont pas terminées, mais que le package Linux empêche la mise à niveau vers la version 17.2.1 ou ultérieure en raison d'un fichier JSON malformé. Par exemple, cette erreur peut s'afficher :

  ```plaintext
  Malformed configuration JSON file found at /opt/gitlab/embedded/nodes/gitlab.example.com.json.
  This usually happens when your last run of `gitlab-ctl reconfigure` didn't complete successfully.
  This file is used to check if any of the unsupported configurations are enabled,
  and hence require a working reconfigure before upgrading.
  Please run `sudo gitlab-ctl reconfigure` to fix it and try again.
  ```

  La solution de contournement actuelle consiste à :

  1. Supprimer les fichiers JSON dans `/opt/gitlab/embedded/nodes` :

     ```shell
     rm /opt/gitlab/embedded/nodes/*.json
     ```

  1. Effectuer la mise à niveau vers GitLab 17.2.1 ou une version ultérieure.

### Installations Geo 17.2.1 {#geo-installations-1721}

- Dans GitLab 16.11 à GitLab 17.2, un index PostgreSQL manquant peut entraîner une utilisation élevée du CPU, une progression lente de la vérification des artefacts de job, et des mises à jour lentes ou expirées du statut des métriques Geo. L'index a été ajouté dans GitLab 17.3. Pour ajouter manuellement l'index, consultez [Dépannage Geo - Utilisation élevée du CPU sur le serveur primaire lors de la vérification des artefacts de job](../../administration/geo/replication/troubleshooting/common.md#high-cpu-usage-on-primary-during-object-verification).

  **Versions affectées** :

  | Versions mineures affectées | Versions correctives affectées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  Tous                    | Aucune     |
  | 17.0                    |  Tous                    | 17.0.7   |
  | 17.1                    |  Tous                    | 17.1.7   |
  | 17.2                    |  Tous                    | 17.2.5   |

- Les pages de détails de réplication Geo pour un site secondaire semblent vides même si la réplication Geo fonctionne, voir le [ticket 468509](https://gitlab.com/gitlab-org/gitlab/-/issues/468509). Il n'existe pas de solution de contournement connue. Le bug est corrigé dans GitLab 17.4.

  **Versions affectées** :

  | Versions mineures affectées | Versions correctives affectées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  16.11.5 - 16.11.10     | Aucune     |
  | 17.0                    |  Tous                    | 17.0.7   |
  | 17.1                    |  Tous                    | 17.1.7   |
  | 17.2                    |  Tous                    | 17.2.5   |
  | 17.3                    |  Tous                    | 17.3.1   |

## Mises à niveau vers la version 17.1.0 {#upgrades-to-1710}

- Les identités Bitbucket avec un `extern_uid` non approuvé sont supprimées. Pour plus d'informations, consultez le [ticket 452426](https://gitlab.com/gitlab-org/gitlab/-/issues/452426).
- Le modèle de [journal des modifications](../../user/project/changelogs.md) par défaut génère des liens sous forme d'URL complètes au lieu de références spécifiques à GitLab. Pour plus d'informations, consultez la [merge request 155806](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/155806).
- Git 2.44.0 ou une version ultérieure est requis par Gitaly. Pour les installations compilées depuis les sources, vous devez utiliser la [version de Git fournie par Gitaly](../../install/self_compiled/_index.md#git).
- La mise à niveau vers GitLab 17.1.0 ou 17.1.1, ou la présence de migrations en arrière-plan non terminées depuis GitLab 17.0, peut entraîner un échec lors de l'exécution des migrations. Cela est dû à un bug. Le [ticket 468875](https://gitlab.com/gitlab-org/gitlab/-/issues/468875) a été corrigé avec GitLab 17.1.2.

### Modification des données des messages de pipeline à exécution longue {#long-running-pipeline-messages-data-change}

GitLab 17.1 est une étape obligatoire pour les grandes instances GitLab avec un grand nombre d'enregistrements dans la table `ci_pipeline_messages`.

Une modification des données peut prendre de nombreuses heures sur les instances GitLab de grande taille, à un rythme de 1,5 à 2 millions d'enregistrements traités par heure. Si votre instance est concernée :

1. Effectuez la mise à niveau vers la version 17.1.
1. [Assurez-vous que toutes les migrations par lots ont été effectuées avec succès](../background_migrations.md#check-for-pending-database-background-migrations).
1. Effectuez la mise à niveau vers la version 17.2 ou 17.3.

Pour vérifier si vous êtes concerné :

1. Démarrez une [console de base de données](../../administration/troubleshooting/postgresql.md#start-a-database-console)
1. Exécutez :

   ```sql
   SELECT relname as table,n_live_tup as rows FROM pg_stat_user_tables
   WHERE relname='ci_pipeline_messages' and n_live_tup>1500000;
   ```

1. Si la requête renvoie un résultat avec un nombre de lignes pour `ci_pipeline_messages`, votre instance atteint le seuil requis pour cette étape obligatoire. Les instances affichant `0 rows` peuvent ignorer l'étape de mise à niveau vers la version 17.1.

GitLab 17.1 a introduit une [migration en arrière-plan par lots](../background_migrations.md#check-for-pending-database-background-migrations) qui garantit que chaque enregistrement de la table `ci_pipeline_messages` possède la [clé de partitionnement correcte](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/153391). Le partitionnement des tables CI est censé améliorer les performances pour les instances contenant de grandes quantités de données CI.

La mise à niveau vers GitLab 17.2 exécute une migration `Finalize` qui garantit que la migration en arrière-plan de la version 17.1 est terminée, en exécutant la modification de la version 17.1 de manière synchrone pendant la mise à niveau si nécessaire.

GitLab 17.2 [ajoute également des contraintes de clé étrangère à la base de données](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/158065) qui nécessitent que la clé de partitionnement soit renseignée. Les contraintes [sont validées](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/159571) dans le cadre de la mise à niveau vers GitLab 17.3.

Si la version 17.1 est omise du chemin de mise à niveau (ou si la migration de la version 17.1 n'est pas terminée) :

- Les instances concernées subiront des temps d'arrêt prolongés pendant la mise à niveau.
- La correction progressive est sans danger.
- Pour rendre l'environnement disponible plus tôt, une tâche Rake peut être utilisée pour exécuter la migration :

  ```shell
  sudo gitlab-rake gitlab:background_migrations:finalize[BackfillPartitionIdCiPipelineMessage,ci_pipeline_messages,id,'[]']
  ```

Tant que toutes les migrations de base de données ne sont pas terminées, GitLab sera probablement inutilisable, générant des erreurs `500`, causées par une incompatibilité entre le schéma de base de données partiellement mis à niveau et les processus Sidekiq et Puma en cours d'exécution.

La mise à niveau du package Linux (Omnibus) ou Docker risque d'échouer après un délai d'attente d'une heure :

```plaintext
FATAL: Mixlib::ShellOut::CommandTimeout: rails_migration[gitlab-rails]
[..]
Mixlib::ShellOut::CommandTimeout: Command timed out after 3600s:
```

Pour résoudre ce problème :

1. Exécutez la tâche Rake précédente pour terminer la migration par lots.
1. [Terminez le reste de l'opération ayant expiré](../package/package_troubleshooting.md#error-command-timed-out-after-3600s). À la fin de ce processus, Sidekiq et Puma sont redémarrés pour corriger les erreurs `500`.

Des retours sur cette étape conditionnelle dans le chemin de mise à niveau peuvent être fournis [dans le ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/503891).

### Installations Geo 17.1.0 {#geo-installations-1710}

- Dans GitLab 16.11 à GitLab 17.2, un index PostgreSQL manquant peut entraîner une utilisation élevée du CPU, une progression lente de la vérification des artefacts de job, et des mises à jour lentes ou expirées du statut des métriques Geo. L'index a été ajouté dans GitLab 17.3. Pour ajouter manuellement l'index, consultez [Dépannage Geo - Utilisation élevée du CPU sur le serveur primaire lors de la vérification des artefacts de job](../../administration/geo/replication/troubleshooting/common.md#high-cpu-usage-on-primary-during-object-verification).

  **Versions affectées** :

  | Versions mineures affectées | Versions correctives affectées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  Tous                    | Aucune     |
  | 17.0                    |  Tous                    | 17.0.7   |
  | 17.1                    |  Tous                    | 17.1.7   |
  | 17.2                    |  Tous                    | 17.2.5   |

- Les pages de détails de réplication Geo pour un site secondaire semblent vides même si la réplication Geo fonctionne, voir le [ticket 468509](https://gitlab.com/gitlab-org/gitlab/-/issues/468509). Il n'existe pas de solution de contournement connue. Le bug est corrigé dans GitLab 17.4.

  **Versions affectées** :

  | Versions mineures affectées | Versions correctives affectées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  16.11.5 - 16.11.10     | Aucune     |
  | 17.0                    |  Tous                    | 17.0.7   |
  | 17.1                    |  Tous                    | 17.1.7   |
  | 17.2                    |  Tous                    | 17.2.5   |
  | 17.3                    |  Tous                    | 17.3.1   |

## Mises à niveau vers la version 17.0.0 {#upgrades-to-1700}

### Installations Geo 17.0.0 {#geo-installations-1700}

- Dans GitLab 16.11 à GitLab 17.2, un index PostgreSQL manquant peut entraîner une utilisation élevée du CPU, une progression lente de la vérification des artefacts de job, et des mises à jour lentes ou expirées du statut des métriques Geo. L'index a été ajouté dans GitLab 17.3. Pour ajouter manuellement l'index, consultez [Dépannage Geo - Utilisation élevée du CPU sur le serveur primaire lors de la vérification des artefacts de job](../../administration/geo/replication/troubleshooting/common.md#high-cpu-usage-on-primary-during-object-verification).

  **Versions affectées** :

  | Versions mineures affectées | Versions correctives affectées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  Tous                    | Aucune     |
  | 17.0                    |  Tous                    | 17.0.7   |
  | 17.1                    |  Tous                    | 17.1.7   |
  | 17.2                    |  Tous                    | 17.2.5   |

- Les pages de détails de réplication Geo pour un site secondaire semblent vides même si la réplication Geo fonctionne, voir le [ticket 468509](https://gitlab.com/gitlab-org/gitlab/-/issues/468509). Il n'existe pas de solution de contournement connue. Le bug est corrigé dans GitLab 17.4.

  **Versions affectées** :

  | Versions mineures affectées | Versions correctives affectées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  16.11.5 - 16.11.10     | Aucune     |
  | 17.0                    |  Tous                    | 17.0.7   |
  | 17.1                    |  Tous                    | 17.1.7   |
  | 17.2                    |  Tous                    | 17.2.5   |
  | 17.3                    |  Tous                    | 17.3.1   |

## Unifier les nouveaux secrets de chiffrement {#unify-new-encryption-secrets}

[GitLab 17.8 a introduit trois nouveaux secrets](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/175154) pour prendre en charge le nouveau framework de chiffrement, [introduit dans GitLab 17.9](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/179559) :

- `active_record_encryption_primary_key`
- `active_record_encryption_deterministic_key`
- `active_record_encryption_key_derivation_salt`

Si vous disposez d'une configuration multi-nœuds, vous devez vous assurer que ces secrets sont identiques sur tous les nœuds. Dans le cas contraire, l'application génère automatiquement les secrets manquants au démarrage.

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

1. Si possible, [activez le mode maintenance](../../administration/maintenance_mode/_index.md#enable-maintenance-mode).
1. (Uniquement pour GitLab >= 17.9) Supprimez tous les enregistrements `CloudConnector::Keys` :

   ```shell
   gitlab-rails runner 'CloudConnector::Keys.delete_all'
   ```

1. Sur tous les nœuds d'application Sidekiq et GitLab, collectez les informations sur les clés de chiffrement et leur utilisation.

   Sur GitLab >= 18.0.0, >= 17.11.2, >= 17.10.6, ou >= 17.9.8, exécutez :

   ```shell
   gitlab-rake gitlab:doctor:encryption_keys
   ```

   Pour les autres versions, vous pouvez procéder directement à la sélection d'un nœud de référence (« Cas 1 » dans la liste suivante), car nous supposons que vous n'avez pas encore de données chiffrées.

   En fonction de la sortie de la commande, déterminez quel processus suivre :

   - Cas 1 : si tous les rapports `Encryption keys usage for <model>` affichent `NONE` :
     - Sélectionnez n'importe quel nœud d'application Sidekiq ou GitLab comme nœud de référence.
     - Copiez `/etc/gitlab/gitlab-secrets.json` depuis ce nœud vers tous les autres nœuds.
   - Cas 2 : si toutes les clés signalées utilisent le même ID de clé :
     - Sélectionnez le nœud sur lequel la clé existe comme nœud de référence.
     - Copiez `/etc/gitlab/gitlab-secrets.json` depuis ce nœud vers tous les autres nœuds.

       Par exemple, si le nœud 1 fournit la sortie suivante :

       ```shell
       Gathering existing encryption keys:
       - active_record_encryption_primary_key: ID => `bb32`; truncated secret => `bEt...eBU`
       - active_record_encryption_deterministic_key: ID => `445f`; truncated secret => `MJo...yg5`

       [... snipped for brevity ...]

       Encryption keys usage for VirtualRegistries::Packages::Maven::Upstream: NONE
       Encryption keys usage for Ai::ActiveContext::Connection: NONE
       Encryption keys usage for CloudConnector::Keys: NONE
       Encryption keys usage for DependencyProxy::GroupSetting:
       - `bb32` => 8
       Encryption keys usage for Ci::PipelineScheduleInput:
       - `bb32` => 1
       ```

       Et que le nœud 2 fournit la sortie suivante (la mention `(UNKNOWN KEY!)` est acceptable tant qu'un seul ID de clé est utilisé. Par exemple, `bb32` ici) :

       ```shell
       Gathering existing encryption keys:
       - active_record_encryption_primary_key: ID => `83kf`; truncated secret => `pKq...ikC`
       - active_record_encryption_deterministic_key: ID => `b722`; truncated secret => `Lma...iJ7`

       [... snipped for brevity ...]

       Encryption keys usage for VirtualRegistries::Packages::Maven::Upstream: NONE
       Encryption keys usage for Ai::ActiveContext::Connection: NONE
       Encryption keys usage for CloudConnector::Keys: NONE
       Encryption keys usage for DependencyProxy::GroupSetting:
       - `bb32` (UNKNOWN KEY!) => 8
       Encryption keys usage for Ci::PipelineScheduleInput:
       - `bb32` (UNKNOWN KEY!) => 1
       ```

       Dans cet exemple, sélectionnez le nœud 1 comme nœud de référence, car il contient la clé `bb32` utilisée par les deux nœuds.
   - Cas 3 : si des ID de clé différents sont utilisés pour les mêmes données sur plusieurs nœuds (par exemple, si le nœud 1 affiche `-bb32 => 1` et que le nœud 2 affiche `-83kf => 1`) :
     - Cela nécessite de re-chiffrer toutes les données avec une seule clé de chiffrement.
     - Si vous êtes prêt à perdre certaines données, vous pouvez également supprimer des enregistrements afin que tous les enregistrements restants utilisent le même ID de clé.
     - Contactez le [support GitLab](https://support.gitlab.com/) pour obtenir de l'aide.

1. Après avoir décidé quel nœud est le nœud de référence, décidez quels secrets de ce nœud de référence doivent être copiés vers les autres nœuds.
1. Sur tous les nœuds Sidekiq et Rails, à l'exception du nœud de référence :

   1. Sauvegardez vos [fichiers de configuration](https://docs.gitlab.com/omnibus/settings/backups/#backup-and-restore-configuration-on-a-linux-package-installation) :

      ```shell
      sudo gitlab-ctl backup-etc
      ```

   1. Copiez `/etc/gitlab/gitlab-secrets.json` depuis le nœud de référence et remplacez le fichier du même nom sur le nœud actuel.
   1. Reconfigurez GitLab :

      ```shell
      sudo gitlab-ctl reconfigure
      ```

   1. Vérifiez à nouveau les clés de chiffrement et leur utilisation avec l'une des commandes suivantes, selon votre version :

      Sur GitLab >= 18.0.0, >= 17.11.2, >= 17.10.6, ou >= 17.9.8, exécutez :

      ```shell
      gitlab-rake gitlab:doctor:encryption_keys
      ```

      Pour les autres versions, vous pouvez ignorer cette vérification, car nous supposons que vous n'avez pas encore de données chiffrées.

      Toutes les utilisations de clés signalées correspondent au même ID de clé. Par exemple, sur le nœud 1 :

      ```shell
      Gathering existing encryption keys:
      - active_record_encryption_primary_key: ID => `bb32`; truncated secret => `bEt...eBU`
      - active_record_encryption_deterministic_key: ID => `445f`; truncated secret => `MJo...yg5`

      [... snipped for brevity ...]

      Encryption keys usage for VirtualRegistries::Packages::Maven::Upstream: NONE
      Encryption keys usage for Ai::ActiveContext::Connection: NONE
      Encryption keys usage for CloudConnector::Keys:
      - `bb32` => 1
      Encryption keys usage for DependencyProxy::GroupSetting:
      - `bb32` => 8
      Encryption keys usage for Ci::PipelineScheduleInput:
      - `bb32` => 1
      ```

      Et par exemple, sur le nœud 2 (vous ne devriez pas voir de mention `(UNKNOWN KEY!)` cette fois) :

      ```shell
      Gathering existing encryption keys:
      - active_record_encryption_primary_key: ID => `bb32`; truncated secret => `bEt...eBU`
      - active_record_encryption_deterministic_key: ID => `445f`; truncated secret => `MJo...yg5`

      [... snipped for brevity ...]

      Encryption keys usage for VirtualRegistries::Packages::Maven::Upstream: NONE
      Encryption keys usage for Ai::ActiveContext::Connection: NONE
      Encryption keys usage for CloudConnector::Keys:
      - `bb32` => 1
      Encryption keys usage for DependencyProxy::GroupSetting:
      - `bb32` => 8
      Encryption keys usage for Ci::PipelineScheduleInput:
      - `bb32` => 1
      ```

1. Créez une nouvelle clé Cloud Connector :

   Pour GitLab >= 17.10 :

   ```shell
   gitlab-rake cloud_connector:keys:create
   ```

   Pour GitLab 17.9 :

   ```shell
   gitlab-rails runner 'CloudConnector::Keys.create!(secret_key: OpenSSL::PKey::RSA.new(2048).to_pem)'
   ```

1. [Désactivez le mode maintenance](../../administration/maintenance_mode/_index.md#disable-maintenance-mode).

{{< /tab >}}

{{< tab title="Chart Helm (Kubernetes)" >}}

Si vous avez désactivé le [chart shared-secrets](https://docs.gitlab.com/charts/charts/shared-secrets/), vous devez [créer ces secrets manuellement](https://docs.gitlab.com/charts/releases/8_0/).

{{< /tab >}}

{{< /tabs >}}
