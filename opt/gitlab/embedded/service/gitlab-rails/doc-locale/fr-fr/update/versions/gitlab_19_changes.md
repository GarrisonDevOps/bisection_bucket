---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Notes de mise à niveau GitLab 19
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Cette page contient des informations de mise à niveau pour les versions mineures et les correctifs de GitLab 19. Assurez-vous de consulter ces instructions pour :

- Votre type d'installation.
- Toutes les versions comprises entre votre version actuelle et votre version cible.

Si vous prévoyez également de mettre à niveau GitLab Runner en même temps que GitLab, consultez le [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/main/CHANGELOG.md) de GitLab Runner pour prendre connaissance des modifications susceptibles d'affecter votre configuration.

Pour des informations complémentaires sur les installations avec chart Helm, consultez [les notes de mise à niveau du chart Helm 10.0](https://docs.gitlab.com/charts/releases/10_0/).

## Arrêts de mise à niveau obligatoires {#required-upgrade-stops}

Pour offrir un calendrier de mise à niveau prévisible aux administrateurs d'instance, des arrêts de mise à niveau obligatoires sont prévus aux versions suivantes :

- `19.2`
- `19.5`
- `19.8`
- `19.11`

## Référence des notes de mise à niveau {#upgrade-notes-reference}

Vous trouverez ci-dessous une liste de référence des notes de mise à niveau pour chaque version mineure de GitLab. Chaque élément de la liste renvoie à une section spécifique contenant plus d'informations.

Les éléments signalés par une méthode d'installation, comme `(Geo)` ou `(Linux package)`, s'appliquent uniquement à cette méthode. Tous les autres éléments s'appliquent à toutes les méthodes d'installation.

### Mise à niveau vers la version 19.5 {#upgrade-to-195}

Avant de mettre à niveau vers GitLab 19.5, consultez les informations suivantes :

- [19.5.0] - [L'adresse de l'agent pour Kubernetes utilise par défaut le protocole gRPC natif](#agent-for-kubernetes-address-defaults-to-native-grpc) (package Linux, chart Helm)
- [19.5.0] - [Migration des points de contrôle de la plateforme Duo Agent](#duo-agent-platform-checkpoint-migration)
- [19.5.0] - [Calcul de somme de contrôle des téléversements Geo par type de téléversement activé par défaut](#geo-upload-checksumming-by-upload-type-enabled-by-default) (Geo)

### Mise à niveau vers la version 19.4 {#upgrade-to-194}

Avant de mettre à niveau vers GitLab 19.4, consultez les informations suivantes :

- [19.4.0] - [Proxy SSH Geo activé par défaut](#geo-ssh-proxying-enabled-by-default)
- [19.4.0] - [Les restaurations utilisant `SKIP_REPOSITORIES_PATHS` conservent les dépôts existants](#restores-that-use-skip_repositories_paths-keep-existing-repositories)
- [19.4.0] - [Les identités SAML de groupe non approuvées sont restaurées comme approuvées](#untrusted-group-saml-identities-are-restored-to-trusted)

### Mise à niveau vers la version 19.3 {#upgrade-to-193}

Avant de mettre à niveau vers GitLab 19.3, consultez les informations suivantes :

- [19.3.0 - 19.3.1] - [Les nouveaux groupes requièrent le paramètre SHA pour les appels API de merge requests](#new-groups-require-sha-parameter-for-merge-requests-api-calls)
- [19.3.0] - [Limite de simultanéité de vérification Geo appliquée comme total global](#geo-verification-concurrency-limit-applied-as-a-global-total)

### Mise à niveau vers la version 19.2 {#upgrade-to-192}

Avant de mettre à niveau vers GitLab 19.2, consultez les informations suivantes :

- [19.2.0] - [Les URL de la passerelle d'IA self-hosted GitLab Duo sont effacées après la mise à niveau](#gitlab-duo-self-hosted-ai-gateway-urls-cleared-after-upgrade) (package Linux)
- [19.2.0 - 19.2.5] - [Les nouveaux groupes requièrent le paramètre SHA pour les appels API de merge requests](#new-groups-require-sha-parameter-for-merge-requests-api-calls)

### Mise à niveau vers la version 19.0 {#upgrade-to-190}

Avant de mettre à niveau vers GitLab 19.0, consultez les informations suivantes :

- [19.0.0 - 19.0.1] - [La base de données de métadonnées du registre de conteneurs activée par défaut en mode préférentiel](#container-registry-metadata-database-enabled-by-default-in-prefer-mode) (package Linux, auto-compilé)
- [19.0.0] - [Le pilote de stockage S3 du registre de conteneurs remplacé par s3_v2](#container-registry-s3-storage-driver-replaced-by-s3_v2) (package Linux, auto-compilé)
- [19.0.0 - 19.1.0] - [Répertoires orphelins `.agents` et `.claude` sur les installations RPM du package Linux](#orphaned-agents-and-claude-directories-on-linux-package-rpm-installs) (package Linux)
- [19.0.0] - [Exigence minimale PostgreSQL 17](#postgresql-17-minimum-requirement)
- [19.0.0] - [Les horodatages de la charge utile du webhook ont été remplacés par le format ISO 8601](#webhook-payload-timestamps-changed-to-iso-8601-format)
- [19.0.0] - [Prise en charge d'Ubuntu 20.04 par le package Linux abandonnée](#linux-package-support-for-ubuntu-2004-discontinued) (package Linux)
- [19.0.0] - [Prise en charge de Redis 6 supprimée](#redis-6-support-removed) (package Linux)
- [19.0.0] - [Mattermost supprimé du package Linux](#mattermost-removed-from-the-linux-package) (package Linux)
- [19.0.0] - [Prise en charge des distributions SUSE par le package Linux abandonnée](#linux-package-support-for-suse-distributions-discontinued) (package Linux)
- [19.0.0] - [Spamcheck supprimé du package Linux et du chart Helm GitLab](#spamcheck-removed-from-linux-package-and-gitlab-helm-chart) (package Linux, chart Helm)
- [19.0.0] - [NGINX Ingress remplacé par la Gateway API avec Envoy Gateway](#nginx-ingress-replaced-by-gateway-api-with-envoy-gateway) (chart Helm)
- [19.0.0] - [PostgreSQL, Redis et MinIO intégrés supprimés du chart Helm GitLab](#bundled-postgresql-redis-and-minio-removed-from-gitlab-helm-chart) (chart Helm)
- [19.0.0 - 19.0.1] - [La synchronisation du dépôt de conteneurs Geo ignore silencieusement les tags d'index d'images OCI](#geo-container-repository-sync-silently-skips-oci-image-index-tags) (Geo)
- [16.0.0 - 19.0.1] - [Réplication de la gestion de conception Geo : `NoMethodError` lorsque le projet est `nil`](#geo-design-management-replication-nomethoderror-when-project-is-nil) (Geo)

## Notes de mise à niveau {#upgrade-notes}

Notes de mise à niveau spécifiques à GitLab 19.

### L'adresse de l'agent pour Kubernetes utilise par défaut le protocole gRPC natif {#agent-for-kubernetes-address-defaults-to-native-grpc}

- Affecte : package Linux, chart Helm
- Versions affectées : 19.5.0 et versions ultérieures

Dans GitLab 19.5, le package Linux et le chart Helm GitLab communiquent par défaut une adresse gRPC native à l'agent pour Kubernetes, au lieu d'une adresse WebSocket. L'adresse est affichée dans les instructions d'installation de l'agent et stockée dans `gitlab_kas.external_url`.

- Package Linux : `grpcs://gitlab.example.com` au lieu de `wss://gitlab.example.com/-/kubernetes-agent/`, lorsque `external_url` utilise HTTPS sans racine d'URL relative et que le NGINX intégré met fin au TLS avec HTTP/2.
- Chart Helm : `grpcs://kas.example.com` au lieu de `wss://kas.example.com`, avec la Gateway API ou avec le fournisseur NGINX Ingress.

Dans les autres configurations, l'adresse WebSocket est conservée. Les agents déjà connectés via WebSocket ne sont pas affectés, car GitLab Relay (KAS) prend en charge les deux protocoles sur le même port. Les agents installés après la mise à niveau se connectent via gRPC, ce qui nécessite HTTP/2 de bout en bout. Si un proxy situé entre vos clusters et GitLab ne transmet pas le protocole HTTP/2, les nouveaux agents ne parviennent pas à se connecter et l'erreur ressemble à un problème réseau. Par exemple, un WAF ou un proxy d'inspection TLS peut se connecter à GitLab via HTTP/1.1. Dans ce cas, continuez à communiquer l'adresse WebSocket en la définissant explicitement :

- Package Linux : `gitlab_rails['gitlab_kas_external_url']` dans `/etc/gitlab/gitlab.rb`.
- Chart Helm : `global.appConfig.gitlab_kas.externalUrl`.

Pour plus d'informations, consultez [GitLab Relay (KAS)](../../administration/clusters/kas.md) et la [documentation du chart KAS](https://docs.gitlab.com/charts/charts/gitlab/kas/#agent-connection-protocol).

### Migration des points de contrôle de la plateforme Duo Agent {#duo-agent-platform-checkpoint-migration}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 19.5.0

GitLab 19.5 met en file d'attente une migration en arrière-plan par lots nommée `BackfillDuoWorkflowsCheckpointHeadersAndBlobs`. Elle copie les points de contrôle de session de la plateforme GitLab Duo Agent depuis la table `p_duo_workflows_checkpoints` vers les tables `p_duo_workflows_checkpoint_headers` et `p_duo_workflows_checkpoint_blobs`. Il s'agit du format de stockage que l'application utilise désormais pour l'écriture et la lecture.

La migration s'exécute en arrière-plan après la mise à niveau. Elle traite uniquement les lignes qui ne sont pas encore stockées dans le nouveau format et ignore les sessions de plus de 30 jours dont les données dépassent la période de rétention.

Les sessions créées avant la mise à niveau restent lisibles pendant l'exécution de la migration. Une version ultérieure de GitLab supprime le code qui lit l'ancienne table. Cette migration doit donc se terminer avant cette mise à niveau. Avant de procéder à une mise à niveau au-delà de la version 19.5, vérifiez le statut de la migration sur la page **Espace d'administration** > **Migrations en arrière-plan** (`/admin/background_migrations`). Pour plus d'informations sur la vérification du statut et la finalisation manuelle de la migration, consultez [les migrations en arrière-plan](../background_migrations.md).

La durée de la migration dépend du nombre de sessions stockées par l'instance au cours des 30 derniers jours. Chaque point de contrôle traité peut représenter plusieurs mégaoctets.

### Calcul de somme de contrôle des téléversements Geo par type de téléversement activé par défaut {#geo-upload-checksumming-by-upload-type-enabled-by-default}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées : 19.5.0

Dans GitLab 19.5, Geo ajoute 23 nouveaux types de données pour les téléversements, un pour chaque type de téléversement, par exemple les téléversements de projet et les téléversements de groupe. Seul le site primaire utilise les nouveaux types de données et calcule les sommes de contrôle des téléversements pour chacun d'eux en arrière-plan. Les sites secondaires continuent de répliquer et de vérifier les téléversements via le type de données de téléversements existant.

Sur le site primaire, la plupart des téléversements réutilisent la somme de contrôle du type de données de téléversements existant, de sorte que GitLab ne lit que les fichiers ne disposant pas encore d'une somme de contrôle valide. Le calcul des sommes de contrôle partage la **Limitation de la simultanéité des vérifications** du site primaire avec tous les autres types de données. Sur les sites disposant de millions de téléversements, le calcul des sommes de contrôle peut prendre plusieurs jours avec une limite de `1`, valeur utilisée par de nombreux sites mis à niveau depuis des versions antérieures. Vous pouvez augmenter la limite pendant l'exécution du calcul des sommes de contrôle, surveiller la charge de la base de données, puis rétablir la valeur précédente. Lors des tests GitLab, le fait de passer la limite de `1` à `10` a rendu le calcul des sommes de contrôle environ huit fois plus rapide, avec une charge supplémentaire minimale sur la base de données. Pour plus d'informations, consultez [l'ajustement de Geo](../../administration/geo/replication/tuning.md#changing-the-syncverification-concurrency-values).

Pour arrêter le calcul des sommes de contrôle pour un type de données, vous devez [désactiver ses deux feature flags](../../administration/feature_flags/_index.md#how-to-enable-and-disable-features-behind-flags) : `geo_<name>_upload_replication` et `geo_<name>_upload_force_primary_checksumming`, où `<name>` est, par exemple, `project` ou `group`. La désactivation du seul flag `_replication` n'arrête pas le calcul des sommes de contrôle.

### Proxy SSH Geo activé par défaut {#geo-ssh-proxying-enabled-by-default}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : charts Helm
- Versions affectées : 19.4.0

Dans GitLab 19.4 et versions ultérieures, les feature flags suivants sont activés par défaut :

- `geo_proxy_fetch_ssh_to_primary`
- `geo_proxy_push_ssh_to_primary`

En raison de cette modification, les déploiements Cloud Native GitLab utilisant le NGINX Ingress intégré doivent soit :

- procéder à une mise à niveau pour utiliser la [Gateway API avec Envoy Gateway](#nginx-ingress-replaced-by-gateway-api-with-envoy-gateway) avant ce déploiement, ou
- désactiver les deux feature flags après le déploiement.

Dans le cas contraire, les récupérations et les poussées SSH via les sites secondaires Geo peuvent se bloquer ou expirer.

Consultez la [documentation de dépannage Geo](../../administration/geo/replication/troubleshooting/ssh_proxying.md) relative au proxying SSH pour plus d'informations.

### Les restaurations utilisant `SKIP_REPOSITORIES_PATHS` conservent les dépôts existants {#restores-that-use-skip_repositories_paths-keep-existing-repositories}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 19.4.0

Dans GitLab 19.4 et versions ultérieures, une restauration conserve les dépôts déjà présents sur l'instance lorsque `SKIP_REPOSITORIES_PATHS` exclut des dépôts de cette restauration. Cela s'applique aussi bien lorsque vous spécifiez l'option pour la restauration que lorsque la sauvegarde a été créée avec cette option, y compris les sauvegardes créées sur des versions antérieures, car la restauration lit également les chemins exclus depuis le manifeste de sauvegarde (`backup_information.yml`).

Auparavant, dans les deux cas et sauf si `REPOSITORIES_PATHS` était également spécifié, la restauration supprimait d'abord tous les dépôts dans les espaces de stockage restaurés. Les dépôts exclus étaient supprimés avec eux et, comme ils étaient également exclus de la restauration elle-même, cette sauvegarde ne pouvait pas les rétablir.

Une restauration complète, où ni `REPOSITORIES_PATHS` ni `SKIP_REPOSITORIES_PATHS` ne s'appliquent, supprime toujours les dépôts qui ne font pas partie de la sauvegarde.

Si votre processus de restauration repose sur le comportement précédent pour effacer les dépôts, effectuez une restauration complète ou supprimez ces dépôts avant la restauration.

Pour plus d'informations, consultez [restaurer des dépôts spécifiques](../../administration/backup_restore/restore_gitlab.md#restore-specific-repositories) et le [ticket 610910](https://gitlab.com/gitlab-org/gitlab/-/issues/610910).

### Les identités SAML de groupe non approuvées sont restaurées comme approuvées {#untrusted-group-saml-identities-are-restored-to-trusted}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 19.4.0

Dans GitLab 18.10, 18.11, 19.0, 19.1, 19.2 et 19.3, la mise à jour de `extern_uid` d'une identité SAML de groupe via l'[API des identités SAML](../../api/saml.md) marquait cette identité comme non approuvée, et l'utilisateur concerné ne pouvait plus se connecter via l'authentification unique SAML jusqu'à ce qu'il ait à nouveau lié son identité.

GitLab 19.4 annule ce comportement. Un propriétaire de groupe contrôle le fournisseur d'identité du groupe et peut donc déjà déclarer n'importe quel `NameID` via le fournisseur d'identité. Une migration post-déploiement remet `trusted_extern_uid` à `true` pour toutes les identités SAML de groupe, ce qui permet aux utilisateurs concernés de se connecter à nouveau via l'authentification unique SAML.

Pour plus d'informations, consultez le [ticket 608236](https://gitlab.com/gitlab-org/gitlab/-/issues/608236).

### Les URL de la passerelle d'IA self-hosted GitLab Duo sont effacées après la mise à niveau {#gitlab-duo-self-hosted-ai-gateway-urls-cleared-after-upgrade}

- Affecte : Paquet Linux
- Versions affectées : 19.2.0
- Versions corrigées : 19.2.1

Lors d'une mise à niveau directe vers GitLab 19.2.0, les paramètres du point d'arrivée du service GitLab Duo Self-Hosted peuvent être effacés. Les champs suivants sous **Espace d'administration** > **GitLab Duo** > **Configuration** > **Points d'arrivée du service** peuvent devenir vides après la mise à niveau :

- **URL de la passerelle d'IA locale**
- **URL locale du service GitLab Duo Agent Platform**

D'autres paramètres associés peuvent également revenir à leurs valeurs par défaut. Les fonctionnalités GitLab Duo Self-Hosted cessent de fonctionner jusqu'à ce que les URL soient saisies à nouveau manuellement.

Ce problème ne se produit pas lors d'une mise à niveau vers GitLab 19.2.1 ou une version ultérieure.

Si vous avez déjà effectué une mise à niveau vers la version 19.2.0 et êtes concerné, restaurez les URL du point d'arrivée de la passerelle d'IA correctes dans **Espace d'administration** > **GitLab Duo** > **Configuration** > **Points d'arrivée du service** et enregistrez les modifications. Pour plus d'informations, consultez le [ticket 606458](https://gitlab.com/gitlab-org/gitlab/-/work_items/606458).

### Les nouveaux groupes requièrent le paramètre SHA pour les appels API de merge requests {#new-groups-require-sha-parameter-for-merge-requests-api-calls}

- Affecte : toutes les méthodes d'installation
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif corrigé |
  | ------- | ----------------------- | ----------------- |
  | 19.2    | 19.2.0 - 19.2.5         | 19.2.6            |
  | 19.3    | 19.3.0 - 19.3.1         | 19.3.2            |

GitLab 19.2 introduit le paramètre `require_sha_for_merge` au niveau du groupe et de l'instance. Lorsqu'il est activé, le point d'arrivée de l'API [fusionner une merge request](../../api/merge_requests.md#merge-a-merge-request) rejette les appels qui n'incluent pas un paramètre de commit `sha` valide.

Les groupes créés après la mise à niveau vers GitLab 19.2 et 19.3 ont `require_sha_for_merge` activé par défaut, sauf si le paramètre est verrouillé par l'instance ou un groupe ancêtre utilisant `lock_require_sha_for_merge`. Si le paramètre est verrouillé, le nouveau groupe hérite à la place de la valeur verrouillée. Les groupes existants ne sont pas affectés.

Après la mise à niveau vers la version 19.2 ou 19.3, si vos automatisations ou clients API appellent le point d'arrivée de fusion sans paramètre `sha`, ces clients échoueront pour tous les nouveaux groupes, sauf si vous désactivez l'exigence et verrouillez le paramètre.

Pour désactiver cette exigence pour tous les nouveaux groupes, définissez `require_sha_for_merge` sur `false` et activez `lock_require_sha_for_merge` via l'[API des paramètres d'application](../../api/settings.md#available-settings).

Ce paramètre a été modifié pour être désactivé par défaut dans GitLab 19.2.6 et GitLab 19.3.2.

### La base de données de métadonnées du registre de conteneurs activée par défaut en mode préférentiel {#container-registry-metadata-database-enabled-by-default-in-prefer-mode}

- Affecte : package Linux, auto-compilé
- Versions affectées : 19.0.0, 19.0.1

Dans GitLab 19.0, la base de données de métadonnées du registre de conteneurs utilise par défaut le mode `prefer` pour les installations existantes qui n'ont pas `registry['database']['enabled']` explicitement défini dans `/etc/gitlab/gitlab.rb`. En mode préférentiel, le registre tente d'utiliser la base de données de métadonnées. Si les données du registre existantes n'ont pas été importées dans la base de données, le registre bascule vers les métadonnées du système de fichiers hérité au démarrage.

En raison d'un bug ([ticket 600955](https://gitlab.com/gitlab-org/gitlab/-/work_items/600955)), le routeur du registre était initialisé avant l'exécution de la détection de repli préférentiel. Cela a provoqué des paniques de déréférencement de pointeur nul sur toutes les routes `/gitlab/v1/`, entraînant des erreurs `HTTP 500` lorsque l'interface utilisateur du registre interroge la taille de stockage au niveau du groupe. Le protocole réel Docker push et pull (`/v2/`) n'est pas affecté par ce bug.

Le bug est corrigé dans GitLab 19.0.2, qui inclut le registre de conteneurs `v4.40.1-gitlab`.

Si vous exécutez la version 19.0.0 ou 19.0.1 et constatez des paniques répétées `runtime error: invalid memory address or nil pointer dereference` dans `/var/log/gitlab/registry/current` à `handlers.(*repositoryHandler).HandleGetRepository`, appliquez la solution de contournement suivante :

1. Ajoutez ce qui suit à `/etc/gitlab/gitlab.rb` :

   ```ruby
   registry['database'] = {
     'enabled' => false
   }
   ```

1. Reconfigurer et redémarrer le registre :

   ```shell
   sudo gitlab-ctl reconfigure
   sudo gitlab-ctl restart registry
   ```

Après la mise à niveau vers la version 19.0.2 ou ultérieure, supprimez la substitution et reconfigurez à nouveau pour restaurer le comportement par défaut.

Pour plus d'informations, consultez [la documentation sur la base de données de métadonnées du registre de conteneurs](../../administration/packages/container_registry_metadata_database.md).

### Le pilote de stockage S3 du registre de conteneurs remplacé par s3_v2 {#container-registry-s3-storage-driver-replaced-by-s3_v2}

- Affecte : package Linux, auto-compilé
- Versions affectées : 19.0.0

Dans GitLab 19.0, le pilote de stockage hérité `s3` du registre de conteneurs (AWS SDK v1) est supprimé. Les noms de pilotes `s3` et `s3aws` sont désormais des alias pour le pilote `s3_v2` (AWS SDK v2). Étant donné que les noms de pilotes précédents continuent de fonctionner, les instances qui n'ont jamais été reconfigurées passent également à AWS SDK v2 lors de leur mise à niveau.

Cette modification affecte deux groupes d'installations :

- Les installations qui utilisent des backends de stockage d'objets compatibles S3 tels que Ceph RGW, MinIO ou OVH S3.
- Les installations qui utilisent AWS S3 et restreignent le trafic réseau sortant. Pour plus d'informations, consultez [les noms d'hôte des URL présignées sur AWS S3](#presigned-url-hostnames-on-aws-s3).

Le pilote `s3_v2` introduit deux changements non rétrocompatibles pour les backends compatibles S3 non-AWS :

- `regionendpoint` nécessite une URI complète incluant le schéma. Le pilote `s3_v2` requiert `https://` (ou `http://`) dans la valeur `regionendpoint`. Un nom d'hôte simple tel que `storage.example.com` n'est plus valide et provoque une erreur au démarrage :

  ```plaintext
  endpoint rule error, Custom endpoint `storage.example.com` was not a valid URI
  ```

  Mettez à jour votre configuration pour inclure le schéma :

  ```ruby
  registry['storage'] = {
    's3_v2' => {
      'regionendpoint' => 'https://storage.example.com',
      # ...
    }
  }
  ```

- AWS SDK v2 envoie des sommes de contrôle améliorées par défaut. Le pilote `s3_v2` envoie des sommes de contrôle `x-amz-content-sha256` et CRC64NVME lors des téléversements. Ceph RGW, les versions plus anciennes de MinIO, OVH S3 et d'autres backends compatibles S3 peuvent les rejeter avec une erreur HTTP 400 (`XAmzContentSHA256Mismatch`). Ajoutez `'checksum_disabled' => true` pour désactiver ce comportement.

  Le paramètre `checksum_disabled` supprime uniquement les sommes de contrôle lors des appels de téléversement (`PutObject`). Le chemin de code `DeleteObjects` envoie également un en-tête de somme de contrôle CRC32 que certains backends compatibles S3 ne prennent pas en charge. Si votre backend rejette cet en-tête, les push d'images qui déclenchent des suppressions de blobs échouent avec une erreur `MissingContentMD5` ou `InvalidRequest`, même lorsque `checksum_disabled` est défini sur `true`.

  Pour résoudre ce problème, mettez à niveau votre backend de stockage compatible S3 vers une version qui prend en charge les en-têtes de somme de contrôle CRC32. Consultez la documentation de votre fournisseur de stockage pour connaître la version minimale requise.

  Il n'existe pas de solution de contournement dans la configuration `gitlab.rb` pour le chemin de code `DeleteObjects`. Pour plus d'informations, consultez le [ticket 2309](https://gitlab.com/gitlab-org/container-registry/-/issues/2309).

Pour Ceph RGW et la plupart des backends compatibles S3, mettez à jour votre configuration comme suit :

```ruby
registry['storage'] = {
  's3_v2' => {
    'accesskey' => '<your-access-key>',
    'secretkey' => '<your-secret-key>',
    'bucket' => '<your-bucket>',
    'region' => '<your-region>',
    'regionendpoint' => 'https://<your-s3-endpoint>',
    'pathstyle' => true,
    'checksum_disabled' => true
  }
}
```

Pour plus d'informations, consultez [la documentation sur le stockage d'objets du registre de conteneurs](../../administration/packages/container_registry.md#use-object-storage).

#### Noms d'hôte des URL présignées sur AWS S3 {#presigned-url-hostnames-on-aws-s3}

Lorsque le registre diffuse un blob, il redirige le client vers une URL S3 présignée. AWS SDK v2 résout le point d'arrivée S3 pour la région dans votre configuration de registre, de sorte que ces URL présignées peuvent utiliser un nom d'hôte régional tel que `s3.us-east-1.amazonaws.com` au lieu du nom d'hôte global `s3.amazonaws.com` que AWS SDK v1 pouvait retourner.

Le registre lui-même continue de fonctionner, mais les clients doivent pouvoir accéder au nouveau nom d'hôte. Dans les environnements qui filtrent le trafic sortant avec un proxy, un pare-feu ou une passerelle web sécurisée, une liste d'autorisation contenant uniquement `s3.amazonaws.com` bloque la cible de redirection. Les pulls d'images échouent alors avec des réponses `403 Forbidden` renvoyées par le dispositif de filtrage plutôt que par S3.

Avant de procéder à la mise à niveau, ajoutez le nom d'hôte régional correspondant à la région de votre bucket à la liste d'autorisation de tout dispositif filtrant le trafic sortant de vos clients d'images de conteneurs. Utilisez le nom d'hôte régional spécifique à votre région, tel que `s3.eu-west-2.amazonaws.com`, plutôt qu'un caractère générique couvrant l'ensemble d'Amazon S3.

Si votre instance utilise un point d'arrivée VPC S3 ou un autre point d'arrivée fixe, définissez `regionendpoint` sur ce point d'arrivée afin que les URL présignées utilisent un nom d'hôte que vous contrôlez. Pour plus d'informations, consultez [utiliser le stockage d'objets](../../administration/packages/container_registry.md#use-object-storage).

Pour valider les pulls de blobs après la mise à niveau :

1. Effectuez le pull d'une image de plus de quelques mégaoctets, afin que le pull soit traité via une redirection de blob plutôt que depuis un cache :

   ```shell
   docker pull gitlab.example.com:5050/mygroup/myproject/myimage:latest
   ```

1. Si le pull échoue, effectuez une requête directe d'un blob pour afficher la cible de redirection :

   ```shell
   curl --head "https://gitlab.example.com:5050/v2/mygroup/myproject/myimage/blobs/<digest>"
   ```

   Vérifiez dans l'en-tête de réponse `location` le nom d'hôte vers lequel le client est redirigé, puis confirmez que ce nom d'hôte est autorisé par vos contrôles de sortie.

### Réplication de la gestion de conception Geo : `NoMethodError` lorsque le projet est `nil` {#geo-design-management-replication-nomethoderror-when-project-is-nil}

- Affecte : Geo
- Versions affectées : 16.0.0 - 19.0.1

Sur les sites secondaires Geo, une erreur `NoMethodError` pouvait se produire lors de la réplication des dépôts de gestion de conception lorsque le projet associé avait été supprimé, laissant un enregistrement `DesignManagement::Repository` orphelin. GitLab 19.0.2 corrige ce problème.

Pour plus d'informations, consultez le [ticket 597049](https://gitlab.com/gitlab-org/gitlab/-/issues/597049).

### Exigence minimale de PostgreSQL 17 {#postgresql-17-minimum-requirement}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 19.0.0

La version minimale prise en charge de PostgreSQL est désormais la version 17. Avant d'installer GitLab 19.0 :

- Si vous utilisez le serveur PostgreSQL 16 intégré, [mettez à niveau le serveur PostgreSQL intégré](https://docs.gitlab.com/omnibus/settings/database.html#upgrade-packaged-postgresql-server).
- Si vous utilisez une instance [PostgreSQL externe](../../administration/postgresql/external.md), mettez-la à niveau vers PostgreSQL 17.

### Les horodatages de la charge utile du webhook ont été remplacés par le format ISO 8601 {#webhook-payload-timestamps-changed-to-iso-8601-format}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 19.0.0

Avant GitLab 19.0, les valeurs d'horodatage dans les charges utiles de webhook (par exemple `object_attributes.created_at`) utilisaient le format `YYYY-MM-DD HH:MM:SS` suivi d'un fuseau horaire. Par exemple, `2026-04-23 12:30:45 UTC`. Dans GitLab 19.0 et versions ultérieures, ces horodatages utilisent le format ISO 8601 avec une précision à la milliseconde et un indicateur de fuseau horaire. Par exemple, `2026-04-23T12:30:45.123Z`.

Cette modification s'applique à tous les horodatages des webhooks de projet, des webhooks de groupe et des modèles de webhook personnalisés, à une exception près. Les événements de pipeline conservent le format précédent pour les champs `created_at`, `started_at` et `finished_at` au sein de `builds[]` et `bridges[]`.

Si votre récepteur de webhook analyse ces champs d'horodatage, mettez-le à jour pour accepter le format ISO 8601 avec une précision à la milliseconde. Pour le format de chaque champ, consultez [les événements de webhook](../../user/project/integrations/webhook_events.md).

Cette modification a été introduite dans la [merge request 233400](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/233400). Elle est suivie dans le [ticket 622832](https://gitlab.com/gitlab-org/gitlab/-/work_items/622832).

### La synchronisation du dépôt de conteneurs Geo ignore silencieusement les tags d'index d'images OCI {#geo-container-repository-sync-silently-skips-oci-image-index-tags}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo (registre de conteneurs)
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif corrigé |
  | ------- | ----------------------- | ----------------- |
  | 19.0    | 19.0.0 - 19.0.1         | 19.0.2            |

Sur les sites secondaires Geo, la synchronisation du dépôt de conteneurs ignorait silencieusement les tags dont le manifeste est un index d'images OCI (`application/vnd.oci.image.index.v1+json`). Les images multi-architectures et les tags de cache BuildKit utilisent couramment ce type de manifeste. Aucune erreur n'était signalée et le nombre de tags correspondait, mais la commande `docker pull` d'un tag concerné depuis le site secondaire renvoyait `manifest unknown`. La même cause première laissait également des tags orphelins sur le site secondaire que la synchronisation ne pouvait pas supprimer.

Après la mise à niveau des sites primaire et secondaire vers une version corrigée, les tags nouvellement synchronisés sont corrects. Les dépôts précédemment affectés convergent lors de leur prochain cycle de vérification, ce qui peut prendre jusqu'à l'intervalle de re-vérification (90 jours par défaut). Pour réparer immédiatement les dépôts affectés, [resynchronisez les dépôts de conteneurs sur le site secondaire](../../administration/geo/replication/container_registry.md#manually-trigger-a-container-registry-sync-event).

Pour plus d'informations, consultez le [ticket 600486](https://gitlab.com/gitlab-org/gitlab/-/work_items/600486).

### Limite de simultanéité de vérification Geo appliquée comme total global {#geo-verification-concurrency-limit-applied-as-a-global-total}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées : 19.3.0

Le paramètre de site Geo **Limitation de la simultanéité des vérifications** est désormais appliqué comme une limite globale unique sur le nombre de jobs de vérification s'exécutant simultanément sur un site, pour tous les types de données combinés. Auparavant, la valeur configurée était divisée par le nombre de types de données avant d'être appliquée, de sorte que la simultanéité effective était plus faible et changeait à mesure que des types de données étaient ajoutés ou consolidés.

Pour préserver la simultanéité effective en usage et éviter un pic de charge de vérification, GitLab 19.3 redimensionne automatiquement la **Limitation de la simultanéité des vérifications** stockée de chaque site vers `max(1, floor(previous_value / number_of_data_types))`. Par conséquent, la valeur affichée dans l'interface d'administration et renvoyée par l'API diminue. Vérifiez et ajustez le paramètre après la mise à niveau. Si vous gérez ce paramètre via l'API ou l'Infrastructure as Code, mettez à jour votre valeur stockée en conséquence.

Pour plus d'informations, consultez le [ticket 596579](https://gitlab.com/gitlab-org/gitlab/-/work_items/596579).

### Prise en charge du paquet Linux pour Ubuntu 20.04 abandonnée {#linux-package-support-for-ubuntu-2004-discontinued}

- Affecte : Paquet Linux
- Versions affectées : 19.0.0

Ubuntu 20.04 a atteint la fin de la prise en charge standard en mai 2025. À partir de GitLab 19.0, les paquets Linux ne sont plus fournis pour Ubuntu 20.04. GitLab 18.11 est la dernière release avec des paquets pour cette distribution. Avant de mettre à niveau vers GitLab 19.0, migrez vers Ubuntu 22.04 ou un autre [système d'exploitation pris en charge](../../install/package/_index.md#supported-platforms).

### Prise en charge de Redis 6 supprimée {#redis-6-support-removed}

- Affecte : Paquet Linux
- Versions affectées : 19.0.0

La prise en charge de Redis 6 est supprimée dans GitLab 19.0. Si vous utilisez un déploiement Redis 6 externe, migrez vers Redis 7.0 ou une version supérieure, ou vers Valkey 7.2, avant de procéder à la mise à niveau. Redis 7.2 ou Valkey 7.2 est recommandé. Redis 7.0 a atteint sa fin de vie (EOL) en amont, mais est dans certains cas activement maintenu par des fournisseurs, comme Amazon ElastiCache pour Redis 7.1. Le Redis inclus dans le paquet Linux utilise Redis 7 depuis GitLab 16.2 et n'est pas affecté.

### Mattermost supprimé du paquet Linux {#mattermost-removed-from-the-linux-package}

- Affecte : Paquet Linux
- Versions affectées : 19.0.0

Mattermost inclus est supprimé du paquet Linux dans GitLab 19.0. Si vous utilisez actuellement le Mattermost intégré, consultez [Migrating from the Linux package to Mattermost Standalone](https://docs.mattermost.com/administration-guide/onboard/migrate-gitlab-omnibus.html) pour les instructions de migration. Si vous n'utilisez pas le Mattermost intégré, vous n'êtes pas concerné.

Avant de mettre à niveau vers GitLab 19.0, supprimez ou commentez tous les paramètres `mattermost[...]` dans `/etc/gitlab/gitlab.rb`. Si des clés `mattermost[...]` subsistent, `gitlab-ctl reconfigure` s'interrompt immédiatement après l'installation du package avec :

```plaintext
RuntimeError: Removed configurations found in gitlab.rb. Aborting reconfigure.
```

> [!warning]
> Le comportement lors d'une mise à niveau depuis certaines versions 18.11.x diffère :
>
> - 18.11.0 à 18.11.6 : la mise à niveau ne détecte pas la configuration Mattermost obsolète. La mise à niveau se poursuit donc sans avertissement, même si le nettoyage est incomplet. Ne vous fiez pas à `gitlab-ctl check-config --version 19.0.x` pour valider la suppression des clés Mattermost avant la mise à niveau ([ticket 9916](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/9916)).
> - 18.11.7 : la mise à niveau est bloquée, même lorsque toutes les clés `mattermost[...]` ont été supprimées de `gitlab.rb`. Le blocage est un faux positif causé par des secrets Mattermost obsolètes que GitLab a générés inconditionnellement dans le cache de nœuds. Pour débloquer la mise à niveau, utilisez l'une des options suivantes :
>   - Mettez à niveau vers la version 18.11.9 ou ultérieure avant de procéder à la mise à niveau vers la version 19.0.
>   - Appliquez la [solution de contournement manuelle](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/10001#workaround).

### Prise en charge du paquet Linux pour les distributions SUSE abandonnée {#linux-package-support-for-suse-distributions-discontinued}

- Affecte : Paquet Linux
- Versions affectées : 19.0.0

La prise en charge du paquet Linux pour les distributions SUSE prend fin dans GitLab 19.0, ce qui affecte openSUSE Leap 15.6, SUSE Linux Enterprise Server 12.5 et SUSE Linux Enterprise Server 15.6. GitLab 18.11 est la dernière version avec des paquets Linux pour ces distributions. Pour continuer à utiliser les distributions SUSE, migrez vers un [déploiement Docker de GitLab](../../install/docker/installation.md).

### Spamcheck supprimé du paquet Linux et du chart Helm GitLab {#spamcheck-removed-from-linux-package-and-gitlab-helm-chart}

- Affecte : package Linux, chart Helm
- Versions affectées : 19.0.0

[Spamcheck](../../administration/reporting/spamcheck.md) est supprimé du paquet Linux et du chart Helm GitLab dans GitLab 19.0. Les clients n'utilisant pas actuellement Spamcheck ne sont pas impactés. Si vous utilisez Spamcheck inclus, vous pouvez le déployer séparément en utilisant [Docker](https://gitlab.com/gitlab-org/gl-security/security-engineering/security-automation/spam/spamcheck). Aucune migration de données n'est requise.

### NGINX Ingress remplacé par Gateway API avec Envoy Gateway {#nginx-ingress-replaced-by-gateway-api-with-envoy-gateway}

- Affecte : Graphique Helm
- Versions affectées : 19.0.0

Gateway API avec Envoy Gateway devient la configuration réseau par défaut dans le chart Helm GitLab dans GitLab 19.0, remplaçant NGINX Ingress qui a atteint sa fin de vie en mars 2026. Si la migration vers Envoy Gateway n'est pas immédiatement réalisable, vous pouvez réactiver explicitement le NGINX Ingress intégré, qui restera disponible jusqu'à sa suppression prévue dans GitLab 20.0. Cette modification n'affecte pas le NGINX utilisé dans le paquet Linux, ni les instances de chart Helm utilisant un Ingress géré en externe ou un contrôleur Gateway API.

Pour les étapes de migration détaillées, consultez les [notes de mise à niveau du chart Helm 10.0](https://docs.gitlab.com/charts/releases/10_0/).

### PostgreSQL, Redis et MinIO inclus supprimés du chart Helm GitLab {#bundled-postgresql-redis-and-minio-removed-from-gitlab-helm-chart}

- Affecte : Graphique Helm
- Versions affectées : 19.0.0

Les charts Bitnami PostgreSQL, Bitnami Redis et MinIO inclus sont supprimés du chart Helm GitLab et de GitLab Operator dans GitLab 19.0 sans remplacement. Ces composants étaient destinés uniquement aux environnements de preuve de concept et de test et ne sont pas recommandés pour une utilisation en production. Si vous exécutez une instance avec l'un de ces services inclus, suivez le [guide de migration](https://docs.gitlab.com/charts/installation/migration/bundled_chart_migration/) pour configurer des services externes avant de mettre à niveau vers GitLab 19.0.

### Répertoires orphelins `.agents` et `.claude` sur les installations RPM du package Linux {#orphaned-agents-and-claude-directories-on-linux-package-rpm-installs}

- Affecte : package Linux (RPM)
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif corrigé |
  |:--------|:------------------------|:------------------|
  | 19.0    | 19.0.0 - 19.0.2         | 19.0.3            |
  | 19.1    | 19.1.0                  | 19.1.1            |

Les packages Linux du correctif affecté incluaient par erreur deux répertoires sous `/opt/gitlab/embedded/service/gitlab-rails/` :

- `.agents/`
- `.claude/`

Ces répertoires sont exclus de la charge utile du package à partir des niveaux de correctifs corrigés, et par défaut dans GitLab 19.2 et versions ultérieures. Pour plus d'informations, consultez le [ticket 603547](https://gitlab.com/gitlab-org/gitlab/-/issues/603547).

Sur les distributions basées sur RPM, RPM ne supprime pas un répertoire qu'il ne possède plus si ce répertoire contient encore des fichiers. Même après la mise à niveau d'une installation RPM du package Linux au-delà d'une version corrigée, ces répertoires peuvent rester sur le disque :

- `/opt/gitlab/embedded/service/gitlab-rails/.agents`
- `/opt/gitlab/embedded/service/gitlab-rails/.claude`

RPM ne supprime pas automatiquement ces répertoires orphelins. Recherchez ces répertoires et, s'ils sont présents, supprimez-les manuellement :

1. Vérifiez si les répertoires existent :

   ```shell
   ls -la /opt/gitlab/embedded/service/gitlab-rails/.agents \
          /opt/gitlab/embedded/service/gitlab-rails/.claude
   ```

1. Si les répertoires sont présents, supprimez-les :

   ```shell
   sudo rm -rf /opt/gitlab/embedded/service/gitlab-rails/.agents \
               /opt/gitlab/embedded/service/gitlab-rails/.claude
   ```

Les distributions basées sur DEB ne sont pas affectées car `dpkg` supprime les répertoires qu'il ne possède plus lors de la mise à niveau.
