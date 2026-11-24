---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Notes de mise à niveau GitLab 16
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Cette page contient des informations de mise à niveau pour les versions mineures et les versions de correctifs de GitLab 16. Assurez-vous de consulter ces instructions pour :

- Votre type d'installation.
- Toutes les versions comprises entre votre version actuelle et votre version cible.

Pour obtenir des informations supplémentaires sur les installations avec le chart Helm, consultez [les notes de mise à niveau du chart Helm](https://docs.gitlab.com/charts/releases/).

## Problèmes à prendre en compte lors de la mise à niveau depuis la version 15.11 {#issues-to-be-aware-of-when-upgrading-from-1511}

- [PostgreSQL 12 n'est pas pris en charge à partir de GitLab 16](../deprecations.md#postgresql-12-deprecated). Mettez à niveau PostgreSQL vers au moins la version 13.6 avant de passer à GitLab 16.0 ou une version ultérieure.
- Si votre instance GitLab a d'abord été mise à niveau vers les versions 15.11.0, 15.11.1 ou 15.11.2, le schéma de base de données est incorrect. Effectuez la [solution de contournement](#undefined-column-error-upgrading-to-162-or-later) avant de mettre à niveau vers la version 16.x.
- À partir de la version 16.0, les installations GitLab Self-Managed disposent désormais de deux connexions à la base de données par défaut, au lieu d'une seule. Ce changement double le nombre de connexions PostgreSQL. Cela permet aux instances GitLab Self-Managed de se comporter de manière similaire à GitLab.com et constitue une étape vers l'activation d'une base de données distincte pour les fonctionnalités CI sur GitLab Self-Managed. Avant de passer à la version 16.0, déterminez si vous devez [augmenter le nombre maximum de connexions pour PostgreSQL](https://docs.gitlab.com/omnibus/settings/database/#configuring-multiple-database-connections).
  - Ce changement s'applique aux méthodes d'installation avec les packages Linux (Omnibus), le chart Helm GitLab, GitLab Operator, les images Docker GitLab et les installations compilées à partir des sources.
  - [La deuxième connexion à la base de données peut être désactivée](#disable-the-second-database-connection).
- La plupart des installations peuvent ignorer les versions 16.0, 16.1 et 16.2, car le premier arrêt obligatoire sur le chemin de mise à niveau est la version 16.3. Dans tous les cas, vous devez consulter les notes relatives à ces versions intermédiaires.

  Certaines installations GitLab doivent s'arrêter à ces versions intermédiaires selon les fonctionnalités utilisées et la taille de l'environnement :

  - 16.0.8 : Instances avec un grand nombre d'enregistrements dans la table des utilisateurs. Pour plus d'informations, consultez la section [modification de données du type utilisateur de longue durée](#long-running-user-type-data-change).
  - [16.1.5](#1610) : Instances utilisant le registre de paquets NPM.
  - [16.2.8](#1620) : Instances avec un grand nombre de variables de pipeline (y compris les pipelines historiques).

  Si votre instance est concernée et que vous ignorez ces arrêts :

  - La mise à niveau peut prendre des heures.
  - L'instance génère des erreurs 500 jusqu'à ce que toutes les modifications de la base de données soient terminées, après quoi Puma et Sidekiq doivent être redémarrés.
  - Pour les installations avec le package Linux, un délai d'expiration se produit et une [solution de contournement manuelle pour terminer les migrations](../package/package_troubleshooting.md#error-command-timed-out-after-3600s) est nécessaire.
- GitLab 16.0 a introduit des changements concernant l'application de limites sur les tailles de projets. Sur GitLab Self-Managed, si vous utilisez ces limites, les projets ayant atteint leur limite génèrent des messages d'erreur lors d'un push vers des dépôts Git non affectés dans le même groupe. Les erreurs font souvent référence au dépassement d'une limite de zéro octet (`limit of 0 B`).

  Les pushs aboutissent, mais les erreurs laissent entendre le contraire et peuvent causer des problèmes avec l'automatisation. [En savoir plus dans le ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/416646). Le [bug est corrigé dans GitLab 16.5 et les versions ultérieures](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/131122).
- En général, les sauvegardes dans les environnements disposant de PgBouncer doivent [contourner PgBouncer en définissant des variables dont le préfixe est `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion régulière à la base de données via PgBouncer au lieu de la connexion directe définie dans le paramètre de remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations avec le paquet Linux {#linux-package-installations}

- La structure de configuration de Gitaly et Praefect doit être modifiée avant la mise à niveau vers GitLab 16. Pour éviter toute perte de données, reconfigurez d'abord Praefect et, dans le cadre de la nouvelle configuration, désactivez la vérification des métadonnées. En savoir plus :

  - [Modification de la structure de configuration de Praefect](#praefect-configuration-structure-change).
  - [Modification de la structure de configuration de Gitaly](#gitaly-configuration-structure-change).
- Si vous reconfigurez Gitaly pour stocker les données Git dans un emplacement autre que `/var/opt/gitlab/git-data/repositories`, GitLab 16.0 packagé et les versions ultérieures ne créent pas automatiquement la structure de répertoires. [Consultez le ticket pour plus de détails et la solution de contournement](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8320).

## 16.11.0 {#16110}

- Un [champ `groups_direct` a été ajouté](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/146881) au [jeton web JSON (jeton ID)](../../ci/secrets/id_token_authentication.md).
  - Si vous utilisez des jetons ID GitLab CI/CD pour vous authentifier auprès de services tiers, ce changement peut entraîner une augmentation de la taille de l'en-tête HTTP. Les serveurs proxy peuvent rejeter la requête si les en-têtes deviennent trop volumineux.
  - Si possible, augmentez la limite d'en-tête sur le système récepteur.
  - Consultez le [ticket 467253](https://gitlab.com/gitlab-org/gitlab/-/issues/467253) pour plus de détails.
- Après la mise à niveau vers GitLab 16.11, certains utilisateurs disposant d'environnements et de bases de données volumineux constatent des délais d'expiration lors du chargement des pages de code source dans l'interface web. Ces délais d'expiration sont causés par des requêtes PostgreSQL lentes pour les données de pipeline qui dépassent le délai d'expiration interne de 60 secondes.
  - Vous pouvez toujours cloner des dépôts Git, et les autres requêtes concernant les données du dépôt fonctionnent.
  - Consultez le [ticket 472420](https://gitlab.com/gitlab-org/gitlab/-/issues/472420) pour connaître les étapes permettant de confirmer que vous êtes concerné et les opérations de maintenance à effectuer dans PostgreSQL pour corriger votre base de données maintenant.
  - [Corrigé dans GitLab 17.4.0](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/162894), qui n'exécute plus la requête à l'origine de ces délais d'expiration.

### Installations avec le paquet Linux {#linux-package-installations-1}

Dans GitLab 16.11, PostgreSQL est automatiquement mis à niveau vers la version 14.x, sauf dans les cas suivants :

- Vous exécutez la base de données en haute disponibilité à l'aide de Patroni.
- Vos nœuds de base de données font partie d'une configuration GitLab Geo.
- Vous avez spécifiquement [refusé](https://docs.gitlab.com/omnibus/settings/database/#opt-out-of-automatic-postgresql-upgrades) la mise à niveau automatique de PostgreSQL.
- Vous avez `postgresql['version'] = 13` dans votre `/etc/gitlab/gitlab.rb`.

Les installations tolérantes aux pannes et Geo prennent en charge les mises à niveau manuelles vers PostgreSQL 14\. Consultez [PostgreSQL packagé déployé dans un cluster HA/Geo](https://docs.gitlab.com/omnibus/settings/database/#packaged-postgresql-deployed-in-an-hageo-cluster).

### Installations Geo {#geo-installations}

- En raison d'un bug introduit dans GitLab 16.5 et corrigé dans la version 17.0, les fichiers de déploiement de [GitLab Pages](../../administration/pages/_index.md) sont orphelins sur les sites Geo secondaires. Si les déploiements Pages sont stockés localement, cela peut entraîner un stockage restant nul et, par conséquent, une perte de données en cas de basculement. Consultez les détails du problème et la solution de contournement dans le [ticket 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

- Dans GitLab 16.11 jusqu'à GitLab 17.2, un index PostgreSQL manquant peut entraîner une utilisation élevée du processeur, une progression lente de la vérification des artefacts de job et des mises à jour lentes ou expirées des statuts des métriques Geo. L'index a été ajouté dans GitLab 17.3. Pour ajouter l'index manuellement, consultez [Dépannage Geo - Utilisation élevée du processeur sur le site principal lors de la vérification des artefacts de job](../../administration/geo/replication/troubleshooting/common.md#high-cpu-usage-on-primary-during-object-verification).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  Tous                    | Aucune     |
  | 17.0                    |  Tous                    | Aucune     |
  | 17.1                    |  Tous                    | Aucune     |
  | 17.2                    |  Tous                    | Aucune     |

- Les détails de réplication Geo pour les sites secondaires semblent vides même si la réplication Geo fonctionne. Consultez le [ticket 468509](https://gitlab.com/gitlab-org/gitlab/-/issues/468509). Aucune solution de contournement connue n'existe. Le bug est corrigé dans GitLab 17.4.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  16.11.5 - 16.11.10     | Aucune     |
  | 17.0                    |  Tous                    | 17.0.7   |
  | 17.1                    |  Tous                    | 17.1.7   |
  | 17.2                    |  Tous                    | 17.2.5   |
  | 17.3                    |  Tous                    | 17.3.1   |

## 16.10.0 {#16100}

Vous pourriez rencontrer l'erreur suivante lors de la mise à niveau vers GitLab 16.10 ou une version ultérieure :

```plaintext
PG::UndefinedColumn: ERROR:  column namespace_settings.delayed_project_removal does not exist
```

Cette erreur peut se produire lorsqu'une migration qui supprime la colonne s'exécute avant une migration ultérieure qui référence la colonne désormais supprimée. Un [correctif](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/148135) pour ce bug est prévu pour la release 16.11.

Pour contourner le problème :

1. Recréez temporairement la colonne. En utilisant `gitlab-psql` ou en vous connectant à la base de données manuellement, exécutez :

   ```sql
   ALTER TABLE namespace_settings ADD COLUMN delayed_project_removal BOOLEAN DEFAULT NULL;
   ```

1. Appliquez les migrations en attente :

   ```shell
   gitlab-ctl reconfigure
   ```

1. Finalisez les vérifications :

   ```shell
   gitlab-ctl upgrade-check
   ```

1. Supprimez la colonne. En utilisant `gitlab-psql` ou en vous connectant à la base de données manuellement, exécutez :

   ```sql
   ALTER TABLE namespace_settings DROP COLUMN delayed_project_removal;
   ```

### Installations avec le paquet Linux {#linux-package-installations-2}

Les installations avec le package Linux pour GitLab 16.10 comprennent une mise à niveau vers une nouvelle version majeure de Patroni, de la version 2.1.0 à la version 3.0.1.

Si vous utilisez l'une des [architectures de référence](../../administration/reference_architectures/_index.md) qui active la [haute disponibilité (HA)](../../administration/reference_architectures/_index.md#high-availability-ha) (3 000 utilisateurs ou plus), vous utilisez la [réplication et le basculement PostgreSQL pour les installations avec le package Linux](../../administration/postgresql/replication_and_failover.md), qui utilise Patroni.

Si c'est votre cas, consultez [Mises à niveau multi-nœuds avec temps d'arrêt](../with_downtime.md) pour savoir comment mettre à niveau votre instance multi-nœuds.

Pour plus d'informations sur les changements introduits entre la version 2.1.0 et la version 3.0.1, consultez les [notes de release de Patroni](https://patroni.readthedocs.io/en/latest/releases.html).

### Installations Geo {#geo-installations-1}

- En raison d'un bug introduit dans GitLab 16.5 et corrigé dans la version 17.0, les fichiers de déploiement de [GitLab Pages](../../administration/pages/_index.md) sont orphelins sur les sites Geo secondaires. Si les déploiements Pages sont stockés localement, cela peut entraîner un stockage restant nul et, par conséquent, une perte de données en cas de basculement. Consultez les détails du problème et la solution de contournement dans le [ticket 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

## 16.9.0 {#1690}

Vous pourriez rencontrer l'erreur suivante lors de la mise à niveau vers GitLab 16.9.0 :

```plaintext
PG::UndefinedTable: ERROR:  relation "p_ci_pipeline_variables" does not exist
```

Assurez-vous que toutes les migrations sont terminées et redémarrez tous les nœuds Rails et Sidekiq. Un [correctif](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/144952) pour ce bug est prévu pour la release 16.9.1.

### Installations Geo {#geo-installations-2}

- En raison d'un [bug dans la réplication des conteneurs](https://gitlab.com/gitlab-org/gitlab/-/issues/431944), un site secondaire mal configuré pourrait marquer une réplication de conteneur échouée comme réussie. La vérification ultérieure marquerait le conteneur comme échoué en raison d'une non-concordance de somme de contrôle. La solution de contournement consiste à corriger la configuration du site secondaire. **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | Tous                     |  Tous                    | 16.10.2  |

- En raison d'un bug introduit dans GitLab 16.5, les [extraits personnels](../../user/snippets.md) ne sont pas répliqués sur les sites Geo secondaires. Cela peut entraîner une perte des données d'extraits personnels en cas de basculement Geo. Consultez les détails du problème et la solution de contournement dans le [ticket 439933](https://gitlab.com/gitlab-org/gitlab/-/issues/439933).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  Tous                    | Aucune     |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- Vous pourriez constater des échecs de vérification sur un sous-ensemble d'images du registre de conteneurs en raison d'une non-concordance de somme de contrôle entre le site principal et le site secondaire. Le [ticket 442667](https://gitlab.com/gitlab-org/gitlab/-/issues/442667) décrit les détails. Bien qu'il n'y ait pas de risque direct de perte de données, les données étant correctement répliquées sur les sites secondaires, la vérification n'est pas effectuée avec succès. Aucune solution de contournement connue n'existe à ce jour.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- En raison d'un bug introduit dans GitLab 16.5 et corrigé dans la version 17.0, les fichiers de déploiement de [GitLab Pages](../../administration/pages/_index.md) sont orphelins sur les sites Geo secondaires. Si les déploiements Pages sont stockés localement, cela peut entraîner un stockage restant nul et, par conséquent, une perte de données en cas de basculement. Consultez les détails du problème et la solution de contournement dans le [ticket 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

### Installations avec le paquet Linux {#linux-package-installations-3}

- Les options Sidekiq `min_concurrency` et `max_concurrency` sont dépréciées dans GitLab 16.9.0 et prévues pour suppression dans GitLab 17.0.0. Dans GitLab 16.9.0 et les versions ultérieures, pour éviter les changements incompatibles dans GitLab 17.0.0, définissez la nouvelle option [`concurrency`](../../administration/sidekiq/extra_sidekiq_processes.md#manage-thread-counts-with-concurrency-field) et supprimez les options `min_concurrency` et `max_concurrency`.

## 16.8.0 {#1680}

- GitLab 16.8.0 et 16.8.1 ont temporairement requis Redis 6.2. GitLab 16.8.2 a rétabli la [compatibilité avec Redis 6.0](https://gitlab.com/gitlab-org/gitlab/-/issues/439418).
- En général, les sauvegardes dans les environnements disposant de PgBouncer doivent [contourner PgBouncer en définissant des variables dont le préfixe est `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion régulière à la base de données via PgBouncer au lieu de la connexion directe définie dans le paramètre de remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations Geo {#geo-installations-3}

- La version 14 de PostgreSQL est la version par défaut pour les nouvelles installations de GitLab 16.7 et des versions ultérieures. En raison d'un problème connu, les sites Geo secondaires existants ne peuvent pas être mis à niveau vers la version 14 de PostgreSQL. Pour plus d'informations, consultez le [ticket 7768](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7768#note_1652076255). Tous les sites Geo doivent exécuter la même version de PostgreSQL. Pour ajouter un nouveau site Geo secondaire sur GitLab 16.7 à 16.8.1, vous devez effectuer l'une des actions suivantes en fonction de votre configuration :

  - Pour ajouter votre premier site Geo secondaire : [Mettez à niveau le site principal vers PostgreSQL 14](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server) avant de configurer le nouveau site Geo secondaire. Aucune action particulière n'est requise si votre site principal utilise déjà PostgreSQL 14.
  - Pour ajouter un nouveau site Geo secondaire à un déploiement qui dispose déjà d'un ou plusieurs sites Geo secondaires :
    - Si tous les sites existants utilisent PostgreSQL 13, installez le nouveau site Geo secondaire avec la [version PostgreSQL 13 épinglée](https://docs.gitlab.com/omnibus/settings/database/#pin-the-packaged-postgresql-version-fresh-installs-only).
    - Si tous les sites existants utilisent PostgreSQL 14 : aucune action particulière n'est requise.
    - Mettez à niveau tous les sites existants vers GitLab 16.8.2 ou une version ultérieure et PostgreSQL 14 avant d'ajouter le nouveau site Geo secondaire au déploiement.
- En raison d'un bug introduit dans GitLab 16.5, les [extraits personnels](../../user/snippets.md) ne sont pas répliqués sur les sites Geo secondaires. Cela peut entraîner une perte des données d'extraits personnels en cas de basculement Geo. Consultez les détails du problème et la solution de contournement dans le [ticket 439933](https://gitlab.com/gitlab-org/gitlab/-/issues/439933).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  Tous                    | Aucune     |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- Vous pourriez constater des échecs de vérification sur un sous-ensemble d'images du registre de conteneurs en raison d'une non-concordance de somme de contrôle entre le site principal et le site secondaire. Le [ticket 442667](https://gitlab.com/gitlab-org/gitlab/-/issues/442667) décrit les détails. Bien qu'il n'y ait pas de risque direct de perte de données, les données étant correctement répliquées sur les sites secondaires, la vérification n'est pas effectuée avec succès. Aucune solution de contournement connue n'existe à ce jour.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- En raison d'un bug introduit dans GitLab 16.5 et corrigé dans la version 17.0, les fichiers de déploiement de [GitLab Pages](../../administration/pages/_index.md) sont orphelins sur les sites Geo secondaires. Si les déploiements Pages sont stockés localement, cela peut entraîner un stockage restant nul et, par conséquent, une perte de données en cas de basculement. Consultez les détails du problème et la solution de contournement dans le [ticket 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

## 16.7.0 {#1670}

- GitLab 16.7 est un arrêt de mise à niveau obligatoire. Cela garantit que toutes les modifications de base de données introduites dans GitLab 16.7 et les versions antérieures ont été implémentées sur toutes les instances GitLab Self-Managed. Les changements dépendants peuvent ensuite être publiés dans GitLab 16.8 et les versions ultérieures. Le [ticket 429611](https://gitlab.com/gitlab-org/gitlab/-/issues/429611) fournit plus de détails.

  - Si vous ignorez la version 16.6 dans votre chemin de mise à niveau, vous pourriez rencontrer des problèmes de performance après la mise à niveau vers la version 16.7, lorsque votre instance traite une migration de base de données en arrière-plan provenant de la release GitLab 16.6. En savoir plus sur la migration `ci_builds` dans les [notes de mise à niveau 16.6.0](#1660).
- En général, les sauvegardes dans les environnements disposant de PgBouncer doivent [contourner PgBouncer en définissant des variables dont le préfixe est `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion régulière à la base de données via PgBouncer au lieu de la connexion directe définie dans le paramètre de remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations avec le paquet Linux {#linux-package-installations-4}

Des informations spécifiques s'appliquent aux installations avec le package Linux :

- À partir de GitLab 16.7, PostgreSQL 14 est la version par défaut installée avec le package Linux. Lors d'une mise à niveau du package, la base de données n'est pas mise à niveau vers PostgreSQL 14. Si vous souhaitez passer à PostgreSQL 14, [vous devez le faire manuellement](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server).

  Si vous souhaitez utiliser PostgreSQL 13, vous devez définir `postgresql['version'] = 13` dans `/etc/gitlab/gitlab.rb`.

### Installations Geo {#geo-installations-4}

- La version 14 de PostgreSQL est la version par défaut pour les nouvelles installations de GitLab 16.7 et des versions ultérieures. En raison d'un problème connu, les sites Geo secondaires existants ne peuvent pas être mis à niveau vers la version 14 de PostgreSQL. Pour plus d'informations, consultez le [ticket](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7768#note_1652076255). Tous les sites Geo doivent exécuter la même version de PostgreSQL. Pour ajouter un nouveau site Geo secondaire basé sur GitLab 16.7 à 16.8.1, vous devez effectuer l'une des actions suivantes en fonction de votre configuration :

  - Vous ajoutez votre premier site Geo secondaire : [Mettez à niveau le site principal vers PostgreSQL 14](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server) avant de configurer le nouveau site Geo secondaire. Aucune action particulière n'est requise si votre site principal utilise déjà PostgreSQL 14.
  - Vous ajoutez un nouveau site Geo secondaire à un déploiement qui dispose déjà d'un ou plusieurs sites Geo secondaires :
    - Si tous les sites existants utilisent PostgreSQL 13 : installez le nouveau site Geo secondaire avec la [version PostgreSQL 13 épinglée](https://docs.gitlab.com/omnibus/settings/database/#pin-the-packaged-postgresql-version-fresh-installs-only).
    - Si tous les sites existants utilisent PostgreSQL 14 : aucune action particulière n'est requise.
    - Mettez à niveau tous les sites existants vers GitLab 16.8.2 ou une version ultérieure et PostgreSQL 14 avant d'ajouter le nouveau site Geo secondaire au déploiement.
- Vous pourriez constater des échecs de vérification sur un sous-ensemble de projets en raison d'une non-concordance de somme de contrôle entre le site principal et le site secondaire. Les détails sont suivis dans ce [ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/427493). Il n'y a aucun risque de perte de données, les données étant correctement répliquées sur les sites secondaires. Les utilisateurs qui clonent des projets affectés depuis un site Geo secondaire seront toujours redirigés vers le site principal. Aucune solution de contournement connue n'existe à ce jour. Nous travaillons activement sur un correctif.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  16.6.0 - 16.6.5        | 16.6.6   |
  | 16.7                    |  16.7.0 - 16.7.3        | 16.7.4   |

- En raison d'un bug introduit dans GitLab 16.5, les [extraits personnels](../../user/snippets.md) ne sont pas répliqués sur les sites Geo secondaires. Cela peut entraîner une perte des données d'extraits personnels en cas de basculement Geo. Consultez les détails du problème et la solution de contournement dans le [ticket 439933](https://gitlab.com/gitlab-org/gitlab/-/issues/439933).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  Tous                    | Aucune     |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- En raison d'un bug introduit dans GitLab 16.5 et corrigé dans la version 17.0, les fichiers de déploiement de [GitLab Pages](../../administration/pages/_index.md) sont orphelins sur les sites Geo secondaires. Si les déploiements Pages sont stockés localement, cela peut entraîner un stockage restant nul et, par conséquent, une perte de données en cas de basculement. Consultez les détails du problème et la solution de contournement dans le [ticket 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

## 16.6.0 {#1660}

- GitLab 16.6 introduit une migration en arrière-plan qui réécrit chaque ligne de la table des jobs CI (`ci_builds`) dans le cadre de la mise à niveau de la clé primaire vers 64 bits. `ci_builds` est l'une des tables les plus volumineuses sur la plupart des instances GitLab. Cette migration s'exécute donc de manière plus agressive que d'habitude pour s'assurer qu'elle prend un temps raisonnable. Les migrations en arrière-plan marquent habituellement une pause entre les lots de lignes, mais cette migration ne le fait pas.

  Cela peut entraîner des problèmes de performance dans les environnements GitLab Self-Managed :

  - Les E/S disque seront plus élevées que d'habitude. Cela sera un problème particulier pour les instances hébergées par des fournisseurs cloud où les E/S disque sont limitées.
  - L'autovacuum peut s'exécuter plus fréquemment en arrière-plan pour s'assurer que les anciennes lignes (tuples morts) sont supprimées et pour effectuer d'autres opérations de maintenance associées.
  - Les requêtes peuvent s'exécuter lentement, temporairement, car des plans de requêtes inefficaces sont sélectionnés par PostgreSQL. Cela peut être déclenché par le volume de modifications sur la table.

  Solutions de contournement :

  - Mettez en pause la migration en cours dans la [zone **Admin**](../background_migrations.md#from-the-gitlab-ui).
  - Recréez les statistiques de table manuellement dans la [console de base de données](../../administration/troubleshooting/postgresql.md#start-a-database-console) pour vous assurer que le bon plan de requête est sélectionné :

    ```sql
    SET statement_timeout = 0;
    VACUUM FREEZE VERBOSE ANALYZE public.ci_builds;
    ```

- D'anciens [jobs de destruction d'environnements CI peuvent être générés](https://gitlab.com/gitlab-org/gitlab/-/issues/433264#) après la mise à niveau vers GitLab 16.6.
- En général, les sauvegardes dans les environnements disposant de PgBouncer doivent [contourner PgBouncer en définissant des variables dont le préfixe est `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion régulière à la base de données via PgBouncer au lieu de la connexion directe définie dans le paramètre de remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations Geo {#geo-installations-5}

- Vous pourriez constater des échecs de vérification sur un sous-ensemble de projets en raison d'une non-concordance de somme de contrôle entre le site principal et le site secondaire. Les détails sont suivis dans ce [ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/427493). Il n'y a aucun risque de perte de données, les données étant correctement répliquées sur les sites secondaires. Les utilisateurs qui clonent des projets affectés depuis un site Geo secondaire seront toujours redirigés vers le site principal. Aucune solution de contournement connue n'existe à ce jour. Nous travaillons activement sur un correctif.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  16.6.0 - 16.6.5        | 16.6.6   |
  | 16.7                    |  16.7.0 - 16.7.3        | 16.7.4   |

- En raison d'un bug introduit dans GitLab 16.5, les [extraits personnels](../../user/snippets.md) ne sont pas répliqués sur les sites Geo secondaires. Cela peut entraîner une perte des données d'extraits personnels en cas de basculement Geo. Consultez les détails du problème et la solution de contournement dans le [ticket 439933](https://gitlab.com/gitlab-org/gitlab/-/issues/439933).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  Tous                    | Aucune     |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- En raison d'un bug introduit dans GitLab 16.5 et corrigé dans la version 17.0, les fichiers de déploiement de [GitLab Pages](../../administration/pages/_index.md) sont orphelins sur les sites Geo secondaires. Si les déploiements Pages sont stockés localement, cela peut entraîner un stockage restant nul et, par conséquent, une perte de données en cas de basculement. Consultez les détails du problème et la solution de contournement dans le [ticket 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

## 16.5.0 {#1650}

- Git 2.42.0 et les versions ultérieures sont requis par Gitaly. Pour les installations compilées à partir des sources, vous devez utiliser la [version Git fournie par Gitaly](../../install/self_compiled/_index.md#git).
- Une régression peut parfois provoquer une [erreur HTTP 500 lors de la navigation dans un groupe](https://gitlab.com/gitlab-org/gitlab/-/issues/431659). La mise à niveau vers GitLab 16.6 ou une version ultérieure résout le problème.
- Une régression peut entraîner le [non-chargement des facettes de recherche avancée non sélectionnées](https://gitlab.com/gitlab-org/gitlab/-/issues/428246). La mise à niveau vers la version 16.6 ou une version ultérieure résout le problème.
- L'index `unique_batched_background_migrations_queued_migration_version` a été introduit dans la version 16.5, et la migration post-déploiement `DeleteOrphansScanFindingLicenseScanningApprovalRules2` peut rompre cette contrainte d'unicité lors d'une mise à niveau sans temps d'arrêt. Une solution de contournement est disponible dans le [ticket #437291](https://gitlab.com/gitlab-org/gitlab/-/issues/437291#to-unblock) qui corrige l'erreur :

  ```plaintext
  PG::UniqueViolation: ERROR:  duplicate key value violates unique constraint
  "unique_batched_background_migrations_queued_migration_version"
  DETAIL:  Key (queued_migration_version)=(20230721095222) already exists.
  ```

- En général, les sauvegardes dans les environnements disposant de PgBouncer doivent [contourner PgBouncer en définissant des variables dont le préfixe est `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion régulière à la base de données via PgBouncer au lieu de la connexion directe définie dans le paramètre de remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations avec le paquet Linux {#linux-package-installations-5}

- Les URL de clonage SSH peuvent être personnalisées en définissant `gitlab_rails['gitlab_ssh_host']` dans `/etc/gitlab/gitlab.rb`. Ce paramètre doit désormais être un [nom d'hôte valide](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/132238). Auparavant, il pouvait s'agir d'une chaîne arbitraire utilisée pour afficher un nom d'hôte et un port personnalisés dans l'URL de clonage du dépôt.

  Par exemple, avant GitLab 16.5, le paramètre suivant fonctionnait :

  ```ruby
  gitlab_rails['gitlab_ssh_host'] = "gitlab.example.com:2222"
  ```

  À partir de GitLab 16.5, le nom d'hôte et le port doivent être spécifiés séparément :

  ```ruby
  gitlab_rails['gitlab_ssh_host'] = "gitlab.example.com"
  gitlab_rails['gitlab_shell_ssh_port'] = 2222
  ```

  Après avoir modifié le paramètre, veillez à reconfigurer GitLab :

  ```shell
  sudo gitlab-ctl reconfigure
  ```

### Installations Geo {#geo-installations-6}

Des informations spécifiques s'appliquent aux installations utilisant Geo :

- Un certain nombre de métriques Prometheus ont été incorrectement supprimées dans la version 16.3.0, ce qui peut altérer les tableaux de bord et les alertes :

  | Métrique affectée                          | Métrique restaurée dans la version 16.5.2 et les versions ultérieures  | Remplacement disponible dans 16.3+                 |
  | ---------------------------------------- | ------------------------------------ | ---------------------------------------------- |
  | `geo_repositories_synced`                | Oui                                  | `geo_project_repositories_synced`              |
  | `geo_repositories_failed`                | Oui                                  | `geo_project_repositories_failed`              |
  | `geo_repositories_checksummed`           | Oui                                  | `geo_project_repositories_checksummed`         |
  | `geo_repositories_checksum_failed`       | Oui                                  | `geo_project_repositories_checksum_failed`     |
  | `geo_repositories_verified`              | Oui                                  | `geo_project_repositories_verified`            |
  | `geo_repositories_verification_failed`   | Oui                                  | `geo_project_repositories_verification_failed` |
  | `geo_repositories_checksum_mismatch`     | Non                                   | Aucun disponible                                 |
  | `geo_repositories_retrying_verification` | Non                                   | Aucun disponible                                 |

  - Versions affectées :
    - 16.3.0 à 16.5.1
  - Versions contenant le correctif :
    - 16.5.2 et les versions ultérieures

  Pour plus d'informations, consultez [le ticket 429617](https://gitlab.com/gitlab-org/gitlab/-/issues/429617).

- [La vérification du stockage d'objets](../../releases/16/gitlab-16-4-released.md#geo-verifies-object-storage) a été ajoutée dans GitLab 16.4. En raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/429242), certaines installations Geo signalent une utilisation élevée de la mémoire, ce qui peut entraîner une absence de réponse de l'application GitLab sur le site principal.

  Votre installation peut être affectée si vous l'avez configurée pour utiliser le [stockage d'objets](../../administration/object_storage.md) et avez activé la [réplication du stockage d'objets géré par GitLab](../../administration/geo/replication/object_storage.md#enabling-gitlab-managed-object-storage-replication)

  Jusqu'à ce que ce problème soit résolu, la solution de contournement consiste à désactiver la vérification du stockage d'objets. Exécutez la commande suivante sur l'un des nœuds Rails du site principal :

  ```shell
  sudo gitlab-rails runner 'Feature.disable(:geo_object_storage_verification)'
  ```

  Ce problème a été corrigé par les releases de correctifs répertoriés dans le tableau suivant, avec un correctif supplémentaire dans GitLab 16.7.0. Si vous avez désactivé la vérification du stockage d'objets comme solution de contournement, réactivez-la après la mise à niveau vers une release corrigée :

  ```shell
  sudo gitlab-rails runner 'Feature.enable(:geo_object_storage_verification)'
  ```

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.4                    | 16.4.0 - 16.4.2         | 16.4.3   |
  | 16.5                    | 16.5.0 - 16.5.1         | 16.5.2   |

- Après l'ajout de la vérification de [Group Wiki](../../user/project/wiki/group.md) dans GitLab 16.3, les dépôts Group Wiki manquants sont incorrectement signalés comme échouant à la vérification. Ce problème n'est pas dû à un échec réel de réplication ou de vérification, mais à un état interne invalide pour ces dépôts manquants dans Geo, ce qui entraîne des erreurs dans les journaux et la progression de la vérification indiquant un état d'échec pour ces dépôts Group Wiki.

  Consultez les détails du problème et la solution de contournement dans [le ticket 426571](https://gitlab.com/gitlab-org/gitlab/-/issues/426571)

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ------ | ------ | ------ |
  | 16.3   | Tous    | Aucune   |
  | 16.4   | Tous    | Aucune   |
  | 16.5   | 16.5.0 - 16.5.1    | 16.5.2   |

- Vous pourriez constater des échecs de vérification sur un sous-ensemble de projets en raison d'une non-concordance de somme de contrôle entre le site principal et le site secondaire. Les détails sont suivis dans ce [ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/427493). Il n'y a aucun risque de perte de données, les données étant correctement répliquées sur les sites secondaires. Les utilisateurs qui clonent des projets affectés depuis un site Geo secondaire seront toujours redirigés vers le site principal. Aucune solution de contournement connue n'existe à ce jour. Nous travaillons activement sur un correctif.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  16.6.0 - 16.6.5        | 16.6.6   |
  | 16.7                    |  16.7.0 - 16.7.3        | 16.7.4   |

- En raison d'un bug introduit dans GitLab 16.5, les [extraits personnels](../../user/snippets.md) ne sont pas répliqués sur les sites Geo secondaires. Cela peut entraîner une perte des données d'extraits personnels en cas de basculement Geo. Consultez les détails du problème et la solution de contournement dans le [ticket 439933](https://gitlab.com/gitlab-org/gitlab/-/issues/439933).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  Tous                    | Aucune     |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- En raison d'un bug introduit dans GitLab 16.5 et corrigé dans la version 17.0, les fichiers de déploiement de [GitLab Pages](../../administration/pages/_index.md) sont orphelins sur les sites Geo secondaires. Si les déploiements Pages sont stockés localement, cela peut entraîner un stockage restant nul et, par conséquent, une perte de données en cas de basculement. Consultez les détails du problème et la solution de contournement dans le [ticket 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159).

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

## 16.4.0 {#1640}

- La mise à jour d'un chemin de groupe a [fait l'objet d'un correctif de bug](https://gitlab.com/gitlab-org/gitlab/-/issues/419289) qui utilise un index de base de données introduit dans la version 16.3.

  Si vous effectuez une mise à niveau vers la version 16.4 depuis une version antérieure à 16.3, vous devez exécuter `ANALYZE packages_packages;` dans la base de données avant de l'utiliser.
- Vous pourriez rencontrer l'erreur suivante lors de la mise à niveau vers GitLab 16.4 ou une version ultérieure :

  ```plaintext
  main: == 20230830084959 ValidatePushRulesConstraints: migrating =====================
  main: -- execute("SET statement_timeout TO 0")
  main:    -> 0.0002s
  main: -- execute("ALTER TABLE push_rules VALIDATE CONSTRAINT force_push_regex_size_constraint;")
  main:    -> 0.0004s
  main: -- execute("RESET statement_timeout")
  main:    -> 0.0003s
  main: -- execute("ALTER TABLE push_rules VALIDATE CONSTRAINT delete_branch_regex_size_constraint;")
  rails aborted!
  StandardError: An error has occurred, all later migrations canceled:

  PG::CheckViolation: ERROR:  check constraint "delete_branch_regex_size_constraint" of relation "push_rules" is violated by some row
  ```

  Ces contraintes peuvent renvoyer une erreur :

  - `author_email_regex_size_constraint`
  - `branch_name_regex_size_constraint`
  - `commit_message_negative_regex_size_constraint`
  - `commit_message_regex_size_constraint`
  - `delete_branch_regex_size_constraint`
  - `file_name_regex_size_constraint`
  - `force_push_regex_size_constraint`

  Pour corriger l'erreur, recherchez les enregistrements dans la table `push_rules` qui dépassent la limite de 511 caractères.

  ```sql
  -- replace `delete_branch_regex` with a name of the field used in constraint
  SELECT id FROM push_rules WHERE LENGTH(delete_branch_regex) > 511;
  ```

  Pour déterminer si une règle push appartient à un projet, un groupe ou une instance, exécutez ce script dans la [console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session) :

  ```ruby
  # replace `delete_branch_regex` with a name of the field used in constraint
  long_rules = PushRule.where("length(delete_branch_regex) > 511")

  array = long_rules.map do |lr|
    if lr.project
      "Push rule with ID #{lr.id} is configured in a project #{lr.project.full_name}"
    elsif lr.group
      "Push rule with ID #{lr.id} is configured in a group #{lr.group.full_name}"
    else
      "Push rule with ID #{lr.id} is configured on the instance level"
    end
  end

  puts "Total long rules: #{array.count}"
  puts array.join("\n")
  ```

  Réduisez la longueur de la valeur du champ regex pour les enregistrements de règles push affectés, puis relancez la migration.

  Si vous avez trop de règles push affectées et que vous ne pouvez pas les mettre à jour via l'interface utilisateur de GitLab, contactez le [support GitLab](https://support.gitlab.com/).

- En général, les sauvegardes dans les environnements disposant de PgBouncer doivent [contourner PgBouncer en définissant des variables dont le préfixe est `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion régulière à la base de données via PgBouncer au lieu de la connexion directe définie dans le paramètre de remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations auto-compilées {#self-compiled-installations}

- Une nouvelle méthode de configuration des chemins pour le secret GitLab et les hooks personnalisés est recommandée dans GitLab 16.4 et les versions ultérieures :
  1. Mettez à jour votre configuration `[gitlab] secret_file` pour configurer le chemin vers le jeton secret GitLab.
  1. Si vous disposez de hooks personnalisés, mettez à jour votre configuration `[hooks] custom_hooks_dir` pour configurer le chemin vers les hooks personnalisés côté serveur.
  1. Supprimez la configuration `[gitlab-shell] dir`.

### Installations Geo {#geo-installations-7}

Des informations spécifiques s'appliquent aux installations utilisant Geo :

- Un certain nombre de métriques Prometheus ont été incorrectement supprimées dans la version 16.3.0, ce qui peut altérer les tableaux de bord et les alertes :

  | Métrique affectée                          | Métrique restaurée dans la version 16.5.2 et les versions ultérieures  | Remplacement disponible dans 16.3+                 |
  | ---------------------------------------- | ------------------------------------ | ---------------------------------------------- |
  | `geo_repositories_synced`                | Oui                                  | `geo_project_repositories_synced`              |
  | `geo_repositories_failed`                | Oui                                  | `geo_project_repositories_failed`              |
  | `geo_repositories_checksummed`           | Oui                                  | `geo_project_repositories_checksummed`         |
  | `geo_repositories_checksum_failed`       | Oui                                  | `geo_project_repositories_checksum_failed`     |
  | `geo_repositories_verified`              | Oui                                  | `geo_project_repositories_verified`            |
  | `geo_repositories_verification_failed`   | Oui                                  | `geo_project_repositories_verification_failed` |
  | `geo_repositories_checksum_mismatch`     | Non                                   | Aucun disponible                                 |
  | `geo_repositories_retrying_verification` | Non                                   | Aucun disponible                                 |

  - Versions affectées :
    - 16.3.0 à 16.5.1
  - Versions contenant le correctif :
    - 16.5.2 et les versions ultérieures

  Pour plus d'informations, consultez [le ticket 429617](https://gitlab.com/gitlab-org/gitlab/-/issues/429617).

- [La vérification du stockage d'objets](../../releases/16/gitlab-16-4-released.md#geo-verifies-object-storage) a été ajoutée dans GitLab 16.4. En raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/429242), certaines installations Geo signalent une utilisation élevée de la mémoire, ce qui peut entraîner une absence de réponse de l'application GitLab sur le site principal.

  Votre installation peut être affectée si vous l'avez configurée pour utiliser le [stockage d'objets](../../administration/object_storage.md) et avez activé la [réplication du stockage d'objets géré par GitLab](../../administration/geo/replication/object_storage.md#enabling-gitlab-managed-object-storage-replication)

  Jusqu'à ce que ce problème soit résolu, la solution de contournement consiste à désactiver la vérification du stockage d'objets. Exécutez la commande suivante sur l'un des nœuds Rails du site principal :

  ```shell
  sudo gitlab-rails runner 'Feature.disable(:geo_object_storage_verification)'
  ```

  Ce problème a été corrigé par les releases de correctifs répertoriés dans le tableau suivant, avec un correctif supplémentaire dans GitLab 16.7.0. Si vous avez désactivé la vérification du stockage d'objets comme solution de contournement, réactivez-la après la mise à niveau vers une release corrigée :

  ```shell
  sudo gitlab-rails runner 'Feature.enable(:geo_object_storage_verification)'
  ```

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.4                    | 16.4.0 - 16.4.2         | 16.4.3   |
  | 16.5                    | 16.5.0 - 16.5.1         | 16.5.2   |

- Un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/419370) lié à des états de synchronisation bloqués en état en attente entraîne un blocage indéfini de la réplication pour les éléments concernés, ce qui présente un risque de perte de données en cas de basculement. Cela affecte principalement les synchronisations de dépôts, mais peut également affecter les synchronisations de registres de conteneurs. Il est conseillé de mettre à niveau vers une version corrigée pour éviter tout risque de perte de données.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ------ | ------ | ------ |
  | 16.3   | 16.3.0 - 16.3.5    | 16.3.6   |
  | 16.4   | 16.4.0 - 16.4.1    | 16.4.2   |

- Après l'ajout de la vérification de [Group Wiki](../../user/project/wiki/group.md) dans GitLab 16.3, les dépôts Group Wiki manquants sont incorrectement signalés comme échouant à la vérification. Ce problème n'est pas dû à un échec réel de réplication ou de vérification, mais à un état interne invalide pour ces dépôts manquants dans Geo, ce qui entraîne des erreurs dans les journaux et la progression de la vérification indiquant un état d'échec pour ces dépôts Group Wiki.

  Consultez les détails du problème et la solution de contournement dans [le ticket 426571](https://gitlab.com/gitlab-org/gitlab/-/issues/426571)

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ------ | ------ | ------ |
  | 16.3   | Tous    | Aucune   |
  | 16.4   | Tous    | Aucune   |
  | 16.5   | 16.5.0 - 16.5.1    | 16.5.2   |

- Vous pourriez constater des échecs de vérification sur un sous-ensemble de projets en raison d'une non-concordance de somme de contrôle entre le site principal et le site secondaire. Les détails sont suivis dans ce [ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/427493). Il n'y a aucun risque de perte de données, les données étant correctement répliquées sur les sites secondaires. Les utilisateurs qui clonent des projets affectés depuis un site Geo secondaire seront toujours redirigés vers le site principal. Aucune solution de contournement connue n'existe à ce jour. Nous travaillons activement sur un correctif.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  16.6.0 - 16.6.5        | 16.6.6   |
  | 16.7                    |  16.7.0 - 16.7.3        | 16.7.4   |

## 16.3.0 {#1630}

- Mettez à jour GitLab vers la version 16.3.5 ou une version ultérieure. Cela permet d'éviter le [ticket 425971](https://gitlab.com/gitlab-org/gitlab/-/issues/425971) qui provoque une utilisation excessive de l'espace disque de la base de données pour GitLab 16.3.3 et 16.3.4.
- Un index unique a été ajouté pour garantir l'absence de packages NPM en double dans la base de données. Si vous avez des packages NPM en double, vous devez d'abord mettre à niveau vers la version 16.1, faute de quoi vous risquez de rencontrer l'erreur suivante : `PG::UniqueViolation: ERROR:  could not create unique index "idx_packages_on_project_id_name_version_unique_when_npm"`.
- Pour les applications Go, [`crypto/tls` : la vérification des chaînes de certificats contenant de grandes clés RSA est lente (CVE-2023-29409)](https://github.com/golang/go/issues/61460) a introduit une limite de 8 192 bits pour les clés RSA. Dans le contexte des applications Go chez GitLab, les clés RSA peuvent être configurées pour :

  - [Registre de conteneurs](../../administration/packages/container_registry.md)
  - [Gitaly](../../administration/gitaly/tls_support.md)
  - [GitLab Pages](../../user/project/pages/custom_domains_ssl_tls_certification/_index.md#manually-add-ssltls-certificates)
  - Workhorse

  Vérifiez la taille de vos clés RSA (`openssl rsa -in <your-key-file> -text -noout | grep "Key:"`) pour l'une des applications précédentes avant la mise à niveau.

- Une migration en arrière-plan `BackfillCiPipelineVariablesForPipelineIdBigintConversion` est finalisée avec la migration post-déploiement `EnsureAgainBackfillForCiPipelineVariablesPipelineIdIsFinished`. GitLab 16.2.0 a introduit une [migration en arrière-plan par lots](../background_migrations.md#check-for-pending-database-background-migrations) pour [remplir les valeurs `bigint` `pipeline_id` dans la table `ci_pipeline_variables`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/123132). Cette migration peut prendre beaucoup de temps sur les instances GitLab de grande taille (4 heures pour traiter 50 millions de lignes ont été signalées dans un cas). Pour éviter un temps d'arrêt prolongé lors de la mise à niveau, assurez-vous que la migration s'est terminée avec succès avant de passer à la version 16.3.

  Vous pouvez vérifier la taille de la table `ci_pipeline_variables` dans la [console de base de données](../../administration/troubleshooting/postgresql.md#start-a-database-console) :

  ```sql
  select count(*) from ci_pipeline_variables;
  ```

- En général, les sauvegardes dans les environnements disposant de PgBouncer doivent [contourner PgBouncer en définissant des variables dont le préfixe est `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion régulière à la base de données via PgBouncer au lieu de la connexion directe définie dans le paramètre de remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations avec le paquet Linux {#linux-package-installations-6}

Des informations spécifiques s'appliquent aux installations avec le package Linux :

- Dans GitLab 16.0, nous avons [annoncé](../../releases/16/gitlab-16-0-released.md#omnibus-improvements) une mise à niveau de l'image Docker de base, qui inclut une nouvelle version d'OpenSSH Server. Une conséquence non intentionnelle de cette nouvelle version est qu'elle désactive par défaut l'acceptation des signatures SSH RSA SHA-1. Ce problème ne devrait affecter que les utilisateurs utilisant des clients SSH très obsolètes.

  Pour éviter les problèmes liés à l'indisponibilité des signatures SHA-1, les utilisateurs doivent mettre à jour leurs clients SSH, car l'utilisation de signatures SHA-1 est déconseillée par la bibliothèque amont pour des raisons de sécurité.

  Pour permettre une période de transition pendant laquelle les utilisateurs ne peuvent pas immédiatement mettre à niveau leurs clients SSH, GitLab 16.3 et les versions ultérieures prennent en charge une variable d'environnement `GITLAB_ALLOW_SHA1_RSA` dans le `Dockerfile`. Si `GITLAB_ALLOW_SHA1_RSA` est défini sur `true`, cette prise en charge obsolète est réactivée.

  Comme nous souhaitons encourager les meilleures pratiques en matière de sécurité et suivre la recommandation amont, cette variable d'environnement ne sera disponible que jusqu'à GitLab 17.0, date à laquelle nous prévoyons de supprimer cette prise en charge.

  Pour plus d'informations, consultez :

  - [Notes de release d'OpenSSH 8.8](https://www.openssh.org/txt/release-8.8).
  - [Une explication informelle](https://gitlab.com/gitlab-org/gitlab/-/issues/416714#note_1482388504).
  - `omnibus-gitlab` [merge request 7035](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/7035), qui introduit la variable d'environnement.

### Installations Geo {#geo-installations-8}

Des informations spécifiques s'appliquent aux installations utilisant Geo :

- Les requêtes Git pull vers un site Geo secondaire sont redirigées par proxy vers le site Geo principal même lorsque ce site secondaire est à jour. Vous êtes affecté si vous utilisez Geo pour accélérer l'accès des utilisateurs distants qui effectuent des requêtes Git pull vers un site Geo secondaire.

  - Versions affectées :
    - 16.3.0 à 16.3.3
  - Versions contenant le correctif :
    - 16.3.4 et les versions ultérieures

  Pour plus d'informations, consultez [le ticket 425224](https://gitlab.com/gitlab-org/gitlab/-/issues/425224).

- Un certain nombre de métriques Prometheus ont été incorrectement supprimées dans la version 16.3.0, ce qui peut altérer les tableaux de bord et les alertes :

  | Métrique affectée                          | Métrique restaurée dans la version 16.5.2 et les versions ultérieures  | Remplacement disponible dans 16.3+                 |
  | ---------------------------------------- | ------------------------------------ | ---------------------------------------------- |
  | `geo_repositories_synced`                | Oui                                  | `geo_project_repositories_synced`              |
  | `geo_repositories_failed`                | Oui                                  | `geo_project_repositories_failed`              |
  | `geo_repositories_checksummed`           | Oui                                  | `geo_project_repositories_checksummed`         |
  | `geo_repositories_checksum_failed`       | Oui                                  | `geo_project_repositories_checksum_failed`     |
  | `geo_repositories_verified`              | Oui                                  | `geo_project_repositories_verified`            |
  | `geo_repositories_verification_failed`   | Oui                                  | `geo_project_repositories_verification_failed` |
  | `geo_repositories_checksum_mismatch`     | Non                                   | Aucun disponible                                 |
  | `geo_repositories_retrying_verification` | Non                                   | Aucun disponible                                 |

  - Versions affectées :
    - 16.3.0 à 16.5.1
  - Versions contenant le correctif :
    - 16.5.2 et les versions ultérieures

  Pour plus d'informations, consultez [le ticket 429617](https://gitlab.com/gitlab-org/gitlab/-/issues/429617).

- Un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/419370) lié à des états de synchronisation bloqués en état en attente entraîne un blocage indéfini de la réplication pour les éléments concernés, ce qui présente un risque de perte de données en cas de basculement. Cela affecte principalement les synchronisations de dépôts, mais peut également affecter les synchronisations de registres de conteneurs. Il est conseillé de mettre à niveau vers une version corrigée pour éviter tout risque de perte de données.
- Vous pourriez constater des échecs de vérification sur un sous-ensemble de projets en raison d'une non-concordance de somme de contrôle entre le site principal et le site secondaire. Les détails sont suivis dans [le ticket 427493](https://gitlab.com/gitlab-org/gitlab/-/issues/427493). Il n'y a aucun risque de perte de données, les données étant correctement répliquées sur les sites secondaires. Les utilisateurs qui clonent des projets affectés depuis un site Geo secondaire seront toujours redirigés vers le site principal. Aucune solution de contournement connue n'existe ; vous devez mettre à niveau vers une version contenant le correctif.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  16.6.0 - 16.6.5        | 16.6.6   |
  | 16.7                    |  16.7.0 - 16.7.3        | 16.7.4   |

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ------ | ------ | ------ |
  | 16.3   | 16.3.0 - 16.3.5    | 16.3.6   |
  | 16.4   | 16.4.0 - 16.4.1    | 16.4.2   |

- Après l'ajout de la vérification de [Group Wiki](../../user/project/wiki/group.md) dans GitLab 16.3, les dépôts Group Wiki manquants sont incorrectement signalés comme échouant à la vérification. Ce problème n'est pas dû à un échec réel de réplication ou de vérification, mais à un état interne invalide pour ces dépôts manquants dans Geo, ce qui entraîne des erreurs dans les journaux et la progression de la vérification indiquant un état d'échec pour ces dépôts Group Wiki.

  Consultez les détails du problème et la solution de contournement dans [le ticket 426571](https://gitlab.com/gitlab-org/gitlab/-/issues/426571)

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ------ | ------ | ------ |
  | 16.3   | Tous    | Aucune   |
  | 16.4   | Tous    | Aucune   |
  | 16.5   | 16.5.0 - 16.5.1    | 16.5.2   |

## 16.2.0 {#1620}

- Les paramètres de configuration LDAP hérités peuvent provoquer des [erreurs `NoMethodError: undefined method 'devise' for User:Class`](https://gitlab.com/gitlab-org/gitlab/-/issues/419485). Cette erreur se produit si vous avez des options TLS (telles que `ca_file`) non spécifiées dans le hash `tls_options`, ou si vous utilisez l'option héritée `gitlab_rails['ldap_host']`. Consultez les [solutions de contournement de configuration](https://gitlab.com/gitlab-org/gitlab/-/issues/419485#workarounds) pour plus de détails.
- Si votre base de données GitLab a été créée par ou mise à niveau via les versions 15.11.0 à 15.11.2 incluses, la mise à niveau vers GitLab 16.2 échoue avec :

  ```plaintext
  PG::UndefinedColumn: ERROR:  column "id_convert_to_bigint" of relation "ci_build_needs" does not exist
  LINE 1: ...db_config_name:main*/ UPDATE "ci_build_needs" SET "id_conver...
  ```

  Consultez [les détails et la solution de contournement](#undefined-column-error-upgrading-to-162-or-later).
- Vous pourriez rencontrer l'erreur suivante lors de la mise à niveau vers GitLab 16.2 ou une version ultérieure :

  ```plaintext
  main: == 20230620134708 ValidateUserTypeConstraint: migrating =======================
  main: -- execute("ALTER TABLE users VALIDATE CONSTRAINT check_0dd5948e38;")
  rake aborted!
  StandardError: An error has occurred, all later migrations canceled:
  PG::CheckViolation: ERROR:  check constraint "check_0dd5948e38" of relation "users" is violated by some row
  ```

  Pour plus d'informations, consultez [le ticket 421629](https://gitlab.com/gitlab-org/gitlab/-/issues/421629).
- Vous pourriez rencontrer l'erreur suivante après la mise à niveau vers GitLab 16.2 ou une version ultérieure :

  ```plaintext
  PG::NotNullViolation: ERROR:  null value in column "source_partition_id" of relation "ci_sources_pipelines" violates not-null constraint
  ```

  Les processus Sidekiq et Puma doivent être redémarrés pour résoudre ce problème.
- En général, les sauvegardes dans les environnements disposant de PgBouncer doivent [contourner PgBouncer en définissant des variables dont le préfixe est `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion régulière à la base de données via PgBouncer au lieu de la connexion directe définie dans le paramètre de remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations avec le paquet Linux {#linux-package-installations-7}

Des informations spécifiques s'appliquent aux installations avec le package Linux :

- À partir de GitLab 16.2, PostgreSQL 13.11 et 14.8 sont tous deux inclus dans le package Linux. Lors d'une mise à niveau du package, la base de données n'est pas mise à niveau vers PostgreSQL 14. Si vous souhaitez passer à PostgreSQL 14, vous devez le faire manuellement :

  ```shell
  sudo gitlab-ctl pg-upgrade -V 14
  ```

  PostgreSQL 14 n'est pas pris en charge sur les déploiements Geo et est [prévu](https://gitlab.com/groups/gitlab-org/-/work_items/9065) pour de futures releases.
- Dans la version 16.2, nous mettons à niveau Redis de 6.2.11 vers 7.0.12. Cette mise à niveau est censée être entièrement rétrocompatible.

  Redis n'est pas redémarré automatiquement dans le cadre de `gitlab-ctl reconfigure`. Par conséquent, les utilisateurs doivent exécuter manuellement `sudo gitlab-ctl restart redis` après l'exécution de la reconfiguration afin d'utiliser la nouvelle version de Redis. Un avertissement indiquant que la version Redis installée est différente de celle en cours d'exécution s'affiche à la fin de l'exécution de la reconfiguration jusqu'à ce que le redémarrage soit effectué.

  Suivez [les instructions de mise à niveau sans interruption de service](../zero_downtime.md) pour mettre à niveau votre cluster Redis HA.

### Installations auto-compilées {#self-compiled-installations-1}

- Git 2.41.0 et les versions ultérieures sont requis par Gitaly. Vous devez utiliser la [version de Git fournie par Gitaly](../../install/self_compiled/_index.md#git).

### Installations Geo {#geo-installations-9}

Des informations spécifiques s'appliquent aux installations utilisant Geo :

- Les nouveaux artefacts de job ne sont pas répliqués par Geo si les artefacts de job sont configurés pour être stockés dans le stockage d'objets et que `direct_upload` est activé. Ce bug est corrigé dans GitLab versions 16.1.4, 16.2.3, 16.3.0 et les versions ultérieures.
  - Versions affectées : GitLab versions 16.1.0 - 16.1.3 et 16.2.0 - 16.2.2.
  - Lors de l'exécution d'une version affectée, des artefacts qui semblaient être synchronisés peuvent en réalité être manquants sur le site secondaire. Les artefacts affectés sont automatiquement resynchronisés lors de la mise à niveau vers les versions 16.1.5, 16.2.5, 16.3.1, 16.4.0 ou une version ultérieure. Vous pouvez [resynchroniser manuellement les artefacts de job affectés](https://gitlab.com/gitlab-org/gitlab/-/issues/419742#to-fix-data) si nécessaire.

#### Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal {#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site}

Un [bug](https://gitlab.com/gitlab-org/gitlab/-/issues/410413) dans la logique de proxy Geo pour les objets LFS impliquait que toutes les requêtes de clonage LFS vers un site secondaire étaient redirigées par proxy vers le site principal, même si le site secondaire était à jour. Cela peut entraîner une charge accrue sur le site principal et des temps d'accès plus longs aux objets LFS pour les utilisateurs clonant depuis le site secondaire.

Dans GitLab 15.1, le proxy a été activé par défaut.

Vous n'êtes pas affecté :

- Si votre installation n'est pas configurée pour utiliser des objets LFS
- Si vous n'utilisez pas Geo pour accélérer l'accès des utilisateurs distants
- Si vous utilisez Geo pour accélérer l'accès des utilisateurs distants, mais avez désactivé le proxy

| Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
|-------------------------|-------------------------|----------|
| 15.1 - 16.2             | Tous                     | 16.3 et les versions ultérieures    |

Solution de contournement : une solution de contournement possible consiste à [désactiver le proxy](../../administration/geo/secondary_proxy/_index.md#disable-secondary-site-http-proxying). Le site secondaire ne peut pas servir les fichiers LFS qui n'ont pas été répliqués au moment du clonage.

## 16.1.0 {#1610}

- Une migration en arrière-plan `BackfillPreparedAtMergeRequests` est finalisée avec la migration post-déploiement `FinalizeBackFillPreparedAtMergeRequests`. GitLab 15.10.0 a introduit une [migration en arrière-plan par lots](../background_migrations.md#check-for-pending-database-background-migrations) pour [remplir les valeurs `prepared_at` dans la table `merge_requests`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/111865). Cette migration peut prendre plusieurs jours à s'exécuter sur les instances GitLab de grande taille. Assurez-vous que la migration s'est terminée avec succès avant de mettre à niveau vers la version 16.1.0.
- GitLab 16.1.0 inclut une [migration en arrière-plan par lots](../background_migrations.md#check-for-pending-database-background-migrations) `MarkDuplicateNpmPackagesForDestruction` pour marquer les packages NPM en double pour suppression. Assurez-vous que la migration s'est terminée avec succès avant de mettre à niveau vers la version 16.3.0 ou une version ultérieure.
- Une migration en arrière-plan `BackfillCiPipelineVariablesForBigintConversion` est finalisée avec la migration post-déploiement `EnsureBackfillBigintIdIsCompleted`. GitLab 16.0.0 a introduit une [migration en arrière-plan par lots](../background_migrations.md#check-for-pending-database-background-migrations) pour [remplir les valeurs `bigint` `id` dans la table `ci_pipeline_variables`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/118878). Cette migration peut prendre beaucoup de temps sur les instances GitLab de grande taille (4 heures pour traiter 50 millions de lignes ont été signalées dans un cas). Pour éviter un temps d'arrêt prolongé lors de la mise à niveau, assurez-vous que la migration s'est terminée avec succès avant de passer à la version 16.1.

  Vous pouvez vérifier la taille de la table `ci_pipeline_variables` dans la [console de base de données](../../administration/troubleshooting/postgresql.md#start-a-database-console) :

  ```sql
  select count(*) from ci_pipeline_variables;
  ```

### Installations auto-compilées {#self-compiled-installations-2}

- Vous devez supprimer tous les paramètres liés au Puma worker killer du fichier de configuration `puma.rb`, car ceux-ci ont été [supprimés](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/118645). Pour plus d'informations, consultez le fichier [`puma.rb.example`](https://gitlab.com/gitlab-org/gitlab/-/blob/16-0-stable-ee/config/puma.rb.example).
- En général, les sauvegardes dans les environnements disposant de PgBouncer doivent [contourner PgBouncer en définissant des variables dont le préfixe est `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion régulière à la base de données via PgBouncer au lieu de la connexion directe définie dans le paramètre de remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations Geo {#geo-installations-10}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Des informations spécifiques s'appliquent aux installations utilisant Geo :

- Certaines importations de projets n'initialisent pas les dépôts wiki lors de la création du projet. Consultez [les détails et la solution de contournement](#wiki-repositories-not-initialized-on-project-creation).
- En raison de la migration des designs de projets vers SSF, [les dépôts de designs manquants sont incorrectement signalés comme échouant à la vérification](https://gitlab.com/gitlab-org/gitlab/-/issues/414279). Ce problème n'est pas dû à un échec réel de réplication ou de vérification, mais à un état interne invalide pour ces dépôts manquants dans Geo, ce qui entraîne des erreurs dans les journaux et la progression de la vérification indiquant un état d'échec pour ces dépôts de designs. Vous pourriez être affecté par ce problème même si vous n'avez pas importé de projets.
  - Versions affectées : GitLab versions 16.1.0 - 16.1.2
  - Versions contenant le correctif : GitLab 16.1.3 et les versions ultérieures.
- Les nouveaux artefacts de job ne sont pas répliqués par Geo si les artefacts de job sont configurés pour être stockés dans le stockage d'objets et que `direct_upload` est activé. Ce bug est corrigé dans GitLab versions 16.1.4, 16.2.3, 16.3.0 et les versions ultérieures.
  - Versions affectées : GitLab versions 16.1.0 - 16.1.3 et 16.2.0 - 16.2.2.
  - Lors de l'exécution d'une version affectée, des artefacts qui semblaient être synchronisés peuvent en réalité être manquants sur le site secondaire. Les artefacts affectés sont automatiquement resynchronisés lors de la mise à niveau vers les versions 16.1.5, 16.2.5, 16.3.1, 16.4.0 ou une version ultérieure. Vous pouvez [resynchroniser manuellement les artefacts de job affectés](https://gitlab.com/gitlab-org/gitlab/-/issues/419742#to-fix-data) si nécessaire.
  - Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

#### Dépôts wiki non initialisés lors de la création du projet {#wiki-repositories-not-initialized-on-project-creation}

| Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
|-------------------------|-------------------------|----------|
| 15.11                   | Tous                     | Aucune     |
| 16.0                    | Tous                     | Aucune     |
| 16.1                    | 16.1.0 - 16.1.2         | 16.1.3 et les versions ultérieures |

Certaines importations de projets n'initialisent pas les dépôts wiki lors de la création du projet. Depuis la migration des wikis de projets vers SSF, [les dépôts wiki manquants sont incorrectement signalés comme échouant à la vérification](https://gitlab.com/gitlab-org/gitlab/-/issues/409704). Ce problème n'est pas dû à un échec réel de réplication ou de vérification, mais à un état interne invalide pour ces dépôts manquants dans Geo, ce qui entraîne des erreurs dans les journaux et la progression de la vérification indiquant un état d'échec pour ces dépôts wiki. Si vous n'avez pas importé de projets, vous n'êtes pas affecté par ce problème.

## 16.0.0 {#1600}

- Sidekiq plante s'il y a des caractères non ASCII dans le fichier `/etc/gitlab/gitlab.rb`. Vous pouvez résoudre ce problème en suivant la solution de contournement décrite dans [le ticket 412767](https://gitlab.com/gitlab-org/gitlab/-/issues/412767#note_1404507549).
- Les jobs Sidekiq sont uniquement routés vers les files d'attente `default` et `mailers` par défaut, et par conséquent, chaque processus Sidekiq écoute également ces files d'attente pour s'assurer que tous les jobs sont traités dans toutes les files d'attente. Ce comportement ne s'applique pas si vous avez configuré les [règles de routage](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules).
- Docker 20.10.10 ou une version ultérieure est requis pour exécuter l'image Docker GitLab. Les versions antérieures [génèrent des erreurs au démarrage](../../install/docker/troubleshooting.md#threaderror-cant-create-thread-operation-not-permitted).
- Le registre de conteneurs utilisant le stockage Azure peut être vide avec zéro tag. Vous pouvez résoudre ce problème en suivant les [instructions relatives au changement non rétrocompatible](../deprecations.md#azure-storage-driver-defaults-to-the-correct-root-prefix).
- En général, les sauvegardes dans les environnements disposant de PgBouncer doivent [contourner PgBouncer en définissant des variables dont le préfixe est `GITLAB_BACKUP_`](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer). Cependant, en raison d'un [problème](https://gitlab.com/gitlab-org/gitlab/-/issues/422163), `gitlab-backup` utilise la connexion régulière à la base de données via PgBouncer au lieu de la connexion directe définie dans le paramètre de remplacement, et la sauvegarde de la base de données échoue. La solution de contournement consiste à utiliser `pg_dump` directement.

  **Versions concernées** :

  | Versions mineures concernées | Versions de correctifs concernées | Corrigé dans |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  Tous                    | Aucune     |
  | 16.0                    |  Tous                    | Aucune     |
  | 16.1                    |  Tous                    | Aucune     |
  | 16.2                    |  Tous                    | Aucune     |
  | 16.3                    |  Tous                    | Aucune     |
  | 16.4                    |  Tous                    | Aucune     |
  | 16.5                    |  Tous                    | Aucune     |
  | 16.6                    |  Tous                    | Aucune     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Installations avec le paquet Linux {#linux-package-installations-8}

Des informations spécifiques s'appliquent aux installations avec le package Linux :

- Les binaires pour PostgreSQL 12 ont été supprimés.

  Avant la mise à niveau, les administrateurs des installations par package Linux doivent s'assurer que l'installation utilise [PostgreSQL 13](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server).
- Grafana, qui était inclus avec GitLab, est obsolète et n'est plus pris en charge. Il est supprimé dans GitLab 16.3.
- Cette opération met à niveau `openssh-server` vers `1:8.9p1-3`.

  L'utilisation de `ssh-keyscan -t rsa` avec des clients OpenSSH plus anciens pour obtenir des informations sur les clés publiques n'est plus viable en raison des dépréciations répertoriées dans les [notes de release d'OpenSSH 8.7](https://www.openssh.org/txt/release-8.7).

  La solution de contournement consiste à utiliser un type de clé différent ou à mettre à niveau le client OpenSSH vers une version >= 8.7.
- [Migrez votre configuration Praefect vers la nouvelle structure](#praefect-configuration-structure-change) pour vous assurer que tous vos paramètres `praefect['..']` continuent de fonctionner dans GitLab 16.0 et les versions ultérieures.
- [Migrez votre configuration Gitaly vers la nouvelle structure](#gitaly-configuration-structure-change) pour vous assurer que tous vos paramètres `gitaly['..']` continuent de fonctionner dans GitLab 16.0 et les versions ultérieures.

### Jetons d'accès sans expiration {#non-expiring-access-tokens}

Les jetons d'accès sans date d'expiration sont valides indéfiniment, ce qui constitue un risque de sécurité si le jeton d'accès est divulgué.

Lorsque vous effectuez une mise à niveau vers GitLab 16.0 ou une version ultérieure, tout jeton d'accès [personnel](../../user/profile/personal_access_tokens.md), [de projet](../../user/project/settings/project_access_tokens.md) ou [de groupe](../../user/group/settings/group_access_tokens.md) sans date d'expiration se voit automatiquement attribuer une date d'expiration fixée à un an à compter de la date de mise à niveau.

Avant l'application de cette date d'expiration automatique, vous devez effectuer les opérations suivantes pour minimiser les perturbations :

1. [Identifiez les jetons d'accès sans date d'expiration](../../administration/raketasks/tokens/_index.md#find-tokens-the-rake-tasks-do-not-report).
1. [Attribuez une date d'expiration à ces jetons](../../administration/raketasks/tokens/_index.md#extend-expiration-dates).

Pour plus d'informations, consultez :

- [La documentation sur les dépréciations et les suppressions](../deprecations.md#non-expiring-access-tokens).
- [Le ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/369122).

### Installations Geo {#geo-installations-11}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Des informations spécifiques s'appliquent aux installations utilisant Geo :

- Certaines importations de projets n'initialisent pas les dépôts wiki lors de la création du projet. Consultez [les détails et la solution de contournement](#wiki-repositories-not-initialized-on-project-creation).
- Le clonage des objets LFS depuis le site secondaire télécharge depuis le site principal, même lorsque le site secondaire est entièrement synchronisé. Consultez [les détails et la solution de contournement](#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site).

### Changement de structure de la configuration Gitaly {#gitaly-configuration-structure-change}

La structure de configuration Gitaly dans le package Linux [change](https://gitlab.com/gitlab-org/gitaly/-/issues/4467) dans GitLab 16.0 pour être cohérente avec la structure de configuration Gitaly utilisée dans les installations auto-compilées.

Suite à ce changement, un seul hash sous `gitaly['configuration']` contient la majeure partie de la configuration Gitaly. Certaines options de configuration `gitaly['..']` continuent d'être utilisées par GitLab 16.0 et les versions ultérieures :

- `enable`
- `dir`
- `bin_path`
- `env_directory`
- `env`
- `open_files_ulimit`
- `consul_service_name`
- `consul_service_meta`

Effectuez la migration en déplaçant votre configuration existante sous la nouvelle structure. `git_data_dirs` est pris en charge [jusqu'à GitLab 18.0](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8786). La nouvelle structure est prise en charge à partir de GitLab 15.10.

**Migrer vers la nouvelle structure**

> [!warning]
> Si vous exécutez Gitaly Cluster (Praefect), [migrez d'abord Praefect vers la nouvelle structure de configuration](#praefect-configuration-structure-change). Une fois ce changement testé, procédez avec vos nœuds Gitaly. Si Gitaly est mal configuré dans le cadre du changement de structure de configuration, la [vérification du dépôt](../../administration/gitaly/praefect/configure.md#repository-verification) va [supprimer les métadonnées requises pour le fonctionnement de Gitaly Cluster (Praefect)](https://gitlab.com/gitlab-org/gitaly/-/issues/5529). Pour vous protéger contre les erreurs de configuration, désactivez temporairement la vérification du dépôt dans Praefect.

1. Si vous exécutez Gitaly Cluster (Praefect), assurez-vous que la vérification du dépôt est désactivée sur tous les nœuds Praefect. Configurez `verification_interval: 0`, puis appliquez avec `gitlab-ctl reconfigure`.
1. Pour appliquer la nouvelle structure à votre configuration :
   1. Remplacez `...` par la valeur de l'ancienne clé.
   1. Lors de la configuration de `storage` pour remplacer `git_data_dirs`, ajoutez `/repositories` à la valeur de `path` comme indiqué dans le script suivant. Si vous ne complétez pas cette étape, vos dépôts Git seront inaccessibles jusqu'à ce que la configuration soit corrigée. Cette mauvaise configuration peut entraîner une suppression de métadonnées.
   1. Ignorez les clés pour lesquelles vous n'avez pas configuré de valeur auparavant.
   1. Recommandé. Incluez une virgule finale pour toutes les clés de hash afin que le hash reste valide lors du réordonnancement des clés ou de l'ajout de nouvelles clés.
1. Appliquez le changement avec `gitlab-ctl reconfigure`.
1. Testez la fonctionnalité du dépôt Git dans GitLab.
1. Supprimez les anciennes clés de la configuration une fois la migration terminée, puis relancez `gitlab-ctl reconfigure`.
1. Recommandé, si vous exécutez Gitaly Cluster (Praefect). Rétablissez la [vérification du dépôt](../../administration/gitaly/praefect/configure.md#repository-verification) Praefect en supprimant `verification_interval: 0`.

La nouvelle structure est documentée dans le script suivant, avec les anciennes clés décrites dans un commentaire au-dessus des nouvelles clés.

> [!warning]
> Vérifiez bien votre mise à jour de `storage`. Vous devez ajouter `/repositories` à la valeur de `path`.

```ruby
gitaly['configuration'] = {
  # gitaly['socket_path']
  socket_path: ...,
  # gitaly['runtime_dir']
  runtime_dir: ...,
  # gitaly['listen_addr']
  listen_addr: ...,
  # gitaly['prometheus_listen_addr']
  prometheus_listen_addr: ...,
  # gitaly['tls_listen_addr']
  tls_listen_addr: ...,
  tls: {
    # gitaly['certificate_path']
    certificate_path: ...,
    # gitaly['key_path']
    key_path: ...,
  },
  # gitaly['graceful_restart_timeout']
  graceful_restart_timeout: ...,
  logging: {
    # gitaly['logging_level']
    level: ...,
    # gitaly['logging_format']
    format: ...,
    # gitaly['logging_sentry_dsn']
    sentry_dsn: ...,
    # gitaly['logging_ruby_sentry_dsn']
    ruby_sentry_dsn: ...,
    # gitaly['logging_sentry_environment']
    sentry_environment: ...,
    # gitaly['log_directory']
    dir: ...,
  },
  prometheus: {
    # gitaly['prometheus_grpc_latency_buckets']. The old value was configured as a string
    # such as '[0, 1, 2]'. The new value must be an array like [0, 1, 2].
    grpc_latency_buckets: ...,
  },
  auth: {
    # gitaly['auth_token']
    token: ...,
    # gitaly['auth_transitioning']
    transitioning: ...,
  },
  git: {
    # gitaly['git_catfile_cache_size']
    catfile_cache_size: ...,
    # gitaly['git_bin_path']
    bin_path: ...,
    # gitaly['use_bundled_git']
    use_bundled_binaries: ...,
    # gitaly['gpg_signing_key_path']
    signing_key: ...,
    # gitaly['gitconfig']. This is still an array but the type of the elements have changed.
    config: [
      {
        # Previously the elements contained 'section', and 'subsection' in addition to 'key'. Now
        # these all should be concatenated into just 'key', separated by dots. For example,
        # {section: 'first', subsection: 'middle', key: 'last', value: 'value'}, should become
        # {key: 'first.middle.last', value: 'value'}.
        key: ...,
        value: ...,
      },
    ],
  },
  # Storage was previously configured with the gitaly['storage'] or 'git_data_dirs' parameters. Use
  # the following instructions to migrate. For 'git_data_dirs', migrate only the 'path' to the
  # gitaly['configuration'] and leave the rest untouched.
  storage: [
    {
      # gitaly['storage'][<index>]['name']
      #
      # git_data_dirs[<name>]. The storage name was configured as a key in the map.
      name: ...,
      # gitaly['storage'][<index>]['path']
      #
      # git_data_dirs[<name>]['path']. Use the value from git_data_dirs[<name>]['path'] and append '/repositories' to it.
      #
      # For example, if the path in 'git_data_dirs' was '/var/opt/gitlab/git-data', use
      # '/var/opt/gitlab/git-data/repositories'. The '/repositories' extension was automatically
      # appended to the path configured in `git_data_dirs`.
      path: ...,
    },
  ],
  hooks: {
    # gitaly['custom_hooks_dir']
    custom_hooks_dir: ...,
  },
  daily_maintenance: {
    # gitaly['daily_maintenance_disabled']
    disabled: ...,
    # gitaly['daily_maintenance_start_hour']
    start_hour: ...,
    # gitaly['daily_maintenance_start_minute']
    start_minute: ...,
    # gitaly['daily_maintenance_duration']
    duration: ...,
    # gitaly['daily_maintenance_storages']
    storages: ...,
  },
  cgroups: {
    # gitaly['cgroups_mountpoint']
    mountpoint: ...,
    # gitaly['cgroups_hierarchy_root']
    hierarchy_root: ...,
    # gitaly['cgroups_memory_bytes']
    memory_bytes: ...,
    # gitaly['cgroups_cpu_shares']
    cpu_shares: ...,
    repositories: {
      # gitaly['cgroups_repositories_count']
      count: ...,
      # gitaly['cgroups_repositories_memory_bytes']
      memory_bytes: ...,
      # gitaly['cgroups_repositories_cpu_shares']
      cpu_shares: ...,
    }
  },
  # gitaly['concurrency']. While the structure is the same, the string keys in the array elements
  # should be replaced by symbols as elsewhere. {'key' => 'value'}, should become {key: 'value'}.
  concurrency: ...,
  # gitaly['rate_limiting']. While the structure is the same, the string keys in the array elements
  # should be replaced by symbols as elsewhere. {'key' => 'value'}, should become {key: 'value'}.
  rate_limiting: ...,
  pack_objects_cache: {
    # gitaly['pack_objects_cache_enabled']
    enabled: ...,
    # gitaly['pack_objects_cache_dir']
    dir: ...,
    # gitaly['pack_objects_cache_max_age']
    max_age: ...,
  }
}
```

### Modification de la structure de configuration de Praefect {#praefect-configuration-structure-change}

La structure de configuration de Praefect dans le package Linux [change](https://gitlab.com/gitlab-org/gitaly/-/issues/4467) dans GitLab 16.0 afin d'être cohérente avec la structure de configuration de Praefect utilisée dans les installations compilées manuellement.

Suite à ce changement, un seul hash sous `praefect['configuration']` contient la majeure partie de la configuration de Praefect. Certaines options de configuration `praefect['..']` continuent d'être utilisées par GitLab 16.0 et les versions ultérieures :

- `enable`
- `dir`
- `log_directory`
- `env_directory`
- `env`
- `wrapper_path`
- `auto_migrate`
- `consul_service_name`

Effectuez la migration en déplaçant votre configuration existante sous la nouvelle structure. La nouvelle structure est prise en charge à partir de GitLab 15.9.

**Migrer vers la nouvelle structure**

> [!warning]
> Migrez d'abord Praefect vers la nouvelle structure de configuration. Une fois ce changement testé, [procédez avec vos nœuds Gitaly](#gitaly-configuration-structure-change). Si Gitaly est mal configuré dans le cadre du changement de structure de configuration, la [vérification du dépôt](../../administration/gitaly/praefect/configure.md#repository-verification) va [supprimer les métadonnées requises pour le fonctionnement de Gitaly Cluster (Praefect)](https://gitlab.com/gitlab-org/gitaly/-/issues/5529). Pour vous protéger contre les erreurs de configuration, désactivez temporairement la vérification du dépôt dans Praefect.

1. Lors de l'application de la nouvelle structure à votre configuration :
   - Remplacez `...` par la valeur de l'ancienne clé.
   - Désactivez la vérification des dépôts en utilisant `verification_interval: 0`, comme indiqué dans le script suivant.
   - Ignorez les clés pour lesquelles vous n'avez pas configuré de valeur auparavant.
   - Recommandé. Incluez une virgule finale pour toutes les clés de hash afin que le hash reste valide lors du réordonnancement des clés ou de l'ajout de nouvelles clés.
1. Appliquez le changement avec `gitlab-ctl reconfigure`.
1. Testez la fonctionnalité du dépôt Git dans GitLab.
1. Supprimez les anciennes clés de la configuration une fois la migration terminée, puis relancez `gitlab-ctl reconfigure`.

La nouvelle structure est documentée dans le script suivant, avec les anciennes clés décrites dans un commentaire au-dessus des nouvelles clés.

```ruby
praefect['configuration'] = {
  # praefect['listen_addr']
  listen_addr: ...,
  # praefect['socket_path']
  socket_path: ...,
  # praefect['prometheus_listen_addr']
  prometheus_listen_addr: ...,
  # praefect['tls_listen_addr']
  tls_listen_addr: ...,
  # praefect['separate_database_metrics']
  prometheus_exclude_database_from_default_metrics: ...,
  auth: {
    # praefect['auth_token']
    token: ...,
    # praefect['auth_transitioning']
    transitioning: ...,
  },
  logging: {
    # praefect['logging_format']
    format: ...,
    # praefect['logging_level']
    level: ...,
  },
  failover: {
    # praefect['failover_enabled']
    enabled: ...,
  },
  background_verification: {
    # praefect['background_verification_delete_invalid_records']
    delete_invalid_records: ...,
    # praefect['background_verification_verification_interval']
    #
    # IMPORTANT:
    # As part of reconfiguring Praefect, disable this feature.
    # Read about this as described previously.
    #
    verification_interval: 0,
  },
  reconciliation: {
    # praefect['reconciliation_scheduling_interval']
    scheduling_interval: ...,
    # praefect['reconciliation_histogram_buckets']. The old value was configured as a string
    # such as '[0, 1, 2]'. The new value must be an array like [0, 1, 2].
    histogram_buckets: ...,
  },
  tls: {
    # praefect['certificate_path']
    certificate_path: ...,
   # praefect['key_path']
    key_path: ...,
  },
  database: {
    # praefect['database_host']
    host: ...,
    # praefect['database_port']
    port: ...,
    # praefect['database_user']
    user: ...,
    # praefect['database_password']
    password: ...,
    # praefect['database_dbname']
    dbname: ...,
    # praefect['database_sslmode']
    sslmode: ...,
    # praefect['database_sslcert']
    sslcert: ...,
    # praefect['database_sslkey']
    sslkey: ...,
    # praefect['database_sslrootcert']
    sslrootcert: ...,
    session_pooled: {
      # praefect['database_direct_host']
      host: ...,
      # praefect['database_direct_port']
      port: ...,
      # praefect['database_direct_user']
      user: ...,
      # praefect['database_direct_password']
      password: ...,
      # praefect['database_direct_dbname']
      dbname: ...,
      # praefect['database_direct_sslmode']
      sslmode: ...,
      # praefect['database_direct_sslcert']
      sslcert: ...,
      # praefect['database_direct_sslkey']
      sslkey: ...,
      # praefect['database_direct_sslrootcert']
      sslrootcert: ...,
    }
  },
  sentry: {
    # praefect['sentry_dsn']
    sentry_dsn: ...,
    # praefect['sentry_environment']
    sentry_environment: ...,
  },
  prometheus: {
    # praefect['prometheus_grpc_latency_buckets']. The old value was configured as a string
    # such as '[0, 1, 2]'. The new value must be an array like [0, 1, 2].
    grpc_latency_buckets: ...,
  },
  # praefect['graceful_stop_timeout']
  graceful_stop_timeout: ...,
  # praefect['virtual_storages']. The old value was a hash map but the new value is an array.
  virtual_storage: [
    {
      # praefect['virtual_storages'][VIRTUAL_STORAGE_NAME]. The name was previously the key in
      # the 'virtual_storages' hash.
      name: ...,
      # praefect['virtual_storages'][VIRTUAL_STORAGE_NAME]['nodes'][NODE_NAME]. The old value was a hash map
      # but the new value is an array.
      node: [
        {
          # praefect['virtual_storages'][VIRTUAL_STORAGE_NAME]['nodes'][NODE_NAME]. Use NODE_NAME key as the
          # storage.
          storage: ...,
          # praefect['virtual_storages'][VIRTUAL_STORAGE_NAME]['nodes'][NODE_NAME]['address'].
          address: ...,
          # praefect['virtual_storages'][VIRTUAL_STORAGE_NAME]['nodes'][NODE_NAME]['token'].
          token: ...,
        },
      ],
    }
  ]
}
```

### Désactiver la deuxième connexion à la base de données {#disable-the-second-database-connection}

Dans GitLab 16.0, GitLab utilise par défaut deux connexions à la base de données pointant vers la même base de données PostgreSQL.

PostgreSQL devra peut-être être configuré avec une valeur plus élevée pour `max_connections`. [Une tâche Rake permet de vérifier si cela est nécessaire](https://docs.gitlab.com/omnibus/settings/database/#configuring-multiple-database-connections).

Si PgBouncer est déployé :

- Les pools frontend (y compris les limites de descripteurs de fichiers et `max_client_conn`) sur vos serveurs PgBouncer [devront peut-être être plus grands](../../administration/postgresql/pgbouncer.md#fine-tuning).
- PgBouncer est mono-thread. Les connexions supplémentaires peuvent saturer entièrement un seul démon PgBouncer. [Nous recommandons d'exécuter trois serveurs PgBouncer avec répartition de charge](../../administration/reference_architectures/5k_users.md#configure-pgbouncer) pour tous les déploiements GitLab à grande échelle, notamment pour résoudre ce problème.

Suivez les instructions correspondant à votre type d'installation pour revenir à une connexion unique à la base de données :

{{< tabs >}}

{{< tab title="Package Linux et Docker" >}}

1. Ajoutez ce paramètre dans `/etc/gitlab/gitlab.rb` :

   ```ruby
   gitlab_rails['databases']['ci']['enable'] = false
   ```

1. Exécutez `gitlab-ctl reconfigure`.

Dans un environnement multi-nœuds, ce paramètre doit être mis à jour sur tous les nœuds Rails et Sidekiq.

{{< /tab >}}

{{< tab title="Chart Helm (Kubernetes)" >}}

Définissez la clé `ci.enabled` sur `false` :

```yaml
global:
  psql:
    ci:
      enabled: false
```

{{< /tab >}}

{{< tab title="Auto-compilée (source)" >}}

Supprimez la section `ci:` de `config/database.yml`.

{{< /tab >}}

{{< /tabs >}}

## Modification de données de type utilisateur de longue durée {#long-running-user-type-data-change}

GitLab 16.0 est un arrêt obligatoire pour les grandes instances GitLab disposant d'un grand nombre d'enregistrements dans la table `users`.

Le seuil est de 30 000 utilisateurs, ce qui inclut :

- Les développeurs et autres utilisateurs dans n'importe quel état, y compris actif, bloqué et en attente d'approbation.
- Les comptes de bots pour les jetons d'accès aux projets et aux groupes.

GitLab 16.0 a introduit une [migration en arrière-plan par lots](../background_migrations.md#check-for-pending-database-background-migrations) pour [migrer les valeurs `user_type` de `NULL` vers `0`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/115849). Cette migration peut prendre plusieurs jours à s'effectuer sur les grandes instances GitLab. Assurez-vous que la migration s'est terminée avec succès avant de mettre à niveau vers la version 16.1.0 ou ultérieure.

GitLab 16.1 introduit la migration `FinalizeUserTypeMigration` qui garantit que la migration en arrière-plan `MigrateHumanUserType` de la version 16.0 est terminée, en exécutant de manière synchrone le changement de la version 16.0 lors de la mise à niveau si celle-ci n'est pas terminée.

GitLab 16.2 [implémente une contrainte de base de données `NOT NULL`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/122454) qui échoue si la migration de la version 16.0 n'est pas terminée.

Si la version 16.0 a été ignorée (ou si la migration de la version 16.0 n'est pas terminée), les mises à niveau ultérieures du package Linux (Omnibus) et de Docker peuvent échouer après une heure :

```plaintext
FATAL: Mixlib::ShellOut::CommandTimeout: rails_migration[gitlab-rails]
[..]
Mixlib::ShellOut::CommandTimeout: Command timed out after 3600s:
```

[Il existe une solution de contournement fix-forward pour ce problème](../package/package_troubleshooting.md#error-command-timed-out-after-3600s).

Pendant que la solution de contournement finalise les modifications de la base de données, GitLab sera probablement dans un état inutilisable, générant des erreurs `500`. Les erreurs sont causées par Sidekiq et Puma qui exécutent du code d'application incompatible avec le schéma de la base de données.

À la fin du processus de solution de contournement, Sidekiq et Puma sont redémarrés pour résoudre ce problème.

## Erreur de colonne non définie lors de la mise à niveau vers la version 16.2 ou ultérieure {#undefined-column-error-upgrading-to-162-or-later}

Un bug dans GitLab 15.11 a incorrectement désactivé une modification de base de données sur les instances GitLab Self-Managed. Pour plus d'informations, consultez le [ticket 408835](https://gitlab.com/gitlab-org/gitlab/-/issues/408835).

Si votre instance GitLab a d'abord été mise à niveau vers 15.11.0, 15.11.1 ou 15.11.2, le schéma de base de données est incorrect et la mise à niveau vers GitLab 16.2 ou ultérieur échoue avec une erreur. Une modification de base de données nécessite que la modification antérieure soit en place :

```plaintext
PG::UndefinedColumn: ERROR:  column "id_convert_to_bigint" of relation "ci_build_needs" does not exist
LINE 1: ...db_config_name:main*/ UPDATE "ci_build_needs" SET "id_conver...
```

GitLab 15.11.3 a livré un correctif pour ce bug, mais il ne résout pas le problème sur les instances déjà exécutant les versions antérieures de 15.11.

Si vous n'êtes pas sûr qu'une instance est affectée, vérifiez la colonne sur la [console de base de données](../../administration/troubleshooting/postgresql.md#start-a-database-console) :

```sql
select pg_typeof (id_convert_to_bigint) from public.ci_build_needs limit 1;
```

Si vous avez besoin de la solution de contournement, cette requête échoue :

```plaintext
ERROR:  column "id_convert_to_bigintd" does not exist
LINE 1: select pg_typeof (id_convert_to_bigintd) from public.ci_buil...
```

Les instances non affectées renvoient :

```plaintext
 pg_typeof
-----------
 bigint
```

La solution de contournement pour ce problème diffère selon que le schéma de base de données de votre instance GitLab a été récemment créé :

| Version d'installation | Solution de contournement |
| -------------------- | ---------- |
| 15.9 ou antérieure      | [15.9](#workaround-instance-created-with-159-or-earlier) |
| 15.10                | [15.10](#workaround-instance-created-with-1510) |
| 15.11                | [15.11](#workaround-instance-created-with-1511) |

La plupart des instances doivent utiliser la procédure 15.9. Seules les instances très récentes nécessitent les procédures 15.10 ou 15.11. Si vous avez migré GitLab à l'aide d'une sauvegarde et d'une restauration, le schéma de base de données provient de l'instance d'origine. Sélectionnez la solution de contournement en fonction de l'instance source.

Les commandes dans les sections suivantes sont destinées aux installations avec le package Linux et diffèrent pour les autres types d'installation :

{{< tabs >}}

{{< tab title="Docker" >}}

- Omettez `sudo`
- Ouvrez un shell dans le conteneur GitLab et exécutez les mêmes commandes :

  ```shell
  docker exec -it <container-id> bash
  ```

{{< /tab >}}

{{< tab title="Auto-compilée (source)" >}}

- Utilisez `sudo -u git -H bundle exec rake RAILS_ENV=production` à la place de `sudo gitlab-rake`
- Exécutez le SQL sur [votre console de base de données PostgreSQL](../../administration/troubleshooting/postgresql.md#start-a-database-console)

{{< /tab >}}

{{< tab title="Chart Helm (Kubernetes)" >}}

- Omettez `sudo`.
- Ouvrez un shell dans le pod `toolbox` pour exécuter les commandes Rake : `gitlab-rake` se trouve dans `/usr/local/bin` s'il n'est pas dans le `PATH`.
  - Consultez notre [aide-mémoire Kubernetes](https://docs.gitlab.com/charts/troubleshooting/kubernetes_cheat_sheet/#gitlab-specific-kubernetes-information) pour plus de détails.
- Exécutez le SQL sur [votre console de base de données PostgreSQL](../../administration/troubleshooting/postgresql.md#start-a-database-console)

{{< /tab >}}

{{< /tabs >}}

### Solution de contournement : instance créée avec la version 15.9 ou antérieure {#workaround-instance-created-with-159-or-earlier}

```shell
# Restore schema
sudo gitlab-psql -c "DELETE FROM schema_migrations WHERE version IN ('20230130175512', '20230130104819');"
sudo gitlab-rake db:migrate:up VERSION=20230130175512
sudo gitlab-rake db:migrate:up VERSION=20230130104819

# Re-schedule background migrations
sudo gitlab-rake db:migrate:down VERSION=20230130202201
sudo gitlab-rake db:migrate:down VERSION=20230130110855
sudo gitlab-rake db:migrate:up VERSION=20230130202201
sudo gitlab-rake db:migrate:up VERSION=20230130110855
```

### Solution de contournement : instance créée avec la version 15.10 {#workaround-instance-created-with-1510}

```shell
# Restore schema for sent_notifications
sudo gitlab-psql -c "DELETE FROM schema_migrations WHERE version = '20230130175512';"
sudo gitlab-rake db:migrate:up VERSION=20230130175512

# Re-schedule background migration for sent_notifications
sudo gitlab-rake db:migrate:down VERSION=20230130202201
sudo gitlab-rake db:migrate:up VERSION=20230130202201

# Restore schema for ci_build_needs
sudo gitlab-rake db:migrate:down VERSION=20230321163547
sudo gitlab-psql -c "INSERT INTO schema_migrations (version) VALUES ('20230321163547');"
```

### Solution de contournement : instance créée avec la version 15.11 {#workaround-instance-created-with-1511}

```shell
# Restore schema for sent_notifications
sudo gitlab-rake db:migrate:down VERSION=20230411153310
sudo gitlab-psql -c "INSERT INTO schema_migrations (version) VALUES ('20230411153310');"

# Restore schema for ci_build_needs
sudo gitlab-rake db:migrate:down VERSION=20230321163547
sudo gitlab-psql -c "INSERT INTO schema_migrations (version) VALUES ('20230321163547');"
```
