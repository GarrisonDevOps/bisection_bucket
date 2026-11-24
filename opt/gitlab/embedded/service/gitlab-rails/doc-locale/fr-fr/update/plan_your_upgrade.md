---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Avant de mettre à niveau
description: Étapes à suivre avant de procéder à la mise à niveau.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Avant de mettre à niveau une instance GitLab, vous devez :

1. Rassembler les informations préalables à la mise à niveau pour vous y préparer.
1. Effectuer les étapes préalables à la mise à niveau avant de mettre à niveau GitLab lui-même.

## Rassembler les informations préalables à la mise à niveau {#gather-pre-upgrade-information}

Lors de la planification de la mise à niveau :

1. Consultez la [politique de release et de maintenance de GitLab](../policy/maintenance.md).
1. Consultez les [notes de mise à niveau de GitLab](versions/_index.md) pour les différentes versions de GitLab afin d'assurer la compatibilité.
1. Le cas échéant, vérifiez la [compatibilité du système d'exploitation avec la version cible de GitLab](../install/package/_index.md).
1. Si vous utilisez Geo :
   - Consultez la [documentation de mise à niveau de Geo](../administration/geo/replication/upgrading_the_geo_sites.md).
   - Consultez les informations spécifiques à Geo dans les [notes de mise à niveau de GitLab](versions/_index.md).
   - Consultez les étapes spécifiques à Geo lors de la [mise à niveau de la base de données](https://docs.gitlab.com/omnibus/settings/database/#upgrading-a-geo-instance).
   - Créez un plan de mise à niveau et de rollback pour chaque site Geo (le site primaire et chaque site secondaire).
1. Déterminez le [chemin de mise à niveau](upgrade_paths.md) approprié pour votre instance, y compris les arrêts de mise à niveau requis. Les arrêts de mise à niveau peuvent nécessiter d'effectuer plusieurs mises à niveau.
1. Exécutez les [vérifications d'intégrité de mise à niveau](#run-upgrade-health-checks) pour détecter et résoudre les problèmes potentiels en amont. Incluez les vérifications d'intégrité de la base de données, car certains problèmes de base de données prennent du temps à résoudre.
1. Créez un plan de mise à niveau qui documente :
   - Les étapes à suivre pour mettre à niveau votre instance, y compris, si possible et nécessaire, une [mise à niveau sans interruption de service](zero_downtime.md).
   - Les étapes à suivre si la mise à niveau ne se déroule pas correctement, notamment comment [effectuer un rollback de GitLab si nécessaire](#create-a-rollback-plan-and-backup).
1. Testez votre plan de mise à niveau sur un clone de votre environnement de production. Cela permet de réduire le risque d'interruptions imprévues et de mesurer la durée des [migrations potentiellement longues](background_migrations.md#execute-a-migration).

Une fois toutes les informations préalables à la mise à niveau rassemblées, vous pouvez passer à l'exécution des étapes préalables à la mise à niveau.

### Créer un plan de rollback et une sauvegarde {#create-a-rollback-plan-and-backup}

Un problème peut survenir lors d'une mise à niveau. Il est donc essentiel de disposer d'un plan de rollback. Un plan de rollback approprié crée un chemin clair pour ramener une instance GitLab à son dernier état fonctionnel et comprend :

- Le processus de sauvegarde de l'instance.
- Le processus de restauration de l'instance.

Vous devriez tester le plan de rollback avant d'en avoir besoin. Pour une vue d'ensemble des étapes requises pour effectuer un rollback, consultez [revenir à des versions antérieures de GitLab](package/downgrade.md).

#### Créer une sauvegarde GitLab {#create-a-gitlab-backup}

Pour pouvoir effectuer un rollback de GitLab en cas de problème lors de la mise à niveau, vous pouvez :

- Créer une [sauvegarde GitLab](../administration/backup_restore/_index.md). Vous devez suivre les instructions correspondant à votre méthode d'installation et vous assurer de sauvegarder les [secrets et les fichiers de configuration](../administration/backup_restore/backup_gitlab.md#storing-configuration-files).
- Créer un instantané de votre instance. Si votre instance est une installation multi-nœuds, vous devez créer un instantané de chaque nœud. Ce processus ne relève pas du périmètre du support GitLab.

#### Effectuer un rollback de GitLab {#roll-back-gitlab}

Si vous disposez d'un environnement de test qui reproduit la production, testez la restauration pour vous assurer que tout fonctionne comme prévu.

Pour restaurer votre sauvegarde GitLab :

1. Consultez les [prérequis de restauration](../administration/backup_restore/restore_gitlab.md#restore-prerequisites). Plus important encore, les versions de l'instance GitLab sauvegardée et de la nouvelle instance GitLab doivent être identiques.
1. [Restaurez GitLab](../administration/backup_restore/_index.md#restore-gitlab) en suivant les instructions correspondant à votre méthode d'installation.
1. Vérifiez que les [secrets et les fichiers de configuration](../administration/backup_restore/backup_gitlab.md#storing-configuration-files) sont également restaurés.

Si vous effectuez une restauration à partir d'un instantané, vous devez déjà savoir comment procéder. Ce processus ne relève pas du périmètre du support GitLab.

## Effectuer les étapes préalables à la mise à niveau {#perform-pre-upgrade-steps}

Peu avant d'effectuer la mise à niveau :

1. Réexécutez les [vérifications d'intégrité de mise à niveau](#run-upgrade-health-checks), y compris les vérifications d'intégrité de la base de données.
1. Effectuez les [mises à niveau pour les fonctionnalités optionnelles](#upgrades-for-optional-features) que vous utilisez.

### Exécuter les vérifications d'intégrité de mise à niveau {#run-upgrade-health-checks}

Immédiatement avant et après la mise à niveau, exécutez des vérifications d'intégrité de mise à niveau pour vous assurer que les principaux composants de GitLab fonctionnent :

1. [Vérifiez la configuration générale](../administration/raketasks/maintenance.md#check-gitlab-configuration) :

   ```shell
   sudo gitlab-rake gitlab:check
   ```

1. Vérifiez le statut de toutes les [migrations de base de données en arrière-plan](background_migrations.md). Toutes les migrations doivent se terminer avant chaque mise à niveau. Vous devez espacer les mises à niveau entre les versions majeures et mineures pour laisser le temps aux migrations en arrière-plan de se terminer.
1. Vérifiez que les valeurs chiffrées de la base de données [peuvent être déchiffrées](../administration/raketasks/check.md#verify-database-values-can-be-decrypted-using-the-current-secrets) :

   ```shell
   sudo gitlab-rake gitlab:doctor:secrets
   ```

1. [Vérifiez l'intégrité de la base de données](#check-database-health).
1. Dans l'interface utilisateur de GitLab, vérifiez que :
   - Les utilisateurs peuvent se connecter.
   - La liste des projets est visible.
   - Les tickets et les merge requests du projet sont accessibles.
   - Les utilisateurs peuvent cloner des dépôts depuis GitLab.
   - Les utilisateurs peuvent pousser des commits vers GitLab.

1. Pour GitLab CI/CD, vérifiez que :
   - Les runners prennent en charge les jobs.
   - Les images Docker peuvent être poussées et extraites depuis le registre.

1. Si vous utilisez Geo, exécutez les vérifications appropriées sur le site primaire et sur chaque site secondaire :

   ```shell
   sudo gitlab-rake gitlab:geo:check
   ```

1. Si vous utilisez Elasticsearch, vérifiez que les recherches aboutissent.
1. Facultatif. [Pré-téléchargez un package depuis le dépôt officiel](package/_index.md#pre-download-a-package-from-the-official-repository) pour tester la disponibilité du package et réduire le temps d'installation.

En cas de problème, [obtenez de l'aide](#get-support).

### Vérifier l'intégrité de la base de données {#check-database-health}

Les migrations de base de données s'exécutent pendant la mise à niveau. Elles s'attendent à ce que le schéma de la base de données corresponde au schéma de votre version actuelle de GitLab et ont besoin de verrous sur les tables qu'elles modifient. Utilisez la page Diagnostic de la base de données pour détecter les problèmes susceptibles de provoquer l'échec des migrations.

Prérequis :

- Vous devez disposer d'un accès administrateur.

Pour vérifier l'intégrité de la base de données :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Surveillance** > **Diagnostic de la base de données**.
1. Dans la section **État des services du schéma**, sélectionnez **Lancer une vérification de schéma**. La vérification s'exécute en tant que job en arrière-plan, Sidekiq doit donc être en cours d'exécution. La page affiche les résultats à la fin du job. Les résultats restent disponibles pendant une semaine. Réexécutez la vérification peu avant d'effectuer la mise à niveau.
1. Passez en revue les résultats et prenez les mesures nécessaires avant d'effectuer la mise à niveau :

   | Section   | Problème   | Action   |
   |-----------|-----------|----------|
   | **État des services du schéma** | La vérification signale des tables, index, clés étrangères ou séquences manquants, ou des propriétaires de séquences incorrects. Les migrations qui dépendent de ces objets peuvent échouer. | Aucun outil de réparation automatisé n'est disponible. Contactez le support GitLab avant d'effectuer la mise à niveau. Pour plus d'informations, consultez [l'état des services du schéma](../administration/admin_area.md#schema-health-check). |
   | **Chemin de recherche** | Une erreur indique que plusieurs schémas dans le chemin de recherche contiennent des objets GitLab. Les migrations peuvent modifier des objets dans le mauvais schéma. | Avant d'effectuer la mise à niveau, assurez-vous que seul le schéma principal dans le chemin de recherche contient des objets GitLab. Pour obtenir de l'aide, contactez le support GitLab. Pour plus d'informations, consultez [la vérification du chemin de recherche](../administration/admin_area.md#search-path-check). |
   | **Informations relatives à l'opération de nettoyage de type VACUUM** | Un vacuum possède le badge **Anti-retour à zéro des ID de transaction**. Ce vacuum ne s'annule pas lui-même, de sorte que les migrations peuvent attendre ses verrous et échouer. | Ne lancez pas la mise à niveau et n'arrêtez pas le vacuum. Attendez que le vacuum se termine. Pour plus d'informations, consultez [Surveiller l'autovacuum](../administration/postgresql/vacuum.md#database-diagnostics-page). |

La section **Informations relatives à l'opération de nettoyage de type VACUUM** affiche les vacuums en cours d'exécution. Vérifiez à nouveau cette section immédiatement avant de démarrer la mise à niveau.

Si vous n'avez pas accès à l'interface utilisateur, vous pouvez vérifier le chemin de recherche depuis la console :

```shell
sudo gitlab-rake gitlab:db:diagnostics:search_path
```

La tâche se termine avec le statut `1` lorsqu'elle détecte une erreur.

### Mises à niveau pour les fonctionnalités optionnelles {#upgrades-for-optional-features}

Selon la configuration de votre instance GitLab, vous pourriez être amené à effectuer ces étapes supplémentaires avant de mettre à niveau GitLab :

1. Si vous utilisez des serveurs Gitaly externes, mettez à niveau les serveurs Gitaly vers la version plus récente avant de mettre à niveau GitLab lui-même. Cela empêche le client gRPC du serveur d'application d'envoyer des RPC que l'ancienne version de Gitaly ne prend pas en charge.
1. Si vous avez des clusters Kubernetes connectés à GitLab, [mettez à niveau vos agents GitLab pour Kubernetes](../user/clusters/agent/install/_index.md#update-the-agent-version) afin de correspondre à votre nouvelle version de GitLab.
1. Si vous utilisez la recherche avancée (Elasticsearch), confirmez que les migrations de recherche avancée sont terminées en [vérifiant les migrations en attente](background_migrations.md#check-for-pending-advanced-search-migrations). [La tâche Rake `gitlab:check`](../integration/advanced_search/elasticsearch.md#all-migrations-must-be-finished-before-doing-a-major-upgrade) indique également si des migrations de recherche avancée sont en attente. La vérification n'arrête pas une mise à niveau. Vous devez donc lire la sortie et agir en conséquence.

   Après la mise à niveau de GitLab, vous pourriez avoir à mettre à niveau [Elasticsearch si la nouvelle version rompt la compatibilité](../integration/advanced_search/elasticsearch.md#version-compatibility). La mise à jour d'Elasticsearch ne relève pas du périmètre du support GitLab.

## Mettre en pause les pipelines CI/CD et les jobs {#pause-cicd-pipelines-and-jobs}

Lors des mises à niveau pour la plupart des types d'instances GitLab, vous devez mettre en pause les pipelines CI/CD et les jobs.

Si vous mettez à niveau votre instance GitLab pendant que GitLab Runner traite des jobs, les mises à jour de trace échouent. Lorsque GitLab est de nouveau en ligne, les mises à jour de trace devraient se réparer automatiquement. Si une mise à jour de trace ne se répare pas automatiquement, selon l'erreur, GitLab Runner réessaie ou met fin au traitement du job.

GitLab Runner tente de télécharger les artefacts de job trois fois, après quoi le job échoue.

Pour mettre en pause les pipelines CI/CD et les jobs :

1. Mettez en pause les runners.
1. Bloquez le démarrage de nouveaux jobs en ajoutant ce qui suit à votre fichier `/etc/gitlab/gitlab.rb` :

   ```ruby
   nginx['custom_gitlab_server_config'] = "location = /api/v4/jobs/request {\n deny all;\n return 503;\n}\n"
   ```

1. Reconfigurez GitLab :

   ```shell
   sudo gitlab-ctl reconfigure
   ```

1. Attendez que tous les jobs soient terminés.

Une fois votre mise à niveau GitLab terminée :

1. Réactivez vos runners.
1. Débloquez le démarrage de nouveaux jobs en annulant la modification précédente du fichier `/etc/gitlab/gitlab.rb`.

## Travailler avec le support {#working-with-support}

Si vous [travaillez avec le support](https://about.gitlab.com/support/scheduling-upgrade-assistance/) pour examiner votre plan de mise à niveau, documentez-le et partagez-le avec les réponses aux questions suivantes :

- Comment GitLab est-il installé ?
- Quel est le système d'exploitation du nœud ? Vérifiez les [plateformes prises en charge](../install/package/_index.md#supported-platforms) pour confirmer que des mises à jour ultérieures sont disponibles.
- S'agit-il d'une configuration à nœud unique ou à plusieurs nœuds ? Si c'est multi-nœuds, documentez et partagez tous les détails architecturaux de chaque nœud. Quels composants externes sont utilisés ? Par exemple, Gitaly, PostgreSQL ou Redis ?
- Utilisez-vous [Geo](../administration/geo/_index.md) ? Si oui, documentez et partagez tous les détails architecturaux de chaque site secondaire.
- Qu'est-ce qui pourrait être unique ou intéressant dans votre configuration et qui pourrait être important ?
- Rencontrez-vous des problèmes connus avec votre version actuelle de GitLab ?
- Que rapportent les vérifications d'intégrité de la base de données ? Enregistrez le rapport de diagnostic de la base de données dans un fichier et partagez ce fichier avec les résultats de l'**État des services du schéma** :

  ```shell
  sudo gitlab-rake gitlab:db:diagnostics > db_diagnostics.txt
  ```

## Obtenir de l'aide {#get-support}

Si un problème survient lors de votre mise à niveau :

1. Copiez toutes les erreurs et rassemblez tous les journaux pour les analyser ultérieurement. Utilisez les outils suivants pour vous aider à collecter des données :
   - [`gitlabsos`](https://gitlab.com/gitlab-com/support/toolbox/gitlabsos) si vous avez installé GitLab avec le package Linux ou Docker.
   - [`kubesos`](https://gitlab.com/gitlab-com/support/toolbox/kubesos/) si vous avez installé GitLab à l'aide des charts Helm.
   - `sudo gitlab-rake gitlab:db:diagnostics > db_diagnostics.txt` si le problème concerne la base de données.
1. Effectuez un rollback vers la dernière version fonctionnelle.

Pour obtenir de l'aide :

- [Contactez le support GitLab](https://support.gitlab.com/hc/en-us) et votre Customer Success Manager, si vous en avez un.
- Si [la situation le justifie](https://support.gitlab.com/hc/en-us/articles/11626416629660-Definitions#definitions-of-support-impact) et que [votre plan inclut le support d'urgence](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#priority-support), créez un ticket d'urgence.
