---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Comprendre comment la taille du dépôt est calculée et affichée, les limites de taille et les méthodes pour réduire le stockage du dépôt Git."
title: Taille du dépôt
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

La taille d'un dépôt Git peut avoir un impact significatif sur les performances et les coûts de stockage. Elle peut différer légèrement d'une instance à une autre en raison de la compression, de la maintenance et d'autres facteurs.

## Calcul de la taille {#size-calculation}

La taille du dépôt correspond à la taille cumulée de tous les fichiers qu'il contient. Ce calcul est similaire à l'exécution de `du --summarize --bytes` sur le [chemin de stockage haché](../../../administration/repository_storage_paths.md) de votre dépôt. La taille est recalculée à chaque modification du dépôt, mais au maximum une fois toutes les 15 minutes.

La taille du dépôt est un sous-ensemble de la taille du projet. La taille du projet, indiquée sur la page d'aperçu du projet sous **Informations sur le projet**, inclut le dépôt ainsi que les objets LFS, les artefacts de job, les packages et le wiki.

### Afficher la taille du dépôt {#view-repository-size}

Prérequis :

- Le rôle Maintainer ou Owner pour le projet, ou le rôle Owner pour l'espace de nommage.

Pour afficher la taille du dépôt :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Quotas d'utilisation**.
1. Sélectionnez l'onglet **Stockage**.
1. Dans la répartition de l'utilisation, consultez la valeur dans la ligne **Dépôt**.

Pour plus d'informations sur le stockage utilisé par un projet, consultez [le stockage](../../storage_usage_quotas.md).

## Limites de taille et de stockage {#size-and-storage-limits}

Les administrateurs peuvent définir une [limite de taille de dépôt](../../../administration/settings/account_and_limit_settings.md#repository-size-limit) pour GitLab Self-Managed. Pour GitLab.com, les limites de taille sont [prédéfinies](../../gitlab_com/_index.md#account-and-limit-settings).

Lorsqu'un projet atteint sa limite de taille, certaines opérations telles que les pushs, la création de merge requests et l'envoi d'objets LFS sont restreintes.

## Avant de réécrire l'historique Git {#before-you-rewrite-git-history}

Avant de réécrire l'historique Git et de supprimer des données d'un dépôt, vous devez prendre en compte les informations des sections suivantes.

### Les clones locaux doivent être modifiés {#local-clones-must-be-changed}

Toute personne disposant d'un clone du dépôt doit soit :

- Supprimer sa copie locale et cloner une nouvelle copie du dépôt.
- Récupérer toutes les modifications distantes et s'assurer que tout le travail en cours est rebasé sur celles-ci.

Si cette opération n'est pas effectuée correctement, les utilisateurs qui envoient des modifications locales peuvent réactiver des fichiers censés avoir été supprimés.

### Les pipelines en cours d'exécution peuvent entraîner l'échec du nettoyage {#running-pipelines-can-cause-cleanup-to-fail}

Lorsque des pipelines sont encore en cours d'exécution lors d'un nettoyage, ils peuvent interagir avec le dépôt et empêcher le bon déroulement du nettoyage.

### Délai de grâce pour la collecte des déchets {#garbage-collection-grace-period}

GitLab exécute la collecte des déchets Git avec un délai de grâce de 30 minutes. Ce processus nettoie les objets qui répondent aux deux conditions suivantes :

- Non accessible depuis aucune référence.
- Âgé d'au moins 30 minutes.

Si les données que vous souhaitez supprimer sont accessibles depuis un commit ou ont moins de 30 minutes, la collecte des déchets Git ne les supprimera pas.

Par conséquent, vous devez attendre au moins 30 minutes avant de sélectionner **Élaguer les objets inaccessibles** après avoir exécuté la maintenance.

### L'historique ne peut pas être réécrit sur un projet dupliqué {#history-cannot-be-rewritten-on-forked-project}

Les méthodes intégrées ne peuvent pas être utilisées sur des dépôts qui ont été dupliqués. La façon dont les objets GitLab sont stockés dans les duplications rend impossible pour Git la collecte des objets partagés entre les duplications.

### Solution de contournement : archiver le projet {#workaround-archive-the-project}

Si vous [archivez](../working_with_projects.md#archive-a-project) le projet avant d'effectuer le nettoyage, le dépôt sera en lecture seule. Cela garantit que personne ne peut apporter de modifications pendant le nettoyage.

L'archivage d'un dépôt supprimera également la relation de duplication. Cela signifie que vous pouvez nettoyer les données. Mais si les données ont été récupérées dans une duplication, le nettoyage devra également y être effectué.

## Méthodes pour réduire la taille du dépôt {#methods-to-reduce-repository-size}

Les méthodes suivantes sont disponibles pour réduire la taille d'un dépôt :

- [Purger les fichiers de l'historique](#purge-files-from-repository-history) : supprimer les fichiers volumineux de l'intégralité de l'historique Git.
- [Nettoyer le dépôt](#clean-up-repository) : supprimer les références Git internes et les objets non référencés.
- [Supprimer les objets blob](#remove-blobs) : supprimer définitivement les blobs contenant des informations sensibles ou confidentielles.

Avant de réduire la taille de votre dépôt, vous devriez [créer une sauvegarde complète de votre dépôt](../../../administration/backup_restore/_index.md). Ces méthodes sont irréversibles et peuvent potentiellement affecter l'historique et les données de votre projet.

Lorsque vous réduisez la taille de votre dépôt avec l'une des méthodes disponibles, vous n'avez pas besoin de bloquer l'accès à votre projet. Vous pouvez effectuer ces opérations pendant que votre projet reste accessible aux utilisateurs. Ces méthodes n'ont aucune incidence connue sur les performances et ne provoquent pas d'interruption de service. Cependant, vous devriez effectuer ces actions pendant les périodes de faible activité afin de minimiser l'impact potentiel sur les utilisateurs.

### Purger les fichiers de l'historique du dépôt {#purge-files-from-repository-history}

Vous pouvez [purger les fichiers avec `git filter-repo`](../../../topics/git/repository.md#purge-files-from-repository-history) pour supprimer les fichiers volumineux de l'historique Git. N'utilisez pas cette méthode pour supprimer des données sensibles telles que des mots de passe ou des clés. Utilisez plutôt [la suppression des blobs](#remove-blobs) ou [l'expurgation du texte](#redact-text-from-repository).

Ce processus :

- Modifie l'intégralité de l'historique Git.
- Peut affecter les merge requests ouvertes.
- Peut affecter les pipelines existants.
- Nécessite de recloner les dépôts locaux.
- N'affecte pas les objets LFS.
- Ne spécifie pas les signatures de commit.
- Est irréversible.

> [!note]
> Les informations sur les commits, y compris le contenu des fichiers, sont mises en cache dans la base de données et restent visibles même après leur suppression du dépôt.

### Nettoyer le dépôt {#clean-up-repository}

Utilisez cette méthode pour supprimer les références Git internes et les objets non référencés de votre dépôt. N'utilisez pas cette méthode pour supprimer des données sensibles. Pour supprimer des données sensibles, utilisez la [méthode de suppression des blobs](#remove-blobs).

Ce processus :

- Exécute `git gc --prune=30.minutes.ago` pour supprimer les objets non référencés.
- Dissocie les objets LFS inutilisés, libérant ainsi de l'espace de stockage.
- Recalcule la taille du dépôt sur le disque.
- Est irréversible.

> [!warning]
> La suppression des références Git internes entraîne l'indisponibilité des commits de merge request associés, des pipelines et des détails des modifications.

Prérequis :

- La liste des objets à supprimer. Utilisez [`git filter-repo`](https://github.com/newren/git-filter-repo) pour produire une liste d'objets dans un fichier `commit-map`.

Pour nettoyer un dépôt :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez à **Paramètres** > **Dépôt**.
1. Développez **Maintenance du dépôt**.
1. Importez la liste des objets à supprimer. Par exemple, le fichier `commit-map` dans le répertoire `filter-repo`.

   Si votre fichier `commit-map` est trop volumineux, le processus de nettoyage en arrière-plan peut expirer et échouer. Par conséquent, la taille du dépôt n'est pas réduite comme prévu. Pour remédier à cela, divisez le fichier et importez-le en plusieurs parties. Commencez avec `20000` et réduisez si nécessaire. Par exemple :

   ```shell
   split -l 20000 filter-repo/commit-map filter-repo/commit-map-
   ```

1. Sélectionnez **Lancer le nettoyage**.

GitLab envoie une notification par e-mail avec la taille du dépôt recalculée une fois le nettoyage terminé.

## Supprimer des données d'un dépôt {#remove-data-from-a-repository}

Pour supprimer des données sensibles ou confidentielles d'un dépôt, utilisez l'une de ces méthodes :

- Pour supprimer complètement les fichiers, [supprimez les blobs](#remove-blobs).
- Pour conserver les fichiers, mais remplacer le texte confidentiel par le texte de remplacement `***REMOVED***`, [expurgez le texte](#redact-text-from-repository).

### Supprimer les objets blob {#remove-blobs}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/450701) dans GitLab 17.1 [avec le feature flag](../../../administration/feature_flags/_index.md) `rewrite_history_ui`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/462999) dans GitLab 17.2.
- [Activé sur GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/462999) dans GitLab 17.3.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/472018) dans GitLab 17.9. Suppression du feature flag `rewrite_history_ui`.

{{< /history >}}

Un objet binaire volumineux Git (blob) stocke le contenu des fichiers sans métadonnées. Chaque blob possède un hachage SHA unique qui représente une version spécifique d'un fichier dans le dépôt.

Utilisez cette méthode pour supprimer définitivement les blobs contenant des informations sensibles ou confidentielles.

Ce processus :

- Réécrit l'historique Git.
- Supprime les signatures de commit.
- Peut entraîner l'échec de la fusion des merge requests ouvertes, nécessitant un rebase manuel.
- Peut entraîner l'interruption des pipelines référençant d'anciens SHA de commit.
- Peut affecter les tags et branches historiques basés sur l'ancien historique de commit.
- Nécessite de recloner les dépôts locaux.
- Est irréversible.

> [!note]
> Vous pouvez également remplacer des chaînes par la chaîne de remplacement `***REMOVED***`. Pour plus d'informations, consultez [expurger le texte du dépôt](#redact-text-from-repository).

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le projet.
- [Une liste d'identifiants d'objets](#get-a-list-of-object-ids) à supprimer.
- Votre projet ne doit pas être :
  - Une duplication d'un projet public en amont.
  - Un projet public en amont avec des duplications en aval.

> [!note]
> Pour garantir la réussite de la suppression des blobs, envisagez de restreindre temporairement l'accès au dépôt pendant le processus. Les nouveaux commits envoyés pendant la suppression des blobs peuvent entraîner l'échec de l'opération.

Pour supprimer des blobs de votre dépôt :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Maintenance du dépôt**.
1. Sélectionnez **Supprimer les objets blob**.
1. Saisissez une liste d'identifiants de blobs à supprimer, chaque identifiant sur sa propre ligne.
1. Sélectionnez **Supprimer les objets blob**.
1. Dans la boîte de dialogue de confirmation, saisissez le chemin de votre projet.
1. Sélectionnez **Oui, supprimer les blobs**.
1. Attendez que la suppression des blobs soit terminée avant de continuer :
   - Si les [notifications par e-mail](../../profile/notifications.md) sont activées, attendez de recevoir un e-mail indiquant que la réécriture de l'historique du dépôt est terminée.
   - Si les notifications par e-mail ne sont pas activées, attendez au moins 5 minutes.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section intitulée **Paramètres avancés**.
1. Sélectionnez **Démarrer la maintenance**. Attendez au moins 30 minutes que l'opération se termine.
1. Dans la même section **Paramètres** > **Général** > **Paramètres avancés**, sélectionnez **Élaguer les objets inaccessibles**. Cette opération prend environ 5 à 10 minutes.

> [!note]
> Si le projet contenant les informations sensibles a été dupliqué, la tâche de maintenance peut réussir sans terminer ce processus. La maintenance doit maintenir l'intégrité du [dépôt de pool d'objets spécial](../../../administration/housekeeping.md#object-pool-repositories), qui contient les données dupliquées. Pour obtenir de l'aide, contactez le support GitLab.

#### Obtenir une liste d'identifiants d'objets {#get-a-list-of-object-ids}

Pour supprimer des blobs, vous avez besoin d'une liste d'objets à supprimer. Pour obtenir ces identifiants, utilisez la commande `ls-tree` ou le [point de terminaison de l'API de liste de l'arborescence du dépôt](../../../api/repositories.md#list-all-repository-trees-in-a-project). Les instructions suivantes utilisent la commande `ls-tree`.

Prérequis :

- Le dépôt doit être cloné sur votre machine locale.

Pour obtenir une liste des blobs à un commit ou une branche donnés, triés par taille :

1. Ouvrez un terminal et accédez au répertoire de votre dépôt.
1. Exécutez la commande suivante :

   ```shell
   git ls-tree -r -t --long --full-name <COMMIT/BRANCH> | sort -nk 4
   ```

   Exemple de résultat :

   ```plaintext
   100644 blob 8150ee86f923548d376459b29afecbe8495514e9  133508 doc/howto/img/remote-development-new-workspace-button.png
   100644 blob cde4360b3d3ee4f4c04c998d43cfaaf586f09740  214231 doc/howto/img/dependency_proxy_macos_config_new.png
   100644 blob 2ad0e839a709e73a6174e78321e87021b20be445  216452 doc/howto/img/gdk-in-gitpod.jpg
   100644 blob 115dd03fc0828a9011f012abbc58746f7c587a05  242304 doc/howto/img/gitpod-button-repository.jpg
   100644 blob c41ebb321a6a99f68ee6c353dd0ed29f52c1dc80  491158 doc/howto/img/dependency_proxy_macos_config.png
   ```

   La troisième colonne du résultat est l'identifiant d'objet du blob. Par exemple : `8150ee86f923548d376459b29afecbe8495514e9`.

### Expurger le texte du dépôt {#redact-text-from-repository}

{{< history >}}

- Introduit dans GitLab 17.1 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `rewrite_history_ui`. Fonctionnalité désactivée par défaut. Les membres de l'équipe GitLab peuvent consulter plus d'informations dans ce ticket confidentiel : `https://gitlab.com/gitlab-org/gitlab/-/issues/450701`.
- Activé sur GitLab.com dans le ticket confidentiel `https://gitlab.com/gitlab-org/gitlab/-/issues/462999` dans GitLab 17.2.
- Activé sur GitLab Self-Managed et GitLab Dedicated dans le ticket confidentiel `https://gitlab.com/gitlab-org/gitlab/-/issues/462999` dans GitLab 17.3.
- Généralement disponible dans le ticket confidentiel `https://gitlab.com/gitlab-org/gitlab/-/issues/472018` dans GitLab 17.9. Suppression du feature flag `rewrite_history_ui`.

{{< /history >}}

Supprimez définitivement les informations sensibles ou confidentielles accidentellement commitées, en vous assurant qu'elles ne sont plus accessibles dans l'historique de votre dépôt. Remplace une liste de chaînes par `***REMOVED***`.

> [!warning]
> Cette action est irréversible. Après la réécriture de l'historique et l'exécution de la maintenance, les modifications sont permanentes.

Bien que l'expurgation des fichiers dans GitLab supprime les secrets exposés, elle :

- Réécrit l'historique Git. Les tags et branches historiques basés sur l'ancien historique de commit peuvent ne pas fonctionner correctement.
- Est destructrice. Les clones locaux existants sont incompatibles avec le dépôt mis à jour et doivent être reclonés.
- Met à jour les hachages de commit car l'expurgation met à jour leur contenu.
- Supprime les signatures de commit lors du processus de réécriture.
- Interrompt les fonctionnalités qui dépendent des hachages de commit, notamment :
  - Les merge requests ouvertes. Les merge requests ouvertes peuvent échouer lors de la fusion et nécessiter un rebase manuel.
  - Les liens vers les commits précédents, ce qui génère des erreurs 404.
- Peut interrompre les pipelines qui référencent d'anciens SHA de commit et nécessiter une reconfiguration.

Pour une meilleure intégrité du dépôt, vous devriez plutôt :

- Révoquer ou faire tourner les secrets exposés.
- Mettre en œuvre [les capacités de détection des secrets de GitLab](../../application_security/secret_detection/_index.md).

Cette approche :

- Prévient de manière proactive les futures fuites de secrets.
- Maintient l'historique Git tout en garantissant la conformité en matière de sécurité.

Pour plus d'informations, consultez [la protection contre les pushs de secrets](../../application_security/secret_detection/secret_push_protection/_index.md).

Alternativement, pour supprimer complètement des fichiers spécifiques d'un dépôt, consultez [la suppression des blobs](#remove-blobs).

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le projet.

Pour expurger du texte de votre dépôt :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Maintenance du dépôt**.
1. Sélectionnez **Expurger le texte**.
1. Dans le panneau latéral, saisissez le texte à expurger. Les expressions régulières et les modèles glob sont acceptés.
1. Sélectionnez **Expurger les chaînes correspondantes**.
1. Dans la boîte de dialogue de confirmation, saisissez le chemin de votre projet.
1. Sélectionnez **Oui, expurger les chaînes correspondantes**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Paramètres avancés**.
1. Sélectionnez **Démarrer la maintenance**. Attendez au moins 30 minutes que l'opération se termine.
1. Dans la même section **Paramètres** > **Général** > **Paramètres avancés**, sélectionnez **Élaguer les objets inaccessibles**. Cette opération prend environ 5 à 10 minutes.

> [!note]
> Si le projet contenant les informations sensibles a été dupliqué, la tâche de maintenance peut échouer à terminer ce processus d'expurgation afin de maintenir l'intégrité du dépôt de pool d'objets spécial [qui contient les données dupliquées](../../../administration/housekeeping.md#object-pool-repositories). Pour obtenir de l'aide, contactez le support GitLab.

## Dépannage {#troubleshooting}

Ces sections proposent des solutions aux problèmes que vous pourriez rencontrer.

### Statistiques de dépôt incorrectes affichées dans l'interface graphique {#incorrect-repository-statistics-shown-in-the-gui}

Si la taille du dépôt ou le nombre de commits affiché dans l'interface GitLab diffère de celui du fichier `.tar.gz` exporté ou du dépôt local :

1. Demandez à un administrateur GitLab de forcer une mise à jour à l'aide de la console Rails.
1. L'administrateur doit exécuter les commandes suivantes :

   ```ruby
   p = Project.find_by_full_path('<namespace>/<project>')
   p.statistics.refresh!
   ```

1. Pour effacer les statistiques du projet et déclencher un recalcul :

   ```ruby
   p.repository.expire_all_method_caches
   UpdateProjectStatisticsWorker.perform_async(p.id, ["commit_count","repository_size","storage_size","lfs_objects_size","container_registry_size"])
   ```

1. Pour vérifier l'espace de stockage total des artefacts :

   ```ruby
   builds_with_artifacts = p.builds.with_downloadable_artifacts.all

   artifact_storage = 0
   builds_with_artifacts.find_each do |build|
     artifact_storage += build.artifacts_size
   end

   puts "#{artifact_storage} bytes"
   ```

### Espace non libéré après le nettoyage {#space-not-being-freed-after-cleanup}

Si vous avez terminé un processus de nettoyage du dépôt mais que l'utilisation du stockage reste inchangée :

- Sachez que les objets inaccessibles restent dans le dépôt pendant une période de grâce de deux semaines.
- Ces objets ne sont pas inclus dans les exports, mais occupent toujours de l'espace sur le système de fichiers.
- Après deux semaines, ces objets sont automatiquement élagués, ce qui met à jour les statistiques d'utilisation du stockage.
- Pour accélérer ce processus, demandez à un administrateur d'exécuter la [tâche de maintenance « Élaguer les objets inaccessibles »](../../../administration/housekeeping.md).

### Les blobs ne sont pas supprimés {#blobs-are-not-removed}

Lorsque les blobs sont supprimés avec succès, GitLab ajoute une entrée dans les journaux d'audit du projet et envoie une notification par e-mail à la personne qui a initié l'action.

Si la suppression du blob échoue, GitLab envoie une notification par e-mail à l'initiateur avec l'objet `<project_name> | Project history rewrite failure`. Le corps de l'e-mail contient le message d'erreur complet.

Erreurs possibles et solutions :

- `validating object ID: invalid object ID` : la liste des identifiants d'objets contient une erreur de syntaxe ou un identifiant d'objet incorrect. Pour résoudre ce problème :
  1. Régénérez la [liste des identifiants d'objets](#get-a-list-of-object-ids).
  1. Relancez les [étapes de suppression des blobs](#remove-blobs).
- `source repository checksum altered` : cela se produit lorsqu'un commit est envoyé pendant le processus de suppression des blobs. Pour résoudre ce problème :
  1. Bloquez temporairement tous les pushs vers le dépôt.
  1. Relancez les [étapes de suppression des blobs](#remove-blobs).
  1. Réactivez les pushs une fois le processus terminé avec succès.

### Limite de taille du dépôt atteinte {#repository-size-limit-reached}

Si vous avez atteint la limite de taille du dépôt :

- Essayez de supprimer certaines données et d'effectuer un nouveau commit.
- Si cela ne fonctionne pas, envisagez de déplacer certains blobs vers [Git LFS](../../../topics/git/lfs/_index.md) ou de supprimer les anciennes mises à jour de dépendances de l'historique.
- Si vous ne parvenez toujours pas à envoyer des modifications, contactez votre administrateur GitLab pour [augmenter temporairement la limite pour votre projet](../../../administration/settings/account_and_limit_settings.md#repository-size-limit).
- En dernier recours, créez un nouveau projet et migrez vos données.

> [!note]
> La suppression de fichiers dans un nouveau commit ne réduit pas immédiatement la taille du dépôt, car les commits et les blobs antérieurs existent toujours. Pour réduire efficacement la taille, vous devez réécrire l'historique à l'aide d'un outil tel que [`git filter-repo`](https://github.com/newren/git-filter-repo).
