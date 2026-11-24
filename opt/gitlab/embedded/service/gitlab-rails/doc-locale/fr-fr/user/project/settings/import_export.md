---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Migrer les données GitLab à l'aide des exports de fichiers"
description: "Utiliser les exports de fichiers pour migrer les données GitLab."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Le renommage des titres de jalons pour éviter les conflits sur les instances de destination [a été introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/221447) dans GitLab 18.6.7 et versions ultérieures, 18.7.5 et versions ultérieures, et 18.8.5 et versions ultérieures.

{{< /history >}}

Les exports de fichiers vous fournissent un package portable de vos données GitLab qui fonctionne dans des environnements hors ligne. Cette méthode de migration préserve la plupart des données de projet, notamment les dépôts, les tickets, les merge requests et les commentaires.

Utilisez les exports de fichiers pour :

- Migrer entre des environnements hors ligne.
- Déplacer des projets spécifiques sans leur structure de groupe entière.

[Le transfert direct](../../group/import/_index.md) reste la méthode de migration recommandée pour la plupart des situations.

> [!note]
> Vous ne devez pas utiliser les fichiers d'export de projet pour sauvegarder vos données. L'utilisation de fichiers d'export de projet pour les sauvegardes ne fonctionne pas toujours, et tous les éléments ne sont pas exportés.

## Problèmes connus {#known-issues}

- En raison d'un problème connu, vous pourriez rencontrer une erreur `PG::QueryCanceled: ERROR: canceling statement due to statement timeout`. Pour plus d'informations, consultez la [documentation de dépannage](import_export_troubleshooting.md#error-pgquerycanceled-error-canceling-statement-due-to-statement-timeout).
- Dans GitLab 17.0, 17.1 et 17.2, les epics et éléments de travail importés sont associés à l'utilisateur effectuant l'importation plutôt qu'à l'auteur d'origine.
- Pour les merge requests, seul le diff le plus récent est préservé lors de l'importation ou de l'exportation. Après l'importation ou l'exportation d'un projet, seule la dernière version du diff et le dernier pipeline des merge requests sont visibles.
- Les jalons importés dont les titres [correspondent à des jalons existants](../milestones/_index.md#milestone-title-rules) dans l'espace de nommage de destination auront leurs titres mis à jour lors de l'importation. Le nouveau titre sera complété par un suffixe unique. Par exemple, `18.0` deviendra `18.0
  (imported-3d-1770206299)`. Pour éviter cela, renommez le jalon dans le groupe ou le projet source avant d'initier un transfert direct.

## Migrer des projets en téléchargeant un fichier d'export {#migrate-projects-by-uploading-an-export-file}

Les projets existants peuvent être exportés vers un fichier, puis importés dans une autre instance GitLab.

### Préserver les contributions des utilisateurs {#preserving-user-contributions}

Les conditions requises pour préserver les contributions des utilisateurs dépendent de si vous migrez vers GitLab.com ou vers une instance GitLab Self-Managed.

#### Lors de la migration de GitLab Self-Managed vers GitLab.com {#when-migrating-from-gitlab-self-managed-to-gitlabcom}

Lors de la migration de projets à l'aide des exports de fichiers, un jeton d'accès administrateur est requis pour que les contributions des utilisateurs soient correctement associées.

Par conséquent, les contributions des utilisateurs ne sont jamais correctement associées lors de l'importation d'exports de fichiers depuis une instance GitLab Self-Managed vers GitLab.com. À la place, toutes les associations d'utilisateurs GitLab (comme l'auteur d'un commentaire) sont modifiées en faveur de l'utilisateur qui importe le projet. Pour préserver l'historique des contributions, effectuez l'une des opérations suivantes :

- [Migrer à l'aide du transfert direct](../../group/import/_index.md).
- Envisagez de faire appel aux Services professionnels. Pour plus d'informations, consultez le [catalogue des Services professionnels](https://about.gitlab.com/professional-services/catalog/).

#### Lors de la migration vers GitLab Self-Managed {#when-migrating-to-gitlab-self-managed}

Pour s'assurer que GitLab associe correctement les utilisateurs et leurs contributions :

- Le propriétaire du groupe principal du projet doit exporter le projet afin que les informations de tous les membres (directs et hérités) ayant accès au projet puissent être incluses dans le fichier exporté. Les chargés de maintenance et les propriétaires de projet peuvent initier l'export du projet. Cependant, seuls les membres directs d'un projet sont alors exportés.
- Un administrateur doit effectuer l'importation.
- Les utilisateurs requis doivent exister sur l'instance GitLab de destination. Un administrateur peut créer des utilisateurs confirmés soit en masse dans une console Rails, soit un par un dans l'interface utilisateur.
- Les utilisateurs doivent [définir une adresse e-mail publique dans leur profil](../../profile/_index.md#set-your-public-email) sur l'instance GitLab source qui correspond à leur adresse e-mail principale sur l'instance GitLab de destination. Vous pouvez également ajouter manuellement les adresses e-mail publiques des utilisateurs en [modifiant les fichiers d'export de projet](#edit-project-export-files).
- [Dans GitLab 18.4 et versions ultérieures](https://gitlab.com/gitlab-org/gitlab/-/issues/559224), lorsque vous créez des membres directs lors de l'importation d'un projet directement dans un groupe existant, le [paramètre **Les utilisateurs ne peuvent pas être ajoutés aux projets de ce groupe**](../../group/access_and_permissions.md#prevent-members-from-being-added-to-projects-in-a-group) est respecté.

Lorsque l'adresse e-mail d'un utilisateur existant correspond à l'adresse e-mail d'un utilisateur importé, cet utilisateur est ajouté en tant que [membre direct](../members/_index.md) au projet importé.

Si l'une des conditions précédentes n'est pas remplie, les contributions des utilisateurs ne sont pas correctement associées. À la place, toutes les associations d'utilisateurs GitLab sont modifiées en faveur de l'utilisateur ayant effectué l'importation. Cet utilisateur devient l'auteur des merge requests créées par d'autres utilisateurs. Des commentaires supplémentaires mentionnant les auteurs d'origine sont :

- Ajoutés pour les commentaires, les approbations de merge requests, les tâches liées et les éléments.
- Non ajoutés pour le créateur de la merge request ou du ticket, les labels ajoutés ou supprimés, et les informations de fusion.

### Modifier les fichiers d'export de projet {#edit-project-export-files}

Vous pouvez ajouter ou supprimer des données dans les fichiers d'export. Par exemple, vous pouvez :

- Ajouter manuellement les adresses e-mail publiques des utilisateurs dans le fichier `project_members.ndjson`.
- Réduire les pipelines CI en supprimant des lignes du fichier `ci_pipelines.ndjson`.

Pour modifier un fichier d'export de projet :

1. Extrayez le fichier `.tar.gz` exporté.
1. Modifiez le fichier approprié. Par exemple, `tree/project/project_members.ndjson`.
1. Compressez à nouveau les fichiers en un fichier `.tar.gz`.

Vous pouvez également vérifier que tous les membres ont été exportés en consultant le fichier `project_members.ndjson`.

### Compatibilité {#compatibility}

Les exports de fichiers de projet sont au format NDJSON.

Vous pouvez importer des exports de fichiers de projet qui ont été exportés depuis une version de GitLab jusqu'à deux versions [mineures](../../../policy/maintenance.md#versioning) en arrière.

Par exemple :

| Version de destination | Versions sources compatibles |
|:--------------------|:---------------------------|
| 13.0                | 13.0, 12.10, 12.9          |
| 13.1                | 13.1, 13.0, 12.10          |

### Configurer les exports de fichiers comme source d'importation {#configure-file-exports-as-an-import-source}

{{< details >}}

- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Avant de pouvoir migrer des projets sur GitLab Self-Managed à l'aide des exports de fichiers, les administrateurs GitLab doivent :

1. [Activer les exports de fichiers](../../../administration/settings/import_and_export_settings.md#enable-project-export) sur l'instance source.
1. Activer les exports de fichiers comme source d'importation pour l'instance de destination. Sur GitLab.com, les exports de fichiers sont déjà activés comme source d'importation.

Pour activer les exports de fichiers comme source d'importation pour l'instance de destination :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Paramètres d'importation et d'exportation**.
1. Faites défiler jusqu'à **Sources d'importation**.
1. Cochez la case **Export GitLab**.

### Entre CE et EE {#between-ce-and-ee}

Vous pouvez exporter des projets de la Community Edition vers l'Enterprise Edition et vice versa, à condition que la [compatibilité](#compatibility) soit respectée.

Si vous exportez un projet de l'Enterprise Edition vers la Community Edition, vous risquez de perdre des données qui ne sont conservées que dans l'Enterprise Edition. Pour plus d'informations, consultez [le retour de l'EE vers la CE](../../../update/convert_to_ee/revert.md).

### Exporter un projet et ses données {#export-a-project-and-its-data}

Avant de pouvoir importer un projet, vous devez l'exporter.

Prérequis :

- Consultez la liste des [éléments exportés](#project-items-that-are-exported). Tous les éléments ne sont pas exportés.
- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.
- Pour des performances considérablement améliorées sur les dépôts comportant un grand nombre de références Git, utilisez GitLab 18.0 ou une version ultérieure. Pour plus d'informations, consultez notre [article de blog sur la réduction des temps de sauvegarde des dépôts GitLab](https://about.gitlab.com/blog/how-we-decreased-gitlab-repo-backup-times-from-48-hours-to-41-minutes/).

Pour exporter un projet et ses données, suivez ces étapes :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Paramètres avancés**.
1. Sélectionnez **Exporter le projet**.
1. Une fois l'export généré, vous pouvez :
   - Suivre un lien contenu dans un e-mail que vous devriez recevoir.
   - Actualisez la page des paramètres du projet et, dans la zone **Exporter le projet**, sélectionnez **Télécharger l'export**.

L'export est généré dans votre `shared_path` configuré, un répertoire partagé temporaire (par défaut, `<shared_path>/tmp/gitlab_exports`), puis :

- Déplacé vers votre `uploads_directory` configuré.
- Téléversé vers le stockage d'objets.

Toutes les 24 heures, un worker supprime ces fichiers d'export.

Sur les instances GitLab comportant des nœuds Sidekiq, Gitaly et application GitLab (Rails) séparés, le répertoire spécifié dans le paramètre [`shared_path`](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/b350e3cd5b06a94adb463ece4d41b9f3df6ab282/files/gitlab-config-template/gitlab.rb.template#L731) doit être accessible à tous les nœuds.

#### Éléments de projet exportés {#project-items-that-are-exported}

Les éléments de projet exportés dépendent de la version de GitLab que vous utilisez. Pour déterminer si un élément de projet spécifique est exporté :

1. Vérifiez le [tableau `exporters`](https://gitlab.com/gitlab-org/gitlab/-/blob/b819a6aa6d53573980dd9ee4a1bfe597d69e88e5/app/services/projects/import_export/export_service.rb#L24).
1. Vérifiez le fichier [`project/import_export.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/import_export/project/import_export.yml) pour les projets correspondant à votre version de GitLab. Par exemple, <https://gitlab.com/gitlab-org/gitlab/-/blob/19-2-stable-ee/lib/gitlab/import_export/project/import_export.yml> pour GitLab 19.2.

Pour un aperçu rapide, les éléments exportés comprennent :

- Dépôts du projet et du wiki
- Téléversements du projet
- Configuration du projet, à l'exclusion des intégrations
- Les tickets
  - Commentaires de tickets
  - Itérations de tickets
  - Événements d'état des ressources de tickets
  - Événements de jalons des ressources de tickets
  - Événements d'itération des ressources de tickets
- Les merge requests
  - Diffs de merge requests
  - Commentaires de merge requests
  - Événements d'état des ressources de merge requests
  - Assignés multiples aux merge requests
  - Relecteurs de merge requests
  - Approbateurs de merge requests
- Commentaires de commits
- Labels
- Les jalons
- les snippets ;
- Les releases
- Suivi du temps et autres entités du projet
- Fichiers et données de gestion des designs
- Objets LFS
- Tableaux des tickets
- Pipelines CI/CD (archivés)
- Planifications de pipeline (inactives et attribuées à l'utilisateur ayant initié l'importation)
- Branches et tags protégés
- Règles de push
- Réactions emoji

  > [!note]
  > Les réactions emoji utilisant des emoji personnalisés ne sont importées que si un emoji personnalisé portant le même nom existe sur la destination. Les réactions faisant référence à un emoji personnalisé absent de la destination sont ignorées.

- Membres directs du projet (si vous disposez du rôle Chargé de maintenance ou Propriétaire pour le groupe du projet exporté)
- Membres de projet hérités en tant que membres directs du projet (si vous disposez du rôle Propriétaire pour le groupe du projet exporté ou d'un accès administrateur à l'instance)
- Certaines règles d'approbation de merge requests :
  - [Approbations pour les branches protégées](../merge_requests/approvals/rules.md#approvals-for-protected-branches)
  - [Approbateurs éligibles](../merge_requests/approvals/rules.md#eligible-approvers)
- Rapport de vulnérabilités ([introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/501466) dans GitLab 17.7)

#### Éléments de projet non exportés {#project-items-that-are-not-exported}

Les éléments non exportés comprennent :

- [Historique des pipelines enfants](https://gitlab.com/gitlab-org/gitlab/-/issues/221088)
- Déclencheurs de pipeline
- Traces et artefacts de jobs CI/CD
- Images du registre de packages et de conteneurs
- Variables CI/CD
- Liste d'autorisation des jetons de jobs CI/CD
- Webhooks
- Tous les jetons chiffrés
- [Nombre d'approbations requises](https://gitlab.com/gitlab-org/gitlab/-/issues/221087)
- Limites de taille des dépôts
- Clés de déploiement autorisées à pousser vers des branches protégées
- Fichiers sécurisés
- [Journaux d'activité pour les événements liés à Git](https://gitlab.com/gitlab-org/gitlab/-/issues/214700) (par exemple, les pushs et la création de tags)
- Politiques de sécurité associées à votre projet
- Liens entre les tickets et les éléments liés
- Liens vers les merge requests associées
- Variables de planification de pipeline

### Importer un projet et ses données {#import-a-project-and-its-data}

{{< history >}}

- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256551) dans GitLab 19.5 pour conserver la date de création du projet source.

{{< /history >}}

Vous pouvez importer un projet et ses données. La quantité de données que vous pouvez importer dépend de la taille maximale du fichier d'importation :

- Sur GitLab Self-Managed, les administrateurs peuvent [définir la taille maximale du fichier d'importation](#set-maximum-import-file-size).
- Sur GitLab.com, la valeur est [définie à 5 Go](../../gitlab_com/_index.md#account-and-limit-settings).

> [!warning]
> Importez uniquement des projets provenant de sources fiables. Si vous importez un projet depuis une source non fiable, il est possible qu'un attaquant puisse voler vos données sensibles.

#### Prérequis {#prerequisites}

- Vous devez avoir [exporté le projet et ses données](#export-a-project-and-its-data).
- Comparez les versions de GitLab et assurez-vous d'importer vers une version de GitLab identique ou ultérieure à celle depuis laquelle vous avez effectué l'export.
- Vérifiez la [compatibilité](#compatibility) pour tout problème éventuel.
- Le rôle Chargé de maintenance ou Propriétaire sur le groupe de destination vers lequel effectuer la migration.
- La commande `tar` doit être installée sur les instances GitLab source et de destination.

#### Importer un projet {#import-a-project}

Pour importer un projet :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Importer un projet**.
1. Dans **Importer un projet depuis**, sélectionnez **Export GitLab**.
1. Saisissez le nom et l'URL de votre projet. Sélectionnez ensuite le fichier que vous avez exporté précédemment.
1. Sélectionnez **Importer un projet**.

Vous pouvez interroger le statut d'une importation à l'aide de l'[API](../../../api/project_import_export.md#retrieve-the-status-of-a-project-import). La requête peut retourner une erreur d'importation ou des exceptions.

#### Modifications apportées aux éléments importés {#changes-to-imported-items}

Les éléments exportés sont importés avec les modifications suivantes :

- Les membres du projet disposant du rôle Propriétaire sont importés avec le rôle Chargé de maintenance.
- Si un projet importé contient des merge requests provenant de duplications, de nouvelles branches associées à ces merge requests sont créées dans le projet. Par conséquent, le nombre de branches dans le nouveau projet peut être supérieur à celui du projet source.
- Si le niveau de visibilité `Internal` [est restreint](../../public_access.md#restrict-use-of-public-or-internal-projects), tous les projets importés se voient attribuer la visibilité `Private`.
- Les niveaux d'accès aux branches protégées et aux tags protégés sont réinitialisés sur Chargés de maintenance. Par exemple, **Autorisés à fusionner** défini sur **Développeurs + Chargés de maintenance** devient **Chargés de maintenance**. Les niveaux d'accès définis sur Personne sont préservés.
  - Pour préserver les niveaux d'accès d'origine, l'utilisateur qui effectue l'importation doit disposer du rôle Propriétaire pour le groupe principal du projet de destination, ou être un administrateur GitLab.
  - Les niveaux d'accès sont toujours réinitialisés lorsque le projet de destination se trouve dans un espace de nommage personnel.

Les clés de déploiement ne sont pas importées. Pour utiliser des clés de déploiement, vous devez les activer dans votre projet importé et mettre à jour les branches protégées.

> [!warning]
> Les pipelines importés pour les merge requests conservent leur statut source et peuvent satisfaire **Les pipelines doivent réussir** et la [vérification du pipeline de politique de sécurité](../../application_security/policies/pipeline_execution_policies.md#security-policy-pipeline-check) sur l'instance de destination sans être réexécutés. Exécutez un nouveau pipeline sur toutes les merge requests importées avant de les fusionner.

#### Importer des projets volumineux {#import-large-projects}

{{< details >}}

- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si votre projet est volumineux, envisagez [d'utiliser une tâche Rake](../../../administration/raketasks/project_import_export.md#import-large-projects).

### Définir la taille maximale du fichier d'importation {#set-maximum-import-file-size}

{{< details >}}

- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les administrateurs peuvent définir la taille maximale du fichier d'importation de deux façons :

- Avec l'option `max_import_size` dans l'[API des paramètres d'application](../../../api/settings.md#update-application-settings).
- Dans l'[interface utilisateur de la zone **Admin**](../../../administration/settings/import_and_export_settings.md#max-import-size).

La valeur par défaut est `0` (illimitée).

### Limites de débit {#rate-limits}

Pour aider à éviter les abus, par défaut, les utilisateurs sont soumis aux limites de débit suivantes :

| Type de requête    | Limite                           |
|:----------------|:--------------------------------|
| Export          | 6 projets par minute           |
| Téléchargement d'export | 1 téléchargement par projet par minute |
| Import          | 6 projets par minute           |

## Migrer des groupes en téléchargeant un fichier d'export (obsolète) {#migrate-groups-by-uploading-an-export-file-deprecated}

{{< history >}}

- [Obsolète](https://gitlab.com/groups/gitlab-org/-/work_items/4619) dans GitLab 14.6.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256551) dans GitLab 19.5 pour conserver la date de création du groupe source.

{{< /history >}}

> [!warning]
> Cette fonctionnalité a été [rendue obsolète](https://gitlab.com/groups/gitlab-org/-/work_items/4619) dans GitLab 14.6 et remplacée par [la migration de groupes par transfert direct](../../group/import/_index.md). Cependant, cette fonctionnalité est toujours recommandée pour les migrations dans des [environnements hors ligne](../../application_security/offline_deployments/_index.md). La prise en charge de la migration entre instances hors ligne est proposée dans l'[epic 8985](https://gitlab.com/groups/gitlab-org/-/work_items/8985).

Prérequis :

- Rôle Propriétaire sur le groupe à migrer.

À l'aide des exports de fichiers, vous pouvez :

- Exporter n'importe quel groupe vers un fichier et téléverser ce fichier vers une autre instance GitLab ou vers un autre emplacement sur la même instance.
- Utiliser l'interface utilisateur GitLab ou l'[API](../../../api/group_import_export.md).
- Migrer les groupes un par un, puis exporter et importer chaque projet pour les groupes un par un.

GitLab associe correctement les contributions des utilisateurs lorsqu'un jeton d'accès administrateur est utilisé pour effectuer l'importation. GitLab n'associe pas correctement les contributions des utilisateurs lorsque vous importez depuis une instance GitLab Self-Managed vers GitLab.com. L'association correcte des contributions des utilisateurs lors de l'importation depuis une instance GitLab Self-Managed vers GitLab.com peut être préservée avec l'intervention payante de l'équipe des Services professionnels.

### Informations supplémentaires {#additional-information}

- Les exports sont stockés dans un répertoire temporaire et sont supprimés toutes les 24 heures par un worker spécifique.
- Pour préserver les relations au niveau du groupe à partir des projets importés, exportez et importez d'abord les groupes afin que les projets puissent être importés dans la structure de groupe souhaitée.
- Les groupes importés se voient attribuer un niveau de visibilité `private`, sauf s'ils sont importés dans un groupe parent.
- Si un sous-groupe est importé dans un groupe parent, il hérite du même niveau de visibilité, sauf restriction contraire.
- Vous pouvez exporter des groupes de la [Community Edition vers l'Enterprise Edition](https://about.gitlab.com/install/) et vice versa. L'Enterprise Edition conserve certaines données de groupe qui ne font pas partie de la Community Edition. Si vous exportez un groupe de l'Enterprise Edition vers la Community Edition, vous risquez de perdre ces données. Pour plus d'informations, consultez [le retour de l'EE vers la CE](../../../update/convert_to_ee/revert.md).

La taille maximale du fichier d'importation dépend de si vous importez vers GitLab Self-Managed ou GitLab.com :

- Si vous importez vers une instance GitLab Self-Managed, vous pouvez importer un fichier d'importation de n'importe quelle taille. Les administrateurs peuvent modifier ce comportement en utilisant l'une ou l'autre des options suivantes :
  - L'option `max_import_size` dans l'[API des paramètres d'application](../../../api/settings.md#update-application-settings).
  - La [zone **Admin**](../../../administration/settings/account_and_limit_settings.md).
- Sur GitLab.com, vous pouvez importer des groupes à l'aide de fichiers d'importation d'une taille maximale de [5 Go](../../gitlab_com/_index.md#account-and-limit-settings).

### Compatibilité {#compatibility-1}

Les exports de fichiers de groupe sont au format NDJSON.

Vous pouvez importer des exports de fichiers de groupe qui ont été exportés depuis une version de GitLab jusqu'à deux versions [mineures](../../../policy/maintenance.md#versioning) en arrière.

Par exemple :

| Version de destination | Versions sources compatibles |
|:--------------------|:---------------------------|
| 13.0                | 13.0, 12.10, 12.9          |
| 13.1                | 13.1, 13.0, 12.10          |

### Éléments de groupe exportés {#group-items-that-are-exported}

Le fichier [`import_export.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/import_export/group/import_export.yml) pour les groupes répertorie les éléments exportés et importés lors de la migration de groupes à l'aide des exports de fichiers. Consultez ce fichier dans la branche correspondant à votre version de GitLab pour vérifier quels éléments peuvent être importés vers l'instance GitLab de destination. Par exemple, [`import_export.yml` sur la branche `19-2-stable-ee`](https://gitlab.com/gitlab-org/gitlab/-/blob/19-2-stable-ee/lib/gitlab/import_export/group/import_export.yml).

Les éléments de groupe exportés comprennent :

- Les jalons
- Labels de groupe (sans priorités de label associées)
- Tableaux et listes de tableaux
- Badges
- Sous-groupes (incluant toutes les données susmentionnées)
- Les epics
  - Événements d'état des ressources d'epic.
- Événements
- [les wikis.](../wiki/group.md)
- Cadences d'itération.

### Éléments de groupe non exportés {#group-items-that-are-not-exported}

Les éléments non exportés comprennent :

- Projets
- Jetons de runner
- Jetons de découverte SAML
- les importations ;

### Préparation {#preparation}

- Pour préserver la liste des membres et leurs autorisations respectives sur les groupes importés, vérifiez les utilisateurs dans ces groupes. Assurez-vous que ces utilisateurs existent avant d'importer les groupes souhaités.
- Les utilisateurs doivent définir une adresse e-mail publique sur l'instance GitLab source qui correspond à leur adresse e-mail principale confirmée sur l'instance GitLab de destination. La plupart des utilisateurs reçoivent un e-mail leur demandant de confirmer leur adresse e-mail.

### Exporter un groupe {#export-a-group}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.

Pour exporter le contenu d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Dans la section **Paramètres avancés**, sélectionnez **Exporter le groupe**.
1. Une fois l'export généré, vous pouvez :
   - Suivre un lien contenu dans un e-mail que vous devriez recevoir.
   - Actualisez la page des paramètres du groupe et, dans la zone **Exporter le projet**, sélectionnez **Télécharger l'export**.

### Importer le groupe {#import-the-group}

Pour importer le groupe :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau groupe**.
1. Sélectionnez **Importer un groupe**.
1. Dans la section **Importer un groupe depuis un fichier**, saisissez un nom de groupe et acceptez ou modifiez l'URL de groupe associée.
1. Sélectionnez **Choisir un fichier**.
1. Sélectionnez le fichier d'export GitLab que vous souhaitez importer.
1. Pour commencer l'importation, sélectionnez **Importer**.

### Limites de débit {#rate-limits-1}

Pour aider à éviter les abus, par défaut, les utilisateurs sont soumis aux limites de débit suivantes :

| Type de requête    | Limite |
|-----------------|-------|
| Export          | 6 groupes par minute |
| Téléchargement d'export | 1 téléchargement par groupe par minute |
| Import          | 6 groupes par minute |

## Sujets connexes {#related-topics}

- [API d'importation et d'exportation de projet](../../../api/project_import_export.md)
- [Tâches Rake d'administration d'importation et d'exportation de projet](../../../administration/raketasks/project_import_export.md)
- [Migration de groupes GitLab](../../group/import/_index.md)
- [API d'importation et d'exportation de groupe](../../../api/group_import_export.md)
- [Migrer des groupes par transfert direct](../../group/import/_index.md)
