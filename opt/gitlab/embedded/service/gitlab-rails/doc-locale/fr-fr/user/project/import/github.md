---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Migrer depuis GitHub
description: "Migrer de GitHub vers GitLab."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Badge **Importé** [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/461208) dans GitLab 17.2.
- Case à cocher **Utiliser la méthode alternative d'importation des commentaires** [supprimée](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250959) dans GitLab 19.4. Cette méthode d'importation des commentaires est désormais toujours utilisée pour les nouvelles importations et ne peut pas être désactivée.

{{< /history >}}

Vous pouvez importer vos projets GitHub depuis GitHub.com ou GitHub Enterprise. L'importation de projets ne migre ni n'importe aucun type de groupe ou d'organisation depuis GitHub vers GitLab.

Les tickets, merge requests, commentaires et événements importés affichent un badge **Importé** dans GitLab.

L'espace de nommage est un utilisateur ou un groupe dans GitLab, tel que `gitlab.com/sidney-jones` ou `gitlab.com/customer-success`.

Via l'interface GitLab, l'importateur GitHub importe toujours depuis le domaine `github.com`. Si vous importez depuis un domaine GitHub Enterprise Server auto-hébergé, utilisez le point de terminaison GitHub de [l'API d'importation](#use-the-api) avec un jeton d'accès GitLab ayant la portée `api`.

Vous pouvez modifier l'espace de nommage cible et le nom du dépôt cible avant d'importer.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation du processus d'importation, voir [comment migrer de GitHub vers GitLab, notamment les actions](https://www.youtube.com/watch?v=0Id5oMl1Kqs).

## Estimation de la durée d'importation {#estimating-import-duration}

Chaque importation depuis GitHub est différente, ce qui influe sur la durée des importations que vous effectuez. Cependant, lors des tests, GitLab a importé `https://github.com/kubernetes/kubernetes` en 76 heures. Les tests ont montré que le projet comprenait :

- 80 000 pull requests.
- 45 000 tickets.
- Environ 1,5 million de commentaires.

## Prérequis {#prerequisites}

Pour importer des projets depuis GitHub, vous devez activer la [source d'importation GitHub](../../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources). Si cette source d'importation n'est pas activée, demandez à votre administrateur GitLab de l'activer. La source d'importation GitHub est activée par défaut sur GitLab.com.

### Autorisations et rôles {#permissions-and-roles}

Pour utiliser l'importateur GitHub, vous devez disposer des éléments suivants :

- Accès au projet GitHub source
- Le rôle Maintainer ou Owner pour le groupe GitLab de destination

De plus, l'organisation à laquelle appartient le dépôt GitHub ne doit pas imposer de restrictions liées à une [politique d'accès aux applications tierces](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions) sur l'instance GitLab vers laquelle vous importez.

## Problèmes connus {#known-issues}

- Les commentaires de pull requests GitHub (appelés notes de diff dans GitLab) créés avant 2017 sont importés dans des fils de discussion séparés. Cela est dû à une limitation de l'API GitHub qui n'inclut pas `in_reply_to_id` pour les commentaires antérieurs à 2017.
- [Dans GitLab 18.3 et versions antérieures](https://gitlab.com/gitlab-org/gitlab/-/issues/424400), les pièces jointes Markdown des dépôts sur les instances GitHub Enterprise Server ne sont pas importées. [Dans GitLab 18.4 et versions ultérieures](https://gitlab.com/gitlab-org/gitlab/-/issues/553386) :
  - Seuls les fichiers vidéo et image des pièces jointes Markdown sont importés.
  - Les autres pièces jointes ne sont pas importées.
- En raison d'un [problème connu](https://gitlab.com/gitlab-org/gitlab/-/issues/418800), lors de l'importation de projets qui utilisaient la [fusion automatique GitHub](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/automatically-merging-a-pull-request), le projet importé dans GitLab peut avoir des commits de fusion étiquetés `unverified` si le commit a été signé avec la clé GPG interne de GitHub.
- GitLab [ne peut pas importer](https://gitlab.com/gitlab-org/gitlab/-/issues/424046) les pièces jointes d'images Markdown GitHub qui ont été chargées dans des dépôts privés avant le 09/05/2023. Si vous rencontrez ce problème et êtes prêt à fournir un exemple de dépôt, ajoutez un commentaire au [ticket 424046](https://gitlab.com/gitlab-org/gitlab/-/issues/424046) et GitLab vous contactera.
- Pour les [références spécifiques à GitLab](../../markdown.md#gitlab-specific-references), GitLab utilise le caractère `#` pour les tickets et le caractère `!` pour les merge requests. Cependant, GitHub utilise uniquement le caractère `#` pour les tickets et les pull requests. Lors de l'importation :

  - Pour les notes de commentaires, GitLab crée uniquement des liens vers des tickets, car il ne peut pas déterminer si une référence pointe vers un ticket ou une merge request.
  - Pour les descriptions de tickets ou de merge requests, GitLab ne crée pas de liens pour les références, car leurs équivalents importés n'ont peut-être pas encore été créés sur la destination.

- Lors de l'importation depuis des comptes GitHub avec l'authentification unique (SSO) SAML activée, l'importation des pièces jointes Markdown peut échouer. Ce problème est dû à une limitation de l'API GitHub qui empêche le téléchargement des ressources à l'aide d'un jeton d'accès personnel lorsque le SSO est appliqué. Pour contourner ce problème, ajoutez l'utilisateur GitLab effectuant l'importation en tant que [collaborateur externe](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators/adding-outside-collaborators-to-repositories-in-your-organization) au dépôt GitHub. Cela autorise l'accès aux pièces jointes privées lors de l'importation.

## Importer votre dépôt GitHub dans GitLab {#import-your-github-repository-into-gitlab}

Vous pouvez importer votre dépôt GitHub de l'une des manières suivantes :

- [Utiliser GitHub OAuth](#use-github-oauth)
- [Utiliser un jeton d'accès personnel GitHub](#use-a-github-personal-access-token)
- [Utiliser l'API](#use-the-api)

Si vous importez depuis `github.com`, vous pouvez utiliser n'importe quelle méthode pour importer. Les clients de GitHub Enterprise Server auto-hébergé doivent utiliser l'API.

### Utiliser GitHub OAuth {#use-github-oauth}

Si vous importez vers GitLab.com ou vers un GitLab Self-Managed sur lequel GitHub OAuth est [configuré](../../../integration/github.md), vous pouvez utiliser GitHub OAuth pour importer votre dépôt.

Cette méthode présente un avantage par rapport à l'utilisation d'un [jeton d'accès personnel (PAT)](#use-a-github-personal-access-token), car le backend échange le jeton d'accès avec les autorisations appropriées.

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Importer un projet**, puis **GitHub**.
1. Sélectionnez **Autoriser avec GitHub**.
1. Passez à l'étape [Sélectionner les dépôts à importer](#select-which-repositories-to-import).

Pour utiliser une méthode différente d'importation après avoir effectué ces étapes, déconnectez-vous de votre compte GitLab et reconnectez-vous.

### Utiliser un jeton d'accès personnel GitHub {#use-a-github-personal-access-token}

Pour importer votre dépôt GitHub à l'aide d'un jeton d'accès personnel GitHub :

1. Générez un jeton d'accès personnel GitHub. Seuls les jetons d'accès personnels classiques sont pris en charge.
   1. Accédez à <https://github.com/settings/tokens/new>.
   1. Dans le champ **Note**, saisissez une description du jeton.
   1. Sélectionnez la portée `repo`.
   1. Facultatif. Pour [importer des collaborateurs](#select-additional-items-to-import), ou si votre projet contient des [fichiers Git LFS](../../../topics/git/lfs/_index.md), sélectionnez la portée `read:org`.
   1. Sélectionnez **Générer un jeton**.
1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Importer un projet**, puis **GitHub**.
1. Sélectionnez **Autoriser avec GitHub**.
1. Dans le champ **Jeton d'accès personnel**, collez le jeton d'accès personnel GitHub.
1. Sélectionnez **Authentification**.
1. Passez à l'étape [Sélectionner les dépôts à importer](#select-which-repositories-to-import).

Pour utiliser un jeton différent pour effectuer une importation après avoir effectué ces étapes, déconnectez-vous de votre compte GitLab et reconnectez-vous, ou révoquez l'ancien jeton dans GitHub.

### Utiliser l'API {#use-the-api}

L'[API d'importation](../../../api/import.md#import-repository-from-github) peut être utilisée pour importer un dépôt GitHub. Elle présente certains avantages par rapport à l'utilisation de l'interface GitLab :

- Peut être utilisée pour importer des dépôts GitHub que vous ne possédez pas s'ils sont publics.
- Peut être utilisée pour importer depuis un GitHub Enterprise Server auto-hébergé.
- Peut être utilisée pour définir l'option `timeout_strategy` qui n'est pas disponible dans l'interface.

L'API REST est limitée à l'authentification avec des jetons d'accès personnels GitLab.

Pour importer votre dépôt GitHub à l'aide de l'API REST GitLab :

1. Générez un jeton d'accès personnel GitHub. Seuls les jetons d'accès personnels classiques sont pris en charge.
   1. Accédez à <https://github.com/settings/tokens/new>.
   1. Dans le champ **Note**, saisissez une description du jeton.
   1. Sélectionnez la portée `repo`.
   1. Facultatif. Pour [importer des collaborateurs](#select-additional-items-to-import), ou si votre projet contient des [fichiers Git LFS](../../../topics/git/lfs/_index.md), sélectionnez la portée `read:org`.
   1. Sélectionnez **Générer un jeton**.
1. Utilisez l'[API d'importation](../../../api/import.md#import-repository-from-github) pour importer votre dépôt GitHub.

### Filtrer la liste des dépôts {#filter-repositories-list}

Après avoir autorisé l'accès à vos dépôts GitHub, GitLab vous redirige vers la page d'importation où vos dépôts GitHub sont répertoriés.

Utilisez l'un des onglets suivants pour filtrer la liste des dépôts :

- **Propriétaire** (par défaut) : filtrer la liste pour n'afficher que les dépôts dont vous êtes propriétaire.
- **Collaborateur** : filtrer la liste pour n'afficher que les dépôts auxquels vous avez contribué.
- **Organisation** : filtrer la liste pour n'afficher que les dépôts appartenant à une organisation dont vous êtes membre.

Lorsque l'onglet **Organisation** est sélectionné, vous pouvez affiner votre recherche en sélectionnant une organisation GitHub disponible dans une liste déroulante.

### Sélectionner des éléments supplémentaires à importer {#select-additional-items-to-import}

Pour que les importations soient aussi rapides que possible, les éléments suivants ne sont pas importés depuis GitHub par défaut :

- Pièces jointes Markdown des commentaires de dépôt, des publications de release, des descriptions de tickets et des descriptions de pull requests. Il peut s'agir d'images, de texte ou de pièces jointes binaires. Si elles ne sont pas importées, les liens Markdown vers les pièces jointes sont rompus après leur suppression de GitHub.

Vous pouvez choisir d'importer ces éléments, mais cela peut augmenter considérablement la durée de l'importation. Pour importer ces éléments, sélectionnez les champs appropriés dans l'interface :

- **Importer les pièces jointes Markdown**.
- **Importer des collaborateurs et collaboratrices** (sélectionné par défaut). Laisser cette option sélectionnée peut entraîner l'utilisation d'un siège dans le groupe ou l'espace de nommage par de nouveaux utilisateurs, et l'attribution d'autorisations [pouvant aller jusqu'au niveau de propriétaire du projet](#collaborators-members). Seuls les collaborateurs directs sont importés. Les collaborateurs externes ne sont jamais importés. [Dans GitLab 18.4 et versions ultérieures](https://gitlab.com/gitlab-org/gitlab/-/issues/559224), lorsque vous importez des collaborateurs, le [paramètre **Les utilisateurs ne peuvent pas être ajoutés aux projets de ce groupe**](../../group/access_and_permissions.md#prevent-members-from-being-added-to-projects-in-a-group) est respecté.

### Sélectionner les dépôts à importer {#select-which-repositories-to-import}

Par défaut, les espaces de nommage de dépôts proposés correspondent aux noms tels qu'ils existent dans GitHub, mais selon vos autorisations, vous pouvez choisir de modifier ces noms avant de procéder à l'importation.

Pour sélectionner les dépôts à importer, cliquez sur **Importer** à côté d'un ou plusieurs dépôts, ou sélectionnez **Importer tous les dépôts**.

De plus, vous pouvez filtrer les projets par nom. Si un filtre est appliqué, **Importer tous les dépôts** importe uniquement les dépôts correspondants.

La colonne **Statut** affiche le statut d'importation de chaque dépôt. Vous pouvez choisir de garder la page ouverte et de surveiller les mises à jour en temps réel, ou y revenir ultérieurement.

Pour annuler les importations en attente ou en cours, sélectionnez **Annuler** à côté du projet importé. Si l'importation a déjà commencé, les fichiers importés sont conservés.

Pour ouvrir un dépôt via l'URL GitLab après son importation, sélectionnez son chemin GitLab.

Les importations terminées peuvent être réimportées en sélectionnant **Réimporter** et en spécifiant un nouveau nom. Cela crée une nouvelle copie du projet source.

![La page de l'importateur GitHub, qui répertorie les dépôts à importer dans GitLab.](img/import_projects_from_github_importer_v16_0.png)

### Vérifier le statut des importations {#check-status-of-imports}

Une fois les importations terminées, elles peuvent se trouver dans l'un des trois états suivants :

- **Terminé** : GitLab a importé toutes les entités du dépôt.
- **Terminé partiellement** : GitLab n'a pas réussi à importer certaines entités du dépôt.
- **Échec** : GitLab a interrompu l'importation après la survenue d'une erreur critique.

Développez **Détails** pour afficher la liste des [entités du dépôt](#imported-data) dont l'importation a échoué.

## Mentions de noms d'utilisateur {#username-mentions}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/477553) dans GitLab 17.5.

{{< /history >}}

GitLab ajoute des backticks aux mentions de noms d'utilisateur dans les tickets, les merge requests et les notes. Ces backticks empêchent la création de liens vers un utilisateur incorrect portant le même nom d'utilisateur sur l'instance GitLab.

## Mappage des contributions des utilisateurs et des membres {#user-contribution-and-membership-mapping}

{{< history >}}

- [Modifié sur GitLab.com](https://gitlab.com/groups/gitlab-org/-/work_items/14667) vers [**mappage des contributions des utilisateurs et des membres**](../../import/mapping/post_migration_mapping.md) dans GitLab 17.8.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/176675) dans GitLab 17.8.

{{< /history >}}

L'importateur GitHub utilise une [méthode post-migration](../../import/mapping/post_migration_mapping.md) pour mapper les contributions des utilisateurs pour GitLab.com, GitLab Self-Managed et GitLab Dedicated.

### Méthode alternative de mappage {#alternative-method-of-mapping}

Dans GitLab 18.7 et versions antérieures, vous pouvez désactiver le feature flag `github_user_mapping` pour utiliser la méthode alternative de mappage des contributions des utilisateurs pour les importations.

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Cette fonctionnalité n'est pas recommandée et n'est pas disponible pour :
>
> - Les migrations vers GitLab.com.
> - Les migrations vers GitLab Self-Managed et GitLab Dedicated 18.8 et versions ultérieures.
>
> Les problèmes détectés dans cette méthode de mappage ne seront probablement pas corrigés. Utilisez plutôt la [méthode post-migration](../../import/mapping/post_migration_mapping.md), qui ne présente pas ces limitations.
>
> Pour plus d'informations, consultez le [ticket 510963](https://gitlab.com/gitlab-org/gitlab/-/work_items/510963).

Prérequis :

- Chaque auteur et assigné GitHub dans le dépôt doit disposer d'une [adresse e-mail publique](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-email-preferences/setting-your-commit-email-address). GitHub Enterprise n'exige pas d'adresse e-mail publique, vous devrez peut-être donc en ajouter une aux comptes existants.
- L'adresse e-mail de l'utilisateur GitHub doit correspondre à son adresse e-mail GitLab.
- Si l'adresse e-mail d'un utilisateur dans GitHub est définie comme adresse e-mail secondaire dans GitLab, il doit la confirmer.

Avec cette méthode, les utilisateurs sont mappés lors de l'importation.

Si les prérequis ne sont pas remplis, l'importateur ne peut pas mapper les contributions de cet utilisateur. Dans ce cas :

- Le créateur du projet est défini comme auteur et assigné des tickets et des merge requests. Le créateur du projet est généralement l'utilisateur qui a initié le processus d'importation. Pour certaines contributions comportant une description ou une note, telles que des pull requests, des tickets et des notes, l'importateur modifie le texte en ajoutant des informations sur l'auteur original de la contribution.
- Les relecteurs et les approbations ajoutés aux pull requests dans GitHub ne peuvent pas être importés. Dans ce cas, l'importateur crée des commentaires indiquant que des utilisateurs inexistants ont été ajoutés en tant que relecteurs et approbateurs. Cependant, le statut de relecteur et l'approbation réels ne sont pas appliqués à la merge request dans GitLab.

## Mettre en miroir un dépôt et partager le statut du pipeline {#mirror-a-repository-and-share-pipeline-status}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

Selon votre édition GitLab, la [mise en miroir de dépôt](../repository/mirror/_index.md) peut être configurée pour maintenir votre dépôt importé synchronisé avec sa copie GitHub.

De plus, vous pouvez configurer GitLab pour envoyer les mises à jour du statut des pipelines vers GitHub via l'[intégration du projet GitHub](../integrations/github.md).

Si vous importez votre projet en utilisant [CI/CD pour les dépôts externes](../../../ci/ci_cd_for_external_repos/_index.md), les deux fonctionnalités sont automatiquement configurées.

> [!note]
> La mise en miroir ne synchronise pas les pull requests nouvelles ou mises à jour de votre projet GitHub.

## Améliorer la vitesse des importations sur les instances GitLab Self-Managed {#improve-the-speed-of-imports-on-gitlab-self-managed-instances}

Un accès administrateur au serveur GitLab est requis pour ces étapes.

### Augmenter le nombre de workers Sidekiq {#increase-the-number-of-sidekiq-workers}

Pour les projets volumineux, l'importation de toutes les données peut prendre un certain temps. Pour réduire le temps nécessaire, vous pouvez augmenter le nombre de workers Sidekiq qui traitent les files d'attente suivantes :

- `github_importer`
- `github_importer_advance_stage`

Pour une expérience optimale, il est recommandé de disposer d'au moins 4 processus Sidekiq (chacun exécutant un nombre de threads égal au nombre de cœurs CPU) qui ne traitent que ces files d'attente. Il est également recommandé que ces processus s'exécutent sur des serveurs distincts. Pour 4 serveurs dotés de 8 cœurs, vous pouvez importer jusqu'à 32 objets (par exemple, des tickets) en parallèle.

La réduction du temps passé au clonage d'un dépôt peut être réalisée en augmentant le débit réseau, la capacité CPU et les performances des disques (en utilisant des SSD haute performance, par exemple) qui stockent les dépôts Git (pour votre instance GitLab). L'augmentation du nombre de workers Sidekiq ne réduit pas le temps passé au clonage des dépôts.

### Activer GitHub OAuth à l'aide d'une application OAuth GitHub Enterprise Cloud {#enable-github-oauth-using-a-github-enterprise-cloud-oauth-app}

Si vous appartenez à une [organisation GitHub Enterprise Cloud](https://docs.github.com/en/enterprise-cloud@latest/get-started/onboarding), vous pouvez configurer GitLab Self-Managed pour obtenir une [limite de débit de l'API GitHub](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#primary-rate-limit-for-authenticated-users) plus élevée.

Les requêtes à l'API GitHub sont généralement soumises à une limite de débit de 5 000 requêtes par heure. En suivant les étapes ci-dessous, vous obtenez une limite de débit plus élevée de 15 000 requêtes par heure, ce qui permet d'accélérer la durée globale de l'importation.

Prérequis :

- Vous avez accès à une [organisation GitHub Enterprise Cloud](https://docs.github.com/en/enterprise-cloud@latest/get-started/onboarding/getting-started-with-github-enterprise-cloud).
- GitLab est configuré pour activer [GitHub OAuth](../../../integration/github.md#enable-github-oauth-in-gitlab).

Pour activer une limite de débit plus élevée :

- [Créez une application OAuth dans GitHub](../../../integration/github.md#create-an-oauth-app-in-github). Vérifiez que l'application OAuth appartient à l'organisation Enterprise Cloud, et non à votre compte GitHub personnel.
- Effectuez l'importation du projet en utilisant [GitHub OAuth](#use-github-oauth).
- Facultatif. Par défaut, la connexion est activée pour tous les fournisseurs OAuth configurés. Si vous souhaitez activer GitHub OAuth pour les importations, mais empêcher les utilisateurs de se connecter à votre instance GitLab avec GitHub, vous pouvez [désactiver la connexion avec GitHub](../../../integration/omniauth.md#enable-or-disable-sign-in-with-an-omniauth-provider-without-disabling-import-sources).

## Données importées {#imported-data}

Les éléments suivants d'un projet sont importés :

- Toutes les branches dupliquées du projet liées aux pull requests ouvertes

  > [!note]
  > Les branches dupliquées sont importées avec un schéma de nommage similaire à `GH-SHA-username/pull-request-number/fork-name/branch`.

- Toutes les branches du projet
- Pièces jointes pour :
  - Commentaires
  - Descriptions des tickets
  - Descriptions des pull requests
  - Notes de release
- Règles de protection des branches
- [Collaborateurs (membres)](#collaborators-members)
- [Objets Git LFS](../../../topics/git/lfs/_index.md)
- Données du dépôt Git
- Commentaires des tickets et des pull requests
- Événements des tickets et des pull requests (peuvent être importés en tant qu'[élément supplémentaire](#select-additional-items-to-import))
- Les tickets
- Labels
- Les jalons
- Relecteurs assignés aux pull requests
- Informations sur la fusion des pull requests
- Revues de pull requests
- Commentaires de revue de pull requests
- Réponses aux discussions dans les revues de pull requests
- Suggestions de revue de pull requests
- Pull requests
- Contenu des notes de release
- Descriptions des dépôts
- Les pages wiki

Les références aux pull requests et aux tickets sont préservées. Chaque dépôt importé conserve son niveau de visibilité, sauf si ce [niveau de visibilité est restreint](../../public_access.md#restrict-use-of-public-or-internal-projects), auquel cas il prend par défaut la visibilité du projet par défaut.

### Règles de protection des branches et paramètres du projet {#branch-protection-rules-and-project-settings}

Les règles de protection des branches GitHub importées sont mappées à l'un des éléments suivants :

- Règles de protection des branches GitLab
- Paramètres GitLab à l'échelle du projet

| Règle GitHub                                                                                         | Règle GitLab                                                                                                                                                                                                                                                          |
|:----------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Exiger la résolution des conversations avant la fusion** pour la branche par défaut du projet                 | **Tous les fils de conversation doivent être résolus** [paramètre du projet](../merge_requests/_index.md#prevent-merge-unless-all-threads-are-resolved)                                                                                                                                         |
| **Exiger une pull request avant la fusion**                                                           | Option **Personne** dans les **Autorisés à pousser et fusionner** [paramètres de protection des branches](../repository/branches/protected.md#protect-a-branch)                                                                                                            |
| **Exiger des commits signés** pour la branche par défaut du projet                                         | **Rejeter les validations sans signature** [règle de push](../repository/push_rules.md#require-signed-commits) GitLab                                                                                                                                                          |
| **Autoriser les poussées forcées - Tout le monde**                                                                   | **Autorisé à forcer les poussées** [paramètre de protection des branches](../repository/branches/protected.md#allow-force-push)                                                                                                                                               |
| **Exiger une pull request avant la fusion - Exiger une revue des propriétaires du code**                         | **Exiger l'approbation des propriétaires du code** [paramètre de protection des branches](../repository/branches/protected.md#require-code-owner-approval)                                                                                                                        |
| **Exiger une pull request avant la fusion - Autoriser certains acteurs à ignorer les pull requests obligatoires** | Liste des utilisateurs dans les **Autorisés à pousser et fusionner** [paramètres de protection des branches](../repository/branches/protected.md#protect-a-branch). Sans abonnement GitLab Premium, la liste des utilisateurs autorisés à pousser et à fusionner est limitée aux rôles. |

La règle GitHub **Exiger que les vérifications de statut passent avant la fusion** n'est pas importée. Vous pouvez toujours créer manuellement des [vérifications de statut externes](../merge_requests/status_checks.md). Pour plus d'informations, consultez le [ticket 370948](https://gitlab.com/gitlab-org/gitlab/-/issues/370948).

### Collaborateurs (membres) {#collaborators-members}

Ces rôles de collaborateurs GitHub sont mappés aux [rôles de membre](../../permissions.md#roles) GitLab suivants :

| Rôle GitHub | Rôle GitLab mappé |
|:------------|:-------------------|
| Lire        | Invité              |
| Triage      | Rapporteur           |
| Écrire       | Développeur          |
| Maintain    | Chargé de maintenance         |
| Admin       | Propriétaire              |

GitHub Enterprise Cloud dispose de [rôles de dépôt personnalisés](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/about-custom-repository-roles). Ces rôles ne sont pas pris en charge et entraînent des importations partiellement terminées.

Pour importer des collaborateurs GitHub, vous devez disposer du rôle Write ou Maintain sur le projet GitHub. Sinon, l'importation des collaborateurs est ignorée.

## Importer depuis GitHub Enterprise sur un réseau interne {#import-from-github-enterprise-on-an-internal-network}

Si votre instance GitHub Enterprise se trouve sur un réseau interne inaccessible depuis Internet, vous pouvez utiliser un proxy inverse pour permettre à GitLab.com d'accéder à l'instance.

Le proxy doit :

- Transférer les requêtes vers l'instance GitHub Enterprise.
- Remplacer toutes les occurrences du nom d'hôte interne par le nom d'hôte public du proxy dans :
  - Le corps de la réponse de l'API.
  - L'en-tête `Link` de la réponse de l'API.

L'API GitHub utilise l'en-tête `Link` pour la pagination.

Après avoir configuré le proxy, testez-le en effectuant des requêtes API. Voici quelques exemples de commandes pour tester l'API :

```shell
curl --header "Authorization: Bearer <YOUR-TOKEN>" "https://{PROXY_HOSTNAME}/user"

### URLs in the response body should use the proxy hostname

{
  "login": "example_username",
  "id": 1,
  "url": "https://{PROXY_HOSTNAME}/users/example_username",
  "html_url": "https://{PROXY_HOSTNAME}/example_username",
  "followers_url": "https://{PROXY_HOSTNAME}/api/v3/users/example_username/followers",
  ...
  "created_at": "2014-02-11T17:03:25Z",
  "updated_at": "2022-10-18T14:36:27Z"
}
```

```shell
curl --head --header "Authorization: Bearer <YOUR-TOKEN>" "https://{PROXY_DOMAIN}/api/v3/repos/{repository_path}/pulls?states=all&sort=created&direction=asc"

### Link header should use the proxy hostname

HTTP/1.1 200 OK
Date: Tue, 18 Oct 2022 21:42:55 GMT
Server: GitHub.com
Content-Type: application/json; charset=utf-8
Cache-Control: private, max-age=60, s-maxage=60
...
X-OAuth-Scopes: repo
X-Accepted-OAuth-Scopes:
github-authentication-token-expiration: 2022-11-22 18:13:46 UTC
X-GitHub-Media-Type: github.v3; format=json
X-RateLimit-Limit: 5000
X-RateLimit-Remaining: 4997
X-RateLimit-Reset: 1666132381
X-RateLimit-Used: 3
X-RateLimit-Resource: core
Link: <https://{PROXY_DOMAIN}/api/v3/repositories/1/pulls?page=2>; rel="next", <https://{PROXY_DOMAIN}/api/v3/repositories/1/pulls?page=11>; rel="last"
```

Testez également que le clonage du dépôt via le proxy ne provoque pas d'échec :

```shell
git clone -c http.extraHeader="Authorization: basic <base64 encode YOUR-TOKEN>" --mirror https://{PROXY_DOMAIN}/{REPOSITORY_PATH}.git
```

### Exemple de configuration de proxy inverse {#sample-reverse-proxy-configuration}

La configuration suivante est un exemple de configuration d'Apache HTTP Server en tant que proxy inverse.

> [!warning]
> Par souci de simplicité, cet extrait ne contient pas de configuration pour chiffrer la connexion entre le client et le proxy. Cependant, pour des raisons de sécurité, vous devriez inclure cette configuration. Consultez l'[exemple de configuration Apache TLS/SSL](https://ssl-config.mozilla.org/#server=apache&version=2.4.41&config=intermediate&openssl=1.1.1k&guideline=5.6).

```plaintext
# Required modules
LoadModule filter_module lib/httpd/modules/mod_filter.so
LoadModule reflector_module lib/httpd/modules/mod_reflector.so
LoadModule substitute_module lib/httpd/modules/mod_substitute.so
LoadModule deflate_module lib/httpd/modules/mod_deflate.so
LoadModule headers_module lib/httpd/modules/mod_headers.so
LoadModule proxy_module lib/httpd/modules/mod_proxy.so
LoadModule proxy_connect_module lib/httpd/modules/mod_proxy_connect.so
LoadModule proxy_http_module lib/httpd/modules/mod_proxy_http.so
LoadModule ssl_module lib/httpd/modules/mod_ssl.so

<VirtualHost GITHUB_ENTERPRISE_HOSTNAME:80>
  ServerName GITHUB_ENTERPRISE_HOSTNAME

  # Enables reverse-proxy configuration with SSL support
  SSLProxyEngine On
  ProxyPass "/" "https://GITHUB_ENTERPRISE_HOSTNAME/"
  ProxyPassReverse "/" "https://GITHUB_ENTERPRISE_HOSTNAME/"

  # Replaces occurrences of the local GitHub Enterprise URL with the Proxy URL
  # GitHub Enterprise compresses the responses, the filters INFLATE and DEFLATE needs to be used to
  # decompress and compress the response back
  AddOutputFilterByType INFLATE;SUBSTITUTE;DEFLATE application/json
  Substitute "s|https://GITHUB_ENTERPRISE_HOSTNAME|https://PROXY_HOSTNAME|ni"
  SubstituteMaxLineLength 50M

  # GitHub API uses the response header "Link" for the API pagination
  # For example:
  #   <https://example.com/api/v3/repositories/1/issues?page=2>; rel="next", <https://example.com/api/v3/repositories/1/issues?page=3>; rel="last"
  # The directive below replaces all occurrences of the GitHub Enterprise URL with the Proxy URL if the
  # response header Link is present
  Header edit* Link "https://GITHUB_ENTERPRISE_HOSTNAME" "https://PROXY_HOSTNAME"
</VirtualHost>
```

## Sujets connexes {#related-topics}

- [Paramètres d'importation et d'exportation](../../../administration/settings/import_and_export_settings.md).
- [Configuration Sidekiq pour les importations](../../../administration/sidekiq/configuration_for_imports.md).
- [Exécuter plusieurs processus Sidekiq](../../../administration/sidekiq/extra_sidekiq_processes.md).
- [Traitement de classes de jobs spécifiques](../../../administration/sidekiq/processing_specific_job_classes.md).
