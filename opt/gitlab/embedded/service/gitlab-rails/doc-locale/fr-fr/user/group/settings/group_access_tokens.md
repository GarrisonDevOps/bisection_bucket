---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Jetons d'accès au groupe"
availability_details: no
---

{{< details >}}

- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les jetons d'accès au groupe fournissent un accès authentifié à un groupe et à ses projets. Ils sont similaires aux jetons d'accès personnels et aux jetons d'accès au projet, mais sont associés à un groupe plutôt qu'à un utilisateur ou à un projet. Vous ne pouvez pas utiliser les jetons d'accès au groupe pour créer d'autres jetons d'accès au groupe, au projet ou personnels.

Vous pouvez utiliser un jeton d'accès au groupe pour vous authentifier :

- Avec l'[API GitLab](../../../api/rest/authentication.md#personal-project-and-group-access-tokens).
- Avec Git via HTTPS. Utilisez :
  - N'importe quelle valeur non vide comme nom d'utilisateur.
  - Le jeton d'accès au groupe comme mot de passe.

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.

> [!note]
> Sur GitLab.com, les jetons d'accès au groupe nécessitent un abonnement Premium ou Ultimate. Ils ne sont pas disponibles durant un [essai](https://about.gitlab.com/free-trial/#what-is-included-in-my-free-trial-what-is-excluded).
>
> Sur GitLab Self-Managed et GitLab Dedicated, les jetons d'accès au groupe sont disponibles avec n'importe quelle licence.

## Créer un jeton d'accès au groupe {#create-a-group-access-token}

{{< history >}}

- La limite de durée de vie maximale autorisée [étendue à 400 jours](https://gitlab.com/gitlab-org/gitlab/-/issues/461901) dans GitLab 17.6 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `buffered_token_expiration_limit`. Fonctionnalité désactivée par défaut.
- La description du jeton d'accès au groupe [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/443819) dans GitLab 17.7.

{{< /history >}}

> [!flag]
> Un feature flag contrôle la disponibilité de l'extension de la limite de durée de vie maximale autorisée. Pour plus d'informations, consultez l'historique.

### Avec l'interface utilisateur {#with-the-ui}

Pour créer un jeton d'accès au groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Jetons d’accès**.
1. Sélectionnez **Ajouter un jeton**.
1. Dans **Nom du jeton**, saisissez un nom. Le nom du jeton est visible par tout utilisateur ayant les permissions nécessaires pour consulter le groupe.
1. Facultatif. Dans **Description du jeton**, saisissez une description pour le jeton.
1. Dans **Date d'expiration**, saisissez une date d'expiration pour le jeton.
   - Le jeton expire à minuit UTC à cette date.
   - Si vous ne saisissez pas de date, la date d'expiration est fixée à 365 jours à compter d'aujourd'hui.
   - Par défaut, la date d'expiration ne peut pas dépasser 365 jours à compter d'aujourd'hui. Dans GitLab 17.6 et les versions ultérieures, les administrateurs peuvent [modifier la durée de vie maximale des jetons d'accès](../../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens).
1. Sélectionnez un rôle pour le jeton.
1. Sélectionnez une ou plusieurs [portées de jeton d'accès au groupe](../../../security/tokens/access_token_scopes.md).
1. Sélectionnez **Créer un jeton d'accès au groupe**.

Un jeton d'accès au groupe s'affiche. Enregistrez le jeton d'accès au groupe dans un endroit sûr. Après avoir quitté ou actualisé la page, vous ne pourrez plus le consulter.

Tous les jetons d'accès au groupe héritent du [paramètre de préfixe par défaut](../../../administration/settings/account_and_limit_settings.md#personal-access-token-prefix) configuré pour les jetons d'accès personnels.

> [!warning]
> Les jetons d'accès au groupe sont traités comme des utilisateurs internes. Si un utilisateur interne crée un jeton d'accès au groupe, ce jeton peut accéder à tous les projets dont le niveau de visibilité est défini sur Interne.

### Avec la console Rails {#with-the-rails-console}

Si vous êtes administrateur, vous pouvez créer des jetons d'accès au groupe dans la console Rails :

1. Exécutez les commandes suivantes dans une [console Rails](../../../administration/operations/rails_console.md) :

   ```ruby
   # Set the GitLab administration user to use. If user ID 1 is not available or is not an administrator, use 'admin = User.admins.first' instead to select an administrator.
   admin = User.find(1)

   # Set the group you want to create a token for. For example, group with ID 109.
   group = Group.find(109)

   # Create the group bot user. For further group access tokens, the username should be `group_{group_id}_bot_{random_string}` and email address `group_{group_id}_bot_{random_string}@noreply.{Gitlab.config.gitlab.host}`.
   random_string = SecureRandom.hex(16)
   service_response = Users::CreateService.new(admin, { name: 'group_token', username: "group_#{group.id}_bot_#{random_string}", email: "group_#{group.id}_bot_#{random_string}@noreply.#{Gitlab.config.gitlab.host}", user_type: :project_bot }).execute
   bot = service_response.payload[:user] if service_response.success?

   # Confirm the group bot.
   bot.confirm

   # Add the bot to the group with the required role.
   group.add_member(bot, :maintainer)

   # Give the bot a personal access token.
   token = bot.personal_access_tokens.create(scopes:[:api, :write_repository], name: 'group_token')

   # Get the token value.
   gtoken = token.token
   ```

1. Testez si le jeton d'accès au groupe généré fonctionne :

   1. Utilisez le jeton d'accès au groupe dans l'en-tête `PRIVATE-TOKEN` avec les API REST GitLab. Par exemple :

      - [Créez un epic](../../../api/epics.md#create-an-epic) dans le groupe.
      - [Créez un pipeline de projet](../../../api/pipelines.md#create-a-new-pipeline) dans l'un des projets du groupe.
      - [Créez un ticket](../../../api/issues.md#create-an-issue) dans l'un des projets du groupe.

   1. Utilisez le jeton de groupe pour [cloner un projet du groupe](../../../topics/git/clone.md#clone-with-https) via HTTPS.

## Afficher vos jetons d'accès {#view-your-access-tokens}

{{< history >}}

- Possibilité d'afficher les adresses IP [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/428577) dans GitLab 17.8 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `pat_ip`. Activé par défaut dans la version 17.9.
- Possibilité d'afficher les adresses IP rendue [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/513302) dans GitLab 17.10. Le feature flag `pat_ip` a été supprimé.

{{< /history >}}

La page des jetons d'accès au groupe affiche des informations sur vos jetons d'accès.

Depuis cette page, vous pouvez effectuer les actions suivantes :

- Créer, remplacer et révoquer des jetons d'accès au groupe.
- Afficher tous les jetons d'accès au groupe actifs et inactifs.
- Afficher les informations sur les jetons, notamment les portées, les rôles attribués et les dates d'expiration.
- Afficher les informations d'utilisation, notamment les dates d'utilisation et les cinq dernières adresses IP de connexion distinctes.
  > [!note]
  > GitLab met périodiquement à jour les informations d'utilisation des jetons lorsque le jeton effectue une opération Git ou authentifie une opération avec l'API [REST](../../../api/rest/_index.md) ou [GraphQL](../../../api/graphql/_index.md). Les heures d'utilisation des jetons sont mises à jour toutes les 10 minutes, les adresses IP d'utilisation des jetons sont mises à jour toutes les minutes.

Pour afficher vos jetons d'accès au groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Jetons d’accès**.

Les jetons d'accès actifs et utilisables sont stockés dans la section **Jetons d'accès au groupe actifs**. Les jetons expirés, remplacés ou révoqués sont stockés dans la section **Jetons d'accès groupe inactifs**.

## Remplacer un jeton d'accès au groupe {#rotate-a-group-access-token}

{{< history >}}

- Possibilité d'afficher les jetons expirés et révoqués [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/462217) dans GitLab 17.3 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `retain_resource_access_token_user_after_revoke`. Fonctionnalité désactivée par défaut.
- Possibilité d'afficher les jetons expirés et révoqués jusqu'à leur suppression automatique [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/471683) dans GitLab 17.9. Le feature flag `retain_resource_access_token_user_after_revoke` a été supprimé.

{{< /history >}}

Remplacez un jeton pour en créer un nouveau avec les mêmes permissions et la même portée que l'original. Le jeton original devient immédiatement inactif, et GitLab conserve les deux versions à des fins d'audit. Vous pouvez afficher les jetons actifs et inactifs sur la page des jetons d'accès.

Sur GitLab Self-Managed et GitLab Dedicated, vous pouvez modifier la [période de rétention des jetons inactifs](../../../administration/settings/account_and_limit_settings.md#inactive-project-and-group-access-token-retention-period).

> [!warning]
> Cette action est irréversible. Les outils qui dépendent d'un jeton d'accès remplacé cesseront de fonctionner jusqu'à ce que vous référenciez votre nouveau jeton.

Pour remplacer un jeton d'accès au groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Jetons d’accès**.
1. Pour le jeton concerné, sélectionnez **Remplacer** ({{< icon name="retry" >}}).
1. Dans la boîte de dialogue de confirmation, sélectionnez **Remplacer**.

## Révoquer un jeton d'accès au groupe {#revoke-a-group-access-token}

{{< history >}}

- Possibilité d'afficher les jetons expirés et révoqués [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/462217) dans GitLab 17.3 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `retain_resource_access_token_user_after_revoke`. Fonctionnalité désactivée par défaut.
- Possibilité d'afficher les jetons expirés et révoqués jusqu'à leur suppression automatique [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/471683) dans GitLab 17.9. Le feature flag `retain_resource_access_token_user_after_revoke` a été supprimé.

{{< /history >}}

Révoquez un jeton pour l'invalider immédiatement et empêcher toute utilisation ultérieure. Les jetons révoqués ne sont pas supprimés immédiatement, mais vous pouvez filtrer les listes de jetons pour n'afficher que les jetons actifs. Par défaut, GitLab supprime les jetons d'accès au groupe et au projet révoqués après 30 jours. Pour plus d'informations, consultez la section [rétention des jetons inactifs](../../../administration/settings/account_and_limit_settings.md#inactive-project-and-group-access-token-retention-period).

> [!warning]
> Cette action est irréversible. Les outils qui dépendent d'un jeton d'accès révoqué cesseront de fonctionner jusqu'à ce que vous ajoutiez un nouveau jeton.

Pour révoquer un jeton d'accès au groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Jetons d’accès**.
1. Pour le jeton concerné, sélectionnez **Révoquer** ({{< icon name="remove" >}}).
1. Dans la boîte de dialogue de confirmation, sélectionnez **Révoquer**.

## Expiration des jetons d'accès {#access-token-expiration}

Les jetons d'accès personnels, au groupe et au projet expirent à minuit UTC à la date d'expiration. Une fois expirés, ils ne peuvent plus être utilisés pour authentifier des requêtes.

Les nouveaux jetons d'accès doivent avoir une date d'expiration. Si aucune date d'expiration n'est explicitement définie lors de la création du jeton, une date d'expiration de 365 jours à compter de la date actuelle est appliquée. Dans GitLab Ultimate, les administrateurs peuvent configurer une [durée de vie maximale autorisée](../../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens) pour les jetons d'accès.

Selon votre version de GitLab et votre offre, vos jetons d'accès existants peuvent se voir automatiquement attribuer une date d'expiration lors de la mise à niveau de GitLab. Pour plus d'informations, consultez la section [jetons d'accès sans expiration](../../../update/deprecations.md#non-expiring-access-tokens).

### E-mails d'expiration des jetons d'accès au groupe {#group-access-token-expiry-emails}

{{< history >}}

- Notifications d'expiration à 60 et 30 jours [introduites](https://gitlab.com/gitlab-org/gitlab/-/issues/464040) dans GitLab 17.6 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `expiring_pats_30d_60d_notifications`. Fonctionnalité désactivée par défaut.
- Notifications à 60 et 30 jours [généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/173792) dans GitLab 17.7. Le feature flag `expiring_pats_30d_60d_notifications` a été supprimé.
- Notifications aux membres hérités du groupe [introduites](https://gitlab.com/gitlab-org/gitlab/-/issues/463016) dans GitLab 17.7 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `pat_expiry_inherited_members_notification`. Fonctionnalité désactivée par défaut.
- Feature flag `pat_expiry_inherited_members_notification` [activé par défaut dans GitLab 17.10](https://gitlab.com/gitlab-org/gitlab/-/issues/393772).
- Feature flag `pat_expiry_inherited_members_notification` supprimé dans GitLab `17.11`

{{< /history >}}

GitLab effectue une vérification quotidienne à 1h00 UTC pour identifier les jetons d'accès au groupe qui expirent prochainement. Les membres directs ayant le rôle Propriétaire sont notifiés par e-mail sept jours avant l'expiration d'un jeton. Dans GitLab 17.6 et versions ultérieures, des notifications sont également envoyées 30 et 60 jours avant l'expiration d'un jeton.

Dans GitLab 17.7 et versions ultérieures, les membres hérités ayant le rôle Propriétaire peuvent également recevoir ces e-mails. Vous pouvez configurer cela pour chaque groupe sur l'[instance GitLab](../../../administration/settings/email.md#group-and-project-access-token-expiry-emails-to-inherited-members) ou pour un [groupe spécifique](../manage.md#expiry-emails-for-group-and-project-access-tokens). Si ce paramètre est appliqué à un groupe parent, il est hérité par tous les groupes et projets descendants.

Les jetons expirés apparaissent dans la section des jetons d'accès au groupe inactifs jusqu'à leur suppression automatique. Sur GitLab Self-Managed, vous pouvez modifier cette [période de rétention](../../../administration/settings/account_and_limit_settings.md#inactive-project-and-group-access-token-retention-period).

## Utilisateurs bots pour les groupes {#bot-users-for-groups}

Lorsque vous créez un jeton d'accès au groupe, GitLab crée un utilisateur bot et l'associe au jeton.

Les utilisateurs bots ont les propriétés suivantes :

- Ils se voient accorder des permissions correspondant au rôle et à la portée du jeton d'accès associé.
- Ils sont membres du groupe et héritent de l'appartenance aux sous-groupes et aux projets, mais ne peuvent pas être ajoutés directement à d'autres groupes ou projets.
- Ils sont des [utilisateurs non facturables](../../../subscriptions/manage_seats.md#criteria-for-non-billable-users) et ne sont pas comptabilisés dans votre limite de licence.
- Leurs contributions sont associées au compte de l'utilisateur bot.
- Lorsqu'ils sont supprimés, leurs contributions sont transférées vers un [utilisateur fantôme](../../profile/account/delete_account.md#associated-records).

Lorsque l'utilisateur bot est créé, les attributs suivants sont définis :

| Attribut | Valeur                                                                                                | Exemple |
| --------- | ---------------------------------------------------------------------------------------------------- | ------- |
| Nom      | Le nom du jeton d'accès associé.                                                             | `Main token - Read registry` |
| Nom d'utilisateur  | Généré dans ce format : `group_{group_id}_bot_{random_string}`                                     | `group_123_bot_4ffca233d8298ea1` |
| E-mail     | Généré dans ce format : `group_{group_id}_bot_{random_string}@noreply.{Gitlab.config.gitlab.host}` | `group_123_bot_4ffca233d8298ea1@noreply.example.com` |

## Restreindre la création de jetons d'accès au groupe et au projet {#restrict-the-creation-of-group-and-project-access-tokens}

Pour limiter les abus potentiels, vous pouvez empêcher les utilisateurs de créer des jetons d'accès au groupe et au projet. La restriction couvre l'ensemble du groupe, y compris tous les sous-groupes et leurs projets. Les jetons existants restent valides jusqu'à leur expiration ou jusqu'à ce que vous les révoquiez.

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.
- Le groupe doit être un groupe principal.
- Sur GitLab.com, le groupe doit disposer d'un abonnement Premium ou Ultimate.

Pour restreindre la création de jetons d'accès :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Sélectionnez **Paramètres** > **Généralités**.
1. Développez **Permissions et fonctionnalités du groupe**.
1. Décochez la case **Les utilisateurs peuvent créer des jetons d'accès au groupe et au projet dans ce groupe**.
1. Sélectionnez **Enregistrer les modifications**.

## Sujets connexes {#related-topics}

- [Jetons d'accès personnels](../../profile/personal_access_tokens.md)
- [Jetons d'accès au projet](../../project/settings/project_access_tokens.md)
- [API des jetons d'accès au groupe](../../../api/group_access_tokens.md)
