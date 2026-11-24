---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Jetons d'accès au projet"
description: "Authentification, création, révocation et expiration des jetons."
availability_details: no
---

{{< details >}}

Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les jetons d'accès au projet fournissent un accès authentifié à un projet spécifique. Ils sont similaires aux jetons d'accès de groupe et aux jetons d'accès personnels, mais leur portée est limitée au projet associé plutôt qu'à un groupe ou un utilisateur. Vous ne pouvez pas utiliser les jetons d'accès au projet pour accéder aux ressources d'autres projets, ni pour créer d'autres jetons d'accès de groupe, de projet ou personnels.

Vous pouvez utiliser un jeton d'accès au projet pour vous authentifier :

- Avec l'[API GitLab](../../../api/rest/authentication.md#personal-project-and-group-access-tokens).
- Avec Git via HTTPS. Utilisez :
  - Toute valeur non vide en tant que nom d'utilisateur.
  - Le jeton d'accès au projet en tant que mot de passe.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

> [!note]
> Sur GitLab.com, les jetons d'accès au projet nécessitent un abonnement Premium ou Ultimate. Lors d'un [essai](https://about.gitlab.com/free-trial/#what-is-included-in-my-free-trial-what-is-excluded), vous êtes limité à un seul jeton d'accès au projet.
>
> Sur GitLab Self-Managed et GitLab Dedicated, les jetons d'accès au projet sont disponibles avec toute licence.

## Créer un jeton d'accès au projet {#create-a-project-access-token}

{{< history >}}

- La limite de durée de vie maximale autorisée a été [étendue à 400 jours](https://gitlab.com/gitlab-org/gitlab/-/issues/461901) dans GitLab 17.6 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `buffered_token_expiration_limit`. Fonctionnalité désactivée par défaut.
- La description du jeton d'accès au projet a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/443819) dans GitLab 17.7.

{{< /history >}}

> [!flag]
> Un feature flag contrôle la disponibilité de l'extension de la limite de durée de vie maximale autorisée. Pour plus d'informations, consultez l'historique.

Pour créer un jeton d'accès au projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Jetons d’accès**.
1. Sélectionnez **Ajouter un jeton**.
1. Dans **Nom du jeton**, saisissez un nom. Le nom du jeton est visible par tout utilisateur disposant des autorisations nécessaires pour consulter le projet.
1. Facultatif. Dans **Description du jeton**, saisissez une description pour le jeton.
1. Dans **Date d'expiration**, saisissez une date d'expiration pour le jeton.
   - Le jeton expire à minuit UTC à cette date.
   - Si vous ne saisissez pas de date, la date d'expiration est fixée à 365 jours à compter d'aujourd'hui.
   - Par défaut, la date d'expiration ne peut pas dépasser 365 jours à compter d'aujourd'hui. Dans GitLab 17.6 et les versions ultérieures, les administrateurs peuvent [modifier la durée de vie maximale des jetons d'accès](../../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens).
1. Sélectionnez un rôle pour le jeton.
1. Sélectionnez une ou plusieurs [portées du jeton d'accès au projet](../../../security/tokens/access_token_scopes.md).
1. Sélectionnez **Créer un jeton d'accès au projet**.

Un jeton d'accès au projet est affiché. Enregistrez le jeton d'accès au projet dans un endroit sécurisé. Après avoir quitté ou actualisé la page, vous ne pourrez plus le consulter.

Tous les jetons d'accès au projet héritent du [paramètre de préfixe par défaut](../../../administration/settings/account_and_limit_settings.md#personal-access-token-prefix) configuré pour les jetons d'accès personnels.

> [!warning]
> Les jetons d'accès au projet sont traités comme des utilisateurs internes. Si un utilisateur interne crée un jeton d'accès au projet, ce jeton peut accéder à tous les projets dont le niveau de visibilité est défini sur Interne.

## Consulter vos jetons d'accès {#view-your-access-tokens}

{{< history >}}

- Possibilité de consulter les adresses IP [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/428577) dans GitLab 17.8 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `pat_ip`. Activé par défaut dans la version 17.9.
- La possibilité de consulter les adresses IP est devenue [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/513302) dans GitLab 17.10. Le feature flag `pat_ip` a été supprimé.

{{< /history >}}

La page des jetons d'accès au projet affiche des informations sur vos jetons d'accès.

Depuis cette page, vous pouvez effectuer les actions suivantes :

- Créer, remplacer et révoquer des jetons d'accès au projet.
- Consulter tous les jetons d'accès au projet actifs et inactifs.
- Consulter les informations sur les jetons, notamment les portées, les rôles attribués et les dates d'expiration.
- Consulter les informations d'utilisation, notamment les dates d'utilisation et les cinq dernières adresses IP de connexion distinctes.
  > [!note]
  > GitLab met régulièrement à jour les informations d'utilisation des jetons lorsque le jeton effectue une opération Git ou authentifie une opération avec l'API [REST](../../../api/rest/_index.md) ou [GraphQL](../../../api/graphql/_index.md). Les heures d'utilisation des jetons sont mises à jour toutes les 10 minutes. Les adresses IP d'utilisation des jetons sont mises à jour toutes les minutes.

Pour consulter vos jetons d'accès au projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Jetons d’accès**.

Les jetons d'accès actifs et utilisables sont stockés dans la section **Jetons d'accès au projet actifs**. Les jetons expirés, remplacés ou révoqués sont stockés dans la section **Jetons d'accès projet inactifs**.

## Remplacer un jeton d'accès au projet {#rotate-a-project-access-token}

{{< history >}}

- Possibilité de consulter les jetons expirés et révoqués [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/462217) dans GitLab 17.3 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `retain_resource_access_token_user_after_revoke`. Fonctionnalité désactivée par défaut.
- Possibilité de consulter les jetons expirés et révoqués jusqu'à leur suppression automatique, devenue [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/471683) dans GitLab 17.9. Le feature flag `retain_resource_access_token_user_after_revoke` a été supprimé.

{{< /history >}}

Remplacez un jeton pour en créer un nouveau avec les mêmes autorisations et la même portée que l'original. Le jeton d'origine devient immédiatement inactif, et GitLab conserve les deux versions à des fins d'audit. Vous pouvez consulter les jetons actifs et inactifs sur la page des jetons d'accès.

Sur GitLab Self-Managed et GitLab Dedicated, vous pouvez modifier la [période de rétention des jetons inactifs](../../../administration/settings/account_and_limit_settings.md#inactive-project-and-group-access-token-retention-period).

> [!warning]
> Cette action est irréversible. Les outils qui reposent sur un jeton d'accès remplacé cesseront de fonctionner jusqu'à ce que vous référenciez votre nouveau jeton.

Pour remplacer un jeton d'accès au projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Jetons d’accès**.
1. Pour le jeton concerné, sélectionnez **Remplacer** ({{< icon name="retry" >}}).
1. Dans la boîte de dialogue de confirmation, sélectionnez **Remplacer**.

## Révoquer un jeton d'accès au projet {#revoke-a-project-access-token}

{{< history >}}

- Possibilité de consulter les jetons expirés et révoqués [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/462217) dans GitLab 17.3 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `retain_resource_access_token_user_after_revoke`. Fonctionnalité désactivée par défaut.
- Possibilité de consulter les jetons expirés et révoqués jusqu'à leur suppression automatique, devenue [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/471683) dans GitLab 17.9. Le feature flag `retain_resource_access_token_user_after_revoke` a été supprimé.

{{< /history >}}

Révoquez un jeton pour l'invalider immédiatement et empêcher toute utilisation ultérieure. Les jetons révoqués ne sont pas supprimés immédiatement, mais vous pouvez filtrer les listes de jetons pour n'afficher que les jetons actifs. Par défaut, GitLab supprime les jetons d'accès de groupe et de projet révoqués après 30 jours. Pour plus d'informations, consultez la section [rétention des jetons inactifs](../../../administration/settings/account_and_limit_settings.md#inactive-project-and-group-access-token-retention-period).

> [!warning]
> Cette action est irréversible. Les outils qui reposent sur un jeton d'accès révoqué cesseront de fonctionner jusqu'à ce que vous ajoutiez un nouveau jeton.

Pour révoquer un jeton d'accès au projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Jetons d’accès**.
1. Pour le jeton concerné, sélectionnez **Révoquer** ({{< icon name="remove" >}}).
1. Dans la boîte de dialogue de confirmation, sélectionnez **Révoquer**.

## Expiration des jetons d'accès {#access-token-expiration}

Les jetons d'accès personnels, de groupe et de projet expirent à minuit UTC à la date d'expiration. Une fois expirés, ils ne peuvent plus être utilisés pour authentifier les requêtes.

Les nouveaux jetons d'accès doivent obligatoirement avoir une date d'expiration. Si aucune date d'expiration n'est explicitement définie lors de la création du jeton, une date d'expiration de 365 jours à compter de la date actuelle est appliquée. Dans GitLab Ultimate, les administrateurs peuvent configurer une [durée de vie maximale autorisée](../../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens) pour les jetons d'accès.

Selon votre version et votre offre GitLab, une date d'expiration peut être automatiquement appliquée à vos jetons d'accès existants lors de la mise à niveau de GitLab. Pour plus d'informations, consultez la section [jetons d'accès sans expiration](../../../update/deprecations.md#non-expiring-access-tokens).

### E-mails d'expiration des jetons d'accès au projet {#project-access-token-expiry-emails}

{{< history >}}

- Notifications d'expiration à 60 et 30 jours [introduites](https://gitlab.com/gitlab-org/gitlab/-/issues/464040) dans GitLab 17.6 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `expiring_pats_30d_60d_notifications`. Fonctionnalité désactivée par défaut.
- Notifications à 60 et 30 jours [généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/173792) dans GitLab 17.7. Le feature flag `expiring_pats_30d_60d_notifications` a été supprimé.
- Notifications aux membres de groupe hérités [introduites](https://gitlab.com/gitlab-org/gitlab/-/issues/463016) dans GitLab 17.7 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `pat_expiry_inherited_members_notification`. Fonctionnalité désactivée par défaut.
- Feature flag `pat_expiry_inherited_members_notification` [activé par défaut dans GitLab 17.10](https://gitlab.com/gitlab-org/gitlab/-/issues/393772).
- Feature flag `pat_expiry_inherited_members_notification` supprimé dans GitLab `17.11`

{{< /history >}}

GitLab effectue une vérification quotidienne à 1 h 00 UTC pour identifier les jetons d'accès au projet qui expirent prochainement. Les membres directs disposant du rôle Chargé de maintenance ou Propriétaire sont informés par e-mail sept jours avant l'expiration d'un jeton. Dans GitLab 17.6 et les versions ultérieures, des notifications sont également envoyées 30 et 60 jours avant l'expiration d'un jeton.

Dans GitLab 17.7 et les versions ultérieures, les membres disposant d'un rôle Chargé de maintenance ou Propriétaire hérité peuvent également recevoir ces e-mails. Vous pouvez configurer cela pour chaque groupe et projet sur l'[instance GitLab](../../../administration/settings/email.md#group-and-project-access-token-expiry-emails-to-inherited-members) ou un [groupe parent spécifique](../../group/manage.md#expiry-emails-for-group-and-project-access-tokens). Si ce paramètre est appliqué à un groupe parent, il est hérité par tous les groupes et projets descendants.

Les jetons expirés apparaissent dans la section des jetons d'accès au projet inactifs jusqu'à leur suppression automatique. Sur GitLab Self-Managed, vous pouvez modifier cette [période de rétention](../../../administration/settings/account_and_limit_settings.md#inactive-project-and-group-access-token-retention-period).

## Utilisateurs bot pour les projets {#bot-users-for-projects}

{{< history >}}

- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/462217) dans GitLab 17.2 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `retain_resource_access_token_user_after_revoke`. Fonctionnalité désactivée par défaut. Lorsqu'il est activé, les nouveaux utilisateurs bot sont ajoutés en tant que membres sans date d'expiration et, lorsque le jeton est ultérieurement révoqué ou expire, l'utilisateur bot est conservé pendant 30 jours.
- La rétention des utilisateurs bot inactifs est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/462217) dans GitLab 17.9. Le feature flag `retain_resource_access_token_user_after_revoke` a été supprimé.

{{< /history >}}

Lorsque vous créez un jeton d'accès au projet, GitLab crée un utilisateur bot et l'associe au jeton.

Les utilisateurs bot ont les propriétés suivantes :

- Ils se voient accorder des autorisations correspondant au rôle et à la portée du jeton d'accès associé.
- Ils sont membres du projet, mais ne peuvent pas être retirés du projet ni ajoutés directement à d'autres groupes ou projets.
- Ils sont des [utilisateurs non facturables](../../../subscriptions/manage_seats.md#criteria-for-non-billable-users) et ne sont pas comptabilisés dans votre limite de licence.
- Leurs contributions sont associées au compte de l'utilisateur bot.
- Lorsqu'ils sont supprimés, leurs contributions sont transférées vers un [utilisateur fantôme](../../profile/account/delete_account.md#associated-records).

Lorsque l'utilisateur bot est créé, les attributs suivants sont définis :

| Attribut | Valeur                                                                                                    | Exemple |
| --------- | -------------------------------------------------------------------------------------------------------- | ------- |
| Nom      | Le nom du jeton d'accès associé.                                                                 | `Main token - Read registry` |
| Nom d'utilisateur  | Généré dans ce format : `project_{project_id}_bot_{random_string}`                                     | `project_123_bot_4ffca233d8298ea1` |
| E-mail     | Généré dans ce format : `project_{project_id}_bot_{random_string}@noreply.{Gitlab.config.gitlab.host}` | `project_123_bot_4ffca233d8298ea1@noreply.example.com` |

## Restreindre la création de jetons d'accès au projet {#restrict-the-creation-of-project-access-tokens}

Pour limiter les abus potentiels, vous pouvez empêcher les utilisateurs de créer des jetons d'accès pour les projets d'un groupe principal. Les jetons existants restent valides jusqu'à leur expiration ou leur révocation manuelle.

Pour plus d'informations, consultez la section [restreindre la création de jetons d'accès de groupe et de projet](../../group/settings/group_access_tokens.md#restrict-the-creation-of-group-and-project-access-tokens).

## Sujets connexes {#related-topics}

- [Jetons d'accès personnels](../../profile/personal_access_tokens.md)
- [Jetons d'accès de groupe](../../group/settings/group_access_tokens.md)
- [API des jetons d'accès au projet](../../../api/project_access_tokens.md)
