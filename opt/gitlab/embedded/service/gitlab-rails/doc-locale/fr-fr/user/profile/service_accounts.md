---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Comptes de service
description: Créez des comptes non-humains pour les processus automatisés et les intégrations de services tiers.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Comptes de service sur l'édition Gratuite :
  - [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225913) dans GitLab 18.10 [avec le feature flag](../../administration/feature_flags/_index.md) `service_accounts_available_on_free_or_unlicensed`. Fonctionnalité désactivée par défaut.
  - [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/227910) dans GitLab 18.11. Feature flag supprimé.
- Les comptes de service de projet [introduits](https://gitlab.com/gitlab-org/gitlab/-/work_items/585509) dans GitLab 18.10 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `allow_projects_to_create_service_accounts`. Fonctionnalité désactivée par défaut.
- Les comptes de service de sous-groupe [introduits](https://gitlab.com/gitlab-org/gitlab/-/work_items/585513) dans GitLab 18.10 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `allow_subgroups_to_create_service_accounts`. Fonctionnalité désactivée par défaut.
- Les comptes de service de sous-groupe et de projet [généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225485/) dans GitLab 18.11. Les feature flags `allow_subgroups_to_create_service_accounts` et `allow_projects_to_create_service_accounts` ont été supprimés.

{{< /history >}}

Les comptes de service sont des comptes utilisateur représentant des entités non-humaines plutôt que des personnes individuelles. Utilisez les comptes de service pour effectuer des actions automatisées, accéder à des données ou exécuter des processus planifiés. Les comptes de service sont couramment utilisés dans les pipelines ou les intégrations tierces où les identifiants doivent rester stables quelle que soit l'évolution de la composition de votre équipe.

Les comptes de service s'authentifient avec un [jeton d'accès personnel](personal_access_tokens.md). Ils peuvent interagir avec les [registres de paquets et de conteneurs](../packages/_index.md), effectuer des [opérations Git](personal_access_tokens.md#clone-repository-using-personal-access-token) et accéder à l'API.

Les comptes de service présentent les caractéristiques suivantes :

- Ils n'utilisent pas de siège.
- Ils ne sont pas des [utilisateurs facturables](../../subscriptions/manage_seats.md#billable-users) ni des [utilisateurs internes](../../administration/internal_users.md).
- Ils sont toujours marqués comme [utilisateurs externes](../../administration/external_users.md).
- Ils ne peuvent pas se connecter à GitLab via l'interface utilisateur.
- Ils ne peuvent pas être gérés via des services tels que LDAP.
- Ils ne peuvent pas créer de groupes principaux ni d'autres comptes de service lorsqu'ils sont provisionnés par un sous-groupe ou un projet.
- Ils apparaissent dans les listes de membres de groupe et de projet en tant que comptes de service, et non en tant qu'utilisateurs ordinaires.
- Ils ne reçoivent pas d'e-mails de notification, sauf si vous ajoutez une [adresse e-mail personnalisée](../../api/service_accounts.md#create-an-instance-service-account).
- Ils sont disponibles sur les [versions d'essai](https://gitlab.com/-/trial_registrations/new?glm_source=docs.gitlab.com&glm_content=free-user-limit-faq/ee/user/free_user_limit.html) de GitLab. Sur GitLab.com, le propriétaire du groupe principal doit d'abord vérifier son identité.

Vous pouvez également gérer les comptes de service via l'[API des comptes de service](../../api/service_accounts.md). Pour gérer les clés SSH des comptes de service, utilisez l'[API des clés SSH et GPG utilisateur](../../api/user_keys.md). Vous ne pouvez pas gérer les clés SSH via l'interface utilisateur de GitLab.

Le nombre de comptes de service que vous pouvez créer dépend de votre abonnement et de votre offre :

- Avec GitLab Premium et Ultimate, vous pouvez créer un nombre illimité de comptes de service pour toutes les offres.
- Avec GitLab Free, les limites varient selon l'offre :
  - Pour GitLab.com, vous pouvez créer jusqu'à 100 comptes de service par groupe principal. Cela inclut les comptes de service créés dans des sous-groupes ou des projets.
  - Pour GitLab Self-Managed, vous pouvez créer jusqu'à 100 comptes de service pour l'ensemble de l'instance. Cela inclut les comptes de service créés au niveau de l'instance, du groupe ou du projet.

## Types de comptes de service {#types-of-service-accounts}

Les comptes de service sont de trois types, chacun avec une portée et des prérequis différents :

{{< tabs >}}

{{< tab title="Comptes de service d'instance" >}}

Les comptes de service d'instance sont créés via la zone d'administration et peuvent être invités dans n'importe quel groupe ou projet de l'instance.

Prérequis :

- Accès administrateur à l'instance.

{{< /tab >}}

{{< tab title="Comptes de service de groupe" >}}

Les comptes de service de groupe sont créés par un groupe spécifique et peuvent être invités dans le groupe où ils ont été créés ou dans tout sous-groupe ou projet descendant. Ils ne peuvent pas créer de groupes principaux ni de comptes de service.

Prérequis :

- Sur GitLab.com, vous devez avoir le rôle Propriétaire pour le groupe.
- Sur GitLab Self-Managed ou GitLab Dedicated, vous devez soit :
  - Être administrateur de l'instance.
  - Avoir le rôle Propriétaire dans un groupe et être [autorisé à créer des comptes de service](../../administration/settings/account_and_limit_settings.md#allow-top-level-group-owners-to-create-service-accounts).

{{< /tab >}}

{{< tab title="Comptes de service de projet" >}}

Les comptes de service de projet sont créés par un projet spécifique et ne sont disponibles que pour ce projet. Ils ne peuvent pas créer de groupes principaux ni de comptes de service.

Prérequis :

- Sur GitLab.com, vous devez avoir le rôle Mainteneur ou Propriétaire pour le projet.
- Sur GitLab Self-Managed ou GitLab Dedicated, vous devez soit :
  - Être administrateur de l'instance.
  - Avoir le rôle Mainteneur ou Propriétaire dans un projet.

{{< /tab >}}

{{< /tabs >}}

## Afficher et gérer les comptes de service {#view-and-manage-service-accounts}

{{< history >}}

- Introduit pour GitLab.com dans GitLab 17.11

{{< /history >}}

La page des comptes de service affiche des informations sur les comptes de service dans votre groupe, projet ou instance. Chaque groupe, projet et instance GitLab Self-Managed dispose d'une page de comptes de service distincte. Depuis ces pages, vous pouvez :

- Afficher tous les comptes de service pour votre groupe ou instance.
- Supprimer un compte de service.
- Modifier le nom ou le nom d'utilisateur d'un compte de service.
- Gérer les jetons d'accès personnels d'un compte de service.

{{< tabs >}}

{{< tab title="Comptes de service d'instance" >}}

Pour afficher les comptes de service pour l'ensemble de l'instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Comptes de service**.

{{< /tab >}}

{{< tab title="Comptes de service de groupe" >}}

Pour afficher les comptes de service pour un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Comptes de service**.

{{< /tab >}}

{{< tab title="Comptes de service de projet" >}}

Pour afficher les comptes de service pour un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Comptes de service**.

{{< /tab >}}

{{< /tabs >}}

### Créer un compte de service {#create-a-service-account}

{{< history >}}

- Introduit pour GitLab.com dans GitLab 16.3
- Les propriétaires de groupe principal peuvent créer des comptes de service [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163726) dans GitLab 17.5 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `allow_top_level_group_owners_to_create_service_accounts` pour GitLab Self-Managed. Fonctionnalité désactivée par défaut.
- Les propriétaires de groupe principal peuvent créer des comptes de service [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/172502) dans GitLab 17.6. Le feature flag `allow_top_level_group_owners_to_create_service_accounts` a été supprimé.

{{< /history >}}

Sur GitLab.com, seuls les propriétaires de groupe principal peuvent créer des comptes de service.

Par défaut, sur GitLab Self-Managed et GitLab Dedicated, seuls les administrateurs peuvent créer l'un ou l'autre type de compte de service. Cependant, vous pouvez [configurer l'instance](../../administration/settings/account_and_limit_settings.md#allow-top-level-group-owners-to-create-service-accounts) pour autoriser les propriétaires de groupe principal à créer des comptes de service de groupe.

Le nombre de comptes de service que vous pouvez créer dépend de votre abonnement et de votre offre :

- Avec GitLab Premium et Ultimate, vous pouvez créer un nombre illimité de comptes de service pour toutes les offres.
- Avec GitLab Free, les limites varient selon l'offre :
  - Pour GitLab.com, vous pouvez créer jusqu'à 100 comptes de service par groupe principal. Cela inclut les comptes de service créés dans des sous-groupes ou des projets.
  - Pour GitLab Self-Managed, vous pouvez créer jusqu'à 100 comptes de service pour l'ensemble de l'instance. Cela inclut les comptes de service créés au niveau de l'instance, du groupe ou du projet.

Pour créer un compte de service :

1. Accédez à la page [Comptes de service](#view-and-manage-service-accounts).
1. Sélectionnez **Ajouter un compte de service**.
1. Saisissez un nom pour le compte de service. Un nom d'utilisateur est automatiquement généré à partir du nom. Vous pouvez modifier le nom d'utilisateur si nécessaire.
1. Sélectionnez **Créer un compte de service**.

### Modifier un compte de service {#edit-a-service-account}

{{< history >}}

- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/work_items/581050) de limites de nom d'utilisateur pour les comptes de service avec des identités composites dans GitLab 18.9.

{{< /history >}}

Vous pouvez modifier le nom ou le nom d'utilisateur d'un compte de service.

> [!note]
> Vous ne pouvez pas mettre à jour le nom d'utilisateur d'un compte de service associé à une [identité composite](../duo_agent_platform/composite_identity.md).

Pour modifier un compte de service :

1. Accédez à la page [Comptes de service](#view-and-manage-service-accounts).
1. Identifiez un compte de service.
1. Sélectionnez l'ellipse verticale ({{< icon name="ellipsis_v" >}}) > **Modifier**.
1. Modifiez le nom ou le nom d'utilisateur du compte de service.
1. Sélectionnez **Enregistrer les modifications**.

### Ajouter un compte de service à un groupe ou un projet {#add-a-service-account-to-a-group-or-project}

Les comptes de service ont un accès limité jusqu'à ce que vous les ajoutiez en tant que membres d'un groupe ou d'un projet. Vous pouvez ajouter un nombre illimité de comptes de service à un groupe ou un projet, et chaque compte de service peut avoir un rôle différent dans chaque groupe, sous-groupe ou projet.

L'accès des comptes de service dépend du type de compte de service :

- Comptes de service d'instance : peuvent être invités dans n'importe quel groupe ou projet de l'instance.
- Comptes de service de groupe : peuvent être invités dans le groupe où ils ont été créés ou dans tout sous-groupe ou projet descendant.
- Comptes de service de projet : peuvent être invités uniquement dans le projet où ils ont été créés.

Lorsque vous [partagez un groupe avec un autre groupe](../project/members/sharing_projects_groups.md#invite-a-group-to-a-group), tous les membres du groupe partagé, y compris les comptes de service, obtiennent l'accès au groupe avec lequel il est partagé.

Si vous attribuez à un compte de service le rôle Propriétaire pour un groupe, les jetons d'accès personnels du compte de service ont également le rôle Propriétaire pour ce groupe.

Vous pouvez attribuer des comptes de service à des groupes et des projets en utilisant :

- L'interface utilisateur de GitLab :
  - [Ajouter des utilisateurs à un groupe](../group/_index.md#add-users-to-a-group).
  - [Ajouter des utilisateurs à un projet](../project/members/_index.md#add-users-to-a-project).
- L'API :
  - L'[API des membres de groupe](../../api/group_members.md).
  - L'[API des membres de projet](../../api/project_members.md).

> [!note]
> Si les paramètres [verrouillage global des appartenances aux groupes SAML](../group/saml_sso/group_sync.md#global-saml-group-memberships-lock) ou [verrouillage global des appartenances aux groupes LDAP](../../administration/auth/ldap/ldap_synchronization.md#global-ldap-group-memberships-lock) sont activés, vous devez utiliser l'API pour contrôler les appartenances des comptes de service.

## Dupliquer des projets avec un compte de service {#fork-projects-with-a-service-account}

Les comptes de service peuvent dupliquer des projets via l'[API de duplication de projet](../../api/project_forks.md), mais ne peuvent pas dupliquer vers leur espace de nommage personnel. Lors d'une duplication avec un compte de service, vous devez spécifier un espace de nommage de groupe cible.

Prérequis :

- Le compte de service a le rôle Développeur et est membre du groupe cible.
- La portée `api` est activée pour le jeton d'accès personnel du compte de service.

Pour dupliquer un projet à l'aide d'un compte de service :

1. Identifiez le groupe cible dans lequel la duplication est créée.
1. Assurez-vous que le compte de service est membre de ce groupe avec les autorisations appropriées.
1. Utilisez l'[API de duplication de projet](../../api/project_forks.md) avec `namespace_id` ou `namespace_path` :

   ```shell
    curl --request POST --header "PRIVATE-TOKEN: <service_account_token>" \
      --data "namespace_path=target-group" \
      "https://gitlab.example.com/api/v4/projects/<project_id>/fork"
   ```

### Supprimer un compte de service {#delete-a-service-account}

Lorsque vous supprimez un compte de service, toutes les contributions effectuées par ce compte sont conservées et la propriété est transférée à un utilisateur fantôme. Ces contributions peuvent inclure des activités telles que des merge requests, des tickets, des projets et des groupes.

Pour supprimer un compte de service :

1. Accédez à la page [Comptes de service](#view-and-manage-service-accounts).
1. Identifiez un compte de service.
1. Sélectionnez l'ellipse verticale ({{< icon name="ellipsis_v" >}}) > **Supprimer le compte**.
1. Saisissez le nom du compte de service.
1. Sélectionnez **Supprimer l'utilisateur**.

Vous pouvez également supprimer le compte de service et toutes les contributions effectuées par ce compte. Ces contributions peuvent inclure des activités telles que des merge requests, des tickets, des groupes et des projets.

1. Accédez à la page [Comptes de service](#view-and-manage-service-accounts).
1. Identifiez un compte de service.
1. Sélectionnez l'ellipse verticale ({{< icon name="ellipsis_v" >}}) > **Supprimer le compte et les contributions**.
1. Saisissez le nom du compte de service.
1. Sélectionnez **Supprimer l'utilisateur et ses contributions**.

Vous pouvez également supprimer des comptes de service via l'API.

- Pour les comptes de service d'instance, utilisez l'[API des utilisateurs](../../api/users.md#delete-a-user).
- Pour les comptes de service de groupe, utilisez l'[API des comptes de service](../../api/service_accounts.md#delete-a-group-service-account).

## Afficher et gérer les jetons d'accès personnels d'un compte de service {#view-and-manage-personal-access-tokens-for-a-service-account}

La page des jetons d'accès personnels affiche des informations sur les jetons d'accès personnels associés à un compte de service dans votre groupe principal ou instance. Depuis ces pages, vous pouvez :

- Filtrer, trier et afficher les détails des jetons d'accès personnels.
- Remplacer des jetons d'accès personnels.
- Révoquer des jetons d'accès personnels.

Vous pouvez également gérer les jetons d'accès personnels des comptes de service via l'API.

- Pour les comptes de service d'instance, utilisez l'[API des jetons d'accès personnels](../../api/personal_access_tokens.md).
- Pour les comptes de service de groupe, utilisez l'[API des comptes de service](../../api/service_accounts.md).

Pour afficher la page des jetons d'accès personnels d'un compte de service :

1. Accédez à la page [Comptes de service](#view-and-manage-service-accounts).
1. Identifiez un compte de service.
1. Sélectionnez l'ellipse verticale ({{< icon name="ellipsis_v" >}}) > **Gérer les jetons d'accès**.

### Créer un jeton d'accès personnel pour un compte de service {#create-a-personal-access-token-for-a-service-account}

Pour utiliser un compte de service, vous devez créer un jeton d'accès personnel afin d'authentifier les requêtes.

Pour créer un jeton d'accès personnel pour un compte de service :

1. Accédez à la page [Comptes de service](#view-and-manage-service-accounts).
1. Identifiez un compte de service.
1. Sélectionnez l'ellipse verticale ({{< icon name="ellipsis_v" >}}) > **Gérer les jetons d'accès**.
1. Sélectionnez **Ajouter un jeton**.
1. Dans **Nom du jeton**, saisissez un nom pour le jeton.
1. Facultatif. Dans **Description du jeton**, saisissez une description pour le jeton.
1. Dans **Date d'expiration**, saisissez une date d'expiration pour le jeton.
   - Le jeton expire à cette date à minuit UTC. Un jeton avec la date d'expiration du 2024-01-01 expire à 00:00:00 UTC le 2024-01-01.
   - Si vous ne saisissez pas de date d'expiration, celle-ci est automatiquement définie à 365 jours après la date actuelle.
   - Si les dates d'expiration ne sont pas obligatoires, le jeton est créé sans date d'expiration.
   - Par défaut, cette date peut être au maximum 365 jours après la date actuelle. Dans GitLab 17.6 ou une version ultérieure, vous pouvez [étendre cette limite à 400 jours](https://gitlab.com/gitlab-org/gitlab/-/issues/461901).
1. Sélectionnez les [portées souhaitées](../../security/tokens/access_token_scopes.md).
1. Sélectionnez **Créer un jeton d'accès personnel**.

### Remplacer un jeton d'accès personnel {#rotate-a-personal-access-token}

Vous pouvez remplacer un jeton d'accès personnel pour invalider le jeton actuel et générer une nouvelle valeur.

> [!warning]
> Cette action est irréversible. Les services qui reposent sur le jeton remplacé cessent de fonctionner.

Pour remplacer un jeton d'accès personnel d'un compte de service :

1. Accédez à la page [Comptes de service](#view-and-manage-service-accounts).
1. Identifiez un compte de service.
1. Sélectionnez l'ellipse verticale ({{< icon name="ellipsis_v" >}}) > **Gérer les jetons d'accès**.
1. À côté d'un jeton actif, sélectionnez l'ellipse verticale ({{< icon name="ellipsis_v" >}}).
1. Sélectionnez **Remplacer**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **Remplacer**.

### Révoquer un jeton d'accès personnel {#revoke-a-personal-access-token}

Vous pouvez révoquer un jeton d'accès personnel pour invalider le jeton actuel.

> [!warning]
> Cette action est irréversible. Les services qui reposent sur le jeton révoqué cessent de fonctionner.

Pour révoquer un jeton d'accès personnel d'un compte de service :

1. Accédez à la page [Comptes de service](#view-and-manage-service-accounts).
1. Identifiez un compte de service.
1. Sélectionnez l'ellipse verticale ({{< icon name="ellipsis_v" >}}) > **Gérer les jetons d'accès**.
1. À côté d'un jeton actif, sélectionnez l'ellipse verticale ({{< icon name="ellipsis_v" >}}).
1. Sélectionnez **Révoquer**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **Révoquer**.

## E-mails des comptes de service {#service-account-emails}

Lorsque vous créez un compte de service, GitLab génère une adresse e-mail sans réponse avec l'un des préfixes suivants :

- Instance : `service_account_`
- Groupe : `service_account_group_`
- Projet : `service_account_project_`

Les adresses e-mail personnalisées nécessitent une confirmation, sauf si le groupe principal dispose d'un [domaine vérifié](../enterprise_user/_index.md#manage-group-domains) correspondant ou si les paramètres de confirmation d'e-mail sont [désactivés](../../administration/settings/sign_up_restrictions.md#confirm-user-email).

## Limites de débit {#rate-limits}

Les [limites de débit](../../rate_limits/_index.md) s'appliquent aux comptes de service :

- Sur GitLab.com, les [limites de débit spécifiques à GitLab.com](../gitlab_com/rate_limits.md) s'appliquent.
- Sur GitLab Self-Managed et GitLab Dedicated, ces limites de débit s'appliquent :
  - [Limites de débit configurables](../../rate_limits/_index.md#configuration-options)
  - [Limites de débit non configurables](../../rate_limits/non_configurable.md)

## Sujets connexes {#related-topics}

- [Utilisateurs facturables](../../subscriptions/manage_seats.md#billable-users)
- [Enregistrements associés](account/delete_account.md#associated-records)
- [Jetons d'accès au projet - utilisateurs bot](../project/settings/project_access_tokens.md#bot-users-for-projects)
- [Jetons d'accès de groupe - utilisateurs bot](../group/settings/group_access_tokens.md#bot-users-for-groups)
- [Utilisateurs internes](../../administration/internal_users.md)
