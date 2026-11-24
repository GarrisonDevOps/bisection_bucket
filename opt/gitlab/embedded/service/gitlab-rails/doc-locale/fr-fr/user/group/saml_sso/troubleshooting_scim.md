---
stage: Fulfillment
group: Seat Management
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Dépannage de SCIM
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Cette section contient des solutions possibles aux problèmes que vous pourriez rencontrer.

## Impossible d'ajouter un utilisateur après sa suppression {#user-cannot-be-added-after-they-are-removed}

Lorsque vous supprimez un utilisateur, il est retiré du groupe, mais son compte n'est pas supprimé (voir [supprimer l'accès](scim_setup.md#remove-access)).

Lorsque l'utilisateur est de nouveau ajouté à l'application SCIM, GitLab ne crée pas de nouvel utilisateur car l'utilisateur existe déjà.

Lorsqu'un utilisateur est déprovisionné via SCIM, GitLab supprime son accès mais ne supprime pas son identité SAML liée. Lorsque cet utilisateur est de nouveau ajouté à l'application SCIM :

- L'attribut `active` de son identité SCIM est défini sur `true`.
- Il peut se connecter via SSO.

> [!note]
> Dans de rares cas, les utilisateurs qui ont été déprovisionnés avant que ce comportement ne soit généralement disponible pourraient encore avoir besoin de relier leur identité SAML. Si vous rencontrez des problèmes de connexion après avoir été de nouveau ajouté, vous pouvez [lier SAML à votre compte GitLab.com existant](_index.md#link-saml-to-your-existing-gitlabcom-account).

### GitLab Self-Managed {#gitlab-self-managed}

Pour GitLab Self-Managed, les administrateurs de cette instance peuvent à la place [ajouter l'identité de l'utilisateur eux-mêmes](../../../administration/admin_area.md#user-identities). Cela peut faire gagner du temps si les administrateurs ont besoin de rajouter plusieurs identités.

## Impossible pour l'utilisateur de se connecter {#user-cannot-sign-in}

Voici les solutions possibles aux problèmes empêchant les utilisateurs de se connecter :

- Vérifiez que l'utilisateur a bien été ajouté à l'application SCIM.
- Si vous recevez l'erreur `User is not linked to a SAML account`, l'utilisateur existe probablement déjà dans GitLab. Demandez à l'utilisateur de suivre les instructions [Lier les identités SCIM et SAML](scim_setup.md#link-scim-and-saml-identities). Sinon, les administrateurs de GitLab Self-Managed peuvent [ajouter une identité d'utilisateur](../../../administration/admin_area.md#user-identities).
- La valeur **Identité** (`extern_uid`) stockée par GitLab est mise à jour par SCIM chaque fois que `id` ou `externalId` change. Les utilisateurs ne peuvent pas se connecter si l'identifiant GitLab (`extern_uid`) de la méthode de connexion ne correspond pas à l'identifiant envoyé par le fournisseur, tel que le `NameId` envoyé par SAML. Cette valeur est également utilisée par SCIM pour identifier les utilisateurs via `id`, et est mise à jour par SCIM chaque fois que les valeurs `id` ou `externalId` changent.
- Sur GitLab.com, les valeurs SCIM `id` et SCIM `externalId` doivent être configurées avec la même valeur que le `NameId` SAML. Vous pouvez tracer les réponses SAML à l'aide des [outils de débogage](troubleshooting.md#saml-debugging-tools), et vérifier les erreurs par rapport aux informations de [dépannage SAML](troubleshooting.md).

## Incertitude quant à la correspondance entre le `NameId` SAML et le `externalId` SCIM de l'utilisateur {#unsure-if-users-saml-nameid-matches-the-scim-externalid}

Pour vérifier si le `NameId` SAML d'un utilisateur correspond à son `externalId` SCIM :

- Les administrateurs peuvent utiliser la zone **Admin** pour [lister les identités SCIM d'un utilisateur](../../../administration/admin_area.md#user-identities).
- Les propriétaires de groupe peuvent voir la liste des utilisateurs et l'identifiant stocké pour chaque utilisateur sur la page des paramètres SSO SAML du groupe.
- Vous pouvez utiliser l'[API SCIM](../../../api/scim.md) pour récupérer manuellement le `extern_uid` stocké par GitLab pour les utilisateurs et comparer la valeur pour chaque utilisateur depuis l'[API SAML](../../../api/saml.md).
- Demandez à l'utilisateur d'utiliser un [SAML Tracer](troubleshooting.md#saml-debugging-tools) et de comparer le `extern_uid` avec la valeur renvoyée en tant que `NameId` SAML.

## Incompatibilité entre le SCIM `extern_uid` et le SAML `NameId` {#mismatched-scim-extern_uid-and-saml-nameid}

Que la valeur ait été modifiée ou que vous ayez besoin de la mapper vers un champ différent, les éléments suivants doivent être mappés vers le même champ :

- `extern_Id`
- `NameId`

Si le SCIM `extern_uid` ne correspond pas au SAML `NameId`, vous devez mettre à jour le SCIM `extern_uid` pour permettre à l'utilisateur de se connecter.

Soyez prudent si vous modifiez les champs utilisés par votre fournisseur d'identité SCIM, généralement `extern_Id`. Votre fournisseur d'identité doit être configuré pour effectuer cette mise à jour. Dans certains cas, le fournisseur d'identité ne peut pas effectuer la mise à jour, par exemple lorsqu'une recherche d'utilisateur échoue.

GitLab utilise ces identifiants pour rechercher des utilisateurs. Si le fournisseur d'identité ne connaît pas les valeurs actuelles de ces champs, ce fournisseur peut créer des utilisateurs en double ou ne pas parvenir à effectuer les actions attendues.

Pour modifier les valeurs d'identifiant afin qu'elles correspondent, vous pouvez effectuer l'une des opérations suivantes :

- Demandez aux utilisateurs de se délier et de se relier eux-mêmes, sur la base de la section [Échec de l'authentification SAML : l'utilisateur a déjà été pris](troubleshooting.md#message-saml-authentication-failed-user-has-already-been-taken).
- Déliez tous les utilisateurs simultanément en les supprimant tous de l'application SCIM pendant que le provisionnement est activé.

  > [!warning]
  > Cette opération réinitialise les rôles de tous les utilisateurs dans le groupe principal et les sous-groupes selon le [rôle d'appartenance par défaut configuré](_index.md#configure-gitlab).

- Utilisez l'[API SAML](../../../api/saml.md) ou l'[API SCIM](../../../api/scim.md) pour corriger manuellement le `extern_uid` stocké pour les utilisateurs afin qu'il corresponde au `NameId` SAML ou au `externalId` SCIM.

Vous ne devez pas :

- Mettre à jour ces valeurs avec des valeurs incorrectes, car cela empêche les utilisateurs de se connecter.
- Attribuer une valeur au mauvais utilisateur, car cela entraîne la connexion des utilisateurs au mauvais compte.

De plus, l'adresse e-mail principale de l'utilisateur doit correspondre à l'adresse e-mail de votre fournisseur d'identité SCIM.

## Changer d'application SCIM {#change-scim-app}

Lors du changement d'application SCIM :

- Les utilisateurs peuvent suivre les instructions de la section [Changer l'application SAML](_index.md#change-the-identity-provider).
- Les administrateurs du fournisseur d'identité peuvent :
  1. Supprimer des utilisateurs de l'application SCIM, ce qui :
     - Sur GitLab.com, supprime tous les utilisateurs supprimés du groupe.
     - Sur GitLab Self-Managed, bloque les utilisateurs.
  1. Activer la synchronisation pour la nouvelle application SCIM afin de [lier les utilisateurs existants](scim_setup.md#link-scim-and-saml-identities).

## L'application SCIM renvoie l'erreur `"User has already been taken","status":409` {#scim-app-returns-user-has-already-been-takenstatus409-error}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

La modification de la configuration ou du fournisseur SAML ou SCIM peut entraîner les problèmes suivants :

- Incompatibilité d'identité SAML et SCIM. Pour résoudre ce problème :
  1. [Vérifiez que le `NameId` SAML de l'utilisateur correspond au `extern_uid` SCIM](#unsure-if-users-saml-nameid-matches-the-scim-externalid).
  1. [Mettez à jour ou corrigez l'incompatibilité entre le SCIM `extern_uid` et le SAML `NameId`](#mismatched-scim-extern_uid-and-saml-nameid).
- Incompatibilité d'identité SCIM entre GitLab et l'application SCIM du fournisseur d'identité. Pour résoudre ce problème :
  1. Utilisez l'[API SCIM](../../../api/scim.md), qui affiche le `extern_uid` de l'utilisateur stocké dans GitLab et le compare avec le `externalId` de l'utilisateur dans l'application SCIM.
  1. Utilisez la même API SCIM pour mettre à jour le `extern_uid` SCIM de l'utilisateur sur GitLab.com.

## L'adresse e-mail du membre n'est pas autorisée pour ce groupe {#the-members-email-address-is-not-allowed-for-this-group}

Le provisionnement SCIM peut échouer avec le statut HTTP `412` et le message d'erreur suivant :

```plaintext
The member's email address is not allowed for this group. Check with your administrator.
```

Cette erreur se produit lorsque les deux conditions suivantes sont vraies :

- [Restreindre l'accès au groupe par domaine](../access_and_permissions.md) est configuré pour le groupe.
- Le compte utilisateur en cours de provisionnement possède un domaine d'adresse e-mail qui n'est pas autorisé.

Pour résoudre ce problème, vous pouvez effectuer l'une des opérations suivantes :

- Ajouter le domaine d'adresse e-mail du compte utilisateur à la liste des domaines autorisés.
- Désactiver la fonctionnalité [Restreindre l'accès au groupe par domaine](../access_and_permissions.md) en supprimant tous les domaines.

## Rechercher des requêtes SCIM dans les journaux Rails {#search-rails-logs-for-scim-requests}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Les administrateurs de GitLab.com peuvent rechercher des requêtes SCIM dans le `api_json.log` en utilisant l'index `pubsub-rails-inf-gprd-*` dans Kibana. Utilisez les filtres suivants basés sur l'[API SCIM de groupe](../../../development/internal_api/_index.md#group-scim-api) interne :

- `json.path` : `/scim/v2/groups/<group-path>`
- `json.params.value` : `<externalId>`

Dans une entrée de journal pertinente, le `json.params.value` affiche les valeurs des paramètres SCIM reçus par GitLab. Utilisez ces valeurs pour vérifier si les paramètres SCIM configurés dans l'application SCIM d'un fournisseur d'identité sont bien communiqués à GitLab comme prévu.

Par exemple, utilisez ces valeurs comme source définitive pour comprendre pourquoi un compte a été provisionné avec un certain ensemble de détails. Ces informations peuvent être utiles lorsqu'un compte a été provisionné via SCIM avec des détails qui ne correspondent pas à la configuration de l'application SCIM.

## Erreur de non-liaison de l'adresse e-mail du membre dans le journal SCIM {#members-email-address-is-not-linked-error-in-scim-log}

Lorsque vous tentez de provisionner un utilisateur SCIM sur GitLab.com, GitLab vérifie si un utilisateur avec cette adresse e-mail existe déjà. Vous pouvez voir l'erreur suivante lorsque :

- L'utilisateur existe, mais n'a pas d'identité SAML liée.
- L'utilisateur existe, possède une identité SAML et une identité SCIM définie sur `active: false`.
- L'utilisateur existe, mais n'est pas membre du groupe principal associé et l'application du SSO SAML est activée.

```plaintext
The member's email address is not linked to a SAML account or has an inactive
SCIM identity.
```

Ce message d'erreur est renvoyé avec le statut `412`.

Cela peut empêcher l'utilisateur final concerné d'accéder correctement à son compte.

La première solution de contournement est :

1. Demandez à l'utilisateur final de [lier SAML à son compte GitLab.com existant](_index.md#link-saml-to-your-existing-gitlabcom-account).
1. Une fois que l'utilisateur a effectué cette opération, lancez une synchronisation SCIM depuis votre fournisseur d'identité. Si la synchronisation SCIM se termine sans la même erreur, GitLab a correctement lié l'identité SCIM au compte utilisateur existant, et l'utilisateur devrait maintenant pouvoir se connecter via SAML SSO.

Si l'erreur persiste, l'utilisateur existe très probablement déjà, possède à la fois une identité SAML et SCIM, et une identité SCIM définie sur `active: false`. Pour résoudre ce problème :

1. Facultatif. Si vous n'avez pas sauvegardé votre jeton SCIM lors de la première configuration de SCIM, [générez un nouveau jeton](scim_setup.md#configure-gitlab). Si vous générez un nouveau jeton SCIM, vous devez mettre à jour le jeton dans la configuration SCIM de votre fournisseur d'identité, sans quoi SCIM cessera de fonctionner.
1. Localisez votre jeton SCIM.
1. Utilisez l'API pour [obtenir un seul utilisateur provisionné via SCIM](../../../development/internal_api/_index.md#get-a-single-scim-provisioned-user).
1. Vérifiez les informations renvoyées pour vous assurer que :

   - L'identifiant (`id`) et l'adresse e-mail de l'utilisateur correspondent à ce que votre fournisseur d'identité envoie.
   - `active` est défini sur `false`.

   Si l'une de ces informations ne correspond pas, [contactez le support GitLab](https://support.gitlab.com/).
1. Utilisez l'API pour [mettre à jour la valeur `active` de l'utilisateur provisionné via SCIM à `true`](../../../development/internal_api/_index.md#update-a-single-scim-provisioned-user).
1. Si la mise à jour renvoie le code de statut `204`, demandez à l'utilisateur de tenter de se connecter via SAML SSO.

## Erreur : `User is pending deprovisioning` {#error-user-is-pending-deprovisioning}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228156) dans GitLab 18.11 [avec le feature flag](../../../administration/feature_flags/_index.md) `group_scim_async_member_removal`. Fonctionnalité désactivée par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/233454) dans GitLab 19.0. Le feature flag `group_scim_async_member_removal` a été supprimé.

{{< /history >}}

Les déprovisionnements SCIM sont traités de manière asynchrone. Lorsqu'un utilisateur SCIM est déprovisionné, les requêtes SCIM `POST` ou `PATCH` suivantes échouent avec le statut HTTP `409` et le message d'erreur suivant :

```plaintext
User is pending deprovisioning. Please wait for the user to be deprovisioned and try again later.
```

Pour résoudre cette erreur, attendez que le système termine le traitement des enregistrements d'appartenance de l'utilisateur. Une fois le processus terminé, vous pouvez essayer de reprovisionner l'utilisateur.

## Azure Active Directory {#azure-active-directory}

Les informations de dépannage suivantes concernent spécifiquement le provisionnement SCIM via Azure Active Directory.

### Vérifier que ma configuration SCIM est correcte {#verify-my-scim-configuration-is-correct}

Vérifiez que :

- La priorité de correspondance pour `externalId` est 1.
- La valeur SCIM pour `externalId` correspond à la valeur SAML pour `NameId`.

Vérifiez les paramètres SCIM suivants pour vous assurer que leurs valeurs sont pertinentes :

- `userName`
- `displayName`
- `emails[type eq "work"].value`

### Erreur `invalid credentials` lors du test de connexion {#invalid-credentials-error-when-testing-connection}

Lors du test de la connexion, vous pouvez rencontrer une erreur :

```plaintext
You appear to have entered invalid credentials. Please confirm
you are using the correct information for an administrative account
```

Si `Tenant URL` et `secret token` sont corrects, vérifiez si le chemin de votre groupe contient des caractères pouvant être considérés comme des primitives JSON non valides (tels que `.`). La suppression ou l'encodage URL de ces caractères dans le chemin du groupe résout généralement l'erreur.

### Erreur de synchronisation `(Field) can't be blank` {#field-cant-be-blank-sync-error}

Lors de la vérification des événements d'audit pour le provisionnement, vous pouvez voir une erreur `Namespace can't be blank, Name can't be blank, and User can't be blank.`.

Cette erreur peut se produire parce que tous les champs obligatoires (tels que le prénom et le nom de famille) ne sont pas présents pour tous les utilisateurs mappés.

Pour contourner ce problème, essayez un autre mappage :

1. Suivez les [instructions de mappage Azure](scim_setup.md#configure-attribute-mappings).
1. Supprimez l'entrée d'attribut cible `name.formatted`.
1. Modifiez l'attribut source `displayName` pour qu'il ait l'attribut cible `name.formatted`.

### Erreur `Failed to match an entry in the source and target systems Group 'Group-Name'` {#failed-to-match-an-entry-in-the-source-and-target-systems-group-group-name-error}

Le provisionnement de groupe dans Azure peut échouer avec l'erreur `Failed to match an entry in the source and target systems Group 'Group-Name'`. La réponse d'erreur peut inclure un résultat HTML de l'URL GitLab `https://gitlab.com/users/sign_in`.

Cette erreur est sans danger et se produit parce que le provisionnement de groupe a été activé, mais l'intégration SCIM de GitLab ne le prend pas en charge et ne le nécessite pas. Pour supprimer l'erreur, suivez les instructions du guide de configuration Azure pour désactiver l'option de [synchronisation des groupes Azure Active Directory avec AppName](scim_setup.md#configure-microsoft-entra-id).

## Okta {#okta}

Les informations de dépannage suivantes concernent spécifiquement le provisionnement SCIM via Okta.

### Message `Error authenticating: null` lors du test des identifiants API SCIM {#error-authenticating-null-message-when-testing-api-scim-credentials}

Lors du test des identifiants API dans votre application Okta SCIM, vous pouvez rencontrer une erreur :

```plaintext
Error authenticating: null
```

Okta doit pouvoir se connecter à votre instance GitLab pour provisionner ou déprovisionner des utilisateurs.

Dans votre application Okta SCIM, vérifiez que l'**URL de base** SCIM est correcte et pointe vers une URL d'endpoint API SCIM GitLab valide. Consultez la documentation suivante pour trouver des informations sur cette URL pour :

- [Groupes GitLab.com](scim_setup.md#configure-gitlab).
- [GitLab Self-Managed](../../../administration/settings/scim_setup.md#configure-gitlab).

Pour GitLab Self-Managed, assurez-vous que votre instance est accessible publiquement afin qu'Okta puisse s'y connecter. Si nécessaire, vous pouvez [autoriser l'accès aux adresses IP d'Okta](https://help.okta.com/en-us/Content/Topics/Security/ip-address-allow-listing.htm) sur votre pare-feu.
