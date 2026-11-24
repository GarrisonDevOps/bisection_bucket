---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Dépannage SAML
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Cette page contient des solutions possibles aux problèmes que vous pourriez rencontrer lors de l'utilisation de :

- [SSO SAML pour les groupes GitLab.com](_index.md).
- Le [fournisseur SAML OmniAuth](../../../integration/saml.md) au niveau de l'instance GitLab Self-Managed.
- [Switchboard](../../../administration/dedicated/configure_instance/authentication/saml.md#add-a-saml-provider-with-switchboard) pour configurer SAML pour les instances GitLab Dedicated.

## Outils de débogage SAML {#saml-debugging-tools}

Les réponses SAML sont encodées en base64. Pour les décoder à la volée, vous pouvez utiliser l'extension de navigateur **SAML-tracer** ([Firefox](https://addons.mozilla.org/en-US/firefox/addon/saml-tracer/), [Chrome](https://chromewebstore.google.com/detail/saml-tracer/mpdajninpobndbfcldcmbpnnbhibjmch?hl=en)).

Si vous ne pouvez pas installer de plugin de navigateur, vous pouvez [générer et capturer manuellement une réponse SAML](#manually-generate-a-saml-response) à la place.

Portez une attention particulière aux éléments suivants :

- Le `NameID`, qui identifie l'utilisateur qui se connecte. Si l'utilisateur s'est déjà connecté, cette valeur doit correspondre à la valeur que [GitLab a stockée](#verify-nameid).
- La présence d'un `X509Certificate`, qui est requis pour vérifier la signature de la réponse.
- Les `SubjectConfirmation` et `Conditions`, qui peuvent provoquer des erreurs en cas de mauvaise configuration.

### Générer une réponse SAML {#generate-a-saml-response}

Utilisez les réponses SAML pour prévisualiser les noms et les valeurs d'attributs envoyés dans la liste des assertions lors d'une tentative de connexion à l'aide d'un fournisseur d'identité.

Pour générer une réponse SAML :

1. Installez l'un des [outils de débogage de navigateur](#saml-debugging-tools).
1. Ouvrez un nouvel onglet de navigateur.
1. Ouvrez la console SAML tracer :
   - Chrome : dans un menu contextuel de la page, sélectionnez **Inspecter**, puis sélectionnez l'onglet **SAML** dans la console développeur.
   - Firefox : sélectionnez l'icône SAML-tracer située dans la barre d'outils du navigateur.
1. Pour les groupes GitLab.com :
   - Accédez à l'URL de l'authentification unique GitLab pour le groupe.
   - Sélectionnez **Autoriser** ou tentez de vous connecter.
1. Pour l'instance GitLab Self-Managed :
   - Accédez à la page d'accueil de l'instance.
   - Sélectionnez le bouton `SAML Login` pour vous connecter.
1. Une réponse SAML s'affiche dans la console tracer et ressemble à cet [exemple de réponse SAML](_index.md#example-saml-response).
1. Dans le SAML tracer, sélectionnez l'icône **Exporter** pour enregistrer la réponse au format JSON.

#### Générer manuellement une réponse SAML {#manually-generate-a-saml-response}

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une vue d'ensemble, consultez cette [vidéo sur la génération manuelle d'une réponse SAML sans utiliser de plugin de navigateur (avec Google Chrome)](https://youtu.be/umMPj6ohF_I), publiée par le Support GitLab.
<!-- Video published on 2024-09-09 -->

Quel que soit le navigateur utilisé, le processus est similaire à ce qui suit :

1. Faites un clic droit sur un nouveau navigateur et sélectionnez **Inspecter** pour ouvrir la fenêtre **DevTools**.
1. Sélectionnez l'onglet **Réseau**. Assurez-vous que **Conserver le journal** est sélectionné.
1. Basculez vers la page du navigateur et connectez-vous à GitLab en utilisant SAML SSO.
1. Revenez à la fenêtre **DevTools** et filtrez pour l'événement `callback`.
1. Sélectionnez l'onglet **Payload** pour l'événement callback et faites un clic droit pour copier la valeur.
1. Collez cette valeur dans la commande suivante : `echo "<value>" | base64 --decode > saml_response.xml`.
1. Ouvrez `saml_response.xml` dans un éditeur de code.

   Si vous avez installé un « embellisseur » XML dans votre éditeur de code, vous devriez pouvoir formater automatiquement la réponse pour la rendre plus lisible.

## Rechercher dans les journaux Rails pour une connexion SAML {#search-rails-logs-for-a-saml-sign-in}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Vous pouvez trouver des informations détaillées sur une connexion SAML dans le [fichier `audit_json.log`](../../../administration/logs/_index.md#audit_jsonlog).

Par exemple, en recherchant `system_access`, vous pouvez trouver des entrées qui indiquent quand un utilisateur s'est connecté à GitLab via SAML :

```json
{
  "severity": "INFO",
  "time": "2024-08-13T06:05:35.721Z",
  "correlation_id": "01J555EZK136DQ8S7P32G9GEND",
  "meta.caller_id": "OmniauthCallbacksController#saml",
  "meta.remote_ip": "45.87.213.198",
  "meta.feature_category": "system_access",
  "meta.user": "bbtest",
  "meta.user_id": 16,
  "meta.client_id": "user/16",
  "author_id": 16,
  "author_name": "bbtest@agounder.onmicrosoft.com",
  "entity_id": 16,
  "entity_type": "User",
  "created_at": "2024-08-13T06:05:35.708+00:00",
  "ip_address": "45.87.213.198",
  "with": "saml",
  "target_id": 16,
  "target_type": "User",
  "target_details": "bbtest@agounder.onmicrosoft.com",
  "entity_path": "bbtest"
}
```

Si vous avez configuré des liens de groupes SAML, le journal affiche également des entrées détaillant la suppression des membres :

```json
{
  "severity": "INFO",
  "time": "2024-08-13T05:24:07.769Z",
  "correlation_id": "01J55330SRTKTD5CHMS96DNZEN",
  "meta.caller_id": "Auth::SamlGroupSyncWorker",
  "meta.remote_ip": "45.87.213.206",
  "meta.feature_category": "system_access",
  "meta.client_id": "ip/45.87.213.206",
  "meta.root_caller_id": "OmniauthCallbacksController#saml",
  "id": 179,
  "author_id": 6,
  "entity_id": 2,
  "entity_type": "Group",
  "details": {
    "remove": "user_access",
    "member_id": 7,
    "author_name": "BB Test",
    "author_class": "User",
    "target_id": 6,
    "target_type": "User",
    "target_details": "BB Test",
    "custom_message": "Membership destroyed",
    "ip_address": "45.87.213.198",
    "entity_path": "group1"
  }
}
```

Vous pouvez également voir les détails de l'utilisateur que GitLab a reçus du fournisseur SAML dans `auth_json.log`, par exemple :

```json
{
  "severity": "INFO",
  "time": "2024-08-20T07:01:20.979Z",
  "correlation_id": "01J5Q9E59X4P40ZT3MCE35C2A9",
  "meta.caller_id": "OmniauthCallbacksController#saml",
  "meta.remote_ip": "xxx.xxx.xxx.xxx",
  "meta.feature_category": "system_access",
  "meta.client_id": "ip/xxx.xxx.xxx.xxx",
  "payload_type": "saml_response",
  "saml_response": {
    "issuer": [
      "https://sts.windows.net/03b8c6c5-104b-43e2-aed3-abb07df387cc/"
    ],
    "name_id": "ab260d59-0317-47f5-9afb-885c7a1257ab",
    "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    "name_id_spnamequalifier": null,
    "name_id_namequalifier": null,
    "destination": "https://dh-gitlab.agounder.com/users/auth/saml/callback",
    "audiences": [
      "https://dh-gitlab.agounder.com/16.11.6"
    ],
    "attributes": {
      "http://schemas.microsoft.com/identity/claims/tenantid": [
        "03b8c6c5-104b-43e2-aed3-abb07df387cc"
      ],
      "http://schemas.microsoft.com/identity/claims/objectidentifier": [
        "ab260d59-0317-47f5-9afb-885c7a1257ab"
      ],
      "http://schemas.microsoft.com/identity/claims/identityprovider": [
        "https://sts.windows.net/03b8c6c5-104b-43e2-aed3-abb07df387cc/"
      ],
      "http://schemas.microsoft.com/claims/authnmethodsreferences": [
        "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password"
      ],
      "email": [
        "bbtest@agounder.com"
      ],
      "firstname": [
        "BB"
      ],
      "name": [
        "bbtest@agounder.onmicrosoft.com"
      ],
      "lastname": [
        "Test"
      ]
    },
    "in_response_to": "_f8863f68-b5f1-43f0-9534-e73933e6ed39",
    "allowed_clock_drift": 2.220446049250313e-16,
    "success": true,
    "status_code": "urn:oasis:names:tc:SAML:2.0:status:Success",
    "status_message": null,
    "session_index": "_b4f253e2-aa61-46a4-902b-43592fe30800",
    "assertion_encrypted": false,
    "response_id": "_392cc747-7c8b-41de-8be0-23f5590d5ded",
    "assertion_id": "_b4f253e2-aa61-46a4-902b-43592fe30800"
  }
}
```

## Tester GitLab SAML {#testing-gitlab-saml}

Vous pouvez utiliser l'un des éléments suivants pour dépanner SAML :

- Un [environnement de test GitLab complet avec SAML utilisant Docker Compose](https://gitlab.com/gitlab-com/support/toolbox/replication/-/tree/main/compose_files).
- Un [guide de démarrage rapide pour lancer un conteneur Docker](../../../administration/troubleshooting/test_environments.md#saml) avec un fournisseur d'identité SAML 2.0 prêt à l'emploi si vous n'avez besoin que d'un fournisseur SAML.
- Un environnement local en [activant SAML pour les groupes sur une instance GitLab Self-Managed](../../../integration/saml.md#configure-group-saml-sso-on-gitlab-self-managed).

## Vérifier la configuration {#verify-configuration}

Pour plus de commodité, quelques [exemples de ressources](example_saml_config.md) utilisées par l'équipe de Support GitLab sont inclus. Bien qu'ils puissent vous aider à vérifier la configuration de l'application SAML, ils ne garantissent pas de refléter l'état actuel des produits tiers.

### Calculer l'empreinte {#calculate-the-fingerprint}

Lors de la configuration de `idp_cert_fingerprint`, vous devez utiliser une empreinte SHA256 dans la mesure du possible. SHA1 est également pris en charge, mais n'est pas recommandé. Pour calculer l'empreinte, exécutez la commande suivante sur le fichier de certificat :

```shell
openssl x509 -in <certificate.crt> -noout -fingerprint -sha256
```

Remplacez `<certificate.crt>` par le nom du fichier de certificat.

> [!note]
> Dans GitLab 17.11 et versions ultérieures, l'algorithme d'empreinte est [détecté automatiquement](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184530) en fonction de la longueur de l'empreinte.
>
> Dans GitLab 17.10 et versions antérieures, SHA1 est l'algorithme d'empreinte par défaut. Pour utiliser une empreinte SHA256, vous devez spécifier l'algorithme :
>
> ```ruby
> idp_cert_fingerprint_algorithm: "http://www.w3.org/2001/04/xmlenc#sha256"
> ```

## Mises à jour du certificat SSO {#sso-certificate-updates}

Lorsque le certificat utilisé pour votre fournisseur d'identité change (par exemple lors de la mise à jour ou du renouvellement du certificat), vous devez également mettre à jour l'empreinte du certificat. Vous pouvez trouver l'empreinte du certificat dans l'interface utilisateur de votre fournisseur d'identité. Si vous ne pouvez pas obtenir le certificat dans l'interface utilisateur du fournisseur d'identité, suivez les étapes de la documentation [calculer l'empreinte](#calculate-the-fingerprint).

## Erreurs de configuration {#configuration-errors}

### Audience non valide {#invalid-audience}

Cette erreur signifie que le fournisseur d'identité ne reconnaît pas GitLab comme un expéditeur et un destinataire valides des requêtes SAML. Assurez-vous de :

- Ajouter l'URL de callback GitLab aux audiences approuvées du serveur du fournisseur d'identité.
- Éviter les espaces de fin dans la chaîne `issuer`.

### Erreur de validation de clé, Divergence de condensat ou Divergence d'empreinte {#key-validation-error-digest-mismatch-or-fingerprint-mismatch}

Ces erreurs proviennent toutes du même endroit, le certificat SAML. Les requêtes SAML doivent être validées à l'aide d'une empreinte, d'un certificat ou d'un validateur.

Pour cette exigence, assurez-vous de prendre en compte les éléments suivants :

- Si vous utilisez une empreinte, confirmez votre empreinte SHA256 :
  1. Re-téléchargez le fichier de certificat.
  1. [Calculez l'empreinte](#calculate-the-fingerprint).
  1. Comparez l'empreinte à la valeur fournie dans `idp_cert_fingerprint`. Les valeurs doivent être identiques.
- Si aucun certificat n'est fourni dans les paramètres, une empreinte ou un validateur d'empreinte doit être fourni et la réponse du serveur doit contenir un certificat (`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>`).
- Si un certificat est fourni dans les paramètres, il n'est plus nécessaire que la requête en contienne un. Dans ce cas, l'empreinte ou les validateurs d'empreinte sont facultatifs.

Si aucun des scénarios décrits précédemment n'est valide, la requête échoue avec l'une des erreurs mentionnées.

### Réclamations manquantes ou erreurs `Email can't be blank` {#missing-claims-or-email-cant-be-blank-errors}

Le serveur du fournisseur d'identité doit transmettre certaines informations pour que GitLab puisse créer un compte ou faire correspondre les informations de connexion à un compte existant. `email` est la quantité minimale d'informations à transmettre. Si le serveur du fournisseur d'identité ne fournit pas ces informations, toutes les requêtes SAML échouent.

Assurez-vous que ces informations sont fournies.

Un autre problème pouvant entraîner cette erreur est lorsque les informations correctes sont envoyées par le fournisseur d'identité, mais que les attributs ne correspondent pas aux noms dans le hash OmniAuth `info`. Dans ce cas, vous devez définir `attribute_statements` dans la configuration SAML pour [mapper les noms d'attributs de votre réponse SAML aux noms correspondants du hash OmniAuth `info`](../../../integration/saml.md#map-saml-response-attribute-names).

### Les liens de groupes SAML existent mais aucune appartenance ne change {#saml-group-links-exist-but-no-memberships-change}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Vous pouvez configurer des liens de groupes SAML et confirmer que la réponse SAML transporte les groupes attendus, mais aucune appartenance n'est ajoutée ou supprimée. Les utilisateurs se connectent avec succès et ni la connexion ni les journaux ne signalent d'erreur.

Ce problème survient lorsque GitLab ne peut pas résoudre une valeur `groups_attribute` pour le fournisseur qui a authentifié l'utilisateur. Une cause fréquente est le placement de `groups_attribute` dans le hash `args` du fournisseur au lieu du niveau du fournisseur, en tant que frère de `name` et `label`. Lorsqu'aucune valeur n'est résolue, la synchronisation des groupes ne s'exécute pas et ne rapporte rien.

Pour résoudre ce problème :

1. Déplacez `groups_attribute` au niveau du fournisseur de la configuration. Pour un exemple, consultez [Configurer la synchronisation des groupes SAML](group_sync.md#configure-saml-group-sync).
1. Enregistrez le fichier et reconfigurez GitLab :

   ```shell
   sudo gitlab-ctl reconfigure
   ```

1. Reconnectez-vous.
1. Recherchez dans `audit_json.log` les entrées contenant `"meta.caller_id": "Auth::SamlGroupSyncWorker"`. La synchronisation des groupes écrit ces entrées lorsqu'elle modifie les appartenances. Si les entrées sont absentes après une connexion qui aurait dû modifier les appartenances, la synchronisation des groupes ne fonctionne pas.

## Messages d'erreur de la bannière de connexion utilisateur {#user-sign-in-banner-error-messages}

### Message : `SAML authentication failed: SAML NameID is missing from your SAML response.` {#message-saml-authentication-failed-saml-nameid-is-missing-from-your-saml-response}

Vous pourriez obtenir une erreur indiquant `SAML authentication failed: SAML NameID is missing from your SAML response. Please contact your administrator.`

Ce problème survient lorsque vous tentez de vous connecter à GitLab via le SSO de groupe, mais que votre réponse SAML n'incluait pas de `NameID`.

Pour résoudre ce problème :

- Contactez votre administrateur pour vous assurer que votre compte IdP possède un `NameID` attribué.
- Utilisez un [outil de débogage SAML](#saml-debugging-tools) pour vérifier que votre réponse SAML possède un `NameID` valide.

### Message : `SAML authentication failed: Extern uid has already been taken.` {#message-saml-authentication-failed-extern-uid-has-already-been-taken}

Vous pourriez obtenir une erreur indiquant `SAML authentication failed: Extern uid has already been taken. Please contact your administrator to generate a unique external_uid (NameID).`

Ce problème survient lorsque vous tentez de lier votre compte GitLab existant à une identité SAML via le SSO de groupe, mais qu'il existe déjà un compte GitLab avec votre `NameID` actuel.

Pour résoudre ce problème, demandez à votre administrateur de re-générer un `Extern UID` (`NameID`) unique pour votre compte IdP. Assurez-vous que ce nouveau `Extern UID` respecte les [contraintes GitLab `NameID`](_index.md#manage-user-saml-identity).

Si vous ne souhaitez pas utiliser cet utilisateur GitLab avec la connexion SAML, vous pouvez [dissocier le compte GitLab de l'application SAML](_index.md#unlink-accounts).

### Message : `SAML authentication failed: User has already been taken` {#message-saml-authentication-failed-user-has-already-been-taken}

L'utilisateur avec lequel vous êtes connecté a déjà SAML lié à une identité différente, ou la valeur `NameID` a changé. Voici les causes et solutions possibles :

| Cause                                                                                          | Solution |
|------------------------------------------------------------------------------------------------|----------|
| Vous avez tenté de lier plusieurs identités SAML au même utilisateur, pour un fournisseur d'identité donné. | Changez l'identité avec laquelle vous vous connectez. Pour ce faire, [dissociez l'identité SAML précédente](_index.md#unlink-accounts) de ce compte GitLab avant de tenter de vous connecter à nouveau. |
| Le `NameID` change à chaque fois que l'utilisateur demande une identification SSO                           | [Vérifiez que le `NameID`](#verify-nameid) n'est pas défini avec le format `Transient`, ou que le `NameID` ne change pas lors des requêtes suivantes. |

### Message : `SAML authentication failed: Email has already been taken` {#message-saml-authentication-failed-email-has-already-been-taken}

| Cause                                                                                                                | Solution |
|----------------------------------------------------------------------------------------------------------------------|----------|
| Si un compte utilisateur GitLab existe avec la même adresse e-mail, mais que le compte n'est pas associé à une identité SAML. | Sur GitLab.com, l'utilisateur doit [lier son compte](_index.md#user-access-and-management). Sur GitLab Self-Managed, les administrateurs peuvent configurer l'instance pour [lier automatiquement l'identité SAML au compte utilisateur GitLab](../../../integration/saml.md#link-saml-identity-for-an-existing-user) lors de leur première connexion. |

Les comptes utilisateurs sont créés de l'une des façons suivantes :

- Inscription de l'utilisateur
- Connexion via OAuth
- Connexion via SAML
- Provisionnement SCIM

### Erreur : l'utilisateur a déjà été pris {#error-user-has-already-been-taken}

Obtenir ces deux erreurs en même temps suggère que la capitalisation du `NameID` fourni par le fournisseur d'identité ne correspondait pas exactement à la valeur précédente pour cet utilisateur :

- `SAML authentication failed: Extern UID has already been taken`
- `User has already been taken`

Cela peut être évité en configurant le `NameID` pour qu'il retourne une valeur cohérente. La correction pour un utilisateur individuel implique de modifier l'identifiant de l'utilisateur. Pour GitLab.com, l'utilisateur doit [dissocier son SAML du compte GitLab](_index.md#unlink-accounts).

### Message : `Request to link SAML account must be authorized` {#message-request-to-link-saml-account-must-be-authorized}

Assurez-vous que l'utilisateur qui tente de lier son compte GitLab a été ajouté en tant qu'utilisateur dans l'application SAML du fournisseur d'identité.

Alternativement, la réponse SAML peut manquer l'attribut `InResponseTo` dans le tag `samlp:Response`, ce qui est [attendu par le gem SAML](https://github.com/onelogin/ruby-saml/blob/9f710c5028b069bfab4b9e2b66891e0549765af5/lib/onelogin/ruby-saml/response.rb#L307-L316). L'administrateur du fournisseur d'identité doit s'assurer que la connexion est initiée par le fournisseur de services et non uniquement par le fournisseur d'identité.

### Message : `There is already a GitLab account associated with this email address.` {#message-there-is-already-a-gitlab-account-associated-with-this-email-address}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Un utilisateur peut voir ce message lorsqu'il tente de [lier manuellement SAML à son compte GitLab.com existant](_index.md#link-saml-to-your-existing-gitlabcom-account) :

```plaintext
There is already a GitLab account associated with this email address.
Sign in with your existing credentials to connect your organization's account
```

Pour résoudre ce problème, l'utilisateur doit vérifier qu'il utilise le bon mot de passe GitLab pour se connecter. L'utilisateur doit d'abord [réinitialiser son mot de passe](https://gitlab.com/users/password/new) si les deux conditions suivantes sont réunies :

- Le compte a été provisionné par SCIM.
- Il se connecte avec un nom d'utilisateur et un mot de passe pour la première fois.

### Message : `SAML Name ID and email address do not match your user account` {#message-saml-name-id-and-email-address-do-not-match-your-user-account}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Les utilisateurs pourraient obtenir une erreur indiquant « SAML Name ID and email address do not match your user account. Contact an administrator. » Cela signifie :

- La valeur NameID envoyée par SAML ne correspond pas à la valeur `extern_uid` de l'identité SAML existante. Le NameID et le `extern_uid` sont tous deux sensibles à la casse. Pour plus d'informations, consultez [gérer l'identité SAML des utilisateurs](_index.md#manage-user-saml-identity).
- Soit la réponse SAML n'incluait pas d'adresse e-mail, soit l'adresse e-mail ne correspondait pas à l'adresse e-mail GitLab de l'utilisateur.

La solution de contournement consiste pour un propriétaire de groupe GitLab à utiliser l'[API SAML](../../../api/saml.md) pour mettre à jour le `extern_uid` SAML de l'utilisateur. La valeur `extern_uid` doit correspondre à la valeur Name ID envoyée par le fournisseur d'identité SAML (IdP). Selon la configuration de l'IdP, il peut s'agir d'un identifiant unique généré, d'une adresse e-mail ou d'une autre valeur.

### Erreur : `Certificate element missing in response (ds:x509certificate)` {#error-certificate-element-missing-in-response-dsx509certificate}

Cette erreur suggère que l'IdP n'est pas configuré pour inclure le certificat X.509 dans la réponse SAML :

```plaintext
Certificate element missing in response (ds:x509certificate) and not cert provided at settings
```

Le certificat X.509 doit être inclus dans la réponse. Pour résoudre ce problème, configurez votre IdP pour inclure le certificat X.509 dans la réponse SAML.

Pour plus d'informations, consultez la documentation sur la [configuration supplémentaire pour les applications SAML sur votre IdP](../../../integration/saml.md#additional-configuration-for-saml-apps-on-your-idp).

## Autres problèmes de connexion utilisateur {#other-user-sign-in-issues}

### Vérifier le `NameID` {#verify-nameid}

Lors du dépannage, tout utilisateur authentifié peut utiliser l'API pour vérifier le `NameID` que GitLab a déjà lié à son compte en visitant <https://gitlab.com/api/v4/user> et en vérifiant le `extern_uid` sous les identités.

Pour GitLab Self-Managed, les administrateurs peuvent utiliser l'[API des utilisateurs](../../../api/users.md) pour consulter les mêmes informations.

Lors de l'utilisation de SAML pour les groupes, les membres du groupe disposant d'un rôle avec les autorisations appropriées peuvent utiliser l'[API des membres](../../../api/group_members.md) pour consulter les informations d'identité SAML de groupe pour les membres du groupe.

Cela peut ensuite être comparé au `NameID` envoyé par le fournisseur d'identité en décodant le message avec un [outil de débogage SAML](#saml-debugging-tools). Ces valeurs doivent correspondre pour identifier les utilisateurs.

### Bloqué dans une « boucle » de connexion {#stuck-in-a-login-loop}

Assurez-vous que l'**URL de l'authentification unique GitLab** (pour GitLab.com) ou l'URL de l'instance (pour GitLab Self-Managed) a été configurée comme « Login URL » (ou un champ portant un nom similaire) dans l'application SAML du fournisseur d'identité.

Pour GitLab.com, en alternative, lorsque les utilisateurs doivent [lier SAML à leur compte GitLab.com existant](_index.md#link-saml-to-your-existing-gitlabcom-account), fournissez l'**URL de l'authentification unique GitLab** et indiquez aux utilisateurs de ne pas utiliser l'application SAML lors de la première connexion.

### Les utilisateurs reçoivent une erreur 404 {#users-receive-a-404}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Si l'utilisateur reçoit une erreur `404` après s'être connecté avec succès, vérifiez si vous avez des restrictions IP configurées. Les paramètres de restriction IP sont configurés :

- Sur GitLab.com, [au niveau du groupe](../access_and_permissions.md#restrict-group-access-by-ip-address).
- Pour GitLab Self-Managed, [au niveau de l'instance](../../../administration/reporting/ip_addr_restrictions.md).

Étant donné que le SSO SAML pour les groupes est une fonctionnalité payante, l'expiration de votre abonnement peut entraîner une erreur `404` lors de votre connexion via SAML SSO sur GitLab.com. Si tous les utilisateurs reçoivent une erreur `404` lors d'une tentative de connexion via SAML, confirmez [qu'il existe un abonnement actif](../../../subscriptions/manage_subscription.md#view-subscription) utilisé dans cet espace de nommage SAML SSO.

Si vous recevez une erreur `404` lors de la configuration en utilisant « verify configuration », assurez-vous d'avoir utilisé la [bonne empreinte générée SHA-1](../../../integration/saml.md#configure-saml-on-your-idp).

Si un utilisateur tente de se connecter pour la première fois et que l'URL de l'authentification unique GitLab n'a pas [été configurée](_index.md#set-up-your-identity-provider), il peut voir une erreur 404. Comme indiqué dans la [section d'accès utilisateur](_index.md#link-saml-to-your-existing-gitlabcom-account), un propriétaire de groupe doit fournir l'URL aux utilisateurs.

Si le groupe principal a [restreint l'appartenance par domaine d'e-mail](../access_and_permissions.md#restrict-group-access-by-domain) et qu'un utilisateur dont le domaine d'e-mail n'est pas autorisé tente de se connecter via SSO, cet utilisateur peut recevoir une erreur 404. Les utilisateurs peuvent avoir plusieurs comptes, et leur identité SAML peut être liée à leur compte personnel qui possède une adresse e-mail différente du domaine de l'entreprise. Pour vérifier cela, contrôlez les éléments suivants :

- Que le groupe principal a restreint l'appartenance par domaine d'e-mail.
- Que, dans les [événements d'audit](../../../administration/compliance/audit_event_reports.md) pour le groupe principal :
  - Vous pouvez voir l'action **Connexion avec l’authentification GROUP_SAML** pour cet utilisateur.
  - Que le nom d'utilisateur de l'utilisateur est identique au nom d'utilisateur que vous avez configuré pour SAML SSO, en sélectionnant le nom de l'**Auteur**.
    - Si le nom d'utilisateur est différent de celui que vous avez configuré pour SAML SSO, demandez à l'utilisateur de [dissocier l'identité SAML](_index.md#unlink-accounts) de son compte personnel.

Si tous les utilisateurs reçoivent une erreur `404` après s'être connectés au fournisseur d'identité (IdP) :

- Vérifiez le `assertion_consumer_service_url` :
  - Dans la configuration GitLab en [le faisant correspondre au point de terminaison HTTPS de GitLab](../../../integration/saml.md#configure-saml-support-in-gitlab).
  - En tant que `Assertion Consumer Service URL` ou équivalent lors de la configuration de l'application SAML sur votre IdP.
- Vérifiez si l'erreur `404` est liée au fait que [l'utilisateur a trop de groupes qui lui sont assignés dans son IdP Azure](group_sync.md#microsoft-azure-active-directory-integration).
- Vérifiez que les horloges du serveur IdP et de GitLab sont synchronisées sur la même heure.

Si un sous-ensemble d'utilisateurs reçoit une erreur `404` après s'être connectés à l'IdP, vérifiez d'abord quels événements d'audit sont retournés si l'utilisateur est ajouté au groupe puis immédiatement supprimé. Alternativement, si l'utilisateur peut se connecter avec succès, mais n'apparaît pas en tant que [membre du groupe principal](../_index.md#search-a-group) :

- Assurez-vous que l'utilisateur a été [ajouté au fournisseur d'identité SAML](_index.md#user-access-and-management), et à [SCIM](scim_setup.md) si configuré.
- Assurez-vous que l'attribut `active` de l'identité SCIM de l'utilisateur est `true` en utilisant l'[API SCIM](../../../api/scim.md). Si l'attribut `active` est `false`, vous pouvez effectuer l'une des actions suivantes pour éventuellement résoudre le problème :

  - Déclenchez une synchronisation pour l'utilisateur dans le fournisseur d'identité SCIM. Par exemple, Azure dispose d'une option « Provision on demand ».
  - Supprimez et rajoutez l'utilisateur dans le fournisseur d'identité SCIM.
  - Demandez à l'utilisateur de [dissocier son compte](_index.md#unlink-accounts) si possible, puis de [lier son compte](_index.md#link-saml-to-your-existing-gitlabcom-account).
  - Utilisez l'[API SCIM interne](../../../development/internal_api/_index.md#update-a-single-scim-provisioned-user) pour mettre à jour l'identité SCIM de l'utilisateur à l'aide du jeton SCIM de votre groupe. Si vous ne connaissez pas le jeton SCIM de votre groupe, réinitialisez le jeton et mettez à jour l'application du fournisseur d'identité SCIM avec le nouveau jeton. Exemple de requête :

    ```plaintext
    curl --request PATCH "https://gitlab.example.com/api/scim/v2/groups/test_group/Users/f0b1d561c-21ff-4092-beab-8154b17f82f2" --header "Authorization: Bearer <SCIM_TOKEN>" --header "Content-Type: application/scim+json" --data '{ "Operations": [{"op":"Replace","path":"active","value":"true"}] }'
    ```

### Erreur 500 après la connexion {#500-error-after-login}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si vous voyez une « erreur 500 » dans GitLab lorsque vous êtes redirigé depuis la page de connexion SAML, cela peut indiquer que :

- GitLab n'a pas pu obtenir l'adresse e-mail de l'utilisateur SAML. Assurez-vous que le fournisseur d'identité fournit une revendication contenant l'adresse e-mail de l'utilisateur en utilisant le nom de revendication `email` ou `mail`.
- Le certificat défini dans votre fichier `gitlab.rb` pour `identity provider_cert_fingerprint` ou le fichier `identity provider_cert` est incorrect.
- Votre fichier `gitlab.rb` est configuré pour activer `identity provider_cert_fingerprint`, et `identity provider_cert` est fourni, ou l'inverse.

### Erreur 422 après la connexion {#422-error-after-login}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si vous voyez une « erreur 422 » dans GitLab lorsque vous êtes redirigé depuis la page de connexion SAML, vous avez peut-être une URL du service consommateur d'assertions (ACS) mal configurée sur le fournisseur d'identité.

Assurez-vous que l'URL ACS pointe vers `https://gitlab.example.com/users/auth/saml/callback`, où `gitlab.example.com` est l'URL de votre instance GitLab.

Si l'URL ACS est correcte et que vous avez toujours des erreurs, consultez les autres sections de dépannage.

#### Erreur 422 avec un e-mail non autorisé {#422-error-with-non-allowed-email}

Vous pourriez obtenir une erreur 422 indiquant « Email is not allowed. Please use your regular email address. »

Ce message peut indiquer que vous devez ajouter ou supprimer un domaine de vos paramètres de liste d'autorisation ou de liste de refus de domaines.

Prérequis :

- Disposer d'un accès administrateur.

Pour mettre en œuvre cette solution de contournement :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Restrictions pour les nouveaux comptes utilisateurs**.
1. Ajoutez ou supprimez un domaine selon le cas dans **Domaines autorisés pour les nouveaux utilisateurs et utilisatrices** et **Domaines refusés pour les nouveaux utilisateurs et utilisatrices**.
1. Sélectionnez **Enregistrer les modifications**.

### L'utilisateur est bloqué lors de la connexion via SAML {#user-is-blocked-when-signing-in-through-saml}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les raisons les plus probables pour lesquelles un utilisateur est bloqué lors de la connexion via SAML sont les suivantes :

- Dans la configuration, `gitlab_rails['omniauth_block_auto_created_users'] = true` est défini et c'est la première fois que l'utilisateur se connecte.
- [`required_groups`](../../../integration/saml.md#required-groups) sont configurés mais l'utilisateur n'est pas membre de l'un d'eux.

## Conseils de dépannage pour Google Workspace {#google-workspace-troubleshooting-tips}

La documentation Google Workspace sur les [messages d'erreur des applications SAML](https://support.google.com/a/answer/6301076?hl=en) est utile pour le débogage si vous voyez une erreur de Google lors de la connexion. Portez une attention particulière aux erreurs 403 suivantes :

- `app_not_configured`
- `app_not_configured_for_user`

## Message : `The member's email address is not linked to a SAML account` {#message-the-members-email-address-is-not-linked-to-a-saml-account}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Cette erreur apparaît lorsque vous tentez d'inviter un utilisateur dans un groupe GitLab.com (ou un sous-groupe ou un projet au sein d'un groupe) qui a l'[application du SSO SAML](_index.md#sso-enforcement) activée.

Si vous voyez ce message après avoir tenté d'inviter un utilisateur dans un groupe :

1. Assurez-vous que l'utilisateur a été [ajouté au fournisseur d'identité SAML](_index.md#user-access-and-management).
1. Demandez à l'utilisateur de [lier SAML à son compte GitLab.com existant](_index.md#link-saml-to-your-existing-gitlabcom-account), s'il en a un. Sinon, demandez à l'utilisateur de créer un compte GitLab.com en [accédant à GitLab.com via le tableau de bord du fournisseur d'identité](_index.md#user-access-and-management), ou en [s'inscrivant manuellement](https://gitlab.com/users/sign_up) et en liant SAML à son nouveau compte.
1. Assurez-vous que l'utilisateur est [membre du groupe principal](../_index.md#search-a-group).

De plus, consultez [le dépannage des utilisateurs recevant une erreur 404 après la connexion](#users-receive-a-404).

## Message : `The SAML response did not contain an email address.` {#message-the-saml-response-did-not-contain-an-email-address}

Si vous voyez cette erreur :

```plaintext
The SAML response did not contain an email address.
Either the SAML identity provider is not configured to send the attribute, or the
identity provider directory does not have an email address value for your user
```

Cette erreur apparaît lorsque :

- la réponse SAML ne contient pas l'adresse e-mail de l'utilisateur dans un attribut **email** ou **mail**.
- un utilisateur tente de [lier SAML](_index.md#user-access-and-management) à son compte mais n'a pas encore terminé le [processus de vérification d'identité](../../../security/identity_verification.md).

Assurez-vous que le fournisseur d'identité SAML est configuré pour envoyer un [attribut de messagerie pris en charge](../../../integration/saml.md) :

```xml
<Attribute Name="email">
  <AttributeValue>user@example.com</AttributeValue>
</Attribute>
```

Les noms d'attributs commençant par des expressions telles que `http://schemas.xmlsoap.org/ws/2005/05/identity/claims` et `http://schemas.microsoft.com/ws/2008/06/identity/claims/` sont pris en charge par défaut.

```xml
<Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress">
  <AttributeValue>user@example.com</AttributeValue>
</Attribute>
```

## Impossible d'ajouter des comptes de service avec le verrou global des membres de groupes SAML {#cannot-add-service-accounts-with-global-saml-group-memberships-lock}

{{< details >}}

- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si le [verrou global des membres de groupes SAML](group_sync.md#global-saml-group-memberships-lock) est activé, seuls les administrateurs peuvent gérer les membres du groupe et les comptes de service via l'interface utilisateur. Si un propriétaire de groupe a besoin de gérer des comptes de service, il peut utiliser l'[API des membres du groupe](../../../api/group_members.md) à la place.

## Base de connaissances du support {#support-knowledge-base}

Si vous rencontrez encore des problèmes, consultez la [base de connaissances du support GitLab](https://support.gitlab.com/hc/en-us/).
