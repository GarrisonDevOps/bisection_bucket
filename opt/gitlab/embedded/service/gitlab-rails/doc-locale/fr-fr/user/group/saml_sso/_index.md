---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Authentification unique SAML pour les groupes GitLab.com
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

> [!note]
> Pour GitLab Self-Managed, voir [Authentification unique SAML pour GitLab Self-Managed](../../../integration/saml.md).

Les utilisateurs peuvent se connecter à GitLab via leur fournisseur d'identité SAML.

[SCIM](scim_setup.md) synchronise les utilisateurs avec le groupe sur GitLab.com.

- Lorsque vous ajoutez ou supprimez un utilisateur de l'application SCIM, SCIM ajoute ou supprime l'utilisateur du groupe GitLab.
- Si l'utilisateur n'est pas encore membre du groupe, il est ajouté au groupe dans le cadre du processus de connexion.

Vous pouvez configurer l'authentification unique SAML uniquement pour le groupe principal.

## Configurer votre fournisseur d'identité {#set-up-your-identity-provider}

La norme SAML vous permet d'utiliser un large éventail de fournisseurs d'identité avec GitLab. Votre fournisseur d'identité peut disposer d'une documentation pertinente. Il peut s'agir d'une documentation SAML générique ou spécifiquement destinée à GitLab.

Lors de la configuration de votre fournisseur d'identité, utilisez la documentation spécifique au fournisseur suivante pour éviter les problèmes courants et comme guide pour la terminologie utilisée.

Pour les fournisseurs d'identité non répertoriés, vous pouvez consulter les [notes SAML de l'instance sur la configuration d'un fournisseur d'identité](../../../integration/saml.md#configure-saml-on-your-idp) pour obtenir des conseils supplémentaires sur les informations que votre fournisseur peut exiger.

GitLab fournit les informations suivantes à titre indicatif uniquement. Si vous avez des questions sur la configuration de l'application SAML, contactez le support de votre fournisseur.

Si vous rencontrez des problèmes lors de la configuration de votre fournisseur d'identité, consultez la [documentation de dépannage](#troubleshooting).

### Azure {#azure}

Pour configurer l'authentification unique avec Azure comme fournisseur d'identité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Authentification unique SAML**.
1. Notez les informations présentes sur cette page.
1. Accédez à Azure, [créez une application hors galerie](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview-application-gallery#create-your-own-application) et [configurez l'authentification unique pour une application](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso). Les paramètres GitLab suivants correspondent aux champs Azure.

   | Paramètre GitLab                           | Champ Azure                                    |
   | -----------------------------------------| ---------------------------------------------- |
   | **Identifiant**                           | **Identifier (Entity ID)**                     |
   | **URL du service consommateur d'assertion**       | **Reply URL (Assertion Consumer Service URL)** |
   | **URL de l'authentification unique GitLab**            | **Sign on URL**                                |
   | **URL d'authentification unique du fournisseur d'identité** | **Login URL**                                  |
   | **Empreinte du certificat**              | **Thumbprint**                                 |

1. Vous devez définir les attributs suivants :
   - **Unique User Identifier (Name ID)** sur `user.objectID`.
     - **Name identifier format** sur `persistent`. Pour plus d'informations, consultez la section [gérer l'identité SAML des utilisateurs](#manage-user-saml-identity).
   - **Additional claims** sur [les attributs pris en charge](#configure-assertions).

1. Assurez-vous que le fournisseur d'identité est configuré pour effectuer des appels initiés par le fournisseur afin de lier les comptes GitLab existants.

1. Facultatif. Si vous utilisez [Group Sync](group_sync.md), personnalisez le nom de la revendication de groupe pour correspondre à l'attribut requis.

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez une démonstration du [provisionnement SCIM sur Azure avec l'authentification unique SAML pour les groupes](https://youtu.be/24-ZxmTeEBU). Le mappage `objectID` est obsolète dans cette vidéo. Suivez plutôt les instructions relatives à la [documentation sur la configuration de Microsoft Entra ID pour SCIM](scim_setup.md#configure-microsoft-entra-id).

Pour plus d'informations, consultez l'[exemple de configuration Azure](example_saml_config.md#azure-active-directory).

### Google Workspace {#google-workspace}

Pour configurer Google Workspace comme fournisseur d'identité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Authentification unique SAML**.
1. Notez les informations présentes sur cette page.
1. Suivez les instructions pour [configurer l'authentification unique avec Google comme fournisseur d'identité](https://support.google.com/a/answer/6087519?hl=en). Les paramètres GitLab suivants correspondent aux champs Google Workspace.

   | Paramètre GitLab                           | Champ Google Workspace |
   |:-----------------------------------------|:-----------------------|
   | **Identifiant**                           | **ID de l'entité**          |
   | **URL du service consommateur d'assertion**       | **ACS URL**            |
   | **URL de l'authentification unique GitLab**            | **Start URL**          |
   | **URL d'authentification unique du fournisseur d'identité** | **SSO URL**            |

1. Google Workspace affiche une empreinte SHA256 lorsque vous récupérez le certificat. Si vous devez générer l'empreinte SHA256 ultérieurement, consultez [calculer l'empreinte](troubleshooting.md#calculate-the-fingerprint).
1. Définissez ces valeurs :
   - Pour **Adresse de courriel principale** : `email`.
   - Pour **Prénom** : `first_name`.
   - Pour **Nom** : `last_name`.
   - Pour **Name ID format** : `EMAIL`.
   - Pour **NameID** : `Basic Information > Primary email`. Pour plus d'informations, consultez [les attributs pris en charge](#configure-assertions).

1. Assurez-vous que le fournisseur d'identité est configuré pour effectuer des appels initiés par le fournisseur afin de lier les comptes GitLab existants.

Sur la page Authentification unique SAML de GitLab, lorsque vous sélectionnez **Vérifier la configuration SAML**, ignorez l'avertissement recommandant de définir le format **NameID** sur `persistent`.

Pour plus d'informations, consultez l'[exemple de configuration Google Workspace](example_saml_config.md#google-workspace).

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez une démonstration de [la configuration de SAML avec Google Workspace et la mise en place de Group Sync](https://youtu.be/NKs0FSQVfCY).

### Okta {#okta}

Pour configurer l'authentification unique avec Okta comme fournisseur d'identité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Authentification unique SAML**.
1. Notez les informations présentes sur cette page.
1. Suivez les instructions pour [créer une application SAML dans Okta](https://developer.okta.com/docs/guides/create-an-app-integration/saml2/main/).

   Les paramètres GitLab suivants correspondent aux champs Okta.

   | Paramètre GitLab                           | Champ Okta                                                     |
   | ---------------------------------------- | -------------------------------------------------------------- |
   | **Identifiant**                           | **Audience URI**                                               |
   | **URL du service consommateur d'assertion**       | **Single sign-on URL**                                         |
   | **URL de l'authentification unique GitLab**            | **Login page URL** (sous les paramètres **Application Login Page**) |
   | **URL d'authentification unique du fournisseur d'identité** | **Identity Provider Single Sign-On URL**                       |

1. Sous le champ **Single sign-on URL** d'Okta, cochez la case **Use this for Recipient URL and Destination URL**.
1. Définissez ces valeurs :
   - Pour **Application username (NameID)** : **Personnalisé** `user.getInternalProperty("id")`.
   - Pour **Name ID Format** : `Persistent`. Pour plus d'informations, consultez [gérer l'identité SAML des utilisateurs](#manage-user-saml-identity).
   - Pour **email** : `user.email` ou similaire.
   - Pour les **Attribute Statements** supplémentaires, consultez [les attributs pris en charge](#configure-assertions).

1. Assurez-vous que le fournisseur d'identité est configuré pour effectuer des appels initiés par le fournisseur afin de lier les comptes GitLab existants.

L'application Okta GitLab disponible dans l'App Catalog prend uniquement en charge [SCIM](scim_setup.md). La prise en charge de SAML est proposée dans le [ticket 216173](https://gitlab.com/gitlab-org/gitlab/-/issues/216173).

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une démonstration de la configuration SAML d'Okta incluant SCIM, voir [Démo : configuration SAML & SCIM pour les groupes Okta](https://youtu.be/0ES9HsZq0AQ).

Pour plus d'informations, consultez l'[exemple de configuration Okta](example_saml_config.md#okta).

### OneLogin {#onelogin}

OneLogin prend en charge sa propre [application GitLab.com](https://onelogin.service-now.com/support?id=kb_article&sys_id=08e6b9d9879a6990c44486e5cebb3556&kb_category=50984e84db738300d5505eea4b961913).

Pour configurer OneLogin comme fournisseur d'identité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Authentification unique SAML**.
1. Notez les informations présentes sur cette page.
1. Si vous utilisez le [SAML Test Connector (Advanced)](https://onelogin.service-now.com/support?id=kb_article&sys_id=b2c19353dbde7b8024c780c74b9619fb&kb_category=93e869b0db185340d5505eea4b961934) générique de OneLogin, vous devez [utiliser le OneLogin SAML Test Connector](https://onelogin.service-now.com/support?id=kb_article&sys_id=93f95543db109700d5505eea4b96198f). Les paramètres GitLab suivants correspondent aux champs OneLogin :

   | Paramètre GitLab                                       | Champ OneLogin                   |
   | ---------------------------------------------------- | -------------------------------- |
   | **Identifiant**                                       | **Audience**                     |
   | **URL du service consommateur d'assertion**                   | **Recipient**                    |
   | **URL du service consommateur d'assertion**                   | **ACS (Consumer) URL**           |
   | **URL du service consommateur d'assertion (version encodée)** | **ACS (Consumer) URL Validator** |
   | **URL de l'authentification unique GitLab**                        | **Login URL**                    |
   | **URL d'authentification unique du fournisseur d'identité**             | **SAML 2.0 Endpoint**            |

1. Pour **NameID**, utilisez `OneLogin ID`. Pour plus d'informations, consultez [gérer l'identité SAML des utilisateurs](#manage-user-saml-identity).
1. Configurez les [attributs requis et pris en charge](#configure-assertions).
1. Assurez-vous que le fournisseur d'identité est configuré pour effectuer des appels initiés par le fournisseur afin de lier les comptes GitLab existants.

Pour plus d'informations, consultez l'[exemple de configuration OneLogin](example_saml_config.md#onelogin).

### Keycloak {#keycloak}

Pour configurer Keycloak comme fournisseur d'identité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Authentification unique SAML**.
1. Notez les informations présentes sur cette page.
1. Suivez les instructions pour [créer un client SAML dans Keycloak](https://www.keycloak.org/docs/latest/server_admin/index.html#_client-saml-configuration).

Les paramètres GitLab suivants correspondent aux champs Keycloak.

   | Paramètre GitLab                           | Champ Keycloak                          |
   |:-----------------------------------------|:------------------------------------------------|
   | **Identifiant**                           | **ID du client**                                   |
   | **URL du service consommateur d'assertion**       | **Valid redirect URIs**                         |
   | **URL du service consommateur d'assertion**       | **Assertion Consumer Service POST Binding URL** |
   | **URL de l'authentification unique GitLab**            | **Home URL**                                    |

1. Configurez votre client GitLab dans Keycloak.
   1. Dans Keycloak, accédez à **Clients** et sélectionnez la configuration de votre client GitLab.
   1. Dans l'onglet **Paramètres**, dans la section **SAML capabilities** :
      1. Définissez le **Name ID format** sur `persistent`.
      1. Activez **Force name ID format**.
      1. Activez **Force POST binding**.
      1. Activez **Include AuthnStatement**.
   1. Dans la section **Signature and Encryption**, activez **Sign documents**.
   1. Dans l'onglet **Clés**, assurez-vous que toutes les sections sont désactivées.
   1. Dans l'onglet **Client scopes** :
      1. Sélectionnez la portée du client pour GitLab. Le nom de la portée doit ressembler à `https://gitlab.com/groups/your-group-name-dedicated`.
      1. Sélectionnez **Configure a new mapper**, puis sélectionnez **User Attribute** dans la fenêtre qui s'ouvre.
      1. Sur la page **Add mapper**, définissez les champs **Nom**, **User Attribute** et **SAML Attribute Name** sur `email`.
      1. Sélectionnez **Enregistrer**.
1. Récupérez les informations du client depuis Keycloak.
   1. Dans la liste déroulante **Action**, sélectionnez **Download adapter config**.
   1. Dans la boîte de dialogue **Download adapter config**, sélectionnez **mod-auth-mellon** dans la liste déroulante.
   1. Sélectionnez **Téléchargement**.
   1. Extrayez l'archive téléchargée et ouvrez `idp-metadata.xml`.
   1. Récupérez l'URL d'authentification unique du fournisseur d'identité.
      1. Localisez la balise `<md:SingleSignOnService>`.
      1. Notez la valeur de l'attribut `Location`.
   1. Récupérez l'empreinte du certificat.
      1. Notez la valeur de la balise `<ds:X509Certificate>`.
      1. Copiez la valeur dans un fichier séparé et convertissez-la au [format PEM](https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/#ftoc-heading-3). Pour ce faire, ajoutez `-----BEGIN CERTIFICATE-----` au début du fichier et `-----END CERTIFICATE-----` à la fin du fichier sous forme de nouvelles lignes.
      1. [Calculez l'empreinte](troubleshooting.md#calculate-the-fingerprint).

### AWS IAM Identity Center {#aws-iam-identity-center}

> [!note]
> AWS IAM Identity Center (anciennement AWS Single Sign-On) n'est pas un fournisseur d'identité testé par GitLab. GitLab fournit les informations suivantes sur la base des configurations signalées par les clients. Si vous avez des questions sur la configuration de l'intégration SAML dans AWS IAM Identity Center, contactez le [Support AWS](https://aws.amazon.com/contact-us/).

AWS IAM Identity Center utilise par défaut la connexion initiée par le fournisseur d'identité (IdP). Pour lier votre compte GitLab existant, vous devez configurer la connexion initiée par le fournisseur de services (SP). Pour plus d'informations, consultez [Connexion initiée par le SP](#sp-initiated-login).

Pour configurer l'authentification unique avec AWS IAM Identity Center comme fournisseur d'identité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre groupe.
1. Sélectionnez **Paramètres** > **Authentification unique SAML**, et notez les valeurs sur cette page.
1. Dans la console AWS IAM Identity Center, [configurez une application SAML 2.0 personnalisée](https://docs.aws.amazon.com/singlesignon/latest/userguide/customermanagedapps-set-up-your-own-app-saml2.html). Lorsque vous êtes invité à saisir des valeurs de métadonnées, entrez les informations suivantes :

   | Paramètre GitLab                           | Champ AWS IAM Identity Center      |
   | ---------------------------------------- | ---------------------------------- |
   | **URL du service consommateur d'assertion**       | **Application ACS URL**            |
   | **Identifiant**                           | **Application SAML audience**      |

1. Pour activer la connexion initiée par le SP, définissez l'**Application start URL** sur votre **URL de l'authentification unique GitLab** (sur la page des paramètres **Authentification unique SAML** de GitLab).

1. Sous **Attribute mappings**, configurez les éléments suivants :

   | Attribut      | Valeur                | Format        |
   | -------------- | -------------------- | ------------- |
   | **Objet**    | `${user:email}`      | `unspecified` |
   | **email**      | `${user:email}`      | `unspecified` |
   | **first_name** | `${user:givenName}`  | `unspecified` |
   | **last_name**  | `${user:familyName}` | `unspecified` |

   > [!warning]
   > Vous devez définir le format **Objet** (NameID) sur `unspecified`. Définir le format sur `persistent` ou `transient` provoque des erreurs d'authentification pour les utilisateurs GitLab existants qui tentent de lier leurs comptes.

1. Sous **IAM Identity Center SAML metadata**, copiez l'**IAM Identity Center sign-in URL** et téléchargez le certificat.

1. Sur votre terminal, générez une empreinte SHA1 à partir du certificat téléchargé :

   ```shell
   openssl x509 -noout -fingerprint -sha1 -inform pem -in <path-to-downloaded-cert.pem>
   ```

1. Dans GitLab, sur la page des paramètres **Authentification unique SAML** du groupe, renseignez les champs suivants :
   - **URL d'authentification unique du fournisseur d'identité** : saisissez l'**IAM Identity Center sign-in URL**.
   - **Empreinte du certificat** : saisissez la valeur de l'empreinte SHA1.

1. Dans AWS IAM Identity Center, affectez des utilisateurs à l'application GitLab. Pour lier des comptes GitLab existants, les utilisateurs doivent se connecter depuis l'**URL de l'authentification unique GitLab** ou l'**Application start URL**.

Pour plus d'informations, consultez l'[exemple de configuration d'AWS IAM Identity Center](example_saml_config.md#aws-iam-identity-center).

#### Connexion initiée par le SP {#sp-initiated-login}

Lorsqu'un utilisateur se connecte via le tableau de bord de son fournisseur d'identité (connexion initiée par le fournisseur d'identité), la réponse SAML n'inclut pas d'attribut `InResponseTo`. GitLab requiert cet attribut pour lier une identité SAML à un compte existant.

AWS IAM Identity Center utilise par défaut la connexion initiée par le fournisseur d'identité (IdP). Si l'**Application start URL** n'est pas configurée, les utilisateurs existants voient l'erreur `Request to link SAML account must be authorized` lorsqu'ils tentent de se connecter.

Pour éviter cela, définissez l'**Application start URL** sur votre **URL de l'authentification unique GitLab**. Cela garantit que les utilisateurs démarrent le flux de connexion depuis GitLab, de sorte que l'attribut `InResponseTo` est présent dans la réponse SAML.

### Configurer les assertions {#configure-assertions}

> [!note]
> Ces attributs sont insensibles à la casse.

Vous devez au minimum configurer les assertions suivantes :

1. [NameID](#manage-user-saml-identity).
1. E-mail.

Vous pouvez également transmettre des informations sur les utilisateurs à GitLab en tant qu'attributs dans l'assertion SAML.

- L'adresse e-mail de l'utilisateur peut être un attribut **email** ou **mail**.
- Le nom d'utilisateur peut être un attribut **nom_d_utilisateur** ou **nickname**. Vous ne devez en spécifier qu'un seul.

Pour plus d'informations sur les attributs disponibles, consultez [Authentification unique SAML pour GitLab Self-Managed](../../../integration/saml.md#configure-assertions).

### Utiliser les métadonnées {#use-metadata}

Pour configurer certains fournisseurs d'identité, vous avez besoin d'une URL des métadonnées de GitLab. Pour trouver cette URL :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Authentification unique SAML**.
1. Copiez l'**URL des métadonnées de GitLab** fournie.
1. Suivez la documentation de votre fournisseur d'identité et collez l'URL des métadonnées lorsqu'elle est demandée.

Consultez la documentation de votre fournisseur d'identité pour vérifier s'il prend en charge l'URL des métadonnées de GitLab.

### Gérer le fournisseur d'identité {#manage-the-identity-provider}

Une fois votre fournisseur d'identité configuré, vous pouvez :

- Changer de fournisseur d'identité.
- Changer de domaines de messagerie.

#### Changer de fournisseur d'identité {#change-the-identity-provider}

Vous pouvez passer à un autre fournisseur d'identité. Pendant le processus de changement, les utilisateurs ne peuvent accéder à aucun des groupes SAML. Pour atténuer ce problème, vous pouvez désactiver l'[application du SSO](#sso-enforcement).

Pour changer de fournisseur d'identité :

1. [Configurez](#set-up-your-identity-provider) le groupe avec le nouveau fournisseur d'identité.
1. Facultatif. Si le **NameID** n'est pas identique, [modifiez le **NameID** des utilisateurs](#manage-user-saml-identity).

#### Changer de domaines de messagerie {#change-email-domains}

Pour migrer les utilisateurs vers un nouveau domaine de messagerie, demandez-leur de :

1. [Ajouter leur nouvelle adresse e-mail](../../profile/_index.md#change-your-primary-email) comme adresse de courriel principale à leur compte et de la vérifier.
1. Facultatif. Supprimer leur ancienne adresse e-mail du compte.

Si le **NameID** est configuré avec l'adresse e-mail, [modifiez le **NameID** des utilisateurs](#manage-user-saml-identity).

## Configurer GitLab {#configure-gitlab}

Après avoir configuré votre fournisseur d'identité pour fonctionner avec GitLab, vous devez configurer GitLab pour l'utiliser pour l'authentification :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Authentification unique SAML**.
1. Remplissez les champs :
   - Dans le champ **URL d'authentification unique du fournisseur d'identité**, saisissez l'URL SSO de votre fournisseur d'identité.
   - Dans le champ **Empreinte du certificat**, saisissez l'empreinte du certificat de signature du jeton SAML.
1. Pour les groupes sur GitLab.com : dans le champ **Rôle d'adhésion par défaut**, sélectionnez :
   1. Le rôle à attribuer aux nouveaux utilisateurs.
   1. Le rôle à attribuer aux [utilisateurs qui ne sont pas membres d'un groupe SAML mappé](group_sync.md#automatic-member-removal) lorsque SAML Group Links est configuré pour le groupe.
1. Pour les groupes sur les instances GitLab Self-Managed : dans le champ **Rôle d'adhésion par défaut**, sélectionnez le rôle à attribuer aux nouveaux utilisateurs. Le rôle par défaut est **Invité**. Ce rôle devient le rôle de départ de tous les utilisateurs ajoutés au groupe. Les propriétaires de groupe peuvent définir un [rôle personnalisé](../../custom_roles/_index.md) comme rôle d'adhésion par défaut.
1. Cochez la case **Activer l'authentification SAML pour ce groupe**.
1. Recommandé. Sélectionnez :
   - Dans GitLab 17.4 et versions ultérieures, **Désactiver l'authentification par mot de passe et clé d'accès pour les utilisateurs et utilisatrices Enterprise**. Pour plus d'informations, consultez la [documentation sur la désactivation de l'authentification par mot de passe et clé d'accès pour les utilisateurs et utilisatrices Enterprise](#disable-password-and-passkey-authentication-for-enterprise-users).
   - **Mettre en œuvre l'authentification unique SSO pour l'activité Web de ce groupe**.
   - **Mettre en œuvre l'authentification unique SSO pour les activités de Git et du Proxy de Dépendance pour ce groupe**. Pour plus d'informations, consultez la [documentation sur l'application du SSO](#sso-enforcement).
1. Sélectionnez **Enregistrer les modifications**.

Si vous rencontrez des problèmes lors de la configuration de GitLab, consultez la [documentation de dépannage](#troubleshooting).

## Accès et gestion des utilisateurs {#user-access-and-management}

Une fois l'authentification unique de groupe configurée et activée, les utilisateurs peuvent accéder au groupe GitLab.com via le tableau de bord du fournisseur d'identité. Si [SCIM](scim_setup.md) est configuré, consultez [l'accès utilisateur](scim_setup.md#user-access) sur la page SCIM.

Lorsqu'un utilisateur tente de se connecter avec l'authentification unique de groupe, GitLab tente de trouver ou de créer un utilisateur selon les critères suivants :

- Trouver un utilisateur existant avec une identité SAML correspondante. Cela signifie que l'utilisateur a soit eu son compte créé par [SCIM](scim_setup.md), soit qu'il s'est connecté précédemment avec le fournisseur d'identité SAML du groupe.
- Si aucun compte n'existe déjà avec la même adresse e-mail, créer automatiquement un nouveau compte. GitLab tente de faire correspondre les adresses e-mail principale et secondaire.
- Si un compte existe déjà avec la même adresse e-mail, rediriger l'utilisateur vers la page de connexion pour :
  - Créer un nouveau compte avec une autre adresse e-mail.
  - Se connecter à son compte existant pour lier l'identité SAML.

### Comportement de provisionnement avec accès restreint {#provisioning-behavior-with-restricted-access}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/206932) dans GitLab 18.6 [avec le feature flag](../../../administration/feature_flags/_index.md) `bso_minimal_access_fallback`. Fonctionnalité désactivée par défaut.
- [Activé par défaut](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225777) dans GitLab 18.10.

{{< /history >}}

Lorsque l'[accès restreint](../../../subscriptions/manage_seats.md#restricted-access) est activé sans sièges disponibles, les utilisateurs provisionnés via SAML se voient attribuer le rôle Accès minimum.

Pour plus d'informations, consultez [Comportement de provisionnement avec SAML, SCIM et LDAP](../../../subscriptions/manage_seats.md#provisioning-behavior-with-saml-scim-and-ldap).

### Lier SAML à votre compte GitLab.com existant {#link-saml-to-your-existing-gitlabcom-account}

> [!note]
> Si l'utilisateur est un [utilisateur Enterprise](../../enterprise_user/_index.md) de ce groupe, les étapes suivantes ne s'appliquent pas. L'utilisateur Enterprise doit plutôt [se connecter avec un compte SAML ayant la même adresse e-mail que le compte GitLab](#automatic-identity-linking-for-enterprise-users). Cela permet à GitLab de lier le compte SAML au compte existant.

Pour lier SAML à votre compte GitLab.com existant :

1. Connectez-vous à votre compte GitLab.com. [Réinitialisez votre mot de passe](https://gitlab.com/users/password/new) si nécessaire.
1. Localisez et visitez l'**URL de l'authentification unique GitLab** pour le groupe auquel vous vous connectez. Un propriétaire de groupe peut le trouver sur la page **Paramètres** > **Authentification unique SAML** du groupe. Si l'URL de connexion est configurée, les utilisateurs peuvent se connecter à l'application GitLab depuis le fournisseur d'identité.
1. Facultatif. Cochez la case **Se souvenir de moi** pour rester connecté à GitLab pendant 2 semaines. Il est possible que vous soyez invité à vous authentifier à nouveau auprès de votre fournisseur SAML plus fréquemment.
1. Sélectionnez **Autoriser**.
1. Saisissez vos identifiants auprès du fournisseur d'identité si vous y êtes invité.
1. Vous êtes alors redirigé vers GitLab.com et devriez maintenant avoir accès au groupe. À l'avenir, vous pourrez utiliser SAML pour vous connecter à GitLab.com.

Si un utilisateur est déjà membre du groupe, la liaison de l'identité SAML ne modifie pas son rôle.

Lors des visites ultérieures, vous devriez pouvoir [vous connecter à GitLab.com avec SAML](#sign-in-to-gitlabcom-with-saml) ou en visitant directement des liens. Si l'option **Appliquer l'authentification unique** est activée, vous êtes alors redirigé pour vous connecter via le fournisseur d'identité.

#### Liaison automatique des identités pour les utilisateurs Enterprise {#automatic-identity-linking-for-enterprise-users}

Si un utilisateur Enterprise est supprimé du groupe puis y revient, il peut se connecter avec son compte SSO Enterprise. Tant que l'adresse e-mail de l'utilisateur dans le fournisseur d'identité reste identique à l'adresse e-mail du compte GitLab existant, l'identité SSO est automatiquement liée au compte et l'utilisateur peut se connecter sans problème. Cette fonctionnalité s'applique également aux utilisateurs existants qui ont été revendiqués en tant qu'utilisateur Enterprise mais qui ne se sont peut-être pas encore connectés au groupe.

### Se connecter à GitLab.com avec SAML {#sign-in-to-gitlabcom-with-saml}

1. Connectez-vous à votre fournisseur d'identité.
1. Dans la liste des applications, sélectionnez l'application « GitLab.com ». (Le nom est défini par l'administrateur du fournisseur d'identité.)
1. Vous êtes alors connecté à GitLab.com et redirigé vers le groupe.

### Gérer l'identité SAML des utilisateurs {#manage-user-saml-identity}

GitLab.com utilise le **NameID** SAML pour identifier les utilisateurs. Le **NameID** est :

- Un champ obligatoire dans la réponse SAML.
- Insensible à la casse.

Le **NameID** doit :

- Être unique pour chaque utilisateur.
- Être une valeur persistante qui ne change jamais, telle qu'un identifiant utilisateur unique généré de manière aléatoire.
- Correspondre exactement lors des tentatives de connexion ultérieures. Il ne doit donc pas dépendre d'une saisie utilisateur susceptible de varier entre majuscules et minuscules.

Le **NameID** ne doit pas être une adresse e-mail ou un nom d'utilisateur car :

- Les adresses e-mail et les noms d'utilisateur sont plus susceptibles de changer avec le temps. Par exemple, lorsque le nom d'une personne change.
- Les adresses e-mail sont insensibles à la casse, ce qui peut empêcher les utilisateurs de se connecter.

Le format du **NameID** doit être `Persistent`, sauf si vous utilisez un champ, comme l'e-mail, qui nécessite un format différent. Vous pouvez utiliser n'importe quel format sauf `Transient`.

#### Modifier le **NameID** d'un utilisateur {#change-user-nameid}

Les propriétaires de groupe peuvent utiliser l'[API SAML](../../../api/saml.md#update-extern_uid-field-for-a-saml-identity) pour modifier le **NameID** des membres de leur groupe et mettre à jour leurs identités SAML.

> [!warning]
> La mise à jour de `extern_uid` via l'API marque l'identité SAML comme non fiable. L'utilisateur concerné ne peut pas se connecter avec SAML tant qu'il n'a pas [relié son compte à la nouvelle application SAML](#link-saml-to-your-existing-gitlabcom-account).

Si [SCIM](scim_setup.md) est configuré, les propriétaires de groupe peuvent mettre à jour les identités SCIM à l'aide de l'[API SCIM](../../../api/scim.md#update-extern_uid-field-for-a-scim-identity).

Vous pouvez également demander aux utilisateurs de reconnecter leur compte SAML.

1. Demandez aux utilisateurs concernés de [dissocier leur compte du groupe](#unlink-accounts).
1. Demandez aux utilisateurs concernés de [lier leur compte à la nouvelle application SAML](#link-saml-to-your-existing-gitlabcom-account).

> [!warning]
> Une fois que les utilisateurs se sont connectés à GitLab via SSO SAML, la modification de la valeur du **NameID** rompt la configuration et peut verrouiller les utilisateurs hors du groupe GitLab.

Pour plus d'informations sur la valeur et le format recommandés pour des fournisseurs d'identité spécifiques, consultez [configurer votre fournisseur d'identité](#set-up-your-identity-provider).

### Configurer les paramètres des utilisateurs Enterprise à partir de la réponse SAML {#configure-enterprise-user-settings-from-saml-response}

GitLab permet de définir certains attributs utilisateur sur la base des valeurs de la réponse SAML. Les attributs d'un utilisateur existant sont mis à jour à partir des valeurs de la réponse SAML si cet utilisateur est un [utilisateur Enterprise](../../enterprise_user/_index.md) du groupe.

#### Attributs utilisateur pris en charge {#supported-user-attributes}

- `can_create_group` - `true` ou `false` pour indiquer si un utilisateur Enterprise peut créer de nouveaux groupes principaux. La valeur par défaut est `true`.
- `projects_limit` - Le nombre total de projets personnels qu'un utilisateur Enterprise peut créer. Une valeur de `0` signifie que l'utilisateur ne peut pas créer de nouveaux projets dans son espace de nommage personnel. La valeur par défaut est `100000`.
- `SessionNotOnOrAfter` - Une valeur d'horodatage ISO 8601 indiquant quand mettre fin à la session SAML de l'utilisateur.

#### Exemple de réponse SAML {#example-saml-response}

Vous pouvez trouver les réponses SAML dans les outils de développement ou la console de votre navigateur, au format encodé en base64. Utilisez l'outil de décodage base64 de votre choix pour convertir les informations en XML. Un exemple de réponse SAML est présenté ici.

```xml
   <saml2:AttributeStatement>
      <saml2:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
         <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user.email</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="username" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user.nickName</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="first_name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
         <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user.firstName</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="last_name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
         <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user.lastName</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="can_create_group" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
         <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">true</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="projects_limit" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
         <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">10</saml2:AttributeValue>
      </saml2:Attribute>
   </saml2:AttributeStatement>
```

### Personnaliser le délai d'expiration des sessions SAML {#customize-saml-session-timeout}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/262074) dans GitLab 18.2 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `saml_timeout_supplied_by_idp_override`.

{{< /history >}}

Par défaut, GitLab met fin aux sessions SAML après 24 heures. Vous pouvez personnaliser cette durée avec l'attribut `SessionNotOnOrAfter` dans l'AuthnStatement SAML2. Cet attribut contient une valeur d'horodatage ISO 8601 indiquant quand mettre fin à la session utilisateur. Lorsqu'elle est spécifiée, cette valeur remplace le délai d'expiration de session SAML par défaut de 24 heures.

Par défaut, GitLab met fin aux sessions après sept jours (10 080 minutes) d'inactivité. Si l'horodatage `SessionNotOnOrAfter` est postérieur à cette durée, les utilisateurs doivent se réauthentifier à l'expiration de leur session.

#### Exemple de réponse {#example-response}

```xml
   <saml:AuthnStatement SessionIndex="WDE5aBYjNEj_9IjCFiK0E1YelZT" SessionNotOnOrAfter="2025-08-25T01:23:45.067Z" AuthnInstant="2025-08-24T13:23:45.067Z">
      <saml:AuthnContext>
         <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>
      </saml:AuthnContext>
   </saml:AuthnStatement>
```

### Contourner la confirmation par e-mail des utilisateurs avec des domaines vérifiés {#bypass-user-email-confirmation-with-verified-domains}

Par défaut, les utilisateurs provisionnés avec SAML ou SCIM reçoivent un e-mail de vérification pour confirmer leur identité. À la place, vous pouvez [configurer GitLab avec un domaine personnalisé](../../enterprise_user/_index.md#add-group-domains) et GitLab confirmera automatiquement les comptes utilisateurs. Les utilisateurs reçoivent tout de même un e-mail de bienvenue pour les [utilisateurs Enterprise](../../enterprise_user/_index.md). La confirmation est contournée si les deux conditions suivantes sont vraies :

- L'utilisateur est provisionné avec SAML ou SCIM.
- L'utilisateur possède une adresse e-mail appartenant au domaine vérifié.

> [!note]
> Les utilisateurs provisionnés avec une adresse e-mail en dehors du domaine vérifié restent non confirmés. Si la [suppression automatique des utilisateurs non confirmés](../../../administration/moderate_users.md#automatically-delete-unconfirmed-users) est activée, GitLab peut supprimer ces utilisateurs.

### Désactiver l'authentification par mot de passe et clé d'accès pour les utilisateurs et utilisatrices Enterprise {#disable-password-and-passkey-authentication-for-enterprise-users}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/373718) dans GitLab 17.4.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Propriétaire pour le groupe auquel appartient l'utilisateur Enterprise.
- L'authentification unique de groupe doit être activée.

Vous pouvez désactiver l'authentification par mot de passe pour tous les [utilisateurs Enterprise](../../enterprise_user/_index.md) du groupe. Cela s'applique également aux utilisateurs Enterprise qui sont administrateurs du groupe. La configuration de ce paramètre empêche les utilisateurs Enterprise de modifier, réinitialiser ou s'authentifier avec leur mot de passe. À la place, ces utilisateurs peuvent s'authentifier avec :

- Le fournisseur d'identité SAML du groupe pour l'interface Web de GitLab.
- Un jeton d'accès personnel pour l'API GitLab et Git avec l'authentification HTTP Basic, sauf si le groupe a [désactivé les jetons d'accès personnels pour les utilisateurs Enterprise](../../profile/personal_access_tokens.md#disable-personal-access-tokens-for-enterprise-users).

Pour désactiver l'authentification par mot de passe et clé d'accès pour les utilisateurs Enterprise :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Authentification unique SAML**.
1. Sous **Configuration**, sélectionnez **Désactiver l'authentification par mot de passe et clé d'accès pour les utilisateurs et utilisatrices Enterprise**.
1. Sélectionnez **Enregistrer les modifications**.

### Bloquer l'accès des utilisateurs {#block-user-access}

Pour révoquer l'accès d'un utilisateur au groupe lorsque seule l'authentification unique SAML est configurée, soit :

- Supprimez (dans l'ordre) l'utilisateur de :
  1. Le magasin de données utilisateur sur le fournisseur d'identité ou la liste des utilisateurs de l'application spécifique.
  1. Le groupe GitLab.com.
- Utilisez [Group Sync](group_sync.md#automatic-member-removal) au niveau principal de votre groupe avec le rôle par défaut défini sur [accès minimum](../../permissions.md#users-with-minimal-access) pour bloquer automatiquement l'accès à toutes les ressources du groupe.

Pour révoquer l'accès d'un utilisateur au groupe lorsque vous utilisez également SCIM, consultez [Supprimer l'accès](scim_setup.md#remove-access).

### Dissocier des comptes {#unlink-accounts}

Les utilisateurs peuvent dissocier SAML pour un groupe depuis leur page de profil. Cela peut être utile si :

- Vous ne souhaitez plus qu'un groupe puisse vous connecter à GitLab.com.
- Votre **NameID** SAML a changé et GitLab ne peut plus trouver votre utilisateur.

> [!warning]
> La dissociation d'un compte supprime tous les rôles attribués à cet utilisateur dans le groupe. Si un utilisateur relie à nouveau son compte, les rôles doivent être réattribués.

Les groupes nécessitent au moins un propriétaire. Si votre compte est le seul propriétaire du groupe, vous n'êtes pas autorisé à dissocier le compte. Dans ce cas, configurez un autre utilisateur en tant que propriétaire du groupe, puis vous pourrez dissocier le compte.

Par exemple, pour dissocier le compte `MyOrg` :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Mot de passe et authentification**.
1. Dans la section **Connexion via un service tiers**, sélectionnez **Déconnecter** en regard du compte connecté.

## Application du SSO {#sso-enforcement}

Sur GitLab.com, l'authentification unique SSO est appliquée :

- Lorsque l'authentification unique SAML est activée.
- Pour les utilisateurs disposant d'une identité SAML existante lors de l'accès aux groupes et aux projets dans la hiérarchie de groupe de l'organisation. En utilisant leurs identifiants GitLab.com, les utilisateurs peuvent consulter d'autres groupes et projets en dehors de leur organisation, ainsi que leurs paramètres utilisateur, sans se connecter via l'authentification unique SAML.

Un utilisateur dispose d'une identité SAML si l'une ou les deux conditions suivantes sont vraies :

- Il s'est connecté à GitLab en utilisant l'URL d'authentification unique de son groupe GitLab.
- Il a été provisionné par SCIM.

Les utilisateurs ne sont pas invités à se connecter via l'authentification unique à chaque visite. GitLab vérifie si un utilisateur s'est authentifié via l'authentification unique. Si l'utilisateur s'est connecté pour la dernière fois il y a plus de 24 heures, GitLab l'invite à se reconnecter via l'authentification unique.

L'application du SSO est la suivante :

| Visibilité du projet/groupe | Paramètre d'application du SSO | Membre avec identité | Membre sans identité | Non-membre ou non connecté |
|--------------------------|---------------------|----------------------|-------------------------|-----------------------------|
| Privé                  | Désactivé                 | Appliqué             | Non appliqué            | Non appliqué                |
| Privé                  | Activée                  | Appliqué             | Appliqué                | Appliqué                    |
| Public                   | Désactivé                 | Appliqué             | Non appliqué            | Non appliqué                |
| Public                   | Activée                  | Appliqué             | Appliqué                | Non appliqué                |

> [!note]
> L'application du SSO ne s'applique pas aux requêtes API. Cependant, vous pouvez [désactiver l'authentification par mot de passe et clé d'accès pour les utilisateurs Enterprise](#disable-password-and-passkey-authentication-for-enterprise-users) afin d'empêcher l'accès à l'API par mot de passe.
>
> Un [ticket propose](https://gitlab.com/gitlab-org/gitlab/-/issues/297389) d'ajouter l'application du SSO pour l'activité API.

### Application du SSO uniquement pour l'activité Web {#sso-only-for-web-activity-enforcement}

Lorsque l'option **Mettre en œuvre l'authentification unique SSO pour l'activité Web de ce groupe** est activée :

- Tous les membres doivent accéder à GitLab en utilisant l'URL d'authentification unique de leur groupe GitLab pour accéder aux ressources du groupe, qu'ils aient ou non une identité SAML existante.
- L'authentification unique est appliquée lorsque les utilisateurs accèdent aux groupes et aux projets dans la hiérarchie de groupe de l'organisation. Les utilisateurs peuvent consulter d'autres groupes et projets en dehors de leur organisation sans se connecter via l'authentification unique SAML.
- Les utilisateurs ne peuvent pas être ajoutés manuellement en tant que nouveaux membres.
- Les utilisateurs disposant du rôle Propriétaire peuvent utiliser le processus de connexion standard pour apporter les modifications nécessaires aux paramètres du groupe principal.
- Pour les non-membres ou les utilisateurs non connectés :
  - L'authentification unique n'est pas appliquée lorsqu'ils accèdent aux ressources de groupe public.
  - L'authentification unique est appliquée lorsqu'ils accèdent aux ressources de groupe privé.
- Pour les éléments dans la hiérarchie de groupe de l'organisation, la visibilité du tableau de bord est la suivante :
  - L'authentification unique est appliquée lors de la consultation de votre [liste de tâches](../../todos.md). Vos éléments de la liste de tâches sont masqués si votre session SSO a expiré, et une [alerte est affichée](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/115254).
  - L'authentification unique est appliquée lors de la consultation de votre liste de tickets assignés. Vos tickets sont masqués si votre session SSO a expiré. Le [ticket 414475](https://gitlab.com/gitlab-org/gitlab/-/issues/414475) propose de modifier ce comportement afin que les tickets soient visibles.
  - L'authentification unique n'est pas appliquée lors de la consultation des merge requests dont vous êtes l'assigné ou le relecteur. Vous pouvez voir les merge requests même si votre session SSO a expiré.
  - L'authentification unique n'est pas appliquée lors de la consultation des extraits de code pour les projets privés pour lesquels vous avez le rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire.

L'application du SSO pour l'activité Web a les effets suivants lorsqu'elle est activée :

- Pour les groupes, les utilisateurs ne peuvent pas partager un projet du groupe en dehors du groupe principal, même si le projet est dupliqué.
- L'activité Git provenant des jobs CI/CD n'est pas soumise à la vérification SSO.
- Les identifiants qui ne sont pas liés aux utilisateurs ordinaires (par exemple, les jetons d'accès aux projets et aux groupes, les comptes de service et les clés de déploiement) ne sont pas soumis à la vérification SSO.
- Les utilisateurs doivent être connectés via l'authentification unique avant de pouvoir extraire des images à l'aide du [proxy de dépendances](../../packages/dependency_proxy/_index.md).
- Lorsque l'option **Mettre en œuvre l'authentification unique SSO pour les activités de Git et du Proxy de Dépendance pour ce groupe** est activée, tout point de terminaison API impliquant une activité Git est soumis à l'application du SSO. Par exemple, la création ou la suppression d'une branche, d'un commit ou d'un tag. Pour l'activité Git via SSH et HTTPS, les utilisateurs doivent disposer d'au moins une session active connectée via l'authentification unique avant de pouvoir envoyer des modifications ou en extraire depuis un dépôt GitLab. La session active peut se trouver sur un autre appareil.

Lorsque l'authentification unique pour l'activité Web est appliquée, les membres du groupe non-SSO ne perdent pas immédiatement l'accès. Si l'utilisateur :

- Dispose d'une session active, il peut continuer à accéder au groupe pendant jusqu'à 24 heures jusqu'à l'expiration de la session du fournisseur d'identité.
- Est déconnecté, il ne peut plus accéder au groupe après avoir été supprimé du fournisseur d'identité.

### Mise en miroir des dépôts avec l'application du SSO {#repository-mirroring-with-sso-enforcement}

Lorsque vous activez **Mettre en œuvre l'authentification unique SSO pour les activités de Git et du Proxy de Dépendance pour ce groupe**, la mise en miroir des dépôts est soumise aux exigences de session SSO. Pour plus d'informations, consultez [Mise en miroir de type Pull avec l'application du SSO](../../project/repository/mirror/pull.md#pull-mirroring-with-sso-enforcement).

## Migrer vers un nouveau fournisseur d'identité {#migrate-to-a-new-identity-provider}

Pour migrer vers un nouveau fournisseur d'identité, utilisez l'[API SAML](../../../api/saml.md) pour mettre à jour toutes les identités des membres de votre groupe.

Par exemple :

1. Définissez une fenêtre de maintenance pour vous assurer qu'aucun utilisateur n'est actif à ce moment-là.
1. Utilisez l'API SAML [pour mettre à jour l'identité de chaque utilisateur](../../../api/saml.md#update-extern_uid-field-for-a-saml-identity).
1. Configurez le nouveau fournisseur d'identité.
1. Vérifiez que la connexion fonctionne.

> [!NOTE]
> Les utilisateurs non Enterprise doivent réinitialiser leur mot de passe SAML et [relier SAML à leur compte](#link-saml-to-your-existing-gitlabcom-account) après la mise à jour de leur identité.

## Sujets connexes {#related-topics}

- [Authentification unique SAML pour GitLab Self-Managed](../../../integration/saml.md)
- [Glossaire](../../../auth/auth_glossary.md)
- [Article de blog : le guide ultime pour activer SAML et SSO sur GitLab.com](https://about.gitlab.com/blog/the-ultimate-guide-to-enabling-saml/)
- [Comparaison de l'authentification entre GitLab.com et GitLab Self-Managed](../../../administration/auth/_index.md#gitlabcom-compared-to-gitlab-self-managed)
- [Mots de passe pour les utilisateurs créés via l'authentification intégrée](../../profile/user_passwords.md)
- [Synchronisation des groupes SAML](group_sync.md)

## Dépannage {#troubleshooting}

Si vous avez du mal à faire correspondre les différents termes SAML entre GitLab et le fournisseur d'identité :

1. Consultez la documentation de votre fournisseur d'identité. Examinez leurs exemples de configurations SAML pour obtenir des informations sur les termes qu'ils utilisent.
1. Consultez la [documentation sur l'authentification unique SAML pour GitLab Self-Managed](../../../integration/saml.md). Le fichier de configuration SAML de GitLab Self-Managed prend en charge plus d'options que le fichier GitLab.com. Vous pouvez trouver des informations sur le fichier de l'instance GitLab Self-Managed dans :
   - La [documentation OmniAuth SAML](https://github.com/omniauth/omniauth-saml/) externe.
   - [La bibliothèque `ruby-saml`](https://github.com/SAML-Toolkits/ruby-saml).
1. Comparez la réponse XML de votre fournisseur avec notre [exemple de XML utilisé pour les tests internes](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/spec/fixtures/saml/response.xml).

Pour d'autres informations de dépannage, consultez le [guide de dépannage SAML](troubleshooting.md).
