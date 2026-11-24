---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Exemples de configurations SAML de groupe et SCIM
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Ces notes et captures d'écran concernant le SAML de groupe et le SCIM sont parfois utilisées par l'équipe de support GitLab lors du dépannage, mais ne font pas partie de la documentation officielle. GitLab les rend publiques afin que toute personne puisse bénéficier des connaissances accumulées par l'équipe de support.

Consultez la documentation GitLab sur le [SAML de groupe](_index.md) pour obtenir des informations sur la fonctionnalité et sa configuration.

Lors du dépannage d'une configuration SAML, les membres de l'équipe GitLab commencent fréquemment par la [section de dépannage SAML](_index.md#troubleshooting).

Ils peuvent ensuite configurer une configuration de test du fournisseur d'identité souhaité. Nous incluons des exemples de captures d'écran dans cette section.

## Captures d'écran SAML et SCIM {#saml-and-scim-screenshots}

Cette section comprend des captures d'écran pertinentes des exemples de configurations suivants pour le [SAML de groupe](_index.md) et le [SCIM de groupe](scim_setup.md) :

- [Azure Active Directory](#azure-active-directory)
- [AWS IAM Identity Center](#aws-iam-identity-center)
- [Google Workspace](#google-workspace)
- [Okta](#okta)
- [OneLogin](#onelogin)

> [!warning]
> Ces captures d'écran sont mises à jour uniquement selon les besoins du support GitLab. Elles ne constituent pas une documentation officielle.

Si vous rencontrez actuellement un problème avec GitLab, vous pouvez consulter vos [options de support](https://support.gitlab.com/).

## Azure Active Directory {#azure-active-directory}

Cette section contient des captures d'écran pour les éléments de la configuration d'Azure Active Directory.

### Configuration de base de l'application SAML {#basic-saml-app-configuration}

![Les paramètres de configuration SAML de base dans Azure Active Directory.](img/AzureAD-basic_SAML_v14_1.png)

### Revendications et attributs utilisateur {#user-claims-and-attributes}

![La configuration des revendications et attributs utilisateur dans Azure Active Directory.](img/AzureAD-claims_v14_1.png)

### Mappage SCIM {#scim-mapping}

Provisionnement :

![Les paramètres de provisionnement SCIM dans Azure Active Directory.](img/AzureAD-scim_provisioning_v14_8.png)

### Mappage d'attributs {#attribute-mapping}

![La configuration du mappage d'attributs SCIM dans Azure Active Directory.](img/AzureAD-scim_attribute_mapping_v12_2.png)

### Synchronisation de groupe {#group-sync}

![La configuration des revendications de groupe pour SAML dans Azure Active Directory.](img/azure_configure_group_claim_v14_0.png)

L'utilisation de l'attribut source **ID du groupe** oblige les utilisateurs à saisir l'ID du groupe ou l'ID d'objet lors de la configuration des liens de groupe SAML.

Si disponible, vous pouvez ajouter à la place des noms de groupe conviviaux. Lors de la configuration des revendications de groupe Azure :

1. Sélectionnez l'attribut source **sAMAccountName**.
1. Saisissez un nom de groupe. Vous pouvez spécifier un nom contenant jusqu'à 256 caractères.
1. Pour vous assurer que l'attribut fait partie de l'assertion, sélectionnez **Émettre les noms de groupe pour les groupes cloud uniquement**.

[Azure AD limite le nombre de groupes pouvant être envoyés dans une réponse SAML à 150](https://support.esri.com/en-us/knowledge-base/when-azure-ad-is-the-saml-identify-provider-the-group-a-000022190). Si un utilisateur est membre de plus de 150 groupes, Azure n'inclut pas la revendication de groupe de cet utilisateur dans la réponse SAML.

## Google Workspace {#google-workspace}

### Configuration de base de l'application SAML {#basic-saml-app-configuration-1}

![Les paramètres de configuration de base de l'application SAML dans Google Workspace.](img/GoogleWorkspace-basic-SAML_v14_10.png)

### Revendications et attributs utilisateur {#user-claims-and-attributes-1}

![La configuration des revendications et attributs utilisateur dans Google Workspace.](img/GoogleWorkspace-claims_v14_10.png)

### Liens IdP et certificat {#idp-links-and-certificate}

![Les liens du fournisseur d'identité et les paramètres de certificat dans Google Workspace.](img/GoogleWorkspace-linkscert_v14_10.png)

## Okta {#okta}

### Configuration de base de l'application SAML pour les groupes GitLab.com {#basic-saml-app-configuration-for-gitlabcom-groups}

![Les paramètres de configuration de base de l'application SAML pour les groupes GitLab.com dans Okta.](img/Okta-GroupSAML_v15_3.png)

### Configuration de base de l'application SAML pour GitLab Self-Managed {#basic-saml-app-configuration-for-gitlab-self-managed}

![Les paramètres de configuration de base de l'application SAML pour GitLab Self-Managed dans le panneau d'administration Okta.](img/Okta-SM_v15_3.png)

### Revendications et attributs utilisateur {#user-claims-and-attributes-2}

![La configuration des revendications et attributs utilisateur dans Okta.](img/Okta-attributes_v15_3.png)

### Synchronisation de groupe {#group-sync-1}

![La configuration des attributs de groupe pour la synchronisation de groupe dans Okta.](img/Okta-GroupAttribute_v15_3.png)

### Paramètres avancés de l'application SAML (valeurs par défaut) {#advanced-saml-app-settings-defaults}

![Les paramètres avancés de l'application SAML et leurs valeurs par défaut dans Okta.](img/Okta-advancedsettings_v15_3.png)

### Liens IdP et certificat {#idp-links-and-certificate-1}

![Les liens du fournisseur d'identité et les paramètres de certificat dans Okta.](img/Okta-linkscert_v15_3.png)

### Paramètres d'authentification SAML {#saml-sign-on-settings}

![Les paramètres d'authentification SAML dans la configuration Okta.](img/okta_saml_settings_v15_3.png)

### Paramètres SCIM {#scim-settings}

Définition du nom d'utilisateur pour les utilisateurs nouvellement provisionnés lors de leur attribution à l'application SCIM :

![L'interface permettant d'attribuer une application SCIM aux utilisateurs et de définir leur nom d'utilisateur dans Okta.](img/okta_setting_username_v14_6.png)

## OneLogin {#onelogin}

### Configuration de base de l'application SAML {#basic-saml-app-configuration-2}

![Les détails et paramètres de configuration de base de l'application dans OneLogin.](img/OneLogin-app_details_v12_8.png)

### Paramètres {#parameters}

![Les paramètres de l'application et les paramètres de mappage d'attributs dans OneLogin.](img/OneLogin-parameters_v12_8.png)

### Ajout d'un utilisateur {#adding-a-user}

![L'interface permettant d'ajouter un utilisateur à une application dans OneLogin.](img/OneLogin-userAdd_v12_8.png)

### Paramètres SSO {#sso-settings}

![Les paramètres d'authentification unique et la configuration du certificat dans OneLogin.](img/OneLogin-SSOsettings_v12_8.png)

## AWS IAM Identity Center {#aws-iam-identity-center}

Configurez AWS IAM Identity Center avec les valeurs indiquées dans les tableaux suivants. Pour obtenir les instructions de configuration complètes, consultez [AWS IAM Identity Center](_index.md#aws-iam-identity-center).

### Propriétés de l'application {#application-properties}

Lors de la configuration de votre propre application SAML 2.0 dans AWS IAM Identity Center, configurez les propriétés d'application suivantes :

| Champ AWS Identity Center       | Valeur                                                                                         |
| ------------------------------- | --------------------------------------------------------------------------------------------- |
| **URL ACS de l'application**         | L'**URL du service consommateur d'assertion** de votre groupe (depuis les paramètres d'**Authentification unique SAML** de GitLab)           |
| **Audience SAML de l'application**   | L'**Identifiant** de votre groupe (depuis les paramètres d'**Authentification unique SAML** de GitLab)                               |
| **URL de démarrage de l'application**       | L'**URL de l'authentification unique GitLab** de votre groupe (depuis les paramètres d'**Authentification unique SAML** de GitLab)                |

Définissez l'**URL de démarrage de l'application** pour l'authentification initiée par le fournisseur de services (SP). Sans elle, les utilisateurs existants ne peuvent pas associer leurs comptes.

### Mappages d'attributs {#attribute-mappings}

| Attribut      | Valeur                | Format        |
| -------------- | -------------------- | ------------- |
| **Objet**    | `${user:email}`      | `unspecified` |
| **email**      | `${user:email}`      | `unspecified` |
| **first_name** | `${user:givenName}`  | `unspecified` |
| **last_name**  | `${user:familyName}` | `unspecified` |

> [!warning]
> Vous devez définir le format **Objet** (NameID) sur `unspecified`. Si vous définissez le format sur `persistent` ou `transient`, les utilisateurs GitLab existants reçoivent une erreur `403` lorsqu'ils tentent d'associer leurs comptes via SAML. Cette erreur se produit uniquement lors de l'association de comptes et n'affecte pas les nouveaux utilisateurs provisionnés via AWS IAM Identity Center.

### Paramètres d'authentification unique SAML GitLab {#gitlab-saml-sso-settings}

| Champ GitLab                             | Valeur                                                                           |
| ---------------------------------------- | ------------------------------------------------------------------------------- |
| **URL d'authentification unique du fournisseur d'identité** | **URL de connexion IAM Identity Center** (depuis la section **Métadonnées SAML IAM Identity Center** de l'application)|
| **Empreinte du certificat**              | Empreinte SHA1 du certificat téléchargé depuis AWS Identity Center         |

## Exemple de réponse SAML {#saml-response-example}

Lorsqu'un utilisateur se connecte via SAML, GitLab reçoit une réponse SAML. La réponse SAML est disponible dans les journaux `production.log` sous forme de message encodé en base64. Localisez la réponse en recherchant `SAMLResponse`. La réponse SAML décodée est au format XML. Par exemple :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" Destination="https://gitlabexample/-/saml/callback" ID="id4898983630840142426821432" InResponseTo="_c65e4c88-9425-4472-b42c-37f4186ac0ee" IssueInstant="2022-05-30T21:30:35.696Z" Version="2.0">
 <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk2y6j57o1Pdr2lI8qh7</saml2:Issuer>
 <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
   <ds:SignedInfo>
     <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
     <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
     <ds:Reference URI="#id4898983630840142426821432">
       <ds:Transforms>
         <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
         <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
           <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/>
         </ds:Transform>
       </ds:Transforms>
       <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
       <ds:DigestValue>neiQvv9d3OgS4GZW8Nptp4JhjpKs3GCefibn+vmRgk4=</ds:DigestValue>
     </ds:Reference>
   </ds:SignedInfo>
   <ds:SignatureValue>dMsQX8ivi...HMuKGhyLRvabGU6CuPrf7==</ds:SignatureValue>
   <ds:KeyInfo>
     <ds:X509Data>
       <ds:X509Certificate>MIIDq...cptGr3vN9TQ==</ds:X509Certificate>
     </ds:X509Data>
   </ds:KeyInfo>
 </ds:Signature>
 <saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
   <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
 </saml2p:Status>
 <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="id489" IssueInstant="2022-05-30T21:30:35.696Z" Version="2.0">
   <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk2y6j57o1Pdr2lI8qh7</saml2:Issuer>
   <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
     <ds:SignedInfo>
       <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
       <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
       <ds:Reference URI="#id48989836309833801859473359">
         <ds:Transforms>
           <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
           <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
             <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/>
           </ds:Transform>
         </ds:Transforms>
         <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
         <ds:DigestValue>MaIsoi8hbT9gsi/mNZsz449mUuAcuEWY0q3bc4asOQs=</ds:DigestValue>
       </ds:Reference>
     </ds:SignedInfo>
     <ds:SignatureValue>dMsQX8ivi...HMuKGhyLRvabGU6CuPrf7==</ds:SignatureValue>
     <ds:KeyInfo>
       <ds:X509Data>
         <ds:X509Certificate>MIIDq...cptGr3vN9TQ==</ds:X509Certificate>
       </ds:X509Data>
     </ds:KeyInfo>
   </ds:Signature>
   <saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
     <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">useremail@domain.com</saml2:NameID>
     <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
       <saml2:SubjectConfirmationData InResponseTo="_c65e4c88-9425-4472-b42c-37f4186ac0ee" NotOnOrAfter="2022-05-30T21:35:35.696Z" Recipient="https://gitlab.example.com/-/saml/callback"/>
     </saml2:SubjectConfirmation>
   </saml2:Subject>
   <saml2:Conditions xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" NotBefore="2022-05-30T21:25:35.696Z" NotOnOrAfter="2022-05-30T21:35:35.696Z">
     <saml2:AudienceRestriction>
       <saml2:Audience>https://gitlab.example.com/</saml2:Audience>
     </saml2:AudienceRestriction>
   </saml2:Conditions>
   <saml2:AuthnStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" AuthnInstant="2022-05-30T21:30:35.696Z" SessionIndex="_c65e4c88-9425-4472-b42c-37f4186ac0ee">
     <saml2:AuthnContext>
       <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
     </saml2:AuthnContext>
   </saml2:AuthnStatement>
   <saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
     <saml2:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
       <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">useremail@domain.com</saml2:AttributeValue>
     </saml2:Attribute>
     <saml2:Attribute Name="firstname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
       <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">John</saml2:AttributeValue>
     </saml2:Attribute>
     <saml2:Attribute Name="lastname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
       <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Doe</saml2:AttributeValue>
     </saml2:Attribute>
     <saml2:Attribute Name="Groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
       <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Super-awesome-group</saml2:AttributeValue>
     </saml2:Attribute>
   </saml2:AttributeStatement>
 </saml2:Assertion>
</saml2p:Response>
```
