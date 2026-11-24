---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 예제 그룹 SAML 및 SCIM 구성
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

다음은 GitLab 지원팀이 문제 해결 중에 사용하는 그룹 SAML 및 SCIM에 관한 메모 및 스크린샷입니다. 다만 공식 문서에는 포함되지 않습니다. GitLab은 지원팀의 수집된 지식을 누구나 활용할 수 있도록 공개합니다.

기능에 대한 정보와 설정 방법은 GitLab [그룹 SAML](_index.md) 문서를 참고하세요.

SAML 구성을 문제 해결할 때 GitLab 팀 멤버는 자주 [SAML 문제 해결 섹션](_index.md#troubleshooting)부터 시작합니다.

그 다음 원하는 자격증명 공급자의 테스트 구성을 설정합니다. 이 섹션에 예제 스크린샷을 포함합니다.

## SAML 및 SCIM 스크린샷 {#saml-and-scim-screenshots}

이 섹션은 [그룹 SAML](_index.md) 및 [그룹 SCIM](scim_setup.md)의 다음 예제 구성에 대한 관련 스크린샷을 포함합니다:

- [Azure Active Directory](#azure-active-directory)
- [AWS IAM Identity Center](#aws-iam-identity-center)
- [Google Workspace](#google-workspace)
- [Okta](#okta)
- [OneLogin](#onelogin)

> [!warning]
> 이러한 스크린샷은 필요에 따라 GitLab 지원팀에서만 업데이트합니다. 공식 문서가 아닙니다.

현재 GitLab에서 문제가 발생하는 경우 [지원 옵션](https://support.gitlab.com/)을 확인할 수 있습니다.

## Azure Active Directory {#azure-active-directory}

이 섹션은 Azure Active Directory 구성 요소의 스크린샷을 포함합니다.

### 기본 SAML 앱 구성 {#basic-saml-app-configuration}

![Azure Active Directory의 기본 SAML 구성 설정입니다.](img/AzureAD-basic_SAML_v14_1.png)

### 사용자 클레임 및 속성 {#user-claims-and-attributes}

![Azure Active Directory의 사용자 클레임 및 속성 구성입니다.](img/AzureAD-claims_v14_1.png)

### SCIM 매핑 {#scim-mapping}

프로비저닝:

![Azure Active Directory의 SCIM 프로비저닝 설정입니다.](img/AzureAD-scim_provisioning_v14_8.png)

### 속성 매핑 {#attribute-mapping}

![Azure Active Directory의 SCIM 속성 매핑 구성입니다.](img/AzureAD-scim_attribute_mapping_v12_2.png)

### 그룹 동기화 {#group-sync}

![Azure Active Directory의 SAML에 대한 그룹 클레임 구성입니다.](img/azure_configure_group_claim_v14_0.png)

**그룹 ID** 소스 속성을 사용하려면 사용자가 SAML 그룹 링크를 구성할 때 그룹 ID 또는 개체 ID를 입력해야 합니다.

가능한 경우 대신 사용자 친화적인 그룹 이름을 추가할 수 있습니다. Azure 그룹 클레임을 설정할 때:

1. **sAMAccountName** 소스 속성을 선택합니다.
1. 그룹 이름을 입력합니다. 최대 256자 길이의 이름을 지정할 수 있습니다.
1. 속성이 어설션의 일부임을 보장하려면 **클라우드 전용 그룹에 대한 그룹 이름 내보내기**를 선택합니다.

[Azure AD는 SAML 응답에서 보낼 수 있는 그룹 수를 150개로 제한합니다](https://support.esri.com/en-us/knowledge-base/when-azure-ad-is-the-saml-identify-provider-the-group-a-000022190). 사용자가 150개 이상의 그룹에 속하는 경우 Azure는 SAML 응답에 해당 사용자의 그룹 클레임을 포함하지 않습니다.

## Google Workspace {#google-workspace}

### 기본 SAML 앱 구성 {#basic-saml-app-configuration-1}

![Google Workspace의 기본 SAML 앱 구성 설정입니다.](img/GoogleWorkspace-basic-SAML_v14_10.png)

### 사용자 클레임 및 속성 {#user-claims-and-attributes-1}

![Google Workspace의 사용자 클레임 및 속성 구성입니다.](img/GoogleWorkspace-claims_v14_10.png)

### IdP 링크 및 인증서 {#idp-links-and-certificate}

![Google Workspace의 자격증명 공급자 링크 및 인증서 설정입니다.](img/GoogleWorkspace-linkscert_v14_10.png)

## Okta {#okta}

### GitLab.com 그룹에 대한 기본 SAML 앱 구성 {#basic-saml-app-configuration-for-gitlabcom-groups}

![Okta의 GitLab.com 그룹에 대한 기본 SAML 앱 구성 설정입니다.](img/Okta-GroupSAML_v15_3.png)

### GitLab Self-Managed에 대한 기본 SAML 앱 구성 {#basic-saml-app-configuration-for-gitlab-self-managed}

![Okta 관리 패널의 GitLab Self-Managed에 대한 기본 SAML 앱 구성 설정입니다.](img/Okta-SM_v15_3.png)

### 사용자 클레임 및 속성 {#user-claims-and-attributes-2}

![Okta의 사용자 클레임 및 속성 구성입니다.](img/Okta-attributes_v15_3.png)

### 그룹 동기화 {#group-sync-1}

![Okta의 그룹 동기화를 위한 그룹 속성 구성입니다.](img/Okta-GroupAttribute_v15_3.png)

### 고급 SAML 앱 설정 (기본값) {#advanced-saml-app-settings-defaults}

![Okta의 고급 SAML 앱 설정 및 기본값입니다.](img/Okta-advancedsettings_v15_3.png)

### IdP 링크 및 인증서 {#idp-links-and-certificate-1}

![Okta의 자격증명 공급자 링크 및 인증서 설정입니다.](img/Okta-linkscert_v15_3.png)

### SAML 로그온 설정 {#saml-sign-on-settings}

![Okta 구성의 SAML 로그온 설정입니다.](img/okta_saml_settings_v15_3.png)

### SCIM 설정 {#scim-settings}

SCIM 앱을 할당할 때 새로 프로비저닝된 사용자의 사용자명 설정:

![Okta에서 사용자에게 SCIM 애플리케이션을 할당하고 사용자명을 설정하는 인터페이스입니다.](img/okta_setting_username_v14_6.png)

## OneLogin {#onelogin}

### 기본 SAML 앱 구성 {#basic-saml-app-configuration-2}

![OneLogin의 기본 애플리케이션 세부 정보 및 구성 설정입니다.](img/OneLogin-app_details_v12_8.png)

### 매개변수 {#parameters}

![OneLogin의 애플리케이션 매개변수 및 속성 매핑 설정입니다.](img/OneLogin-parameters_v12_8.png)

### 사용자 추가 {#adding-a-user}

![OneLogin에서 애플리케이션에 사용자를 추가하는 인터페이스입니다.](img/OneLogin-userAdd_v12_8.png)

### SSO 설정 {#sso-settings}

![OneLogin의 통합 인증(SSO) 설정 및 인증서 구성입니다.](img/OneLogin-SSOsettings_v12_8.png)

## AWS IAM Identity Center {#aws-iam-identity-center}

다음 표의 값으로 AWS IAM Identity Center를 구성합니다. 전체 설정 지침은 [AWS IAM Identity Center](_index.md#aws-iam-identity-center)를 참고하세요.

### 애플리케이션 속성 {#application-properties}

AWS IAM Identity Center에서 자체 SAML 2.0 애플리케이션을 설정할 때 다음 애플리케이션 속성을 구성합니다:

| AWS Identity Center 필드       | 값                                                                                         |
| ------------------------------- | --------------------------------------------------------------------------------------------- |
| **애플리케이션 ACS URL**         | 그룹의 **어설션 컨슈머 서비스 (Assertion Consumer Service) URL** (GitLab **SAML SSO** 설정에서)           |
| **애플리케이션 SAML 대상**   | 그룹의 **식별자** (GitLab **SAML SSO** 설정에서)                               |
| **애플리케이션 시작 URL**       | 그룹의 **GitLab 통합 인증(SSO) URL** (GitLab **SAML SSO** 설정에서)                |

SP 시작 로그인을 위해 **애플리케이션 시작 URL**을 설정합니다. 이를 설정하지 않으면 기존 사용자가 자신의 계정을 연결할 수 없습니다.

### 속성 매핑 {#attribute-mappings}

| 속성      | 값                | 형식        |
| -------------- | -------------------- | ------------- |
| **제목**    | `${user:email}`      | `unspecified` |
| **이메일**      | `${user:email}`      | `unspecified` |
| **이름** | `${user:givenName}`  | `unspecified` |
| **성**  | `${user:familyName}` | `unspecified` |

> [!warning]
> **제목** (NameID) 형식을 `unspecified`으로 설정해야 합니다. 형식을 `persistent` 또는 `transient`로 설정하면 기존 GitLab 사용자는 SAML을 통해 자신의 계정을 연결하려고 할 때 `403` 오류를 수신합니다. 이 오류는 계정 연결 중에만 발생하며 AWS IAM Identity Center를 통해 프로비저닝된 새 사용자에게는 영향을 미치지 않습니다.

### GitLab SAML SSO 설정 {#gitlab-saml-sso-settings}

| GitLab 필드                             | 값                                                                           |
| ---------------------------------------- | ------------------------------------------------------------------------------- |
| **자격증명 공급자 통합 인증(SSO)** | **IAM Identity Center 로그인 URL** (애플리케이션의 **IAM Identity Center SAML 메타데이터** 섹션에서)|
| **인증서 핑거프린트**              | AWS Identity Center에서 다운로드한 인증서의 SHA1 핑거프린트         |

## SAML 응답 예제 {#saml-response-example}

사용자가 SAML을 사용하여 로그인하면 GitLab은 SAML 응답을 수신합니다. SAML 응답은 `production.log` 로그에서 base64로 인코딩된 메시지로 찾을 수 있습니다. `SAMLResponse`를 검색하여 응답을 찾습니다. 디코딩된 SAML 응답은 XML 형식입니다. 예를 들어:

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
