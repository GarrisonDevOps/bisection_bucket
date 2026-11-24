---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab.com 그룹용 SAML SSO
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

> [!note]
> GitLab Self-Managed의 경우 [GitLab Self-Managed용 SAML SSO](../../../integration/saml.md)를 참조하세요.

사용자는 SAML 자격증명 공급자를 통해 GitLab에 로그인할 수 있습니다.

[SCIM](scim_setup.md)은 GitLab.com의 그룹과 사용자를 동기화합니다.

- SCIM 앱에서 사용자를 추가하거나 제거하면 SCIM은 GitLab 그룹에서 사용자를 추가하거나 제거합니다.
- 사용자가 아직 그룹 구성원이 아닌 경우 로그인 프로세스의 일부로 그룹에 추가됩니다.

최상위 그룹에만 SAML SSO를 구성할 수 있습니다.

## 자격증명 공급자 설정 {#set-up-your-identity-provider}

SAML 표준은 GitLab과 함께 광범위한 자격증명 공급자를 사용할 수 있음을 의미합니다. 자격증명 공급자에는 관련 설명서가 있을 수 있습니다. 일반 SAML 설명서이거나 GitLab을 대상으로 하는 설명서일 수 있습니다.

자격증명 공급자를 설정할 때 다음 공급자 특정 설명서를 사용하여 일반적인 문제를 피하고 사용된 용어에 대한 가이드로 사용하세요.

목록에 없는 자격증명 공급자의 경우 [인스턴스 SAML 구성 참고](../../../integration/saml.md#configure-saml-on-your-idp)를 참조하여 공급자가 필요로 할 수 있는 정보에 대한 추가 지침을 얻을 수 있습니다.

GitLab은 다음 정보만 참고용으로 제공합니다. SAML 앱 구성에 대해 질문이 있으면 공급자의 지원팀에 문의하세요.

자격증명 공급자 설정에 문제가 있으면 [문제 해결 설명서](#troubleshooting)를 참조하세요.

### Azure {#azure}

Azure를 자격증명 공급자로 SSO를 설정하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **SAML SSO**를 선택합니다.
1. 이 페이지의 정보를 기록하세요.
1. Azure로 이동하여 [비갤러리 애플리케이션 만들기](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview-application-gallery#create-your-own-application)를 수행하고 [애플리케이션용 SSO 구성](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso)을 수행하세요. 다음 GitLab 설정은 Azure 필드에 해당합니다.

   | GitLab 설정                           | Azure 필드                                    |
   | -----------------------------------------| ---------------------------------------------- |
   | **식별자**                           | **식별자(엔터티 ID)**                     |
   | **어설션 컨슈머 서비스 (Assertion Consumer Service) URL**       | **회신 URL(어설션 컨슈머 서비스 URL)** |
   | **GitLab 통합 인증(SSO) URL**            | **로그인 URL**                                |
   | **자격증명 공급자 통합 인증(SSO)** | **로그인 URL**                                  |
   | **인증서 핑거프린트**              | **지문**                                 |

1. 다음 특성을 설정해야 합니다:
   - **고유한 사용자 식별자(이름 ID)**를 `user.objectID`로 설정하세요.
     - **이름 식별자 형식**을 `persistent`로 설정하세요. 자세한 내용은 [사용자 SAML ID 관리](#manage-user-saml-identity)를 참조하세요.
   - **추가 클레임**을 [지원되는 특성](#configure-assertions)으로 설정하세요.

1. 자격증명 공급자가 기존 GitLab 계정을 연결하도록 공급자에서 시작한 호출을 갖도록 설정되어 있는지 확인하세요.

1. 선택 사항. [그룹 동기화](group_sync.md)를 사용하는 경우 그룹 클레임의 이름을 필요한 특성과 일치하도록 사용자 지정하세요.

<i class="fa-youtube-play" aria-hidden="true"></i> [Azure를 사용하여 그룹에 대한 SCIM 프로비저닝](https://youtu.be/24-ZxmTeEBU) 데모를 봅니다. `objectID` 매핑은 이 비디오에서 오래되었습니다. 대신 [SCIM에 대한 Microsoft Entra ID 구성 설명서](scim_setup.md#configure-microsoft-entra-id)의 지침을 따르세요.

자세한 내용은 [Azure 구성 예제](example_saml_config.md#azure-active-directory)를 참조하세요.

### Google Workspace {#google-workspace}

Google Workspace를 자격증명 공급자로 설정하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **SAML SSO**를 선택합니다.
1. 이 페이지의 정보를 기록하세요.
1. [Google을 자격증명 공급자로 SSO 설정](https://support.google.com/a/answer/6087519?hl=en)의 지침을 따르세요. 다음 GitLab 설정은 Google Workspace 필드에 해당합니다.

   | GitLab 설정                           | Google Workspace 필드 |
   |:-----------------------------------------|:-----------------------|
   | **식별자**                           | **엔터티 ID**          |
   | **어설션 컨슈머 서비스 (Assertion Consumer Service) URL**       | **ACS URL**            |
   | **GitLab 통합 인증(SSO) URL**            | **시작 URL**          |
   | **자격증명 공급자 통합 인증(SSO)** | **SSO URL**            |

1. Google Workspace는 인증서를 검색할 때 SHA256 핑거프린트를 표시합니다. 나중에 SHA256 핑거프린트를 생성해야 하면 [핑거프린트 계산](troubleshooting.md#calculate-the-fingerprint)을 참조하세요.
1. 이 값들을 설정하세요:
   - **기본 이메일**의 경우: `email`.
   - **이름**의 경우: `first_name`.
   - **성**의 경우: `last_name`.
   - **NameID 형식**의 경우: `EMAIL`.
   - **NameID**의 경우: `Basic Information > Primary email`. 자세한 내용은 [지원되는 특성](#configure-assertions)을 참조하세요.

1. 자격증명 공급자가 기존 GitLab 계정을 연결하도록 공급자에서 시작한 호출을 갖도록 설정되어 있는지 확인하세요.

GitLab SAML SSO 페이지에서 **SAML 구성 확인**을 선택할 때 NameID 형식을 `persistent`로 설정하도록 권장하는 경고는 무시하세요.

자세한 내용은 [Google Workspace 구성 예제](example_saml_config.md#google-workspace)를 참조하세요.

<i class="fa-youtube-play" aria-hidden="true"></i> [Google Workspace를 사용하여 SAML을 구성하고 그룹 동기화를 설정하는 방법](https://youtu.be/NKs0FSQVfCY)의 데모를 봅니다.

### Okta {#okta}

Okta를 자격증명 공급자로 SSO를 설정하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **SAML SSO**를 선택합니다.
1. 이 페이지의 정보를 기록하세요.
1. [Okta에서 SAML 애플리케이션 만들기](https://developer.okta.com/docs/guides/create-an-app-integration/saml2/main/) 지침을 따르세요.

   다음 GitLab 설정은 Okta 필드에 해당합니다.

   | GitLab 설정                           | Okta 필드                                                     |
   | ---------------------------------------- | -------------------------------------------------------------- |
   | **식별자**                           | **오디언스**                                               |
   | **어설션 컨슈머 서비스 (Assertion Consumer Service) URL**       | **통합 인증(SSO) URL**                                         |
   | **GitLab 통합 인증(SSO) URL**            | **로그인 페이지 URL** (**애플리케이션 로그인 페이지** 설정 아래) |
   | **자격증명 공급자 통합 인증(SSO)** | **자격증명 공급자 통합 인증(SSO) URL**                       |

1. Okta **통합 인증(SSO) URL** 필드 아래에서 **이를 수신자 URL 및 대상 URL로 사용** 확인란을 선택하세요.
1. 이 값들을 설정하세요:
   - **애플리케이션 사용자명(NameID)**의 경우: **커스텀** `user.getInternalProperty("id")`.
   - **이름 ID 형식**: `Persistent`. 자세한 내용은 [사용자 SAML ID 관리](#manage-user-saml-identity)를 참조하세요.
   - **이메일**의 경우: `user.email` 또는 유사한 것.
   - 추가 **특성 문**의 경우 [지원되는 특성](#configure-assertions)을 참조하세요.

1. 자격증명 공급자가 기존 GitLab 계정을 연결하도록 공급자에서 시작한 호출을 갖도록 설정되어 있는지 확인하세요.

앱 카탈로그에서 사용할 수 있는 Okta GitLab 애플리케이션은 [SCIM](scim_setup.md)만 지원합니다. SAML 지원은 [문제 216173](https://gitlab.com/gitlab-org/gitlab/-/issues/216173)에서 제안되었습니다.

<i class="fa-youtube-play" aria-hidden="true"></i> Okta SAML 설정(SCIM 포함)의 데모는 [데모: Okta 그룹 SAML 및 SCIM 설정](https://youtu.be/0ES9HsZq0AQ).

자세한 내용은 [Okta 구성 예제](example_saml_config.md#okta)를 참조하세요.

### OneLogin {#onelogin}

OneLogin은 자체 [GitLab.com 애플리케이션](https://onelogin.service-now.com/support?id=kb_article&sys_id=08e6b9d9879a6990c44486e5cebb3556&kb_category=50984e84db738300d5505eea4b961913)을 지원합니다.

OneLogin을 자격증명 공급자로 설정하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **SAML SSO**를 선택합니다.
1. 이 페이지의 정보를 기록하세요.
1. OneLogin 제네릭 [SAML 테스트 커넥터(고급)](https://onelogin.service-now.com/support?id=kb_article&sys_id=b2c19353dbde7b8024c780c74b9619fb&kb_category=93e869b0db185340d5505eea4b961934)를 사용하는 경우 [OneLogin SAML 테스트 커넥터 사용](https://onelogin.service-now.com/support?id=kb_article&sys_id=93f95543db109700d5505eea4b96198f)해야 합니다. 다음 GitLab 설정은 OneLogin 필드에 해당합니다:

   | GitLab 설정                                       | OneLogin 필드                   |
   | ---------------------------------------------------- | -------------------------------- |
   | **식별자**                                       | **오디언스**                     |
   | **어설션 컨슈머 서비스 (Assertion Consumer Service) URL**                   | **수신자**                    |
   | **어설션 컨슈머 서비스 (Assertion Consumer Service) URL**                   | **ACS(컨슈머) URL**           |
   | **어설션 컨슈머 서비스 URL(이스케이프된 버전)** | **ACS(컨슈머) URL 검증자** |
   | **GitLab 통합 인증(SSO) URL**                        | **로그인 URL**                    |
   | **자격증명 공급자 통합 인증(SSO)**             | **SAML 2.0 엔드포인트**            |

1. **NameID**의 경우 `OneLogin ID`를 사용하세요. 자세한 내용은 [사용자 SAML ID 관리](#manage-user-saml-identity)를 참조하세요.
1. [필수 및 지원되는 특성](#configure-assertions)을 구성하세요.
1. 자격증명 공급자가 기존 GitLab 계정을 연결하도록 공급자에서 시작한 호출을 갖도록 설정되어 있는지 확인하세요.

자세한 내용은 [OneLogin 구성 예제](example_saml_config.md#onelogin)를 참조하세요.

### Keycloak {#keycloak}

Keycloak을 자격증명 공급자로 설정하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **SAML SSO**를 선택합니다.
1. 이 페이지의 정보를 기록하세요.
1. [Keycloak에서 SAML 클라이언트 만들기](https://www.keycloak.org/docs/latest/server_admin/index.html#_client-saml-configuration) 지침을 따르세요.

다음 GitLab 설정은 Keycloak 필드에 해당합니다.

   | GitLab 설정                           | Keycloak 필드                          |
   |:-----------------------------------------|:------------------------------------------------|
   | **식별자**                           | **클라이언트 ID**                                   |
   | **어설션 컨슈머 서비스 (Assertion Consumer Service) URL**       | **유효한 리디렉션 URI**                         |
   | **어설션 컨슈머 서비스 (Assertion Consumer Service) URL**       | **어설션 컨슈머 서비스 POST 바인딩 URL** |
   | **GitLab 통합 인증(SSO) URL**            | **홈 URL**                                    |

1. Keycloak에서 GitLab 클라이언트를 구성합니다.
   1. Keycloak에서 **클라이언트**로 이동하여 GitLab 클라이언트 구성을 선택합니다.
   1. **설정** 탭의 **SAML 기능** 섹션에서:
      1. **이름 ID 형식**을 `persistent`로 설정합니다.
      1. **이름 ID 형식 강제**를 켭니다.
      1. **POST 바인딩 강제**를 켭니다.
      1. **AuthnStatement 포함**을 켭니다.
   1. **서명 및 암호화** 섹션에서 **문서 서명**을 켭니다.
   1. **키** 탭에서 모든 섹션이 비활성화되어 있는지 확인합니다.
   1. **클라이언트 범위** 탭에서:
      1. GitLab의 클라이언트 범위를 선택합니다. 범위의 이름은 `https://gitlab.com/groups/your-group-name-dedicated`처럼 보여야 합니다.
      1. **새 매퍼 구성**을 선택하고 열리는 창에서 **사용자 특성**을 선택합니다.
      1. **매퍼 추가** 페이지에서 **이름**, **사용자 특성** 및 **SAML 특성 이름** 필드를 `email`로 설정합니다.
      1. **저장**을 선택합니다.
1. Keycloak에서 클라이언트 정보를 검색합니다.
   1. **조치** 드롭다운 목록에서 **어댑터 구성 다운로드**를 선택합니다.
   1. **어댑터 구성 다운로드** 대화상자에서 드롭다운 목록에서 **mod-auth-mellon**을 선택합니다.
   1. **다운로드**를 선택합니다.
   1. 다운로드한 아카이브를 추출하고 `idp-metadata.xml`을 엽니다.
   1. 자격증명 공급자 통합 인증(SSO) URL을 검색합니다.
      1. `<md:SingleSignOnService>` 태그를 찾습니다.
      1. `Location` 특성의 값을 기록합니다.
   1. 인증서 핑거프린트를 검색합니다.
      1. `<ds:X509Certificate>` 태그의 값을 기록합니다.
      1. 값을 별도의 파일에 복사하고 값을 [PEM 형식](https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/#ftoc-heading-3)으로 변환합니다. 이렇게 하려면 파일의 시작 부분에 `-----BEGIN CERTIFICATE-----`를 추가하고 파일의 끝에 `-----END CERTIFICATE-----`을 새 줄로 추가합니다.
      1. [핑거프린트 계산](troubleshooting.md#calculate-the-fingerprint).

### AWS IAM Identity Center {#aws-iam-identity-center}

> [!note]
> AWS IAM Identity Center(이전 AWS Single Sign-On)는 GitLab에서 테스트한 자격증명 공급자가 아닙니다. GitLab은 고객 보고 구성을 기반으로 다음 정보를 제공합니다. AWS IAM Identity Center에서 SAML 통합 구성에 대해 질문이 있으면 [AWS 지원](https://aws.amazon.com/contact-us/)에 문의하세요.

AWS IAM Identity Center는 IdP에서 시작한 로그인을 기본값으로 설정합니다. 기존 GitLab 계정을 연결하려면 SP에서 시작한 로그인을 구성해야 합니다. 자세한 내용은 [SP에서 시작한 로그인](#sp-initiated-login)을 참조하세요.

AWS IAM Identity Center를 자격증명 공급자로 SSO를 설정하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. **설정** > **SAML SSO**를 선택하고 이 페이지의 값을 기록합니다.
1. AWS IAM Identity Center 콘솔에서 [맞춤 SAML 2.0 애플리케이션 설정](https://docs.aws.amazon.com/singlesignon/latest/userguide/customermanagedapps-set-up-your-own-app-saml2.html)을 수행합니다. 메타데이터 값을 입력하라는 메시지가 나타나면 다음을 입력합니다:

   | GitLab 설정                           | AWS IAM Identity Center 필드      |
   | ---------------------------------------- | ---------------------------------- |
   | **어설션 컨슈머 서비스 (Assertion Consumer Service) URL**       | **애플리케이션 ACS URL**            |
   | **식별자**                           | **애플리케이션 SAML 오디언스**      |

1. SP에서 시작한 로그인을 활성화하려면 **애플리케이션 시작 URL**을 GitLab **SAML SSO** 설정 페이지의 **GitLab 통합 인증(SSO) URL**로 설정합니다.

1. **특성 매핑** 아래에서 다음을 구성합니다:

   | 특성      | 값                | 형식        |
   | -------------- | -------------------- | ------------- |
   | **제목**    | `${user:email}`      | `unspecified` |
   | **이메일**      | `${user:email}`      | `unspecified` |
   | **이름** | `${user:givenName}`  | `unspecified` |
   | **성**  | `${user:familyName}` | `unspecified` |

   > [!warning]
   > **제목**(NameID) 형식을 `unspecified`로 설정해야 합니다. 형식을 `persistent` 또는 `transient`로 설정하면 기존 GitLab 사용자가 계정을 연결하려고 할 때 인증 오류가 발생합니다.

1. **IAM Identity Center SAML 메타데이터** 아래에서 **IAM Identity Center 로그인 URL**을 복사하고 인증서를 다운로드합니다.

1. 터미널에서 다운로드한 인증서에서 SHA1 핑거프린트를 생성합니다:

   ```shell
   openssl x509 -noout -fingerprint -sha1 -inform pem -in <path-to-downloaded-cert.pem>
   ```

1. GitLab의 그룹 **SAML SSO** 설정 페이지에서 다음 필드를 완료합니다:
   - **자격증명 공급자 통합 인증(SSO)**: **IAM Identity Center 로그인 URL**을 입력합니다.
   - **인증서 핑거프린트**: SHA1 핑거프린트 값을 입력합니다.

1. AWS IAM Identity Center에서 GitLab 애플리케이션에 사용자를 할당합니다. 기존 GitLab 계정을 연결하려면 사용자가 **GitLab 통합 인증(SSO) URL** 또는 **애플리케이션 시작 URL**에서 로그인해야 합니다.

자세한 내용은 [AWS IAM Identity Center 구성 예제](example_saml_config.md#aws-iam-identity-center)를 참조하세요.

#### SP에서 시작한 로그인 {#sp-initiated-login}

사용자가 자격증명 공급자 대시보드를 통해 로그인할 때(IdP에서 시작한 로그인) SAML 응답에 `InResponseTo` 특성이 포함되지 않습니다. GitLab은 SAML ID를 기존 계정에 연결하기 위해 이 특성이 필요합니다.

AWS IAM Identity Center는 IdP에서 시작한 로그인을 기본값으로 설정합니다. **애플리케이션 시작 URL**이 구성되지 않으면 기존 사용자는 로그인할 때 오류 `Request to link SAML account must be authorized`가 표시됩니다.

이를 피하려면 **애플리케이션 시작 URL**을 **GitLab 통합 인증(SSO) URL**로 설정합니다. 이렇게 하면 사용자가 GitLab에서 로그인 흐름을 시작하므로 `InResponseTo` 특성이 SAML 응답에 있습니다.

### 어설션 구성 {#configure-assertions}

> [!note]
> 이 특성들은 대소문자를 구분하지 않습니다.

최소한 다음 어설션을 구성해야 합니다:

1. [NameID](#manage-user-saml-identity).
1. 이메일.

선택적으로 SAML 어설션에 특성으로 GitLab에 사용자 정보를 전달할 수 있습니다.

- 사용자의 이메일 주소는 **이메일** 또는 **메일** 특성일 수 있습니다.
- 사용자명은 **사용자명** 또는 **별칭** 특성일 수 있습니다. 이 중 하나만 지정해야 합니다.

사용 가능한 특성에 대한 자세한 내용은 [GitLab Self-Managed용 SAML SSO](../../../integration/saml.md#configure-assertions)를 참조하세요.

### 메타데이터 사용 {#use-metadata}

일부 자격증명 공급자를 구성하려면 GitLab 메타데이터 URL이 필요합니다. 이 URL을 찾으려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **SAML SSO**를 선택합니다.
1. 제공된 **GitLab 메타데이터 URL**을 복사합니다.
1. 자격증명 공급자의 설명서를 따르고 요청된 메타데이터 URL을 붙여 넣습니다.

자격증명 공급자의 설명서를 확인하여 GitLab 메타데이터 URL을 지원하는지 확인합니다.

### 자격증명 공급자 관리 {#manage-the-identity-provider}

자격증명 공급자를 설정한 후 다음을 수행할 수 있습니다:

- 자격증명 공급자를 변경합니다.
- 이메일 도메인을 변경합니다.

#### 자격증명 공급자 변경 {#change-the-identity-provider}

다른 자격증명 공급자로 변경할 수 있습니다. 변경 프로세스 중에 사용자는 SAML 그룹에 액세스할 수 없습니다. 이를 완화하기 위해 [SSO 강제](#sso-enforcement)를 비활성화할 수 있습니다.

자격증명 공급자를 변경하려면:

1. 새 자격증명 공급자로 [그룹 구성](#set-up-your-identity-provider)을 수행합니다.
1. 선택 사항. **NameID**가 동일하지 않으면 [사용자에 대한 **NameID** 변경](#manage-user-saml-identity)을 수행합니다.

#### 이메일 도메인 변경 {#change-email-domains}

사용자를 새 이메일 도메인으로 마이그레이션하려면 사용자에게 다음을 수행하도록 지시합니다:

1. [새 이메일 추가](../../profile/_index.md#change-your-primary-email)를 계정의 기본 이메일로 추가하고 확인합니다.
1. 선택 사항. 계정에서 이전 이메일을 제거합니다.

**NameID**가 이메일 주소로 구성된 경우 [사용자에 대한 **NameID** 변경](#manage-user-saml-identity)을 수행합니다.

## GitLab 구성 {#configure-gitlab}

자격증명 공급자를 설정하여 GitLab과 함께 작동하도록 한 후 인증을 위해 GitLab을 사용하도록 구성해야 합니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **SAML SSO**를 선택합니다.
1. 필드를 완성합니다:
   - **자격증명 공급자 통합 인증(SSO)** 필드에 자격증명 공급자의 SSO URL을 입력합니다.
   - **인증서 핑거프린트** 필드에 SAML 토큰 서명 인증서의 핑거프린트를 입력합니다.
1. GitLab.com의 그룹의 경우: **멤버십 역할 기본값** 필드에서:
   1. 새 사용자에게 할당할 역할입니다.
   1. SAML 그룹 링크가 그룹에 대해 구성된 경우 [매핑된 SAML 그룹의 구성원이 아닌 사용자](group_sync.md#automatic-member-removal)에게 할당할 역할입니다.
1. GitLab Self-Managed 인스턴스의 그룹의 경우: **멤버십 역할 기본값** 필드에서 새 사용자에게 할당할 역할을 선택합니다. 기본 역할은 **게스트**입니다. 이 역할은 그룹에 추가된 모든 사용자의 시작 역할이 됩니다. 그룹 소유자는 [사용자 지정 역할](../../custom_roles/_index.md)을 기본 멤버십 역할로 설정할 수 있습니다.
1. **이 그룹에 SAML 인증 활성화** 확인란을 선택합니다.
1. 권장하는 방식입니다. 다음 중 하나를 선택합니다.
   - GitLab 17.4 이상에서 **엔터프라이즈 사용자에 대한 암호 및 패스키 인증 비활성화**합니다. 자세한 내용은 [엔터프라이즈 사용자에 대한 암호 및 패스키 인증 비활성화 설명서](#disable-password-and-passkey-authentication-for-enterprise-users)를 참조하세요.
   - **이 그룹에 대한 웹 활동에 SSO 전용 인증 강제 적용**.
   - **이 그룹에 대한 Git 및 의존성 프록시 활동에 SSO 전용 인증 강제 적용**. 자세한 내용은 [SSO 강제 설명서](#sso-enforcement)를 참조하세요.
1. **변경 사항 저장**을 선택합니다.

GitLab 구성에 문제가 있으면 [문제 해결 설명서](#troubleshooting)를 참조하세요.

## 사용자 액세스 및 관리 {#user-access-and-management}

그룹 SSO가 구성되고 활성화되면 사용자는 자격증명 공급자의 대시보드를 통해 GitLab.com 그룹에 액세스할 수 있습니다. [SCIM](scim_setup.md)이 구성된 경우 SCIM 페이지의 [사용자 액세스](scim_setup.md#user-access)를 참조하세요.

사용자가 그룹 SSO로 로그인하려고 할 때 GitLab은 다음을 기반으로 사용자를 찾거나 만들려고 시도합니다:

- 일치하는 SAML ID를 가진 기존 사용자를 찾습니다. 이는 사용자가 [SCIM](scim_setup.md)에 의해 계정을 만들었거나 그룹의 SAML IdP로 이전에 로그인했음을 의미합니다.
- 동일한 이메일 주소의 계정이 아직 없으면 자동으로 새 계정을 만듭니다. GitLab은 기본 이메일 주소와 보조 이메일 주소를 모두 일치시킵니다.
- 동일한 이메일 주소의 계정이 이미 존재하면 사용자를 로그인 페이지로 리디렉션합니다:
  - 다른 이메일 주소로 새 계정을 만듭니다.
  - 기존 계정에 로그인하여 SAML ID를 연결합니다.

### 제한된 액세스를 통한 프로비저닝 동작 {#provisioning-behavior-with-restricted-access}

{{< history >}}

- GitLab 18.6에서 `bso_minimal_access_fallback`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/206932)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.10에서 [기본으로 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225777).

{{< /history >}}

[제한된 액세스](../../../subscriptions/manage_seats.md#restricted-access)가 사용 가능한 사용자가 없는 상태에서 활성화되면 SAML을 통해 프로비저닝된 사용자에게 최소 액세스 역할이 할당됩니다.

자세한 내용은 [SAML, SCIM 및 LDAP를 사용한 프로비저닝 동작](../../../subscriptions/manage_seats.md#provisioning-behavior-with-saml-scim-and-ldap)을 참조하세요.

### 기존 GitLab.com 계정에 SAML 연결 {#link-saml-to-your-existing-gitlabcom-account}

> [!note]
> 사용자가 해당 그룹의 [엔터프라이즈 사용자](../../enterprise_user/_index.md)인 경우 다음 단계는 적용되지 않습니다. 대신 엔터프라이즈 사용자는 [GitLab 계정과 동일한 이메일을 가진 SAML 계정으로 로그인](#automatic-identity-linking-for-enterprise-users)해야 합니다. 이렇게 하면 GitLab이 SAML 계정을 기존 계정에 연결할 수 있습니다.

기존 GitLab.com 계정에 SAML을 연결하려면:

1. GitLab.com 계정에 로그인합니다. 필요한 경우 [비밀번호 재설정](https://gitlab.com/users/password/new)을 수행합니다.
1. 로그인하려는 그룹의 **GitLab 통합 인증(SSO) URL**을 찾아 방문합니다. 그룹 소유자는 그룹의 **설정** > **SAML SSO** 페이지에서 이를 찾을 수 있습니다. 로그인 URL이 구성되면 사용자는 자격증명 공급자에서 GitLab 앱에 연결할 수 있습니다.
1. 선택 사항. **계정 정보 저장** 확인란을 선택하여 2주 동안 GitLab에 로그인 상태를 유지합니다. SAML 공급자로 더 자주 다시 인증하도록 요청받을 수 있습니다.
1. **권한 부여**를 선택합니다.
1. 필요한 경우 자격증명 공급자에서 자격증명을 입력합니다.
1. 그러면 GitLab.com으로 리디렉션되며 이제 그룹에 액세스할 수 있어야 합니다. 향후에는 SAML을 사용하여 GitLab.com에 로그인할 수 있습니다.

사용자가 이미 그룹의 구성원인 경우 SAML ID를 연결해도 역할이 변경되지 않습니다.

이후 방문 시 [SAML을 사용하여 GitLab.com에 로그인](#sign-in-to-gitlabcom-with-saml)하거나 직접 링크를 방문할 수 있어야 합니다. **SSO 강제** 옵션이 켜져 있으면 자격증명 공급자를 통해 로그인하도록 리디렉션됩니다.

#### 엔터프라이즈 사용자를 위한 자동 ID 연결 {#automatic-identity-linking-for-enterprise-users}

엔터프라이즈 사용자가 그룹에서 제거된 후 돌아오면 엔터프라이즈 SSO 계정으로 로그인할 수 있습니다. 자격증명 공급자의 사용자 이메일 주소가 기존 GitLab 계정의 이메일 주소와 동일하게 유지되면 SSO ID는 자동으로 계정에 연결되고 사용자는 문제 없이 로그인할 수 있습니다. 이 기능은 엔터프라이즈 사용자로 청구되었지만 아직 그룹에 로그인하지 않았을 수 있는 기존 사용자에게도 적용됩니다.

### SAML을 사용하여 GitLab.com에 로그인 {#sign-in-to-gitlabcom-with-saml}

1. 자격증명 공급자에 로그인합니다.
1. 앱 목록에서 "GitLab.com" 앱을 선택합니다. (이름은 자격증명 공급자의 관리자가 설정합니다.)
1. 그러면 GitLab.com에 로그인되고 그룹으로 리디렉션됩니다.

### 사용자 SAML ID 관리 {#manage-user-saml-identity}

GitLab.com은 SAML **NameID**를 사용하여 사용자를 식별합니다. **NameID**는:

- SAML 응답의 필수 필드입니다.
- 대소문자를 구분하지 않습니다.

**NameID**는:

- 각 사용자마다 고유해야 합니다.
- 임의로 생성된 고유한 사용자 ID와 같이 절대 변경되지 않는 영구적인 값이어야 합니다.
- 이후 로그인 시도 시 정확히 일치해야 하므로 대문자와 소문자 사이에서 변경될 수 있는 사용자 입력에 의존하면 안 됩니다.

**NameID**는 이메일 주소나 사용자명이 아니어야 합니다:

- 이메일 주소와 사용자명은 시간이 지남에 따라 변경될 가능성이 높습니다. 예를 들어 사람의 이름이 변경될 때입니다.
- 이메일 주소는 대소문자를 구분하지 않으므로 사용자가 로그인할 수 없을 수 있습니다.

**NameID** 형식은 `Persistent`이어야 합니다. 단, 다른 형식이 필요한 이메일과 같은 필드를 사용하는 경우는 예외입니다. `Transient`을 제외한 모든 형식을 사용할 수 있습니다.

#### 사용자 **NameID** 변경 {#change-user-nameid}

그룹 소유자는 [SAML API](../../../api/saml.md#update-extern_uid-field-for-a-saml-identity)를 사용하여 그룹 구성원의 **NameID**를 변경하고 SAML ID를 업데이트할 수 있습니다.

> [!warning]
> API를 통해 `extern_uid`를 업데이트하면 SAML ID가 신뢰할 수 없음으로 표시됩니다. 영향을 받은 사용자는 [새 SAML 앱에 계정 다시 연결](#link-saml-to-your-existing-gitlabcom-account)할 때까지 SAML로 로그인할 수 없습니다.

[SCIM](scim_setup.md)이 구성된 경우 그룹 소유자는 [SCIM API](../../../api/scim.md#update-extern_uid-field-for-a-scim-identity)를 사용하여 SCIM ID를 업데이트할 수 있습니다.

또는 사용자에게 SAML 계정을 다시 연결하도록 요청하세요.

1. 관련 사용자에게 [그룹에서 계정 연결 해제](#unlink-accounts)를 요청합니다.
1. 관련 사용자에게 [새 SAML 앱에 계정 연결](#link-saml-to-your-existing-gitlabcom-account)을 요청합니다.

> [!warning]
> 사용자가 SSO SAML을 사용하여 GitLab에 로그인한 후 **NameID** 값을 변경하면 구성이 중단되고 사용자가 GitLab 그룹에서 잠길 수 있습니다.

특정 자격증명 공급자에 대한 권장 값 및 형식에 대한 자세한 내용은 [자격증명 공급자 설정](#set-up-your-identity-provider)을 참조하세요.

### SAML 응답에서 엔터프라이즈 사용자 설정 구성 {#configure-enterprise-user-settings-from-saml-response}

GitLab은 SAML 응답의 값을 기반으로 특정 사용자 특성을 설정할 수 있습니다. 기존 사용자의 특성은 해당 사용자가 그룹의 [엔터프라이즈 사용자](../../enterprise_user/_index.md)인 경우 SAML 응답 값에서 업데이트됩니다.

#### 지원되는 사용자 특성 {#supported-user-attributes}

- `can_create_group` - `true` 또는 `false`를 사용하여 엔터프라이즈 사용자가 새로운 최상위 그룹을 만들 수 있는지 나타냅니다. 기본값은 `true`입니다.
- `projects_limit` - 엔터프라이즈 사용자가 만들 수 있는 개인 프로젝트의 총 개수입니다. `0`의 값은 사용자가 개인 네임스페이스에서 새 프로젝트를 만들 수 없음을 의미합니다. 기본값은 `100000`입니다.
- `SessionNotOnOrAfter` - 사용자 SAML 세션을 종료할 시점을 나타내는 ISO 8601 타임스탬프 값입니다.

#### SAML 응답 예제 {#example-saml-response}

SAML 응답은 브라우저의 개발자 도구 또는 콘솔에서 base64로 인코딩된 형식으로 찾을 수 있습니다. 선택한 base64 디코딩 도구를 사용하여 정보를 XML로 변환합니다. SAML 응답의 예가 여기에 표시됩니다.

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

### SAML 세션 타임아웃 사용자 지정 {#customize-saml-session-timeout}

{{< history >}}

- `saml_timeout_supplied_by_idp_override`라는 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)로 GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/262074)되었습니다.

{{< /history >}}

기본적으로 GitLab은 24시간 후에 SAML 세션을 종료합니다. SAML2 AuthnStatement의 `SessionNotOnOrAfter` 특성으로 이 기간을 사용자 지정할 수 있습니다. 이 특성에는 사용자 세션을 종료할 시점을 나타내는 ISO 8601 타임스탬프 값이 포함됩니다. 지정된 경우 이 값은 기본 SAML 세션 타임아웃인 24시간을 재정의합니다.

기본적으로 GitLab은 7일(10080분)의 비활성 후 세션을 종료합니다. `SessionNotOnOrAfter` 타임스탬프가 이 시간 이후인 경우 사용자는 세션이 종료될 때 다시 인증해야 합니다.

#### 응답 예제 {#example-response}

```xml
   <saml:AuthnStatement SessionIndex="WDE5aBYjNEj_9IjCFiK0E1YelZT" SessionNotOnOrAfter="2025-08-25T01:23:45.067Z" AuthnInstant="2025-08-24T13:23:45.067Z">
      <saml:AuthnContext>
         <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>
      </saml:AuthnContext>
   </saml:AuthnStatement>
```

### 확인된 도메인을 사용하여 사용자 이메일 확인 우회 {#bypass-user-email-confirmation-with-verified-domains}

기본적으로 SAML 또는 SCIM으로 프로비저닝된 사용자는 ID를 확인하기 위해 확인 이메일을 받습니다. 대신 [GitLab을 맞춤 도메인으로 구성](../../enterprise_user/_index.md#add-group-domains)할 수 있으며 GitLab은 자동으로 사용자 계정을 확인합니다. 사용자는 여전히 [엔터프라이즈 사용자](../../enterprise_user/_index.md) 환영 이메일을 받습니다. 다음 두 가지가 모두 참인 경우 확인이 우회됩니다:

- 사용자는 SAML 또는 SCIM으로 프로비저닝됩니다.
- 사용자의 이메일 주소가 확인된 도메인에 속합니다.

> [!note]
> 확인된 도메인 외부의 이메일 주소를 가진 프로비저닝된 사용자는 확인되지 않은 상태로 유지됩니다. [확인되지 않은 사용자의 자동 삭제](../../../administration/moderate_users.md#automatically-delete-unconfirmed-users)가 활성화되면 GitLab이 이러한 사용자를 삭제할 수 있습니다.

### 엔터프라이즈 사용자에 대한 암호 및 패스키 인증 비활성화 {#disable-password-and-passkey-authentication-for-enterprise-users}

{{< history >}}

- GitLab 17.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/373718)되었습니다.

{{< /history >}}

사전 요구 사항:

- 엔터프라이즈 사용자가 속한 그룹의 소유자 역할이 있어야 합니다.
- 그룹 SSO를 활성화해야 합니다.

그룹의 모든 [엔터프라이즈 사용자](../../enterprise_user/_index.md)에 대해 암호 인증을 비활성화할 수 있습니다. 이는 그룹의 관리자인 엔터프라이즈 사용자에게도 적용됩니다. 이 설정을 구성하면 엔터프라이즈 사용자가 암호를 변경, 재설정 또는 인증할 수 없습니다. 대신 이러한 사용자는 다음을 통해 인증할 수 있습니다:

- GitLab 웹 UI용 그룹 SAML IdP.
- 그룹이 [엔터프라이즈 사용자에 대한 개인 액세스 토큰 비활성화](../../profile/personal_access_tokens.md#disable-personal-access-tokens-for-enterprise-users)하지 않은 경우 GitLab API 및 HTTP 기본 인증을 사용한 Git용 개인 액세스 토큰.

엔터프라이즈 사용자에 대한 암호 및 패스키 인증을 비활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **SAML SSO**를 선택합니다.
1. **구성** 아래에서 **엔터프라이즈 사용자에 대한 암호 및 패스키 인증 비활성화**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 사용자 액세스 차단 {#block-user-access}

SAML SSO만 구성된 경우 사용자의 그룹 액세스를 취소하려면:

- (순서대로) 사용자를 제거합니다:
  1. 자격증명 공급자의 사용자 데이터 저장소 또는 특정 앱의 사용자 목록입니다.
  1. GitLab.com 그룹.
- [그룹 동기화](group_sync.md#automatic-member-removal)를 그룹의 최상위 레벨에서 기본 역할이 [최소 액세스](../../permissions.md#users-with-minimal-access)로 설정된 상태로 사용하여 그룹의 모든 리소스에 대한 액세스를 자동으로 차단합니다.

SCIM도 사용하는 경우 사용자 액세스를 취소하려면 [액세스 제거](scim_setup.md#remove-access)를 참조합니다.

### 계정 연결 해제 {#unlink-accounts}

사용자는 프로필 페이지에서 그룹의 SAML 연결을 해제할 수 있습니다. 이는 다음과 같은 경우에 도움이 될 수 있습니다:

- 그룹이 더 이상 GitLab.com에 로그인할 수 있기를 원하지 않습니다.
- SAML **NameID**가 변경되었으므로 GitLab이 더 이상 사용자를 찾을 수 없습니다.

> [!warning]
> 계정 연결을 해제하면 그룹의 해당 사용자에게 할당된 모든 역할이 제거됩니다. 사용자가 계정을 다시 연결하면 역할을 다시 할당해야 합니다.

그룹에는 최소 한 명의 소유자가 필요합니다. 계정이 그룹의 유일한 소유자인 경우 계정 연결을 해제할 수 없습니다. 그 경우 다른 사용자를 그룹 소유자로 설정한 후 계정을 연결 해제할 수 있습니다.

예를 들어 `MyOrg` 계정 연결을 해제하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **비밀번호와 인증**을 선택합니다.
1. **서비스 로그인** 섹션에서 연결된 계정 옆의 **연결해제**를 선택합니다.

## SSO 강제 {#sso-enforcement}

GitLab.com에서 SSO는 다음과 같이 강제됩니다:

- SAML SSO가 활성화되면.
- 조직의 그룹 계층 구조에서 그룹 및 프로젝트에 액세스할 때 기존 SAML ID를 가진 사용자에게. GitLab.com 자격증명을 사용하면 사용자는 SAML SSO를 통해 로그인하지 않고 조직 외부의 다른 그룹 및 프로젝트는 물론 사용자 설정도 볼 수 있습니다.

사용자는 다음 중 하나 이상이 참인 경우 SAML ID를 갖습니다:

- GitLab 그룹의 통합 인증(SSO) URL을 사용하여 GitLab에 로그인했습니다.
- SCIM으로 프로비저닝되었습니다.

사용자는 각 방문 시 SSO를 통해 로그인하도록 요청받지 않습니다. GitLab은 사용자가 SSO를 통해 인증했는지 확인합니다. 사용자가 24시간 이상 전에 마지막으로 로그인한 경우 GitLab은 사용자에게 SSO를 통해 다시 로그인하도록 요청합니다.

SSO는 다음과 같이 강제됩니다:

| 프로젝트/그룹 가시성 | SSO 설정 강제 | ID를 가진 구성원 | ID 없는 구성원 | 비구성원 또는 로그인하지 않은 상태 |
|--------------------------|---------------------|----------------------|-------------------------|-----------------------------|
| 비공개                  | 해제                 | 강제됨             | 강제되지 않음            | 강제되지 않음                |
| 비공개                  | 활성                  | 강제됨             | 강제됨                | 강제됨                    |
| 공개                   | 해제                 | 강제됨             | 강제되지 않음            | 강제되지 않음                |
| 공개                   | 활성                  | 강제됨             | 강제됨                | 강제되지 않음                |

> [!note]
> SSO 강제는 API 요청에 적용되지 않습니다. 그러나 [엔터프라이즈 사용자에 대한 암호 및 패스키 인증 비활성화](#disable-password-and-passkey-authentication-for-enterprise-users)를 통해 암호 기반 API 액세스를 방지할 수 있습니다.
>
> [이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/297389)는 API 활동에 대한 SSO 강제를 추가할 것을 제안합니다.

### 웹 활동에 대한 SSO 전용 강제 {#sso-only-for-web-activity-enforcement}

**이 그룹에 대한 웹 활동에 SSO 전용 인증 강제 적용** 옵션이 활성화되면:

- 모든 구성원은 기존 SAML ID가 있는지 여부와 관계없이 그룹 리소스에 액세스하기 위해 GitLab 그룹의 통합 인증(SSO) URL을 사용하여 GitLab에 액세스해야 합니다.
- SSO는 조직의 그룹 계층 구조에서 그룹 및 프로젝트에 액세스할 때 강제됩니다. 사용자는 SAML SSO를 통해 로그인하지 않고 조직 외부의 다른 그룹 및 프로젝트를 볼 수 있습니다.
- 사용자는 수동으로 새 구성원으로 추가할 수 없습니다.
- 소유자 역할을 가진 사용자는 표준 로그인 프로세스를 사용하여 최상위 그룹 설정을 필요에 따라 변경할 수 있습니다.
- 비구성원 또는 로그인하지 않은 사용자의 경우:
  - 공개 그룹 리소스에 액세스할 때 SSO는 강제되지 않습니다.
  - 비공개 그룹 리소스에 액세스할 때 SSO는 강제됩니다.
- 조직의 그룹 계층 구조의 항목의 경우 대시보드 가시성은 다음과 같습니다:
  - SSO는 [할 일 목록](../../todos.md)을 볼 때 강제됩니다. SSO 세션이 만료되면 할 일 항목이 숨겨지고 [경고가 표시](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/115254)됩니다.
  - SSO는 할당된 이슈 목록을 볼 때 강제됩니다. SSO 세션이 만료되면 이슈가 숨겨집니다. [이슈 414475](https://gitlab.com/gitlab-org/gitlab/-/issues/414475)는 이슈가 보이도록 이 동작을 변경할 것을 제안합니다.
  - 피할당자 또는 검토자인 병합 요청을 볼 때는 SSO가 강제되지 않습니다. SSO 세션이 만료된 경우에도 병합 요청을 볼 수 있습니다.
  - 게스트, 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할을 가진 비공개 프로젝트의 코드 조각을 볼 때는 SSO가 강제되지 않습니다.

웹 활동에 대한 SSO 강제는 활성화될 때 다음과 같은 효과가 있습니다:

- 그룹의 경우 사용자는 프로젝트가 포크된 경우에도 최상위 그룹 외부의 그룹에서 프로젝트를 공유할 수 없습니다.
- CI/CD 작업에서 발생하는 Git 활동은 SSO 확인이 강제되지 않습니다.
- 일반 사용자와 연결되지 않은 자격증명(예: 프로젝트 및 그룹 액세스 토큰, 서비스 계정 및 배포 키)은 SSO 확인이 강제되지 않습니다.
- 사용자는 [종속성 프록시](../../packages/dependency_proxy/_index.md)를 사용하여 이미지를 가져오기 전에 SSO를 통해 로그인해야 합니다.
- **이 그룹에 대한 Git 및 의존성 프록시 활동에 SSO 전용 인증 강제 적용** 옵션이 활성화되면 Git 활동과 관련된 모든 API 엔드포인트는 SSO 강제 대상이 됩니다. 예를 들어 분기, 커밋 또는 태그를 생성하거나 삭제하는 것입니다. SSH 및 HTTPS를 통한 Git 활동의 경우 사용자는 GitLab 리포지토리에서 푸시하거나 풀할 수 있기 전에 SSO를 통해 로그인한 활성 세션이 최소 하나 있어야 합니다. 활성 세션은 다른 기기에 있을 수 있습니다.

웹 활동에 대한 SSO가 강제되면 비-SSO 그룹 구성원은 즉시 액세스를 잃지 않습니다. 사용자:

- 활성 세션을 가진 경우 자격증명 공급자 세션이 시간 초과될 때까지 최대 24시간 동안 그룹에 계속 액세스할 수 있습니다.
- 로그인한 경우 자격증명 공급자에서 제거된 후 그룹에 액세스할 수 없습니다.

### SSO 강제를 통한 리포지토리 미러링 {#repository-mirroring-with-sso-enforcement}

**이 그룹에 대한 Git 및 의존성 프록시 활동에 SSO 전용 인증 강제 적용**을 활성화하면 리포지토리 미러링은 SSO 세션 요구 사항의 대상이 됩니다. 자세한 내용은 [SSO 강제를 통한 미러링 가져오기](../../project/repository/mirror/pull.md#pull-mirroring-with-sso-enforcement)를 참조하세요.

## 새 자격증명 공급자로 마이그레이션 {#migrate-to-a-new-identity-provider}

새 자격증명 공급자로 마이그레이션하려면 [SAML API](../../../api/saml.md)를 사용하여 모든 그룹 구성원의 ID를 업데이트합니다.

예를 들어:

1. 유지보수 창을 설정하여 활성 사용자가 없는 시간을 확인합니다.
1. SAML API를 사용하여 [각 사용자의 ID를 업데이트](../../../api/saml.md#update-extern_uid-field-for-a-saml-identity)합니다.
1. 새 자격증명 공급자를 구성합니다.
1. 로그인이 작동하는지 테스트합니다.

> [!NOTE]
> 비엔터프라이즈 사용자는 ID가 업데이트된 후 SAML 비밀번호를 재설정하고 [SAML을 계정에 다시 연결](#link-saml-to-your-existing-gitlabcom-account)해야 합니다.

## 관련 항목 {#related-topics}

- [GitLab Self-Managed용 SAML SSO](../../../integration/saml.md)
- [용어집](../../../auth/auth_glossary.md)
- [블로그 게시물: GitLab.com에서 SAML 및 SSO를 활성화하기 위한 최종 가이드](https://about.gitlab.com/blog/the-ultimate-guide-to-enabling-saml/)
- [GitLab.com 및 GitLab Self-Managed 간 인증 비교](../../../administration/auth/_index.md#gitlabcom-compared-to-gitlab-self-managed)
- [통합 인증을 통해 만들어진 사용자의 비밀번호](../../profile/user_passwords.md)
- [SAML 그룹 동기화](group_sync.md)

## 문제 해결 {#troubleshooting}

GitLab과 자격증명 공급자 간의 다양한 SAML 용어를 일치시키기 어려운 경우:

1. 자격증명 공급자의 설명서를 확인합니다. 사용하는 용어에 대한 정보는 SAML 구성 예제를 확인합니다.
1. [GitLab Self-Managed 설명서용 SAML SSO](../../../integration/saml.md)를 확인합니다. GitLab Self-Managed SAML 구성 파일은 GitLab.com 파일보다 더 많은 옵션을 지원합니다. GitLab Self-Managed 인스턴스 파일에 대한 정보는 다음에서 찾을 수 있습니다:
   - 외부 [OmniAuth SAML 설명서](https://github.com/omniauth/omniauth-saml/).
   - [`ruby-saml` 라이브러리](https://github.com/SAML-Toolkits/ruby-saml).
1. 공급자의 XML 응답과 [내부 테스트용 XML 예제](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/spec/fixtures/saml/response.xml)를 비교합니다.

기타 문제 해결 정보는 [SAML 문제 해결 가이드](troubleshooting.md)를 참조하세요.
