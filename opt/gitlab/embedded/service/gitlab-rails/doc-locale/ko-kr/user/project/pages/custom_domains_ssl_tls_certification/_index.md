---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Pages 사용자 정의 도메인
description: GitLab Pages 사이트를 위해 사용자 정의 도메인 및 SSL/TLS 인증서를 설정합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

사용자 정의 도메인을 사용할 수 있습니다:

- GitLab Pages와 함께 사용합니다.
- [SAML 또는 SCIM으로 프로비저닝된 사용자를 위한 사용자 이메일 확인 건너뛰기](../../../group/saml_sso/_index.md#bypass-user-email-confirmation-with-verified-domains). 이 방식으로 사용자 정의 도메인을 사용할 때 GitLab Pages 기능을 사용하지만 [필수 조건](#prerequisites)을 건너뛸 수 있습니다.

하나 이상의 사용자 정의 도메인 이름을 사용하려면:

- [사용자 정의 루트 도메인 또는 서브도메인](#set-up-a-custom-domain)을 추가합니다.
- [SSL/TLS 인증](#add-an-ssltls-certificate-to-pages)을 추가합니다.

> [!warning]
> [가장 인기 있는 공개 이메일 도메인](../../../group/access_and_permissions.md#restrict-group-access-by-domain)은 확인할 수 없습니다.

## 사용자 정의 도메인 설정 {#set-up-a-custom-domain}

사용자 정의 도메인을 사용하여 Pages를 설정하려면 다음 단계를 완료합니다.

### 사전 요구 사항 {#prerequisites}

- 관리자가 [GitLab Pages 사용자 정의 도메인](../../../../administration/pages/_index.md#configure-custom-domains)에 대해 서버를 구성했습니다.
- GitLab Pages 웹사이트가 실행 중이며 기본 Pages 도메인 (`*.gitlab.io`, GitLab.com의 경우)에서 제공됩니다.
- 사용자 정의 도메인 이름 `example.com` 또는 서브도메인 `subdomain.example.com`.
- DNS 레코드를 설정하기 위한 도메인 서버 제어판에 대한 액세스:
  - 도메인을 GitLab Pages 서버로 가리키는 DNS 레코드 (`A`, `AAAA`, `ALIAS` 또는 `CNAME`). 해당 이름에 여러 DNS 레코드가 있는 경우 `ALIAS` 레코드를 사용해야 합니다.
  - 도메인의 소유권을 확인하기 위한 DNS `TXT` 레코드.

DNS 레코드의 개요는 [GitLab Pages DNS 레코드](dns_concepts.md)를 참조하세요.

### 1단계:  사용자 정의 도메인 추가 {#step-1-add-a-custom-domain}

사용자 정의 도메인을 GitLab Pages에 추가하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. 오른쪽 위 모서리에서 **새 도메인**을 선택합니다.
1. **도메인**에서 도메인 이름을 입력합니다.
1. 선택 사항. **인증서**에서 **Let's Encrypt를 사용하여 인증서를 자동으로 관리** 토글을 끄고 [SSL/TLS 인증서](#add-an-ssltls-certificate-to-pages)를 추가합니다. 나중에 인증서 및 키를 추가할 수도 있습니다.
1. **새 도메인 만들기**를 선택합니다.

### 2단계:  검증 코드 가져오기 {#step-2-get-the-verification-code}

Pages에 새 도메인을 추가한 후 GitLab은 검증 코드를 표시합니다. 값을 복사하여 도메인의 제어판에 다음 단계에서 `TXT` 레코드로 붙여넣습니다.

![새 도메인에 대해 생성된 검증 코드를 보여주는 GitLab Pages입니다.](img/get_domain_verification_code_v18_8.png)

검증 코드는 다음과 같은 구조를 가지고 있습니다:

- 이름/호스트:
  - 루트 도메인의 경우: `_gitlab-pages-verification-code.example.com`
  - 서브도메인의 경우: `_gitlab-pages-verification-code.subdomain.example.com`
- DNS 레코드 유형: `TXT`
- 값: `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` (GitLab에서 실제 코드 사용)

> [!note]
> Cloudflare와 같은 일부 DNS 공급자는 자동으로 도메인 이름을 이름 또는 호스트 필드에 추가합니다. 공급자가 이렇게 하면 루트 도메인의 경우 `_gitlab-pages-verification-code` 또는 서브도메인의 경우 `_gitlab-pages-verification-code.subdomain`만 입력합니다.

### 3단계:  DNS 레코드 설정 {#step-3-set-up-dns-records}

Pages 사이트에서 사용하려는 도메인 유형에 따라 DNS 레코드를 설정하려면 다음 중 하나를 선택합니다:

- [루트 도메인](#root-domains)
- [서브도메인](#subdomains)
- [루트 도메인과 서브도메인 모두](#both-root-and-subdomains)

#### 루트 도메인 {#root-domains}

루트 도메인 (`example.com`)에는 다음이 필요합니다:

- 최소 하나:
  - 도메인을 Pages 서버로 가리키는 [DNS `A` 레코드](dns_concepts.md#a-record).
  - 도메인을 Pages 서버로 가리키는 [DNS `AAAA` 레코드](dns_concepts.md#aaaa-record).
- 도메인의 소유권을 확인하기 위한 [`TXT` 레코드](dns_concepts.md#txt-record).

| 원본                                          | DNS 레코드 | 대상              |
| --------------------------------------------- | ---------- | --------------- |
| `example.com`                                 | `A`        | `35.185.44.232` |
| `example.com`                                 | `AAAA`     | `2600:1901:0:7b8a::` |
| `_gitlab-pages-verification-code.example.com` | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |

GitLab.com의 프로젝트의 경우 IPv4 주소는 `35.185.44.232`이고 IPv6 주소는 `2600:1901:0:7b8a::`입니다.

다른 GitLab 인스턴스(CE 또는 EE)의 프로젝트의 경우 시스템 관리자에게 문의하고 인스턴스의 Pages 서버 IP 주소를 요청합니다.

![GitLab Pages 서버에 추가된 A 레코드를 보여주는 DNS 구성 화면입니다.](img/dns_add_new_a_record_v11_2.png)

> [!warning]
> 루트 도메인에 대해 `A` 또는 `AAAA` 레코드 대신 `CNAME` 레코드를 사용하면 안 됩니다. 루트 도메인에 대해 [`MX` 레코드](dns_concepts.md#mx-record)를 설정하면 이 방법이 작동하지 않을 가능성이 높습니다.

#### 서브도메인 {#subdomains}

서브도메인 (`subdomain.example.com`)에는 다음이 필요합니다:

- 서브도메인을 Pages 서버로 가리키는 DNS [`ALIAS` 또는 `CNAME` 레코드](dns_concepts.md#cname-record).
- 도메인의 소유권을 확인하기 위한 DNS [`TXT` 레코드](dns_concepts.md#txt-record).

| 원본                                                    | DNS 레코드      | 대상 |
|---------------------------------------------------------|-----------------|----|
| `subdomain.example.com`                                 | `ALIAS`/`CNAME` | `namespace.gitlab.io` |
| `_gitlab-pages-verification-code.subdomain.example.com` | `TXT`           | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |

사용자 또는 프로젝트 웹사이트인지 여부에 관계없이 DNS 레코드는 Pages 도메인 (`namespace.gitlab.io`)을 가리켜야 하며 경로가 없어야 합니다.

#### 루트 도메인과 서브도메인 모두 {#both-root-and-subdomains}

루트 도메인과 서브도메인을 같은 웹사이트로 가리키려면(예: `example.com` 및 `www.example.com`) 다음이 필요합니다:

- 도메인의 DNS `A` 레코드.
- 도메인의 DNS `AAAA` 레코드.
- 서브도메인의 DNS `ALIAS`/`CNAME` 레코드.
- 각 DNS `TXT` 레코드.

| 원본                                              | DNS 레코드 | 대상 |
|---------------------------------------------------|------------|----|
| `example.com`                                     | `A`        | `35.185.44.232` |
| `example.com`                                     | `AAAA`     | `2600:1901:0:7b8a::` |
| `_gitlab-pages-verification-code.example.com`     | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |
| `www.example.com`                                 | `CNAME`    | `namespace.gitlab.io` |
| `_gitlab-pages-verification-code.www.example.com` | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |

Cloudflare를 사용 중인 경우 [`www.domain.com`을(를) `domain.com`으로 리디렉션(Cloudflare 사용)](#redirect-wwwdomaincom-to-domaincom-with-cloudflare)을 참조하세요.

추가:

- GitLab Pages 사이트로 `domain.com`을(를) 가리키려면 `CNAME` 레코드를 사용하면 안 됩니다. 대신 `A` 레코드를 사용합니다.
- 기본 Pages 도메인 뒤에 특수 문자를 추가하면 안 됩니다. 예를 들어 `subdomain.domain.com`을(를) 가리키거나 `namespace.gitlab.io/`로 이동하면 안 됩니다. 일부 도메인 호스팅 공급자는 후행 점 (`namespace.gitlab.io.`)을 요청할 수 있습니다.
- [변경됨](https://about.gitlab.com/blog/gcp-move-update/#gitlab-pages-and-custom-domains) 2018년에 GitLab.com의 GitLab Pages IP가 `52.167.214.135`에서 `35.185.44.232`으로 변경됨.
- [추가됨](https://gitlab.com/gitlab-org/gitlab/-/issues/214718) 2023년 GitLab.com에 IPv6 지원이 추가됨.

### 4단계:  도메인의 소유권 확인 {#step-4-verify-the-domains-ownership}

모든 DNS 레코드를 추가한 후:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. 도메인 이름 옆에서 **편집** ({{< icon name="pencil" >}})을 선택합니다.
1. **검증 상태**에서 **검증 재시도** ({{< icon name="retry" >}})를 선택합니다.

![도메인에 대한 검증 재시도 옵션을 보여주는 GitLab Pages 설정입니다.](img/retry_domain_verification_v18_8.png)

도메인이 활성화되면 웹사이트를 도메인 이름으로 이용할 수 있습니다.

> [!warning]
> 도메인 검증이 켜진 GitLab 인스턴스에서 GitLab은 7일 후에 프로젝트에서 검증되지 않은 도메인을 제거합니다.

추가:

- GitLab.com 사용자에게는 도메인 검증이 필수입니다. GitLab Self-Managed의 경우 GitLab 관리자는 [사용자 정의 도메인 검증을 끌 수 있습니다](../../../../administration/pages/_index.md#custom-domain-verification).
- [DNS 전파는 시간이 걸릴 수 있습니다(최대 24시간)](https://www.inmotionhosting.com/support/domain-names/dns-nameserver-changes/complete-guide-to-dns-records/), 하지만 일반적으로 완료하는 데 몇 분 정도 걸립니다. 그때까지 검증이 실패하고 도메인 방문 시도 결과 404 오류가 발생합니다.
- 도메인이 검증된 후 검증 레코드를 유지합니다. 도메인은 정기적으로 재검증되며, 레코드가 제거되면 꺼질 수 있습니다.

## 더 많은 도메인 별칭 추가 {#add-more-domain-aliases}

같은 프로젝트에 둘 이상의 별칭(사용자 정의 도메인 및 서브도메인)을 추가할 수 있습니다. 별칭은 같은 방으로 통하는 많은 문으로 이해할 수 있습니다.

사이트에 설정한 모든 별칭은 **설정** > **Pages**에 나열됩니다. 해당 페이지에서 이를 보고 추가하고 제거할 수 있습니다.

## Cloudflare를 사용하여 `www.domain.com`을(를) `domain.com`로 리디렉션 {#redirect-wwwdomaincom-to-domaincom-with-cloudflare}

Cloudflare를 사용하는 경우 페이지 규칙을 사용하여 `www.domain.com`을(를) `domain.com`로 리디렉션할 수 있으며 두 도메인을 모두 GitLab에 추가할 필요가 없습니다:

1. Cloudflare에서 다음 중 최소 하나를 만듭니다:
   - `A` 레코드가 `domain.com`을(를) `35.185.44.232`으로 가리키는 DNS.
   - `AAAA` 레코드가 `domain.com`을(를) `2600:1901:0:7b8a::`으로 가리키는 DNS.
1. GitLab에서 GitLab Pages에 도메인을 추가하고 검증 코드를 가져옵니다.
1. Cloudflare에서 도메인을 확인하기 위해 DNS `TXT` 레코드를 만듭니다.
1. GitLab에서 도메인을 확인합니다.
1. Cloudflare에서 `CNAME` 레코드가 `www`을(를) `domain.com`으로 가리키는 DNS를 만듭니다.
1. Cloudflare에서 `www.domain.com`을(를) `domain.com`로 가리키는 페이지 규칙을 추가합니다:
   1. 도메인의 대시보드로 이동합니다. 상단 탐색에서 **페이지 규칙**을 선택합니다.
   1. **페이지 규칙 만들기**를 선택합니다.
   1. 도메인 `www.domain.com`을(를) 입력하고 **+ 설정 추가**를 선택합니다.
   1. 드롭다운 목록에서 **전달 URL**을 선택한 다음 상태 코드 **301 - 영구 리디렉션**을 선택합니다.
   1. 대상 URL `https://domain.com`을 입력합니다.

## Pages에 SSL/TLS 인증서 추가 {#add-an-ssltls-certificate-to-pages}

GitLab Pages로 사용자 정의 도메인을 보호하려면 다음을 수행할 수 있습니다:

- [Let's Encrypt 통합](lets_encrypt_integration.md)을 사용하여 SSL 인증서를 자동으로 얻고 갱신합니다.
- 수동으로 SSL/TLS 인증서를 추가합니다.

SSL/TLS 인증의 개요는 [GitLab Pages SSL/TLS 인증서](ssl_tls_concepts.md)를 참조하세요.

### 수동으로 SSL/TLS 인증서 추가 {#manually-add-ssltls-certificates}

사전 요구 사항:

- GitLab Pages 웹사이트가 실행 중이며 사용자 정의 도메인에서 액세스할 수 있습니다.
- 다음 인증서 구성 요소:

  - **PEM 인증서**: CA에서 생성한 인증서입니다.
  - **중간 인증서**: 루트 인증서라고도 하며 CA를 식별합니다. 일반적으로 PEM 인증서와 함께 결합되지만 [Cloudflare 인증서](https://about.gitlab.com/blog/setting-up-gitlab-pages-with-cloudflare-certificates/)와 같은 일부 인증서는 별도로 추가해야 합니다.
  - **개인 키**: 도메인에 대해 PEM을 검증하는 암호화된 키입니다.

새 도메인을 만들 때 인증서를 추가하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. 오른쪽 위 모서리에서 **새 도메인**을 선택합니다.
1. **도메인**에서 도메인 이름을 입력합니다.
1. **인증서**에서 **Let's Encrypt를 사용하여 인증서를 자동으로 관리** 토글을 끕니다.
1. 인증서 필드를 완료합니다.
1. **새 도메인 만들기**를 선택합니다.

기존 도메인에 인증서를 추가하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. 도메인 이름 옆에서 **편집** ({{< icon name="pencil" >}})을 선택합니다.
1. **인증서**에서 **Let's Encrypt를 사용하여 인증서를 자동으로 관리** 토글을 끕니다.
1. 인증서 필드를 완료합니다.
1. **변경 사항 저장**을 선택합니다.

인증서 필드를 완료할 때:

- **인증서 (PEM)**에 PEM 인증서를 붙여넣습니다. 인증서에 별도의 중간 인증서가 필요한 경우 같은 필드에 붙여넣되 공백 줄로 구분합니다. 자세한 내용은 [Cloudflare 인증서를 사용하여 GitLab Pages 설정](https://about.gitlab.com/blog/setting-up-gitlab-pages-with-cloudflare-certificates/)을 참조하세요.
- 개인 키 필드에 개인 키를 붙여넣습니다.

> [!note]
> 인증서 또는 암호화 키를 일반 텍스트 편집기에서 열지 마세요. Sublime Text, Dreamweaver 또는 VS Code와 같은 코드 편집기를 사용합니다.

## GitLab Pages 웹사이트에 HTTPS 강제 전환 {#force-https-for-gitlab-pages-websites}

GitLab Pages에 HTTPS를 강제로 적용하여 HTTP 요청을 301 리디렉션을 통해 HTTPS로 자동 리디렉션할 수 있습니다. 이는 기본 GitLab Pages 도메인과 유효한 인증서가 있는 사용자 정의 도메인에서 작동합니다.

HTTPS를 강제로 적용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. **HTTPS 강제 전환 (유효한 인증서 필요)** 체크박스를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

GitLab Pages 앞에 Cloudflare CDN을 사용하는 경우 SSL 연결 설정을 `flexible` 대신 `full`로 설정합니다. 자세한 내용은 [Cloudflare CDN 지침](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes#h_4e0d1a7c-eb71-4204-9e22-9d3ef9ef7fef)을 참조하세요.

## 사용자 정의 도메인 편집 {#edit-a-custom-domain}

사용자 정의 도메인을 편집할 수 있습니다:

- 사용자 정의 도메인을 봅니다.
- 추가할 DNS 레코드를 봅니다.
- `TXT` 검증 항목을 봅니다.
- 검증 재시도합니다.
- 인증서 설정을 편집합니다.

사용자 정의 도메인을 편집하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. 도메인 이름 옆에서 **편집** ({{< icon name="pencil" >}})을 선택합니다.

## 사용자 정의 도메인 삭제 {#delete-a-custom-domain}

사용자 정의 도메인을 삭제한 후 도메인은 더 이상 GitLab에서 검증되지 않으며 GitLab Pages와 함께 사용할 수 없습니다.

사용자 정의 도메인을 삭제하고 제거하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. 도메인 이름 옆에서 **도메인 제거** ({{< icon name="remove" >}})을 선택합니다.
1. 메시지가 표시되면 **도메인 제거**를 선택합니다.

## 문제 해결 {#troubleshooting}

### 도메인 검증 {#domain-verification}

도메인 검증 `TXT` DNS 항목을 제대로 구성했는지 수동으로 확인하려면 터미널에서 다음 명령을 실행할 수 있습니다:

```shell
dig _gitlab-pages-verification-code.<YOUR-PAGES-DOMAIN> TXT
```

예상 출력:

```plaintext
;; ANSWER SECTION:
_gitlab-pages-verification-code.<YOUR-PAGES-DOMAIN>. 300 IN TXT "gitlab-pages-verification-code=<YOUR-VERIFICATION-CODE>"
```

경우에 따라 등록하려는 도메인 이름과 동일한 도메인 이름으로 검증 코드를 추가하면 도움이 될 수 있습니다.

루트 도메인의 경우:

| 원본                                          | DNS 레코드 | 대상 |
|-----------------------------------------------|------------|----|
| `example.com`                                 | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |
| `_gitlab-pages-verification-code.example.com` | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |

서브도메인의 경우:

| 원본                                              | DNS 레코드 | 대상 |
|---------------------------------------------------|------------|----|
| `www.example.com`                                 | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |
| `_gitlab-pages-verification-code.www.example.com` | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |
