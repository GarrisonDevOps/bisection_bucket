---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: GitLab Pages DNS 레코드
description: 사용자 지정 도메인을 GitLab Pages 사이트로 가리키기 위해 사용되는 DNS 레코드입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

도메인 이름 시스템(DNS) 웹 서비스는 도메인 이름(예: `www.example.com`)을 컴퓨터가 서로 연결할 때 사용하는 숫자 IP 주소(예: `192.0.2.1`)로 변환하여 웹사이트 방문자를 라우팅합니다.

DNS 레코드는 (서브)도메인을 특정 위치로 가리키도록 생성되며, 이는 IP 주소 또는 다른 도메인일 수 있습니다. GitLab Pages를 자신의 (서브)도메인과 함께 사용하려면 도메인 레지스트라 제어판에 액세스하여 GitLab Pages 사이트로 다시 가리키는 DNS 레코드를 추가해야 합니다.

DNS 레코드를 추가하는 방법은 도메인이 호스팅되는 서버에 따라 다릅니다. 모든 제어판에는 이를 수행할 수 있는 자체 위치가 있습니다. 도메인의 관리자가 아니거나 레지스트라에 액세스할 수 없으면 호스팅 서비스의 기술 지원에 요청하여 이를 수행하도록 해야 합니다.

자세한 내용은 [GitLab Pages용 DNS 레코드 설정](_index.md#step-3-set-up-dns-records)을 참조하세요.

가장 인기 있는 호스팅 서비스의 경우 다음 지침을 참조하세요:

<!-- vale gitlab_base.Spelling = NO -->

- [123-reg](https://www.123-reg.co.uk/support/domains/domain-name-server-dns-management-guide/)
- [Amazon](https://docs.aws.amazon.com/AmazonS3/latest/userguide/website-hosting-custom-domain-walkthrough.html)
- [Bluehost](https://www.bluehost.com/help/article/dns-management-add-edit-or-delete-dns-entries)
- [Cloudflare](https://developers.cloudflare.com/fundamentals/account/)
- [cPanel](https://docs.cpanel.net/cpanel/domains/zone-editor/)
- [DigitalOcean](https://docs.digitalocean.com/products/networking/dns/how-to/manage-records/)
- [DreamHost](https://help.dreamhost.com/hc/en-us/articles/360035516812-Adding-custom-DNS-records)
- [Gandi](https://docs.gandi.net/en/domain_names/faq/dns_records.html)
- [Go Daddy](https://www.godaddy.com/help/add-an-a-record-19238)
- [Hostgator](https://www.hostgator.com/help/article/changing-dns-records)
- [Inmotion hosting](https://www.inmotionhosting.com/support/edu/cpanel/how-do-i-make-custom-dns-records/)
- [Microsoft](https://learn.microsoft.com/en-us/windows-server/networking/dns/manage-resource-records?tabs=powershell)
- [Namecheap](https://www.namecheap.com/support/knowledgebase/subcategory/2237/host-records-setup/)

<!-- vale gitlab_base.Spelling = YES -->

호스팅 서비스가 나열되지 않으면 `how to add dns record on <my hosting service>`을 웹에서 검색하면 됩니다.

## `A` 레코드 {#a-record}

DNS `A` 레코드는 호스트를 IPv4 IP 주소로 매핑합니다. 루트 도메인 `example.com`을 호스트의 IP 주소 `192.0.2.1`로 가리킵니다.

예:

- `example.com` => `A` => `192.0.2.1`

## `AAAA` 레코드 {#aaaa-record}

DNS `AAAA` 레코드는 호스트를 IPv6 IP 주소로 매핑합니다. 루트 도메인 `example.com`을 호스트의 IP 주소 `2001:db8::1`로 가리킵니다.

예:

- `example.com` => `AAAA` => `2001:db8::1`

## `CNAME` 레코드 {#cname-record}

`CNAME` 레코드는 서버의 정규 이름에 대한 별칭을 정의합니다(`A` 레코드로 정의됨). 서브도메인을 다른 도메인으로 가리킵니다.

예:

- `www` => `CNAME` => `example.com`

이렇게 하면 `www.example.com`을 방문하는 방문자가 `example.com`로 리디렉션됩니다.

## `MX` 레코드 {#mx-record}

MX 레코드는 도메인에 사용되는 메일 교환을 정의하는 데 사용됩니다. 이는 이메일 메시지가 메일 서버에 올바르게 도착하는 데 도움이 됩니다.

예:

- `MX` => `mail.example.com`

그러면 `users@mail.example.com`에 대한 이메일을 등록할 수 있습니다.

## `TXT` 레코드 {#txt-record}

`TXT` 레코드는 임의의 텍스트를 호스트 또는 다른 이름과 연결할 수 있습니다. 일반적인 용도는 사이트 검증입니다.

예:

- `example.com` => `TXT` => `"google-site-verification=6P08Ow5E-8Q0m6vQ7FMAqAYIDprkVV8fUf_7hZ4Qvc8"`

이렇게 하면 해당 도메인 이름의 소유권을 확인할 수 있습니다.

## 모든 것이 결합됨 {#all-combined}

하나 이상의 DNS 레코드를 결합할 수 있습니다:

- `example.com` => `A` => `192.0.2.1`
- `example.com` => `AAAA` => `2001:db8::1`
- `www` => `CNAME` => `example.com`
- `MX` => `mail.example.com`
- `example.com` => `TXT` => `"google-site-verification=6P08Ow5E-8Q0m6vQ7FMAqAYIDprkVV8fUf_7hZ4Qvc8"`
