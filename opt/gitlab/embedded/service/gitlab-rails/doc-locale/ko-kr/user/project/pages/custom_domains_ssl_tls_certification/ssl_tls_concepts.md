---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Pages SSL/TLS 인증서
description: GitLab Pages의 사용자 지정 도메인을 위한 HTTPS 및 SSL/TLS 인증서 개념입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

GitLab.com의 모든 GitLab Pages 프로젝트는 기본 Pages 도메인(`*.gitlab.io`)에서 HTTPS로 사용 가능합니다. Pages 프로젝트를 사용자 정의 (서브)도메인으로 설정한 후 HTTPS로 보호하려면 해당 (서브)도메인에 대한 인증서를 발급하고 프로젝트에 설치해야 합니다.

> [!note]
> GitLab Pages 프로젝트의 사용자 정의 (서브)도메인에 인증서를 추가할 필요는 없지만 매우 권장됩니다.

## HTTPS의 중요성 {#importance-of-https}

GitLab Pages 사이트는 정적입니다. 서버 측 스크립트를 사용하거나 신용카드 거래를 처리하지 않습니다. 그렇다면 왜 보안 연결이 필요할까요?

HTTPS가 1990년에 출시되었을 때, [SSL](https://en.wikipedia.org/wiki/Transport_Layer_Security#SSL_1.0.2C_2.0_and_3.0)은 은행 및 금융 거래가 있는 쇼핑 사이트와 같은 대규모 회사에만 필요한 "특별한" 보안 조치로 간주되었습니다.

<!-- vale gitlab_base.Spelling = NO -->

상황이 이제는 다릅니다. [Josh Aas에 따르면](https://letsencrypt.org/2015/10/29/phishing-and-malware.html) [Internet Security Research Group (ISRG)](https://en.wikipedia.org/wiki/Internet_Security_Research_Group)의 회장은 다음과 같습니다:

<!-- vale gitlab_base.rulename = YES -->

> HTTPS는 거의 모든 웹사이트에 중요하다는 것을 알게 되었습니다. 비밀번호로 로그인할 수 있는 모든 웹사이트, [사용자를 추적하는](https://www.washingtonpost.com/news/the-switch/wp/2013/12/10/nsa-uses-google-cookies-to-pinpoint-targets-for-hacking/) 모든 웹사이트, [콘텐츠가 변경되지 않기를 원하는](https://arstechnica.com/tech-policy/2014/09/why-comcasts-javascript-ad-injections-threaten-security-net-neutrality/) 모든 웹사이트, 그리고 사람들이 다른 사람들이 보고 있다는 것을 알고 싶지 않을 수 있는 콘텐츠를 제공하는 모든 사이트에 중요합니다. 우리는 또한 HTTPS로 보호되지 않는 모든 사이트가 [다른 사이트를 공격하는 데 사용될 수 있다](https://krebsonsecurity.com/2015/04/dont-be-fodder-for-chinas-great-cannon/)는 것을 알게 되었습니다.

인증서는 인증 및 검증의 키체인을 통해 **클라이언트**(귀하 및 방문자)와 **서버**(사이트가 있는 위치) 간의 연결을 암호화하기 때문에 중요합니다.

## HTTPS를 지원하는 조직 {#organizations-supporting-https}

웹 전체를 보호하려는 거대한 운동이 있습니다. W3C는 완전히 [이 대의를 지원하며](https://w3ctag.github.io/web-https/) 그 이유를 매우 잘 설명합니다. Mozilla Security Blog의 작가인 Richard Barnes는 [Firefox가 HTTP를 더 이상 사용하지 않을 것이며](https://blog.mozilla.org/security/2015/04/30/deprecating-non-secure-http/) 보안되지 않은 연결을 더 이상 허용하지 않을 것을 제안했습니다. 최근 Mozilla는 HTTPS의 중요성을 재강조하는 [통신](https://blog.mozilla.org/security/2016/03/29/march-2016-ca-communication/)을 발표했습니다.

## 인증서 발급 {#issuing-certificates}

GitLab Pages는 [PEM](https://knowledge.digicert.com/quovadis) 형식으로 제공되고 [인증 기관](https://en.wikipedia.org/wiki/Certificate_authority)에서 발급하거나 [자체 서명된 인증서](https://en.wikipedia.org/wiki/Self-signed_certificate)로 발급된 인증서를 허용합니다. [자체 서명된 인증서는 일반적으로 사용되지 않습니다](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/self-signed-certificates-secure-so-why-ban/) 공개 웹사이트의 경우 보안상의 이유로 그리고 브라우저가 사이트의 인증서를 신뢰하도록 하기 위해서입니다.

다양한 인증서는 다양한 보안 수준을 가지고 있습니다. 예를 들어 정적 개인 웹사이트는 온라인 뱅킹 웹 앱과 동일한 보안 수준을 요구하지 않습니다.

일부 인증 기관은 무료 인증서를 제공하여 모두를 위해 인터넷을 더 안전하게 하려고 합니다. 가장 인기 있는 것은 [Let's Encrypt](https://letsencrypt.org/)로 대부분의 브라우저에서 신뢰하는 인증서를 발급하며 오픈 소스이고 무료로 사용할 수 있습니다. [GitLab Pages와 Let's Encrypt의 통합](lets_encrypt_integration.md)을 참조하여 사용자 정의 도메인에 대해 HTTPS를 켜십시오.

마찬가지로 인기 있는 것은 [Cloudflare에서 발급한 인증서](https://www.cloudflare.com/products/ssl/)로 [무료 CDN 서비스](https://blog.cloudflare.com/cloudflares-free-cdn-and-you/)도 제공합니다. 이들 인증서는 최대 15년까지 유효합니다. [GitLab Pages 웹사이트에 Cloudflare 인증서를 추가하는 방법](https://about.gitlab.com/blog/setting-up-gitlab-pages-with-cloudflare-certificates/)에 대한 자습서를 참조하십시오.
