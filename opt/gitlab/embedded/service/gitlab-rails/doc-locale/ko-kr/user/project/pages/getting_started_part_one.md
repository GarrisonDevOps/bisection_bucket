---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Pages 기본 도메인 이름 및 URL
description: GitLab Pages 사이트의 기본 도메인 이름 및 URL 구조입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Pages는 네임스페이스와 프로젝트 이름을 기반으로 기본 도메인 이름을 제공합니다. 이 도메인:

- 프로젝트 사이트, 사용자 사이트 및 그룹 사이트에 대한 예측 가능한 URL을 생성합니다.
- GitLab 조직 구조를 반영하는 계층적 경로를 지원합니다.
- 활성화되면 자동 리디렉션을 포함한 고유한 도메인 이름을 생성합니다.
- 사용자 지정 도메인 이름 및 SSL/TLS 인증서와 원활하게 작동합니다.
- 사용자, 그룹 및 하위 그룹 프로젝트 전체에 걸쳐 확장됩니다.

이 URL을 사용하여 정적 사이트 생성기를 구성합니다.

## GitLab Pages 기본 도메인 이름 {#gitlab-pages-default-domain-names}

{{< history >}}

- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163523) GitLab 17.4에서 고유 도메인 URL을 더 짧게 했습니다.

{{< /history >}}

GitLab Pages를 사용하여 자신의 GitLab 인스턴스를 배포하려면 Pages 와일드카드 도메인을 시스템 관리자와 확인합니다. 이 가이드는 Pages 와일드카드 도메인을 GitLab.com (`*.gitlab.io`)에서 자신의 것으로 바꾸는 조건이 있는 모든 GitLab 인스턴스에 적용됩니다.

GitLab Pages 프로젝트를 GitLab에 설정하면 `namespace.example.io`의 하위 도메인 아래에서 자동으로 액세스할 수 있습니다. [`namespace`](../../namespace/_index.md)는 GitLab.com의 사용자 이름 또는 이 프로젝트를 만든 그룹 이름으로 정의됩니다. GitLab Self-Managed의 경우 `example.io`을 인스턴스의 Pages 도메인으로 바꿉니다. GitLab.com의 경우 Pages 도메인은 `*.gitlab.io`입니다.

| GitLab Pages 유형 | GitLab의 프로젝트 경로 예시 | 웹사이트 URL |
| -------------------- | ------------ | ----------- |
| 사용자 페이지  | `username/username.example.io`  | `http(s)://username.example.io`  |
| 그룹 페이지 | `acmecorp/acmecorp.example.io` | `http(s)://acmecorp.example.io` |
| 사용자가 소유한 프로젝트 페이지  | `username/my-website` | `http(s)://username.example.io/my-website` |
| 그룹이 소유한 프로젝트 페이지 | `acmecorp/webshop` | `http(s)://acmecorp.example.io/webshop`|
| 하위 그룹이 소유한 프로젝트 페이지 | `acmecorp/documentation/product-manual` | `http(s)://acmecorp.example.io/documentation/product-manual`|

**고유 도메인 사용** 설정이 활성화되면 Pages는 평면화된 프로젝트 이름과 6자 고유 ID에서 도메인 이름을 생성합니다. 사용자는 `308 Permanent Redirect` 상태를 받아 브라우저를 이 고유 도메인 URL로 리디렉션합니다. 브라우저는 이 리디렉션을 캐시할 수 있습니다:

| GitLab Pages 유형              | GitLab의 프로젝트 경로 예시     | 웹사이트 URL |
| --------------------------------- | --------------------------------------- | ----------- |
| 사용자 페이지                        | `username/username.example.io`          | `http(s)://username-example-io-123456.example.io` |
| 그룹 페이지                       | `acmecorp/acmecorp.example.io`          | `http(s)://acmecorp-example-io-123456.example.io` |
| 사용자가 소유한 프로젝트 페이지     | `username/my-website`                   | `https://my-website-123456.gitlab.io/` |
| 그룹이 소유한 프로젝트 페이지    | `acmecorp/webshop`                      | `http(s)://webshop-123456.example.io/` |
| 하위 그룹이 소유한 프로젝트 페이지 | `acmecorp/documentation/product-manual` | `http(s)://product-manual-123456.example.io/` |

예제 URL의 `123456`은 6자 고유 ID입니다. 예를 들어 고유 ID가 `f85695`인 경우 마지막 예제는 `http(s)://product-manual-f85695.example.io/`입니다.

> [!warning]
> 일반 도메인 이름 아래에서 제공되는 네임스페이스와 HTTPS에 대한 제한 사항은 [하위 도메인의 하위 도메인](introduction.md#subdomains-of-subdomains)을 참조하세요.

다음 예제는 Pages 도메인의 작동 방식을 보여줍니다.

> [!note]
> 다음 예제는 **고유 도메인 사용** 설정을 비활성화했음을 의미합니다. 그렇지 않은 경우 이전 테이블을 참조하여 `example.io`을 `gitlab.io`로 바꿉니다.

### 프로젝트 웹사이트 예제 {#project-website-examples}

- `blog` 프로젝트를 사용자 이름 `john` 아래에 만들었으므로 프로젝트 URL은 `https://gitlab.com/john/blog/`입니다. 이 프로젝트에 대해 GitLab Pages를 활성화하고 사이트를 구축한 후 `https://john.gitlab.io/blog/`에서 액세스할 수 있습니다.
- 모든 웹사이트에 대한 `websites` 그룹을 만들었고, 이 그룹의 프로젝트를 `blog`라고 합니다. 프로젝트 URL은 `https://gitlab.com/websites/blog/`입니다. 이 프로젝트에 대해 GitLab Pages를 활성화한 후 사이트는 `https://websites.gitlab.io/blog/`에서 사용 가능합니다.
- 엔지니어링 부서의 `engineering` 그룹, 모든 문서 웹사이트의 `docs` 하위 그룹, 그리고 이 하위 그룹의 `workflows` 프로젝트를 만들었습니다. 프로젝트 URL은 `https://gitlab.com/engineering/docs/workflows/`입니다. 이 프로젝트에 대해 GitLab Pages를 활성화한 후 사이트는 `https://engineering.gitlab.io/docs/workflows`에서 사용 가능합니다.

### 사용자 및 그룹 웹사이트 예제 {#user-and-group-website-examples}

- 사용자 이름 `john` 아래에서 `john.gitlab.io` 프로젝트를 만들었습니다. 프로젝트 URL은 `https://gitlab.com/john/john.gitlab.io`입니다. 프로젝트에 대해 GitLab Pages를 활성화한 후 웹사이트는 `https://john.gitlab.io` 아래에 게시됩니다.
- 그룹 `websites` 아래에서 `websites.gitlab.io` 프로젝트를 만들었습니다. 프로젝트의 URL은 `https://gitlab.com/websites/websites.gitlab.io`입니다. 프로젝트에 대해 GitLab Pages를 활성화한 후 웹사이트는 `https://websites.gitlab.io` 아래에 게시됩니다.

**일반적인 예제**:

- GitLab.com에서 프로젝트 사이트는 항상 `https://namespace.gitlab.io/project-slug` 아래에서 사용 가능합니다.
- GitLab.com에서 사용자 또는 그룹 웹사이트는 `https://namespace.gitlab.io/` 아래에서 사용 가능합니다.
- GitLab 인스턴스에서 `gitlab.io`을 Pages 서버 도메인으로 바꿉니다. 이 정보는 시스템 관리자에게 문의하세요.

## URL 및 기본 URL {#urls-and-base-urls}

> [!note]
> `baseurl` 옵션은 일부 정적 사이트 생성기에서 다르게 명명될 수 있습니다.

모든 정적 사이트 생성기(SSG) 기본 구성은 해당 도메인의 하위 디렉터리(`example.com/subdir`)가 아닌 (하위)도메인(`example.com`) 아래에서 웹사이트를 찾을 수 있어야 합니다. 따라서 프로젝트 웹사이트(예: `namespace.gitlab.io/project-slug`)를 게시할 때마다 정적 사이트 생성기의 설명서에서 이 구성(기본 URL)을 찾고 이 패턴을 반영하도록 설정해야 합니다.

예를 들어 Jekyll 사이트의 경우 `baseurl`은 Jekyll 구성 파일 `_config.yml`에서 정의됩니다. 웹사이트 URL이 `https://john.gitlab.io/blog/`인 경우 `_config.yml`에 이 줄을 추가해야 합니다:

```yaml
baseurl: "/blog"
```

[기본 예제](https://gitlab.com/pages) 중 하나를 포크한 후 웹사이트를 배포하면 `baseurl`은 이미 이렇게 구성되어 있습니다. 모든 예제는 프로젝트 웹사이트입니다. 프로젝트를 사용자 또는 그룹 웹사이트로 변경하기로 결정한 경우 프로젝트에서 이 구성을 제거해야 합니다. Jekyll 예제의 경우 Jekyll `_config.yml`을 다음으로 변경합니다:

```yaml
baseurl: ""
```

[평문 HTML 예제](https://gitlab.com/pages/plain-html)를 사용 중인 경우 `baseurl`을 설정할 필요가 없습니다.

## 사용자 지정 도메인 {#custom-domains}

GitLab Pages는 HTTP 또는 HTTPS에서 제공되는 사용자 지정 도메인 및 하위 도메인을 지원합니다. [GitLab Pages 사용자 지정 도메인 및 SSL/TLS 인증서](custom_domains_ssl_tls_certification/_index.md)를 참조하세요.
