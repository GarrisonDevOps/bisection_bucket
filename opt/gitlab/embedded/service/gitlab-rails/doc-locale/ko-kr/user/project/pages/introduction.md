---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Pages 설정
description: "사용자 지정 오류 페이지, 리디렉션 및 고유 도메인을 포함한 GitLab Pages 구성 옵션입니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Pages는 정적 사이트의 배포 및 프레젠테이션을 사용자 지정할 수 있는 구성 옵션을 제공합니다. Pages 설정을 사용하여 다음을 수행할 수 있습니다:

- 403 및 404 응답에 대한 사용자 지정 오류 페이지를 제공합니다.
- `_redirects` 파일을 통해 URL 리디렉션을 구성합니다.
- CI/CD 규칙을 사용하여 모든 브랜치에서 페이지를 배포합니다.
- 더 빠른 페이지 로드를 위해 사전 압축된 자산을 제공합니다.
- 사이트가 게시되는 폴더를 사용자 지정합니다.
- 사이트의 고유 도메인을 생성하고 관리합니다.

Pages 소개는 [GitLab Pages](_index.md)를 참조하세요.

## GitLab Pages 요구사항 {#gitlab-pages-requirements}

간단히 말해서 GitLab Pages에 웹사이트를 업로드하기 위해 필요한 것입니다:

1. 인스턴스의 도메인: GitLab Pages에 사용되는 도메인 이름(관리자에게 문의하세요).
1. GitLab CI/CD: 리포지토리의 루트 디렉터리에 [`pages`](../../../ci/yaml/_index.md#pages) 이름의 특정 작업이 있는 `.gitlab-ci.yml` 파일입니다.
1. 프로젝트에 대해 GitLab Runner가 켜져 있습니다.

## GitLab.com의 GitLab Pages {#gitlab-pages-on-gitlabcom}

[GitLab.com의 GitLab Pages](#gitlab-pages-on-gitlabcom)를 사용하여 웹사이트를 호스팅하는 경우:

- GitLab.com의 GitLab Pages 도메인 이름은 `gitlab.io`입니다.
- 사용자 지정 도메인 및 TLS 지원이 활성화되어 있습니다.
- 인스턴스 러너는 기본적으로 켜져 있으며, 무료로 제공되며 웹사이트를 빌드하는 데 사용할 수 있습니다. 원하면 자신의 러너를 가져올 수도 있습니다.

## 예제 프로젝트 {#example-projects}

[GitLab Pages 그룹](https://gitlab.com/groups/pages)을 방문하여 예제 프로젝트의 전체 목록을 확인합니다. 기여는 매우 환영합니다.

## 사용자 지정 오류 코드 페이지 {#custom-error-codes-pages}

`public/` 디렉터리의 루트에 `403.html` 및 `404.html` 파일을 생성하여 자신의 `403` 및 `404` 오류 페이지를 제공할 수 있습니다. 일반적으로 프로젝트의 루트 디렉터리이지만 정적 생성기 구성에 따라 다를 수 있습니다.

`404.html`의 경우 다양한 시나리오가 있습니다. 예를 들어:

- 프로젝트 Pages를 사용하는 경우(`/project-slug/`에서 제공) `/project-slug/non/existing_file`에 액세스하려고 하면 GitLab Pages는 먼저 `/project-slug/404.html`을 제공하고 그 다음 `/404.html`을 제공하려고 합니다.
- 사용자 또는 그룹 Pages를 사용하는 경우(`/`에서 제공) `/non/existing_file`에 액세스하려고 하면 GitLab Pages는 `/404.html`을 제공하려고 합니다.
- 사용자 지정 도메인을 사용하고 `/non/existing_file`에 액세스하려고 하면 GitLab Pages는 `/404.html`만 제공하려고 합니다.

## GitLab Pages의 리디렉션 {#redirects-in-gitlab-pages}

`_redirects` 파일을 사용하여 사이트의 리디렉션을 구성할 수 있습니다. 자세한 내용은 [GitLab Pages용 리디렉션 만들기](redirects.md)를 참조하세요.

## Pages 사이트 삭제 {#delete-a-pages-site}

프로젝트의 모든 Pages 배포를 영구적으로 삭제합니다.

> [!warning]
> 변경 사항을 실행 취소할 수 없습니다.

Pages를 삭제하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. **도메인 & 설정** 탭을 선택합니다.
1. **Pages 제거**를 선택합니다.
1. 확인 대화상자에서 **Pages 제거**를 선택합니다.

Pages 사이트가 더 이상 배포되지 않습니다. Pages 사이트를 다시 배포하려면 새 파이프라인을 실행합니다.

## 서브도메인의 서브도메인 {#subdomains-of-subdomains}

GitLab 인스턴스의 최상위 도메인(`*.example.io`) 아래에서 Pages를 사용하는 경우 서브도메인의 서브도메인에 HTTPS를 사용할 수 없습니다. 네임스페이스 또는 그룹 이름에 점이 포함된 경우(예: `foo.bar`) `https://foo.bar.example.io` 도메인은 작동하지 않습니다.

이러한 제한은 [HTTP Over TLS 프로토콜](https://www.rfc-editor.org/rfc/rfc2818#section-3.1) 때문입니다. HTTP를 HTTPS로 리디렉션하지 않는 한 HTTP 페이지는 작동합니다.

## 프로젝트 및 그룹의 GitLab Pages {#gitlab-pages-in-projects-and-groups}

GitLab Pages 웹사이트를 프로젝트에서 호스팅해야 합니다. 이 프로젝트는 [비공개, 내부 또는 공개](../../public_access.md)일 수 있으며 [그룹](../../group/_index.md) 또는 [하위 그룹](../../group/subgroups/_index.md)에 속할 수 있습니다.

[그룹 웹사이트](getting_started_part_one.md#user-and-group-website-examples)의 경우 그룹은 최상위 수준에 있어야 하며 하위 그룹이 아니어야 합니다.

[프로젝트 웹사이트](getting_started_part_one.md#project-website-examples)의 경우 먼저 프로젝트를 생성하고 `http(s)://namespace.example.io/project-path`에서 액세스할 수 있습니다.

## Pages의 특정 구성 옵션 {#specific-configuration-options-for-pages}

특정 사용 사례에 대해 GitLab CI/CD를 설정하는 방법을 알아봅니다.

### 일반 HTML 웹사이트용 `.gitlab-ci.yml` {#gitlab-ciyml-for-plain-html-websites}

리포지토리에 다음 파일이 포함되어 있다고 가정합니다:

```plaintext
├── index.html
├── css
│   └── main.css
└── js
    └── main.js
```

그러면 아래의 `.gitlab-ci.yml` 예제는 프로젝트의 루트 디렉터리에서 `public/` 디렉터리로 모든 파일을 이동합니다. `.public` 해결 방법은 `cp`이 `public/`을 자신에게 무한 루프로 복사하지 않도록 하기 위한 것입니다:

```yaml
create-pages:
  script:
    - mkdir .public
    - cp -r * .public
    - mv .public public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

이전 YAML 예제는 [사용자 정의 작업 이름](_index.md#user-defined-job-names)을 사용합니다.

### 정적 사이트 생성기용 `.gitlab-ci.yml` {#gitlab-ciyml-for-a-static-site-generator}

[단계별 가이드](getting_started/pages_from_scratch.md)는 이 문서를 참조하세요.

### 코드가 있는 리포지토리용 `.gitlab-ci.yml` {#gitlab-ciyml-for-a-repository-with-code}

GitLab Pages는 기본적으로 브랜치/태그와 무관하며, 배포는 `.gitlab-ci.yml`에서 지정한 내용에만 의존한다는 점을 기억하세요. `pages` 작업을 [`rules:if`](../../../ci/yaml/_index.md#rulesif)로 제한할 수 있으며, 페이지용으로 특별히 사용되는 브랜치에 새 커밋이 푸시될 때마다 제한할 수 있습니다.

이렇게 하면 프로젝트의 코드를 `main` 브랜치에 유지하고 고아 브랜치(이름을 `pages`라고 하겠습니다)를 사용하여 정적 생성기 사이트를 호스팅할 수 있습니다.

다음과 같이 새 빈 브랜치를 만들 수 있습니다:

```shell
git checkout --orphan pages
```

이 새 브랜치에서 만든 첫 번째 커밋은 부모가 없으며 다른 모든 브랜치 및 커밋과 완전히 연결되지 않은 새 기록의 루트입니다. 정적 생성기의 소스 파일을 `pages` 브랜치에 푸시합니다.

아래는 `.gitlab-ci.yml`의 복사본으로, 가장 중요한 줄은 `pages` 브랜치에서 모든 것을 실행하도록 지정하는 마지막 줄입니다:

```yaml
create-pages:
  image: ruby:2.6
  script:
    - gem install jekyll
    - jekyll build -d public/
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: '$CI_COMMIT_REF_NAME == "pages"'
```

[`main` 브랜치](https://gitlab.com/pages/jekyll-branched/tree/main)에 다양한 파일이 있고 Jekyll의 소스 파일이 [`pages` 브랜치](https://gitlab.com/pages/jekyll-branched/tree/pages)에 있으며, 여기에는 `.gitlab-ci.yml`도 포함되어 있는 예제를 참조하세요.

이전 YAML 예제는 [사용자 정의 작업 이름](_index.md#user-defined-job-names)을 사용합니다.

### 압축된 자산 제공 {#serving-compressed-assets}

대부분의 최신 브라우저는 압축된 형식으로 파일을 다운로드할 수 있습니다. 파일 크기를 줄여 다운로드 속도를 높입니다.

압축되지 않은 파일을 제공하기 전에 Pages는 같은 파일이 `.br` 또는 `.gz` 확장명으로 존재하는지 확인합니다. 그렇다면 브라우저가 압축된 파일 수신을 지원하면 압축되지 않은 버전 대신 해당 버전을 제공합니다.

이 기능을 활용하려면 Pages에 업로드하는 아티팩트에 다음 구조가 있어야 합니다:

```plaintext
public/
├─┬ index.html
│ | index.html.br
│ └ index.html.gz
│
├── css/
│   └─┬ main.css
│     | main.css.br
│     └ main.css.gz
│
└── js/
    └─┬ main.js
      | main.js.br
      └ main.js.gz
```

이는 `.gitlab-ci.yml` pages 작업의 `script:` 명령을 포함하여 달성할 수 있습니다:

```yaml
create-pages:
  # Other directives
  script:
    # Build the public/ directory first
    - find public -type f -regex '.*\.\(htm\|html\|xml\|txt\|text\|js\|css\|svg\)$' -exec gzip -f -k {} \;
    - find public -type f -regex '.*\.\(htm\|html\|xml\|txt\|text\|js\|css\|svg\)$' -exec brotli -f -k {} \;
  pages: true  # specifies that this is a Pages job
```

파일을 사전 압축하고 아티팩트에 두 버전을 모두 포함하면 Pages는 필요에 따라 파일을 압축할 필요 없이 압축된 콘텐츠와 압축되지 않은 콘텐츠에 대한 요청을 모두 제공할 수 있습니다.

이전 YAML 예제는 [사용자 정의 작업 이름](_index.md#user-defined-job-names)을 사용합니다.

### 모호한 URL 해결 {#resolving-ambiguous-urls}

GitLab Pages는 확장명을 포함하지 않는 URL에 대한 요청을 받을 때 제공할 파일에 대해 가정합니다.

다음 파일과 함께 배포된 Pages 사이트를 고려합니다:

```plaintext
public/
├── index.html
├── data.html
├── info.html
├── data/
│   └── index.html
└── info/
    └── details.html
```

Pages는 여러 다른 URL을 통해 이러한 각 파일에 도달할 수 있습니다. 특히 URL이 디렉터리만 지정하면 항상 `index.html` 파일을 찾습니다. URL이 존재하지 않는 파일을 참조하지만 URL에 `.html`을 추가하면 존재하는 파일로 이어지면 대신 제공됩니다. 이전 Pages 사이트가 주어진 경우 발생하는 일의 몇 가지 예는 다음과 같습니다:

| URL 경로             | HTTP 응답 |
| -------------------- | ------------- |
| `/`                  | `200 OK`: `public/index.html` |
| `/index.html`        | `200 OK`: `public/index.html` |
| `/index`             | `200 OK`: `public/index.html` |
| `/data`              | `302 Found`: `/data/`로 리디렉션 |
| `/data/`             | `200 OK`: `public/data/index.html` |
| `/data.html`         | `200 OK`: `public/data.html` |
| `/info`              | `302 Found`: `/info/`로 리디렉션 |
| `/info/`             | `404 Not Found` 오류 페이지 |
| `/info.html`         | `200 OK`: `public/info.html` |
| `/info/details`      | `200 OK`: `public/info/details.html` |
| `/info/details.html` | `200 OK`: `public/info/details.html` |

`public/data/index.html`이 존재하면 `public/data.html` 파일에 우선하며 `/data` 및 `/data/` URL 경로 모두에 적용됩니다.

## 기본 폴더 사용자 지정 {#customize-the-default-folder}

{{< history >}}

- [GitLab 16.1](https://gitlab.com/gitlab-org/gitlab-pages/-/merge_requests/859)에서 `FF_CONFIGURABLE_ROOT_DIR` 이름의 Pages 플래그와 함께 도입되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab-pages/-/issues/1073)됨 (GitLab 16.1).
- [GitLab Self-Managed에서 활성화](https://gitlab.com/gitlab-org/gitlab-pages/-/merge_requests/890)됨 (GitLab 16.2).
- [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/500000) \- GitLab 17.9에서 `publish` 속성에 전달될 때 변수를 허용합니다.
- [이동](https://gitlab.com/gitlab-org/gitlab/-/issues/428018)됨 - `publish` 속성을 GitLab 17.9의 `pages` 키워드 아래로 이동합니다.
- [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/428018)됨 - `pages.publish` 경로를 GitLab 17.10의 `artifacts:paths`로 자동으로 추가합니다.

{{< /history >}}

기본적으로 Pages는 빌드 파일에서 `public` 이름의 폴더를 찾아 게시합니다.

폴더 이름을 다른 값으로 변경하려면 `.gitlab-ci.yml`의 `deploy-pages` 작업 구성에 `pages.publish` 속성을 추가합니다.

다음 예제는 대신 `dist` 이름의 폴더를 게시합니다:

```yaml
create-pages:
  script:
    - npm run build
  pages:  # specifies that this is a Pages job
    publish: dist
```

이전 YAML 예제는 [사용자 정의 작업 이름](_index.md#user-defined-job-names)을 사용합니다.

`pages.publish` 필드에서 변수를 사용하려면 [`pages.publish`](../../../ci/yaml/_index.md#pagespublish)를 참조하세요.

Pages는 아티팩트를 사용하여 사이트의 파일을 저장하므로 `pages.publish`의 값이 자동으로 [`artifacts:paths`](../../../ci/yaml/_index.md#artifactspaths)에 추가됩니다. 이전 예제는 다음과 동등합니다:

```yaml
create-pages:
  script:
    - npm run build
  pages:
    publish: dist
  artifacts:
    paths:
      - dist
```

> [!note]
> 최상위 수준의 `publish` 키워드는 GitLab 17.9에서 [더 이상 사용되지 않음](https://gitlab.com/gitlab-org/gitlab/-/issues/519499)이며 이제 `pages` 키워드 아래에 중첩되어야 합니다.

## GitLab Pages용 고유 도메인 재생성 {#regenerate-unique-domain-for-gitlab-pages}

{{< history >}}

- GitLab 17.7에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/481746)되었습니다.

{{< /history >}}

GitLab Pages 사이트의 고유 도메인을 재생성할 수 있습니다.

도메인이 재생성되면 이전 URL은 더 이상 활성화되지 않습니다. 아무나 이전 URL에 액세스하려고 하면 `404` 오류를 받습니다.

필수 조건

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.
- **고유 도메인 사용** 설정이 프로젝트의 Pages 설정에서 [켜져 있어야 합니다](_index.md#unique-domains).

GitLab Pages 사이트의 고유 도메인을 재생성하려면:

1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. **Pages 액세스** 옆에서 **고유 도메인 재생성**을 누릅니다.
1. GitLab은 Pages 사이트의 새로운 고유 도메인을 생성합니다.

## 알려진 이슈 {#known-issues}

알려진 문제 목록은 GitLab [공개 이슈 추적기](https://gitlab.com/gitlab-org/gitlab/-/issues?label_name[]=Category%3APages)를 참조하세요.

## 문제 해결 {#troubleshooting}

### GitLab Pages 사이트 URL에 액세스할 때 404 오류 {#404-error-when-accessing-a-gitlab-pages-site-url}

이 문제는 대부분 공개 디렉터리에 `index.html` 파일이 없기 때문에 발생합니다. Pages 사이트를 배포한 후 404가 발생하면 공개 디렉터리에 `index.html` 파일이 포함되어 있는지 확인하세요. 파일의 이름이 `test.html`처럼 다른 경우 Pages 사이트에 여전히 액세스할 수 있지만 전체 경로가 필요합니다. 예: `https://group-name.pages.example.com/project-slug/test.html`.

공개 디렉터리의 내용은 최신 파이프라인에서 [아티팩트를 브라우징](../../../ci/jobs/job_artifacts.md#download-job-artifacts)하여 확인할 수 있습니다.

공개 디렉터리 아래에 나열된 파일은 프로젝트의 Pages URL을 통해 액세스할 수 있습니다.

404는 잘못된 권한과도 관련이 있을 수 있습니다. [Pages 액세스 제어](pages_access_control.md)가 켜져 있고 사용자가 Pages URL로 이동하여 404 응답을 받으면 사용자가 사이트를 볼 수 있는 권한이 없을 수 있습니다. 이를 해결하려면 사용자가 프로젝트의 멤버인지 확인하세요.

### 손상된 상대 링크 {#broken-relative-links}

GitLab Pages는 확장명이 없는 URL을 지원합니다. 그러나 [이슈 #354](https://gitlab.com/gitlab-org/gitlab-pages/-/issues/354)에 설명된 문제로 인해 확장명이 없는 URL이 슬래시(`/`)로 끝나면 페이지의 상대 링크가 손상됩니다.

이 문제를 해결하려면:

- Pages 사이트를 가리키는 모든 URL에 확장명이 있는지 또는 후행 슬래시가 포함되지 않는지 확인합니다.
- 가능하면 사이트에서만 절대 URL을 사용합니다.

### Safari에서 미디어 콘텐츠를 재생할 수 없음 {#cannot-play-media-content-on-safari}

Safari는 웹 서버가 미디어 콘텐츠를 재생하기 위해 [범위 요청 헤더](https://developer.apple.com/library/archive/documentation/AppleApplications/Reference/SafariWebContent/CreatingVideoforSafarioniPhone/CreatingVideoforSafarioniPhone.html#//apple_ref/doc/uid/TP40006514-SW6)를 지원하도록 요구합니다. GitLab Pages가 HTTP 범위 요청을 제공하려면 `.gitlab-ci.yml` 파일에서 다음 두 변수를 사용해야 합니다:

```yaml
create-pages:
  stage: deploy
  variables:
    FF_USE_FASTZIP: "true"
    ARTIFACT_COMPRESSION_LEVEL: "fastest"
  script:
    - echo "Deploying pages"
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  environment: production
```

`FF_USE_FASTZIP` 변수는 [기능 플래그](https://docs.gitlab.com/runner/configuration/feature-flags/#available-feature-flags)를 켜며 [`ARTIFACT_COMPRESSION_LEVEL`](../../../ci/runners/configure_runners.md#artifact-and-cache-settings)에 필요합니다.

이전 YAML 예제는 [사용자 정의 작업 이름](_index.md#user-defined-job-names)을 사용합니다.

### 여러 브라우저 탭에서 개인 GitLab Pages 사이트에 액세스할 때 `401` 오류 {#401-error-when-accessing-private-gitlab-pages-sites-in-multiple-browser-tabs}

사전 인증 없이 두 개의 서로 다른 탭에서 동시에 개인 Pages URL에 액세스하려고 하면 각 탭에 대해 두 개의 다른 `state` 값이 반환됩니다. 그러나 Pages 세션에서는 지정된 클라이언트에 대해 가장 최근의 `state` 값만 저장됩니다. 결과적으로 자격 증명을 제출한 후 탭 중 하나에서 `401 Unauthorized` 오류가 반환됩니다.

`401` 오류를 해결하려면 페이지를 새로 고칩니다.

### `pages:deploy` 작업 실패 {#failing-pagesdeploy-job}

GitLab Pages로 배포하려면 루트 콘텐츠 디렉터리에 비어있지 않은 `index.html` 파일이 포함되어 있어야 하거나 `pages:deploy` 작업이 실패합니다.

콘텐츠 디렉터리는 기본적으로 `public/`이거나 `.gitlab-ci.yml` 파일의 `pages.publish` 키워드로 지정된 디렉터리입니다.
