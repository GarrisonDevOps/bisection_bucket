---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Pages 리디렉션
description: Netlify 스타일 규칙을 사용하여 GitLab Pages 사이트에 대한 URL 리디렉션 및 재작성을 구성합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Pages에서 [Netlify 스타일](https://docs.netlify.com/manage/routing/redirects/overview/#syntax-for-the-redirects-file) HTTP 리디렉션을 사용하여 한 URL을 다른 URL로 전달하도록 규칙을 구성할 수 있습니다.

Netlify에서 제공하는 모든 [특수 옵션](https://docs.netlify.com/manage/routing/redirects/redirect-options/)이 지원되지는 않습니다.

| 기능                                           | 지원됨              | 예제 |
|---------------------------------------------------|------------------------|---------|
| [리디렉션(`301`, `302`)](#redirects)            | {{< yes >}} | `/wardrobe.html /narnia.html 302` |
| [재작성(`200`)](#rewrites)                     | {{< yes >}} | `/* / 200` |
| [스플렛](#splats)                                 | {{< yes >}} | `/news/*  /blog/:splat` |
| [자리 표시자](#placeholders)                     | {{< yes >}} | `/news/:year/:month/:date /blog-:year-:month-:date.html` |
| `200` 이외의 재작성                       | {{< no >}} | `/en/* /en/404.html 404` |
| 쿼리 매개변수                                  | {{< no >}} | `/store id=:id  /blog/:id  301` |
| 강제([숨김](https://docs.netlify.com/manage/routing/redirects/rewrites-proxies/#shadowing)) | {{< no >}} | `/app/  /app/index.html  200!` |
| [도메인 수준 리디렉션](#domain-level-redirects) | {{< yes >}} | `http://blog.example.com/* https://www.example.com/blog/:splat 301` |
| 국가 또는 언어별 리디렉션                   | {{< no >}} | `/  /anz     302  Country=au,nz` |
| 역할별 리디렉션                                  | {{< no >}} | `/admin/*  200!  Role=admin` |

> [!note]
> [매칭 동작 테스트 사례](https://gitlab.com/gitlab-org/gitlab-pages/-/blob/master/internal/redirects/matching_test.go)는 GitLab이 규칙 매칭을 어떻게 구현하는지 자세히 이해하기 위한 좋은 리소스입니다. 커뮤니티 기여는 이 테스트 모음에 포함되지 않은 모든 엣지 케이스에 대해 환영합니다!

## 리디렉션 생성 {#create-redirects}

리디렉션을 생성하려면 GitLab Pages 사이트의 `public/` 디렉터리에 `_redirects` 이름의 구성 파일을 생성합니다.

- 모든 경로는 슬래시 `/`로 시작해야 합니다.
- [상태 코드](#http-status-codes)가 제공되지 않으면 기본 상태 코드 `301`가 적용됩니다.
- `_redirects` 파일에는 파일 크기 제한 및 프로젝트당 최대 규칙 수가 있으며 인스턴스에 대해 구성됩니다. 구성된 최대값의 첫 번째 매칭 규칙만 처리됩니다. 기본 파일 크기 제한은 64KB이고 기본 최대 규칙 수는 1,000입니다.
- GitLab Pages 사이트에서 기본 도메인 이름(예: `namespace.gitlab.io/project-slug`)을 사용하면 모든 규칙 앞에 경로를 접두사로 붙여야 합니다:

  ```plaintext
  /project-slug/wardrobe.html /project-slug/narnia.html 302
  ```

- GitLab Pages 사이트에서 [사용자 지정 도메인](custom_domains_ssl_tls_certification/_index.md)을 사용하면 프로젝트 경로 접두사가 필요하지 않습니다. 예를 들어 사용자 지정 도메인이 `example.com`인 경우 `_redirects` 파일은 다음과 같이 표시됩니다:

  ```plaintext
  /wardrobe.html /narnia.html 302
  ```

## 파일이 리디렉션을 재정의 {#files-override-redirects}

파일은 리디렉션보다 우선합니다. 파일이 디스크에 있으면 GitLab Pages는 리디렉션 대신 파일을 제공합니다. `hello.html` 및 `world.html` 파일이 있고 `_redirects` 파일에 다음 줄이 포함된 경우 `hello.html`이(가) 있으므로 리디렉션은 무시됩니다:

```plaintext
/project-slug/hello.html /project-slug/world.html 302
```

GitLab은 이 동작을 변경하는 Netlify [강제 옵션](https://docs.netlify.com/manage/routing/redirects/rewrites-proxies/#shadowing)을 지원하지 않습니다.

## HTTP 상태 코드 {#http-status-codes}

상태 코드가 제공되지 않으면 기본 상태 코드 `301`이(가) 적용되지만 명시적으로 자신의 코드를 설정할 수 있습니다. 다음 HTTP 코드가 지원됩니다:

- **301**: 영구 리디렉션.
- **302**: 임시 리디렉션.
- **200**: 성공한 HTTP 요청에 대한 표준 응답입니다. Pages는 `to` 규칙의 콘텐츠를 제공하며 주소 표시줄의 URL을 변경하지 않습니다.

## 리디렉션 {#redirects}

리디렉션을 생성하려면 `from` 경로, `to` 경로 및 [HTTP 상태 코드](#http-status-codes)를 포함하는 규칙을 추가합니다:

```plaintext
# 301 permanent redirect
/old/file.html /new/file.html 301

# 302 temporary redirect
/old/another_file.html /new/another_file.html 302
```

## 재작성 {#rewrites}

`200` 상태 코드를 제공하여 요청이 `from`과(와) 매칭될 때 `to` 경로의 콘텐츠를 제공합니다:

```plaintext
/old/file.html /new/file.html 200
```

이 상태 코드를 [스플렛 규칙](#splats)과 함께 사용하여 URL을 동적으로 재작성할 수 있습니다.

## 도메인 수준 리디렉션 {#domain-level-redirects}

{{< history >}}

- GitLab 16.8에서 `FF_ENABLE_DOMAIN_REDIRECT` [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab-pages/-/merge_requests/936)되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-com/gl-infra/k8s-workloads/gitlab-com/-/merge_requests/3395) \- GitLab 16.9
- [GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab-pages/-/issues/1087) \- GitLab 16.10
- GitLab 17.4에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab-pages/-/issues/1097)하게 되었습니다. 기능 플래그 `FF_ENABLE_DOMAIN_REDIRECT`이 제거되었습니다.

{{< /history >}}

도메인 수준 리디렉션을 생성하려면 `http://` 또는 `https://`로 시작하는 도메인 수준 경로를 다음 중 하나에 추가합니다:

- `to` 경로만.
- `from` 및 `to` 경로.

지원되는 [HTTP 상태 코드](#http-status-codes)는 `301` 및 `302`입니다:

```plaintext
# 301 permanent redirect
http://blog.example.com/file_1.html https://www.example.com/blog/file_1.html 301
/file_2.html https://www.example.com/blog/file_2.html 301

# 302 temporary redirect
http://blog.example.com/file_3.html https://www.example.com/blog/file_3.html 302
/file_4.html https://www.example.com/blog/file_4.html 302
```

도메인 수준 리디렉션을 [스플렛 규칙](#splats)(스플렛 자리 표시자 포함)과 함께 사용하여 URL 경로를 동적으로 재작성할 수 있습니다.

## 스플렛 {#splats}

규칙의 `from` 경로에 별표(`*`)가 있으면 스플렛으로 알려져 있으며 요청된 경로의 시작, 중간 또는 끝에서 모든 항목과 매칭됩니다. 이 예제는 `/old/` 이후의 모든 항목과 매칭되고 `/new/file.html`로 재작성합니다:

```plaintext
/old/* /new/file.html 200
```

### 스플렛 자리 표시자 {#splat-placeholders}

규칙의 `from` 경로에서 `*`과(와) 매칭된 콘텐츠를 `:splat` 자리 표시자를 사용하여 `to` 경로에 주입할 수 있습니다:

```plaintext
/old/* /new/:splat 200
```

이 예제에서 `/old/file.html`에 대한 요청은 `200` 상태 코드로 `/new/file.html`의 콘텐츠를 제공합니다.

규칙의 `from` 경로에 여러 스플렛이 포함된 경우 첫 번째 스플렛 매칭의 값이 `to` 경로의 모든 `:splat`를 대체합니다.

### 스플렛 매칭 동작 {#splat-matching-behavior}

스플렛은 "탐욕적"이며 최대한 많은 문자와 매칭됩니다:

```plaintext
/old/*/file /new/:splat/file 301
```

이 예제에서 규칙은 `/old/a/b/c/file`를 `/new/a/b/c/file`로 리디렉션합니다.

스플렛도 빈 문자열과 매칭되므로 이전 규칙은 `/old/file`를 `/new/file`로 리디렉션합니다.

### 스플렛으로 파일 확장자 매칭 {#match-a-file-extension-with-a-splat}

스플렛은 `from` 경로의 파일 확장자 바로 앞에 올 수 있습니다. 예를 들어 이 규칙은 모든 `.html` 요청과 매칭되고 후행 슬래시가 있고 확장자가 없는 동일한 경로로 리디렉션합니다:

```plaintext
/*.html /:splat/ 301
```

이 예제에서 `/page.html`에 대한 요청은 `/page/`로 리디렉션되고 `/docs/page.html`에 대한 요청은 `/docs/page/`로 리디렉션됩니다.

### 루트 `index.html`에 대한 모든 요청을 재작성 {#rewrite-all-requests-to-a-root-indexhtml}

단일 페이지 애플리케이션(SPA)은 클라이언트 측 경로를 사용하여 자체 라우팅을 수행하는 경우가 많습니다. 이러한 애플리케이션의 경우 루트 `index.html`로 모든 요청을 재작성하여 라우팅 논리가 JavaScript 애플리케이션에서 처리되도록 합니다.

`index.html`로 요청을 재작성하려면:

1. 이 `_redirects` 규칙을 추가합니다:

   ```plaintext
   /* /index.html 200
   ```

1. 단일 페이지 애플리케이션이 병렬 배포와 함께 작동하도록 하려면 경로 접두사를 포함하도록 리디렉션 규칙을 편집합니다:

   ```plaintext
   /project/base/<prefix>/* /project/base/<prefix>/index.html 200
   ```

   `<prefix>`을(를) 경로 접두사 값으로 바꿉니다.

## 자리 표시자 {#placeholders}

규칙의 자리 표시자를 사용하여 요청된 URL의 일부를 매칭하고 새 URL로 재작성하거나 리디렉션할 때 이러한 매칭을 사용합니다.

자리 표시자는 `:` 문자 뒤에 문자 문자열(`[a-zA-Z]+`)이 오는 형식으로 `from` 및 `to` 경로 모두에 있습니다:

```plaintext
/news/:year/:month/:date/:slug /blog/:year-:month-:date-:slug 200
```

이 규칙은 Pages가 `/news/2021/08/12/file.html`에 대한 요청에 응답하여 `200` 상태 코드로 `/blog/2021-08-12-file.html`의 콘텐츠를 제공하도록 합니다.

### 자리 표시자 매칭 동작 {#placeholder-matching-behavior}

[스플렛](#splats)과 비교하여 자리 표시자는 매칭하는 콘텐츠 양이 더 제한됩니다. 자리 표시자는 전방 슬래시(`/`) 사이의 텍스트와 매칭되므로 자리 표시자를 사용하여 단일 경로 세그먼트와 매칭합니다.

또한 자리 표시자는 빈 문자열과 매칭되지 않습니다. 다음과 같은 규칙은 `/old/file`과(와) 같은 요청 URL과 매칭되지 않습니다:

```plaintext
/old/:path /new/:path
```

## 리디렉션 규칙 디버깅 {#debug-redirect-rules}

리디렉션이 예상대로 작동하지 않거나 리디렉션 구문을 확인하려면 `[your pages url]/_redirects`을(를) 방문합니다. `_redirects` 파일이 직접 제공되지 않지만 브라우저에 리디렉션 규칙의 번호가 매겨진 목록과 규칙이 유효한지 무효한지가 표시됩니다:

```plaintext
11 rules
rule 1: valid
rule 2: valid
rule 3: error: splats are not supported
rule 4: valid
rule 5: error: placeholders are not supported
rule 6: valid
rule 7: error: no domain-level redirects to outside sites
rule 8: error: url path must start with forward slash /
rule 9: error: no domain-level redirects to outside sites
rule 10: valid
rule 11: valid
```

## Netlify 구현과의 차이점 {#differences-from-netlify-implementation}

지원되는 대부분의 `_redirects` 규칙은 GitLab과 Netlify에서 동일하게 작동합니다. 그러나 몇 가지 작은 차이점이 있습니다:

- **모든 규칙 URL은 슬래시로 시작해야 합니다**:

  Netlify는 URL을 슬래시로 시작하도록 요구하지 않습니다:

  ```plaintext
  # Valid in Netlify, invalid in GitLab
  */path /new/path 200
  ```

  GitLab은 모든 URL이 슬래시로 시작하도록 유효성 검사합니다. 이전 예제의 유효한 동등물입니다:

  ```plaintext
  # Valid in both Netlify and GitLab
  /old/path /new/path 200
  ```

- **모든 자리 표시자 값이 채워집니다**:

  Netlify는 `to` 경로에 나타나는 자리 표시자 값만 채웁니다:

  ```plaintext
  /old /new/:placeholder
  ```

  `/old`에 대한 요청이 주어진 경우:

  - Netlify는 `/new/:placeholder`(리터럴 `:placeholder` 포함)로 리디렉션합니다.
  - GitLab은 `/new/`로 리디렉션합니다.
