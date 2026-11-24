---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 가장 일반적인 정적 사이트 생성기에 대해 빌드 출력 폴더를 구성하는 방법을 알아봅니다.
title: GitLab Pages 공개 폴더
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

`.gitlab-ci.yml`에서 게시된 폴더를 구성할 수 있습니다. 더 이상 프레임워크 구성을 변경할 필요가 없습니다. 자세한 내용은 [Pages에 배포할 사용자 지정 폴더 설정](introduction.md#customize-the-default-folder)을 참조하세요.

다음 지침에 따라 다음 프레임워크에 대해 `public` 폴더를 구성합니다.

## Eleventy {#eleventy}

Eleventy의 경우 다음 중 하나를 수행해야 합니다:

- Eleventy 빌드 명령에 `--output=public` 플래그를 추가합니다. 예:

  `npx @11ty/eleventy --input=path/to/sourcefiles --output=public`

- 다음을 `.eleventy.js` 파일에 추가합니다:

  ```javascript
  // .eleventy.js
  module.exports = function(eleventyConfig) {
    return {
      dir: {
        output: "public"
      }
    }
  };
  ```

## Astro {#astro}

기본적으로 Astro는 `public` 폴더를 사용하여 정적 자산을 저장합니다. GitLab Pages의 경우 해당 폴더를 먼저 충돌 없는 대체 폴더로 이름을 바꿉니다:

1. 프로젝트 디렉터리에서 다음을 실행합니다:

   ```shell
   mv public static
   ```

1. 이름을 바꾼 폴더에 대해 Astro를 구성하려면 다음을 `astro.config.mjs`에 추가합니다:

   ```javascript
   // astro.config.mjs
   import { defineConfig } from 'astro/config';

   export default defineConfig({
     // GitLab Pages requires exposed files to be located in a folder called "public".
     // This instructs Astro to put the static build output in a folder of that name.
     outDir: 'public',

     // The folder name Astro uses for static files (`public`) is already reserved
     // for the build output. This uses a folder called `static` instead.
     publicDir: 'static',
   });
   ```

## SvelteKit {#sveltekit}

> [!note]
> GitLab Pages는 정적 사이트만 지원합니다. SvelteKit의 경우 [`adapter-static`](https://kit.svelte.dev/docs/adapters#supported-environments-static-sites)을(를) 사용할 수 있습니다.

`adapter-static`을(를) 사용할 때 다음을 `svelte.config.js`에 추가합니다:

```javascript
// svelte.config.js
import adapter from '@sveltejs/adapter-static';

export default {
  kit: {
    adapter: adapter({
      pages: 'public'
    })
  }
};
```

## Next.js {#nextjs}

> [!note]
> GitLab Pages는 정적 사이트만 지원합니다. Next.js의 경우 Next [정적 HTML 내보내기 기능](https://nextjs.org/docs/pages/guides/static-exports)을(를) 사용할 수 있습니다.

[Next.js 13](https://nextjs.org/blog/next-13) 릴리스로 Next.js 작동 방식이 크게 변경되었습니다. 모든 정적 자산을 올바르게 내보낼 수 있도록 다음 `next.config.js`을(를) 사용해야 합니다:

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  images: {
    unoptimized: true,
  },
  assetPrefix: "https://example.gitlab.io/namespace-here/my-gitlab-project/"
}

module.exports = nextConfig
```

예제 `.gitlab-ci.yml`은(는) 다음과 같이 최소한으로 구성될 수 있습니다:

```yaml
create-pages:
  before_script:
    - npm install
  script:
    - npm run build
    - mv out/* public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
```

이전 YAML 예제는 [사용자 지정 작업 이름](_index.md#user-defined-job-names)을(를) 사용합니다.

## Nuxt.js {#nuxtjs}

> [!note]
> GitLab Pages는 정적 사이트만 지원합니다.

기본적으로 Nuxt는 `public` 폴더를 사용하여 정적 자산을 저장합니다. GitLab Pages의 경우 `public` 폴더를 먼저 충돌 없는 대체 폴더로 이름을 바꿉니다:

1. 프로젝트 디렉터리에서 다음을 실행합니다:

   ```shell
   mv public static
   ```

1. 다음을 `nuxt.config.js`에 추가합니다:

   ```javascript
   export default {
     target: 'static',
     generate: {
       dir: 'public'
     },
     dir: {
       // The folder name Nuxt uses for static files (`public`) is already
       // reserved for the build output. This uses a folder called `static` instead.
       public: 'static'
     }
   }
   ```

1. [정적 사이트 생성](https://nuxt.com/docs/getting-started/deployment#static-hosting)을(를) 위해 Nuxt.js 애플리케이션을 구성합니다.

## Vite {#vite}

`vite.config.js`을(를) 업데이트하여 다음을 포함시킵니다:

```javascript
// vite.config.js
export default {
  build: {
    outDir: 'public'
  }
}
```

## Webpack {#webpack}

`webpack.config.js`을(를) 업데이트하여 다음을 포함시킵니다:

```javascript
// webpack.config.js
module.exports = {
  output: {
    path: __dirname + '/public'
  }
};
```

## `public` 폴더를 커밋해야 합니까? {#should-you-commit-the-public-folder}

반드시 그럴 필요는 없습니다. 그러나 GitLab Pages 배포 파이프라인이 실행되면 해당 이름의 [아티팩트](../../../ci/jobs/job_artifacts.md)를 찾습니다. `public` 폴더를 생성하는 작업을 배포 전에 설정하면(예: `npm run build`을(를) 실행하여) 폴더를 커밋할 필요가 없습니다.

로컬로 사이트를 빌드하려면 `public` 폴더를 커밋하고 대신 작업 중에 빌드 단계를 생략할 수 있습니다.
