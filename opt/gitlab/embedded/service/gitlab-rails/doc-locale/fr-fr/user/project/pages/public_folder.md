---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Apprenez à configurer le dossier de sortie de build pour les générateurs de sites statiques les plus courants
title: Dossier public de GitLab Pages
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez configurer le dossier publié dans `.gitlab-ci.yml`. Vous n'avez plus besoin de modifier la configuration de votre framework. Pour plus d'informations, voir [définir un dossier personnalisé à déployer avec Pages](introduction.md#customize-the-default-folder).

Suivez ces instructions pour configurer le dossier `public` pour les frameworks suivants.

## Eleventy {#eleventy}

Pour Eleventy, effectuez l'une des opérations suivantes :

- Ajoutez le flag `--output=public` dans les commandes de build Eleventy, par exemple :

  `npx @11ty/eleventy --input=path/to/sourcefiles --output=public`

- Ajoutez ce qui suit à votre fichier `.eleventy.js` :

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

Par défaut, Astro utilise le dossier `public` pour stocker les ressources statiques. Pour GitLab Pages, renommez d'abord ce dossier en une alternative sans conflit :

1. Dans le répertoire de votre projet, exécutez :

   ```shell
   mv public static
   ```

1. Ajoutez ce qui suit à votre `astro.config.mjs` pour configurer Astro avec le dossier renommé :

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
> GitLab Pages prend en charge uniquement les sites statiques. Pour SvelteKit, vous pouvez utiliser [`adapter-static`](https://kit.svelte.dev/docs/adapters#supported-environments-static-sites).

Lors de l'utilisation de `adapter-static`, ajoutez ce qui suit à votre `svelte.config.js` :

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
> GitLab Pages prend en charge uniquement les sites statiques. Pour Next.js, vous pouvez utiliser la [fonctionnalité d'exportation HTML statique](https://nextjs.org/docs/pages/guides/static-exports) de Next.

Avec la sortie de [Next.js 13](https://nextjs.org/blog/next-13), beaucoup de choses ont changé dans le fonctionnement de Next.js. Vous devez utiliser le `next.config.js` suivant pour que toutes les ressources statiques puissent être exportées correctement :

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

Un exemple de `.gitlab-ci.yml` peut être aussi minimal que :

```yaml
create-pages:
  before_script:
    - npm install
  script:
    - npm run build
    - mv out/* public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
```

L'exemple YAML précédent utilise des [noms de job définis par l'utilisateur](_index.md#user-defined-job-names).

## Nuxt.js {#nuxtjs}

> [!note]
> GitLab Pages prend en charge uniquement les sites statiques.

Par défaut, Nuxt utilise le dossier `public` pour stocker les ressources statiques. Pour GitLab Pages, renommez d'abord le dossier `public` en une alternative sans conflit :

1. Dans le répertoire de votre projet, exécutez :

   ```shell
   mv public static
   ```

1. Ajoutez ce qui suit à votre `nuxt.config.js` :

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

1. Configurez votre application Nuxt.js pour la [génération de site statique](https://nuxt.com/docs/getting-started/deployment#static-hosting).

## Vite {#vite}

Mettez à jour votre `vite.config.js` pour y inclure ce qui suit :

```javascript
// vite.config.js
export default {
  build: {
    outDir: 'public'
  }
}
```

## Webpack {#webpack}

Mettez à jour votre `webpack.config.js` pour y inclure ce qui suit :

```javascript
// webpack.config.js
module.exports = {
  output: {
    path: __dirname + '/public'
  }
};
```

## Devez-vous commiter le dossier `public` ? {#should-you-commit-the-public-folder}

Pas nécessairement. Cependant, lorsque le pipeline de déploiement de GitLab Pages s'exécute, il recherche un [artifact](../../../ci/jobs/job_artifacts.md) portant ce nom. Si vous configurez un job qui crée le dossier `public` avant le déploiement, par exemple en exécutant `npm run build`, il n'est pas nécessaire de commiter le dossier.

Si vous préférez builder votre site localement, vous pouvez commiter le dossier `public` et ignorer l'étape de build pendant le job.
