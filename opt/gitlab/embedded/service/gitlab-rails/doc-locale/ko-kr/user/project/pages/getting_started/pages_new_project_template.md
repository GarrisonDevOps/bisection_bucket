---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 프로젝트 템플릿에서 GitLab Pages 웹사이트 만들기
description: 정적 사이트 생성기를 위한 프로젝트 템플릿에서 GitLab Pages 웹사이트를 만듭니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab은 가장 인기 있는 정적 사이트 생성기(SSGs)용 템플릿을 제공합니다. 템플릿에서 새 프로젝트를 만들고 CI/CD 파이프라인을 실행하여 Pages 웹사이트를 생성할 수 있습니다.

GitLab Pages를 테스트하거나 Pages 사이트를 생성하도록 이미 구성된 새 프로젝트를 시작하려면 템플릿을 사용합니다.

1. 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **템플릿에서 만들기**를 선택합니다.
1. **Pages**로 시작하는 템플릿 중 하나 옆에서 **템플릿 사용**을 선택합니다.
1. 양식을 완성하고 **프로젝트 생성**을 선택합니다.
1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택하고 **새 파이프라인**을 선택하여 GitLab CI/CD가 사이트를 빌드하고 배포하도록 트리거합니다.

파이프라인이 완료되면 **배포** > **Pages**로 이동하여 Pages 웹사이트의 링크를 찾습니다.

리포지토리에 푸시되는 모든 변경 사항에 대해 GitLab CI/CD는 새 파이프라인을 실행하고 변경 사항을 Pages 사이트에 즉시 게시합니다.

사이트를 위해 생성된 HTML 및 기타 자산을 보려면 [작업 아티팩트 다운로드](../../../../ci/jobs/job_artifacts.md#download-job-artifacts)합니다.

## 프로젝트 템플릿 {#project-templates}

{{< history >}}

- GitLab 18.0에서 프로젝트 템플릿에서 다음 템플릿을 [제거](https://gitlab.com/groups/gitlab-org/-/epics/13847)했습니다: [`Bridgetown`](https://gitlab.com/pages/bridgetown), [`Gatsby`](https://gitlab.com/pages/gatsby), [`Hexo`](https://gitlab.com/pages/hexo), [`Middleman`](https://gitlab.com/pages/middleman), `Netlify/GitBook`, [`Netlify/Hexo`](https://gitlab.com/pages/nfhexo), [`Netlify/Hugo`](https://gitlab.com/pages/nfhugo), [`Netlify/Jekyll`](https://gitlab.com/pages/nfjekyll), [`Netlify/Plain HTML`](https://gitlab.com/pages/nfplain-html), 및 [`Pelican`](https://gitlab.com/pages/pelican).

{{< /history >}}

GitLab은 이 프레임워크에 대한 템플릿 프로젝트를 유지합니다:

| 영역          | 프레임워크                                           | 사용 가능한 프로젝트 템플릿 |
|----------------|-----------------------------------------------------|-----------------------------|
| **Go**         | [`hugo`](https://gitlab.com/pages/hugo)             | Pages/Hugo                  |
| **마크다운**   | [`astro`](https://gitlab.com/pages/astro)           | Pages/Astro                 |
| **마크다운**   | [`docusaurus`](https://gitlab.com/pages/docusaurus) | Pages/Docusaurus            |
| **순수 HTML** | [`plain-html`](https://gitlab.com/pages/plain-html) | Pages/Plain HTML            |
| **React**      | [`next.js`](https://gitlab.com/pages/nextjs)        | Pages/Next.js               |
| **Ruby**       | [`jekyll`](https://gitlab.com/pages/jekyll)         | Pages/Jekyll                |
| **Vue.js**     | [`nuxt`](https://gitlab.com/pages/nuxt)             | Pages/Nuxt                  |
