---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Créer un site web GitLab Pages à partir d'un modèle de projet"
description: "Créer un site web GitLab Pages à partir d'un modèle de projet pour un générateur de site statique."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab fournit des modèles pour les générateurs de sites statiques (SSG) les plus populaires. Vous pouvez créer un nouveau projet à partir d'un modèle et exécuter le pipeline CI/CD pour générer un site web Pages.

Utilisez un modèle lorsque vous souhaitez tester GitLab Pages ou démarrer un nouveau projet déjà configuré pour générer un site Pages.

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer à partir d'un modèle**.
1. En regard de l'un des modèles commençant par **Pages**, sélectionnez **Utiliser un modèle**.
1. Remplissez le formulaire et sélectionnez **Créer le projet**.
1. Dans la barre latérale gauche, sélectionnez **Version** > **Pipelines** et sélectionnez **Nouveau pipeline** pour déclencher GitLab CI/CD afin de compiler et de déployer votre site.

Une fois le pipeline terminé, accédez à **Déployer** > **Pages** pour trouver le lien vers votre site web Pages.

Pour chaque modification poussée vers votre dépôt, GitLab CI/CD exécute un nouveau pipeline qui publie immédiatement vos modifications sur le site Pages.

Pour afficher le HTML et les autres ressources créées pour le site, [téléchargez les artefacts de job](../../../../ci/jobs/job_artifacts.md#download-job-artifacts).

## Modèles de projet {#project-templates}

{{< history >}}

- [Suppression](https://gitlab.com/groups/gitlab-org/-/epics/13847) des modèles suivants des modèles de projet dans GitLab 18.0 : [`Bridgetown`](https://gitlab.com/pages/bridgetown), [`Gatsby`](https://gitlab.com/pages/gatsby), [`Hexo`](https://gitlab.com/pages/hexo), [`Middleman`](https://gitlab.com/pages/middleman), `Netlify/GitBook`, [`Netlify/Hexo`](https://gitlab.com/pages/nfhexo), [`Netlify/Hugo`](https://gitlab.com/pages/nfhugo), [`Netlify/Jekyll`](https://gitlab.com/pages/nfjekyll), [`Netlify/Plain HTML`](https://gitlab.com/pages/nfplain-html) et [`Pelican`](https://gitlab.com/pages/pelican).

{{< /history >}}

GitLab maintient des projets de modèles pour ces frameworks :

| Domaine          | Framework                                           | Modèles de projet disponibles |
|----------------|-----------------------------------------------------|-----------------------------|
| **Go**         | [`hugo`](https://gitlab.com/pages/hugo)             | Pages/Hugo                  |
| **Markdown**   | [`astro`](https://gitlab.com/pages/astro)           | Pages/Astro                 |
| **Markdown**   | [`docusaurus`](https://gitlab.com/pages/docusaurus) | Pages/Docusaurus            |
| **Plain HTML** | [`plain-html`](https://gitlab.com/pages/plain-html) | Pages/Plain HTML            |
| **React**      | [`next.js`](https://gitlab.com/pages/nextjs)        | Pages/Next.js               |
| **Ruby**       | [`jekyll`](https://gitlab.com/pages/jekyll)         | Pages/Jekyll                |
| **Vue.js**     | [`nuxt`](https://gitlab.com/pages/nuxt)             | Pages/Nuxt                  |
