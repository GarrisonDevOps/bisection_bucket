---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Create a GitLab Pages deployment for a static site
description: Deploy a static site or framework-based application to GitLab Pages with a guided UI form.
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Create a GitLab Pages deployment to convert your static site or framework into a website hosted on GitLab.
Through a step-by-step form, GitLab:

- Generates a custom CI/CD configuration based on your project setup.
- Creates a `.gitlab-ci.yml` file configured for GitLab Pages deployments.
- Submits the changes through a merge request for your review.
- Deploys your website automatically when the merge request is merged.

With the Pages UI, you can deploy a static site or framework-based application.

## Prerequisites

- Your app must [output files to the `public` folder](../public_folder.md). If you create
  this folder during the build pipeline, you do not need to commit it to Git.

  > [!warning]
  > This step is important. Ensure your files are in a root-level `public` folder.

- You must have a project that either:
  - Generates static sites or a client-rendered single-page application (SPA),
    like [Eleventy](https://www.11ty.dev), [Astro](https://astro.build), or [Jekyll](https://jekyllrb.com).
  - Contains a framework configured for static output, such as [Next.js](https://nextjs.org),
    [Nuxt](https://nuxt.com), or [SvelteKit](https://kit.svelte.dev).
- GitLab Pages must be turned on for the project. (To turn it on, go to {{< ui text="Settings" >}} > {{< ui text="General" >}},
  expand {{< ui text="Visibility, project features, permissions" >}}, and turn on the {{< ui text="ProjectSettings|Pages" >}} toggle.)

## Create the Pages deployment

To complete the setup and generate a GitLab Pages deployment:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your project.
1. In the left sidebar, select {{< ui text="Navigation|Deploy" >}} > {{< ui text="Pages" >}}.

   A **Get started with GitLab Pages** form appears. If this form is not available,
   see [Troubleshooting](#if-the-get-started-with-gitlab-pages-form-is-not-available).
1. For **Step 1**, enter an image name. You can also [set a custom folder to be deployed with Pages](../introduction.md#customize-the-default-folder).
1. Select {{< ui text="Next" >}}.
1. For **Step 2**, enter your installation steps. If your framework's build process does not
   need one of the provided build commands, you can either:
   - Skip the step by selecting {{< ui text="Next" >}}.
   - Enter `:` (the bash "do nothing" command) if you still want to incorporate that
     step's boilerplate into your `.gitlab-ci.yml` file.
1. Select {{< ui text="Next" >}}.
1. For **Step 3**, enter scripts that indicate how to build your application.
1. Select {{< ui text="Next" >}}.
1. Optional. Edit the generated `.gitlab-ci.yml` file as needed.
1. For **Step 4**, add a commit message and select {{< ui text="PipelineWizard|Commit" >}}. This commit triggers your first
   GitLab Pages deployment.

To view the running pipeline, go to {{< ui text="Navigation|Build" >}} > {{< ui text="Pipelines" >}}. When the pipeline succeeds,
your Pages site is deployed and accessible.

To view the artifacts that were created during the deployment, view the job,
and on the right side, select {{< ui text="Download artifacts" >}}.

## View deployment URL

After your pipeline completes successfully:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your project.
1. In the left sidebar, select {{< ui text="Navigation|Deploy" >}} > {{< ui text="Pages" >}}.
1. In {{< ui text="Pages|Deployments" >}}, you can view your active deployment URL.
1. To visit your deployed GitLab Pages site, select the URL.

> [!note]
> It might take a few minutes for your site to become available after the pipeline completes.

## Troubleshooting

### If the `Get started with GitLab Pages` form is not available

The `Get started with GitLab Pages` form is not available if you:

- Deployed a GitLab Pages site before.
- Committed `.gitlab-ci.yml` through the forms at least one time.

To fix this issue:

- If the message {{< ui text="GitLabPages|Waiting for the Pages Pipeline to complete" >}} appears, select
  {{< ui text="GitLabPages|Start over" >}} to start the form again.
- If your project has previously deployed GitLab Pages successfully,
  [manually update](pages_from_scratch.md) your `.gitlab-ci.yml` file.
