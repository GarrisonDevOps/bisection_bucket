---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Infrastructure as Code avec OpenTofu et GitLab
description: "Gestion d'infrastructure, versionnage, automatisation, stockage d'état et modules."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour gérer votre infrastructure avec GitLab, vous pouvez utiliser l'intégration avec OpenTofu pour définir des ressources que vous pouvez versionner, réutiliser et partager :

- Gérez les composants de bas niveau tels que les ressources de calcul, de stockage et de réseau.
- Gérez les composants de haut niveau tels que les entrées DNS et les fonctionnalités SaaS.
- Utilisez GitLab comme stockage d'état OpenTofu.
- Stockez et utilisez des modules OpenTofu pour simplifier les patterns d'infrastructure courants et complexes.
- Intégrez les déploiements GitOps et les workflows Infrastructure as Code (IaC).

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez [une présentation vidéo](https://www.youtube.com/watch?v=iGXjUrkkzDI) des fonctionnalités que GitLab propose avec l'intégration avec OpenTofu.

Les exemples suivants utilisent principalement OpenTofu, mais ils peuvent également fonctionner avec Terraform.

## Prise en charge de Terraform et OpenTofu {#terraform-and-opentofu-support}

GitLab s'intègre à la fois avec Terraform et OpenTofu. La plupart des fonctionnalités sont entièrement compatibles, notamment :

- [État Terraform/OpenTofu géré par GitLab](terraform_state.md)
- [Intégration de Terraform/OpenTofu dans les merge requests](mr_integration.md)
- [Registre de modules Terraform/OpenTofu](../../packages/terraform_module_registry/_index.md)

Par souci de simplicité, la documentation GitLab fait principalement référence à OpenTofu. Toutefois, les différences entre l'intégration de Terraform et celle d'OpenTofu sont documentées.

## Démarrage rapide d'un projet OpenTofu dans des pipelines {#quickstart-an-opentofu-project-in-pipelines}

OpenTofu peut s'intégrer à toutes les fonctionnalités GitLab spécifiques à Terraform grâce au composant CI/CD GitLab OpenTofu.

Vous pouvez ajouter un workflow *validate*, *plan* et *apply* à votre pipeline en incluant le composant :

```yaml
include:
  - component: gitlab.com/components/opentofu/validate-plan-apply@<VERSION>
    inputs:
      version: <VERSION>
      opentofu_version: <OPENTOFU_VERSION>
      root_dir: terraform/
      state_name: production

stages: [validate, build, deploy]
```

Pour plus d'informations sur les templates, les entrées et la manière d'utiliser le composant CI/CD OpenTofu, consultez le [README du composant CI/CD OpenTofu](https://gitlab.com/components/opentofu).

## Créer et héberger vos propres templates CI/CD Terraform {#build-and-host-your-own-terraform-cicd-templates}

Bien que GitLab ne distribue plus les templates CI/CD Terraform ni `terraform-images` (les images de job sous-jacentes, incluant `terraform`), vous pouvez toujours utiliser Terraform dans les pipelines GitLab.

Pour savoir comment créer et héberger vos propres templates et images, consultez le projet [Terraform Images](https://gitlab.com/gitlab-org/terraform-images).

## Sujets connexes {#related-topics}

- Utilisez GitLab comme [Registre de modules Terraform/OpenTofu](../../packages/terraform_module_registry/_index.md).
- Pour stocker les fichiers d'état dans un stockage local ou dans un store distant, utilisez l'[état Terraform/OpenTofu géré par GitLab](terraform_state.md).
- Pour collaborer sur les modifications de code Terraform et les workflows IaC, utilisez l'[intégration de Terraform dans les merge requests](mr_integration.md).
- Pour gérer les ressources GitLab telles que les utilisateurs, les groupes et les projets, utilisez le [fournisseur Terraform GitLab](https://gitlab.com/gitlab-org/terraform-provider-gitlab). La documentation du fournisseur Terraform GitLab est disponible sur [le site de documentation Terraform](https://registry.terraform.io/providers/gitlabhq/gitlab/latest/docs).
- [Créer un nouveau cluster sur Amazon Elastic Kubernetes Service (EKS)](../clusters/connect/new_eks_cluster.md).
- [Résoudre les problèmes](troubleshooting.md) liés à GitLab et Terraform.
- Consultez [les images contenant le script shell `gitlab-terraform`](https://gitlab.com/gitlab-org/terraform-images).
