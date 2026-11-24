---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Paquets et registres
description: "Gestion des paquets, registre de conteneurs, stockage des artefacts et gestion des dépendances."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le [registre de paquets](package_registry/_index.md) GitLab fait office de registre privé ou public pour une grande variété de gestionnaires de paquets courants. Vous pouvez publier et partager des paquets, qui peuvent être utilisés comme dépendance dans des projets en aval.

## Registre de conteneurs {#container-registry}

Le [Container Registry](container_registry/_index.md) GitLab est un registre sécurisé et privé pour les images de conteneurs. Il repose sur des logiciels open source et est entièrement intégré à GitLab. Utilisez GitLab CI/CD pour créer et publier des images. Utilisez l'[API](../../api/container_registry.md) GitLab pour gérer le registre au sein de vos groupes et projets.

## Registre de modules Terraform {#terraform-module-registry}

Le [Registre de modules Terraform](terraform_module_registry/_index.md) GitLab est un registre sécurisé et privé pour les modules Terraform. Vous pouvez utiliser GitLab CI/CD pour créer et publier des modules.

## Registre virtuel {#virtual-registry}

Le [registre virtuel](virtual_registry/_index.md) GitLab offre des fonctionnalités avancées de mise en cache, de proxy et de distribution pour améliorer la gestion des paquets provenant de registres externes dans GitLab.

## Proxy de dépendances {#dependency-proxy}

Le [proxy de dépendances](dependency_proxy/_index.md) est un proxy local pour les images et les paquets fréquemment utilisés en amont.
