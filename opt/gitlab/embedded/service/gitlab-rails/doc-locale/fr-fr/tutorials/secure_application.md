---
stage: Tutorials
group: Tutorials
info: For assistance with this tutorials page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments-to-other-projects-and-subjects>.
description: Analyse des dépendances et conformité.
title: 'Tutoriels : sécuriser votre application et vérifier la conformité'
---

GitLab peut analyser votre application pour détecter les vulnérabilités de sécurité et vérifier qu'elle répond aux exigences de conformité.

## Découvrir les fondamentaux de la sécurité {#learn-security-fundamentals}

Commencez ici pour comprendre les bases de la sécurité dans GitLab.

| Sujet | Description | Recommandé pour les débutants |
|-------|-------------|--------------------|
| [GitLab Security Essentials](https://university.gitlab.com/learning-paths/gitlab-security-essentials-v100) | Découvrez les fonctionnalités de sécurité essentielles de GitLab dans ce cours en autonomie. Durée estimée : 6 heures. | {{< icon name="star" >}}  |

## Configurer la détection de sécurité de base {#set-up-basic-security-detection}

Créez des analyses fondamentales pour identifier les vulnérabilités.

| Sujet | Description | Recommandé pour les débutants |
|-------|-------------|--------------------|
| [Configurer l'analyse des dépendances](dependency_scanning.md) | Apprenez à détecter les vulnérabilités dans les dépendances d'une application. Durée estimée : 15-20 minutes. | {{< icon name="star" >}} |
| [Configurer l'analyse des dépendances à l'aide de la méthode SBOM](dependency_scanning_by_sbom.md) | Apprenez à détecter les vulnérabilités dans les dépendances d'une application à l'aide de la méthode SBOM. Durée estimée : 15-20 minutes. | {{< icon name="star" >}} |
| [Scanner un conteneur Docker pour détecter des vulnérabilités](container_scanning/_index.md) | Apprenez à utiliser les templates d'analyse de conteneurs pour ajouter l'analyse de conteneurs à vos projets. Durée estimée : 15-20 minutes. | {{< icon name="star" >}} |
| [Guide complet du DAST GitLab](https://about.gitlab.com/blog/comprehensive-guide-to-gitlab-dast/) | Apprenez à configurer le test dynamique de sécurité des applications (DAST), à effectuer des analyses et à mettre en œuvre des politiques de sécurité. Durée estimée : 15-20 minutes. | {{< icon name="star" >}} |

## Se protéger contre l'exposition des secrets {#protect-against-secret-exposure}

Empêchez que des données sensibles soient committées dans votre dépôt.

| Sujet | Description | Recommandé pour les débutants |
|-------|-------------|--------------------|
| [Protéger votre projet avec la protection contre les pushs de secrets](../user/application_security/secret_detection/push_protection_tutorial.md) | Activez la protection push contre les secrets dans votre projet. Durée estimée : 5-10 minutes. | {{< icon name="star" >}} |
| [Détecter les secrets commités dans un projet](../user/application_security/secret_detection/pipeline/tutorial.md) | Apprenez à détecter et à corriger les secrets commités dans le dépôt de votre projet. Durée estimée : 15-20 minutes. | {{< icon name="star" >}} |
| [Supprimer un secret de vos commits](../user/application_security/secret_detection/remove_secrets_tutorial.md) | Apprenez à supprimer un secret de l'historique de vos commits. Durée estimée : 15-20 minutes. | {{< icon name="star" >}} |

## Mettre en œuvre des politiques de sécurité et une gouvernance {#implement-security-policies-and-governance}

Appliquez des exigences de sécurité à l'ensemble de vos projets.

| Sujet | Description | Recommandé pour les débutants |
|-------|-------------|--------------------|
| [Configurer une politique d'exécution de scan](scan_execution_policy/_index.md) | Apprenez à créer une politique d'exécution de scan pour appliquer l'analyse de sécurité à votre projet. Durée estimée : 30-45 minutes. | {{< icon name="star" >}} |
| [Configurer une politique d'exécution de pipeline](pipeline_execution_policy/_index.md) | Apprenez à créer une politique d'exécution de pipeline pour appliquer l'analyse de sécurité à l'ensemble des projets dans le cadre du pipeline. Durée estimée : 30-45 minutes. | {{< icon name="star" >}} |
| [Configurer une politique d'approbation des merge requests](scan_result_policy/_index.md) | Apprenez à configurer une politique d'approbation des merge requests qui effectue des actions en fonction des résultats d'analyse. Durée estimée : 30-45 minutes. | {{< icon name="star" >}} |

## Établir la conformité et le reporting {#establish-compliance-and-reporting}

Répondez aux exigences réglementaires et générez la documentation de conformité.

| Sujet | Description | Recommandé pour les débutants |
|-------|-------------|--------------------|
| [Générer une nomenclature logicielle avec le registre de paquets GitLab](../user/packages/package_registry/tutorial_generate_sbom.md) | Apprenez à générer un SBOM pour l'ensemble des projets d'un groupe. Durée estimée : 1 heure. | {{< icon name="star" >}} |
| [Exporter la liste des dépendances au format SBOM](export_sbom.md) | Apprenez à exporter les dépendances d'une application vers le format SBOM CycloneDX. Durée estimée : 15-20 minutes. | {{< icon name="star" >}} |
