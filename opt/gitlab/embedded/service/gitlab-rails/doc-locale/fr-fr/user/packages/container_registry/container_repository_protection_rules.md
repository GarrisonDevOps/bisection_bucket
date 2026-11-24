---
stage: Container
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
gitlab_dedicated: yes
title: Dépôts de conteneurs protégés
description: Les dépôts de conteneurs protégés dans GitLab limitent les rôles utilisateurs autorisés à pousser ou supprimer des images.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/463669) dans GitLab 16.7 [avec le feature flag](../../../administration/feature_flags/_index.md) `container_registry_protected_containers`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md).
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/429074) dans GitLab 17.8.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/480385) dans GitLab 17.8. Le feature flag `container_registry_protected_containers` a été supprimé.

{{< /history >}}

Par défaut, tout utilisateur disposant du rôle Developer, Maintainer ou Owner peut pousser et supprimer des images de conteneurs vers ou depuis des dépôts de conteneurs. Protégez un dépôt de conteneurs pour restreindre les utilisateurs autorisés à apporter des modifications aux images de conteneurs dans votre dépôt de conteneurs.

Lorsqu'un dépôt de conteneurs est protégé, le comportement par défaut applique ces restrictions au dépôt de conteneurs et à ses images :

| Action                                                                                   | Rôle minimum         |
|------------------------------------------------------------------------------------------|----------------------|
| Protéger un dépôt de conteneurs et ses images de conteneurs.                                 | Le rôle Maintainer. |
| Pousser ou créer une nouvelle image dans un dépôt de conteneurs.                                    | Le rôle défini dans le paramètre [**Niveau d'accès minimum pour la poussée**](#create-a-container-repository-protection-rule). |
| Pousser ou mettre à jour une image existante dans un dépôt de conteneurs.                              | Le rôle défini dans le paramètre [**Niveau d'accès minimum pour la poussée**](#create-a-container-repository-protection-rule). |
| Pousser, créer ou mettre à jour une image existante dans un dépôt de conteneurs avec un jeton de déploiement. | non applicable. Les jetons de déploiement peuvent être utilisés avec des dépôts non protégés, mais ne peuvent pas être utilisés pour pousser des images vers des dépôts de conteneurs protégés, quelle que soit leur portée. |

Vous pouvez utiliser un caractère générique (`*`) pour protéger plusieurs dépôts de conteneurs avec la même règle de protection de conteneurs. Par exemple, vous pouvez protéger différents dépôts de conteneurs contenant des images de conteneurs temporaires créées pendant un pipeline CI/CD.

Le tableau suivant contient des exemples de règles de protection de conteneurs correspondant à plusieurs dépôts de conteneurs :

| Schéma de chemin avec caractère générique | Exemples de dépôts de conteneurs correspondants |
|----------------------------|-----------------------------------------|
| `group/container-*`        | `group/container-prod`, `group/container-prod-sha123456789` |
| `group/*container`         | `group/container`, `group/prod-container`, `group/prod-sha123456789-container` |
| `group/*container*`        | `group/container`, `group/prod-sha123456789-container-v1` |

Vous pouvez appliquer plusieurs règles de protection au même dépôt de conteneurs. Un dépôt de conteneurs est protégé si au moins une règle de protection correspond.

## Créer une règle de protection de dépôt de conteneurs {#create-a-container-repository-protection-rule}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire.

Pour créer une règle de protection :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Développez **Registre de conteneurs**.
1. Sous **Dépôts de conteneurs protégés**, sélectionnez **Ajouter une règle de protection**.
1. Remplissez les champs :
   - **Schéma de chemin d'accès au dépôt** est le chemin d'accès au dépôt de conteneurs que vous souhaitez protéger. Le schéma peut inclure un caractère générique (`*`).
   - **Niveau d'accès minimum pour la poussée** décrit le niveau d'accès minimum requis pour pousser (créer ou mettre à jour) vers le chemin d'accès au dépôt de conteneurs protégé.
1. Sélectionnez **Protéger**.

La règle de protection est créée et le dépôt de conteneurs est désormais protégé.

## Supprimer une règle de protection de dépôt de conteneurs {#delete-a-container-repository-protection-rule}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/146622) dans GitLab 17.0.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire.

Pour supprimer une règle de protection :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Développez **Registre de conteneurs**.
1. Sous **Dépôts de conteneurs protégés**, à côté de la règle de protection que vous souhaitez supprimer, sélectionnez **Supprimer** ({{< icon name="remove" >}}).
1. Dans la boîte de dialogue de confirmation, sélectionnez **Supprimer**.

La règle de protection est supprimée et le dépôt de conteneurs n'est plus protégé.
