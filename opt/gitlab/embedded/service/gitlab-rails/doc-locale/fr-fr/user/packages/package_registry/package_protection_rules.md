---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
gitlab_dedicated: yes
title: Paquets protégés
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/416395) dans GitLab 16.5 [avec le feature flag](../../../administration/feature_flags/_index.md) `packages_protected_packages`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md).
- Le paramètre de règle de protection **Push protected up to access level** a été [renommé](https://gitlab.com/gitlab-org/gitlab/-/issues/416382) en **Niveau d'accès minimum pour la poussée** dans GitLab 17.1.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/472655) dans GitLab 17.6. Le feature flag `packages_protected_packages` a été supprimé.
- Les paquets Conan protégés ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/issues/323975) dans GitLab 17.6 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `packages_protected_packages_conan`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md).
- Les paquets Maven protégés ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/issues/323969) dans GitLab 17.9 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `packages_protected_packages_maven`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md).
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/516215) dans GitLab 17.10 [avec le feature flag](../../../administration/feature_flags/_index.md) `packages_protected_packages_delete`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md).
- Les paquets Maven protégés sont devenus [généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/issues/497082) dans GitLab 17.11. Le feature flag `packages_protected_packages_maven` a été supprimé.
- Les paquets Conan protégés sont devenus [généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/issues/497811) dans GitLab 17.11. Le feature flag `packages_protected_packages_conan` a été supprimé.
- Les paquets NuGet protégés ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/issues/323972) dans GitLab 18.0 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `packages_protected_packages_nuget`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md).
- Les charts Helm protégés ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/issues/323973) dans GitLab 18.1 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `packages_protected_packages_helm`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md).
- Les paquets génériques protégés ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/issues/323973) dans GitLab 18.1 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `packages_protected_packages_generic`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md).
- Les paquets génériques protégés sont devenus [généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/issues/537971) dans GitLab 18.2. Le feature flag `packages_protected_packages_generic` a été supprimé.
- Les paquets NuGet protégés sont devenus [généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/issues/524145) dans GitLab 18.2. Le feature flag `packages_protected_packages_nuget` a été supprimé.
- Les paquets Helm protégés sont devenus [généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/issues/538375) dans GitLab 18.3. Le feature flag `packages_protected_packages_helm` a été supprimé.

{{< /history >}}

Par défaut, tout utilisateur disposant du rôle Développeur, Mainteneur ou Propriétaire peut créer, modifier et supprimer des paquets. Ajoutez une règle de protection de paquets pour restreindre les utilisateurs autorisés à apporter des modifications à vos paquets.

GitLab prend en charge la protection des paquets pour npm, PyPI, Maven et Conan, mais l'[epic 5574](https://gitlab.com/groups/gitlab-org/-/epics/5574) propose d'ajouter des fonctionnalités supplémentaires et de nouveaux formats de paquets.

Lorsqu'un paquet est protégé, le comportement par défaut applique ces restrictions sur le paquet :

| Action                                 | Rôle ou jeton minimum requis                                                                     |
|:---------------------------------------|:----------------------------------------------------------------------------------|
| Protéger un paquet                      | Le rôle Mainteneur ou Propriétaire.                                                     |
| Pousser un nouveau paquet                     | Au moins le rôle défini dans [**Niveau d'accès minimum pour la poussée**](#protect-a-package). |
| Pousser un nouveau paquet avec un jeton de déploiement | Tout jeton de déploiement valide, uniquement si le paquet poussé ne correspond pas à une règle de protection. Les paquets protégés ne peuvent pas être poussés avec un jeton de déploiement. |
| Supprimer un paquet                       | Au moins le rôle défini dans [**Niveau d'accès minimal pour la suppression**](#protect-a-package). |

## Protéger un paquet {#protect-a-package}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire.

Pour protéger un paquet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Développez **Registre de paquets**.
1. Sous **Paquets protégés**, sélectionnez **Ajouter une règle de protection**.
1. Remplissez les champs :
   - **Modèle de nom** est un modèle de nom de paquet que vous souhaitez protéger. Le modèle peut inclure un caractère générique (`*`).
   - **Type de paquet** est le type de paquet à protéger.
   - **Niveau d'accès minimum pour la poussée** est le rôle minimum requis pour pousser un paquet correspondant au modèle de nom.
   - **Niveau d'accès minimal pour la suppression** est le rôle minimum requis pour supprimer un paquet correspondant au modèle de nom.
1. Sélectionnez **Protéger**.

La règle de protection des paquets est créée et apparaît dans les paramètres.

### Protection de plusieurs paquets {#protecting-multiple-packages}

Vous pouvez utiliser un caractère générique pour protéger plusieurs paquets avec la même règle de protection de paquets. Par exemple, vous pouvez protéger tous les paquets temporaires créés lors d'un pipeline CI/CD.

Le tableau suivant contient des exemples de règles de protection de paquets correspondant à plusieurs paquets :

| Modèle de nom de paquet avec caractère générique | Paquets correspondants                                                           |
|------------------------------------|-----------------------------------------------------------------------------|
| `@group/package-*`                 | `@group/package-prod`, `@group/package-prod-sha123456789`                   |
| `@group/*package`                  | `@group/package`, `@group/prod-package`, `@group/prod-sha123456789-package` |
| `@group/*package*`                 | `@group/package`, `@group/prod-sha123456789-package-v1`                     |

Il est possible d'appliquer plusieurs règles de protection au même paquet. Si au moins une règle de protection s'applique au paquet, le paquet est protégé.

## Supprimer une règle de protection de paquets et ôter la protection d'un paquet {#delete-a-package-protection-rule-and-unprotect-a-package}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire.

Pour ôter la protection d'un paquet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Développez **Registre de paquets**.
1. Sous **Paquets protégés**, à côté de la règle de protection que vous souhaitez supprimer, sélectionnez **Supprimer** ({{< icon name="remove" >}}).
1. Dans la boîte de dialogue de confirmation, sélectionnez **Supprimer**.

La règle de protection des paquets est supprimée et n'apparaît plus dans les paramètres.
