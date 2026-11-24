---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Découvrez comment gérer les frameworks de conformité dans l'ensemble de votre instance GitLab depuis un emplacement unique et centralisé."
title: Frameworks de conformité centralisés
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/15864) dans GitLab 18.3 [avec des feature flags](../../../administration/feature_flags/_index.md) nommés `security_policies_csp` et `include_csp_frameworks`. Activés par défaut.
- Le feature flag `security_policies_csp` a été [supprimé](https://gitlab.com/groups/gitlab-org/-/work_items/17392) dans GitLab 18.5.
- [Disponibilité générale](https://gitlab.com/groups/gitlab-org/-/work_items/15864) dans GitLab 18.6. Le feature flag `include_csp_frameworks` a été supprimé.

{{< /history >}}

La gestion centralisée des frameworks de conformité de sécurité permet aux administrateurs GitLab de gérer et d'appliquer de manière centralisée les exigences de conformité dans l'ensemble des groupes et projets d'une instance GitLab.

En désignant un groupe de politique de conformité et de sécurité (CSP), vous pouvez créer des frameworks de conformité automatiquement disponibles pour tous les groupes principaux.

Lorsque vous désignez un groupe de politique de conformité et de sécurité :

- Tous les frameworks de conformité créés dans le groupe de politique de conformité et de sécurité deviennent disponibles pour chaque groupe principal de votre instance.
- Les propriétaires de groupes peuvent attribuer ces frameworks centralisés à leurs projets.
- Les frameworks apparaissent aux côtés de tout framework spécifique au groupe, avec des indicateurs clairs montrant qu'ils proviennent du groupe de politique de conformité et de sécurité.
- Les frameworks de politique de conformité et de sécurité sont en lecture seule pour les non-membres du groupe de politique de conformité et de sécurité, garantissant une application cohérente des normes de conformité.

Visibilité des frameworks et autorisations :

- Tous les utilisateurs peuvent voir quels frameworks sont appliqués aux projets auxquels ils ont accès.
- Les membres du groupe peuvent consulter tous les frameworks de politique de conformité et de sécurité disponibles pour leur groupe.
- Le centre de conformité affiche à la fois les frameworks du groupe de politique de conformité et de sécurité et les frameworks spécifiques au groupe.

## Prérequis {#prerequisites}

- Vous devez être administrateur.
- Un groupe principal existant devant servir de groupe de politique de conformité et de sécurité.
- Pour utiliser l'API REST (facultatif), vous devez disposer d'un jeton avec accès administrateur.

## Avant de commencer {#before-you-begin}

Avant de commencer, désignez un groupe principal comme groupe de politique de conformité et de sécurité pour qu'il serve d'emplacement central pour la gestion des frameworks de conformité.

Pour des instructions détaillées, consultez [Désigner un groupe de politique de conformité et de sécurité](../../../security/compliance_security_policy_management.md#designate-a-compliance-and-security-policy-group).

## Créer des frameworks de conformité dans le groupe de politique de conformité et de sécurité {#create-compliance-frameworks-in-the-compliance-and-security-policy-group}

Une fois que vous avez désigné un groupe de politique de conformité et de sécurité, créez-y des frameworks de conformité :

1. Accédez à votre groupe de politique de conformité et de sécurité désigné.
1. Sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Frameworks**.
1. Sélectionnez **Nouveau framework**.
1. Renseignez les détails du framework :
   - **Nom** : un nom descriptif pour le framework.
   - **Description** : expliquez l'objet et les exigences du framework.
   - **Couleur** : choisissez une couleur pour l'identification visuelle.
   - **Exigences** (facultatif) : ajoutez des contrôles et des exigences spécifiques.
1. Sélectionnez **Enregistrer les modifications**.

Le framework est désormais disponible pour tous les groupes principaux de votre instance.

## Configurer les exigences du framework (facultatif) {#configure-framework-requirements-optional}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Vous pouvez définir des exigences et des contrôles spécifiques pour chaque framework de conformité :

1. Lors de la création ou de la modification d'un framework dans le groupe de politique de conformité et de sécurité, accédez à la section **Exigences**.
1. Sélectionnez **Nouvelle exigence**.
1. Ajoutez un ou plusieurs contrôles :
   - **Contrôles GitLab** : vérifications prédéfinies pour les fonctionnalités et paramètres GitLab.
   - **Contrôles externes** : Intégration avec des outils de conformité tiers.
1. Sélectionnez **Enregistrer les modifications du cadriciel**.

Pour plus d'informations sur les contrôles disponibles, consultez [Contrôles de conformité GitLab](_index.md#gitlab-compliance-controls) et les détails des [normes de conformité prises en charge](compliance_standards.md).

## Appliquer des frameworks de politique de conformité et de sécurité aux projets {#apply-compliance-and-security-policy-frameworks-to-projects}

Appliquez des frameworks de politique de conformité et de sécurité aux projets en tant que propriétaire de groupe ou propriétaire de projet.

### En tant que propriétaire de groupe {#as-a-group-owner}

Les propriétaires de groupes peuvent consulter et appliquer des frameworks de politique de conformité et de sécurité à leurs projets. Les frameworks de politique de conformité et de sécurité sont en lecture seule sur les groupes et vous ne pouvez pas les modifier ni les supprimer depuis votre groupe.

Pour appliquer un framework de politique de conformité et de sécurité aux projets de votre groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Projets**.
1. Les frameworks de politique de conformité et de sécurité apparaissent dans la liste avec un indicateur spécial.
1. Sélectionnez un framework de politique de conformité et de sécurité pour l'appliquer aux projets de votre groupe.

### En tant que propriétaire de projet {#as-a-project-owner}

Pour voir quels frameworks de conformité s'appliquent à vos projets :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Frameworks de conformité**.
1. Consultez tous les frameworks appliqués, y compris ceux provenant du groupe de politique de conformité et de sécurité.

## Modification des frameworks de politique de conformité et de sécurité {#modifying-compliance-and-security-policy-frameworks}

Lorsque vous modifiez un framework de conformité dans le groupe de politique de conformité et de sécurité :

- Les modifications sont immédiatement répercutées dans tous les groupes.
- Les projets utilisant le framework héritent automatiquement des mises à jour.
- Les événements d'audit enregistrent toutes les modifications.
- Aucune action n'est requise de la part des propriétaires de groupes ou de projets.

## Suppression des frameworks de politique de conformité et de sécurité {#deleting-compliance-and-security-policy-frameworks}

Lorsque vous supprimez un framework de politique de conformité et de sécurité, GitLab affiche un avertissement concernant les projets affectés.

Lorsque vous confirmez la suppression d'un framework de politique de conformité et de sécurité :

- Le framework est supprimé de tous les projets.
- Des événements d'audit sont générés.
- Le framework n'est plus visible dans aucun groupe.

## Modification du groupe de politique de conformité et de sécurité {#changing-the-compliance-and-security-policy-group}

Si vous devez changer le groupe qui sert de groupe de politique de conformité et de sécurité :

- Tous les frameworks de l'ancien groupe de politique de conformité et de sécurité deviennent indisponibles.
- Les frameworks du nouveau groupe de politique de conformité et de sécurité deviennent disponibles.
- Les projets doivent être réaffectés aux nouveaux frameworks si nécessaire.

Pour des instructions détaillées, consultez [désigner un groupe de politique de conformité et de sécurité](../../../security/compliance_security_policy_management.md#designate-a-compliance-and-security-policy-group).

## Intégration avec les politiques de sécurité {#integration-with-security-policies}

Les frameworks de politique de conformité et de sécurité peuvent être intégrés aux politiques de sécurité pour une conformité renforcée :

1. Créez des politiques de sécurité dans le groupe de politique de conformité et de sécurité.
1. Définissez la portée des politiques sur des frameworks de conformité spécifiques.
1. Les projets dotés de ces frameworks héritent automatiquement des politiques.

Pour plus d'informations, consultez [la gestion des politiques de sécurité dans le groupe de politique de conformité et de sécurité](../../application_security/policies/enforcement/compliance_and_security_policy_groups.md).

## Dépannage {#troubleshooting}

Solutions possibles aux problèmes que vous pourriez rencontrer lors de l'utilisation des frameworks de conformité centralisés.

### Les frameworks n'apparaissent pas dans les groupes {#frameworks-not-appearing-in-groups}

Si les frameworks de politique de conformité et de sécurité ne sont pas visibles dans vos groupes :

1. Vérifiez que le groupe de politique de conformité et de sécurité est correctement désigné dans les paramètres d'administration.
1. Vérifiez que des frameworks existent dans le groupe de politique de conformité et de sécurité.
1. Assurez-vous de disposer des autorisations appropriées pour consulter les frameworks.

### Impossible de modifier les frameworks de politique de conformité et de sécurité {#cannot-modify-compliance-and-security-policy-frameworks}

Les frameworks de politique de conformité et de sécurité ne peuvent être modifiés qu'à partir du groupe de politique de conformité et de sécurité :

1. Accédez directement au groupe de politique de conformité et de sécurité.
1. Assurez-vous de disposer du rôle Propriétaire sur le groupe de politique de conformité et de sécurité.
1. Effectuez les modifications depuis le centre de conformité du groupe de politique de conformité et de sécurité.

## Sujets connexes {#related-topics}

- [Gestion des politiques de conformité et de sécurité à l'échelle de l'instance](../../../security/compliance_security_policy_management.md)
- [Frameworks de conformité](_index.md)
- [Groupes de conformité et de politique de sécurité](../../application_security/policies/enforcement/compliance_and_security_policy_groups.md)
- [Centre de conformité](../compliance_center/_index.md)
