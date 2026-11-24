---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Rapport sur les cadres de conformité
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le rapport sur les cadres de conformité vous permet de voir tous les cadres de conformité d'un groupe. Chaque ligne du rapport indique :

- Nom du cadre.
- Projets associés.

Le cadre par défaut du groupe possède un badge **par défaut**.

## Afficher le rapport sur les cadres de conformité {#view-the-compliance-frameworks-report}

Pour afficher le rapport sur les cadres de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Frameworks**.

## Créer un nouveau cadre de conformité {#create-a-new-compliance-framework}

Prérequis :

- Vous devez être administrateur ou avoir le rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour créer un nouveau cadre de conformité depuis le rapport sur les cadres de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Frameworks**.
1. Sélectionnez **Nouveau framework**.
1. Sélectionnez **Créer un framework vierge**.
1. Sélectionnez **Ajouter un cadriciel** pour créer un cadre de conformité.

## Modifier un cadre de conformité {#edit-a-compliance-framework}

Prérequis :

- Vous devez être administrateur ou avoir le rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour modifier un cadre de conformité depuis le rapport sur les cadres de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Frameworks**.
1. Survolez le framework et sélectionnez **Modifier le framework**.
1. Sélectionnez **Enregistrer les modifications** pour modifier le cadre de conformité.

## Supprimer un cadre de conformité {#delete-a-compliance-framework}

Prérequis :

- Vous devez être administrateur ou avoir le rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour supprimer un cadre de conformité depuis le rapport sur les cadres de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Frameworks**.
1. Survolez le framework et sélectionnez **Modifier le framework**.
1. Sélectionnez **Supprimer le cadriciel** pour supprimer le cadre de conformité.

## Définir et retirer un cadre de conformité par défaut {#set-and-remove-a-compliance-framework-as-default}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181500) dans GitLab 17.10.

{{< /history >}}

Prérequis :

- Vous devez être administrateur ou avoir le rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour définir un cadre de conformité comme [cadre par défaut](../compliance_frameworks/_index.md#default-compliance-frameworks) depuis le rapport sur les cadres de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Frameworks**.
1. À côté du cadre de conformité que vous souhaitez définir par défaut, sélectionnez l'action {{< icon name="pencil" >}}.
1. Sélectionnez **Définir par défaut**.

Pour retirer un cadre de conformité par défaut depuis le rapport sur les cadres de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Frameworks**.
1. À côté du cadre de conformité défini par défaut, sélectionnez l'action {{< icon name="pencil" >}}.
1. Sélectionnez **Ne plus utiliser comme cadriciel par défaut**.

## Exporter un rapport sur les cadres de conformité d'un groupe {#export-a-report-of-compliance-frameworks-in-a-group}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/413736) dans GitLab 16.11 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `compliance_frameworks_report_csv_export`. Fonctionnalité désactivée par défaut.
- [Disponible en général](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/152644) dans GitLab 17.1. Le feature flag `compliance_frameworks_report_csv_export` a été supprimé.

{{< /history >}}

Exporte le contenu d'un rapport sur les cadres de conformité dans un groupe. Les rapports sont tronqués à 15 Mo pour éviter les pièces jointes volumineuses.

Prérequis :

- Vous devez être administrateur ou avoir le rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour exporter le rapport de conformité aux normes pour les projets d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Dans le coin supérieur droit, sélectionnez **Exporter**.
1. Sélectionnez **Exporter le rapport du framework**.

Un rapport est compilé et envoyé dans votre boîte de réception sous forme de pièce jointe.
