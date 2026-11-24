---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Rapport sur le statut de conformité
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/186525) dans GitLab 17.11 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `enable_standards_adherence_dashboard_v2`. Activés par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/535563) dans GitLab 18.3. Suppression du feature flag `enable_standards_adherence_dashboard_v2`.

{{< /history >}}

Le rapport sur le statut de conformité affiche les instances les plus récentes dans lesquelles des projets ne respectent pas les [exigences du cadre de conformité](../compliance_frameworks/_index.md#requirements). Il fait partie du centre de conformité et vous aide à identifier et corriger rapidement les lacunes dans la mise en œuvre des contrôles au sein de vos projets.

## Planification et déclencheurs des analyses {#scan-timing-and-triggers}

Les analyses de conformité qui mettent à jour le rapport de statut sont automatiquement déclenchées dans les situations suivantes :

- Un cadre est ajouté à un projet.
- Les exigences d'un cadre associé sont modifiées.
- Une analyse planifiée s'exécute (toutes les 12 heures).

Une fois une analyse déclenchée, les résultats peuvent mettre cinq à dix minutes à apparaître dans le rapport sur le statut de conformité.

Pour en savoir plus sur la façon dont les exigences et les contrôles sont définis dans un cadre de conformité, consultez [Créer et gérer les exigences du cadre de conformité](../compliance_frameworks/_index.md#add-requirements).

## Afficher le rapport sur le statut de conformité {#view-the-compliance-status-report}

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour afficher le rapport sur le statut de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Dans la section **Rapports de conformité**, sélectionnez **Rapport sur le statut de conformité**.

## Détails du rapport {#report-details}

Le rapport sur le statut de conformité affiche la dernière instance dans laquelle un projet respecte ou ne respecte pas un contrôle de cadre. Chaque ligne fournit des détails sur le statut actuel d'un contrôle dans un projet spécifique, ce qui vous permet de surveiller la conformité dans l'ensemble de votre groupe.

Vous pouvez :

- Filtrer le rapport par projet, cadre ou contrôle.
- Accéder directement à la vue détaillée de conformité d'un projet.
- Examiner la date à laquelle la non-conformité a été détectée pour la première fois.

Le rapport sur le statut de conformité contient les colonnes suivantes :

- **Projet** : le projet présentant une non-conformité.
- **Cadre** : le cadre de conformité auquel appartient le contrôle (par exemple, GitLab ou SOC 2).
- **Contrôle** : le contrôle spécifique que le projet ne respecte pas (par exemple, « Au moins deux approbations »).
- **Détecté le** : la date et l'heure auxquelles la non-conformité a été enregistrée pour la première fois.
- **En savoir plus** : un lien vers du contexte supplémentaire ou des paramètres connexes pour le projet.

## Exporter le rapport sur le statut de conformité {#export-compliance-status-report}

Exportez le contenu d'un rapport de statut pour les projets d'un groupe. Les rapports sont tronqués à 15 Mo pour éviter les pièces jointes volumineuses par e-mail.

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour exporter le rapport sur le statut de conformité pour les projets d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Dans le coin supérieur droit, sélectionnez **Exporter**.
1. Sélectionnez **Exporter le rapport sur le statut de conformité**.

Un rapport est compilé et envoyé dans votre boîte de réception sous forme de pièce jointe.
