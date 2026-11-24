---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Les tickets
description: "Tâches, rapports de bugs, demandes de fonctionnalités et suivi."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les tickets vous aident à collaborer avec votre équipe pour planifier, suivre et livrer du travail dans GitLab. Les tickets permettent de :

- Suivre les propositions de fonctionnalités, les tâches, les demandes d'assistance et les rapports de bugs.
- Organiser et prioriser le travail grâce aux personnes assignées, aux dates d'échéance et au statut de santé.
- Faciliter les discussions d'équipe et la prise de décision via les commentaires et les fils de discussion.
- Prendre en charge des workflows personnalisés grâce aux modèles, labels, epics et tableaux.
- S'intégrer avec des outils externes tels que Zoom, Jira et les services de messagerie.

Les tickets sont toujours associés à un projet spécifique. Si vous avez plusieurs projets dans un groupe, vous pouvez afficher tous les tickets de ces projets simultanément.

<div class="video-fallback">
  Voir la vidéo : <a href="https://www.youtube.com/watch?v=Mt1EzlKToig">Issues - Setting up your Organization with GitLab</a>.
</div>
<figure class="video-container">
  <iframe src="https://www.youtube-nocookie.com/embed/Mt1EzlKToig" frameborder="0" allowfullscreen> </iframe>
</figure>
<!-- Video published on 2023-10-30 -->

<i class="fa-youtube-play" aria-hidden="true"></i> Pour découvrir comment le département Marketing Stratégique de GitLab utilise les tickets GitLab avec les [labels](../labels.md) et les [tableaux des tickets](../issue_board.md), consultez la vidéo [managing commitments with issues](https://www.youtube.com/watch?v=cuIHNintg1o&t=3).
<!-- Video published on 2020-04-10 -->

## Les tickets en tant qu'éléments de travail {#issues-as-work-items}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/epics/9584) dans GitLab 17.5 [avec le feature flag](../../../administration/feature_flags/_index.md) `work_items_view_preference`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est en [version bêta](../../../policy/development_stages_support.md#beta).
- Le feature flag nommé `work_items_view_preference` a été activé sur GitLab.com dans GitLab 17.9 pour un sous-ensemble d'utilisateurs.
- Le feature flag nommé `work_items_view_preference` [activé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184496) sur GitLab.com, GitLab Self-Managed et GitLab Dedicated dans la version 17.10.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/482931) dans GitLab 17.11.
- [Déplacé](https://gitlab.com/gitlab-org/gitlab/-/issues/482931) vers le feature flag nommé `work_item_view_for_issues` dans GitLab 18.1. Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated. Le feature flag `work_items_view_preference` a été supprimé.
- Des filtres supplémentaires sur la page des tickets dans les projets [introduits](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/198544) dans GitLab 18.4. [Activation sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/204139).
- Des filtres supplémentaires sur la page des tickets dans les groupes [introduits](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/202089) dans GitLab 18.5. [Activation sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/205308).
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/520791) dans GitLab 18.7. Le feature flag `work_item_view_for_issues` a été supprimé.

{{< /history >}}

Les tickets ont été intégrés à un cadre unifié pour les éléments de travail, afin de mieux répondre aux besoins produit de l'offre GitLab Agile Planning.

Pour plus d'informations, consultez l'[epic 9290](https://gitlab.com/groups/gitlab-org/-/work_items/9290) et l'article de blog [nouvelle expérience de planification Agile dans GitLab](https://about.gitlab.com/blog/first-look-the-new-agile-planning-experience-in-gitlab/) (juin 2024).

Si vous rencontrez des problèmes lors de l'utilisation de cette modification, vous pouvez utiliser le [ticket de retour d'expérience](https://gitlab.com/gitlab-org/gitlab/-/issues/523713) pour fournir plus de détails.

### Référence Markdown pour les éléments de travail {#work-item-markdown-reference}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/352861) dans GitLab 18.1 [avec le feature flag](../../../administration/feature_flags/_index.md) `extensible_reference_filters`. Fonctionnalité désactivée par défaut.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197052) dans GitLab 18.2. Le feature flag `extensible_reference_filters` a été supprimé.

{{< /history >}}

Vous pouvez référencer des éléments de travail dans les champs Markdown GitLab avec `[work_item:123]`. Pour plus d'informations, consultez [les références spécifiques à GitLab](../../markdown.md#gitlab-specific-references).

## Sujets connexes {#related-topics}

- [Créer des tickets](create_issues.md)
- [Créer un ticket à partir d'un modèle](../description_templates.md#use-the-templates)
- [Modifier des tickets](managing_issues.md#edit-an-issue)
- [Déplacer des tickets](managing_issues.md#move-an-issue)
- [Fermer des tickets](managing_issues.md#close-an-issue)
- [Supprimer des tickets](managing_issues.md#delete-an-issue)
- [Promouvoir des tickets](managing_issues.md#promote-an-issue-to-an-epic)
- [Définir une date d'échéance](due_dates.md)
- [Importer des tickets](csv_import.md)
- [Exporter des tickets](csv_export.md)
- [Téléverser des designs vers des tickets](design_management.md)
- [Tickets liés](related_issues.md)
- [Tickets similaires](managing_issues.md#similar-issues)
- [Statut de santé](managing_issues.md#health-status)
- [Créer des liens croisés entre tickets](crosslinking_issues.md)
- [Trier les listes de tickets](sorting_issue_lists.md)
- [Rechercher des tickets](managing_issues.md#filter-the-list-of-issues)
- [Les epics](../../group/epics/_index.md)
- [Tableaux des tickets](../issue_board.md)
- [API des tickets](../../../api/issues.md)
- [Configurer un système de suivi de tickets externe](../../../integration/external-issue-tracker.md)
- [Tâches](../../tasks.md)
- [Afficher le nombre et le poids des tâches dans un ticket](../../tasks.md#view-count-and-weight-of-tasks-in-the-parent-issue)
- [Afficher la progression d'un ticket avec des tâches enfants](../../tasks.md#view-progress-of-the-parent-issue)
- [Participants externes](../service_desk/external_participants.md)
