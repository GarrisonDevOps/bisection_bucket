---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Organisez le travail de votre équipe avec les éléments de travail GitLab. Suivez les tâches, les epics, les tickets et les objectifs dans une vue unifiée pour relier la stratégie à la mise en œuvre et surveiller la progression."
title: Éléments de travail
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les éléments de travail sont les composants fondamentaux de la planification et du suivi du travail dans GitLab. La planification et le suivi du développement produit nécessitent souvent de décomposer le travail en parties plus petites et gérables, tout en maintenant le lien avec la vue d'ensemble. Les éléments de travail sont conçus autour de ce besoin fondamental, en offrant un moyen unifié de représenter les unités de travail à n'importe quel niveau, des initiatives stratégiques aux tâches individuelles.

La nature hiérarchique des éléments de travail crée des relations claires entre les différents niveaux de travail, aidant les équipes à comprendre comment les tâches quotidiennes contribuent aux objectifs plus larges et comment les objectifs stratégiques se décomposent en composantes actionnables.

Cette structure prend en charge différents cadres de planification tels que Scrum, Kanban et les approches de gestion de portefeuille, tout en offrant aux équipes une visibilité sur la progression à chaque niveau.

## Types d'éléments de travail {#work-item-types}

GitLab prend en charge les types d'éléments de travail suivants :

- [Tickets](../project/issues/_index.md) : suivez les tâches, les fonctionnalités et les bugs.
- [Épopées](../group/epics/_index.md) : gérez les grandes initiatives sur plusieurs jalons et tickets.
- [Tâches](../tasks.md) : suivez les petites unités de travail.
- [OKR](../okrs.md) : suivez les objectifs stratégiques et leurs résultats mesurables.
- [Cas de test](../../ci/test_cases/_index.md) : intégrez la planification des tests directement dans vos workflows GitLab.

Vous pouvez également [configurer les types d'éléments de travail](configurable_work_item_types.md) pour créer de nouveaux types et contrôler leur disponibilité dans les groupes et les projets.

## Afficher tous les éléments de travail {#view-all-work-items}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/epics/11918) dans GitLab 18.7 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `work_item_planning_view`. Fonctionnalité désactivée par défaut.
- [Disponible en général](https://gitlab.com/gitlab-org/gitlab/-/work_items/520452) dans GitLab 18.10. Le feature flag `work_item_planning_view` a été supprimé.

{{< /history >}}

La liste **Éléments de travail** est l'emplacement central pour afficher et gérer tous les types d'éléments de travail (tels que les tickets, les epics et les tâches) pour un projet ou un groupe. Utilisez cette vue pour comprendre la portée complète du travail dans votre projet ou groupe et prioriser efficacement.

Dans les versions antérieures de GitLab, les tickets et les epics disposaient de pages de liste distinctes sous **Forfait** > **Tickets** et **Forfait** > **Épopées**. Dans GitLab 18.10 et versions ultérieures, ces pages sont remplacées par **Forfait** > **Éléments de travail**, qui regroupe tous les types d'éléments de travail dans une vue unique. Si vous aviez épinglé **Tickets** ou **Épopées** dans la barre latérale, **Éléments de travail** est épinglé à leur place. Les URL contenant `/epics/:iid` ou `/issues/:iid` sont automatiquement redirigées vers `/work_items/:iid`.

Pour afficher les éléments de travail d'un projet ou d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.

### Filtrer les éléments de travail {#filter-work-items}

La liste **Éléments de travail** affiche tous les types d'éléments de travail par défaut. Pour afficher un type spécifique (par exemple, uniquement les tickets ou uniquement les epics), utilisez le filtre **Type**.

Pour filtrer la liste des éléments de travail :

1. En haut de la page, dans la barre de filtres, sélectionnez un filtre, un opérateur et sa valeur. Par exemple, pour afficher uniquement les epics, sélectionnez le filtre **Type**, l'opérateur **est** et la valeur **Épopée**.
1. Facultatif. Ajoutez d'autres filtres pour affiner votre recherche.
1. Appuyez sur <kbd>Entrée</kbd> ou sélectionnez l'icône de recherche ({{< icon name="search" >}}).

#### Filtres disponibles {#available-filters}

{{< history >}}

- Le filtrage par description a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/536876) dans GitLab 18.3.

{{< /history >}}

Ces filtres sont disponibles pour les éléments de travail :

- Assigné
  - Opérateurs : `is`, `is not one of`, `is one of`
- Auteur
  - Opérateurs : `is`, `is not one of`, `is one of`
- Confidentiel
  - Valeurs : `Yes`, `No`
- Contact
  - Opérateurs : `is`
- Statut
  - Opérateurs : `is`
- Statut de santé
  - Opérateurs : `is`, `is not`
- Itération
  - Opérateurs : `is`, `is not`
- Label
  - Opérateurs : `is`, `is not one of`, `is one of`
- Jalon
  - Opérateurs : `is`, `is not`
- Ma réaction
  - Opérateurs : `is`, `is not`
- Organisation
  - Opérateurs : `is`
- Parent
  - Opérateurs : `is`, `is not`
  - Valeurs : n'importe quel `Issue`, `Epic`, `Objective`
- Release
  - Opérateurs : `is`, `is not`
- Rechercher dans
  - Opérateurs : `Titles`, `Descriptions`
- État
  - Valeurs : `Any`, `Open`, `Closed`
- Type
  - Valeurs : `Issue`, `Incident`, `Task`, `Epic`, `Objective`, `Key Result`, `Test case`
- Poids
  - Opérateurs : `is`, `is not`

Pour accéder aux filtres que vous avez utilisés récemment, sur le côté gauche de la barre de filtres, sélectionnez la liste déroulante **Recherches récentes** ({{< icon name="history" >}}).

### Trier les éléments de travail {#sort-work-items}

{{< history >}}

- Le tri par statut a été [introduit](https://gitlab.com/groups/gitlab-org/-/epics/18638) dans GitLab 18.5 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `work_item_status_mvc2`. Activés par défaut.
- Le tri par statut est [disponible en général](https://gitlab.com/gitlab-org/gitlab/-/issues/576610) dans GitLab 18.6. Le feature flag `work_item_status_mvc2` a été supprimé.

{{< /history >}}

Triez la liste des éléments de travail selon les critères suivants :

- Date de création
- Date de mise à jour
- Date de début
- Date d'échéance
- Titre
- Statut
- Poids

Pour modifier les critères de tri :

1. Sur le côté droit de la barre de filtres, sélectionnez **Afficher** ({{< icon name="preferences" >}}) pour ouvrir le panneau des préférences d'affichage.
1. En haut du panneau, sélectionnez la liste déroulante **Trier par**.

Pour modifier l'ordre de tri entre croissant et décroissant :

1. Sur le côté droit de la barre de filtres, sélectionnez **Afficher** ({{< icon name="preferences" >}}) pour ouvrir le panneau des préférences d'affichage.
1. En haut du panneau, à côté de la liste déroulante **Trier par**, sélectionnez **Sens de tri** ({{< icon name="sort-lowest" >}} ou {{< icon name="sort-highest" >}}).

Pour plus d'informations sur la logique de tri, consultez [le tri et l'organisation des listes de tickets](../project/issues/sorting_issue_lists.md).

### S'abonner à un flux RSS de la liste des éléments de travail {#subscribe-to-an-rss-feed-of-the-work-item-list}

GitLab fournit un flux RSS de la liste des éléments de travail.

Pour s'abonner au flux :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Facultatif. Appliquez des filtres pour affiner la liste.
1. Dans le coin supérieur droit, sélectionnez **Actions** ({{< icon name="ellipsis_v" >}}) > **S'abonner au flux RSS**.

Par défaut, le flux contient tous les types d'éléments de travail. Si vous avez appliqué des filtres, le flux correspond à ces filtres.

L'URL du flux contient un [jeton de flux](../../security/tokens/_index.md#feed-token) qui vous authentifie en tant que lecteur du flux.

## Configurer les préférences d'affichage de la liste {#configure-list-display-preferences}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/393559) dans GitLab 18.2.
- La prise en charge des tickets a été [ajoutée](https://gitlab.com/gitlab-org/gitlab/-/issues/520791) dans GitLab 18.7.

{{< /history >}}

Personnalisez l'affichage des éléments de travail sur les pages de liste en affichant ou en masquant des champs de métadonnées spécifiques et en configurant les préférences d'affichage.

GitLab enregistre vos préférences d'affichage à différents niveaux :

- **Champs** : enregistré par espace de nommage. Vous pouvez avoir différents paramètres de visibilité des champs pour différents groupes et projets en fonction de vos besoins de workflow. Par exemple, vous pouvez afficher l'assigné et les labels dans un groupe ou un projet, mais les masquer dans un autre.
- **Vos préférences** : enregistré globalement dans tous les projets et groupes. Cela garantit un comportement cohérent quant à la façon dont vous préférez afficher les éléments de travail.

Pour configurer les préférences d'affichage :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Sur le côté droit de la barre de filtres, sélectionnez **Afficher** ({{< icon name="preferences" >}}) pour ouvrir le panneau des préférences d'affichage.
1. Sous **Champs**, activez ou désactivez les métadonnées que vous souhaitez afficher :
   - Statut (pour les tickets)
   - Assigné
   - Labels
   - Poids (pour les tickets)
   - Jalon
   - Itération (pour les tickets)
   - Dates : dates d'échéance et plages de dates
   - Santé : indicateurs de statut de santé
   - Bloqué/Bloquant : indicateurs de relation de blocage
   - Commentaires : nombre de commentaires
   - Popularité : métriques de popularité

   Les champs que vous activez apparaissent sous **Affichés**. Les champs que vous désactivez apparaissent sous **Cachée**.
1. Facultatif. Pour rechercher un champ spécifique, utilisez le champ de saisie **Rechercher des champs**.
1. Sous **Vos préférences**, activez ou désactivez **Ouvrir les éléments dans le panneau latéral** pour choisir comment les éléments de travail s'ouvrent lorsque vous les sélectionnez :
   - Activé (par défaut) : les éléments s'ouvrent dans un panneau sur le côté droit de l'écran.
   - Désactivé : les éléments s'ouvrent en pleine page.

Votre préférence est enregistrée et mémorisée pour toutes vos sessions et tous vos appareils.

## Référence Markdown des éléments de travail {#work-item-markdown-reference}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/352861) dans GitLab 18.1 [avec le feature flag](../../administration/feature_flags/_index.md) `extensible_reference_filters`. Fonctionnalité désactivée par défaut.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197052) dans GitLab 18.2. Le feature flag `extensible_reference_filters` a été supprimé.

{{< /history >}}

Vous pouvez référencer des éléments de travail dans les champs GitLab Flavored Markdown avec `[work_item:123]`. Pour plus d'informations, consultez [les références spécifiques à GitLab](../markdown.md#gitlab-specific-references).

## Éléments de travail dans les merge requests {#work-items-in-merge-requests}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/plan-stage/-/work_items/456) dans GitLab 18.11 [avec le feature flag](../../administration/feature_flags/_index.md) `mr_related_work_items`. Fonctionnalité désactivée par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/233554) dans GitLab 19.0. Le feature flag `mr_related_work_items` a été supprimé.

{{< /history >}}

Lorsque vous référencez un élément de travail dans la description d'une merge request, il apparaît automatiquement dans le widget **Éléments de travail** dans la barre latérale de la merge request. Le widget regroupe les éléments de travail selon la façon dont ils sont liés :

- **Clôture** : éléments de travail liés avec un [modèle de clôture](../project/issues/managing_issues.md#closing-issues-automatically), tels que `Closes #123`. Ces éléments de travail se ferment automatiquement lorsque la merge request est fusionnée.
- **Mentionnés** : éléments de travail référencés dans la description mais non liés avec un modèle de clôture, tels que `Related to #456`. Ces éléments de travail ne sont pas fermés lors de la fusion de la merge request.

Si le widget contient plus de deux éléments de travail, il est réduit par défaut. Sélectionnez l'en-tête du widget pour le développer. Sélectionnez n'importe quel élément de travail pour l'ouvrir dans un panneau.

### Lier des éléments de travail manuellement {#link-work-items-manually}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/238648) dans GitLab 19.1 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `explicit_mr_work_item_relations`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256281) dans GitLab 19.5.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Vous pouvez également lier des éléments de travail à une merge request sans modifier la description de la merge request. Les éléments de travail que vous liez de cette façon apparaissent dans le groupe **Clôture** ou **Associées**, et la merge request apparaît dans la section **Développement** de chaque élément de travail lié.

Prérequis :

- Vous devez disposer au minimum du rôle Développeur pour le projet.

Pour lier un élément de travail existant à une merge request :

1. Sur la page de la merge request, dans la barre latérale droite, dans la section **Éléments de travail**, sélectionnez **Ajouter un élément de travail** ({{< icon name="plus" >}}).
1. Dans la boîte de dialogue **Lier un élément de travail**, dans la liste déroulante **Relation**, sélectionnez **Ferme** ou **Associé à**.
1. Dans le champ de recherche, recherchez l'élément de travail ou saisissez son URL ou son ID de référence, puis sélectionnez-le.
1. Sélectionnez **Ajouter**.

Pour créer un élément de travail et le lier à une merge request :

1. Sur la page de la merge request, dans la barre latérale droite, dans la section **Éléments de travail**, sélectionnez **Ajouter un élément de travail** ({{< icon name="plus" >}}).
1. Dans la boîte de dialogue **Lier un élément de travail**, dans la liste déroulante **Relation**, sélectionnez **Ferme** ou **Associé à**.
1. Sélectionnez **Créer un nouvel élément**.
1. Dans la liste déroulante **Projet**, sélectionnez un projet.
1. Dans la liste déroulante **Type**, sélectionnez un type d'élément de travail.
1. Remplissez les champs.
1. Sélectionnez **Créer** pour le type sélectionné, par exemple **Créer un ticket**.

Pour supprimer un lien :

1. Sur la page de la merge request, dans la barre latérale droite, dans la section **Éléments de travail**, à côté de l'élément de travail, sélectionnez **Supprimer** ({{< icon name="close" >}}).

Vous ne pouvez pas supprimer les éléments de travail ajoutés par un modèle de clôture ou une mention dans la description de la merge request.

Pour lier un élément de travail d'un autre projet, saisissez son URL ou sa référence complète, par exemple `group/project#123`.

## Sujets connexes {#related-topics}

- [Tickets liés](../project/issues/related_issues.md)
- [Epics liés](../group/epics/linked_epics.md)
- [Tableaux des tickets](../project/issue_board.md)
- [Labels](../project/labels.md)
- [Itérations](../group/iterations/_index.md)
- [Les jalons](../project/milestones/_index.md)
- [Champs personnalisés](custom_fields.md)
- [Types d'éléments de travail configurables](configurable_work_item_types.md)
- [Plan de travail](workplan.md)
