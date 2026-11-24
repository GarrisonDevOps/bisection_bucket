---
stage: Plan
group: Portfolio Planning
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Utilisez des éléments enfants pour connecter et suivre les relations entre les éléments de travail dans GitLab."
title: Éléments enfants
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les éléments enfants sont des éléments de travail imbriqués sous un élément de travail parent. Cela crée une hiérarchie pour organiser et suivre le travail.

Les éléments enfants peuvent être :

- Un epic enfant imbriqué sous un epic parent.
- Un ticket tel qu'une fonctionnalité ou un bug assigné à un epic.
- Une tâche qui peut être un élément enfant d'un ticket.

```plaintext
Parent epic
|─ Child epic
   |─ Issue
      |- Task
   |─ Issue
      |- Task
   |─ Issue
  ```

Vous pouvez utiliser des éléments enfants pour résoudre plusieurs problèmes de planification et de coordination.

Les exemples suivants illustrent comment les éléments enfants aident les équipes à collaborer plus efficacement.

## Afficher tous les éléments enfants assignés à un élément de travail parent {#view-all-child-items-assigned-to-a-parent-work-item}

Dans la section Éléments enfants, vous pouvez voir les épics, les tickets et les tâches assignés à un epic.

Vous pouvez également voir les épics, les tickets et les tâches hérités par les éléments descendants.

Seuls les épics, les tickets et les tâches auxquels vous avez accès apparaissent dans la liste.

Vous pouvez afficher les tickets assignés à un epic s'ils se trouvent dans le projet enfant du groupe. En effet, le paramètre de visibilité d'un projet doit être identique ou moins restrictif que celui de son groupe parent.

## Suivre la progression des éléments de travail {#track-work-item-progress}

Vous pouvez suivre la progression des éléments de travail selon différents critères.

### Afficher le nombre et le poids des tickets dans un epic {#view-count-and-weight-of-issues-in-an-epic}

Dans l'en-tête de la section **Éléments enfants** d'un epic, le nombre d'éléments de travail descendants et leur poids total sont affichés. Les poids des tâches sont inclus dans le poids total des tickets.

Pour voir le nombre d'éléments de travail ouverts et fermés, dans l'en-tête de section ou sous chaque nom d'epic, survolez les totaux.

Les chiffres reflètent tous les éléments de travail enfants associés à l'epic, y compris ceux pour lesquels vous n'avez peut-être pas l'autorisation de les afficher.

### Afficher la progression de l'epic {#view-epic-progress}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/5163) dans GitLab 17.1.

{{< /history >}}

Dans l'en-tête de la section **Éléments enfants** d'un epic, le pourcentage de progression de l'epic est affiché.

Pour voir le poids complété et le poids total des éléments enfants, dans l'en-tête de section, survolez le pourcentage.

Les tâches sont incluses dans le pourcentage de progression en tant que partie du pourcentage des tickets enfants.

Les poids et la progression reflètent tous les tickets associés à l'epic, y compris les tickets pour lesquels vous n'avez peut-être pas l'autorisation de les afficher.

## Ajouter des éléments enfants {#add-child-items}

Vous pouvez :

- Ajoutez des éléments de travail existants en tant qu'éléments enfants, y compris des éléments de travail dans un projet issu d'une hiérarchie de groupes différente.
- Créez un nouvel élément de travail qui est automatiquement ajouté en tant qu'élément enfant.

### Ajouter un ticket à un epic {#add-an-issue-to-an-epic}

{{< history >}}

- Le nombre maximal de tickets enfants et d'épics [est passé](https://gitlab.com/gitlab-org/gitlab/-/issues/452111) à 5 000 dans GitLab 17.1.

{{< /history >}}

Ajoutez un ticket existant à un epic, ou créez un nouveau ticket qui est automatiquement ajouté à l'epic.

Le nombre maximal de tickets enfants directs et d'épics est de 5 000.

#### Ajouter un ticket existant à un epic {#add-an-existing-issue-to-an-epic}

Vous pouvez ajouter des tickets existants à un epic, y compris des tickets dans un projet issu d'une [hiérarchie de groupes différente](../group/epics/_index.md#child-issues-from-different-group-hierarchies).

Les tickets nouvellement ajoutés apparaissent en haut de la liste des tickets dans la section **Éléments enfants**.

Un epic contient une liste de tickets et un ticket peut être défini comme élément enfant d'au plus un epic. Lorsque vous ajoutez un nouveau ticket déjà lié à un epic, le ticket est automatiquement dissocié de son parent actuel.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet du ticket.
- Vous devez avoir l'autorisation de [consulter l'epic](../group/epics/manage_epics.md#who-can-view-an-epic). Un rôle dans le groupe de l'epic n'est pas requis. L'appartenance à un projet dans le groupe de l'epic, ou dans l'un de ses groupes descendants, est suffisante.

Pour ajouter un ticket existant à un epic :

1. Sur la page de l'epic, sous **Éléments enfants**, sélectionnez **Ajouter**.
1. Sélectionnez **Ticket existant**.
1. Identifiez le ticket à ajouter en utilisant l'une des méthodes suivantes :
   - Collez le lien du ticket.
   - Recherchez le ticket souhaité en saisissant une partie du titre du ticket, puis sélectionnez la correspondance souhaitée. Les tickets issus de hiérarchies de groupes différentes n'apparaissent pas dans les résultats de recherche. Pour ajouter un tel ticket, saisissez son URL complète.

   S'il y a plusieurs tickets à ajouter, appuyez sur <kbd>Espace</kbd> et répétez cette étape.
1. Sélectionnez **Ajouter**.

#### Créer un ticket depuis un epic {#create-an-issue-from-an-epic}

La création d'un ticket depuis un epic vous permet de maintenir votre attention sur le contexte global de l'epic tout en divisant le travail en parties plus petites.

Vous pouvez créer un nouveau ticket depuis un epic uniquement dans les projets qui se trouvent dans le groupe de l'epic ou dans l'un de ses sous-groupes descendants. Pour créer un nouveau ticket dans un [projet partagé avec le groupe de l'epic](../project/members/sharing_projects_groups.md), commencez par [créer le ticket directement dans le projet](../project/issues/create_issues.md#from-a-project), puis [ajoutez un ticket existant à un epic](#add-an-existing-issue-to-an-epic).

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet du ticket et le groupe de l'epic.

Pour créer un ticket depuis un epic :

1. Sur la page de l'epic, sous **Éléments enfants**, sélectionnez **Ajouter**.
1. Sélectionnez **Ajouter un nouveau ticket**.
1. Sous **Intitulé**, saisissez le titre du nouveau ticket.
1. Dans la liste déroulante **Projet**, sélectionnez le projet dans lequel le ticket doit être créé.
1. Sélectionnez **Créer un ticket**.

Le nouveau ticket est assigné à l'epic.

## Réorganiser les éléments enfants {#reorganize-child-items}

Vous pouvez réordonner les éléments enfants et les réorganiser au sein de la hiérarchie.

### Réordonner les tickets assignés à un epic {#reorder-issues-assigned-to-an-epic}

Les nouveaux tickets apparaissent en haut de la liste dans la section **Éléments enfants**. Vous pouvez réordonner la liste des tickets en les faisant glisser.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet du ticket et le groupe de l'epic.

Pour réordonner les tickets assignés à un epic :

1. Accédez à la section **Éléments enfants**.
1. Faites glisser les tickets dans l'ordre souhaité.

### Déplacer des tickets entre des épics {#move-issues-between-epics}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les nouveaux tickets apparaissent en haut de la liste dans l'onglet **Éléments enfants**. Vous pouvez déplacer des tickets d'un epic à un autre.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet du ticket et le groupe de l'epic.

Pour déplacer un ticket vers un autre epic :

1. Accédez à la section **Éléments enfants**.
1. Faites glisser les tickets vers l'epic parent souhaité dans la hiérarchie visible.

### Déplacement des éléments enfants lors du déplacement du ticket parent {#moving-child-items-when-the-parent-issue-is-moved}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/371252) dans GitLab 16.9 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `move_issue_children`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com et GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/issues/371252) dans GitLab 16.11.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/371252) dans GitLab 17.3. Feature flag `move_issue_children` supprimé.

{{< /history >}}

Lorsque vous déplacez un ticket vers un autre projet, tous ses éléments enfants sont également déplacés vers le projet cible et restent des éléments enfants du ticket déplacé. Chaque élément est déplacé de la même façon que le parent, c'est-à-dire qu'il est fermé dans le projet d'origine et copié dans le projet cible.

### Retirer un ticket d'un epic {#remove-an-issue-from-an-epic}

Vous pouvez retirer des tickets d'un epic lorsque vous êtes sur la page de détails de l'epic. Après avoir retiré un ticket d'un epic, le ticket n'est plus associé à cet epic.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet du ticket.
- Vous devez avoir l'autorisation de [consulter l'epic](../group/epics/manage_epics.md#who-can-view-an-epic). Un rôle dans le groupe de l'epic n'est pas requis. L'appartenance à un projet dans le groupe de l'epic, ou dans l'un de ses groupes descendants, est suffisante.

Pour retirer un ticket d'un epic :

1. À côté du ticket que vous souhaitez retirer, sélectionnez **Supprimer** ({{< icon name="close" >}}). L'avertissement **Supprimer le ticket** apparaît.
1. Sélectionnez **Supprimer**.

## Travailler avec des hiérarchies à plusieurs niveaux {#work-with-multi-level-hierarchies}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les épics peuvent contenir plusieurs épics enfants imbriqués. Vous pouvez travailler avec ces épics enfants à plusieurs niveaux de la façon suivante :

- Créez une hiérarchie d'épics en ajoutant un epic parent à un epic existant.
- Ajoutez un epic enfant qui appartient à un groupe différent du groupe de l'epic parent.
- Affichez les épics enfants d'un epic et les jalons associés sur le roadmap.
- Ajoutez, déplacez, réordonnez et supprimez des épics enfants depuis des épics.

Les épics peuvent contenir plusieurs épics enfants imbriqués, jusqu'à un total de 7 niveaux de profondeur.

### Ajouter un epic parent à un epic {#add-a-parent-epic-to-an-epic}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/epics/11198) dans GitLab 17.5.

{{< /history >}}

Pour créer une hiérarchie d'épics, ajoutez un epic parent à un epic existant. Cela permet d'organiser et de suivre le travail connexe à travers plusieurs épics.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le groupe de l'epic parent ou le groupe de l'epic enfant.

Pour ajouter un epic parent :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre groupe.
1. Sélectionnez **Forfait** > **Éléments de travail**.
1. Sélectionnez un epic.
1. Dans la barre latérale droite, dans la section **Parent**, sélectionnez **Modifier**.
1. Dans la zone de recherche, saisissez une partie du titre de l'epic parent. Vous pouvez uniquement rechercher des épics dans la même hiérarchie de groupes.
1. Dans les résultats de recherche, sélectionnez l'epic que vous souhaitez ajouter en tant que parent.

L'epic parent est ajouté.

### Épics enfants provenant d'autres groupes {#child-epics-from-other-groups}

Ajoutez un epic enfant qui appartient à un groupe différent du groupe de l'epic parent.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour les groupes des épics enfant et parent.
- Les épics enfants à plusieurs niveaux doivent être disponibles pour les groupes des épics enfant et parent.

Pour ajouter un epic enfant depuis un autre groupe, collez l'URL de l'epic lors de l'[ajout d'un epic existant](#add-a-child-epic-to-an-epic).

### Afficher les épics enfants sur un roadmap {#view-child-epics-on-a-roadmap}

Depuis un epic, affichez ses épics enfants et les jalons associés sur le [roadmap](../group/roadmap/_index.md).

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le groupe de l'epic parent.

Pour afficher les épics enfants depuis le parent :

- Dans l'en-tête de la section **Éléments enfants**, sélectionnez **Options d'affichage** ({{< icon name="preferences" >}}) > **Afficher sur une feuille de route**.

### Ajouter un epic enfant à un epic {#add-a-child-epic-to-an-epic}

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le groupe de l'epic parent.

#### Nouvel epic {#new-epic}

Pour ajouter un nouvel epic en tant qu'epic enfant :

1. Dans un epic, dans la section **Éléments enfants**, sélectionnez **Ajouter** > **Ajouter un nouvel epic**.
1. Sélectionnez un groupe dans la liste déroulante. Le groupe de l'epic est sélectionné par défaut.
1. Saisissez un titre pour le nouvel epic.
1. Sélectionnez **Créer une épopée**.

#### Epic existant {#existing-epic}

Pour ajouter un epic existant en tant qu'epic enfant :

1. Dans un epic, dans la section **Éléments enfants**, sélectionnez **Ajouter** > **Epic existant**.
1. Identifiez l'epic à ajouter en utilisant l'une des méthodes suivantes :
   - Collez le lien de l'epic.
   - Recherchez l'epic souhaité en saisissant une partie du titre de l'epic, puis sélectionnez la correspondance souhaitée. Cette recherche est uniquement disponible pour les épics dans la même hiérarchie de groupes.

   S'il y a plusieurs épics à ajouter, appuyez sur <kbd>Espace</kbd> et répétez cette étape.
1. Sélectionnez **Ajouter**.

### Déplacer des épics enfants entre des épics {#move-child-epics-between-epics}

Les nouveaux épics enfants apparaissent en haut de la liste dans la section **Éléments enfants**. Vous pouvez déplacer des épics enfants d'un epic à un autre. Lorsque vous ajoutez un nouvel epic déjà lié à un epic parent, le lien vers son parent actuel est supprimé. Les tickets et les épics enfants ne peuvent pas être mélangés.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le groupe de l'epic parent.

Pour déplacer des épics enfants vers un autre epic :

1. Accédez à la section **Éléments enfants**.
1. Faites glisser les épics vers l'epic parent souhaité.

### Réordonner les épics enfants assignés à un epic {#reorder-child-epics-assigned-to-an-epic}

Les nouveaux épics enfants apparaissent en haut de la liste dans la section **Éléments enfants**. Vous pouvez réordonner la liste des épics enfants.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le groupe de l'epic parent.

Pour réordonner les épics enfants assignés à un epic :

1. Accédez à la section **Éléments enfants**.
1. Faites glisser les épics dans l'ordre souhaité.

### Retirer un epic enfant d'un epic parent {#remove-a-child-epic-from-a-parent-epic}

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le groupe de l'epic parent.

Pour retirer un epic enfant d'un epic parent :

1. Sélectionnez **Supprimer** ({{< icon name="close" >}}) dans la liste des épics de l'epic parent. L'avertissement **Supprimer l'epic** apparaît.
1. Sélectionnez **Supprimer**.

## Configurer les préférences d'affichage des éléments enfants {#configure-child-item-display-preferences}

Vous pouvez configurer les informations affichées dans la section **Éléments enfants**, afin de vous concentrer sur ce qui importe le plus pour votre workflow.

{{< history >}}

- Les options d'affichage pour les éléments enfants ont été [étendues](https://gitlab.com/gitlab-org/gitlab/-/work_items/551231) dans GitLab 18.10.

{{< /history >}}

Vous pouvez configurer les informations affichées dans la section **Éléments enfants**, afin de vous concentrer sur ce qui importe le plus pour votre workflow.

> [!note]
> Lorsque vous modifiez les informations affichées dans un epic ou un ticket, vous les modifiez pour tous les éléments de travail dans vos groupes et projets.

1. Dans le coin supérieur droit de l'en-tête de la section **Éléments enfants**, sélectionnez **Options d'affichage** ({{< icon name="preferences" >}}).

   Par défaut, toutes les options et tous les champs sont visibles.
1. Pour modifier les informations affichées, activez ou désactivez les bascules suivantes :

   - Pour les options d'affichage :
     - **Afficher les éléments fermés**
   - Pour les champs affichés :
     - **Statut**
     - **Personne assignée**
     - **Labels**
     - **Poids**
     - **Jalon**
     - **Itération**
     - **Dates**
     - **Santé**
     - **Bloqué/Blocage**

## Sujets connexes {#related-topics}

- [Gérer les épics](../group/epics/manage_epics.md)
- [Gérer les tickets](../project/issues/managing_issues.md)
