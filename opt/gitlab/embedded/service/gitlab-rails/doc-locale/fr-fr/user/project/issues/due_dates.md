---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: "Dates d'échéance"
description: "Définissez des dates d'échéance sur les tickets, les epics et d'autres éléments de travail pour suivre les délais, visualiser les travaux à venir et exporter les dates d'échéance vers un calendrier."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Le rôle minimum requis pour définir des dates d'échéance a été [modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Utilisez les dates d'échéance dans les éléments de travail pour suivre les délais et vous assurer que les fonctionnalités sont livrées dans les temps.

Les dates d'échéance sont prises en charge dans :

- [Les tickets](_index.md)
- [Les epics](../../group/epics/_index.md)
- [Tâches](../../tasks.md)
- [OKR](../../okrs.md)
- [Incidents](../../../operations/incident_management/incidents.md)

La veille de la date d'échéance d'un élément ouvert, un e-mail est envoyé à tous les participants.
<!-- For issue due timing source, see 'issue_due_scheduler_worker' in <https://gitlab.com/gitlab-org/gitlab/-/blob/master/config/initializers/1_settings.rb> -->
La notification est envoyée à 00:50 selon le fuseau horaire du serveur (pour GitLab.com, il s'agit de l'UTC) pour tous les éléments ouverts dont la date d'échéance correspond au jour calendaire suivant.

Les dates d'échéance apparaissent également dans vos [éléments de la liste de tâches](../../todos.md).

## Afficher les tickets avec des dates d'échéance {#view-issues-with-due-dates}

Vous pouvez voir les tickets avec leurs dates d'échéance sur la page **Éléments de travail**. Si un ticket contient une date d'échéance, elle est affichée sous le titre du ticket :

![Un ticket avec une date d'échéance en 2024.](img/overdue_issue_v17_9.png)

Les dates de ticket passées sont affichées avec une icône rouge ({{< icon name="calendar-overdue" >}}).

Pour afficher et trier les tickets contenant des dates d'échéance dans votre projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail** et filtrez par **Type** = **Ticket**.
1. À droite de la barre de filtre, sélectionnez **Afficher** ({{< icon name="preferences" >}}) pour ouvrir le panneau des préférences d'affichage.
1. En haut du panneau, dans la liste déroulante **Trier par**, sélectionnez **Date d'échéance**.
1. Facultatif. Pour inverser l'ordre de tri, dans le panneau des préférences d'affichage, à côté de la liste déroulante **Trier par**, sélectionnez **Sens de tri** ({{< icon name="sort-lowest" >}}).

## Définir une date d'échéance pour un ticket {#set-a-due-date-for-an-issue}

Tous les utilisateurs autorisés à consulter le ticket peuvent voir sa date d'échéance.

### Lors de la création d'un ticket {#when-creating-an-issue}

Si vous avez le rôle Planificateur, Reporter, Developer, Maintainer ou Owner, lors de la création d'un ticket, sélectionnez **Date d'échéance** pour afficher un calendrier. Cette date utilise le fuseau horaire du serveur, et non celui de l'utilisateur actuel.

Pour supprimer la date, sélectionnez le texte de la date, puis supprimez-le.

### Dans un ticket existant {#in-an-existing-issue}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner.

Pour cela :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**, puis filtrez par **Type** = **Ticket** et sélectionnez votre ticket.
1. Dans la barre latérale droite, dans la section **Dates**, sélectionnez **Modifier**.
1. Sélectionnez la date souhaitée, puis sélectionnez **Appliquer** pour enregistrer vos modifications.

### Avec une action rapide {#with-a-quick-action}

Pour définir une date d'échéance avec des actions rapides dans la description ou un commentaire d'un ticket :

- [`/due`](../quick_actions.md#due) : définir la date d'échéance.
- [`/remove_due_date`](../quick_actions.md#remove_due_date) : supprimer une date d'échéance existante.

## Exporter les dates d'échéance des tickets vers un calendrier {#export-issue-due-dates-to-a-calendar}

Les tickets avec des dates d'échéance peuvent également être exportés sous forme de flux iCalendar. L'URL du flux peut être ajoutée aux applications de calendrier.

- La page **Éléments de travail du projet**
- La page **Éléments de travail du groupe**

1. Accédez à la page contenant la liste des tickets auxquels vous souhaitez vous abonner. Par exemple :

   - [Tickets qui vous sont assignés](managing_issues.md#view-all-issues-assigned-to-you)
   - [Tickets dans un projet spécifique](managing_issues.md#issue-list)
   - Tickets pour tous les projets [dans un groupe](../../group/_index.md)

1. À droite, dans la liste déroulante **Actions** ({{< icon name="ellipsis_v" >}}), sélectionnez **S'abonner au calendrier** pour afficher le fichier `.ics`.
1. Copiez le lien complet vers la page (y compris la chaîne de requête complète) et utilisez-le dans l'application de calendrier de votre choix.
