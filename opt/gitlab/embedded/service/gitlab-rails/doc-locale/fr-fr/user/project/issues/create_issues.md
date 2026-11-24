---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Créer un ticket
description: "Créez un ticket à partir d'un projet, d'un groupe, d'un autre ticket, d'un tableau des tickets, par courriel, via une URL préremplie ou via Service Desk."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque vous créez un ticket, vous êtes invité à renseigner les champs du ticket. Si vous connaissez les valeurs que vous souhaitez attribuer à un ticket, vous pouvez utiliser les [actions rapides](../quick_actions.md) pour les saisir.

Vous pouvez créer un ticket de plusieurs façons dans GitLab :

- [À partir d'un projet](#from-a-project)
- [À partir d'un groupe](#from-a-group)
- [À partir d'un autre ticket ou incident](#from-another-issue-or-incident)
- [À partir d'un tableau des tickets](#from-an-issue-board)
- [En envoyant un courriel](#by-sending-an-email)
- [À l'aide d'une URL avec des valeurs préremplies](#using-a-url-with-prefilled-values)
- [À l'aide de Service Desk](#using-service-desk)

## À partir d'un projet {#from-a-project}

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet.

Pour créer un ticket :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. L'une ou l'autre des options :

   - Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**, puis, dans le coin supérieur droit, sélectionnez **Nouvel élément**.
   - Dans le coin supérieur droit, sélectionnez le signe plus ({{< icon name="plus" >}}) puis, sous **Dans ce projet**, sélectionnez **Nouvel élément de travail**.

1. Dans la liste déroulante **Type**, sélectionnez **Ticket** si ce n'est pas déjà le cas.
1. Renseignez les [champs](#fields-in-the-new-issue-form).
1. Sélectionnez **Créer un ticket**.

Le ticket nouvellement créé s'ouvre.

## À partir d'un groupe {#from-a-group}

Les tickets appartiennent à des projets, mais lorsque vous êtes dans un groupe, vous pouvez accéder aux tickets appartenant aux projets du groupe et en créer de nouveaux.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet dans le groupe.

Pour créer un ticket à partir d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Dans le coin supérieur droit, sélectionnez **Sélectionner un projet pour créer un ticket**.
1. Sélectionnez le projet pour lequel vous souhaitez créer un ticket. Le bouton reflète désormais le projet sélectionné.
1. Sélectionnez **Nouveau ticket dans `<project name>`**.
1. Renseignez les [champs](#fields-in-the-new-issue-form).
1. Sélectionnez **Créer un ticket**.

Le ticket nouvellement créé s'ouvre.

Le projet que vous avez sélectionné le plus récemment devient le projet par défaut pour votre prochaine visite. Cela peut vous faire gagner beaucoup de temps si vous créez principalement des tickets pour le même projet.

## À partir d'un autre ticket ou incident {#from-another-issue-or-incident}

Vous pouvez créer un nouveau ticket à partir d'un ticket existant. Les deux tickets peuvent ensuite être marqués comme liés.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet.

Pour créer un ticket à partir d'un autre ticket :

1. Dans un ticket existant, sélectionnez **Actions du ticket** ({{< icon name="ellipsis_v" >}}).
1. Sélectionnez **Nouveau ticket lié**.
1. Renseignez les [champs](#fields-in-the-new-issue-form). Le formulaire de nouveau ticket comporte une case à cocher **Lier au ticket n°123**, où `123` est l'identifiant du ticket d'origine. Si vous laissez cette case cochée, les deux tickets deviennent [liés](related_issues.md).
1. Sélectionnez **Créer un ticket**.

Le ticket nouvellement créé s'ouvre.

## À partir d'un tableau des tickets {#from-an-issue-board}

Vous pouvez créer un nouveau ticket à partir d'un [tableau des tickets](../issue_board.md).

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet.

Pour créer un ticket à partir d'un tableau des tickets de projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Tableaux des tickets**.
1. En haut d'une liste du tableau, sélectionnez **Créer un nouveau ticket** ({{< icon name="plus-square" >}}).
1. Saisissez le titre du ticket.
1. Sélectionnez **Créer un ticket**.

Pour créer un ticket à partir d'un tableau des tickets de groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Tableaux des tickets**.
1. En haut d'une liste du tableau, sélectionnez **Créer un nouveau ticket** ({{< icon name="plus-square" >}}).
1. Saisissez le titre du ticket.
1. Sous **Projets**, sélectionnez le projet du groupe auquel le ticket doit appartenir.
1. Sélectionnez **Créer un ticket**.

Le ticket est créé et apparaît dans la liste du tableau. Il partage la caractéristique de la liste ; ainsi, par exemple, si la liste est limitée à un label `Frontend`, le nouveau ticket aura également ce label.

## En envoyant un courriel {#by-sending-an-email}

{{< history >}}

- **Envoyer un nouveau ticket à ce projet par courriel** [renommé](https://gitlab.com/gitlab-org/gitlab/-/issues/560277) en **Envoyer le ticket à ce projet par courriel** dans GitLab 18.6.

{{< /history >}}

Vous pouvez envoyer un courriel pour créer un ticket dans un projet depuis la page **Tickets** du projet.

Prérequis :

- Votre instance GitLab doit être configurée avec un [courriel entrant](../../../administration/incoming_email.md) et une [sous-adresse de courriel ou une boîte de réception universelle](../../../administration/incoming_email.md#requirements).
- La liste des tickets doit contenir au moins un ticket.
- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet.

Pour envoyer un ticket à un projet par courriel :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Dans le coin supérieur droit, sélectionnez **Plus d'actions** ({{< icon name="ellipsis_v" >}}), puis sélectionnez **Envoyer un élément de travail à ce projet par courriel**.
1. Pour copier l'adresse courriel, sélectionnez **Copier** ({{< icon name="copy-to-clipboard" >}}).
1. Depuis votre client de messagerie, envoyez un courriel à cette adresse. L'objet est utilisé comme titre du nouveau ticket, et le corps du courriel devient la description. Vous pouvez utiliser [Markdown](../../markdown.md) et les [actions rapides](../quick_actions.md).

Un nouveau ticket est créé, avec votre utilisateur comme auteur. Vous pouvez enregistrer cette adresse comme contact dans votre client de messagerie pour la réutiliser.

> [!warning]
> L'adresse courriel que vous voyez est une adresse courriel privée, générée uniquement pour vous. Gardez-la pour vous, car toute personne qui la connaît peut créer des tickets ou des merge requests en se faisant passer pour vous. Si vous pensez que cette adresse courriel privée a été divulguée, réinitialisez immédiatement le jeton.

Pour réinitialiser l'adresse courriel :

1. Sur la page **Tickets**, sélectionnez **Envoyer le ticket à ce projet par courriel**.
1. Sélectionnez **réinitialiser ce jeton**.

## À l'aide d'une URL avec des valeurs préremplies {#using-a-url-with-prefilled-values}

Pour créer un lien direct vers la page du nouveau ticket avec des champs préremplis, utilisez des paramètres de chaîne de requête dans une URL. Vous pouvez intégrer une URL dans une page HTML externe pour créer des tickets avec certains champs préremplis.

Pour construire l'URL permettant de créer un ticket avec des valeurs préremplies, combinez :

1. L'URL de la page Tickets du projet ou du groupe, suivie de `/new`. Par exemple : `https://gitlab.com/gitlab-org/gitlab/-/work_items/new`

1. `?` pour commencer à lister les paramètres.
1. Le paramètre d'URL, suivi de `=` et de la valeur. Par exemple : `issue[title]=My%20test%20issue`.
1. Facultatif. `&` pour joindre d'autres paramètres.

| Champ                                                                                          | Paramètre d'URL          | Remarques |
| ---------------------------------------------------------------------------------------------- | ---------------------- | ----- |
| Titre                                                                                          | `issue[title]`         | Doit être [encodé en URL](../../../api/rest/_index.md#namespaced-paths). |
| Type de ticket                                                                                     | `issue[issue_type]`    | `incident` ou `issue`. |
| Modèle de description (tickets, incidents et merge requests)                                   | `issuable_template`    | Doit être [encodé en URL](../../../api/rest/_index.md#namespaced-paths). |
| Modèle de description (tâches, OKR, tickets et epics) | `description_template` | Doit être [encodé en URL](../../../api/rest/_index.md#namespaced-paths). [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/513095) dans GitLab 17.9. |
| Description | `issue[description]` | Doit être [encodé en URL](../../../api/rest/_index.md#namespaced-paths). Si utilisé en combinaison avec `issuable_template` ou un [modèle de ticket par défaut](../description_templates.md#set-a-default-template-for-merge-requests-and-issues), la valeur `issue[description]` remplace le modèle. |
| Confidentiel                                                                                   | `issue[confidential]`  | Si `true`, le ticket est marqué comme confidentiel. |
| Lier à…                                                                                     | `add_related_issue`    | Un identifiant de ticket numérique. Le cas échéant, le formulaire de ticket affiche une [case à cocher **Lier à**](#from-another-issue-or-incident) pour lier facultativement le nouveau ticket au ticket existant spécifié. |

Dans [GitLab 17.8 et versions ultérieures](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/177215), lorsque vous sélectionnez un modèle de ticket, l'URL change pour afficher le modèle utilisé.

Adaptez ces exemples pour former l'URL de votre nouveau ticket avec des champs préremplis. Pour créer un ticket dans le projet GitLab :

- Avec un titre et une description préremplis :

  ```plaintext
  https://gitlab.com/gitlab-org/gitlab/-/work_items/new?issue[title]=Whoa%2C%20we%27re%20half-way%20there&issue[description]=Whoa%2C%20livin%27%20in%20a%20URL
  ```

- Avec un titre et un modèle de description préremplis :

  ```plaintext
  https://gitlab.com/gitlab-org/gitlab/-/work_items/new?issue[title]=Validate%20new%20concept&issuable_template=Feature%20Proposal%20-%20basic
  ```

- Avec un titre et une description préremplis, et marqué comme confidentiel :

  ```plaintext
  https://gitlab.com/gitlab-org/gitlab/-/work_items/new?issue[title]=Validate%20new%20concept&issue[description]=Research%20idea&issue[confidential]=true
  ```

## À l'aide de Service Desk {#using-service-desk}

Pour proposer une assistance par courriel, activez [Service Desk](../service_desk/_index.md) pour votre projet.

Désormais, lorsque votre client envoie un nouveau courriel, un nouveau ticket peut être créé dans le projet approprié et traité depuis celui-ci.

## Champs du formulaire de nouveau ticket {#fields-in-the-new-issue-form}

Lorsque vous créez un nouveau ticket, vous pouvez renseigner les champs suivants :

- Titre : [prise en charge limitée de la mise en forme](../../markdown.md#work-item-and-merge-request-titles)
- Projet : correspond par défaut au projet actuel
- Type : ticket (par défaut) ou incident
- [Modèle de description](../description_templates.md) : remplace tout contenu dans la zone de texte Description
- Description : vous pouvez utiliser [Markdown](../../markdown.md) et les [actions rapides](../quick_actions.md)
- Case à cocher pour rendre le ticket [confidentiel](confidential_issues.md)
- [Responsables](managing_issues.md#assignees)
- [Poids](../../work_items/weight.md)
- [Parent](../../group/epics/_index.md)
- [Dates](due_dates.md)
- [Jalon](../milestones/_index.md)
- [Labels](../labels.md)
- [Itération](../../group/iterations/_index.md)
- [État de santé](managing_issues.md#health-status)
- [Contacts](../../crm/_index.md)
