---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Utiliser le Service d'assistance"
description: "Créez un ticket Service d'assistance par e-mail ou dans l'interface utilisateur de GitLab, et répondez aux tickets depuis le suivi de tickets."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

Vous pouvez utiliser le Service d'assistance pour [créer un ticket](#as-an-end-user-ticket-creator) ou [y répondre](#as-a-responder-to-the-ticket). Dans ces tickets, vous pouvez également voir le [Support Bot](configure.md#support-bot-user).

## Afficher l'adresse e-mail du Service d'assistance {#view-service-desk-email-address}

Pour vérifier l'adresse e-mail du Service d'assistance de votre projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Supervision** > **Service d'assistance**.

L'adresse e-mail est disponible en haut de la liste des tickets.

## En tant qu'utilisateur final (créateur de ticket) {#as-an-end-user-ticket-creator}

Pour créer un ticket Service d'assistance, un utilisateur final n'a pas besoin de connaître quoi que ce soit sur l'instance GitLab. Il envoie simplement un e-mail à l'adresse qui lui est communiquée et reçoit en retour un e-mail du Support Bot de GitLab confirmant la réception :

```plaintext
Thank you for your support request! We are tracking your request as ticket `#%{issue_iid}`, and will respond as soon as we can.
```

Cet e-mail offre également à l'utilisateur final la possibilité de se désabonner.

S'il ne choisit pas de se désabonner, tout nouveau commentaire ajouté au ticket lui est envoyé par e-mail.

Toutes les réponses qu'il envoie par e-mail sont affichées dans le ticket lui-même.

Pour plus d'informations, voir [les participants externes](external_participants.md) et les [en-têtes utilisés pour le traitement des e-mails](../../../administration/incoming_email.md#accepted-headers).

### Créer un ticket Service d'assistance dans l'interface utilisateur de GitLab {#create-a-service-desk-ticket-in-gitlab-ui}

Prérequis :

- Le Service d'assistance doit être [configuré pour le projet](configure.md). Sur GitLab Self-Managed, cela inclut la configuration des [e-mails entrants](../../../administration/incoming_email.md#set-it-up) avec le sous-adressage d'e-mail ou une boîte mail de type catch-all. Sans e-mail entrant, l'action rapide `/convert_to_ticket` n'est pas disponible.

Pour créer un ticket Service d'assistance depuis l'interface utilisateur :

1. [Créez un ticket](../issues/create_issues.md).
1. Ajoutez un commentaire contenant uniquement l'action rapide `/convert_to_ticket user@example.com`. Vous devriez voir un commentaire du [Support Bot de GitLab](configure.md#support-bot-user).
1. Rechargez la page afin que l'interface utilisateur reflète le changement de type.
1. Facultatif. Ajoutez un commentaire sur le ticket pour envoyer un e-mail Service d'assistance initial au participant externe.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation générale, voir [créer des tickets Service d'assistance dans l'interface utilisateur et l'API](https://www.youtube.com/watch?v=ibUGNc2wifQ).
<!-- Video published on 2024-03-05 -->

## En tant que personne chargée de répondre au ticket {#as-a-responder-to-the-ticket}

Pour les personnes chargées de répondre aux tickets, tout fonctionne comme avec les tickets GitLab. GitLab affiche un suivi de tickets familier où les personnes chargées des réponses peuvent voir les tickets créés via les demandes d'assistance client, les filtrer ou interagir avec eux.

![Suivi des tickets du Service d'assistance.](img/service_desk_issue_tracker_v16_10.png)

Les messages de l'utilisateur final s'affichent comme provenant du [Support Bot](../../../subscriptions/manage_seats.md#criteria-for-non-billable-users) spécial. Vous pouvez lire et écrire des commentaires comme vous le faites habituellement dans GitLab :

- La visibilité du projet (privé, interne, public) n'affecte pas le Service d'assistance.
- Le chemin d'accès au projet, y compris son groupe ou espace de nommage, est indiqué dans les e-mails.

### Afficher les tickets du Service d'assistance {#view-service-desk-tickets}

Prérequis :

- Vous devez disposer du rôle Rapporteur, Développeur, Mainteneur ou Propriétaire pour le projet.

Pour afficher les tickets du Service d'assistance :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Supervision** > **Service d'assistance**.

#### Liste de tickets repensée {#redesigned-ticket-list}

La liste des tickets du Service d'assistance correspond désormais plus étroitement à la liste des tickets standard. Les fonctionnalités disponibles comprennent :

- Les mêmes options de tri et d'ordre [que dans la liste des tickets](../issues/sorting_issue_lists.md).
- Les mêmes filtres, notamment l'[opérateur OR](#filter-the-list-of-tickets) et le [filtrage par ID de ticket](#filter-tickets-by-id).

Il n'est plus possible de créer un nouveau ticket depuis la liste de tickets du Service d'assistance. Cette décision reflète mieux la nature du Service d'assistance, où les nouveaux tickets sont créés en envoyant un e-mail à une adresse e-mail dédiée.

##### Filtrer la liste des tickets {#filter-the-list-of-tickets}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Supervision** > **Service d'assistance**.
1. Au-dessus de la liste des tickets, sélectionnez **Rechercher ou filtrer les résultats**.
1. Dans la liste déroulante qui s'affiche, sélectionnez l'attribut par lequel vous souhaitez filtrer.
1. Sélectionnez ou saisissez l'opérateur à utiliser pour filtrer l'attribut. Les opérateurs suivants sont disponibles :
   - `=` : est
   - `!=` : n'est pas l'un des
1. Saisissez le texte permettant de filtrer l'attribut. Vous pouvez filtrer certains attributs par **Aucun** ou **Tout**.
1. Répétez cette procédure pour filtrer selon plusieurs attributs. Les attributs multiples sont joints par un opérateur logique `AND`.

##### Filtrer avec l'opérateur OR {#filter-with-the-or-operator}

Lorsque le [filtrage avec l'opérateur OR](../issues/managing_issues.md#filter-the-list-of-issues) est activé, vous pouvez utiliser **est l'un des : `||`** lorsque vous [filtrez la liste des tickets](#filter-the-list-of-tickets) par :

- Personnes assignées
- Labels

`is one of` représente un OR inclusif. Par exemple, si vous filtrez par `Assignee is one of Sidney Jones` et `Assignee is one of Zhang Wei`, GitLab affiche les tickets où `Sidney`, `Zhang`, ou les deux, sont des personnes assignées.

##### Filtrer les tickets par ID {#filter-tickets-by-id}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Supervision** > **Service d'assistance**.
1. Dans la zone de texte **Rechercher**, saisissez l'ID du ticket. Par exemple, saisissez le filtre `#10` pour n'afficher que le ticket 10.

## Contenu et mise en forme des e-mails {#email-contents-and-formatting}

### Mise en forme HTML spéciale dans les e-mails HTML {#special-html-formatting-in-html-emails}

Les e-mails HTML envoyés depuis les tickets du Service d'assistance affichent une mise en forme HTML, par exemple :

- Tableaux
- Citations
- Images
- Sections réductibles

### Fichiers joints aux commentaires {#files-attached-to-comments}

Si un commentaire contient des pièces jointes dont la taille totale est inférieure ou égale à 10 Mo, ces pièces jointes sont envoyées dans le cadre de l'e-mail. Dans les autres cas, l'e-mail contient des liens vers les pièces jointes.

## Convertir un ticket standard en ticket Service d'assistance {#convert-a-regular-issue-to-a-service-desk-ticket}

Prérequis :

- Le Service d'assistance doit être [configuré pour le projet](configure.md).

Utilisez l'action rapide `/convert_to_ticket external-ticket-author@example.com` pour convertir tout ticket standard en ticket Service d'assistance. Cela désigne l'adresse e-mail fournie comme auteur externe du ticket et l'ajoute à la liste des participants externes. Ces participants reçoivent des e-mails du Service d'assistance pour tout commentaire public sur le ticket et peuvent répondre à ces e-mails. Les réponses ajoutent un nouveau commentaire sur le ticket.

GitLab n'envoie pas l'[e-mail `thank_you`](configure.md#customize-emails-sent-to-external-participants) par défaut. Vous pouvez ajouter un commentaire public sur le ticket pour informer l'utilisateur final que le ticket a été créé.

## Considérations relatives à la confidentialité {#privacy-considerations}

Les tickets du Service d'assistance sont [confidentiels](../issues/confidential_issues.md) et ne sont donc visibles que par les membres du projet. Le propriétaire du projet peut [rendre un ticket public](../issues/confidential_issues.md#in-an-existing-issue). Lorsqu'un ticket Service d'assistance devient public, les adresses e-mail du créateur du ticket et des participants sont visibles par les utilisateurs connectés disposant du rôle Rapporteur, Développeur, Mainteneur ou Propriétaire pour le projet.

Toute personne faisant partie de votre projet peut utiliser l'adresse e-mail du Service d'assistance pour créer un ticket dans ce projet, quel que soit son rôle dans le projet.

L'adresse e-mail interne unique est visible par les membres du projet disposant au minimum du rôle Planificateur dans votre instance GitLab. Un utilisateur externe (créateur de ticket) ne peut pas voir l'adresse e-mail interne affichée dans la note d'information.

### Déplacer un ticket Service d'assistance {#moving-a-service-desk-ticket}

Vous pouvez déplacer un ticket Service d'assistance de la même manière que vous [déplacez un ticket standard](../issues/managing_issues.md#move-an-issue) dans GitLab.

Si un ticket Service d'assistance est déplacé vers un autre projet avec le Service d'assistance activé, le client qui a créé le ticket continue de recevoir des notifications par e-mail. Étant donné qu'un ticket déplacé est d'abord fermé, puis copié, le client est considéré comme participant dans les deux tickets. Il continue de recevoir toutes les notifications relatives à l'ancien ticket et au nouveau.
