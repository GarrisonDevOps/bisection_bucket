---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Participants externes
description: "Ajoutez des participants externes qui interagissent avec un ticket ou un ticket du Service d'assistance uniquement par e-mail, et gérez la façon dont ils répondent aux e-mails et s'en désabonnent."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/epics/3758) dans GitLab 17.0.

{{< /history >}}

Les participants externes sont des utilisateurs sans compte GitLab qui peuvent interagir avec un ticket ou un ticket du Service d'assistance uniquement par e-mail. Ils sont notifiés des commentaires publics sur un ticket par [e-mails du Service d'assistance](configure.md#customize-emails-sent-to-external-participants).

Le nombre maximum de participants externes sur un ticket est de 10.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation générale, consultez [plusieurs participants externes dans GitLab Service d'assistance](https://www.youtube.com/watch?v=eKNe7fYQCLc).
<!-- Video published on 2024-05-13 -->

## Tickets du Service d'assistance {#service-desk-tickets}

GitLab ajoute l'auteur externe d'un ticket du Service d'assistance en tant que participant externe. Il s'agit généralement de l'adresse e-mail provenant de l'en-tête `From` de l'e-mail initial qui a créé le ticket.

### Ajouter des participants externes depuis l'en-tête `Cc` {#add-external-participants-from-the-cc-header}

Par défaut, GitLab n'ajoute que l'expéditeur de l'e-mail qui crée le ticket du Service d'assistance en tant que participant externe.

Vous pouvez configurer GitLab pour qu'il ajoute également toutes les adresses e-mail de l'en-tête `Cc` au ticket du Service d'assistance. Cela fonctionne pour l'e-mail initial et toutes les réponses à l'[e-mail `thank_you`](configure.md#customize-emails-sent-to-external-participants).

Les participants externes ajoutés depuis l'en-tête `Cc` reçoivent l'e-mail `new_participant` à la place de l'e-mail `thank_you` pour les informer qu'ils ont été ajoutés au ticket.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour activer le paramètre pour le projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance**.
1. Sélectionnez **Ajouter des participants externes depuis l'en-tête `Cc`**.
1. Sélectionnez **Enregistrer les modifications**.

## En tant que participant externe {#as-an-external-participant}

Un participant externe reçoit une notification pour chaque commentaire public sur le ticket en utilisant les [e-mails du Service d'assistance](configure.md#customize-emails-sent-to-external-participants).

### Répondre aux e-mails de notification {#replying-to-notification-emails}

Un participant externe peut [répondre à l'e-mail de notification reçu](../../../administration/reply_by_email.md#you-reply-to-the-notification-email). Cela crée un nouveau commentaire sur le ticket et affiche l'adresse e-mail du participant externe à la place d'un nom d'utilisateur GitLab. L'adresse e-mail est suivie de `(external participant)`.

![Commentaire d'un participant externe sur un ticket.](img/service_desk_external_participants_comment_v17_0.png)

### Se désabonner des e-mails de notification {#unsubscribing-from-notification-emails}

Les participants externes peuvent utiliser le lien de désabonnement dans le modèle d'e-mail du Service d'assistance par défaut pour se désabonner du ticket.

Si vous [personnalisez vos modèles d'e-mail `thank_you`, `new_participant` et `new_note`](configure.md#customize-emails-sent-to-external-participants), vous pouvez utiliser l'espace réservé `%{UNSUBSCRIBE_URL}` pour ajouter le lien de désabonnement aux modèles.

Votre instance GitLab doit être accessible (par exemple, depuis l'internet public) pour que le participant externe puisse se désabonner avec succès. Si ce n'est pas le cas, envisagez de supprimer le lien de désabonnement de votre modèle.

Les e-mails de GitLab contiennent également des en-têtes spéciaux qui permettent aux clients de messagerie compatibles et aux autres logiciels de [désabonner automatiquement les participants externes](../../profile/notifications.md#using-an-email-client-or-other-software).

## En tant qu'utilisateur GitLab {#as-a-gitlab-user}

Pour voir l'adresse e-mail d'un participant externe, vous devez disposer du rôle Reporter, Developer, Maintainer ou Owner pour le projet.

L'adresse e-mail du participant externe est masquée si ces deux conditions sont remplies :

- Vous n'êtes pas membre du projet ou vous disposez du rôle Invité.
- Le ticket est public ([non confidentiel](../issues/confidential_issues.md)).

L'adresse e-mail du participant externe est alors masquée dans :

- Le champ auteur d'un ticket du Service d'assistance.
- Toutes les [notes système](../system_notes.md) qui mentionnent un participant externe.
- Les API [REST](../../../api/notes.md) et [GraphQL](../../../api/graphql/_index.md).
- Le message d'avertissement sous l'éditeur de commentaires.

Par exemple :

![Adresses e-mail masquées des participants externes dans les notes système.](img/service_desk_external_participants_email_obfuscation_v17_0.png)

### Notifications envoyées aux participants externes {#notifications-sent-to-external-participants}

Les participants externes reçoivent des notifications pour tous les commentaires publics sur un ticket. Pour les communications privées, utilisez les [notes internes](../../discussions/_index.md#add-an-internal-note).

Les participants externes ne reçoivent pas de notifications pour les autres événements liés au ticket.

### Afficher tous les participants externes {#view-all-external-participants}

Obtenez une vue d'ensemble de tous les participants externes qui reçoivent un e-mail du Service d'assistance pour un nouveau commentaire.

Prérequis :

- Vous devez disposer du rôle Reporter, Developer, Maintainer ou Owner pour le projet.

Pour afficher la liste de tous les participants externes :

1. Accédez au ticket.
1. Faites défiler vers le bas jusqu'à l'éditeur de commentaires.
1. Si le ticket a des participants externes, un avertissement s'affiche sous l'éditeur de commentaires, listant tous les participants externes.

![Avertissement sous l'éditeur de commentaires listant les participants externes.](img/service_desk_external_participants_comment_editor_warning_v17_0.png)

### Ajouter un participant externe {#add-an-external-participant}

{{< history >}}

- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/350460) dans GitLab 18.10. Le feature flag `issue_email_participants` a été supprimé.

{{< /history >}}

Ajoutez un participant externe à l'aide de la [action rapide `/add_email`](../quick_actions.md#add_email) lorsque vous souhaitez l'inclure dans la conversation à tout moment.

Une fois ajouté, le participant externe commence à recevoir des notifications par e-mails du Service d'assistance.

Les nouveaux participants externes reçoivent l'e-mail `new_participant` pour les informer qu'ils ont été ajoutés au ticket. GitLab n'envoie pas d'e-mail `thank_you` pour les participants externes ajoutés manuellement.

Vous devriez ajouter des participants externes dans un commentaire dédié, car ils ne reçoivent pas d'e-mail de notification pour le commentaire qui contient l'action rapide `/add_email`.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet.

Pour ajouter un participant externe à un ticket :

1. Accédez au ticket.
1. Ajoutez un commentaire contenant uniquement l'action rapide `/add_email user@example.com`. Vous pouvez enchaîner jusqu'à 6 adresses e-mail. Par exemple, `/add_email user@example.com user2@example.com`

Un message de réussite et une nouvelle note système avec l'adresse e-mail devraient s'afficher.

### Supprimer un participant externe {#remove-an-external-participant}

{{< history >}}

- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/350460) dans GitLab 18.10. Le feature flag `issue_email_participants` a été supprimé.

{{< /history >}}

Supprimez un participant externe d'un ticket ou d'un ticket du Service d'assistance à l'aide de la [action rapide `/remove_email`](../quick_actions.md#remove_email) lorsqu'il ne doit plus recevoir de notifications.

Après leur suppression du ticket, ils ne reçoivent plus de nouvelles notifications. Mais ils peuvent toujours répondre aux e-mails qu'ils ont reçus auparavant et créer un nouveau commentaire sur le ticket.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet.
- Il doit y avoir au moins un participant externe sur le ticket.

Pour supprimer un participant externe existant d'un ticket :

1. Accédez au ticket.
1. Ajoutez un commentaire contenant uniquement l'action rapide `/remove_email user@example.com`. Vous pouvez enchaîner jusqu'à 6 adresses e-mail. Par exemple, `/remove_email user@example.com user2@example.com`

Un message de réussite et une nouvelle note système avec l'adresse e-mail devraient s'afficher.
