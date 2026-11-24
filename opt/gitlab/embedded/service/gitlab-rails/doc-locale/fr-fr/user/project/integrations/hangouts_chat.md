---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Google Chat
description: "Configurez l'intégration Google Chat pour recevoir des notifications de GitLab dans un espace Google Chat."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez configurer votre projet dans GitLab pour envoyer des notifications à l'espace de votre choix dans [Google Chat](https://chat.google.com/).

Les notifications en fil de discussion sont activées par défaut dans Google Chat pour le même objet GitLab (par exemple, un ticket ou une merge request). Pour plus d'informations, consultez le [ticket 438452](https://gitlab.com/gitlab-org/gitlab/-/issues/438452).

## Configurer l'intégration {#configure-the-integration}

### Dans Google Chat {#in-google-chat}

Pour configurer l'intégration dans Google Chat :

1. Accédez à l'espace où vous souhaitez recevoir des notifications de GitLab.
1. En haut à gauche, à côté du nom de l'espace, sélectionnez la flèche vers le bas ({{< icon name="chevron-down" >}}) > **Apps & integrations**.
1. Dans la section **Crochets web**, sélectionnez **Add webhooks**.
1. Dans la boîte de dialogue **Incoming webhooks** :
   - Dans **Nom**, saisissez un nom pour votre webhook (par exemple, `GitLab integration`).
   - Facultatif. Dans **Avatar URL**, saisissez un avatar pour votre bot.
1. Sélectionnez **Enregistrer**.
1. À côté de l'URL du webhook, sélectionnez l'ellipse verticale ({{< icon name="ellipsis_v" >}}) > **Copier le lien**.

Pour plus d'informations sur les webhooks, consultez la [documentation Google Chat](https://developers.google.com/workspace/chat/quickstart/webhooks).

### Dans GitLab {#in-gitlab}

Pour configurer l'intégration dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Google Chat**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Dans **Crochet Web**, [collez l'URL copiée depuis Google Chat](#in-google-chat).
1. Dans la section **Déclencheur**, cochez la case correspondant à chaque événement GitLab pour lequel vous souhaitez recevoir des notifications dans votre espace Google Chat.
1. Facultatif. Dans la section **Paramètres de notification** :
   - Cochez la case **Envoyer une notification uniquement pour les pipelines cassés** pour recevoir des notifications uniquement pour les pipelines en échec.
   - Cochez la case **Notify only when status changes** pour recevoir des notifications uniquement lorsque le statut du pipeline pour la référence change.
   - Dans la liste déroulante **Branches pour lesquelles des notifications doivent être envoyées**, sélectionnez les branches pour lesquelles vous souhaitez recevoir des notifications.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.
