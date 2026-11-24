---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Notifications Discord
description: "Configurez l'intégration des notifications Discord pour recevoir des notifications de GitLab dans les canaux Discord."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'intégration Notifications Discord envoie des notifications d'événements de GitLab vers le canal pour lequel le webhook a été créé.

Pour envoyer des notifications d'événements GitLab vers un canal Discord, [créez un webhook dans Discord](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks) et configurez-le dans GitLab.

## Créer un webhook {#create-webhook}

1. Ouvrez le canal Discord sur lequel vous souhaitez recevoir les notifications d'événements GitLab.
1. Dans le menu du canal, sélectionnez **Modifier le canal**.
1. Sélectionnez **Intégrations**.
1. S'il n'existe aucun webhook, sélectionnez **Créer un webhook**. Sinon, sélectionnez **Afficher les webhooks**, puis **Nouveau webhook**.
1. Saisissez le nom du bot qui publiera le message.
1. Facultatif. Modifiez l'avatar.
1. Copiez l'URL depuis la zone de texte **URL DU WEBHOOK**.
1. Sélectionnez **Enregistrer**.

## Configurer le webhook créé dans GitLab {#configure-created-webhook-in-gitlab}

{{< history >}}

- Validation de l'URL du webhook introduite dans GitLab 18.0.

{{< /history >}}

Prérequis :

- Vous devez utiliser une URL Discord (`https://discord.com/api/webhooks/webhook-snowflake/webhook-token`).

Avec l'URL du webhook créée dans le canal Discord, vous pouvez configurer l'intégration Notifications Discord dans GitLab.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Notifications Discord**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Dans la zone de texte **Crochet Web**, collez l'URL du webhook que vous avez [créé précédemment](#create-webhook).
1. Cochez les cases correspondant aux événements GitLab pour lesquels vous souhaitez envoyer des notifications à Discord.
1. Facultatif. Pour chaque case cochée, saisissez une autre URL de webhook Discord que vous avez [configurée](#create-webhook) afin de remplacer l'URL dans la zone de texte **Crochet Web**.
1. Configurez les options restantes et sélectionnez **Enregistrer les modifications**.

Le canal Discord pour lequel vous avez créé le webhook reçoit désormais les notifications des événements GitLab qui ont été configurés.
