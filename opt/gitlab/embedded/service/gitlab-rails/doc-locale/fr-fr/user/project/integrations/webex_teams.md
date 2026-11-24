---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Webex Teams
description: "Envoyez des notifications d'événements depuis GitLab vers des espaces Webex Teams avec des webhooks."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez configurer GitLab pour envoyer des notifications à un espace Webex Teams :

1. Créez un webhook pour l'espace.
1. Ajoutez le webhook à GitLab.

## Créer un webhook pour l'espace {#create-a-webhook-for-the-space}

1. Accédez à la [page de l'application Incoming Webhooks](https://apphub.webex.com/applications/incoming-webhooks-cisco-systems-38054-23307-75252).
1. Sélectionnez **Connecter** et connectez-vous à Webex Teams si nécessaire.
1. Saisissez un nom pour le webhook et sélectionnez l'espace pour recevoir les notifications.
1. Sélectionnez **AJOUTER**.
1. Copiez l'**URL du crochet Web**.

## Configurer les paramètres dans GitLab {#configure-settings-in-gitlab}

Prérequis :

- Accès administrateur pour activer l'intégration pour une instance.
- Le rôle Propriétaire pour activer l'intégration pour un groupe.
- Le rôle Maintainer ou Propriétaire pour activer l'intégration pour un projet.

Une fois que vous disposez d'une URL de webhook pour votre espace Webex Teams, vous pouvez configurer GitLab pour envoyer des notifications :

1. Pour activer l'intégration :
   - Pour votre groupe ou projet :
     1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
     1. Sélectionnez **Paramètres** > **Intégrations**.
   - Pour votre instance :
     1. Dans le coin supérieur droit, sélectionnez **Admin**.
     1. Sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez l'intégration **Webex Teams**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Cochez les cases correspondant aux événements GitLab que vous souhaitez recevoir dans Webex Teams.
1. Collez l'URL du **Crochet Web** pour l'espace Webex Teams.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

L'espace Webex Teams commence à recevoir tous les événements GitLab applicables.
