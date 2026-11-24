---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Courriels lors des poussées
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Utilisez les courriels lors des poussées pour recevoir des notifications par courriel concernant les modifications poussées vers votre projet GitLab. Vous pouvez sélectionner les événements de poussée qui déclenchent ces notifications.

Avec les courriels lors des poussées, vous pouvez spécifier une liste d'adresses courriel pour recevoir les commits et les diffs à chaque poussée.

## Configurer l'intégration {#set-up-the-integration}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour configurer les courriels lors des poussées :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Courriels lors des poussées**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Dans **Destinataires**, saisissez une liste d'adresses courriel séparées par des espaces ou des sauts de ligne. Les adresses courriel invalides sont automatiquement filtrées et ne reçoivent pas de notifications.
1. Configurez les options suivantes :

   - **Événements poussés** \- Un courriel est déclenché lors de la réception d'un événement de poussée.
   - **Événements en lien avec les poussées d'étiquette** \- Un courriel est déclenché lorsqu'une étiquette est créée et poussée.
   - **Envoyer depuis le contributeur** \- Envoie les notifications depuis l'adresse courriel du contributeur si le domaine correspond au domaine utilisé par votre instance GitLab (par exemple `user@gitlab.com`).
   - **Désactiver les diffs de code** \- N'inclut pas les diffs de code potentiellement sensibles dans le corps de la notification.
