---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Unify Circuit
description: "Configurez GitLab pour envoyer des notifications d'événements aux conversations Unify Circuit."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'intégration Unify Circuit envoie des notifications de GitLab vers une conversation Circuit.

## Configurer Unify Circuit {#set-up-unify-circuit}

Dans Unify Circuit, [ajoutez un webhook](https://www.circuit.com/unifyportalfaqdetail?articleId=164448) et copiez son URL.

Dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Unify Circuit**.
1. Activez le bouton bascule **Actif**.
1. Cochez les cases correspondant aux événements GitLab que vous souhaitez recevoir dans Unify Circuit.
1. Collez l'**URL du crochet Web** que vous avez copiée lors de l'étape de configuration d'Unify Circuit.
1. Cochez la case **Envoyer une notification uniquement pour les pipelines cassés** pour n'être notifié qu'en cas d'échec.
1. Cochez la case **Envoyer une notification uniquement lorsque le statut change** pour envoyer des notifications uniquement lorsque le statut du pipeline pour la référence change.
1. Dans la liste déroulante **Branches pour lesquelles des notifications doivent être envoyées**, sélectionnez les types de branches pour lesquelles envoyer des notifications.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

Votre conversation Unify Circuit commence désormais à recevoir des notifications d'événements GitLab.
