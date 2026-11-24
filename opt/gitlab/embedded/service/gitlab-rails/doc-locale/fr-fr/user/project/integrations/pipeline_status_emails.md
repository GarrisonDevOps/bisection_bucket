---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Courriels sur l'état du pipeline"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez envoyer des notifications concernant les changements de statut de pipeline dans un groupe ou un projet à une liste d'adresses e-mail.

Les notifications de pipeline déclenchées par des utilisateurs bloqués ne sont pas transmises.

## Activer les notifications par e-mail sur l'état du pipeline {#enable-pipeline-status-email-notifications}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire pour le projet, ou du rôle Propriétaire pour le groupe.

Pour activer les courriels sur l'état du pipeline :

1. Dans votre projet ou groupe, dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Courriels sur l'état du pipeline**.
1. Assurez-vous que la case **Actif** est cochée.
1. Dans **Destinataires**, saisissez une liste d'adresses e-mail séparées par des virgules. Les adresses e-mail non valides sont automatiquement filtrées et ne recevront pas de notifications.
1. Facultatif. Pour recevoir des notifications uniquement pour les pipelines cassés, sélectionnez **Envoyer une notification uniquement pour les pipelines cassés**.
1. Facultatif. Pour recevoir des notifications uniquement lorsque le statut d'un pipeline change, sélectionnez **Envoyer une notification uniquement en cas de changement de statut**.
1. Facultatif. Pour recevoir des notifications pour les pipelines parents et enfants, sélectionnez **Envoyer une notification pour les pipelines enfants**.
1. Sélectionnez les branches pour lesquelles envoyer des notifications.
1. Sélectionnez **Enregistrer les modifications**.
