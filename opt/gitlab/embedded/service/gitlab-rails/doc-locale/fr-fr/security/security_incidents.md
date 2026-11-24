---
stage: Security
group: Security Operations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Détecter, analyser et répondre aux incidents de sécurité dans GitLab."
title: Incidents de sécurité
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'équipe GitLab Security Operations a rédigé ces recommandations pour aider les administrateurs et les responsables des instances GitLab Self-Managed et des groupes sur GitLab.com à détecter les incidents de sécurité impliquant GitLab et à y répondre. Utilisez-les pour compléter les processus de sécurité définis par votre organisation, et non pour les remplacer.

La détection et la réponse fonctionnent ensemble :

1. Détection : collectez les événements d'audit et les journaux, centralisez-les dans un système de gestion des informations et des événements de sécurité (SIEM), et déployez des règles de détection qui vous alertent en cas d'activité suspecte.
1. Réponse : lorsqu'une détection se déclenche et que vous confirmez un incident, contenez la menace, déterminez sa portée et remédiez aux comptes, aux identifiants et aux paramètres affectés.

## Collecter la télémétrie de sécurité {#collect-security-telemetry}

Comprenez les types de télémétrie de sécurité que GitLab produit, ce que chacun vous indique, et ce que vous pouvez collecter selon votre offre et votre édition d'abonnement : les événements d'audit consultables, les événements d'audit diffusables en continu vers un SIEM et les journaux d'application.

Pour plus d'informations, consultez la [télémétrie de sécurité](security_telemetry.md).

## Détecter les incidents de sécurité {#detect-security-incidents}

Créez une couverture de détection pour les activités liées à la sécurité dans GitLab. Découvrez quelles sources de données collecter, comment diffuser en continu les événements d'audit vers un SIEM, comment utiliser le framework de détection open source TLDR et quels signaux surveiller pour les scénarios d'incidents courants.

Pour plus d'informations, consultez la [détection des incidents de sécurité](detecting_security_incidents.md).

## Répondre aux incidents de sécurité {#respond-to-security-incidents}

Contenez et remédiez aux incidents de sécurité courants dans GitLab, notamment les identifiants exposés, les comptes d'utilisateurs compromis, les incidents liés à CI/CD, les instances compromises et les paramètres de projet ou de groupe mal configurés.

Pour plus d'informations, consultez la [réponse aux incidents de sécurité](responding_to_security_incidents.md).

## Sujets connexes {#related-topics}

- [Sécuriser GitLab](_index.md)
- [Recommandations de renforcement](hardening.md)
- [Types d'événements d'audit](../user/compliance/audit_event_types.md)
