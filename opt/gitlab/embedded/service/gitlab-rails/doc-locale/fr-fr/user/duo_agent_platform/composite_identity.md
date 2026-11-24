---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Découvrez comment l'identité composite combine un compte de service et un utilisateur humain en un seul token pour permettre des actions d'agent sécurisées et traçables."
title: Identité composite
---

{{< history >}}

- [Introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/554156) dans GitLab 18.3 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `duo_workflow_use_composite_identity`, désactivé par défaut.
- [Activée par défaut](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/212618) dans GitLab 18.6.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273) dans GitLab 18.8.
- L'identité composite est automatiquement incluse dans GitLab Duo Agent Platform et le paramètre permettant d'activer ou de désactiver l'identité composite a été [supprimé](https://gitlab.com/gitlab-org/gitlab/-/work_items/588629) dans GitLab 18.9.
- Le feature flag `duo_workflow_use_composite_identity` a été [supprimé](https://gitlab.com/gitlab-org/gitlab/-/issues/554199) dans GitLab 19.3.

{{< /history >}}

L'identité composite est un mécanisme d'authentification et d'autorisation qui combine deux identités en un seul token :

- Un compte de service. L'agent qui effectue les actions réelles.
- Un utilisateur humain. La personne qui a initié la requête.

Tous les comptes de service ont une identité composite, car chaque action qu'ils effectuent est initiée par un utilisateur humain.

L'identité composite est automatiquement incluse dans GitLab Duo Agent Platform.

Cette approche à double identité résout un défi critique : les agents doivent agir avec un accès qui ne dépasse pas celui de l'utilisateur qui les a déclenchés ni celui accordé au compte de service, tout en conservant une identité distincte qui indique clairement que l'action a été effectuée par un agent, et non directement par l'utilisateur humain.

## Pourquoi l'identité composite est importante {#why-composite-identity-matters}

L'identité composite est importante car elle contribue à garantir :

- Traçabilité : toutes les activités des agents sont clairement attribuées à un compte de service, ce qui facilite l'identification des actions automatisées dans les journaux d'audit et les historiques de commits.
- Sécurité : l'agent peut effectuer des actions auxquelles seuls le compte de service et l'utilisateur déclencheur ont accès. Cet accès intersectionnel empêche l'élévation de privilèges.
- Responsabilité : l'identité de l'utilisateur humain est intégrée dans le token, créant ainsi une piste d'audit qui relie les actions de l'agent à la personne qui les a initiées.

Par exemple, lorsque vous demandez à un agent de créer des tests pour votre code, les commits résultants indiquent qu'ils ont été créés par le compte de service en votre nom.

## Où l'identité composite est utilisée {#where-composite-identity-is-used}

L'identité composite est utilisée lorsque des flows et des agents s'exécutent sur des runners. Cette liste inclut :

- Flows par défaut.
- Flows personnalisés.
- Agents externes.
- Tout flow démarré via l'endpoint `api/v4/ai/duo_workflows/workflows`.

L'identité composite ne s'applique pas à GitLab Duo Agentic Chat dans l'interface utilisateur et l'IDE.

## Fonctionnement de l'identité composite {#how-composite-identity-works}

Le token qui authentifie les requêtes est un composite de deux identités :

- Auteur principal : l'utilisateur humain qui a démarré l'agent ou le flow. L'`id` de l'utilisateur humain est inclus dans les portées du token via une [portée dynamique](https://github.com/doorkeeper-gem/doorkeeper/pull/1739).
- Auteur secondaire : un [compte de service](../profile/service_accounts.md), qui est le propriétaire du token et possède le rôle Développeur.

Cette identité composite garantit que toutes les activités créées par GitLab Duo Agent Platform sont attribuées à l'utilisateur humain, tout en empêchant l'[élévation de privilèges](https://en.wikipedia.org/wiki/Privilege_escalation) par l'utilisateur humain ou le compte de service.

## Workflow d'identité composite {#composite-identity-workflow}

L'identité composite fait partie du workflow.

1. Créez un flow dans le catalogue d'IA.
   - Aucune modification liée à l'identité composite n'est effectuée.
1. Activez le flow pour un projet.
   - Un compte de service est créé dans le groupe principal. (Le nom est similaire à `ai-flowname-groupname`.)
   - Le compte de service est ajouté au projet avec le rôle Développeur.
1. Un utilisateur exécute le flow.
   - Le flow est exécuté par une identité composite à usage unique. Cette identité combine le rôle de l'utilisateur et le rôle Développeur du compte de service, selon le plus restrictif des deux. Ainsi, si l'utilisateur est Maintainer, mais que le compte de service est Développeur, le rôle Développeur est utilisé.
   - Le flow a accès à tous les projets auxquels :
     - L'utilisateur a accès.
     - Le compte de service a été ajouté.

     Par exemple, si le compte de service a été ajouté à d'autres projets et que l'utilisateur a accès à ces projets, le flow peut accéder à ces projets même si l'utilisateur n'y a pas encore utilisé le flow.

## Autorisations des tokens pour les flows du catalogue d'IA {#token-permissions-for-ai-catalog-flows}

Les flows du catalogue d'IA utilisent différents types de tokens avec différentes portées d'autorisations :

- Les tokens OAuth utilisés pour l'identité composite dans les workflows d'IA ont un accès limité aux portées `ai_workflows` et `mcp`. Ce token OAuth est transmis à la passerelle d'IA pour exécuter le flow.
- Les tokens de job CI déclenchés dans le cadre du flow ont des autorisations davantage restreintes par les [autorisations de token de job disponibles](../../ci/jobs/ci_job_token.md#job-token-access).

Étant donné qu'il s'agit de types de tokens différents avec des portées différentes, le job CI/CD dispose d'autorisations différentes de celles du token OAuth.

## Considérations de conformité pour les merge requests {#compliance-considerations-for-merge-requests}

Lorsqu'un flow crée une merge request, celle-ci est attribuée à l'utilisateur humain qui a déclenché le flow, et non au compte de service. Cette approche vise à respecter les référentiels de conformité qui exigent une séparation des tâches, notamment :

- SOC 2 (System and Organization Controls 2)
- SOX (Sarbanes-Oxley Act)
- ISO 27001 (Gestion de la sécurité de l'information)
- FedRAMP (Federal Risk and Authorization Management Program)

Ces référentiels exigent généralement qu'un utilisateur ne puisse pas être à la fois l'auteur de modifications de code et l'approbateur de ces modifications pour le déploiement en production.

### Comprendre le modèle d'attribution {#understanding-the-attribution-model}

Même si le compte de service crée les commits et ouvre la merge request, l'utilisateur humain est considéré comme l'auteur, car :

- L'utilisateur humain a demandé au compte de service de créer les modifications.
- Du point de vue de la conformité, demander à un système d'IA d'écrire du code équivaut à écrire ce code soi-même.
- Le compte de service agit en tant que proxy pour l'intention de l'utilisateur humain.
