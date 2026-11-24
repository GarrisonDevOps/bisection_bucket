---
stage: Security Governance
Group: AI Control Plane
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Contrôler la disponibilité de GitLab Duo Agent Platform pour les groupes, les projets et les instances."
title: Contrôler la disponibilité de GitLab Duo Agent Platform
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Duo Agent Platform est activée par défaut. Agent Platform inclut un [ensemble de fonctionnalités](_index.md).

Pour utiliser Agent Platform, des [GitLab Credits](../../subscriptions/gitlab_credits.md) sont requis.

Vous pouvez activer ou désactiver Agent Platform :

- Sur GitLab.com : pour les groupes principaux.
- Sur GitLab Self-Managed : pour les instances.

Pour configurer la gouvernance des outils pour Agent Platform, consultez la section [gouvernance des outils des agents](../ai-governance/tool-governance.md).

## Activer ou désactiver GitLab Duo Agent Platform {#turn-gitlab-duo-agent-platform-on-or-off}

### Sur GitLab.com {#on-gitlabcom}

{{< details >}}

- Édition : [Gratuite](../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- Disponibilité pour l'édition Gratuite sur GitLab.com avec des GitLab Credits dans GitLab 18.10.

{{< /history >}}

Prérequis :

- Disposer du rôle Propriétaire pour le groupe principal.

Pour activer ou désactiver Agent Platform pour un groupe principal :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Sélectionnez **Paramètres** > **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **GitLab Duo Agent Platform**, cochez ou décochez la case **Activer GitLab Duo Agentic Chat, les agents et les flux**.
1. Sélectionnez **Enregistrer les modifications**.

La disponibilité d'Agent Platform change pour tous les sous-groupes et projets.

Lorsqu'Agent Platform est désactivée, les fonctionnalités suivantes sont masquées :

- Les paramètres associés aux flows et aux [agents par défaut](agents/foundational_agents/_index.md#turn-foundational-agents-on-or-off).
- Le catalogue d'IA.

### Sur GitLab Self-Managed {#on-gitlab-self-managed}

Prérequis :

- Disposer d'un accès administrateur.
- Une instance avec l'un des éléments suivants :
  - Un module complémentaire GitLab Duo Pro, Enterprise ou Self-Hosted actif avec une licence payante.
  - Des GitLab Credits actifs.

Pour activer ou désactiver Agent Platform pour une instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **GitLab Duo Agent Platform**, cochez ou décochez la case **Activer GitLab Duo Agentic Chat, les agents et les flux**.
1. Sélectionnez **Enregistrer les modifications**.

Lorsqu'Agent Platform est désactivée, les fonctionnalités suivantes sont masquées :

- Les paramètres associés aux flows, aux [agents par défaut](agents/foundational_agents/_index.md#turn-foundational-agents-on-or-off) et à l'interface de ligne de commande GitLab Duo.
- Le catalogue d'IA.

## Verrouiller GitLab Duo en mode activé {#lock-gitlab-duo-on}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/21844) dans GitLab 19.1.

{{< /history >}}

Activation de GitLab Duo pour l'ensemble des utilisateurs, quels que soient les paramètres du groupe ou du projet.

Lorsque vous définissez la disponibilité de GitLab Duo sur **Toujours activé**, les fonctionnalités en version expérimentale et en version bêta ne sont pas automatiquement activées. Pour utiliser les fonctionnalités en version expérimentale et en version bêta, vous devez [les activer séparément](#turn-on-beta-and-experimental-features).

{{< tabs >}}

{{< tab title="Sur GitLab.com" >}}

Prérequis :

- Disposer du rôle Propriétaire pour le groupe principal.

Pour verrouiller GitLab Duo en mode activé pour un groupe principal :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **Disponibilité de GitLab Duo**, sélectionnez **Toujours activé**.
1. Sélectionnez **Enregistrer les modifications**.

GitLab Duo est verrouillé en mode activé pour tous les sous-groupes et projets. Les personnes qui disposent du rôle Propriétaire pour un sous-groupe ou un projet ne peuvent pas désactiver GitLab Duo.

{{< /tab >}}

{{< tab title="Sur GitLab Self-Managed" >}}

Prérequis :

- Disposer d'un accès administrateur.
- Une instance avec l'un des éléments suivants :
  - Un module complémentaire GitLab Duo Pro, Enterprise ou Self-Hosted actif avec une licence payante.
  - Des GitLab Credits actifs.

Pour verrouiller GitLab Duo en mode activé pour une instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **Disponibilité de GitLab Duo**, sélectionnez **Toujours activé**.
1. Sélectionnez **Enregistrer les modifications**.

GitLab Duo est verrouillé en mode activé pour tous les groupes, sous-groupes et projets. Les personnes qui disposent du rôle Propriétaire pour un groupe, un sous-groupe ou un projet ne peuvent pas désactiver GitLab Duo.

{{< /tab >}}

{{< /tabs >}}

## Activer ou désactiver GitLab Duo {#turn-gitlab-duo-on-or-off}

GitLab Duo est activé par défaut. Vous pouvez activer ou désactiver GitLab Duo :

- Sur GitLab.com : pour les groupes principaux, les autres groupes ou sous-groupes et les projets.
- Sur GitLab Self-Managed : pour les instances, les groupes ou sous-groupes et les projets.

### Sur GitLab.com {#on-gitlabcom-1}

{{< details >}}

- Édition : [Gratuite](../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- Disponibilité pour l'édition Gratuite sur GitLab.com avec des GitLab Credits dans GitLab 18.10.

{{< /history >}}

#### Pour un groupe principal {#for-a-top-level-group}

Prérequis :

- Disposer du rôle Propriétaire pour le groupe principal.

Pour modifier la disponibilité de GitLab Duo pour un groupe principal :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Sélectionnez **Paramètres** > **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **Disponibilité de GitLab Duo**, sélectionnez une option.
1. Sélectionnez **Enregistrer les modifications**.

La disponibilité de GitLab Duo est modifiée pour tous les sous-groupes et projets.

#### Pour un groupe ou un sous-groupe {#for-a-group-or-subgroup}

Prérequis :

- Disposer du rôle Propriétaire pour le groupe ou le sous-groupe.

Pour modifier la disponibilité de GitLab Duo pour un groupe ou un sous-groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe ou votre sous-groupe.
1. Sélectionnez **Paramètres** > **Généralités**.
1. Développez **Fonctionnalités de GitLab Duo**.
1. Sous **Disponibilité de GitLab Duo**, sélectionnez une option.
1. Sélectionnez **Enregistrer les modifications**.

La disponibilité de GitLab Duo est modifiée pour tous les sous-groupes et projets.

#### Pour un projet {#for-a-project}

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour modifier la disponibilité de GitLab Duo pour un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **GitLab Duo**.
1. Activez ou désactivez le bouton bascule **GitLab Duo**.
1. Sélectionnez **Enregistrer les modifications**.

### Sur GitLab Self-Managed {#on-gitlab-self-managed-1}

#### Pour une instance {#for-an-instance}

Prérequis :

- Disposer d'un accès administrateur.
- Une instance avec l'un des éléments suivants :
  - Un module complémentaire GitLab Duo Pro, Enterprise ou Self-Hosted actif avec une licence payante.
  - Des GitLab Credits actifs.

Pour modifier la disponibilité de GitLab Duo pour une instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **Disponibilité de GitLab Duo**, sélectionnez une option.
1. Sélectionnez **Enregistrer les modifications**.

#### Pour un groupe ou un sous-groupe {#for-a-group-or-subgroup-1}

Prérequis :

- Disposer du rôle Propriétaire pour le groupe ou le sous-groupe.

Pour modifier la disponibilité de GitLab Duo pour un groupe ou un sous-groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe ou votre sous-groupe.
1. Sélectionnez **Paramètres** > **Généralités**.
1. Développez **Fonctionnalités de GitLab Duo**.
1. Sous **Disponibilité de GitLab Duo**, sélectionnez une option.
1. Sélectionnez **Enregistrer les modifications**.

La disponibilité de GitLab Duo est modifiée pour tous les sous-groupes et projets.

#### Pour un projet {#for-a-project-1}

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour modifier la disponibilité de GitLab Duo pour un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **GitLab Duo**.
1. Activez ou désactivez le bouton bascule **GitLab Duo**.
1. Sélectionnez **Enregistrer les modifications**.

## Activer ou désactiver GitLab Duo Core {#turn-gitlab-duo-core-on-or-off}

GitLab Duo Core est inclus avec les abonnements GitLab Premium et GitLab Ultimate.

- Si vous étiez déjà client sous GitLab 17.11 ou une version antérieure, vous devez activer les fonctionnalités de GitLab Duo Core.
- Si vous êtes un nouveau client sous GitLab 18.0 ou une version ultérieure, GitLab Duo Core est automatiquement activé et aucune autre action n'est requise.

Si vous disposiez déjà d'un abonnement GitLab Premium ou GitLab Ultimate avant le 15 mai 2025, vous devez activer GitLab Duo Core pour l'utiliser lorsque vous passez à GitLab 18.0 ou à une version ultérieure.

### Sur GitLab.com {#on-gitlabcom-2}

{{< details >}}

- Édition : [Gratuite](../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- Disponibilité pour l'édition Gratuite sur GitLab.com avec des GitLab Credits dans GitLab 18.10.

{{< /history >}}

Prérequis :

- Disposer du rôle Propriétaire pour le groupe principal.

Pour modifier la disponibilité de GitLab Duo Core pour un groupe principal :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Sélectionnez **Paramètres** > **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **Disponibilité de GitLab Duo**, sélectionnez une option.
1. Sous **GitLab Duo Core**, cochez ou décochez la case **Activer les fonctionnalités pour Gitlab Duo Core**. Si vous avez défini la disponibilité de GitLab Duo sur **Toujours désactivé**, vous ne pouvez pas accéder à ce paramètre.
1. Sélectionnez **Enregistrer les modifications**.

La modification peut ne prendre effet qu'au bout de 10 minutes.

### Sur GitLab Self-Managed {#on-gitlab-self-managed-2}

Prérequis :

- Disposer d'un accès administrateur.
- Une instance avec l'un des éléments suivants :
  - Un module complémentaire GitLab Duo Pro, Enterprise ou Self-Hosted actif avec une licence payante.
  - Des GitLab Credits actifs.

Pour modifier la disponibilité de GitLab Duo Core pour une instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **Disponibilité de GitLab Duo**, sélectionnez une option.
1. Sous **GitLab Duo Core**, cochez ou décochez la case **Activer les fonctionnalités pour Gitlab Duo Core**. Si vous avez défini la disponibilité de GitLab Duo sur **Toujours désactivé**, vous ne pouvez pas accéder à ce paramètre.
1. Sélectionnez **Enregistrer les modifications**.

## Activer les fonctionnalités en version bêta et en version expérimentale {#turn-on-beta-and-experimental-features}

Les fonctionnalités GitLab Duo en version expérimentale et en version bêta sont désactivées par défaut. Ces fonctionnalités sont soumises au [Testing Agreement](https://handbook.gitlab.com/handbook/legal/testing-agreement/).

### Sur GitLab.com {#on-gitlabcom-3}

{{< details >}}

- Édition : [Gratuite](../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- Disponibilité pour l'édition Gratuite sur GitLab.com avec des GitLab Credits dans GitLab 18.10.

{{< /history >}}

Prérequis :

- Disposer du rôle Propriétaire pour le groupe principal.

Pour activer les fonctionnalités GitLab Duo en version expérimentale et en version bêta pour un groupe principal :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **Aperçu des fonctionnalités**, sélectionnez **Activer les fonctionnalités expérimentales et bêta de GitLab Duo**.
1. Sélectionnez **Enregistrer les modifications**.

Ce paramètre [s'applique en cascade à tous les projets](../project/merge_requests/approvals/settings.md#cascade-settings-from-the-instance-or-top-level-group) appartenant au groupe.

### Sur GitLab Self-Managed {#on-gitlab-self-managed-3}

{{< tabs >}}

{{< tab title="Dans la version 17.4 et les versions ultérieures" >}}

Dans GitLab 17.4 et les versions ultérieures, suivez ces instructions pour activer les fonctionnalités GitLab Duo en version expérimentale et en version bêta pour votre instance GitLab Self-Managed.

Prérequis :

- Disposer d'un accès administrateur.
- Une instance avec l'un des éléments suivants :
  - Un module complémentaire GitLab Duo Pro, Enterprise ou Self-Hosted actif avec une licence payante.
  - Des GitLab Credits actifs.

Pour activer les fonctionnalités GitLab Duo en version expérimentale et en version bêta pour une instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **GitLab Duo**.
1. Développez **Modifier la configuration**.
1. Sous **Aperçu des fonctionnalités**, sélectionnez **Utiliser les fonctionnalités expérimentales et bêta de GitLab Duo**.
1. Sélectionnez **Enregistrer les modifications**.

{{< /tab >}}

{{< tab title="Dans la version 17.3 et les versions antérieures" >}}

Prérequis :

- Disposer d'un accès administrateur.
- Une instance avec l'un des éléments suivants :
  - Un module complémentaire GitLab Duo Pro, Enterprise ou Self-Hosted actif avec une licence payante.
  - Des GitLab Credits actifs.
- [Connectivité réseau](../../administration/gitlab_duo/configure/_index.md) activée.
- [Mode silencieux](../../administration/silent_mode/_index.md) désactivé.

Pour activer les fonctionnalités GitLab Duo en version expérimentale et en version bêta pour une instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **GitLab Duo**.
1. Développez **Modifier la configuration**.
1. Sous **Aperçu des fonctionnalités**, sélectionnez **Utiliser les fonctionnalités expérimentales et bêta de GitLab Duo**.
1. Sélectionnez **Enregistrer les modifications**.
1. Pour que GitLab Duo Chat fonctionne immédiatement, [synchronisez manuellement votre abonnement](../../subscriptions/manage_subscription.md#manually-synchronize-subscription-data).

   Si vous ne synchronisez pas manuellement votre abonnement, l'activation de GitLab Duo Chat sur votre instance peut prendre jusqu'à 24 heures.

{{< /tab >}}

{{< /tabs >}}
