---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments
gitlab_dedicated: no
title: "Agent d'intégration"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Module d'extension : GitLab Duo
- Offre : GitLab.com, GitLab Self-Managed
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245452) dans GitLab 19.4 en tant que [version expérimentale](../../../../policy/development_stages_support.md#experiment) [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `onboarding_guide_agent`. Fonctionnalité désactivée par défaut.

{{< /history >}}

L'agent d'intégration vous aide à configurer la plateforme GitLab DevSecOps. L'agent lit le contexte de votre projet et votre édition d'abonnement, puis explique les fonctionnalités, recommande la prochaine étape d'adoption et fournit des exemples de configuration (par exemple, un `.gitlab-ci.yml`).

L'agent d'intégration fournit des réponses uniquement dans GitLab Duo Chat. Il ne modifie pas vos fichiers, pipelines ou paramètres de projet. L'agent peut créer et mettre à jour des éléments de travail, des tickets et des epics, et ajouter des commentaires aux tickets et aux éléments de travail. Avant chaque action, l'agent vous affiche le contenu exact et attend votre approbation.

Utilisez l'agent d'intégration lorsque vous devez :

- Configurer une équipe ou un projet pour la première fois.
- Migrer depuis GitHub, Bitbucket ou Jenkins et adapter votre workflow existant à GitLab.
- Adopter davantage de fonctionnalités de la plateforme, telles que l'analyse de sécurité, la conformité ou les workflows agentiques.
- Découvrir les capacités incluses dans votre édition ou ce qu'il faut configurer ensuite.

## Prérequis {#prerequisites}

Avant de pouvoir utiliser l'agent d'intégration :

- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.
- [Activer les fonctionnalités bêta et expérimentales](../../turn_on_off.md#turn-on-beta-and-experimental-features)

## Utiliser l'agent d'intégration {#use-the-onboarding-agent}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale GitLab Duo, sélectionnez **Ajouter une discussion** ({{< icon name="pencil-square" >}}).
1. Dans la liste déroulante, sélectionnez **Onboarding Agent**.

   Une conversation Chat s'ouvre dans la barre latérale GitLab Duo située à droite de l'écran.
1. Décrivez ce pour quoi vous avez besoin d'aide. Pour obtenir les meilleurs résultats :
   - Posez des questions complémentaires dans la même conversation. L'agent mémorise le contexte de votre session et l'utilise pour fournir des instructions.
   - Soyez explicite quant à l'étape spécifique que vous souhaitez explorer (par exemple, la sécurité ou la conformité).
   - Vérifiez les suggestions de configuration de l'agent avant de les appliquer à votre propre projet.

L'agent rassemble le contexte de votre projet actuel et de votre édition avant de répondre, et fournit des instructions spécifiques au contexte.

## Exemples de prompts {#example-prompts}

Utilisez ces invites pour commencer :

- `Help me get started with GitLab.`
- `I'm migrating from GitHub — where should I begin?`
- `Set up security scanning for this project.`
- `What should I do next to get more value out of GitLab?`
- `What features am I missing on my current tier?`
- `Help me convert my Jenkins pipeline to GitLab CI/CD.`
- `Help me get started with compliance frameworks.` (GitLab Ultimate)

## Problèmes connus {#known-issues}

- L'agent s'exécute uniquement dans l'interface GitLab Duo Chat et dans votre IDE. Vous ne pouvez pas créer de [déclencheur](../../triggers/_index.md) pour cet agent.
- L'agent ne crée pas, ne modifie pas et ne commit pas de fichiers, ne modifie pas les pipelines et ne change pas les paramètres du projet. Il peut créer et mettre à jour des éléments de travail, des tickets et des epics, et ajouter des commentaires aux tickets et aux éléments de travail après que vous avez approuvé chaque action.
- L'agent ne peut pas lire les vulnérabilités, les résultats de sécurité, les erreurs de pipeline ou les job logs. Il vous demande la sortie pertinente et peut vous orienter vers l'agent Security Analyst ou l'agent CI Expert. Il ne peut pas déléguer à un autre agent.
- L'agent utilise le contexte du projet et de la page, mais ne peut pas toujours détecter si une fonctionnalité spécifique a été activée pour le projet.
- L'utilisation de l'Agent Platform est rapportée de manière agrégée dans le [tableau de bord des tendances GitLab Duo et SDLC](../../../analytics/duo_and_sdlc_trends.md). Vous ne pouvez pas encore voir l'utilisation des agents individuels.

## Donner un avis {#give-feedback}

Cet agent est une version expérimentale, et vos retours nous aident à l'améliorer. Pour partager votre expérience ou signaler un problème, ajoutez un commentaire au [ticket 606350](https://gitlab.com/gitlab-org/gitlab/-/issues/606350).

## Sujets connexes {#related-topics}

- [Agents par défaut](_index.md)
- [GitLab Duo Agent Platform](../../_index.md)
