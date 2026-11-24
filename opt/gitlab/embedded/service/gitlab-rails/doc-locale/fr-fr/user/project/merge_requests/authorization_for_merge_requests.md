---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Les workflows de merge request les plus courants dans GitLab utilisent des duplications, des branches protégées, ou les deux."
title: Workflows de merge request
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les merge requests GitLab suivent généralement l'un de ces workflows :

- Utilisation des [branches protégées](../repository/branches/protected.md) dans un seul dépôt.
- Utilisation de duplications d'un projet de référence.

## Workflow par branche protégée {#protected-branch-flow}

Avec le workflow par branche protégée, tout le monde travaille dans le même projet GitLab, plutôt que dans des duplications.

Les responsables de maintenance du projet obtiennent le rôle Maintainer et les développeurs réguliers obtiennent le rôle Developer.

Les responsables de maintenance marquent les branches de référence comme « Protected ».

Les développeurs poussent des branches de fonctionnalité vers le projet et créent des merge requests pour que leurs branches de fonctionnalité soient examinées et fusionnées dans l'une des branches protégées.

Par défaut, seuls les utilisateurs disposant du rôle Maintainer peuvent fusionner des modifications dans une branche protégée.

- Avantages :
  - Moins de projets signifie moins d'encombrement.
  - Les développeurs n'ont à prendre en compte qu'un seul dépôt distant.
- Inconvénients :
  - Une configuration manuelle de la branche protégée est requise pour chaque nouveau projet.

Pour configurer un workflow par branche protégée :

1. Commencez par vous assurer que votre branche par défaut est protégée avec les [protections de branche par défaut](../repository/branches/default.md).
1. Si votre équipe possède plusieurs branches et que vous souhaitez gérer qui peut fusionner des modifications et qui dispose explicitement de l'option pour pousser ou forcer le push, envisagez de protéger ces branches :

   - [Gérer et protéger les branches](../repository/branches/_index.md#manage-and-protect-branches)
   - [Branches protégées](../repository/branches/protected.md)

1. Chaque modification du code est transmise sous forme de commit. Vous pouvez spécifier le format et les mesures de sécurité, comme l'exigence d'une signature par clé SSH pour les modifications entrant dans votre base de code, à l'aide de règles de push :

   - [Règles de push](../repository/push_rules.md)

1. Pour vous assurer que le code est examiné et vérifié par les bonnes personnes de votre équipe, utilisez :

   - [Propriétaires du code](../codeowners/_index.md)
   - [Règles d'approbation des merge requests](approvals/rules.md)

Également disponible dans l'édition Ultimate :

- [Vérifications de statut](status_checks.md)
- [Approbations de sécurité](approvals/rules.md#security-approvals)

## Workflow de duplication {#forking-workflow}

Avec le workflow de duplication, les responsables de maintenance obtiennent le rôle Maintainer et les développeurs réguliers obtiennent le rôle Reporter sur le dépôt de référence, ce qui leur interdit de pousser des modifications dans celui-ci.

Les développeurs créent des duplications du projet de référence et poussent leurs branches de fonctionnalité vers leurs propres duplications.

Pour intégrer leurs modifications dans la branche par défaut, ils doivent créer une merge request entre duplications.

- Avantages :
  - Dans un groupe GitLab correctement configuré, les nouveaux projets obtiennent automatiquement les restrictions d'accès requises pour les développeurs réguliers : moins d'étapes manuelles pour configurer les autorisations des nouveaux projets.
- Inconvénients :
  - Le projet doit maintenir ses duplications à jour, ce qui requiert des compétences Git plus avancées (gestion de plusieurs dépôts distants).
