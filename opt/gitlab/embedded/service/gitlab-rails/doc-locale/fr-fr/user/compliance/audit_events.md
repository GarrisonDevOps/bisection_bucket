---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: "Événements d'audit"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Un audit de sécurité est une analyse approfondie et un examen de votre infrastructure, utilisés pour mettre en évidence les domaines préoccupants et les pratiques potentiellement dangereuses. Pour faciliter le processus d'audit, GitLab fournit des événements d'audit qui vous permettent de suivre une variété d'actions différentes dans GitLab. GitLab peut aider les propriétaires et les administrateurs à répondre aux auditeurs en générant des rapports complets. Ces rapports d'audit varient en portée selon vos besoins.

Par exemple, vous pouvez utiliser les événements d'audit pour suivre :

- Qui a modifié le niveau d'autorisation d'un utilisateur particulier pour un projet GitLab, et à quel moment.
- Qui a ajouté un nouvel utilisateur ou supprimé un utilisateur, et à quel moment.

Ces événements peuvent être utilisés dans un audit pour évaluer les risques, renforcer les mesures de sécurité, répondre aux incidents et se conformer aux exigences de conformité. Pour obtenir la liste complète des événements d'audit fournis par GitLab, consultez [les types d'événements d'audit](audit_event_types.md). Par exemple :

- Générer un rapport d'événements d'audit à fournir à un auditeur externe demandant la preuve de certaines capacités de journalisation.
- Fournir un rapport de tous les utilisateurs indiquant leurs appartenances aux groupes et aux projets dans le cadre d'une revue d'accès trimestrielle, afin que l'auditeur puisse vérifier la conformité avec la politique de gestion des accès de l'organisation.

Les événements d'audit sont conservés indéfiniment. Comme il n'existe pas de délai de conservation, tous les événements d'audit sont disponibles.

## Prérequis {#prerequisites}

Pour afficher des types spécifiques d'événements d'audit, vous devez disposer d'un rôle minimum.

- Pour afficher les événements d'audit de groupe de tous les utilisateurs d'un groupe, vous devez disposer du [rôle Propriétaire](../permissions.md#roles) pour le groupe.
- Pour afficher les événements d'audit de projet de tous les utilisateurs d'un projet, vous devez disposer au minimum du [rôle Maintainer](../permissions.md#roles) pour le projet.
- Pour afficher les événements d'audit de groupe et de projet basés sur vos propres actions dans un groupe ou un projet, vous devez disposer au minimum du [rôle Developer](../permissions.md#roles) pour le groupe ou le projet.

Les utilisateurs disposant du [niveau d'accès Auditeur](../../administration/auditor_users.md) peuvent voir les événements de groupe et de projet pour tous les utilisateurs.

## Affichage des événements d'audit {#viewing-audit-events}

Les événements d'audit peuvent être consultés au niveau du groupe, du projet, de l'instance et de la connexion. Chaque niveau comporte des événements d'audit différents qu'il enregistre.

### Événements d'audit de connexion {#sign-in-audit-events}

Les événements de connexion réussie sont les seuls événements d'audit disponibles pour toutes les éditions. Pour voir les événements de connexion réussie :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Journal d'authentification**.

Après la mise à niveau vers une édition payante, vous pouvez également voir les événements de connexion réussie sur les pages d'événements d'audit.

### Événements d'audit de groupe {#group-audit-events}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour afficher les événements d'audit d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécurisation** > **Événements d'audit**.
1. Filtrez les événements d'audit par membre du projet (utilisateur) ayant effectué l'action et par plage de dates.

Les événements d'audit de groupe sont également accessibles via l'[API des événements d'audit de groupe](../../api/audit_events.md#group-audit-events). Les paramètres `created_after` et `created_before` des requêtes d'événements d'audit de groupe sont limités à un écart maximum de 30 jours entre les dates.

### Événements d'audit de projet {#project-audit-events}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Sécurisation** > **Événements d'audit**.
1. Filtrez les événements d'audit par membre du projet (utilisateur) ayant effectué l'action et par plage de dates.

Les événements d'audit de projet sont également accessibles via l'[API des événements d'audit de projet](../../api/audit_events.md#project-audit-events). Les paramètres `created_after` et `created_before` des requêtes d'événements d'audit de projet sont limités à un écart maximum de 30 jours entre les dates.

## Fuseaux horaires {#time-zones}

Le fuseau horaire utilisé pour les événements d'audit dépend de l'endroit où vous les consultez :

- Dans l'interface GitLab, votre fuseau horaire local est utilisé.
- L'[API des événements d'audit](../../api/audit_events.md) renvoie les dates et heures en UTC par défaut, ou selon le [fuseau horaire configuré](../../administration/timezone.md) sur GitLab Self-Managed.
- Dans les exports CSV, l'UTC est utilisé.

## Problèmes connus {#known-issues}

L'interface des événements d'audit dispose de capacités de recherche limitées. La recherche textuelle dans les détails des événements d'audit n'est pas prise en charge. Vous pouvez uniquement filtrer les événements d'audit par :

- Événements membres : l'auteur qui a effectué l'action.
- Plage de dates : période glissante de 30 jours maximum.

L'amélioration de la convivialité des rapports d'événements d'audit est proposée dans l'[epic 418](https://gitlab.com/groups/gitlab-org/-/epics/418).

Pour une recherche avancée et une analyse des événements d'audit, envisagez de [diffuser les événements d'audit](audit_event_streaming.md) vers une destination externe où vous pouvez effectuer des recherches textuelles complètes et des analyses.

## Contribuer aux événements d'audit {#contribute-to-audit-events}

Si vous ne voyez pas l'événement souhaité dans l'un des epics, vous pouvez :

- Utiliser le modèle de ticket de proposition d'événement d'audit pour [créer un ticket](https://gitlab.com/gitlab-org/gitlab/-/work_items/new?description_template=Audit%20Event%20Proposal) afin de le demander.
- Contribuer à GitLab et ajouter l'événement.

## Événements d'audit IA {#ai-audit-events}

Les sessions d'agents GitLab Duo génèrent des événements d'audit IA qui capturent les entrées, le contexte du modèle, la chronologie des événements et les sorties pour chaque session. Vous pouvez parcourir, filtrer et télécharger ces événements depuis l'onglet **Événements d'audit** de la page **Gouvernance**.

Pour plus d'informations, consultez [le rapport d'événements d'audit IA](../ai-governance/ai-audit-events.md).

## Rubriques d'administration {#administer-topics}

Les administrateurs d'instance peuvent [administrer les événements d'audit](../../administration/compliance/audit_event_reports.md) depuis la zone **Admin**.
