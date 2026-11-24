---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Agent Planner
---

{{< details >}}

- Édition : [Gratuite](../../../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/576618) en version bêta dans GitLab 18.6.
- Les fonctionnalités de création et de modification ont été introduites dans GitLab 18.7.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273) dans GitLab 18.8.
- Disponibilité pour l'édition Gratuite sur GitLab.com avec des GitLab Credits dans GitLab 18.10.
- La gestion des tâches à faire a été introduite dans GitLab 19.0.
- Intégration d'[Orbit](https://docs.gitlab.com/orbit/) pour les requêtes basées sur les graphes [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/598775) dans GitLab 19.1.
- Les relations entre éléments liés (est lié à, bloque, est bloqué par) [introduites](https://gitlab.com/gitlab-org/gitlab/-/work_items/586331) dans GitLab 19.2.
- Prise en charge des vues enregistrées [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/592440) dans GitLab 19.2.

{{< /history >}}

L'agent Planner est un agent d'IA spécialisé qui assiste les workflows de gestion de produits et de planification dans GitLab. Il vous aide à créer, prioriser et suivre le travail de manière plus efficace.

L'agent Planner comprend les concepts de planification de GitLab, notamment les hiérarchies d'éléments de travail (epics, tickets et tâches), les jalons, les labels et les poids. Il peut analyser des éléments de travail, suggérer des stratégies de priorisation et vous aider à structurer et à communiquer vos plans.

Lorsque vous activez [Orbit](https://docs.gitlab.com/orbit/) pour votre groupe principal et dans vos préférences utilisateur, l'agent Planner peut également utiliser le graphe de connaissances pour répondre aux questions sur les relations, les dépendances et le contexte historique entre les projets.

Utilisez l'agent Planner lorsque vous avez besoin d'aide pour :

- Priorisation : application de frameworks tels que RICE, MoSCoW ou WSJF pour classer les éléments de travail.
- Décomposition du travail : décomposer les initiatives en epics, fonctionnalités et user stories.
- Création de contenu : rédiger des mémos, des exigences et d'autres artefacts de planification, ou créer des epics, des tickets et des tâches directement sur demande.
- Analyse des dépendances : identifier les travaux bloqués et comprendre les relations entre les éléments.
- Modification de contenu : mettre à jour les éléments de travail, les labels, les jalons, les relations entre éléments liés et d'autres attributs, sur demande ou après avoir demandé une confirmation avant d'agir.
- Gestion des tâches à faire : ajouter des tâches à faire aux éléments de travail et les marquer comme terminées.
- Sessions de planification : organiser des sprints, des jalons ou la planification trimestrielle.
- Rapports de statut : générer des résumés de l'avancement, des risques et des blocages.
- Gestion du backlog : identifier les tickets obsolètes, les doublons ou les éléments nécessitant une clarification.
- Vues enregistrées : analyser les éléments de travail d'une vue enregistrée, en utilisant les filtres et l'ordre de tri de la vue.
- Estimation : suggérer des estimations de taille relative ou d'effort pour les éléments de travail.
- Contexte basé sur les graphes : trouver des travaux passés similaires, des dépendances entre projets et des contributeurs ayant une expérience connexe. Nécessite [Orbit](https://docs.gitlab.com/orbit/).

Vous pouvez laisser vos commentaires dans [l'issue 583008](https://gitlab.com/gitlab-org/gitlab/-/work_items/583008).

## Utiliser l'agent Planner {#use-the-planner-agent}

Vous pouvez utiliser l'agent Planner dans l'interface utilisateur GitLab, VS Code et les IDE JetBrains.

### Conseils pour de meilleurs résultats {#tips-for-best-results}

Pour obtenir les meilleurs résultats de vos requêtes :

- Fournissez le contexte de votre requête, comme les URL, les critères de filtre ou la portée.
- Précisez le type d'élément de travail (epic, ticket ou tâche) lorsque cela est pertinent.
- Si vous avez un framework de priorisation préféré, précisez-le.
- Précisez votre audience cible lorsque vous demandez des résumés ou des mises à jour, par exemple, l'équipe d'ingénierie, la direction ou les parties prenantes.
- Utilisez des verbes d'action explicites tels que « créer », « mettre à jour » ou « fermer » lorsque vous souhaitez que l'agent effectue une action plutôt que de formuler une recommandation.
- Si les hypothèses de l'agent ne correspondent pas à votre workflow, demandez des clarifications.

### Dans l'interface GitLab {#in-the-gitlab-ui}

Prérequis :

- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.
- Facultatif. Pour utiliser le contexte basé sur les graphes, [activez Orbit](https://docs.gitlab.com/orbit/remote/getting-started/) pour votre groupe principal et dans vos préférences utilisateur.

Pour utiliser l'agent Planner dans l'interface utilisateur GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale GitLab Duo, sélectionnez **Ajouter une discussion** ({{< icon name="pencil-square" >}}).
1. Dans la liste déroulante, sélectionnez **Planificateur**.

   Une conversation Chat s'ouvre dans la barre latérale GitLab Duo située à droite de l'écran.
1. Saisissez votre question ou votre requête liée à la planification.

### Dans VS Code {#in-vs-code}

Prérequis :

- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.
- Installez et configurez [GitLab for VS Code](../../../../editor_extensions/visual_studio_code/setup.md) version 6.57.3 ou ultérieure.
- Définir un [espace de nommage GitLab Duo par défaut](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace).
- Facultatif. Pour utiliser le contexte basé sur les graphes, [activez Orbit](https://docs.gitlab.com/orbit/remote/getting-started/) pour votre groupe principal et dans vos préférences utilisateur.

Pour utiliser l'agent Planner dans VS Code :

1. Dans VS Code, dans la barre latérale gauche, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Sélectionnez l'onglet **Chat**.
1. Dans la liste déroulante **Nouvelle discussion** ({{< icon name="duo-chat-new" >}}), sélectionnez **Planificateur**.
1. Saisissez votre question ou votre requête liée à la planification.

### Dans les IDE JetBrains {#in-jetbrains-ides}

Prérequis :

- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.
- Installez et configurez le [plugin GitLab Duo pour les IDE JetBrains](../../../../editor_extensions/jetbrains_ide/setup.md) version 3.11.1 ou ultérieure.
- Définir un [espace de nommage GitLab Duo par défaut](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace).
- Facultatif. Pour utiliser le contexte basé sur les graphes, [activez Orbit](https://docs.gitlab.com/orbit/remote/getting-started/) pour votre groupe principal et dans vos préférences utilisateur.

Tout d'abord, activez GitLab Duo Agent Platform :

1. Dans votre IDE JetBrains, accédez à **Paramètres** > **Outils** > **GitLab Duo**.
1. Sous **GitLab Duo Agent Platform**, cochez la case **Activer GitLab Duo Agent Platform**.
1. Redémarrez votre IDE si vous y êtes invité.

Ensuite, pour utiliser l'agent Planner :

1. Dans votre IDE JetBrains, dans la barre d'outils de la fenêtre de droite, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Sélectionnez l'onglet **Chat**.
1. Dans la liste déroulante **Nouvelle discussion** ({{< icon name="duo-chat-new" >}}), sélectionnez **Planificateur**.
1. Saisissez votre question ou votre requête liée à la planification.

## Exemples de prompts {#example-prompts}

- Priorisation :
  - « Aidez-moi à prioriser les éléments de travail de mon backlog avec le label `<label name>` à l'aide du framework RICE. »
  - « Utilisez MoSCoW pour catégoriser les fonctionnalités de cet élément de travail selon les critères `<criteria>` en fonction de l'impact client : `<URL>` »
  - « Classez ces éléments de travail par valeur stratégique pour le T1 : `<URLs>` »
  - « Comparez ces fonctionnalités à l'aide d'une matrice effort/impact : `<URLs>` »
  - « Quels éléments enfants de cet élément de travail dois-je retirer de la portée actuelle pour respecter l'échéance ? `<URL>` »
- Décomposition du travail :
  - « Décomposez cette initiative en fonctionnalités clés à livrer : `<URL>` »
  - « Quelles tâches sont nécessaires pour implémenter cet élément de travail ? `<URL>` »
  - « Quelle serait la version MVP de cette fonctionnalité ? `<URL>` »
  - « Comment devrions-nous séquencer les fonctionnalités de cet élément de travail ? `<URL>` »
  - « Proposez une approche progressive pour ce projet : `<URL>` »
- Rapports de statut :
  - « Fournissez une mise à jour du statut et un rapport d'avancement pour cet élément de travail, y compris tous les éléments enfants : `<URL>` »
  - « Générez un résumé exécutif de l'avancement de cet élément de travail : `<URL>` »
  - « Résumez les blocages et les plans d'atténuation à l'intention de la direction : `<URL>` »
  - « Rédigez une mise à jour pour les parties prenantes sur l'état de santé de cette initiative : `<URL>` »
- Création de contenu :
  - « Rédigez un mémo pour cette initiative incluant les objectifs, les critères de succès et les principales parties prenantes : `<URL>` »
  - « Rédigez un élément de travail sur les exigences techniques pour ce projet, notamment les besoins en API, les modèles de données et les points d'intégration : `<URL>` »
  - « Rédigez une narration de carte des dépendances expliquant les relations et le séquençage entre ces éléments de travail : `<URLs>` »
  - « Générez une évaluation des risques pour cet epic en identifiant les blocages potentiels et les stratégies d'atténuation : `<URL>` »
  - « Estimez l'effort d'implémentation pour cet élément de travail, en incluant le temps de développement, les tests et les blocages potentiels : `<URL>` »
- Analyse des dépendances :
  - « Quel travail devrions-nous reporter dans cet élément de travail pour réduire la portée ? `<URL>` »
  - « Aidez-moi à prioriser la dette technique par rapport aux nouvelles fonctionnalités. »
- Sessions de planification :
  - « Regroupez ces éléments de travail en thèmes de release cohérents : `<URLs>` »
  - « Quels éléments de travail ont dépassé leur date d'échéance ? »
- Gestion du backlog :
  - « Trouvez les éléments de travail obsolètes qui n'ont pas été mis à jour depuis 6 mois. »
  - « Identifiez les éléments de travail en doublon ou similaires dans ce projet. »
  - « Affichez les éléments de travail qui me sont assignés. »
- Vues enregistrées :
  - « Résumez les éléments de travail de cette vue enregistrée : `<URL>` »
  - « Quels éléments de travail de cette vue enregistrée ne sont pas assignés ? `<URL>` »
- Modification de contenu :
  - « Fermez cet élément de travail comme terminé et créez un nouvel élément de travail rétrospectif documentant ce qui s'est bien passé et ce qui doit être amélioré : `<URL>` »
  - « Marquez cet élément de travail comme bloqué par ces éléments : `<URLs>` »
  - « Liez ces éléments de travail comme étant liés : `<URLs>` »
- Gestion des tâches à faire :
  - « Ajoutez une tâche à faire pour cet élément de travail : `<URL>` »
  - « Marquez toutes mes tâches à faire comme terminées pour cet élément de travail : `<URL>` »
- Contexte basé sur les graphes (nécessite [Orbit](https://docs.gitlab.com/orbit/)) :
  - « Trouvez des epics similaires à celui-ci qui ont déjà été livrés : `<URL>` »
  - « Comment des initiatives similaires ont-elles été décomposées par le passé pour cet élément de travail : `<URL>` »
  - « Quelqu'un suit-il déjà des travaux liés à cette idée ? »
  - « Quels contributeurs ont travaillé sur des domaines liés à cet epic ? `<URL>` »
  - « De quels autres éléments de travail dans d'autres projets celui-ci pourrait-il dépendre ? `<URL>` »

## Problèmes connus {#known-issues}

- L'agent peut analyser des éléments de travail en masse, mais la qualité des réponses peut diminuer pour les requêtes impliquant un grand nombre d'éléments.
- L'agent ne peut pas accéder de manière fiable aux commentaires des éléments de travail ayant de longs historiques de discussion. Les historiques de commentaires dépassant environ 100 entrées peuvent être incomplets.
- Lorsque vous demandez à l'agent de mettre à jour le statut d'un élément de travail avec une valeur qui n'existe pas, l'agent peut signaler à tort la mise à jour comme réussie sans appliquer aucun changement.
