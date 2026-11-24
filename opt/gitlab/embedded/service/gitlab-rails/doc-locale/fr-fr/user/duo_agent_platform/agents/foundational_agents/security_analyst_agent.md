---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Agent Security Analyst
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/epics/19659) dans GitLab 18.6.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273) dans GitLab 18.8.

{{< /history >}}

L'agent Security Analyst est un assistant IA spécialisé qui aide à la gestion des vulnérabilités et aux workflows d'analyse de sécurité dans GitLab. Il combine une expertise en sécurité avec une connaissance approfondie des fonctionnalités de sécurité de GitLab, des rapports de vulnérabilités, des tableaux de bord de sécurité et des outils de conformité pour vous aider à trier, évaluer et remédier efficacement aux résultats de sécurité.

Utilisez l'agent Security Analyst lorsque vous avez besoin d'aide pour :

- Triage des vulnérabilités : analysez et priorisez les résultats de sécurité selon différents types d'analyse.
- Évaluation des risques : évaluez la gravité, l'exploitabilité et l'impact métier des vulnérabilités.
- Identification des faux positifs : distinguez les menaces réelles des résultats bénins.
- Gestion de la conformité : comprenez les exigences réglementaires et les délais de remédiation.
- Rapports de sécurité : générez des résumés de la posture de sécurité et de la progression de la remédiation.
- Planification de la remédiation : créez des plans d'action pour traiter les vulnérabilités de sécurité.
- Automatisation des workflows de sécurité : rationalisez les tâches répétitives d'évaluation de la sécurité.

L'agent Security Analyst comprend les implémentations de sécurité spécifiques à GitLab, notamment les états des vulnérabilités, les niveaux de gravité et les sorties des analyseurs de sécurité. Il peut interpréter les scores EPSS, les données CVE et l'analyse de l'accessibilité pour fournir des conseils de sécurité contextuels.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une vue d'ensemble, consultez [How to Use the GitLab Security Analyst Agent for AI-Powered Triage](https://www.youtube.com/watch?v=XqVmrsa9BnM).
<!-- Video published on 2026-02-25 -->

## Utiliser l'agent Security Analyst {#use-the-security-analyst-agent}

Vous pouvez utiliser l'agent Security Analyst dans l'interface utilisateur de GitLab, VS Code et les IDE JetBrains.

### Dans l'interface GitLab {#in-the-gitlab-ui}

Prérequis :

- Utilisez un projet GitLab avec l'analyse de sécurité activée.
- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.

Pour utiliser l'agent Security Analyst dans l'interface utilisateur de GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale GitLab Duo, sélectionnez **Ajouter une discussion** ({{< icon name="pencil-square" >}}).
1. Dans la liste déroulante, sélectionnez **Analyste sécurité**.

   Une conversation Chat s'ouvre dans la barre latérale GitLab Duo située à droite de l'écran.
1. Saisissez votre question ou requête liée à la sécurité. Pour obtenir les meilleurs résultats de votre requête :

   - Fournissez du contexte sur vos exigences de sécurité et votre tolérance au risque.
   - Précisez les types de vulnérabilités ou de résultats d'analyse sur lesquels vous vous concentrez.
   - Incluez les détails pertinents du projet ou du composant lorsque vous demandez une analyse.
   - Demandez des éclaircissements si les recommandations de l'agent Security Analyst ne correspondent pas à vos politiques de sécurité.
   - Utilisez des identifiants de vulnérabilité ou des URL spécifiques lorsque vous discutez de résultats particuliers.

### Dans VS Code {#in-vs-code}

Prérequis :

- Utilisez un projet GitLab avec l'analyse de sécurité activée.
- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.
- Installez et configurez [GitLab for VS Code](../../../../editor_extensions/visual_studio_code/setup.md) version 6.57.3 ou ultérieure.
- Définir un [espace de nommage GitLab Duo par défaut](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace).

Pour utiliser l'agent Security Analyst dans VS Code :

1. Dans VS Code, dans la barre latérale gauche, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Sélectionnez l'onglet **Chat**.
1. Dans la liste déroulante **Nouvelle discussion** ({{< icon name="duo-chat-new" >}}), sélectionnez **Analyste sécurité**.
1. Saisissez votre question ou requête liée à la sécurité. Pour obtenir les meilleurs résultats de votre requête :

   - Fournissez du contexte sur vos exigences de sécurité et votre tolérance au risque.
   - Précisez les types de vulnérabilités ou de résultats d'analyse sur lesquels vous vous concentrez.
   - Incluez les détails pertinents du projet ou du composant lorsque vous demandez une analyse.
   - Demandez des éclaircissements si les recommandations de l'agent Security Analyst ne correspondent pas à vos politiques de sécurité.
   - Utilisez des identifiants de vulnérabilité ou des URL spécifiques lorsque vous discutez de résultats particuliers.

### Dans les IDE JetBrains {#in-jetbrains-ides}

Prérequis :

- Utilisez un projet GitLab avec l'analyse de sécurité activée.
- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.
- Installez et configurez le [plugin GitLab Duo pour les IDE JetBrains](../../../../editor_extensions/jetbrains_ide/setup.md) version 3.11.1 ou ultérieure.
- Définir un [espace de nommage GitLab Duo par défaut](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace).

Tout d'abord, activez GitLab Duo Agent Platform :

1. Dans votre IDE JetBrains, accédez à **Paramètres** > **Outils** > **GitLab Duo**.
1. Sous **GitLab Duo Agent Platform**, cochez la case **Activer GitLab Duo Agent Platform**.
1. Redémarrez votre IDE si vous y êtes invité.

Ensuite, pour utiliser l'agent Security Analyst :

1. Dans votre IDE JetBrains, dans la barre de la fenêtre d'outils de droite, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Sélectionnez l'onglet **Chat**.
1. Dans la liste déroulante **Nouvelle discussion** ({{< icon name="duo-chat-new" >}}), sélectionnez **Analyste sécurité**.
1. Saisissez votre question ou requête liée à la sécurité. Pour obtenir les meilleurs résultats de votre requête :

   - Fournissez du contexte sur vos exigences de sécurité et votre tolérance au risque.
   - Précisez les types de vulnérabilités ou de résultats d'analyse sur lesquels vous vous concentrez.
   - Incluez les détails pertinents du projet ou du composant lorsque vous demandez une analyse.
   - Demandez des éclaircissements si les recommandations de l'agent Security Analyst ne correspondent pas à vos politiques de sécurité.
   - Utilisez des identifiants de vulnérabilité ou des URL spécifiques lorsque vous discutez de résultats particuliers.

## Exemples de prompts {#example-prompts}

- Analyse des vulnérabilités :
  - « Montrez-moi toutes les vulnérabilités critiques dans mon projet. »
  - « Listez les vulnérabilités avec des scores EPSS supérieurs à 0,7 qui sont accessibles. »
  - « Quels résultats SAST dois-je prioriser en fonction de l'exploitabilité ? »
  - « Analysez l'impact de sécurité des vulnérabilités dans (nom du composant). »
  - « Comparez les tendances des vulnérabilités entre ce release et le précédent. »
- Évaluation des risques :
  - « Quel est le risque métier de ces résultats d'analyse de conteneurs ? »
  - « Aidez-moi à évaluer si cette vulnérabilité de dépendance affecte notre cas d'usage. »
  - « Évaluez la gravité des vulnérabilités qui franchissent les limites de confiance. »
  - « Quelles vulnérabilités représentent le risque le plus élevé pour la production ? »
- Triage et gestion :
  - « Ignorez toutes les vulnérabilités de l'analyse des dépendances marquées comme faux positifs avec du code inaccessible. »
  - « Confirmez toutes les vulnérabilités d'analyse de conteneurs avec des exploits connus. »
  - « Mettez à jour la gravité à HIGH pour toutes les vulnérabilités qui franchissent les limites de confiance. »
  - « Montrez-moi les vulnérabilités ignorées au cours de la semaine passée, avec leur justification. »
  - « Revenez au statut détecté pour les vulnérabilités afin de les réévaluer. »
- Gestion des tickets :
  - « Créez des tickets pour toutes les vulnérabilités SAST de haute gravité confirmées et assignez-les aux derniers commiteurs. »
  - « Liez la vulnérabilité (ID de vulnérabilité) au ticket (ID de ticket) pour le suivi de la remédiation. »
  - « Générez des tâches de remédiation pour les vulnérabilités d'infrastructure critiques. »
  - « Créez un epic de sécurité pour suivre toutes les vulnérabilités liées à l'authentification. »
- Rapports et conformité :
  - « Générez un résumé exécutif de notre posture de sécurité actuelle. »
  - « Rédigez un rapport de conformité montrant la progression de la remédiation. »
  - « Résumez les résultats de sécurité pour le comité de revue de sécurité. »
  - « Créez un calendrier pour traiter tous les résultats de haute gravité. »
- Conseils de remédiation :
  - « Suggérez des approches de remédiation pour ces vulnérabilités d'injection SQL. »
  - « Quelle est la correction recommandée pour cette vulnérabilité d'image de base de conteneur ? »
  - « Aidez-moi à prioriser les correctifs de sécurité pour le prochain sprint. »
  - « Fournissez des conseils sur les pratiques de codage sécurisé pour prévenir ces problèmes. »
