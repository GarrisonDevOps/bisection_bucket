---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Agent Data Analyst
---

{{< details >}}

- Édition : [Gratuite](../../../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/578342) dans GitLab 18.6 [avec le feature flag](../../../../administration/feature_flags/_index.md) `foundational_analytics_agent`. Fonctionnalité désactivée par défaut.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/583940) en [version bêta](../../../../policy/development_stages_support.md#beta) dans GitLab 18.7.
- [Activation sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/583940) dans GitLab 18.7.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/584536) dans GitLab 18.11.

{{< /history >}}

L'agent Data Analyst est un assistant IA spécialisé qui vous aide à interroger, visualiser et faire remonter des données sur la plateforme GitLab. Il utilise [GitLab Query Language (GLQL)](../../../glql/_index.md) et [Orbit](https://docs.gitlab.com/orbit/) pour récupérer et analyser les données, puis fournit des informations claires et exploitables sur vos projets et groupes. Pour obtenir des informations sur les sources de données et les champs disponibles dans votre édition, consultez [les sources de données GLQL](../../../glql/data_sources/_index.md) et [ce qu'Orbit indexe](https://docs.gitlab.com/orbit/remote/indexing/).

Utilisez l'agent Data Analyst lorsque vous avez besoin d'aide avec :

- Analyse de volume : comptage des merge requests, tickets ou autres éléments de travail sur des périodes données.
- Performance de l'équipe : compréhension des tâches effectuées par les membres de l'équipe et de leurs résultats.
- Analyse des tendances : identification des tendances dans votre workflow de développement.
- Surveillance du statut : vérification de l'état des éléments de travail dans votre projet ou groupe.
- Découverte d'éléments de travail : recherche de tickets, merge requests ou epics par auteur, label, jalon ou d'autres critères.
- Génération de requêtes GLQL : création de requêtes à intégrer partout où GitLab Flavored Markdown est pris en charge, notamment dans les tickets, les merge requests, les epics, les commentaires, les wikis, les extraits de code et les releases.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation générale, consultez la [démo GitLab Duo Data Analyst](https://youtu.be/9MTT2P_t-CU).

Vous pouvez laisser un commentaire dans le [ticket 574028](https://gitlab.com/gitlab-org/gitlab/-/issues/574028).

## Problèmes connus {#known-issues}

- L'agent peut effectuer une agrégation légère sur les données interrogées, mais les résultats peuvent être incomplets pour les ensembles de données dépassant 100 éléments.
- GLQL prend en charge l'interrogation de [zones spécifiques](../../../glql/data_sources/_index.md), mais pas de toutes les sources de données GitLab.
- L'agent ne peut pas générer de sortie directement vers des éléments de travail ou des tableaux de bord. Cependant, vous pouvez copier les requêtes GLQL générées et les intégrer sur n'importe quelle page prenant en charge GitLab Flavored Markdown.

## Utiliser l'agent Data Analyst {#use-the-data-analyst-agent}

Vous pouvez utiliser l'agent Data Analyst dans l'interface utilisateur GitLab, VS Code et les IDE JetBrains.

### Dans l'interface GitLab {#in-the-gitlab-ui}

Prérequis :

- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.

Pour utiliser l'agent Data Analyst dans l'interface utilisateur GitLab :

1. Dans la barre latérale GitLab Duo, sélectionnez **Ajouter une discussion** ({{< icon name="pencil-square" >}}).
1. Dans la liste déroulante, sélectionnez **Analyste de données**.

   Une conversation Chat s'ouvre dans la barre latérale GitLab Duo située à droite de l'écran.
1. Saisissez votre question ou votre demande d'analyse. Pour obtenir les meilleurs résultats de votre demande :

   - Précisez la portée (projet ou groupe) lorsque vous interrogez des données.
   - Incluez des plages horaires pour les analyses temporelles.
   - Soyez précis quant au type d'éléments de travail qui vous intéressent.

### Dans VS Code {#in-vs-code}

Prérequis :

- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.
- Installez et configurez [GitLab for VS Code](../../../../editor_extensions/visual_studio_code/setup.md) version 6.57.3 ou ultérieure.
- Définir un [espace de nommage GitLab Duo par défaut](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace).

Pour utiliser l'agent Data Analyst dans VS Code :

1. Dans VS Code, dans la barre latérale gauche, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Sélectionnez l'onglet **Chat**.
1. Dans la liste déroulante **Nouvelle discussion** ({{< icon name="duo-chat-new" >}}), sélectionnez **Analyste de données**.
1. Saisissez votre question ou votre demande d'analyse. Pour obtenir les meilleurs résultats de votre demande :

   - Précisez la portée (projet ou groupe) lorsque vous interrogez des données.
   - Incluez des plages horaires pour les analyses temporelles.
   - Soyez précis quant au type d'éléments de travail qui vous intéressent.

### Dans les IDE JetBrains {#in-jetbrains-ides}

Prérequis :

- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.
- Installez et configurez le [plugin GitLab Duo pour les IDE JetBrains](../../../../editor_extensions/jetbrains_ide/setup.md) version 3.24.4 ou ultérieure.
- Définir un [espace de nommage GitLab Duo par défaut](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace).

Tout d'abord, activez GitLab Duo Agent Platform :

1. Dans votre IDE JetBrains, accédez à **Paramètres** > **Outils** > **GitLab Duo**.
1. Sous **GitLab Duo Agent Platform**, cochez la case **Activer GitLab Duo Agent Platform**.
1. Redémarrez votre IDE si vous y êtes invité.

Ensuite, pour utiliser l'agent Data Analyst :

1. Dans votre IDE JetBrains, dans la barre des fenêtres d'outils de droite, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Sélectionnez l'onglet **Chat**.
1. Dans la liste déroulante **Nouvelle discussion** ({{< icon name="duo-chat-new" >}}), sélectionnez **Analyste de données**.
1. Saisissez votre question ou votre demande d'analyse. Pour obtenir les meilleurs résultats de votre demande :

   - Précisez la portée (projet ou groupe) lorsque vous interrogez des données.
   - Incluez des plages horaires pour les analyses temporelles.
   - Soyez précis quant au type d'éléments de travail qui vous intéressent.

## Exemples de prompts {#example-prompts}

- Volume et comptage :
  - « Combien de merge requests ont été fusionnées ce mois-ci ? »
  - « Comptez les tickets créés la semaine dernière. »
  - « Combien de bugs sont actuellement ouverts ? »
- Performance de l'équipe :
  - « Sur quoi @username a-t-il travaillé ce mois-ci ? »
  - « Montrez-moi les merge requests fusionnées par l'équipe X au cours des deux dernières semaines. »
  - « Montrez-moi un tableau des tickets avec les titres et les labels qui me sont attribués. »
  - « Listez les merge requests ouvertes par auteur. »
- Statut et surveillance :
  - « Montrez-moi les tickets ouverts avec les labels `~priority::1` et `~bug`. »
  - « Montrez-moi les tickets en retard. »
  - « Quelles merge requests attendent une révision ? »
  - « Listez les tickets du jalon en cours. »
- Analyse des tendances :
  - « Montrez-moi l'activité des merge requests au cours du dernier mois. »
  - « Quelle est la tendance de création de bugs ce trimestre ? »
  - « Comparez les taux de clôture des tickets entre ce mois-ci et le mois dernier. »
- Génération de requêtes GLQL :
  - « Écrivez une requête GLQL pour les tickets ouverts qui me sont attribués. »
  - « Créez un tableau affichant toutes les merge requests fusionnées cette semaine. »
  - « Générez une vue intégrée GLQL pour les travaux ouverts de l'équipe X. »
  - « Quelle est la syntaxe GLQL pour filtrer par plusieurs labels ? »
- Découverte d'éléments de travail :
  - « Listez les merge requests ciblant la branche principale. »
  - « Trouvez les tickets mis à jour au cours des dernières 24 heures. »
  - « Montrez-moi les bugs ouverts attribués à l'équipe X. »
