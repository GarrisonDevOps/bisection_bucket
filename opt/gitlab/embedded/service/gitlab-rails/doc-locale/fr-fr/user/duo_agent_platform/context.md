---
stage: Agent Foundations
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Comprenez quel contexte est disponible pour les fonctionnalités GitLab Duo et comment contrôler les informations auxquelles elles peuvent accéder.
title: Sensibilisation contextuelle de GitLab Duo Agent Platform
---

Différentes informations sont disponibles pour aider GitLab Duo à prendre des décisions et à formuler des suggestions.

Les informations peuvent être disponibles :

- Toujours.
- En fonction de votre emplacement (le contexte change lorsque vous naviguez).
- Lorsqu'elles sont référencées explicitement. Par exemple, vous mentionnez les informations par URL, identifiant ou chemin de fichier.

## GitLab Duo Agentic Chat {#gitlab-duo-agentic-chat}

{{< history >}}

- Le titre et l'URL de la page actuelle ont été [ajoutés](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/209186) dans GitLab 18.6.

{{< /history >}}

Le contexte suivant est disponible pour GitLab Duo Agentic Chat.

### Toujours disponible {#always-available}

- Documentation GitLab.
- Connaissances générales en programmation, bonnes pratiques et spécificités des langages.
- L'intégralité de votre projet et tous ses fichiers suivis par Git.
- L'[API de recherche](../../api/search.md) de GitLab, que Chat utilise pour trouver les tickets ou les merge requests associés.
- Lors de l'utilisation de Chat dans l'interface utilisateur GitLab, le titre et l'URL de la page actuelle.

Chat recherche automatiquement le contexte nécessaire à partir des données SDLC, du [graphe de connaissances](../project/repository/knowledge_graph/_index.md), des [clients MCP](../gitlab_duo/model_context_protocol/mcp_clients.md) et des [instructions personnalisées](customize/_index.md).

### En fonction de l'emplacement {#based-on-location}

- Dans votre IDE, les fichiers que vous avez ouverts. Vous pouvez fermer ces fichiers si vous ne souhaitez pas qu'ils soient utilisés comme contexte.
- Dans l'interface utilisateur GitLab, le contexte de la page actuelle (par exemple, lors de la consultation d'une merge request ou d'un ticket).

### Lorsque référencé explicitement {#when-referenced-explicitly}

GitLab Duo Agentic Chat peut récupérer et utiliser de manière autonome :

- Fichiers (en effectuant une recherche dans votre projet ou lorsque vous fournissez des chemins de fichiers)
- Les epics
- Les tickets
- Les merge requests
- Pipelines CI/CD et job logs
- Commits
- Éléments de travail

Contrairement au Chat non agentique, le Chat agentique peut rechercher ces ressources sans vous demander de spécifier des identifiants ou des URL exacts. Par exemple, vous pouvez demander « Trouver la merge request concernant l'authentification » et Chat recherche les merge requests pertinentes.

### Contexte étendu {#extended-context}

- Pour connecter Chat à des sources de données et des outils externes, utilisez le [Model Context Protocol (MCP)](../gitlab_duo/model_context_protocol/_index.md).
- Pour fournir un contexte spécifique au projet, des normes de codage et des pratiques d'équipe, utilisez les [règles personnalisées](customize/custom_rules.md) ou [AGENTS.md](customize/agents_md.md) dans Chat, les agents et les flows.

## Flow de développement logiciel {#software-development-flow}

Le contexte suivant est disponible pour le flow de développement logiciel dans GitLab Duo Agent Platform.

### Toujours disponible {#always-available-1}

- Connaissances générales en programmation, bonnes pratiques et spécificités des langages.
- L'intégralité de votre projet et tous ses fichiers suivis par Git.
- L'[API de recherche](../../api/search.md) de GitLab, utilisée pour trouver les tickets ou les merge requests associés.

### En fonction de l'emplacement {#based-on-location-1}

- Fichiers ouverts dans l'IDE (fermez les fichiers si vous ne souhaitez pas qu'ils soient utilisés comme contexte).

### Lorsque référencé explicitement {#when-referenced-explicitly-1}

- Fichiers
- Les epics
- Les tickets
- Les merge requests
- Les pipelines de la merge request

## Exclure le contexte de GitLab Duo {#exclude-context-from-gitlab-duo}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}} {{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/17124) dans GitLab 18.2 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `use_duo_context_exclusion`. Fonctionnalité désactivée par défaut.
- Passage en version bêta dans GitLab 18.4.
- Activé par défaut dans GitLab 18.5.
- [Disponible en version générale](https://gitlab.com/gitlab-org/gitlab/-/issues/589801) dans GitLab 18.10.

{{< /history >}}

Vous pouvez contrôler le contenu du projet exclu en tant que contexte pour GitLab Duo. Utilisez cette fonctionnalité pour protéger les informations sensibles, comme les mots de passe et les fichiers de configuration.

Lorsque vous excluez du contenu, toutes les fonctionnalités de GitLab Duo Agent Platform excluent ces informations du contexte.

### Gérer les exclusions du contexte GitLab Duo {#manage-gitlab-duo-context-exclusions}

Pour spécifier le contenu que GitLab Duo exclut :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Sous **GitLab Duo**, dans la section **Exclusions du contexte de GitLab Duo**, sélectionnez **Gérer les exclusions**.
1. Spécifiez les fichiers et répertoires du projet à exclure du contexte GitLab Duo, puis sélectionnez **Sauvegarder les exclusions**.
1. Facultatif. Pour supprimer une exclusion existante, sélectionnez **Supprimer** ({{< icon name="remove" >}}) pour l'exclusion concernée.
1. Sélectionnez **Enregistrer les modifications**.

### Problèmes connus {#known-issues}

Les problèmes connus suivants concernent les exclusions de contexte dans le [serveur MCP GitLab](../model_context_protocol/mcp_server.md) :

- L'outil `get_merge_request` peut renvoyer des diffs de commits incluant du contenu provenant de fichiers exclus. Le serveur MCP GitLab ne vérifie pas les exclusions lorsqu'il récupère les diffs.
- L'outil `add_commit` dispose d'une action `move` qui copie un fichier d'un chemin vers un autre. Si le fichier source est exclu, la vérification d'exclusion n'est pas appliquée au chemin source. Un agent disposant d'un accès en écriture (push) pourrait déplacer un fichier exclu vers un chemin non exclu, puis lire son contenu.

Ces problèmes connus sont suivis dans le [ticket 628141](https://gitlab.com/gitlab-org/gitlab/-/work_items/628141). Pour garantir la protection des informations sensibles, vérifiez quels outils et permissions sont accordés aux clients MCP qui accèdent aux projets sensibles.
