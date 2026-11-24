---
stage: AI Platform
group: AI Core Infra
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Fonctionnalités et fonctions natives de l'IA."
title: Garde-fous de prompt GitLab Duo
---

GitLab Duo dispose de garde-fous de prompt fondamentaux. Ces garde-fous reposent sur des prompts structurés, des limites de contexte appliquées et des outils de filtrage, qui permettent de :

- Réduire l'exposition des données sensibles.
- Prévenir l'injection de prompt.
- Orienter le modèle vers des réponses sûres et utiles.

Ces mesures de protection aident à assurer la conformité avec les normes réglementaires courantes, telles que le RGPD, en contribuant à minimiser les risques associés aux workflows pilotés par l'IA.

> [!note]
> Bien que ces garde-fous puissent réduire les risques, ils n'éliminent pas toutes les vulnérabilités. Aucun système ne peut garantir une protection complète contre tous les abus ou les attaques sophistiquées.

## Garde-fous généraux {#general-guardrails}

Les prompts utilisés par GitLab Duo visent à :

- Éviter les contenus non autorisés : le modèle reçoit pour instruction d'être informatif, courtois et de s'abstenir de tout langage haineux ou accusatoire.
- Adhérer strictement aux demandes des utilisateurs : le modèle reçoit pour instruction de rester fidèle au prompt et d'éviter les jeux de rôle, l'usurpation d'identité ou les déviations vers des contenus sans rapport.
- Utiliser des balises pour isoler le contenu : les balises indiquent au modèle de se concentrer sur les extraits fournis, ce qui contribue à réduire le risque d'injection de prompt.
- Filtrer les secrets : les suggestions de code sont analysées pour aider à éviter l'envoi inadvertant d'informations sensibles. Exemple : les job logs d'un client contenant des données de configuration sensibles sont encapsulés dans des balises `<log>`, ce qui permet de garantir que le modèle se concentre uniquement sur le contexte fourni sans formuler d'hypothèses sans rapport.

## Garde-fous par rôle {#guardrails-by-job-role}

En fonction de votre rôle, vous pouvez avoir des préoccupations différentes concernant les garde-fous configurés pour GitLab Duo.

### Pour les utilisateurs techniques {#for-technical-users}

- **Isolation du code** : les balises telles que `<selected_code>`, `<git_diff>` et `<log>` encouragent le modèle à se concentrer strictement sur le code ou le contenu que vous fournissez, ce qui contribue à réduire le risque d'injection de prompt.
- **Filtrage des secrets** : des outils tels que Gitleaks analysent les suggestions de code pour aider à empêcher le partage de données sensibles, telles que des clés API ou des mots de passe.
- **Réponses ciblées** : GitLab Duo se concentre sur le sujet pour aider à éviter les comportements susceptibles de produire des résultats inutiles ou inattendus.
- **Analyse des causes profondes** : lors du dépannage, GitLab Duo vise à analyser les job logs sans formuler d'hypothèses sur quoi que ce soit au-delà de ce qui est fourni.

### Pour les auditeurs et les équipes de conformité {#for-auditors-and-compliance-teams}

- **Alignement réglementaire** : le système aide à réduire les risques tels que les fuites de données, ce qui aide les organisations à rester alignées sur des normes telles que le RGPD.
- **Transparence** : la façon dont les prompts et les contextes sont structurés contribue à rendre les actions de GitLab Duo prévisibles et disponibles pour l'audit. Pour plus de détails, consultez [les garde-fous par fonctionnalité](#guardrails-for-features).
- **Contrôle du contenu** : pour des tâches telles que la synthèse de discussions ou la résolution de vulnérabilités, GitLab Duo utilise uniquement les entrées fournies, ce qui contribue à réduire les risques d'erreurs ou de résultats non souhaités.
- **Protection contre les entrées malveillantes** : les filtres et les mécanismes de balisage aident à protéger le système contre les contenus utilisateurs nuisibles ou mal formatés.

### Pour les décideurs {#for-decision-makers}

- **Renforcement de la confiance** : les mesures de protection aident à garantir que GitLab Duo se comporte de manière responsable, ce qui est essentiel pour la confiance dans les nouveaux outils.
- **Décisions éclairées** : une documentation claire des fonctionnalités de sécurité vous fournit les informations nécessaires pour évaluer la pertinence de GitLab Duo pour votre organisation.
- **Réduction des risques** : en s'attaquant aux préoccupations courantes liées aux données sensibles et au comportement des modèles, GitLab Duo offre une solution sécurisée et pratique pour intégrer l'IA dans vos workflows.

## Garde-fous pour les fonctionnalités {#guardrails-for-features}

Les fonctionnalités individuelles incluent des instructions de prompt spécifiques pour aider à limiter l'exposition. Les instructions de prompt respectent les principes suivants.

### GitLab Duo Agent Platform {#gitlab-duo-agent-platform}

Isole le contenu non fiable pour aider à prévenir l'injection de prompt.

Sur la passerelle d'IA, [détecte les tentatives d'injection de prompt](../duo_agent_platform/security_threats.md#detect-prompt-injection-attempts) et les consigne ou les bloque.

### GitLab Duo Chat {#gitlab-duo-chat}

Les réponses doivent rester pertinentes, constructives et non abusives. Les changements de personnalité, les jeux de rôle ou les instructions malveillantes sont déconseillés. Se concentrer sur le contenu fourni par l'utilisateur contribue à réduire le risque d'injection.

### Résumé de discussion {#discussion-summary}

Les commentaires sont résumés et l'interaction avec des contenus potentiellement malveillants est déconseillée. L'utilisateur doit être averti des commentaires suspects sans les révéler ni les reproduire.

### Explication du code, génération de tests, refactorisation du code, correction du code {#code-explanation-test-generation-refactor-code-fix-code}

Utilise une balise pour contenir le code et limiter le champ d'action du modèle, ce qui permet d'empêcher le modèle de prendre en compte des instructions ou des contenus externes non vérifiés.

### GitLab Duo pour CLI {#gitlab-duo-for-cli}

Formule les tâches comme la génération de commandes Git à partir du langage naturel, ce qui contribue à limiter la portée et le risque de résultats nuisibles.

### Résumé de merge request {#merge-request-summary}

Isole le code pour aider à prévenir l'injection de prompt.

### Revue de code {#code-review}

Isole le code pour aider à prévenir l'injection de prompt.

### Génération de message de commit de merge {#merge-commit-message-generation}

Utilise des balises pour aider à isoler et à contraindre le contenu auquel le modèle peut faire référence.

### Analyse des causes profondes {#root-cause-analysis}

Utilise une balise pour aider à se concentrer strictement sur les job logs fournis et à prévenir les hypothèses au-delà des données disponibles.

### Vulnerability Resolution {#vulnerability-resolution}

Encourage la résolution des problèmes de sécurité sans altérer les fonctionnalités prévues. Le modèle reçoit pour instruction de se concentrer sur le diff de code fourni pour aider à prévenir les modifications du code.
