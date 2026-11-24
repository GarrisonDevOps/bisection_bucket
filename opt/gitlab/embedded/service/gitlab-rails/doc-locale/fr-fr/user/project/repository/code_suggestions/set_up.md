---
stage: AI Coding
group: DAP Repository Flows
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Configurer Code Suggestions dans votre IDE.
title: Configurer Code Suggestions
---

GitLab Duo Code Suggestions est disponible via une extension d'éditeur dans votre IDE.

## Prérequis {#prerequisites}

- GitLab Duo Core [activé](../../../gitlab_duo/turn_on_off.md#turn-gitlab-duo-core-on-or-off).
- Un [langage et un IDE pris en charge](supported_extensions.md).
- Un [espace de nommage GitLab Duo par défaut](../../../profile/preferences.md#namespace-resolution-in-your-local-environment) défini, ou un projet ouvert ayant accès à GitLab Duo.

## Configurer une extension d'éditeur {#configure-an-editor-extension}

Pour utiliser Code Suggestions, installez l'extension pour votre IDE, puis authentifiez-vous et configurez-la pour GitLab Duo. Code Suggestions est activé par défaut.

- [Visual Studio Code](../../../../editor_extensions/visual_studio_code/setup.md)
- [Plugin GitLab Duo pour les IDE JetBrains](../../../../editor_extensions/jetbrains_ide/setup.md)
- [Visual Studio](../../../../editor_extensions/visual_studio/setup.md)
- [Plugin `gitlab.vim` pour Neovim](../../../../editor_extensions/neovim/setup.md)
- [GitLab pour Eclipse](../../../../editor_extensions/eclipse/setup.md)

Dans le Web IDE GitLab, Code Suggestions ne nécessite aucune configuration supplémentaire. Vous pouvez [commencer à utiliser Code Suggestions](_index.md#use-code-suggestions) immédiatement.

## Vérifier que Code Suggestions est activé {#verify-that-code-suggestions-is-on}

Toutes les extensions d'éditeur de GitLab, à l'exception de Neovim, ajoutent une icône à la barre d'état de votre IDE. Vérifiez l'icône pour vous assurer que les suggestions fonctionnent.

Par exemple, dans Visual Studio :

![La barre d'état dans Visual Studio.](img/visual_studio_status_bar_v17_4.png)

| Icône | Statut | Signification |
| :--- | :----- | :------ |
| {{< icon name="tanuki-ai" >}} | **Prêt** | Vous avez configuré et activé GitLab Duo, et vous utilisez un langage qui prend en charge Code Suggestions. |
| {{< icon name="tanuki-ai-off" >}} | **Non configuré** | Vous n'avez pas saisi de jeton d'accès personnel, ou vous utilisez un langage que Code Suggestions ne prend pas en charge. |
| ![L'icône de statut pour la récupération de Code Suggestions.](img/code_suggestions_loading_v17_4.svg) | **Chargement de la suggestion** | GitLab Duo récupère des suggestions Code Suggestions pour vous. |
| ![L'icône de statut pour une erreur de Code Suggestions.](img/code_suggestions_error_v17_4.svg) | **Erreur** | GitLab Duo a rencontré une erreur. |
