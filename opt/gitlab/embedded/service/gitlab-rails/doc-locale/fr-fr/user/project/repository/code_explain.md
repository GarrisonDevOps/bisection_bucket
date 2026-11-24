---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Expliquer le code dans un fichier
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Module complémentaire : GitLab Duo Pro ou GitLab Duo Enterprise, GitLab Duo avec Amazon Q
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="Informations sur le modèle" >}}

- [LLM par défaut](../../gitlab_duo/model_selection.md#default-models)
- LLM pour Amazon Q : Amazon Q Developer
- Disponible sur [GitLab Duo avec des modèles auto-hébergés](../../../administration/gitlab_duo_self_hosted/_index.md)

{{< /collapsible >}}

{{< history >}}

- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/429915) dans GitLab 16.8.
- Modifié pour nécessiter le module complémentaire GitLab Duo dans GitLab 17.6 et versions ultérieures.
- [LLM par défaut mis à jour](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/issues/1541) vers Claude Sonnet 4.5 dans GitLab 18.6.

{{< /history >}}

Si vous passez beaucoup de temps à essayer de comprendre du code créé par d'autres personnes, ou si vous avez du mal à comprendre du code écrit dans un langage que vous ne connaissez pas, vous pouvez demander à GitLab Duo de vous expliquer le code.

Prérequis :

- Vous devez appartenir à au moins un groupe avec le [paramètre de fonctionnalités expérimentales et bêta](../../gitlab_duo/turn_on_off.md#turn-on-beta-and-experimental-features) activé.
- Vous devez avoir accès à la consultation du projet.

Pour expliquer le code dans un fichier :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans le projet, sélectionnez un fichier contenant du code.
1. Sélectionnez les lignes dont vous souhaitez obtenir une explication.
1. Sur le côté gauche, sélectionnez le point d'interrogation ({{< icon name="question" >}}). Vous devrez peut-être faire défiler jusqu'à la première ligne de votre sélection pour le voir.

   ![Vue de fichier affichant les lignes sélectionnées et l'icône en forme de point d'interrogation que vous pouvez utiliser pour expliquer le code.](img/explain_code_v17_1.png)

GitLab Duo Chat explique le code. La génération de l'explication peut prendre un moment.

Si vous le souhaitez, vous pouvez fournir des commentaires sur la qualité de l'explication.

Nous ne pouvons pas garantir que le grand modèle de langage produit des résultats corrects. Utilisez l'explication avec prudence.

Vous pouvez également expliquer le code dans :

- Une [merge request](../merge_requests/changes.md#explain-code-in-a-merge-request).
- L'[IDE](../../gitlab_duo_chat/examples.md#explain-selected-code)
