---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Agent Flow Creator
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated, GitLab Dedicated for Government

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/22644) dans GitLab 19.3.

{{< /history >}}

L'agent Flow Creator est un agent d'IA spécialisé qui vous aide à créer des [flows personnalisés](../../flows/custom.md) pour le catalogue d'IA. Décrivez en langage courant le flow que vous souhaitez, et l'agent génère un flow YAML complet que vous pouvez utiliser dans le catalogue d'IA.

L'agent comprend le framework Flow Registry, notamment les composants, les déclencheurs, les entrées et le routage. Il consulte la documentation à jour du framework avant de répondre. Ses réponses reflètent ainsi les capacités actuelles du framework, et non celles d'une version figée.

Utilisez l'agent Flow Creator lorsque vous devez accomplir l'une des tâches suivantes :

- Créer un flow : générer un flow YAML complet à partir de votre description des opérations que le flow doit effectuer et des conditions qui doivent le déclencher.
- Déboguer un flow : déterminer pourquoi une configuration de flow existante échoue à la validation ou ne se comporte pas comme prévu.
- Comprendre le framework : découvrir quels composants, paramètres et déclencheurs sont disponibles et comment les relier.

## Utiliser l'agent Flow Creator {#use-the-flow-creator}

Prérequis :

- [Activer](_index.md#turn-foundational-agents-on-or-off) les agents par défaut.

Pour utiliser l'agent Flow Creator dans l'interface GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale GitLab Duo, sélectionnez **Ajouter une discussion** ({{< icon name="pencil-square" >}}).
1. Dans la liste déroulante, sélectionnez **Flow Creator**.

   Une conversation Chat s'ouvre dans la barre latérale GitLab Duo située à droite de l'écran.
1. Décrivez le flow que vous souhaitez créer. Pour obtenir les meilleurs résultats :

   - Décrivez ce qui doit déclencher le flow, par exemple lorsqu'un ticket vous est assigné ou lorsqu'une nouvelle merge request est créée.
   - Décrivez le résultat que vous souhaitez obtenir, et non les composants dont vous pensez avoir besoin. L'agent sélectionne les composants appropriés.
   - Lors du débogage, collez le flow YAML complet pour que l'agent puisse en vérifier la conformité aux règles du framework.
1. Copiez le flow YAML contenu dans la réponse de l'agent puis, dans un projet où vous êtes autorisé à créer des flows, collez-le dans l'écran de création d'un [nouveau flow](../../flows/custom.md).

## Exemples de prompts {#example-prompts}

- Créer un flow :
  - « Crée un flow qui résume un ticket lorsqu'il m'est assigné. »
  - « Crée un flow qui ajoute un label aux nouveaux tickets selon leur description. »
  - « Crée un flow qui me demande mon approbation avant de commenter une merge request. »
- Déboguer un flow :
  - « Pourquoi cette configuration de flow ne passe-t-elle pas la validation ? `<flow YAML>` »
  - « Ce flow ne s'arrête jamais. Quel est le problème avec ce flow ? `<flow YAML>` »
- Comprendre le fonctionnement des flows :
  - « Comment puis-je transmettre le nom de la branche à mon flow ? »
  - « Quel composant dois-je utiliser pour demander à l'utilisateur de saisir des données pendant l'exécution d'un flow ? »

## Problèmes connus {#known-issues}

- L'agent ne génère du YAML que pour le schéma Flow Registry v1.
- L'agent consulte la documentation du framework avant de répondre. Ses réponses peuvent donc prendre plus de temps que celles des autres agents.
