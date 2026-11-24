---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Utiliser ces outils pour interagir avec GitLab via le serveur MCP GitLab.
title: Outils du serveur MCP GitLab
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : Disponibilité générale

{{< /details >}}

> [!warning]
> Pour fournir des commentaires sur cette fonctionnalité, laissez un commentaire sur [l'issue 630189](https://gitlab.com/gitlab-org/gitlab/-/issues/630189).

Le serveur MCP GitLab fournit un ensemble d'outils qui s'intègrent à vos workflows GitLab existants. Vous pouvez utiliser ces outils pour interagir directement avec GitLab et y effectuer des opérations courantes.

## `get_mcp_server_version` {#get_mcp_server_version}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200105) dans GitLab 18.3.
- Passée de [version bêta](../../policy/development_stages_support.md#beta) à [disponibilité générale](../../policy/development_stages_support.md#generally-available) dans GitLab 19.5.

{{< /history >}}

Renvoie la version actuelle du serveur MCP GitLab.

Exemple :

```plaintext
What version of the GitLab MCP server am I connected to?
```

## `get_project` {#get_project}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250430) dans GitLab 19.4.

{{< /history >}}

Renvoie les métadonnées d'un seul projet GitLab : ID numérique, chemin complet, branche par défaut, visibilité et URL web.

| Paramètre    | Type   | Obligatoire | Description |
|--------------|--------|----------|-------------|
| `url`        | Chaîne | Non       | URL du projet. Renseignez un seul des deux paramètres `url` et `project_id`. |
| `project_id` | Chaîne | Non       | ID ou chemin complet du projet. Renseignez un seul des deux paramètres `url` et `project_id`. |

`default_branch` est `null` lorsque le projet n'a pas encore de dépôt. Pour trouver un projet que vous ne pouvez pas encore nommer, utilisez `search` avec la portée `projects`.

Exemple :

```plaintext
What is the default branch of gitlab-org/gitlab?
```

## `add_commit` {#add_commit}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605876) dans GitLab 19.3.
- Les paramètres `start_sha` et `start_project` ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/work_items/621972) dans GitLab 19.4.

{{< /history >}}

Ajoute un commit avec une ou plusieurs actions de fichier à une branche en un seul appel.

| Paramètre        | Type             | Obligatoire | Description |
|------------------|------------------|----------|-------------|
| `commit_message` | Chaîne           | Oui      | Message de commit. |
| `actions`        | tableau d'objets | Oui      | Actions de fichier à committer en un seul lot. |
| `branch`         | Chaîne           | Oui      | Nom de la branche dans laquelle effectuer le commit. |
| `project_id`     | Chaîne           | Non       | ID ou chemin du projet. Obligatoire si `url` n'est pas renseigné. |
| `url`            | Chaîne           | Non       | URL GitLab du projet. Obligatoire si `project_id` n'est pas renseigné. |
| `start_branch`   | Chaîne           | Non       | Nom de la branche à partir de laquelle créer la nouvelle branche. Obligatoire lorsque `branch` n'existe pas. |
| `start_sha`      | Chaîne           | Non       | SHA du commit à partir duquel créer une nouvelle branche. Mutuellement exclusif avec `start_branch`. |
| `start_project`  | Chaîne           | Non       | Chemin complet du projet à partir duquel démarrer le commit. Doit être le projet lui-même ou un projet dont il est une duplication. |

Chaque objet dans `actions` accepte les champs suivants :

| Champ              | Type    | Obligatoire | Description |
|--------------------|---------|----------|-------------|
| `action`           | Chaîne  | Oui      | L'action à effectuer : `create`, `update`, `delete`, `move` ou `chmod`. |
| `file_path`        | Chaîne  | Oui      | Chemin complet vers le fichier. |
| `content`          | Chaîne  | Non       | Contenu du fichier. Utilisé par `create`, `update` et `move`. Mutuellement exclusif avec `old_str` et `new_str`. |
| `old_str`          | Chaîne  | Non       | Texte existant à remplacer dans une action `update`. Requiert `new_str`. |
| `new_str`          | Chaîne  | Non       | Texte de remplacement pour `old_str` dans une action `update`. |
| `previous_path`    | Chaîne  | Non       | Chemin de fichier d'origine. Obligatoire pour `move`. |
| `encoding`         | Chaîne  | Non       | Encodage de `content` : `text` ou `base64`. La valeur par défaut est `text`. |
| `last_commit_id`   | Chaîne  | Non       | Dernier ID de commit connu pour le fichier, utilisé pour la concurrence optimiste. |
| `execute_filemode` | Booléen | Non       | Indique si le fichier est exécutable. Obligatoire pour `chmod`. |

Les modifications partielles remplacent exactement une occurrence de `old_str`. Si elle apparaît plus d'une fois, fournissez davantage de contexte environnant. Les modifications partielles lisent le fichier complet sur le serveur ; elles ne sont donc pas prises en charge pour les fichiers de plus de 10 Mio. Pour les fichiers plus volumineux, committez le contenu complet du fichier à la place.

Les modifications partielles ne sont pas prises en charge pour les fichiers binaires ni pour les fichiers stockés dans LFS.

Exemple :

```plaintext
In project gitlab-org/gitlab, create README.md on branch "docs-update"
with the content "# New title" and commit message "Add README"
```

## `create_issue` {#create_issue}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203055) dans GitLab 18.4.
- [Non listé](https://gitlab.com/gitlab-org/gitlab/-/work_items/625129) dans GitLab 19.4. Remplacé par [`save_work_item`](#save_work_item).

{{< /history >}}

Remplacé par [`save_work_item`](#save_work_item), qui résout les titres de jalon et les noms de label aux mêmes endroits (le projet et ses groupes ancêtres), mais est plus strict sur les noms introuvables : `create_issue` crée les noms de label qui n'existent pas encore et ignore silencieusement un titre de jalon inconnu, tandis que `save_work_item` renvoie une erreur nommant tout ce qu'il ne peut pas trouver. Cet outil n'apparaît plus dans `tools/list` mais reste appelable pendant la migration des appelants.

Crée un nouveau ticket dans un projet GitLab.

| Paramètre      | Type              | Obligatoire | Description |
|----------------|-------------------|----------|-------------|
| `id`           | Chaîne            | Oui      | ID ou chemin complet du projet. |
| `title`        | Chaîne            | Oui      | Titre du ticket. |
| `description`  | Chaîne            | Non       | Description du ticket. |
| `assignee_ids` | Tableau d'entiers | Non       | Tableau des ID des utilisateurs assignés. |
| `milestone_id` | Entier           | Non       | ID du jalon. |
| `labels`       | Tableau de chaînes de caractères  | Non       | Tableau des noms de label. |
| `confidential` | Booléen           | Non       | Rend le ticket confidentiel. La valeur par défaut est `false`. |
| `epic_id`      | Entier           | Non       | ID de l'epic lié. |

Exemple :

```plaintext
Create a new issue titled "Fix login bug" in project 123 with description
"Users cannot log in with special characters in password"
```

## `get_issue` {#get_issue}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/201838) dans GitLab 18.4.
- [Non listé](https://gitlab.com/gitlab-org/gitlab/-/work_items/628333) dans GitLab 19.4. Remplacé par [`get_work_item`](#get_work_item).

{{< /history >}}

Remplacé par [`get_work_item`](#get_work_item), qui couvre les tickets et les autres types d'éléments de travail. Cet outil n'apparaît plus dans `tools/list` mais reste appelable pendant la migration des appelants.

Récupère des informations détaillées sur un ticket GitLab précis.

| Paramètre   | Type    | Obligatoire | Description |
|-------------|---------|----------|-------------|
| `id`        | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `issue_iid` | Entier | Oui      | ID interne du ticket. |

Exemple :

```plaintext
Get details for issue 42 in project 123
```

## `save_merge_request` {#save_merge_request}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/571243) sous le nom `create_merge_request` dans GitLab 18.5.
- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/217458) de `assignee_ids`, `reviewer_ids`, `description`, `labels` et `milestone_id` dans GitLab 18.8.
- Renommé en `save_merge_request` et étendu pour mettre à jour les merge requests dans GitLab 19.3. Les noms `create_merge_request` et `update_merge_request` restent disponibles en tant qu'alias.

{{< /history >}}

Crée ou met à jour une merge request dans un projet GitLab. La présence de `merge_request_iid` détermine l'opération : omettez-le pour créer une merge request, ou fournissez-le pour en mettre une à jour.

| Paramètre              | Type              | Obligatoire | Description |
|------------------------|-------------------|----------|-------------|
| `project_id`           | Chaîne            | Oui      | ID ou chemin complet du projet. |
| `merge_request_iid`    | Entier           | Non       | ID interne de la merge request. À fournir pour mettre à jour une merge request existante ; à omettre pour en créer une. |
| `title`                | Chaîne            | Non       | Titre de la merge request. Obligatoire lors de la création. |
| `source_branch`        | Chaîne            | Non       | Nom de la branche source. Obligatoire lors de la création. |
| `target_branch`        | Chaîne            | Non       | Nom de la branche cible. Obligatoire lors de la création. |
| `target_project_id`    | Entier           | Non       | ID du projet cible. S'applique lors de la création. |
| `description`          | Chaîne            | Non       | Description de la merge request. |
| `labels`               | Tableau de chaînes de caractères  | Non       | Noms des labels. Remplace tous les labels existants. Passez un tableau vide pour supprimer tous les labels. |
| `add_labels`           | Tableau de chaînes de caractères  | Non       | Noms des labels à ajouter. S'applique lors de la mise à jour. |
| `remove_labels`        | Tableau de chaînes de caractères  | Non       | Noms des labels à supprimer. S'applique lors de la mise à jour. |
| `assignees`            | Tableau de chaînes de caractères  | Non       | Noms d'utilisateur à assigner. Alternative à `assignee_ids` ; fournissez-en un. Passez un tableau vide pour supprimer tous les assignés. |
| `assignee_ids`         | Tableau d'entiers | Non       | ID d'utilisateur à assigner. Alternative à `assignees` ; fournissez-en un. Passez un tableau vide pour supprimer tous les assignés. |
| `reviewers`            | Tableau de chaînes de caractères  | Non       | Noms d'utilisateur à inviter à effectuer une revue. Alternative à `reviewer_ids` ; fournissez-en un. Passez un tableau vide pour supprimer tous les relecteurs. |
| `reviewer_ids`         | Tableau d'entiers | Non       | ID d'utilisateur à inviter à effectuer une revue. Alternative à `reviewers` ; fournissez-en un. Passez un tableau vide pour supprimer tous les relecteurs. |
| `milestone_id`         | Entier           | Non       | ID du jalon. |
| `milestone`            | Chaîne            | Non       | Titre d'un jalon de projet ou de groupe ancêtre à assigner. Mutuellement exclusif avec `milestone_id`. |
| `remove_source_branch` | Booléen           | Non       | Supprimer la branche source lorsque la merge request est fusionnée. |
| `squash`               | Booléen           | Non       | Écraser les commits en un seul commit lors de la fusion. |
| `state_event`          | Chaîne            | Non       | Transition d'état à effectuer. L'un de `close` ou `reopen`. S'applique lors de la mise à jour. |
| `discussion_locked`    | Booléen           | Non       | Verrouiller la discussion de la merge request. S'applique lors de la mise à jour. |
| `allow_collaboration`  | Booléen           | Non       | Autoriser les commits des membres pouvant fusionner vers la branche cible. S'applique lors de la mise à jour. |

Exemples :

```plaintext
Create a merge request in project gitlab-org/gitlab titled "Bug fix broken specs"
from branch "fix/specs-broken" into "master" and enable squash
```

```plaintext
Update merge request 42 in project gitlab-org/gitlab to add the "bug" label and close it
```

## `get_merge_request` {#get_merge_request}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/201838) dans GitLab 18.4.
- [Modification](https://gitlab.com/gitlab-org/gitlab/-/issues/605878) dans GitLab 19.3 avec prise en charge de `url` et renvoi des facettes de données associées.

{{< /history >}}

Récupère une merge request et, éventuellement, ses diffs, commits, notes, pipelines, discussions, approbations ou conflits. Seule la merge request de base est renvoyée, sauf si vous demandez des données associées au moyen du paramètre `include`.

| Paramètre           | Type    | Obligatoire | Description |
|---------------------|---------|----------|-------------|
| `url`               | Chaîne  | Non       | URL GitLab de la merge request. Renseignez ce paramètre ou les paramètres `project_id` et `merge_request_iid`. |
| `project_id`        | Chaîne  | Non       | ID ou chemin complet du projet. Obligatoire si `url` n'est pas renseigné. |
| `merge_request_iid` | Entier | Non       | ID interne de la merge request. Obligatoire si `url` n'est pas renseigné. |
| `include`           | Tableau   | Non       | Facettes associées à renvoyer avec la merge request. L'un de `diffs`, `commits`, `notes`, `pipelines`, `discussions`, `approvals` ou `conflicts`. Limité à une facette par appel. |
| `detail`            | Chaîne  | Non       | Niveau de détail du diff. L'un de `none` pour les totaux uniquement, `stats` pour les ajouts et suppressions par fichier, ou `full_patch` pour le texte du patch par fichier ainsi que les statistiques par fichier. La valeur par défaut est `stats`. S'applique uniquement lorsque `include` a la valeur `["diffs"]`. |
| `diffs_after`       | Chaîne  | Non       | Curseur pour la pagination avant des fichiers. S'applique uniquement lorsque `include` est `["diffs"]` et que `detail` est `full_patch`. |
| `diffs_first`       | Entier | Non       | Nombre de fichiers à retourner après le curseur, jusqu'à 100. S'applique uniquement lorsque `include` est `["diffs"]` et que `detail` est `full_patch`. |
| `notes_after`       | Chaîne  | Non       | Curseur de pagination vers l'avant pour les notes. S'applique uniquement lorsque `include` a la valeur `["notes"]`. |
| `notes_first`       | Entier | Non       | Nombre de notes à renvoyer après le curseur, dans la limite de 100. S'applique uniquement lorsque `include` a la valeur `["notes"]`. |
| `notes_before`      | Chaîne  | Non       | Curseur pour la pagination arrière des notes. S'applique uniquement lorsque `include` a la valeur `["notes"]`. |
| `notes_last`        | Entier | Non       | Nombre de notes à retourner avant le curseur, jusqu'à 100. S'applique uniquement lorsque `include` a la valeur `["notes"]`. |
| `commits_after`     | Chaîne  | Non       | Curseur pour la pagination avant des commits. S'applique uniquement lorsque `include` a la valeur `["commits"]`. |
| `commits_first`     | Entier | Non       | Nombre de commits à retourner après le curseur, jusqu'à 100. S'applique uniquement lorsque `include` a la valeur `["commits"]`. |
| `pipelines_after`   | Chaîne  | Non       | Curseur pour la pagination avant des pipelines. S'applique uniquement lorsque `include` a la valeur `["pipelines"]`. |
| `pipelines_first`   | Entier | Non       | Nombre de pipelines à retourner après le curseur, jusqu'à 100. S'applique uniquement lorsque `include` a la valeur `["pipelines"]`. |

La facette `diffs` renvoie par défaut des statistiques de modification : totaux généraux et ajouts et suppressions par fichier. Pour obtenir le texte du patch, définissez `detail` sur `full_patch`.

Les facettes `commits` et `pipelines` renvoient jusqu'à 100 entrées par appel. Chaque réponse contient `pageInfo.hasNextPage` et `pageInfo.endCursor`. Transmettez ce curseur via `commits_after` ou `pipelines_after` pour lire la page suivante.

La facette `notes` prend également en charge la pagination arrière avec `notes_last` et `notes_before`. Pour lire les notes les plus récentes, passez `notes_last` sans `notes_first` ni `notes_after`. Combiner les deux directions dans un seul appel renvoie une erreur. Chaque note renvoie sa `position` (le fichier et la ligne d'un commentaire de diff) et sa `discussion` (le fil de discussion auquel elle appartient et si le fil est résolu). La réponse inclut également `resolvedDiscussionsCount` et `resolvableDiscussionsCount`.

La facette `conflicts` renvoie le contenu brut du fichier de conflit, y compris les marqueurs de conflit Git. Elle est disponible uniquement lorsque la merge request ne peut pas être fusionnée et que vous pouvez pousser vers la branche source, et est `null` tant que la fusionnabilité n'a pas été vérifiée. Lisez le champ `conflicts` de base pour déterminer l'état.

Exemple :

```plaintext
Get merge request 15 in project gitlab-org/gitlab with its commits
```

## `list_duo_agents_and_flows` {#list_duo_agents_and_flows}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/617173) dans GitLab 19.5.

{{< /history >}}

Répertorie les agents et flows GitLab Duo activés dans un projet, afin de découvrir ce qui est disponible sans avoir à deviner un nom de flow. Les agents et flows proposés par un projet sont configurés par projet, et leurs IDs diffèrent d'un projet à l'autre.

Chaque entrée inclut `can_start_session`, qui est `true` pour un flow que vous avez la permission d'exécuter, et pour un agent de chat par défaut lorsque vous pouvez exécuter des sessions en CI dans le projet. L'agent GitLab Duo par défaut, les autres agents et les agents externes sont répertoriés uniquement à des fins de découverte, et `can_start_session` est toujours `false` pour eux. Il est également `false` pour un flow que vous ne pouvez pas exécuter, ou dont la version n'est pas encore publiée ou est toujours en brouillon.

Si vous n'avez pas d'abonnement GitLab Ultimate, un agent de chat par défaut qui le requiert est soit absent de la liste, soit listé avec `can_start_session` défini sur `false`.

Seuls les flows dont `can_start_session` est défini sur `true` incluent le `ai_catalog_item_consumer_id` qu'utilise `start_duo_session`. Pour démarrer un agent de chat par défaut, passez sa `workflow_definition` en tant que `agent`. Les descriptions peuvent être tronquées.

La liste couvre les agents, les flows et les agents externes configurés dans le projet, ainsi que les agents de chat par défaut. Les agents de chat constituent une liste fixe plutôt qu'une partie des résultats paginés du projet ; ils sont donc renvoyés uniquement avec la première page et omis si les agents ne sont pas inclus. Ils s'ajoutent à `first`, de sorte que la première page peut contenir plus d'entrées que demandé. Ils portent une `workflow_definition` au lieu d'un `ai_catalog_item_consumer_id`, ce qui permet également de distinguer les deux agents partageant le nom d'affichage `GitLab Duo` ; les entrées configurées dans le projet ont `workflow_definition` défini sur `null`.

Les agents de chat par défaut sont régis par le groupe principal du projet sur GitLab.com, et par l'organisation sur GitLab Self-Managed, plutôt que par le projet.

| Paramètre    | Type    | Obligatoire | Description |
|--------------|---------|----------|-------------|
| `project_id` | Chaîne  | Oui      | ID numérique ou chemin complet du projet pour lequel répertorier les agents et les flows. |
| `item_type`  | Chaîne  | Non       | Retourne uniquement les entrées de type `agent`, `flow` ou `third_party_flow`. Tous les types sont retournés en l'absence de ce paramètre. |
| `after`      | Chaîne  | Non       | Curseur pour la pagination vers l'avant. |
| `first`      | Entier | Non       | Nombre d'agents et de flows à retourner pour la pagination avant. La valeur par défaut est 20 et la valeur maximale est 100. |

Chaque appel renvoie une seule page de résultats. Si d'autres pages existent, la réponse comprend `pageInfo.endCursor`, que vous pouvez transmettre comme valeur du paramètre `after`.

Les éléments configurés mais désactivés sont supprimés après la récupération de la page ; une page peut donc contenir moins d'entrées que `first`, voire aucune, tandis que `pageInfo.hasNextPage` est toujours `true`. Continuez la pagination jusqu'à ce que `hasNextPage` soit `false`, plutôt que de vous arrêter à une page vide.

Exemple :

```plaintext
Which Duo flows can I run in gitlab-org/gitlab?
```

## `start_duo_session` {#start_duo_session}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/607619) dans GitLab 19.5.

{{< /history >}}

Démarre une session asynchrone de la plateforme GitLab Duo Agent pour accomplir un objectif dans un projet. Retourne immédiatement un `workflow_id`. Utilisez `get_duo_session` avec cet ID pour suivre la progression et récupérer le résultat final.

Ces outils ne sont répertoriés que lorsque la plateforme GitLab Duo Agent est disponible pour vous. Pour plus d'informations, voir [sélectionner des groupes d'outils](mcp_server.md#select-tool-groups-toolsets).

La session s'exécute dans un job CI qui peut pousser des commits et ouvrir des merge requests.

Renseignez un seul des deux paramètres `url` et `project_id`. Fournissez au plus l'un de `flow`, `flow_item_id`, `ai_catalog_item_consumer_id` ou `agent`.

| Paramètre                     | Type    | Obligatoire | Description |
|-------------------------------|---------|----------|-------------|
| `url`                         | Chaîne  | Non       | URL GitLab complète du projet (par exemple, `https://gitlab.com/group/project`). Ne pas utiliser avec `project_id`. |
| `project_id`                  | Chaîne  | Non       | ID numérique ou chemin complet du projet (par exemple, `gitlab-org/gitlab`). Ne pas utiliser avec `url`. |
| `goal`                        | Chaîne  | Oui      | Objectif en langage naturel pour la session (par exemple, `Fix the flaky spec in issue #1234 and open a merge request`). Certains flows acceptent une URL à la place, par exemple l'URL du pipeline en échec pour `fix_pipeline/v1`. |
| `flow`                        | Chaîne  | Non       | Référence de flow par défaut (par exemple, `developer/v1`, `fix_pipeline/v1`). Par défaut `developer/v1` lorsqu'aucun flow ni agent n'est fourni. Ne pas utiliser avec `flow_item_id`, `ai_catalog_item_consumer_id` ou `agent`. |
| `flow_item_id`                | Entier | Non       | ID d'élément du catalogue d'IA d'un flow personnalisé activé dans le projet. La dernière version publiée est exécutée. Ne pas utiliser avec `flow`, `ai_catalog_item_consumer_id` ou `agent`. |
| `ai_catalog_item_consumer_id` | Entier | Non       | ID du consommateur d'élément du catalogue d'IA qui configure le flow à exécuter. Utilisez `list_duo_agents_and_flows` pour le trouver. Ne pas utiliser avec `flow`, `flow_item_id` ou `agent`. |
| `agent`                       | Chaîne  | Non       | Référence d'un agent par défaut à exécuter (par exemple, `analytics_agent/v1`). L'agent GitLab Duo par défaut ne peut pas être démarré. Ne pas utiliser avec `flow`, `flow_item_id` ou `ai_catalog_item_consumer_id`. |

Le flow doit être activé pour le projet ou pour un groupe ancêtre du projet. Si le flow n'est pas activé, l'outil renvoie une erreur.

Un flow protégé par un feature flag ne s'exécute que lorsque ce flag est activé. Si un flow ne remplit pas ces conditions, l'outil renvoie une erreur.

Certains flows attendent l'objectif dans un format spécifique, et l'outil le vérifie avant de démarrer la session :

- `fix_pipeline/v1` attend l'URL du pipeline en échec, dans le même projet. La session s'exécute sur la branche du pipeline. Si le pipeline appartient à une merge request ouverte, le flow publie sa suggestion de correction sur cette merge request. Sinon, il ouvre une nouvelle merge request avec la correction. Si l'objectif n'est pas un pipeline du projet, l'outil renvoie une erreur et ne démarre pas de session.
- `code_review/v1` attend l'URL ou l'IID d'une merge request. La session s'exécute sur la branche source de la merge request.

Il s'agit de la même branche et de la même merge request que celles utilisées par le flow lorsque vous le démarrez depuis le pipeline ou la merge request dans l'interface GitLab.

Pour démarrer un flow par défaut, utilisez `flow`. Si vous passez l'ID d'élément du catalogue d'IA d'un flow par défaut à `flow_item_id`, l'outil renvoie une erreur indiquant la valeur `flow` à utiliser à la place. Si vous passez la référence d'un agent par défaut à `flow`, l'outil renvoie une erreur indiquant la valeur `agent` à utiliser à la place.

La réponse inclut `poll_after_seconds` comme indication du temps d'attente avant d'appeler `get_duo_session`.

Exemple :

```plaintext
Fix the flaky spec in issue #1234 and open an MR in gitlab-org/gitlab
```

## `list_duo_sessions` {#list_duo_sessions}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248587) dans GitLab 19.3.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256101) pour accepter le paramètre `statuses` dans GitLab 19.5.

{{< /history >}}

Répertorie vos sessions de GitLab Duo Agent Platform, sauf les sessions Duo Chat. Chaque session comprend son statut individuel, un aperçu de son objectif, la définition de son flow et son horodatage de création. Les sessions de projet et de groupe incluent également une URL de session. L'aperçu de l'objectif peut être tronqué.

| Paramètre      | Type    | Obligatoire | Description |
|----------------|---------|----------|-------------|
| `url`          | Chaîne  | Non       | URL GitLab du projet à utiliser pour filtrer les sessions. Ne pas utiliser avec `project_id`. |
| `project_id`   | Chaîne  | Non       | ID numérique ou chemin complet du projet à utiliser pour filtrer les sessions. Ne pas utiliser avec `url`. |
| `status_group` | Chaîne  | Non       | Groupe de statuts de session. L'un des statuts `active`, `paused`, `awaiting_input`, `completed`, `failed` ou `canceled`. |
| `statuses`     | Tableau   | Non       | Statuts de session. Un ou plusieurs de `created`, `running`, `paused`, `finished`, `failed`, `stopped`, `input_required`, `plan_approval_required` ou `tool_call_approval_required`. Ne pas utiliser avec `status_group`. |
| `after`        | Chaîne  | Non       | Curseur pour la pagination vers l'avant. |
| `first`        | Entier | Non       | Nombre de sessions à renvoyer pour la pagination vers l'avant. La valeur par défaut est 20 et la valeur maximale est 100. |

Le filtre `status_group` peut renvoyer des sessions correspondant à plusieurs statuts individuels. Utilisez `statuses` pour filtrer par un ou plusieurs statuts exacts à la place. Chaque appel renvoie une seule page de résultats. Si d'autres pages existent, la réponse comprend `pageInfo.endCursor`, que vous pouvez transmettre comme valeur du paramètre `after`.

Exemple :

```plaintext
List my active Duo Agent Platform sessions in gitlab-org/gitlab
```

## `get_duo_session` {#get_duo_session}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/607634) dans GitLab 19.4. `get_duo_workflow_status` est également accepté comme alias.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/work_items/627561) pour retourner les merge requests, les éléments de travail et les commentaires créés par la session, varier le délai d'interrogation selon le statut, et signaler `status` avec des underscores (`input_required` plutôt que `input required`) pour correspondre à `list_duo_sessions`, dans GitLab 19.5.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/work_items/631690) pour retourner la raison de l'échec d'une session en échec et un lien vers son job CI, dans GitLab 19.5.

{{< /history >}}

Vérifie le statut d'une session de la plateforme GitLab Duo Agent. Les sessions en cours d'exécution incluent un délai d'interrogation suggéré, qui est plus long pendant que la session attend le démarrage de son job CI. Les sessions terminées et les tours de chat complétés incluent la dernière réponse de l'agent. Toute merge request, tout élément de travail ou commentaire créé par la session est inclus dès qu'il existe, sous les noms `created_merge_requests`, `created_work_items` et `created_notes`. Chacun est un tableau, vide lorsque la session n'a rien créé de ce type, et contient au plus les 20 éléments les plus récents. Lorsqu'une liste est tronquée, `artifacts_truncated` nomme les listes qui ont été coupées et `artifact_limit` indique la limite. Utilisez `get_merge_request` avec `include: ["notes"]` pour parcourir tous les commentaires d'une merge request. Les sessions en attente d'approbation incluent des instructions pour continuer la session avec `send_duo_session_input`.

Les sessions en échec incluent également :

- `failure_reason` : la raison enregistrée pour l'échec, ou `null` si aucune raison n'a été enregistrée.
- `job_url` : le job CI qui a exécuté la session, ou `null` si aucun job CI n'a été exécuté ou si vous ne pouvez pas lire son journal.

Lorsqu'une session a échoué avant le démarrage de son agent, la réponse indique qu'elle n'a apporté aucune modification et peut être relancée. Les sessions de plus de 30 jours n'incluent pas ce message. Les points de contrôle de plus de 30 jours ne sont pas conservés ; l'outil ne peut donc pas déterminer si l'agent a exécuté la session.

| Paramètre     | Type    | Obligatoire | Description |
|---------------|---------|----------|-------------|
| `workflow_id` | Entier | Oui      | ID de la session Duo, tel que retourné par `start_duo_session` ou `list_duo_sessions`. |

Exemple :

```plaintext
Check the status of Duo session 42
```

## `send_duo_session_input` {#send_duo_session_input}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/617171) dans GitLab 19.5.

{{< /history >}}

Répond à une session de la plateforme GitLab Duo Agent en attente d'entrée : approuve ou rejette un plan ou un appel d'outil en attente, ou répond à une question posée par l'agent. Fonctionne pour les sessions démarrées depuis `ai_catalog_item_consumer_id` et pour celles démarrées depuis `agent`. Une session accepte une entrée une fois que son dernier job CI est terminé, qu'elle soit en attente avec le statut `input_required`, `plan_approval_required` ou `tool_call_approval_required`.

La session continue dans un job CI. La réponse inclut un délai d'interrogation suggéré ; utilisez `get_duo_session` avec le même `workflow_id` pour suivre la progression.

| Paramètre        | Type    | Obligatoire | Description |
|------------------|---------|----------|-------------|
| `workflow_id`    | Entier | Oui      | ID de la session Duo, tel que retourné par `list_duo_sessions` ou `get_duo_session`. |
| `human_approval` | Booléen | Oui      | `true` approuve le plan ou l'appel d'outil en attente. N'incluez pas `human_message` avec `true`, ou l'outil rejettera l'appel au lieu de reprendre la session. `false` le rejette : incluez `human_message` afin que l'agent continue avec votre retour. Sans cela, l'agent est informé de ne pas procéder et la session continue. |
| `human_message`  | Chaîne  | Non       | Votre retour pour l'agent, ou votre réponse lorsque la session a posé une question, jusqu'à 2 000 caractères. Fournissez-le avec `human_approval=false`. Avec `human_approval=true`, l'outil rejette l'appel au lieu de reprendre la session. |

Exemples :

```plaintext
Approve the plan for Duo session 42
```

```plaintext
Reject the plan for Duo session 42 and ask it to also add tests
```

## `list_merge_requests` {#list_merge_requests}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246413) dans GitLab 19.3.
- Le paramètre `group_id` et la portée de groupe ont été [ajoutés](https://gitlab.com/gitlab-org/gitlab/-/work_items/606934) dans GitLab 19.4.

{{< /history >}}

Répertorie ou recherche des merge requests dans un projet ou un groupe GitLab, en renvoyant les métadonnées compactes des merge requests. La portée de groupe inclut toujours les merge requests de chaque projet du groupe et de ses sous-groupes, mais exclut les merge requests des projets archivés. Un résultat de groupe inclut également le chemin du projet propriétaire de chaque merge request, à utiliser avec `get_merge_request`.

| Paramètre           | Type    | Obligatoire | Description |
|---------------------|---------|----------|-------------|
| `url`               | Chaîne  | Non       | URL GitLab du projet ou du groupe. Renseignez un seul des trois paramètres `url`, `project_id` et `group_id`. |
| `project_id`        | Chaîne  | Non       | ID ou chemin complet du projet. Renseignez un seul des trois paramètres `url`, `project_id` et `group_id`. |
| `group_id`          | Chaîne  | Non       | ID ou chemin complet du groupe. Renseignez un seul des trois paramètres `url`, `project_id` et `group_id`. |
| `author_username`   | Chaîne  | Non       | Filtrer selon le nom d'utilisateur de l'auteur de la merge request. |
| `assignee_username` | Chaîne  | Non       | Filtrer selon le nom d'utilisateur d'un assigné. |
| `reviewer_username` | Chaîne  | Non       | Filtrer selon le nom d'utilisateur d'un relecteur. |
| `state`             | Chaîne  | Non       | Filtrer selon le statut. L'une des valeurs `opened`, `closed`, `merged`, `locked` ou `all`. Omettez ce paramètre pour inclure tous les statuts. |
| `scope`             | Chaîne  | Non       | Filtrer en fonction de l'utilisateur authentifié. L'une des valeurs `created_by_me`, `assigned_to_me` ou `review_requested`. Un nom d'utilisateur renseigné explicitement prévaut pour le champ concerné. |
| `milestone`         | Chaîne  | Non       | Filtrer selon le titre du jalon. |
| `labels`            | Chaîne  | Non       | Liste de noms de labels séparés par des virgules. Seules les merge requests qui comportent tous ces labels sont renvoyées. |
| `search`            | Chaîne  | Non       | Requête de recherche comparée au titre et à la description de la merge request. |
| `after`             | Chaîne  | Non       | Curseur pour la pagination vers l'avant. |
| `first`             | Entier | Non       | Nombre de merge requests à renvoyer pour la pagination vers l'avant. La valeur par défaut est 20 et la valeur maximale est 100. |

Pour récupérer une seule merge request avec tous ses détails, utilisez `get_merge_request`. Pour obtenir ses commits, utilisez `get_merge_request` avec `include: ["commits"]`. Pour les diffs ou les notes, utilisez `include: ["diffs"]` ou `include: ["notes"]`. Pour obtenir le texte du patch, définissez également `detail` sur `full_patch`. Pour lancer une recherche en texte intégral dans différents types de ressources, utilisez `search`.

Exemple :

```plaintext
List my open merge requests in gitlab-org/gitlab
```

## `get_merge_request_commits` {#get_merge_request_commits}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203055) dans GitLab 18.4.
- [Non listé](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712) dans GitLab 19.5. Remplacé par [`get_merge_request`](#get_merge_request) avec `include: ["commits"]`.

{{< /history >}}

Remplacé par [`get_merge_request`](#get_merge_request) avec `include: ["commits"]`. Cet outil n'apparaît plus dans `tools/list` mais reste appelable pendant la migration des appelants.

Récupère la liste des commits d'une merge request précise dans GitLab.

| Paramètre           | Type    | Obligatoire | Description |
|---------------------|---------|----------|-------------|
| `id`                | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `merge_request_iid` | Entier | Oui      | ID interne de la merge request. |
| `per_page`          | Entier | Non       | Nombre de commits par page. |
| `page`              | Entier | Non       | Numéro de page actuel. |

Exemple :

```plaintext
Show me all commits in merge request 42 from project 123
```

## `get_merge_request_diffs` {#get_merge_request_diffs}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203055) dans GitLab 18.4.
- [Non listé](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712) dans GitLab 19.5. Remplacé par [`get_merge_request`](#get_merge_request) avec `include: ["diffs"]`.

{{< /history >}}

Remplacé par [`get_merge_request`](#get_merge_request) avec `include: ["diffs"]`. Pour le texte brut du patch, passez également `detail: full_patch`. Cet outil n'apparaît plus dans `tools/list` mais reste appelable pendant la migration des appelants.

Récupère les diffs d'une merge request précise dans GitLab.

| Paramètre           | Type    | Obligatoire | Description |
|---------------------|---------|----------|-------------|
| `id`                | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `merge_request_iid` | Entier | Oui      | ID interne de la merge request. |
| `per_page`          | Entier | Non       | Nombre de diffs par page. |
| `page`              | Entier | Non       | Numéro de page actuel. |

Exemple :

```plaintext
What files were changed in merge request 25 in the gitlab project?
```

## `get_merge_request_pipelines` {#get_merge_request_pipelines}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203055) dans GitLab 18.4.
- [Non listé](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712) dans GitLab 19.5. Remplacé par [`get_merge_request`](#get_merge_request) avec `include: ["pipelines"]`.

{{< /history >}}

Remplacé par [`get_merge_request`](#get_merge_request) avec `include: ["pipelines"]`. Cet outil n'apparaît plus dans `tools/list` mais reste appelable pendant la migration des appelants.

Récupère les pipelines d'une merge request précise dans GitLab.

| Paramètre           | Type    | Obligatoire | Description |
|---------------------|---------|----------|-------------|
| `id`                | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `merge_request_iid` | Entier | Oui      | ID interne de la merge request. |

Exemple :

```plaintext
Show me all pipelines for merge request 42 in project gitlab-org/gitlab
```

## `get_merge_request_conflicts` {#get_merge_request_conflicts}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/221941) dans GitLab 18.10.
- [Non listé](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712) dans GitLab 19.5. Remplacé par [`get_merge_request`](#get_merge_request) avec `include: ["conflicts"]`.

{{< /history >}}

Remplacé par [`get_merge_request`](#get_merge_request) avec `include: ["conflicts"]`, qui retourne les mêmes conflits sous forme d'entrées `conflictFiles` structurées avec des champs `ourPath` et `theirPath` séparés, au lieu du texte brut ci-dessous. Cet outil n'apparaît plus dans `tools/list` mais reste appelable pendant la migration des appelants.

Récupère le contenu des conflits de fusion pour une merge request qui ne peut pas être fusionnée. Retourne les marqueurs de conflit Git bruts (`<<<<<<<`, `=======` et `>>>>>>>`) tels qu'ils apparaissent dans les fichiers en conflit. Le contenu de chaque fichier est regroupé sous un en-tête `# File:`. Pour les fichiers renommés, l'en-tête affiche le chemin dans chaque branche.

| Paramètre           | Type    | Obligatoire | Description |
|---------------------|---------|----------|-------------|
| `project_id`        | Chaîne  | Oui      | ID ou chemin complet du projet (par exemple, `gitlab-org/gitlab`). |
| `merge_request_iid` | Entier | Oui      | ID interne de la merge request. |

Vous devez avoir la permission de pousser vers la branche source de la merge request. L'outil renvoie une erreur lorsque la merge request n'a pas de conflits, lorsque sa fusionnabilité n'a pas encore été vérifiée, ou lorsqu'une branche ou une référence de diff est manquante.

Exemple :

```plaintext
Show the conflicts for merge request 42 in project gitlab-org/gitlab
```

## `save_note` {#save_note}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241114) dans GitLab 19.2.
- [Remplacé](https://gitlab.com/gitlab-org/gitlab/-/work_items/605848) les outils `create_merge_request_note` et `create_workitem_note` dans GitLab 19.4. Les deux noms d'outils d'origine continuent de fonctionner en tant qu'alias.

{{< /history >}}

Ajoute un commentaire à une merge request ou un élément de travail GitLab, ou répond à un fil de discussion existant, en tant qu'utilisateur authentifié.

| Paramètre           | Type    | Obligatoire | Description |
|---------------------|---------|----------|-------------|
| `url`               | Chaîne  | Non       | URL de la merge request ou de l'élément de travail. L'URL détermine le type de cible. |
| `project_id`        | Chaîne  | Non       | ID ou chemin du projet. Obligatoire avec `merge_request_iid`, et avec `work_item_iid` pour les éléments de travail au niveau du projet. |
| `group_id`          | Chaîne  | Non       | ID ou chemin du groupe. Obligatoire avec `work_item_iid` pour les éléments de travail au niveau du groupe. |
| `merge_request_iid` | Entier | Non       | ID interne de la merge request. À fournir avec `project_id`. Mutuellement exclusif avec `work_item_iid`. |
| `work_item_iid`     | Entier | Non       | ID interne de l'élément de travail. À fournir avec `project_id` ou `group_id`. Mutuellement exclusif avec `merge_request_iid`. |
| `body`              | Chaîne  | Oui      | Contenu de la note. Les lignes ne peuvent pas commencer par `/` pour éviter de déclencher des actions rapides (par exemple, `/merge`). |
| `internal`          | Booléen | Non       | Marque la note comme interne (visible uniquement par les membres ayant au moins le rôle Reporter). La valeur par défaut est `false`. |
| `discussion_id`     | Chaîne  | Non       | ID global de la discussion à laquelle répondre (au format `gid://gitlab/Discussion/<id>`). Une nouvelle note de premier niveau est créée en l'absence de cet ID. |

Exemples :

- Commenter sur une merge request :

  ```plaintext
  Reply "Thanks, fixed in the latest push" to merge request 42 in project gitlab-org/gitlab
  ```

- Commenter sur un élément de travail :

  ```plaintext
  Add a comment "This looks good to me" to work item 42 in project gitlab-org/gitlab
  ```

## `get_merge_request_notes` {#get_merge_request_notes}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/597494) dans GitLab 19.2.
- [Non listé](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712) dans GitLab 19.5. Remplacé par la facette `notes` de [`get_merge_request`](#get_merge_request).

{{< /history >}}

Remplacé par [`get_merge_request`](#get_merge_request) avec `include: ["notes"]`. Cet outil n'apparaît plus dans `tools/list` mais reste appelable pendant la migration des appelants.

Récupère les notes (commentaires et notes système) d'une merge request précise dans GitLab.

| Paramètre           | Type    | Obligatoire | Description                                                                                    |
|---------------------|---------|----------|--------------------------------------------------------------------------------------------------|
| `url`               | Chaîne  | Non       | URL de la merge request GitLab. Obligatoire si `project_id` et `merge_request_iid` ne sont pas renseignés.   |
| `project_id`        | Chaîne  | Non       | ID ou chemin complet du projet. Obligatoire si `url` n'est pas renseigné.                                  |
| `merge_request_iid` | Entier | Non       | ID interne de la merge request. Obligatoire si `url` n'est pas renseigné.                                |
| `after`             | Chaîne  | Non       | Curseur pour la pagination vers l'avant.                                                                 |
| `before`            | Chaîne  | Non       | Curseur pour la pagination vers l'arrière.                                                                |
| `first`             | Entier | Non       | Nombre de notes à renvoyer pour la pagination vers l'avant.                                              |
| `last`              | Entier | Non       | Nombre de notes à renvoyer pour la pagination vers l'arrière.                                             |

Chaque note renvoyée contient l'ID de sa discussion ; les notes associées peuvent ainsi être regroupées en fils de discussion.

Exemple :

```plaintext
Show me all comments on merge request 5 in project gitlab-org/gitlab
```

## `save_merge_request_review` {#save_merge_request_review}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605881) dans GitLab 19.4.

{{< /history >}}

Écrit des artefacts de revue de merge request sous l'identité de l'utilisateur authentifié. Chaque appel exécute exactement une opération sélectionnée au moyen du paramètre `method` :

| Méthode               | Action |
|----------------------|--------|
| `create_note`        | Ajoute un commentaire de premier niveau. |
| `reply_discussion`   | Répond à une discussion existante. |
| `create_diff_note`   | Commente une ligne précise d'un diff. |
| `resolve_discussion` | Résout ou annule la résolution d'une discussion. |
| `submit_review`      | Publie plusieurs commentaires de diff et un résumé facultatif en un seul appel. |
| `post_duo_review`    | Demande à GitLab Duo d'examiner la merge request. Nécessite GitLab Duo Code Review. |
| `approve`            | Approuve la merge request. Les appels déjà approuvés réussissent avec le statut `already_approved`. |
| `unapprove`          | Retire votre approbation. Les appels sans approbation préalable réussissent avec le statut `not_approved`. |

Les réponses de `post_duo_review`, `approve` et `unapprove` incluent le `diff_head_sha` actuel de la merge request, afin que vous puissiez vérifier si une approbation ou une revue en cours couvre toujours les derniers commits.

| Paramètre           | Type    | Obligatoire | Description |
|---------------------|---------|----------|-------------|
| `url`               | Chaîne  | Non       | URL de la merge request GitLab. Obligatoire si `project_id` et `merge_request_iid` ne sont pas renseignés. |
| `project_id`        | Chaîne  | Non       | ID ou chemin du projet. Obligatoire si `url` n'est pas renseigné. |
| `merge_request_iid` | Entier | Non       | ID interne de la merge request. Obligatoire si `url` n'est pas renseigné. |
| `method`            | Chaîne  | Oui      | Opération à effectuer. Les paramètres qui relèvent d'une autre méthode sont rejetés. |
| `body`              | Chaîne  | Non       | Texte de la note. Obligatoire pour `create_note`, `reply_discussion` et `create_diff_note`. Les lignes ne peuvent pas commencer par `/` pour éviter de déclencher des actions rapides (par exemple, `/merge`). |
| `discussion_id`     | Chaîne  | Non       | Discussion à laquelle appliquer l'opération. Obligatoire pour `reply_discussion` et `resolve_discussion`. Accepte un ID global ou un ID de discussion brut. |
| `internal`          | Booléen | Non       | Pour `create_note`, marque la note comme interne. |
| `resolved`          | Booléen | Non       | Pour `resolve_discussion`, `true` résout la discussion et `false` annule sa résolution. Obligatoire pour cette méthode. |
| `old_path`          | Chaîne  | Non       | Pour `create_diff_note`, le chemin du fichier avant la modification. Renseignez `old_path` ou `new_path`, ou les deux. |
| `new_path`          | Chaîne  | Non       | Pour `create_diff_note`, le chemin du fichier après la modification. |
| `old_line`          | Entier | Non       | Pour `create_diff_note`, le numéro de ligne dans l'ancienne version. Renseignez `old_line` ou `new_line`, ou les deux. |
| `new_line`          | Entier | Non       | Pour `create_diff_note`, le numéro de ligne dans la nouvelle version. |
| `comments`          | Tableau   | Non       | Pour `submit_review`, 1 à 20 commentaires de diff. Chaque entrée contient `file` et `body` (obligatoires), ainsi que `old_line`, `new_line` et `suggestion` (facultatifs). Obligatoire pour cette méthode. `file` est le chemin après modification ; pour les fichiers renommés, utilisez `create_diff_note` à la place. |
| `verdict`           | Chaîne  | Non       | Pour `submit_review`, un verdict global placé au début de la note récapitulative. |
| `summary`           | Chaîne  | Non       | Pour `submit_review`, une note récapitulative publiée après les commentaires de diff. |
| `summary_internal`  | Booléen | Non       | Pour `submit_review`, marque la note récapitulative comme interne. |
| `sha`               | Chaîne  | Non       | Pour `approve`, garde-fou du SHA HEAD. Lorsqu'il ne correspond plus au HEAD de la merge request, l'approbation est refusée. Passez le `diff_head_sha` complet de 40 caractères retourné par `get_merge_request`. |

Exemple :

```plaintext
Review merge request 42 in project gitlab-org/gitlab and leave your findings as diff comments with a summary
```

## `list_project_members` {#list_project_members}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251379) dans GitLab 19.4.

{{< /history >}}

Répertorie les membres d'un projet GitLab avec leur rôle et leur niveau d'accès.

| Paramètre           | Type    | Obligatoire | Description |
|---------------------|---------|----------|-------------|
| `project_id`        | Chaîne  | Oui      | Chemin complet ou ID numérique du projet (par exemple, `gitlab-org/gitlab` ou `278964`). |
| `include_inherited` | Booléen | Non       | Retourne également les membres qui héritent de leur rôle d'un groupe parent ou d'un sous-groupe du projet. Par défaut : `false`. |
| `query`             | Chaîne  | Non       | Retourne uniquement les membres dont le nom ou le nom d'utilisateur contient ce texte. |
| `first`             | Entier | Non       | Nombre de membres à retourner pour la pagination avant (par défaut 20, maximum 100). |
| `after`             | Chaîne  | Non       | Curseur pour la pagination vers l'avant. |

Pour chaque membre, la réponse retourne l'ID utilisateur, le nom d'utilisateur, le nom, le `access_level` numérique, le `access_level_name` correspondant (par exemple, `Maintainer`) et la date `expires_at` de l'appartenance. Les membres invités par e-mail mais n'ayant pas encore accepté leur invitation ne sont pas retournés.

Chaque appel renvoie une seule page de résultats. S'il existe davantage de pages, les `metadata` de la réponse incluent un `end_cursor` que vous pouvez passer en tant que `after` pour récupérer la page suivante.

Exemple :

```plaintext
Who are the maintainers of gitlab-org/gitlab?
```

## `get_user` {#get_user}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253176) dans GitLab 19.4.

{{< /history >}}

Obtient un seul utilisateur GitLab. Utilisez cet outil pour résoudre un nom d'utilisateur, ou votre propre compte, en un ID utilisateur numérique. Par exemple, utilisez-le avant de définir des assignés ou des relecteurs avec d'autres outils.

Renseignez un seul des trois paramètres `username`, `id` et `me`.

| Paramètre  | Type    | Obligatoire | Description |
|------------|---------|----------|-------------|
| `username` | Chaîne  | Non       | Nom d'utilisateur de l'utilisateur à rechercher. |
| `id`       | Entier | Non       | ID numérique de l'utilisateur à rechercher. |
| `me`       | Booléen | Non       | Définissez sur `true` pour rechercher l'utilisateur authentifié. Omettez `username` et `id` lorsque ce paramètre est défini. Définissez sur `false` pour ne pas utiliser ce paramètre. |

La réponse retourne le `id` numérique, le `username`, le `name`, le `state` et le `web_url` de l'utilisateur.

Exemple :

```plaintext
What is my GitLab user ID?
```

## `accept_merge_request` {#accept_merge_request}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/617968) dans GitLab 19.4.

{{< /history >}}

Fusionne une merge request ou la planifie pour une fusion automatique. Sans `strategy`, la fusion démarre immédiatement et se termine de manière asynchrone. Avec `strategy`, la fusion automatique est armée et la merge request fusionne une fois ses vérifications réussies. Pour approuver une merge request à la place, utilisez l'outil `save_merge_request_review`.

Les appels sur une merge request déjà fusionnée réussissent avec le statut `already_merged`, et les appels avec une `strategy` sur une merge request déjà planifiée réussissent avec le statut `already_scheduled`.

| Paramètre                     | Type    | Obligatoire | Description |
|-------------------------------|---------|----------|-------------|
| `url`                         | Chaîne  | Non       | URL GitLab de la merge request. Renseignez ce paramètre ou les paramètres `project_id` et `merge_request_iid`. |
| `project_id`                  | Chaîne  | Non       | ID ou chemin du projet. Obligatoire si `url` n'est pas renseigné. |
| `merge_request_iid`           | Entier | Non       | ID interne de la merge request. Obligatoire si `url` n'est pas renseigné. |
| `sha`                         | Chaîne  | Oui      | Garde-fou du SHA HEAD. Lorsqu'il ne correspond plus au HEAD de la merge request, la fusion est refusée. Passez le `diff_head_sha` retourné par `get_merge_request`. |
| `strategy`                    | Chaîne  | Non       | Stratégie de fusion automatique, par exemple `merge_when_checks_pass`. Lorsqu'elle est fournie, arme la fusion automatique au lieu de fusionner immédiatement. |
| `squash`                      | Booléen | Non       | Écraser les commits en un seul commit lors de la fusion. |
| `commit_message`              | Chaîne  | Non       | Message de commit de fusion personnalisé. |
| `squash_commit_message`       | Chaîne  | Non       | Message de commit d'écrasement personnalisé. S'applique lorsque `squash` est `true`. |
| `should_remove_source_branch` | Booléen | Non       | Supprimer la branche source après la fusion. |

Exemple :

```plaintext
Merge merge request 42 in project gitlab-org/gitlab once its checks pass, and remove the source branch
```

## `add_branch` {#add_branch}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605877) dans GitLab 19.3. `create_branch` est également accepté comme alias.

{{< /history >}}

Ajoute une branche à un projet GitLab à partir d'une référence source.

| Paramètre    | Type   | Obligatoire | Description |
|--------------|--------|----------|-------------|
| `url`        | Chaîne | Non       | URL GitLab du projet. Renseignez soit cette valeur, soit `project_id`. |
| `project_id` | Chaîne | Non       | ID ou chemin du projet. Obligatoire si `url` n'est pas renseigné. |
| `branch`     | Chaîne | Oui      | Nom de la nouvelle branche. |
| `ref`        | Chaîne | Oui      | Nom de branche ou SHA de commit à partir duquel créer la nouvelle branche. |

Exemple :

```plaintext
Create a branch named feature/x from main in project gitlab-org/gitlab
```

## `fork_repository` {#fork_repository}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/597680) dans GitLab 19.4.

{{< /history >}}

Duplique un projet GitLab dans un espace de nommage.

La duplication est créée de manière asynchrone. La réponse contient les attributs du nouveau projet, notamment un champ `import_status`, tel que `scheduled`, qui indique la progression de la duplication.

L'appel échoue pour les raisons suivantes en fonction des statuts :

- Statut `409` lorsque l'espace de nommage possède déjà une duplication du projet.
- Statut `404` lorsque le projet ou l'espace de nommage n'existe pas, ou lorsque vous n'avez pas la permission de dupliquer le projet.

| Paramètre        | Type    | Obligatoire | Description |
|------------------|---------|----------|-------------|
| `id`             | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `namespace_id`   | Entier | Non       | ID de l'espace de nommage dans lequel dupliquer le projet. |
| `namespace_path` | Chaîne  | Non       | Chemin de l'espace de nommage dans lequel dupliquer le projet. |
| `name`           | Chaîne  | Non       | Nom à attribuer à la duplication. |
| `path`           | Chaîne  | Non       | Chemin à attribuer à la duplication. |
| `description`    | Chaîne  | Non       | Description à attribuer à la duplication. |
| `visibility`     | Chaîne  | Non       | Visibilité de la duplication. |

Exemple :

```plaintext
Fork gitlab-org/gitlab-test into my personal namespace
```

## `list_branches` {#list_branches}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605849) dans GitLab 19.4.

{{< /history >}}

Répertorie les branches d'un projet GitLab, éventuellement filtrées par nom.

| Paramètre  | Type    | Obligatoire | Description |
|------------|---------|----------|-------------|
| `id`       | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `search`   | Chaîne  | Non       | Filtre les branches par nom. |
| `page`     | Entier | Non       | Numéro de page actuel. La valeur par défaut est `1`. |
| `per_page` | Entier | Non       | Nombre d'éléments par page. La valeur par défaut est `20`. |

Exemple :

```plaintext
List branches in gitlab-org/gitlab whose names contain "release"
```

## `get_repository_file` {#get_repository_file}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248744) dans GitLab 19.3.

{{< /history >}}

Récupère le contenu d'un seul fichier d'un dépôt pour une référence donnée.

Le contenu provient du dépôt, et non de votre système de fichiers local. Le fichier est renvoyé dans l'état du commit désigné par `ref` ; les modifications non validées d'une copie de travail locale ne sont donc pas incluses.

| Paramètre    | Type    | Obligatoire | Description |
|--------------|---------|----------|-------------|
| `url`        | Chaîne  | Non       | URL du fichier, par exemple `https://gitlab.example.com/my-group/my-project/-/blob/main/app/models/user.rb`. Renseignez soit cette valeur, soit `project_id`, `file_path` et `ref`. |
| `project_id` | Chaîne  | Non       | ID ou chemin complet du projet. Obligatoire si `url` n'est pas renseigné. Si `url` est également fourni, les deux doivent faire référence au même projet. |
| `file_path`  | Chaîne  | Non       | Chemin du fichier relatif à la racine du dépôt. Obligatoire si `url` n'est pas renseigné. |
| `ref`        | Chaîne  | Non       | Nom de branche, nom de tag ou SHA de commit. Utilisez `HEAD` pour désigner la branche par défaut. Obligatoire si `url` n'est pas renseigné. |
| `offset`     | Entier | Non       | Ligne indexée à partir de zéro où commencer la lecture. La valeur par défaut est `0`. |
| `limit`      | Entier | Non       | Nombre maximum de lignes à renvoyer. La valeur par défaut et la valeur maximale sont `2000`. |

La réponse contient un objet `metadata` dans lequel figurent `total_lines`, `returned_lines`, `truncated` et `size_bytes`. Lorsque la réponse ne couvre qu'une partie du fichier, `system_instruction` indique le `offset` à utiliser lors du prochain appel.

Cet outil renvoie du texte uniquement. Les fichiers binaires et les fichiers stockés dans Git LFS renvoient une erreur. Les fichiers qu'un projet exclut du contexte GitLab Duo renvoient également une erreur.

Exemple :

```plaintext
Show me app/models/user.rb from the main branch of my-group/my-project
```

## `list_repository_tree` {#list_repository_tree}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605873) dans GitLab 19.4.

{{< /history >}}

Répertorie les fichiers et répertoires d'un dépôt GitLab à un chemin et une référence donnés. Retourne uniquement les métadonnées des entrées, jamais le contenu des fichiers. Pour lire le contenu d'un fichier, utilisez [`get_repository_file`](#get_repository_file).

| Paramètre    | Type    | Obligatoire | Description |
|--------------|---------|----------|-------------|
| `url`        | Chaîne  | Non       | URL GitLab du projet. Renseignez un seul des deux paramètres `url` et `project_id`. |
| `project_id` | Chaîne  | Non       | ID ou chemin complet du projet. Renseignez un seul des deux paramètres `url` et `project_id`. |
| `path`       | Chaîne  | Non       | Chemin du répertoire à lister, relatif à la racine du dépôt. Par défaut, la racine. |
| `ref`        | Chaîne  | Non       | Nom de branche, nom de tag ou SHA de commit. Par défaut, la branche par défaut. |
| `recursive`  | Booléen | Non       | Répertorie les entrées de tous les sous-répertoires de manière récursive. La valeur par défaut est `false`. |
| `after`      | Chaîne  | Non       | Curseur pour la pagination vers l'avant. Utilisez `endCursor` de la réponse précédente. |

Chaque appel retourne jusqu'à 100 entrées. Lorsque `pageInfo.hasNextPage` est `true`, passez `pageInfo.endCursor` en tant que `after` pour récupérer la page suivante.

Exemple :

```plaintext
List the files under app/services in gitlab-org/gitlab on the default branch
```

## `get_commit` {#get_commit}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/605874) dans GitLab 19.3.

{{< /history >}}

Récupère les métadonnées d'un seul commit, seules ou avec son diff ou ses notes.

| Paramètre     | Type    | Obligatoire | Description |
|---------------|---------|----------|-------------|
| `url`         | Chaîne  | Non       | URL du commit GitLab. Obligatoire si `project_id` et `commit_sha` ne sont pas renseignés. |
| `project_id`  | Chaîne  | Non       | ID ou chemin complet du projet. Obligatoire si `url` n'est pas renseigné. |
| `commit_sha`  | Chaîne  | Non       | Commit à rechercher. Accepte un SHA complet ou abrégé, un nom de branche ou un nom de tag. Obligatoire si `url` n'est pas renseigné. |
| `include`     | Tableau   | Non       | Facette associée à récupérer dans la même réponse, à raison d'une par appel (`diff` ou `notes`) Les métadonnées de base sont toujours renvoyées. |
| `diff_detail` | Chaîne  | Non       | Niveau de détail dans le diff du commit. S'applique uniquement lorsque `include` contient `diff`. Peut être soit `stats` soit `full_patch`. La valeur par défaut est `stats`. |
| `notes_after` | Chaîne  | Non       | Jeton pour récupérer la page suivante de notes. S'applique uniquement lorsque `include` contient `notes`. |
| `notes_first` | Entier | Non       | Nombre de notes à renvoyer par page (maximum 100). S'applique uniquement lorsque `include` contient `notes`. |

Lorsque `diff_detail` a la valeur `stats`, la facette diff renvoie le décompte des lignes pour chaque fichier et pour l'ensemble du diff. Avec `full_patch`, elle renvoie le texte du patch.

Exemple :

```plaintext
Show me commit abc123 in gitlab-org/gitlab with its diff stats
```

## `list_commits` {#list_commits}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605875) dans GitLab 19.4.

{{< /history >}}

Répertorie les commits d'un projet GitLab, éventuellement filtrés par référence, auteur, chemin ou date. Retourne les métadonnées compactes des commits. Pour obtenir le diff ou les notes d'un seul commit, utilisez [`get_commit`](#get_commit).

| Paramètre      | Type    | Obligatoire | Description |
|----------------|---------|----------|-------------|
| `url`          | Chaîne  | Non       | URL GitLab du projet. Renseignez un seul des deux paramètres `url` et `project_id`. |
| `project_id`   | Chaîne  | Non       | ID ou chemin complet du projet. Renseignez un seul des deux paramètres `url` et `project_id`. |
| `ref_name`     | Chaîne  | Non       | Branche ou tag à partir duquel lister les commits. Par défaut, la branche par défaut. |
| `author`       | Chaîne  | Non       | Filtre par nom ou e-mail de l'auteur du commit. |
| `path`         | Chaîne  | Non       | Retourne uniquement les commits qui touchent ce chemin de fichier. |
| `since`        | Chaîne  | Non       | Retourne uniquement les commits dont la date de commit est postérieure à cette date ou heure ISO 8601. |
| `until`        | Chaîne  | Non       | Retourne uniquement les commits dont la date de commit est antérieure à cette date ou heure ISO 8601. |
| `order`        | Chaîne  | Non       | Stratégie de tri. Peut être `topo` ou `date`. Par défaut, ordre chronologique inverse. |
| `first_parent` | Booléen | Non       | Ne suit que le premier parent des commits de fusion. |
| `with_stats`   | Booléen | Non       | Inclut les statistiques de nombre de lignes par commit (ajouts, suppressions et fichiers modifiés). |
| `after`        | Chaîne  | Non       | Curseur pour la pagination vers l'avant. Utilisez `endCursor` de la réponse précédente. |
| `first`        | Entier | Non       | Nombre de commits à retourner. La valeur par défaut est `20` et la valeur maximale est `100`. |

Chaque commit nécessite un appel Gitaly lorsque `with_stats` est `true`, donc `first` est par défaut `10` et ne doit pas dépasser `10` lorsque `with_stats` est défini.

Exemple :

```plaintext
List commits to app/models in gitlab-org/gitlab since 2026-08-01 by Alex
```

## `list_releases` {#list_releases}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/618494) dans GitLab 19.4.

{{< /history >}}

Répertorie les releases d'un projet GitLab, les plus récentes en premier.

| Paramètre    | Type    | Obligatoire | Description |
|--------------|---------|----------|-------------|
| `url`        | Chaîne  | Non       | URL GitLab du projet. Obligatoire si `project_id` n'est pas renseigné. |
| `project_id` | Chaîne  | Non       | ID ou chemin complet du projet. Obligatoire si `url` n'est pas renseigné. |
| `page`       | Entier | Non       | Numéro de page à récupérer. La valeur par défaut est `1`. |
| `per_page`   | Entier | Non       | Releases à retourner par page. La valeur par défaut est `20` et la valeur maximale est `100`. |
| `state`      | Chaîne  | Non       | Filtrer par état de release : `released`, `upcoming` ou `all`. La valeur par défaut est `released`. |

Renseignez un seul des deux paramètres `url` et `project_id`.

Chaque entrée retourne uniquement les métadonnées de la release : `tag_name`, `name`, `released_at`, `upcoming` et `assets`. `assets` contient un `count` des liens d'assets de la release et jusqu'à cinq de ces `links`. Lorsqu'une release a plus de cinq, `count` indique le total réel. Les archives sources sont exclues, car elles sont dérivables à partir du tag.

La réponse contient également un objet `metadata` avec `page`, `per_page` et `has_more`. Utilisez `has_more` pour décider s'il faut demander la page suivante.

Les notes de release ne sont intentionnellement pas retournées dans cette réponse.

Une release avec un `released_at` futur est planifiée plutôt que publiée, et apparaît avant les releases publiées. Utilisez `state` pour contrôler ce que vous obtenez. Les releases planifiées portent `upcoming` défini sur `true`.

Pour lire le commit sur lequel est basée une release, passez son `tag_name` à l'outil `get_commit`. Pour télécharger un asset, utilisez l'`url` depuis `assets.links`.

Exemple :

```plaintext
List the most recent releases for project gitlab-org/gitlab
```

## `list_tags` {#list_tags}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/618493) dans GitLab 19.4.

{{< /history >}}

Répertorie les tags d'un projet GitLab, les plus récemment mis à jour en premier. Si `search` correspond exactement à un nom de tag, GitLab liste ce tag en premier.

| Paramètre    | Type    | Obligatoire | Description |
|--------------|---------|----------|-------------|
| `url`        | Chaîne  | Non       | URL GitLab du projet. Obligatoire si `project_id` n'est pas renseigné. |
| `project_id` | Chaîne  | Non       | ID ou chemin complet du projet. Obligatoire si `url` n'est pas renseigné. |
| `search`     | Chaîne  | Non       | Filtre les tags par nom. Prend en charge `^` pour ancrer le début, `$` pour ancrer la fin et `*` comme caractère générique. |
| `first`      | Entier | Non       | Nombre de tags à retourner. La valeur par défaut est `20` et la valeur maximale est `100`. |
| `after`      | Chaîne  | Non       | Curseur pour la pagination vers l'avant. Utilisez `metadata.end_cursor` de la réponse précédente. |

Renseignez un seul des deux paramètres `url` et `project_id`.

Chaque entrée retourne `name` et `commit`, où `commit` contient le `sha` et le `title` du commit de pointe du tag. `commit` est `null` pour un tag qui pointe vers autre chose qu'un commit.

Les messages de tag ne sont intentionnellement pas retournés dans cette réponse.

La réponse contient également un objet `metadata` avec `has_next_page` et `end_cursor`. Lorsque `has_next_page` est `true`, passez `end_cursor` en tant que `after` pour récupérer la page suivante.

Pour lire le commit complet vers lequel pointe un tag, utilisez l'outil `get_commit`.

Exemple :

```plaintext
List the most recent tags for the gitlab-org/gitlab project
```

## `get_pipeline` {#get_pipeline}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605853) dans GitLab 19.3.
- La facette `artifacts` a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/585022) dans GitLab 19.5.

{{< /history >}}

Récupère un pipeline et, éventuellement, ses jobs, pipelines downstream, jobs bridge (déclencheurs) ou les artefacts produits par ses jobs.

| Paramètre     | Type    | Obligatoire | Description |
|---------------|---------|----------|-------------|
| `id`          | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `pipeline_id` | Entier | Oui      | ID du pipeline. |
| `include`     | Tableau   | Non       | Facette à inclure avec le pipeline, une par appel : `jobs`, `downstream_pipelines`, `bridge_jobs` ou `artifacts`. |
| `job_status`  | Chaîne  | Non       | Filtre la facette `jobs` par statut (par exemple, `failed`). S'applique uniquement lorsque `include` est `jobs`. |
| `first`       | Entier | Non       | Nombre d'éléments à renvoyer pour la facette `include` sélectionnée. Pour la facette `artifacts`, il s'agit du nombre de jobs dont les artefacts sont retournés. La valeur par défaut est `20` et la valeur maximale est `100`. |
| `after`       | Chaîne  | Non       | Curseur de pagination vers l'avant pour la facette `include` sélectionnée. Utilisez `page_info.end_cursor` d'une réponse précédente. |

Le `downstream_pipeline` d'un job bridge est omis (`null`) à la fois lorsque le job déclencheur n'a pas encore déclenché de pipeline downstream et lorsque vous n'avez pas accès à ce pipeline.

Chaque pipeline downstream inclut un `project_full_path`, car un pipeline downstream peut appartenir à un autre projet. Utilisez cette valeur comme `id` lors d'un appel ultérieur.

La facette `artifacts` retourne une liste plate d'artefacts. Chaque artefact contient son `name`, sa `size`, son `file_type`, les informations d'expiration ainsi que le `job_id` et le `job_name` du job qui l'a produit. La pagination parcourt les jobs du pipeline, et non les artefacts.

Exemples :

- Obtenir un pipeline :

  ```plaintext
  Get the status of pipeline 12345 in project gitlab-org/gitlab
  ```

- Obtenir les jobs en échec d'un pipeline :

  ```plaintext
  Show me the failed jobs in pipeline 12345 for project gitlab-org/gitlab
  ```

- Obtenir les pipelines downstream d'un pipeline :

  ```plaintext
  Show me the downstream pipelines triggered by pipeline 12345 in project gitlab-org/gitlab
  ```

- Obtenir les artefacts produits par un pipeline :

  ```plaintext
  List the artifacts of pipeline 12345 in project gitlab-org/gitlab
  ```

## `get_pipeline_jobs` {#get_pipeline_jobs}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203055) dans GitLab 18.4.
- [Non listé](https://gitlab.com/gitlab-org/gitlab/-/work_items/622712) dans GitLab 19.5. Remplacé par [`get_pipeline`](#get_pipeline) avec `include: ["jobs"]`.

{{< /history >}}

Remplacé par [`get_pipeline`](#get_pipeline) avec `include: ["jobs"]`, qui retourne les jobs avec le reste des données du pipeline en un seul appel. La facette `jobs` retourne moins de champs par job : elle n'inclut pas `failure_reason`, `duration`, `queued_duration` ni les horodatages. Cet outil n'apparaît plus dans `tools/list` mais reste appelable pendant la migration des appelants.

Récupère les jobs d'un pipeline précis de GitLab CI/CD.

| Paramètre     | Type    | Obligatoire | Description |
|---------------|---------|----------|-------------|
| `id`          | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `pipeline_id` | Entier | Oui      | ID du pipeline. |
| `per_page`    | Entier | Non       | Nombre de jobs par page. |
| `page`        | Entier | Non       | Numéro de page actuel. |

Exemple :

```plaintext
Show me all jobs in pipeline 12345 for project gitlab-org/gitlab
```

## `get_job` {#get_job}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605856) dans GitLab 19.3.
- [Changement de nom](https://gitlab.com/gitlab-org/gitlab/-/work_items/605856) de `get_job_log` dans GitLab 19.3. `get_job_log` continue de fonctionner comme alias et renvoie toujours la facette `log`, plafonnée à `byte_limit`.
- La facette `artifacts` a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/585022) dans GitLab 19.5.

{{< /history >}}

Obtient les métadonnées d'un job CI/CD et, éventuellement, sa trace/son journal ou les artefacts qu'il a produits.

| Paramètre     | Type    | Obligatoire | Description |
|---------------|---------|----------|-------------|
| `id`          | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `job_id`      | Entier | Oui      | ID du job. |
| `include`     | Tableau   | Non       | Facette à inclure avec le job, une par appel : `log` ou `artifacts`. |
| `byte_offset` | Entier | Non       | Décalage en octets à partir duquel commencer à lire le job log. S'applique uniquement lorsque `include` est `log`. La valeur par défaut est `0`. |
| `byte_limit`  | Entier | Non       | Nombre maximal d'octets du job log à renvoyer. S'applique uniquement lorsque `include` est `log`. La valeur par défaut et la valeur maximale sont `512000`. |

Lorsque le job log dépasse `byte_limit`, la réponse indique sa taille totale et le `byte_offset` à utiliser pour la fenêtre suivante.

La facette `artifacts` liste tous les artefacts produits par le job, avec leur `name`, leur `size`, leur `file_type` et les informations d'expiration.

Exemples :

- Obtenir les métadonnées d'un job :

  ```plaintext
  Get the status of job 88 in project gitlab-org/gitlab
  ```

- Obtenir le job log d'un job :

  ```plaintext
  Show me the log output for job 88 in project gitlab-org/gitlab
  ```

- Obtenir les artefacts d'un job :

  ```plaintext
  What artifacts did job 88 in project gitlab-org/gitlab produce?
  ```

## `get_artifact_file` {#get_artifact_file}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/585022) dans GitLab 19.5.

{{< /history >}}

Lit un fichier dans l'archive d'artefacts d'un job CI/CD en tant que texte. Pour découvrir ce qu'un job ou un pipeline a produit, utilisez l'outil `get_job` ou `get_pipeline` avec `include: artifacts`.

| Paramètre       | Type    | Obligatoire | Description |
|-----------------|---------|----------|-------------|
| `url`           | Chaîne  | Non       | URL du job. Renseignez ce paramètre ou les paramètres `project_id` et `job_id`. |
| `project_id`    | Chaîne  | Non       | ID ou chemin complet du projet. Obligatoire si `url` n'est pas renseigné. |
| `job_id`        | Entier | Non       | ID du job. Obligatoire si `url` n'est pas renseigné. |
| `artifact_path` | Chaîne  | Oui      | Chemin du fichier dans l'archive d'artefacts, par exemple `coverage/index.html`. |
| `byte_offset`   | Entier | Non       | Décalage en octets à partir duquel commencer la lecture du fichier. La valeur par défaut est `0`. |
| `byte_limit`    | Entier | Non       | Nombre maximum d'octets à retourner. La valeur par défaut et le maximum sont `1048576` (1 Mo). |

L'outil lit uniquement depuis l'artefact d'archive. Les artefacts de rapport stockés en tant que fichiers séparés, tels que les artefacts `junit` ou `dotenv`, ne font pas partie de l'archive et ne peuvent pas être lus avec cet outil.

Lorsque le fichier est plus long que `byte_limit`, la réponse indique la taille totale et vous donne le `byte_offset` à utiliser pour la fenêtre suivante. Les fichiers binaires ne sont pas retournés ; l'erreur indique le nom du fichier, sa taille, son type et l'emplacement pour le consulter dans le navigateur.

Exemples :

- Lire un rapport de test depuis les artefacts d'un job :

  ```plaintext
  Read coverage/index.html from the artifacts of job 88 in project gitlab-org/gitlab
  ```

- Analyser un test de bout en bout en échec :

  ```plaintext
  Find the JUnit report in the artifacts of job 88 in gitlab-org/gitlab and summarize the failures
  ```

## `list_pipelines` {#list_pipelines}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605854) dans GitLab 19.3.

{{< /history >}}

Répertorie les pipelines d'un projet GitLab avec des filtres facultatifs.

| Paramètre        | Type    | Obligatoire | Description |
|------------------|---------|----------|-------------|
| `id`             | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `ref`            | Chaîne  | Non       | Nom de la branche ou du tag. Filtre les pipelines par référence. |
| `status`         | Chaîne  | Non       | Filtre les pipelines par statut (par exemple, `running`, `success`, `failed`). |
| `source`         | Chaîne  | Non       | Filtre les pipelines par source (par exemple, `push`, `web`, `schedule`). |
| `created_after`  | Chaîne  | Non       | Renvoie les pipelines créés après la date et l'heure indiquées (format ISO 8601). |
| `created_before` | Chaîne  | Non       | Renvoie les pipelines créés avant la date et l'heure indiquées (format ISO 8601). |
| `order_by`       | Chaîne  | Non       | Trie les pipelines par `id`, `status`, `ref`, `updated_at` ou `user_id`. La valeur par défaut est `id`. |
| `sort`           | Chaîne  | Non       | Tri dans le sens `asc` ou `desc`. La valeur par défaut est `desc`. |
| `page`           | Entier | Non       | Numéro de page actuel. La valeur par défaut est `1`. |
| `per_page`       | Entier | Non       | Nombre d'éléments par page. La valeur par défaut est `20`. |

Les pipelines enfants sont exclus des résultats par défaut. Attribuez la valeur `parent_pipeline` à `source` pour ne renvoyer que les pipelines enfants.

L'ordre par défaut (`id`, `desc`) renvoie d'abord les pipelines dont l'ID est le plus élevé. L'ordre des ID correspond généralement à l'ordre de création, mais ces deux ordres ne coïncident pas nécessairement. Utilisez `created_after` ou `created_before` pour filtrer les pipelines selon une borne temporelle explicite. L'appelant peut parcourir les pages de résultats et s'arrêter au premier pipeline situé hors de la plage qu'il cible.

Exemple :

```plaintext
List all failed pipelines on the main branch for project gitlab-org/gitlab
```

## `save_pipeline` {#save_pipeline}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605855) dans GitLab 19.3.
- L'action `update` a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/619469) dans GitLab 19.4.

{{< /history >}}

Exécute, relance, annule ou renomme un pipeline CI/CD dans un projet GitLab. Utilisez plutôt l'outil `list_pipelines` pour répertorier les pipelines.

| Paramètre     | Type    | Obligatoire    | Description |
|---------------|---------|-------------|-------------|
| `url`         | Chaîne  | Non          | URL GitLab du projet. Ce paramètre sert uniquement à créer un pipeline. Renseignez soit cette valeur, soit `project_id`. |
| `project_id`  | Chaîne  | Non          | ID ou chemin complet du projet. Ce paramètre sert uniquement à créer un pipeline. Renseignez soit cette valeur, soit `url`. |
| `pipeline_id` | Entier | Non          | ID d'un pipeline existant à cibler. Ce paramètre requiert `action` lorsqu'il est renseigné. Omettez ce paramètre pour créer un nouveau pipeline. |
| `action`      | Chaîne  | Non          | Action de cycle de vie à effectuer sur `pipeline_id` : `retry`, `cancel` ou `update`. Obligatoire lorsque `pipeline_id` est défini. |
| `ref`         | Chaîne  | Non          | Nom de la branche ou du tag. Obligatoire pour créer un pipeline (lorsque `pipeline_id` est absent). |
| `name`        | Chaîne  | Non          | Nouveau nom du pipeline. Obligatoire pour `action: "update"`. |
| `variables`   | Tableau   | Non          | Variables du pipeline au format tableau (`[{key, value, variable_type}]`). |
| `inputs`      | hash    | Non          | Paramètres d'entrée du pipeline sous forme de paires clé-valeur. |

Exemples :

- Créer un pipeline :

  ```plaintext
  Create a pipeline on the main branch for project gitlab-org/gitlab
  ```

- Relancer un pipeline :

  ```plaintext
  Retry failed jobs in pipeline 12345 for project gitlab-org/gitlab
  ```

- Annuler un pipeline :

  ```plaintext
  Cancel pipeline 12345 in project gitlab-org/gitlab
  ```

- Renommer un pipeline :

  ```plaintext
  Rename pipeline 12345 to "Nightly security scan" in project gitlab-org/gitlab
  ```

## `manage_pipeline` {#manage_pipeline}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/583826) dans GitLab 18.10.
- [Suppression](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247806) de l'action `list` au profit de l'outil `list_pipelines` dans GitLab 19.3.
- [Suppression](https://gitlab.com/gitlab-org/gitlab/-/work_items/605855) des actions `create`, `retry` et `cancel` au profit de l'outil `save_pipeline` dans GitLab 19.3.
- [Non listé](https://gitlab.com/gitlab-org/gitlab/-/work_items/631276) dans GitLab 19.5. Pour renommer un pipeline, utilisez [`save_pipeline`](#save_pipeline) avec `action: "update"`.

{{< /history >}}

> [!warning]
> Cet outil n'est plus listé mais reste appelable par les agents disposant d'une liste d'outils obsolète ou ayant mémorisé le nom de l'outil. Pour renommer un pipeline, utilisez [`save_pipeline`](#save_pipeline) avec `action: "update"` à la place. La suppression de pipeline n'a pas encore de remplacement.

Met à jour les métadonnées du pipeline ou supprime un pipeline dans un projet GitLab. Utilisez plutôt l'outil `save_pipeline` pour créer, relancer ou annuler un pipeline. Utilisez plutôt l'outil `list_pipelines` pour répertorier les pipelines.

| Paramètre     | Type    | Obligatoire    | Description |
|---------------|---------|-------------|-------------|
| `id`          | Chaîne  | Oui         | ID ou chemin complet du projet. |
| `pipeline_id` | Entier | Oui         | ID du pipeline. Un pipeline et toutes les données associées sont supprimés si seul ce paramètre est renseigné. |
| `name`        | Chaîne  | Non          | Nom du pipeline. Les métadonnées du pipeline sont mises à jour si ce paramètre et `pipeline_id` sont renseignés. |

Exemples :

- Mettre à jour un pipeline :

  ```plaintext
  Rename pipeline 12345 to "My deploy pipeline" in project gitlab-org/gitlab
  ```

- Supprimer un pipeline :

  ```plaintext
  Delete pipeline 12345 in project gitlab-org/gitlab
  ```

## `get_work_item` {#get_work_item}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605882) dans GitLab 19.4.
- La facette `discussions` a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/597686) dans GitLab 19.5.

{{< /history >}}

Récupère un seul élément de travail (ticket, epic, tâche, incident, objectif ou résultat clé) avec son type, ses dates, ses assignés, ses labels, son jalon et son parent. Inclut éventuellement ses notes, ses discussions ou les merge requests qui lui sont associées. Les widgets non pris en charge par le type d'élément de travail sont omis.

| Paramètre                       | Type    | Obligatoire | Description |
|---------------------------------|---------|----------|-------------|
| `url`                           | Chaîne  | Non       | URL GitLab de l'élément de travail (une URL `/-/work_items/`, `/-/issues/` ou `/-/epics/`). Fournissez ceci, ou `work_item_iid` avec `group_id` ou `project_id`. |
| `group_id`                      | Chaîne  | Non       | ID ou chemin du groupe. Obligatoire si `url` et `project_id` ne sont pas renseignés. |
| `project_id`                    | Chaîne  | Non       | ID ou chemin du projet. Obligatoire si `url` et `group_id` ne sont pas renseignés. |
| `work_item_iid`                 | Entier | Non       | ID interne de l'élément de travail. Obligatoire si `url` n'est pas renseigné. |
| `include`                       | Tableau   | Non       | Données associées à retourner. L'un de `notes`, `discussions` ou `related_merge_requests`, une facette par appel. Pour les notes les plus récentes, utilisez `notes_last` sans `notes_first` ni `notes_after`. |
| `notes_first`                   | Entier | Non       | Nombre de notes à retourner après le curseur (pagination avant). Par défaut 100, maximum 100. |
| `notes_after`                   | Chaîne  | Non       | Curseur de pagination vers l'avant pour les notes. Utilisez `pageInfo.endCursor` d'une réponse précédente. |
| `notes_last`                    | Entier | Non       | Nombre de notes à retourner avant le curseur (pagination arrière). Par défaut 100, maximum 100. |
| `notes_before`                  | Chaîne  | Non       | Curseur pour la pagination arrière des notes. Utilisez `pageInfo.startCursor` d'une réponse précédente. |
| `discussions_first`             | Entier | Non       | Nombre de discussions à retourner après le curseur. Par défaut 20, maximum 100. |
| `discussions_after`             | Chaîne  | Non       | Curseur pour la pagination avant des discussions. Utilisez `pageInfo.endCursor` d'une réponse précédente. |
| `discussions_filter`            | Chaîne  | Non       | Discussions à retourner : `all_notes` (par défaut), `only_comments` pour exclure les notes système, ou `only_activity` pour les notes système uniquement. |
| `related_merge_requests_first`  | Entier | Non       | Nombre de merge requests associées à retourner. Par défaut 20, maximum 100. |
| `related_merge_requests_after`  | Chaîne  | Non       | Curseur pour la pagination avant des merge requests associées. |
| `mr_page_size`                  | Entier | Non       | Déprécié : utilisez `related_merge_requests_first` à la place. |
| `mr_pagination_cursor`          | Chaîne  | Non       | Déprécié : utilisez `related_merge_requests_after` à la place. |

La facette `notes` retourne jusqu'à 100 notes par appel et pagine dans les deux directions avec les paramètres `notes_*`. Chaque note inclut `discussion.id`, l'ID du fil de discussion auquel elle appartient, afin que vous puissiez regrouper les notes par fil de discussion.

Utilisez `discussions` pour la structure des fils de discussion et l'état de résolution, et `notes` pour un historique chronologique plat.

La facette `discussions` retourne les fils de discussion de l'élément de travail. Chaque discussion inclut son état `resolvable` et `resolved` ainsi que ses notes, afin que vous puissiez identifier les fils de discussion encore non résolus. Un fil de discussion non résolu a `resolvable` défini sur `true` et `resolved` défini sur `false`. Il pagine vers l'avant uniquement avec les paramètres `discussions_*`, et une discussion n'est jamais divisée entre deux pages.

La facette `related_merge_requests` est vide pour les éléments de travail de groupe tels que les epics.

Exemple :

```plaintext
Get issue 42 in project gitlab-org/gitlab with its related merge requests
```

## `get_workitem_notes` {#get_workitem_notes}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/581892) dans GitLab 18.7.
- [Non listé](https://gitlab.com/gitlab-org/gitlab/-/work_items/625128) dans GitLab 19.4. Remplacé par la facette `notes` de [`get_work_item`](#get_work_item).

{{< /history >}}

Remplacé par [`get_work_item`](#get_work_item) avec `include: ["notes"]`, qui pagine les notes dans les deux directions. Cet outil n'apparaît plus dans `tools/list` mais reste appelable pendant la migration des appelants.

Récupère toutes les notes (commentaires) d'un élément de travail GitLab précis.

| Paramètre       | Type    | Obligatoire | Description |
|-----------------|---------|----------|-------------|
| `url`           | Chaîne  | Non       | URL de l'élément de travail. Obligatoire si `work_item_iid` n'est renseigné ni avec `group_id` ni avec `project_id`. |
| `group_id`      | Chaîne  | Non       | ID ou chemin du groupe. Obligatoire si `url` et `project_id` ne sont pas renseignés. |
| `project_id`    | Chaîne  | Non       | ID ou chemin du projet. Obligatoire si `url` et `group_id` ne sont pas renseignés. |
| `work_item_iid` | Entier | Non       | ID interne de l'élément de travail. Obligatoire si `url` n'est pas renseigné. |
| `after`         | Chaîne  | Non       | Curseur pour la pagination vers l'avant. |
| `before`        | Chaîne  | Non       | Curseur pour la pagination vers l'arrière. |
| `first`         | Entier | Non       | Nombre de notes à renvoyer pour la pagination vers l'avant. |
| `last`          | Entier | Non       | Nombre de notes à renvoyer pour la pagination vers l'arrière. |

Exemple :

```plaintext
Show me all comments on work item 42 in project gitlab-org/gitlab
```

## `link_work_items` {#link_work_items}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/230221) dans GitLab 19.0.
- Les IID simples pour `work_items_ids` ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254551) dans GitLab 19.4.

{{< /history >}}

Lie un élément de travail à un ou plusieurs autres éléments de travail selon un type de relation.

| Paramètre        | Type             | Obligatoire | Description |
|------------------|------------------|----------|-------------|
| `work_items_ids` | Tableau            | Oui      | Éléments de travail à lier : IID simples, résolus dans le même projet ou groupe que la source, ou IDs globaux (`gid://gitlab/WorkItem/<id>`) pour les éléments de travail dans d'autres projets ou groupes. 10 éléments au maximum. |
| `url`            | Chaîne           | Non       | URL de l'élément de travail source. Obligatoire si `work_item_iid` n'est renseigné ni avec `group_id` ni avec `project_id`. |
| `group_id`       | Chaîne           | Non       | ID ou chemin du groupe. Obligatoire si `url` et `project_id` ne sont pas renseignés. |
| `project_id`     | Chaîne           | Non       | ID ou chemin du projet. Obligatoire si `url` et `group_id` ne sont pas renseignés. |
| `work_item_iid`  | Entier          | Non       | ID interne de l'élément de travail source. Obligatoire si `url` n'est pas renseigné. |
| `link_type`      | Chaîne           | Non       | Type de relation. L'une des valeurs `relates_to`, `blocks` ou `blocked_by`. La valeur par défaut est `relates_to`. Les types `blocks` et `blocked_by` nécessitent GitLab Premium ou GitLab Ultimate. |

Exemple :

```plaintext
Mark work item 42 in project gitlab-org/gitlab as blocked by work item 40
```

## `get_saved_view_work_items` {#get_saved_view_work_items}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/227911) dans GitLab 18.11.

{{< /history >}}

Récupère une vue enregistrée et sa liste d'éléments de travail dans un espace de nommage. L'outil applique les filtres et l'ordre de tri de la vue enregistrée aux éléments de travail renvoyés.

| Paramètre       | Type    | Obligatoire | Description |
|-----------------|---------|----------|-------------|
| `saved_view_id` | Chaîne  | Oui      | ID global de la vue enregistrée (au format `gid://gitlab/WorkItems::SavedViews::SavedView/<id>`). |
| `url`           | Chaîne  | Non       | URL de l'espace de nommage (projet ou groupe). Obligatoire si `group_id` ou `project_id` est manquant. |
| `group_id`      | Chaîne  | Non       | ID ou chemin du groupe. Obligatoire si `url` et `project_id` ne sont pas renseignés. |
| `project_id`    | Chaîne  | Non       | ID ou chemin du projet. Obligatoire si `url` et `group_id` ne sont pas renseignés. |
| `after`         | Chaîne  | Non       | Curseur pour la pagination vers l'avant. |
| `first`         | Entier | Non       | Nombre d'éléments de travail à renvoyer. 100 au maximum. |

Exemple :

```plaintext
Show me the work items in this saved view: <URL>
```

## `list_vulnerabilities` {#list_vulnerabilities}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251243) dans GitLab 19.4.

{{< /history >}}

Répertorie les vulnérabilités de sécurité dans un projet GitLab, avec des filtres optionnels et une pagination par curseur. Retourne les métadonnées paginées des vulnérabilités. Pour obtenir les détails complets d'une seule vulnérabilité, utilisez [`get_vulnerability`](#get_vulnerability).

Nécessite que la fonctionnalité de tableau de bord de sécurité soit activée.

Cet outil n'est répertorié que lorsque la fonctionnalité sous licence est disponible pour vous. Pour plus d'informations, voir [sélectionner des groupes d'outils](mcp_server.md#select-tool-groups-toolsets).

| Paramètre            | Type             | Obligatoire | Description |
|----------------------|------------------|----------|-------------|
| `project_full_path`  | Chaîne           | Oui      | Chemin complet du projet (par exemple, `namespace/project` ou `group/subgroup/project`). |
| `severity`           | Tableau de chaînes de caractères | Non       | Filtrer par niveau de gravité. Omettez ce paramètre pour inclure les vulnérabilités de toute gravité. Un ou plusieurs de `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` ou `UNKNOWN`. |
| `report_type`        | Tableau de chaînes de caractères | Non       | Filtrer par type de rapport de sécurité. Omettez ce paramètre pour inclure tous les types de rapport. Par exemple, `SAST`, `DAST` ou `DEPENDENCY_SCANNING`. |
| `state`              | Tableau de chaînes de caractères | Non       | Filtrer par état de vulnérabilité. Omettez ce paramètre pour inclure les vulnérabilités dans n'importe quel état. Un ou plusieurs de `CONFIRMED`, `DETECTED`, `DISMISSED` ou `RESOLVED`. |
| `first`              | Entier          | Non       | Nombre de vulnérabilités à retourner pour la pagination avant. La valeur par défaut est `20` et la valeur maximale est `100`. |
| `after`              | Chaîne           | Non       | Curseur pour la pagination vers l'avant. Utilisez `pageInfo.endCursor` d'une réponse précédente. |

Exemple :

```plaintext
List critical and high severity vulnerabilities in project gitlab-org/gitlab
```

## `get_vulnerability` {#get_vulnerability}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251243) dans GitLab 19.4.

{{< /history >}}

Retourne les détails complets d'une seule vulnérabilité, notamment son titre, son état, sa description, sa gravité et ses identifiants.

Cet outil n'est répertorié que lorsque la fonctionnalité sous licence est disponible pour vous. Pour plus d'informations, voir [sélectionner des groupes d'outils](mcp_server.md#select-tool-groups-toolsets).

| Paramètre          | Type   | Obligatoire | Description |
|--------------------|--------|----------|-------------|
| `vulnerability_id` | Chaîne | Oui      | ID numérique de la vulnérabilité (par exemple, `567`). |

Exemple :

```plaintext
Get full details for vulnerability 567
```

## `save_vulnerability` {#save_vulnerability}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/613026) dans GitLab 19.4.

{{< /history >}}

Effectue des opérations d'écriture sur une vulnérabilité dans un projet GitLab.

Cet outil n'est répertorié que lorsque la fonctionnalité sous licence est disponible pour vous. Pour plus d'informations, voir [sélectionner des groupes d'outils](mcp_server.md#select-tool-groups-toolsets).

| Paramètre            | Type   | Obligatoire | Description |
|----------------------|--------|----------|-------------|
| `action`             | Chaîne | Oui      | Opération à effectuer. L'une des valeurs `dismiss`, `confirm`, `revert_to_detected`, `update_severity` ou `create_issue`. |
| `vulnerability_id`   | Chaîne | Oui      | ID numérique de la vulnérabilité (par exemple, `567`). |
| `comment`            | Chaîne | Non       | Explication de l'action. Obligatoire lorsque `action` vaut `update_severity`. |
| `dismissal_reason`   | Chaîne | Non       | Raison du rejet. L'une des valeurs `ACCEPTABLE_RISK`, `FALSE_POSITIVE`, `MITIGATING_CONTROL`, `USED_IN_TESTS` ou `NOT_APPLICABLE`. À utiliser uniquement lorsque `action` est `dismiss`. |
| `severity`           | Chaîne | Non       | Nouveau niveau de gravité. L'un des statuts `INFO`, `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH` ou `CRITICAL`. Obligatoire lorsque `action` vaut `update_severity`. |
| `project_full_path`  | Chaîne | Non       | Chemin complet du projet (par exemple, `namespace/project`). Obligatoire lorsque `action` vaut `create_issue`. |

Exemples :

- Rejeter une vulnérabilité :

  ```plaintext
  Dismiss vulnerability 123 with reason FALSE_POSITIVE
  ```

- Confirmer une vulnérabilité :

  ```plaintext
  Mark vulnerability 456 as confirmed
  ```

- Revenir à l'état détecté :

  ```plaintext
  Revert vulnerability 789 back to detected state
  ```

- Mettre à jour la gravité :

  ```plaintext
  Change severity of vulnerability 321 to CRITICAL with comment "Reassessed based on new intel"
  ```

- Créer un ticket :

  ```plaintext
  Create an issue for vulnerability 654 in project gitlab-org/gitlab
  ```

## `save_work_item` {#save_work_item}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605852) dans GitLab 19.4.
- Les paramètres `labels`, `add_labels`, `remove_labels`, `milestone_id` et `milestone` ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/work_items/622711) dans GitLab 19.4.

{{< /history >}}

Crée ou met à jour un élément de travail GitLab, tel qu'un ticket, une tâche ou un epic. Omettez `work_item_iid` pour créer un nouvel élément de travail. Renseignez soit `work_item_iid`, soit l'URL d'un élément de travail existant pour le mettre à jour. N'envoyez que les champs que vous souhaitez définir, et omettez les autres. Les noms d'outils `create_work_item` et `update_work_item` sont des alias de cet outil.

| Paramètre          | Type              | Obligatoire | Description |
|--------------------|-------------------|----------|-------------|
| `url`              | Chaîne            | Non       | URL GitLab du projet, du groupe ou de l'élément de travail. Renseignez un seul des trois paramètres `url`, `project_id` et `group_id`. |
| `group_id`         | Chaîne            | Non       | ID ou chemin du groupe. Obligatoire si `url` et `project_id` ne sont pas renseignés. |
| `project_id`       | Chaîne            | Non       | ID ou chemin du projet. Obligatoire si `url` et `group_id` ne sont pas renseignés. |
| `work_item_iid`    | Entier           | Non       | ID interne positif de l'élément de travail à mettre à jour. Omettez ce paramètre pour créer un nouvel élément de travail. |
| `title`            | Chaîne            | Non       | Titre de l'élément de travail. Obligatoire lors de la création d'un élément de travail. |
| `type_name`        | Chaîne            | Non       | Nom du type d'élément de travail, par exemple `Issue`, `Task` ou `Epic`. Obligatoire lors de la création d'un élément de travail. Les types valides dépendent de l'espace de nommage et de la licence. |
| `description`      | Chaîne            | Non       | Description en GitLab Flavored Markdown. 1 048 576 caractères au maximum. |
| `assignee_ids`     | Tableau d'entiers | Non       | ID d'utilisateurs à assigner à l'élément de travail. 100 éléments au maximum. |
| `label_ids`        | Tableau de chaînes de caractères  | Non       | ID de labels ou ID globaux. Création uniquement ; lors d'une mise à jour, utilisez `add_label_ids` ou `remove_label_ids`. 100 éléments au maximum. |
| `labels`           | Tableau de chaînes de caractères  | Non       | Noms des labels à définir, résolus dans le projet ou le groupe et ses groupes ancêtres. Création uniquement ; lors d'une mise à jour, utilisez `add_labels` ou `remove_labels`. 100 éléments au maximum. |
| `add_label_ids`    | Tableau de chaînes de caractères  | Non       | Mise à jour uniquement. ID de labels ou ID globaux à ajouter. 100 éléments au maximum. |
| `add_labels`       | Tableau de chaînes de caractères  | Non       | Mise à jour uniquement. Noms des labels à ajouter. 100 éléments au maximum. |
| `remove_label_ids` | Tableau de chaînes de caractères  | Non       | Mise à jour uniquement. ID de labels ou ID globaux à supprimer. 100 éléments au maximum. |
| `remove_labels`    | Tableau de chaînes de caractères  | Non       | Mise à jour uniquement. Noms des labels à supprimer. 100 éléments au maximum. |
| `milestone_id`     | Chaîne            | Non       | ID ou ID global du jalon à assigner, validé par rapport au projet ou au groupe et ses groupes ancêtres. Prévaut sur `milestone` lorsque les deux sont fournis. |
| `milestone`        | Chaîne            | Non       | Titre du jalon à assigner, résolu parmi les jalons du projet ou du groupe et ses groupes ancêtres. |
| `confidential`     | Booléen           | Non       | Définit la confidentialité de l'élément de travail. |
| `start_date`       | Chaîne            | Non       | Date de début, au format `YYYY-MM-DD`. |
| `due_date`         | Chaîne            | Non       | Date d'échéance, au format `YYYY-MM-DD`. |
| `state`            | Chaîne            | Non       | Mise à jour uniquement. `closed` ferme l'élément de travail et `opened` le rouvre. |
| `parent_id`        | Chaîne            | Non       | ID global ou ID numérique de l'élément de travail parent. |
| `todo_action`      | Chaîne            | Non       | Mise à jour uniquement. `add` ajoute une tâche à faire pour l'utilisateur actuel et `mark_as_done` marque les tâches à faire comme effectuées. |
| `todo_id`          | Chaîne            | Non       | Mise à jour uniquement. ID global ou ID numérique de la tâche à faire. Omettez ce paramètre pour mettre à jour toutes les tâches à faire de l'élément de travail. |
| `health_status`    | Chaîne            | Non       | Statut de santé. L'une des valeurs `onTrack`, `needsAttention` ou `atRisk`. GitLab Ultimate uniquement. |
| `weight`           | Entier           | Non       | Poids de l'élément de travail. Doit être supérieur ou égal à 0. GitLab Premium et GitLab Ultimate uniquement. |
| `clear_weight`     | Booléen           | Non       | Mise à jour uniquement. Supprime le poids. Prévaut sur `weight`. GitLab Premium et GitLab Ultimate uniquement. |
| `status_id`        | Chaîne            | Non       | ID global du statut à définir. GitLab Premium et GitLab Ultimate uniquement. |
| `is_fixed`         | Booléen           | Non       | Indique si les dates de début et d'échéance sont fixes. Lorsque `false`, les dates sont agrégées à partir de celles des éléments enfants, tandis que `start_date` et `due_date` sont ignorés. GitLab Premium et GitLab Ultimate uniquement. |
| `agent_plan`       | Chaîne            | Non       | Contenu Markdown du plan d'agent. GitLab Ultimate uniquement. Nécessite la fonctionnalité workplan. |
| `readiness_score`  | Entier           | Non       | Score de préparation du plan de l'agent, de 0 à 100. GitLab Ultimate uniquement. Requiert le feature flag `workplan_score`. Renvoie une erreur lorsque le flag est désactivé. |

Exemple :

```plaintext
Create a task "Update the onboarding guide" in project gitlab-org/gitlab and assign it to me
```

## `list_work_items` {#list_work_items}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/605850) dans GitLab 19.4.

{{< /history >}}

Répertorie ou recherche des éléments de travail (tickets, incidents, cas de test, exigences, tâches, tickets, objectifs, résultats clés, epics) dans un groupe ou un projet. La portée du groupe inclut les éléments de travail des projets descendants et des sous-groupes. Chaque résultat contient uniquement l'ID, l'IID, le titre, l'état, l'URL web, la référence complète, les horodatages de création et de mise à jour, ainsi que le type d'élément de travail, avec pagination par curseur. Utilisez `get_work_item` pour lire un élément de travail en détail.

| Paramètre               | Type    | Obligatoire | Description |
|-------------------------|---------|----------|-------------|
| `url`                   | Chaîne  | Non       | URL GitLab du projet ou du groupe. Renseignez un seul des trois paramètres `url`, `group_id` et `project_id`. |
| `group_id`              | Chaîne  | Non       | ID ou chemin du groupe. Obligatoire si `url` et `project_id` ne sont pas renseignés. |
| `project_id`            | Chaîne  | Non       | ID ou chemin du projet. Obligatoire si `url` et `group_id` ne sont pas renseignés. |
| `state`                 | Chaîne  | Non       | Filtre par état : `opened`, `closed`, ou `all` (par défaut). |
| `search`                | Chaîne  | Non       | Recherche en texte libre dans le titre et la description. |
| `author_username`       | Chaîne  | Non       | Nom d'utilisateur de l'auteur. |
| `assignee_usernames`    | Tableau   | Non       | Noms d'utilisateur des personnes assignées. Un élément de travail doit correspondre à tous ces critères. Maximum 100 valeurs. |
| `label_name`            | Tableau   | Non       | Noms des labels. Un élément de travail doit avoir tous ces labels. Maximum 100 valeurs. |
| `milestone_title`       | Tableau   | Non       | Titres des jalons. Ne peut pas être combiné avec `milestone_wildcard_id`. Maximum 100 valeurs. |
| `milestone_wildcard_id` | Chaîne  | Non       | `NONE`, `ANY`, `STARTED`, ou `UPCOMING`. Ne peut pas être combiné avec `milestone_title`. |
| `types`                 | Tableau   | Non       | Types d'éléments de travail à inclure, par exemple `["ISSUE", "TASK"]`. |
| `created_after`         | Chaîne  | Non       | Créé après cette heure (ISO 8601 ; une date seule correspond au début de la journée, les décalages sont pris en compte). |
| `created_before`        | Chaîne  | Non       | Créé avant cette heure (ISO 8601 ; une date seule correspond au début de la journée, les décalages sont pris en compte). |
| `updated_after`         | Chaîne  | Non       | Mis à jour après cette heure (ISO 8601 ; une date seule correspond au début de la journée, les décalages sont pris en compte). |
| `updated_before`        | Chaîne  | Non       | Mis à jour avant cette heure (ISO 8601 ; une date seule correspond au début de la journée, les décalages sont pris en compte). |
| `due_after`             | Chaîne  | Non       | Dû après cette heure (ISO 8601 ; une date seule correspond au début de la journée, les décalages sont pris en compte). |
| `due_before`            | Chaîne  | Non       | Dû avant cette heure (ISO 8601 ; une date seule correspond au début de la journée, les décalages sont pris en compte). |
| `sort`                  | Chaîne  | Non       | Ordre de tri, par exemple `UPDATED_DESC`. Par défaut `CREATED_DESC`. |
| `first`                 | Entier | Non       | Nombre d'éléments de travail à renvoyer. Par défaut 20, maximum 100. |
| `after`                 | Chaîne  | Non       | Curseur pour la pagination vers l'avant. |
| `health_status_filter`  | Chaîne  | Non       | GitLab Ultimate uniquement. `onTrack`, `needsAttention`, ou `atRisk`. |
| `status`                | objet  | Non       | GitLab Ultimate uniquement. Filtre par nom de statut personnalisé, par exemple `{"name": "In progress"}`. |

Exemple :

```plaintext
List my open tasks in the gitlab-org group updated this month.
```

## `get_work_item_types` {#get_work_item_types}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/237071) dans GitLab 19.1.

{{< /history >}}

Répertorie les types d'éléments de travail disponibles dans un espace de nommage (groupe ou projet), y compris les types définis par le système (tels que Ticket, Epic et Tâche) et les types personnalisés. Chaque type renvoyé inclut son ID global, son nom, son icône et les types de widgets activés, afin d'éviter de définir des champs que le type ne prend pas en charge.

| Paramètre    | Type   | Obligatoire | Description |
|--------------|--------|----------|-------------|
| `url`        | Chaîne | Non       | URL GitLab pour l'espace de nommage (projet ou groupe). Obligatoire si `group_id` et `project_id` ne sont pas renseignés. |
| `group_id`   | Chaîne | Non       | ID ou chemin du groupe. Obligatoire si `url` et `project_id` ne sont pas renseignés. |
| `project_id` | Chaîne | Non       | ID ou chemin du projet. Obligatoire si `url` et `group_id` ne sont pas renseignés. |

Exemple :

```plaintext
List the work item types available in the gitlab-org group
```

## `list_projects` {#list_projects}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250301) dans GitLab 19.4.

{{< /history >}}

Sans `group_id`, répertorie par défaut les projets pour lesquels vous avez au moins le rôle Invité ; utilisez `min_access_level` pour augmenter ce seuil. Avec `group_id`, répertorie tous les projets de ce groupe et de ses sous-groupes, quel que soit le niveau d'accès ; l'ajout de `min_access_level` ou de `visibility` restreint la liste à ce groupe uniquement, sans ses sous-groupes, car GitLab ne prend pas en charge la combinaison de la traversée des sous-groupes avec ces filtres lors de la liste des projets d'un groupe.

| Paramètre          | Type    | Obligatoire | Description |
|--------------------|---------|----------|-------------|
| `group_id`         | Chaîne  | Non       | ID ou chemin complet d'un groupe. Omettez ce paramètre pour lister tous les projets de l'instance, en affichant par défaut les projets pour lesquels vous avez au moins le rôle Invité. |
| `min_access_level` | Chaîne  | Non       | Niveau d'accès minimal qu'un projet doit vous accorder pour être inclus. L'un des statuts `guest`, `planner`, `reporter`, `developer`, `maintainer` ou `owner`. |
| `search`           | Chaîne  | Non       | Recherche des projets par nom, chemin ou description. |
| `visibility`       | Chaîne  | Non       | Filtre par niveau de visibilité : `public`, `internal`, ou `private`. |
| `archived`         | Chaîne  | Non       | Filtre par état d'archivage : `only`, `include`, ou `exclude` (par défaut). |
| `after`            | Chaîne  | Non       | Curseur pour la pagination vers l'avant. |
| `first`            | Entier | Non       | Nombre de projets à retourner pour la pagination ascendante. La valeur par défaut est 20 et la valeur maximale est 100. |

Lorsque vous fournissez `group_id`, la réponse inclut `subgroupsIncluded` : `true` lorsque la liste couvre les sous-groupes du groupe, `false` lorsque `min_access_level` ou `visibility` a restreint la liste à ce groupe uniquement.

Exemple :

```plaintext
List my projects
```

## `list_groups` {#list_groups}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/607719) dans GitLab 19.4.

{{< /history >}}

Répertorie les groupes, pour naviguer dans la hiérarchie des groupes et découvrir les ID et chemins complets des groupes à utiliser avec d'autres outils. Sans `group_id`, cet outil répertorie les groupes principaux dont vous êtes membre. Avec `group_id`, il répertorie les sous-groupes directs de ce groupe, quel que soit le statut de membre. Définissez `include_subgroups` sur `true` pour parcourir récursivement tous les sous-groupes descendants. Sans `group_id`, cela répertorie vos groupes à n'importe quelle profondeur. Les groupes archivés et les groupes en attente de suppression sont exclus.

| Paramètre           | Type    | Obligatoire | Description |
|---------------------|---------|----------|-------------|
| `group_id`         | Chaîne  | Non       | ID ou chemin complet d'un groupe parent dont vous souhaitez lister les sous-groupes. Omettez ce paramètre pour lister les groupes principaux dont vous êtes membre. |
| `search`            | Chaîne  | Non       | Recherche des groupes par nom ou chemin complet. |
| `visibility`        | Chaîne  | Non       | Filtre par niveau de visibilité : `public`, `internal`, ou `private`. |
| `include_subgroups` | Booléen | Non       | Inclut tous les sous-groupes descendants de manière récursive, au lieu des enfants directs uniquement. |
| `after`             | Chaîne  | Non       | Curseur pour la pagination vers l'avant. |
| `first`             | Entier | Non       | Nombre de groupes à retourner pour la pagination ascendante. La valeur par défaut est 20 et la valeur maximale est 100. |

Exemple :

```plaintext
List the subgroups of gitlab-org
```

## `search` {#search}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/566143) dans GitLab 18.4.
- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/issues/571132) de la recherche de groupes et de projets ainsi que du classement et du tri des résultats dans GitLab 18.6.
- [Changement de nom](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/214734) de `gitlab_search` en `search` dans GitLab 18.8.

{{< /history >}}

Recherche un terme dans l'ensemble de l'instance GitLab au moyen de l'API de recherche. Cet outil est disponible pour la recherche globale, par groupe et par projet. Les portées disponibles dépendent du [type de recherche](../search/_index.md).

| Paramètre      | Type             | Obligatoire | Description |
|----------------|------------------|----------|-------------|
| `scope`        | Chaîne           | Oui      | Portée de la recherche (par exemple, `work_items`, `merge_requests` ou `projects`). |
| `search`       | Chaîne           | Oui      | Terme de recherche. |
| `group_id`     | Chaîne           | Non       | ID ou chemin complet du groupe dans lequel vous souhaitez effectuer une recherche. |
| `project_id`   | Chaîne           | Non       | ID ou chemin complet du projet dans lequel vous souhaitez effectuer une recherche. |
| `state`        | Chaîne           | Non       | État des résultats de recherche (pour `work_items` et `merge_requests`). |
| `confidential` | Booléen          | Non       | Filtre les résultats selon leur caractère confidentiel (pour `work_items`). La valeur par défaut est `false`. |
| `fields`       | Tableau de chaînes de caractères | Non       | Tableau des champs dans lesquels vous souhaitez effectuer la recherche (pour `work_items` et `merge_requests`). |
| `order_by`     | Chaîne           | Non       | Attribut selon lequel classer les résultats. La valeur par défaut est `created_at` pour la recherche de base et la pertinence pour la recherche avancée. |
| `sort`         | Chaîne           | Non       | Sens du tri des résultats. La valeur par défaut est `desc`. |
| `per_page`     | Entier          | Non       | Nombre de résultats par page. La valeur par défaut est `20`. |
| `page`         | Entier          | Non       | Numéro de page actuel. La valeur par défaut est `1`. |

Exemple :

```plaintext
Search issues for "flaky test" across GitLab
```

## `search_labels` {#search_labels}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/218121) dans GitLab 18.9.
- [Modification](https://gitlab.com/gitlab-org/gitlab/-/work_items/621662) dans GitLab 19.5 pour accepter plusieurs termes de recherche.

{{< /history >}}

Recherche des labels dans un projet GitLab ou un groupe GitLab.

| Paramètre    | Type                        | Obligatoire | Description |
|--------------|-----------------------------|----------|-------------|
| `full_path`  | Chaîne                      | Oui      | Chemin complet du projet ou du groupe (par exemple, `group/project`). |
| `is_project` | Booléen                     | Oui      | Indique si la recherche doit être effectuée dans un projet (`true`) ou un groupe (`false`). |
| `search`     | chaîne ou tableau de chaînes  | Non       | Un terme ou un tableau de 10 termes maximum pour filtrer les labels par titre. Si ce paramètre est omis, les labels sont répertoriés à la place. Un tableau vide est invalide. |

Lorsque vous recherchez des labels de groupe, les résultats incluent les labels des groupes ascendants et descendants. Les résultats provenant de plusieurs termes forment une seule liste sans labels en double.

Exemple :

```plaintext
Show me all labels in project gitlab-org/gitlab
```

## `list_wiki_pages` {#list_wiki_pages}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/240973) dans GitLab 19.3.

{{< /history >}}

Répertorie les pages wiki dans un projet ou groupe GitLab.

| Paramètre    | Type    | Obligatoire | Description |
|--------------|---------|----------|-------------|
| `project_id` | Chaîne  | Non       | Chemin complet ou ID numérique du projet (par exemple, `gitlab-org/gitlab` ou `278964`). |
| `group_id`   | Chaîne  | Non       | Chemin complet ou ID numérique du groupe (par exemple, `gitlab-org` ou `9970`). |
| `first`      | Entier | Non       | Nombre de pages wiki à renvoyer pour la pagination vers l'avant (100 au maximum). |
| `after`      | Chaîne  | Non       | Curseur pour la pagination vers l'avant. |

Renseignez soit `project_id`, soit `group_id`. Chaque appel renvoie une seule page de résultats. Si d'autres pages existent, la réponse inclut un `end_cursor` que vous pouvez renseigner comme valeur de `after` pour récupérer la page suivante.

Exemple :

```plaintext
List the wiki pages in gitlab-org/gitlab
```

## `semantic_search` {#semantic_search}

{{< details >}}

- Module d'extension : GitLab Duo Core, GitLab Duo Pro ou GitLab Duo Enterprise
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/569624) en [version expérimentale](../../policy/development_stages_support.md#experiment) dans GitLab 18.5 [avec le feature flag](../../administration/feature_flags/_index.md) `code_snippet_search_graphqlapi`. Désactivé par défaut.
- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/issues/575234) de la recherche par chemin de projet dans GitLab 18.6.
- [Passage](https://gitlab.com/gitlab-org/gitlab/-/issues/568359) de la version expérimentale à la [version bêta](../../policy/development_stages_support.md#beta) dans GitLab 18.7. Le feature flag `code_snippet_search_graphqlapi` a été supprimé.
- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/issues/581105) à l'interface utilisateur GitLab dans GitLab 18.7 [avec le feature flag](../../administration/feature_flags/_index.md) `mcp_client`. Désactivé par défaut.
- [Mise à jour](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228569) pour utiliser l'[API REST](../../api/search.md#semantic-search) dans GitLab 18.11 [avec le feature flag](../../administration/feature_flags/_index.md) `mcp_semantic_code_search_use_rest_api`. Désactivé par défaut.
- Passage de l'utilisation de l'API REST [en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/239364) dans GitLab 19.1. Le feature flag `mcp_semantic_code_search_use_rest_api` a été supprimé.
- [Renommé](https://gitlab.com/gitlab-org/gitlab/-/work_items/606755) depuis `semantic_code_search` dans GitLab 19.4. `semantic_code_search` continue de fonctionner comme alias.
- Paramètre `scope` [ajouté](https://gitlab.com/gitlab-org/gitlab/-/work_items/606755) dans GitLab 19.4.
- Paramètre `semantic_query` [renommé](https://gitlab.com/gitlab-org/gitlab/-/work_items/606755) en `q` dans GitLab 19.4.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Recherche du contenu pertinent dans un projet GitLab par signification plutôt que par mot-clé. Utilisez cet outil lorsque vous ne connaissez pas le symbole ou le nom de fichier exact, ou pour découvrir comment un comportement est implémenté dans une base de code. Pour plus d'informations, notamment sur la configuration et l'activation, consultez [la recherche sémantique de code](../gitlab_duo/semantic_code_search.md).

| Paramètre        | Type    | Obligatoire | Description |
|------------------|---------|----------|-------------|
| `scope`          | Chaîne  | Oui      | Type de contenu à rechercher. Seul `code` est pris en charge. |
| `q`              | Chaîne  | Oui      | Requête de recherche en langage naturel. |
| `project_id`     | Chaîne  | Oui      | ID ou chemin complet du projet. |
| `directory_path` | Chaîne  | Non       | Restreint la recherche aux fichiers situés sous ce chemin de répertoire (par exemple, `app/services/`). Doit être un chemin relatif, sans barre oblique initiale ni segments `..`. S'applique uniquement lorsque `scope` a la valeur `code`. |
| `knn`            | Entier | Non       | Nombre de voisins les plus proches récupérés en interne. La valeur par défaut est `64` et la valeur maximale est `100`. Des valeurs plus élevées améliorent le rappel au détriment de la latence. S'applique uniquement lorsque `scope` a la valeur `code`. |
| `limit`          | Entier | Non       | Nombre maximal de résultats à renvoyer. La valeur par défaut est `20` et la valeur maximale est `100`. S'applique uniquement lorsque `scope` a la valeur `code`. |

Les résultats sont regroupés par fichier. Chaque fichier inclut des plages de lignes fusionnées avec le contenu et un score de pertinence. Pour de meilleurs résultats, décrivez la fonctionnalité ou le comportement qui vous intéresse plutôt que d'utiliser des mots-clés génériques ou des noms de fonction ou de variable spécifiques.

Exemple :

```plaintext
How are authorizations managed in this project?
```

## `attach_scan_profile` {#attach_scan_profile}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/240685) dans GitLab 19.2.

{{< /history >}}

Associe le profil d'analyse de sécurité donné aux projets spécifiés, ou à tous les projets appartenant aux groupes spécifiés.

Cet outil n'est répertorié que lorsque la fonctionnalité sous licence est disponible pour vous. Pour plus d'informations, voir [sélectionner des groupes d'outils](mcp_server.md#select-tool-groups-toolsets).

| Paramètre                  | Type             | Obligatoire | Description |
|----------------------------|------------------|----------|-------------|
| `security_scan_profile_id` | Chaîne           | Oui      | ID global du profil d'analyse de sécurité (par exemple, `gid://gitlab/Security::ScanProfile/1`). |
| `project_ids`              | Tableau de chaînes de caractères | Non       | Tableau d'ID globaux de projets (par exemple, `[gid://gitlab/Project/1]`). Ce paramètre est obligatoire sauf si `group_ids` est renseigné. |
| `group_ids`                | Tableau de chaînes de caractères | Non       | Tableau d'ID globaux de groupes (par exemple, `[gid://gitlab/Group/1]`). Ce paramètre est obligatoire sauf si `project_ids` est renseigné. |

Exemple :

```plaintext
Attach `gid://gitlab/Security::ScanProfile/1` to all projects under `gid://gitlab/Group/1`.
```
