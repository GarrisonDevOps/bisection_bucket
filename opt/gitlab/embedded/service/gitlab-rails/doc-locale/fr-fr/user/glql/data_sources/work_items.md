---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Éléments de travail
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les éléments de travail incluent les types : `Issue`, `Incident`, `TestCase`, `Requirement`, `Task`, `Ticket`, `Objective`, `KeyResult` et `Epic`.

> [!note]
> L'interrogation des epics est disponible uniquement dans les éditions Premium et Ultimate.

## Portées autorisées {#allowed-scopes}

| Portée     | Description                                      |
| --------- | ------------------------------------------------ |
| `project` | Interroger les éléments de travail dans un projet spécifique.          |
| `group`   | Interroger les éléments de travail dans tous les projets d'un groupe, y compris les sous-groupes. |

Pour plus d'informations, consultez [les portées](_index.md#scopes).

## Filtres de requête {#query-filters}

Utilisez ces champs dans le paramètre `query` pour filtrer vos résultats.

| Champ                                                          | Nom (et alias)                             | Opérateurs                  | Types              |
| -------------------------------------------------------------- | -------------------------------------------- | -------------------------- | ------------------ |
| [Personnes assignées](#workitem-assignees)                               | `assignee`, `assignees`                      | `=`, `in`, `!=`            | Tous                |
| [Auteur](#workitem-author)                                     | `author`                                     | `=`, `in`, `!=`            | Tous                |
| [Cadence](#workitem-cadence)                                   | `cadence`                                    | `=`, `in`                  | Tous sauf Epic    |
| [Fermé le](#workitem-closed-at)                               | `closed`, `closedAt`                         | `=`, `>`, `<`, `>=`, `<=`  | Tous                |
| [Confidentiel](#workitem-confidential)                         | `confidential`                               | `=`, `!=`                  | Tous                |
| [Créé le](#workitem-created-at)                             | `created`, `createdAt`, `opened`, `openedAt` | `=`, `>`, `<`, `>=`, `<=`  | Tous                |
| [Champ personnalisé](#workitem-custom-field)                         | `customField("Field name")`                  | `=`                        | Tous                |
| [Date d'échéance](#workitem-due-date)                                 | `due`, `dueDate`                             | `=`, `>`, `<`, `>=`, `<=`  | Tous                |
| [Epic](#workitem-epic)                                         | `epic`                                       | `=`, `!=`                  | Tous sauf Epic    |
| [Statut de santé](#workitem-health-status)                       | `health`, `healthStatus`                     | `=`, `!=`                  | Tous                |
| [ID](#workitem-identifier)                                     | `id`                                         | `=`, `in`                  | Tous                |
| [Inclure les sous-groupes](#workitem-include-subgroups)               | `includeSubgroups`                           | `=`, `!=`                  | Tous                |
| [Itération](#workitem-iteration)                               | `iteration`                                  | `=`, `in`, `!=`            | Tous sauf Epic    |
| [Labels](#workitem-labels)                                     | `label`, `labels`                            | `=`, `in`, `!=`            | Tous                |
| [Jalon](#workitem-milestone)                               | `milestone`                                  | `=`, `in`, `!=`            | Tous                |
| [Mon emoji de réaction](#workitem-my-reaction-emoji)               | `myReaction`, `myReactionEmoji`              | `=`, `!=`                  | Tous                |
| [Parent](#workitem-parent)                                     | `parent`                                     | `=`, `!=`                  | Tous sauf Epic    |
| [État](#workitem-state)                                       | `state`                                      | `=`                        | Tous                |
| [Statut](#workitem-status)                                     | `status`                                     | `=`                        | Tous sauf Epic    |
| [Abonné](#workitem-subscribed)                             | `subscribed`                                 | `=`, `!=`                  | Tous                |
| [Mis à jour le](#workitem-updated-at)                             | `updated`, `updatedAt`                       | `=`, `>`, `<`, `>=`, `<=`  | Tous                |
| [Poids](#workitem-weight)                                     | `weight`                                     | `=`, `!=`                  | Tous sauf Epic    |

### Personnes assignées {#workitem-assignees}

{{< history >}}

- L'alias `assignees` a été [introduit](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) dans GitLab 18.0.
- La prise en charge de l'interrogation des epics par personnes assignées a été [introduite](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) dans GitLab 18.3.

{{< /history >}}

**Description** : interroger les éléments de travail par un ou plusieurs utilisateurs qui leur sont assignés.

**Types de valeurs autorisés** :

- `String`
- `User` (par exemple, `@username`)
- `List` (contenant des valeurs `String` ou `User`)
- `Nullable` (l'une des valeurs `null`, `none` ou `any`)

### Auteur {#workitem-author}

{{< history >}}

- La prise en charge de l'interrogation des epics par auteur a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) dans GitLab 18.1.
- La prise en charge de l'opérateur `in` a été [introduite](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/221) dans GitLab 18.3.

{{< /history >}}

**Description** : interroger les éléments de travail par leur auteur.

**Types de valeurs autorisés** :

- `String`
- `User` (par exemple, `@username`)
- `List` (contenant des valeurs `String` ou `User`)

### Cadence {#workitem-cadence}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab-query-language/glql-haskell/-/issues/74) dans GitLab 17.6.

{{< /history >}}

**Description** : interroger les éléments de travail, à l'exception des epics, par la [cadence](../../group/iterations/_index.md#iteration-cadences) dont fait partie l'itération de l'élément de travail.

**Types de valeurs autorisés** :

- `Number` (entiers positifs uniquement)
- `List` (contenant des valeurs `Number`)
- `Nullable` (l'une des valeurs `none` ou `any`)

**Notes** :

- Étant donné qu'un élément de travail ne peut avoir qu'une seule itération, l'opérateur `=` ne peut pas être utilisé avec le type `List` pour le champ `cadence`.

### Fermé le {#workitem-closed-at}

{{< history >}}

- L'alias `closedAt` a été [introduit](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) dans GitLab 18.0.
- Les opérateurs `>=` et `<=` ont été [introduits](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/work_items/58) dans GitLab 18.0.
- La prise en charge de l'interrogation des epics par date de fermeture a été [introduite](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) dans GitLab 18.3.

{{< /history >}}

**Description** : interroger les éléments de travail par la date à laquelle ils ont été fermés.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-` ou omis, le chiffre est un entier, et `unit` est l'une des valeurs `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

**Notes** :

- Pour l'opérateur `=`, la plage horaire est considérée de 00:00 à 23:59 dans le fuseau horaire de l'utilisateur.

### Confidentiel {#workitem-confidential}

{{< history >}}

- La prise en charge de l'interrogation des epics par leur confidentialité a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) dans GitLab 18.1.

{{< /history >}}

**Description** : interroger les éléments de travail par leur visibilité aux membres du projet.

**Types de valeurs autorisés** :

- `Boolean` (l'une des valeurs `true` ou `false`)

**Notes** :

- Les éléments de travail confidentiels interrogés via GLQL ne sont visibles que par les personnes autorisées à les consulter.

### Créé le {#workitem-created-at}

{{< history >}}

- Les alias `createdAt`, `opened` et `openedAt` ont été [introduits](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) dans GitLab 18.0.
- Les opérateurs `>=` et `<=` ont été [introduits](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/work_items/58) dans GitLab 18.0.
- La prise en charge de l'interrogation des epics par date de création a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) dans GitLab 18.1.

{{< /history >}}

**Description** : interroger les éléments de travail par la date à laquelle ils ont été créés.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-` ou omis, le chiffre est un entier, et `unit` est l'une des valeurs `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

**Notes** :

- Pour l'opérateur `=`, la plage horaire est considérée de 00:00 à 23:59 dans le fuseau horaire de l'utilisateur.

### Champ personnalisé {#workitem-custom-field}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/glql/-/merge_requests/233) dans GitLab 18.3.

{{< /history >}}

**Description** : interroger les éléments de travail par [champs personnalisés](../../work_items/custom_fields.md).

**Types de valeurs autorisés** :

- `String` (pour les champs personnalisés à sélection unique)
- `List` (de `String`, pour les champs personnalisés à sélection multiple)

**Notes** :

- Les noms et valeurs des champs personnalisés ne sont pas sensibles à la casse.

### Date d'échéance {#workitem-due-date}

{{< history >}}

- L'alias `dueDate` a été [introduit](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) dans GitLab 18.0.
- Les opérateurs `>=` et `<=` ont été [introduits](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/work_items/58) dans GitLab 18.0.
- La prise en charge de l'interrogation des epics par date d'échéance a été [introduite](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) dans GitLab 18.3.

{{< /history >}}

**Description** : interroger les éléments de travail par la date à laquelle ils sont dus.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-` ou omis, le chiffre est un entier, et `unit` est l'une des valeurs `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

**Notes** :

- Pour l'opérateur `=`, la plage horaire est considérée de 00:00 à 23:59 dans le fuseau horaire de l'utilisateur.

### Epic {#workitem-epic}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/issues/30) dans GitLab 18.1.

{{< /history >}}

**Description** : interroger les éléments de travail par l'identifiant ou la référence de leur epic parent.

**Types de valeurs autorisés** :

- `Number` (identifiant de l'epic)
- `String` (contenant une référence d'epic comme `&123`)
- `Epic` (par exemple, `&123`, `gitlab-org&123`)

### Statut de santé {#workitem-health-status}

{{< details >}}

- Édition : GitLab Ultimate

{{< /details >}}

{{< history >}}

- L'alias `healthStatus` a été [introduit](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) dans GitLab 18.0.
- La prise en charge de l'interrogation des epics par statut de santé a été [introduite](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) dans GitLab 18.3.

{{< /history >}}

**Description** : interroger les éléments de travail par leur statut de santé.

**Types de valeurs autorisés** :

- `StringEnum` (l'une des valeurs `"needs attention"`, `"at risk"` ou `"on track"`)
- `Nullable` (l'une des valeurs `null`, `none` ou `any`)

### ID {#workitem-identifier}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/glql/-/merge_requests/92) dans GitLab 17.8.
- La prise en charge de l'interrogation des epics par identifiant a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) dans GitLab 18.1.

{{< /history >}}

**Description** : interroger les éléments de travail par leurs identifiants.

**Types de valeurs autorisés** :

- `Number` (entiers positifs uniquement)
- `List` (contenant des valeurs `Number`)

### Inclure les sous-groupes {#workitem-include-subgroups}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/glql/-/merge_requests/106) dans GitLab 17.10.
- La prise en charge de ce champ avec les epics a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) dans GitLab 18.1.

{{< /history >}}

**Description** : interroger les éléments de travail dans l'ensemble de la hiérarchie d'un groupe.

**Types de valeurs autorisés** :

- `Boolean` (l'une des valeurs `true` ou `false`)

**Notes** :

- Ce champ ne peut être utilisé qu'avec une portée `group`.
- La valeur par défaut de ce champ est `false`.

### Itération {#workitem-iteration}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab-query-language/glql-haskell/-/issues/74) dans GitLab 17.6.
- La prise en charge des types de valeurs d'itération a été [introduite](https://gitlab.com/gitlab-org/glql/-/merge_requests/79) dans GitLab 17.8.

{{< /history >}}

**Description** : interroger les éléments de travail, à l'exception des epics, par leur [itération](../../group/iterations/_index.md) associée.

**Types de valeurs autorisés** :

- `Number` (entiers positifs uniquement)
- `Iteration` (par exemple, `*iteration:123456`)
- `List` (contenant des valeurs `Number` ou `Iteration`)
- `Enum` (seul `current` est pris en charge)
- `Nullable` (l'une des valeurs `none` ou `any`)

**Notes** :

- Étant donné qu'un élément de travail ne peut avoir qu'une seule itération, l'opérateur `=` ne peut pas être utilisé avec le type `List` pour le champ `iteration`.

### Labels {#workitem-labels}

{{< history >}}

- La prise en charge des types de valeurs de label a été [introduite](https://gitlab.com/gitlab-org/glql/-/merge_requests/79) dans GitLab 17.8.
- L'alias `labels` a été [introduit](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) dans GitLab 18.0.
- La prise en charge de l'interrogation des epics par labels a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) dans GitLab 18.1.

{{< /history >}}

**Description** : interroger les éléments de travail par leurs labels associés.

**Types de valeurs autorisés** :

- `String`
- `Label` (par exemple, `~bug`, `~"team::planning"`)
- `List` (contenant des valeurs `String` ou `Label`)
- `Nullable` (l'une des valeurs `none` ou `any`)

**Notes** :

- Les labels à portée limitée ou les labels contenant des espaces doivent être encadrés de guillemets.

### Jalon {#workitem-milestone}

{{< history >}}

- La prise en charge des types de valeurs de jalon a été [introduite](https://gitlab.com/gitlab-org/glql/-/merge_requests/77) dans GitLab 17.8.
- La prise en charge de l'interrogation des epics par jalon a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) dans GitLab 18.1.

{{< /history >}}

**Description** : interroger les éléments de travail par leur jalon associé.

**Types de valeurs autorisés** :

- `String`
- `Milestone` (par exemple, `%Backlog`, `%"Awaiting Further Demand"`)
- `List` (contenant des valeurs `String` ou `Milestone`)
- `Nullable` (l'une des valeurs `none` ou `any`)

**Notes** :

- Les jalons contenant des espaces doivent être encadrés de guillemets (`"`).
- Étant donné qu'un élément de travail ne peut avoir qu'un seul jalon, l'opérateur `=` ne peut pas être utilisé avec le type `List` pour le champ `milestone`.
- Le type `Epic` ne prend pas en charge les filtres de jalon génériques tels que `none` ou `any`.

### Mon emoji de réaction {#workitem-my-reaction-emoji}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/glql/-/merge_requests/223) dans GitLab 18.3.

{{< /history >}}

**Description** : interroger les éléments de travail par la [réaction emoji](../../emoji_reactions.md) de l'utilisateur actuel sur ceux-ci.

**Types de valeurs autorisés** : `String`

### Parent {#workitem-parent}

**Description** : interroger les éléments de travail, à l'exception des epics, par leur élément de travail parent ou epic.

**Types de valeurs autorisés** :

- `Number` (identifiant du parent)
- `String` (contenant une référence comme `#123`)
- `WorkItem` (par exemple, `#123`, `gitlab-org/gitlab#123`)
- `Epic` (par exemple, `&123`, `gitlab-org&123`)

### État {#workitem-state}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/glql/-/merge_requests/96) dans GitLab 17.8.
- La prise en charge de l'interrogation des epics par état a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) dans GitLab 18.1.

{{< /history >}}

**Description** : interroger les éléments de travail par état.

**Types de valeurs autorisés** :

- `Enum`, l'une des valeurs `opened`, `closed` ou `all`

**Notes** :

- Le champ `state` ne prend pas en charge l'opérateur `!=`.

### Statut {#workitem-status}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197407) dans GitLab 18.2.

{{< /history >}}

**Description :** Interroger les éléments de travail par leur statut.

**Types de valeurs autorisés :** `String`

### Abonné {#workitem-subscribed}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/glql/-/merge_requests/223) dans GitLab 18.3.

{{< /history >}}

**Description** : interroger les éléments de travail selon que l'utilisateur actuel a [activé ou désactivé les notifications](../../profile/notifications.md).

**Types de valeurs autorisés** : `Boolean`

### Mis à jour le {#workitem-updated-at}

{{< history >}}

- L'alias `updatedAt` a été [introduit](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/merge_requests/137) dans GitLab 18.0.
- Les opérateurs `>=` et `<=` ont été [introduits](https://gitlab.com/gitlab-org/gitlab-query-language/glql-rust/-/work_items/58) dans GitLab 18.0.
- La prise en charge de l'interrogation des epics par dernière mise à jour a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) dans GitLab 18.1.

{{< /history >}}

**Description** : interroger les éléments de travail par date de dernière mise à jour.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-` ou omis, le chiffre est un entier, et `unit` est l'une des valeurs `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

**Notes** :

- Pour l'opérateur `=`, la plage horaire est considérée de 00:00 à 23:59 dans le fuseau horaire de l'utilisateur.

### Poids {#workitem-weight}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

**Description** : interroger les éléments de travail, à l'exception des epics, par leur poids.

**Types de valeurs autorisés** :

- `Number` (entiers positifs ou 0 uniquement)
- `Nullable` (l'une des valeurs `null`, `none` ou `any`)

**Notes** :

- Les opérateurs de comparaison `<` et `>` ne peuvent pas être utilisés.

## Champs d'affichage {#display-fields}

{{< history >}}

- Le champ `iteration` a été [introduit](https://gitlab.com/gitlab-org/gitlab-query-language/glql-haskell/-/issues/74) dans GitLab 17.6.
- Le champ `lastComment` a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/512154) dans GitLab 17.11.
- La prise en charge des epics a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192680) dans GitLab 18.1.
- Le champ `status` a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197407) dans GitLab 18.2.
- Les champs `health` et `type` dans les epics ont été [introduits](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) dans GitLab 18.3.

{{< /history >}}

| Champ            | Nom ou alias                         | Types           | Description |
| ---------------- | ------------------------------------- | --------------- | ----------- |
| Personnes assignées        | `assignee`, `assignees`               | Tous             | Afficher les utilisateurs assignés à l'objet |
| Auteur           | `author`                              | Tous             | Afficher l'auteur de l'objet |
| Fermé le        | `closed`, `closedAt`                  | Tous             | Afficher le temps écoulé depuis la fermeture de l'objet |
| Couleur            | `color`                               | Epic uniquement       | Afficher la pastille de couleur associée à l'epic |
| Confidentiel     | `confidential`                        | Tous             | Afficher `Yes` ou `No` pour indiquer si l'objet est confidentiel |
| Créé le       | `created`, `createdAt`                | Tous             | Afficher le temps écoulé depuis la création de l'objet |
| Description      | `description`                         | Tous             | Afficher la description de l'objet |
| Date d'échéance         | `due`, `dueDate`                      | Tous             | Afficher le temps restant avant l'échéance de l'objet |
| Epic             | `epic`                                | Tous sauf Epic | Afficher un lien vers l'epic. Disponible dans les éditions Premium et Ultimate |
| Statut de santé    | `health`, `healthStatus`              | Tous             | Afficher un badge indiquant le statut de santé. Disponible dans l'édition Ultimate |
| ID               | `id`                                  | Tous             | Afficher l'identifiant de l'objet |
| Itération        | `iteration`                           | Tous sauf Epic | Afficher l'itération. Disponible dans les éditions Premium et Ultimate |
| Labels           | `label`, `labels`                     | Tous             | Afficher les labels. Peut accepter des paramètres pour filtrer des labels spécifiques, par exemple `labels("workflow::*", "backend")` |
| Dernier commentaire     | `lastComment`                         | Tous             | Afficher le dernier commentaire ajouté à l'objet |
| Jalon        | `milestone`                           | Tous             | Afficher le jalon associé à l'objet |
| Parent           | `parent`                              | Tous             | Afficher un lien vers l'élément de travail parent ou l'epic |
| Progression         | `progress`                            | Objectif et résultat clé uniquement | Afficher le pourcentage de progression (0-100) de l'élément de travail |
| Projet          | `project`                             | Tous sauf Epic | Afficher le projet auquel appartient l'élément de travail |
| Date de début       | `start`, `startDate`                  | Epic uniquement       | Afficher la date de début de l'epic |
| État            | `state`                               | Tous             | Afficher un badge indiquant l'état. Les valeurs sont `Open` ou `Closed` |
| Statut           | `status`                              | Tous sauf Epic | Afficher un badge indiquant le statut. Par exemple, « À faire » ou « Terminé ». Disponible dans les éditions Premium et Ultimate |
| Statut d'achèvement des tâches | `taskCompletionStatus`          | Tous             | Afficher l'achèvement des tâches sous forme de fraction (complétées/total) |
| Estimation du temps    | `timeEstimate`                        | Tous             | Afficher le temps estimé pour l'élément de travail |
| Titre            | `title`                               | Tous             | Afficher le titre de l'objet |
| Temps total passé | `totalTimeSpent`                      | Tous             | Afficher le temps total passé sur l'élément de travail |
| Type             | `type`                                | Tous             | Afficher le type d'élément de travail, par exemple `Issue`, `Task` ou `Objective` |
| Mis à jour le       | `updated`, `updatedAt`                | Tous             | Afficher le temps écoulé depuis la dernière mise à jour de l'objet |
| Poids           | `weight`                              | Tous sauf Epic | Afficher le poids. Disponible dans les éditions Premium et Ultimate |

## Champs de tri {#sort-fields}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/glql/-/merge_requests/178) dans GitLab 18.2.
- La prise en charge du tri des epics par statut de santé a été [introduite](https://gitlab.com/gitlab-org/glql/-/merge_requests/222) dans GitLab 18.3.

{{< /history >}}

| Champ         | Nom (et alias)         | Types           | Description                                     |
|---------------|--------------------------|-----------------|------------------------------------------------ |
| Fermé le     | `closed`, `closedAt`     | Tous             | Trier par date de fermeture                             |
| Créé       | `created`, `createdAt`   | Tous             | Trier par date de création                            |
| Date d'échéance      | `due`, `dueDate`         | Tous             | Trier par date d'échéance                                |
| Statut de santé | `health`, `healthStatus` | Tous             | Trier par statut de santé                           |
| Jalon     | `milestone`              | Tous sauf Epic | Trier par date d'échéance du jalon                      |
| Popularité    | `popularity`             | Tous             | Trier par nombre de réactions emoji « pouce vers le haut » |
| Date de début    | `start`, `startDate`     | Epic uniquement       | Trier par date de début                              |
| Titre         | `title`                  | Tous             | Trier par titre                                   |
| Mis à jour le    | `updated`, `updatedAt`   | Tous             | Trier par date de dernière mise à jour                       |
| Poids        | `weight`                 | Tous sauf Epic | Trier par poids                                  |

## Exemples {#examples}

- Lister tous les tickets du projet `gitlab-org/gitlab` triés par titre :

  ````yaml
  ```glql
  display: table
  fields: state, title, updated
  sort: title asc
  query: project = "gitlab-org/gitlab" and type = Issue
  ```
  ````

- Lister tous les epics du groupe `gitlab-org` triés par date de début (du plus ancien au plus récent) :

  ````yaml
  ```glql
  display: table
  fields: title, state, startDate
  sort: startDate asc
  query: group = "gitlab-org" and type = Epic
  ```
  ````

- Lister tous les tickets du groupe `gitlab-org` avec un poids assigné, triés par poids (du plus élevé au plus faible) :

  ````yaml
  ```glql
  display: table
  fields: title, weight, health
  sort: weight desc
  query: type = Issue and group = "gitlab-org" and weight = any
  ```
  ````

- Lister tous les tickets du groupe `gitlab-org` dont l'échéance est dans une semaine au plus à compter d'aujourd'hui, triés par date d'échéance (du plus proche au plus lointain) :

  ````yaml
  ```glql
  display: table
  fields: title, dueDate, assignee
  sort: dueDate asc
  query: type = Issue and group = "gitlab-org" and due >= today() and due <= 1w
  ```
  ````
