---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Fonctions GLQL
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduite](https://gitlab.com/groups/gitlab-org/-/work_items/14767) dans GitLab 17.4 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `glql_integration`. Fonctionnalité désactivée par défaut.
- Activée sur GitLab.com dans GitLab 17.4 pour un sous-ensemble de groupes et de projets.
- [Passée](https://gitlab.com/gitlab-org/gitlab/-/issues/476990) de version expérimentale à [version bêta](../../policy/development_stages_support.md#beta) dans GitLab 17.10.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/work_items/476990) dans GitLab 17.10.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/554870) dans GitLab 18.3. Suppression du feature flag `glql_integration`.

{{< /history >}}

Utilisez des fonctions avec le [langage de requête GitLab (GLQL)](_index.md) pour créer des requêtes dynamiques.

## Fonctions dans une requête {#functions-inside-query}

Pour rendre une requête spécifique à un contexte, utilisez des fonctions dans une [requête](_index.md#query-syntax), par exemple en filtrant par utilisateur actuel ou par date.

### Utilisateur actuel {#current-user}

**Nom de la fonction** : `currentUser`

**Paramètres** : Aucune

**Syntaxe** : `currentUser()`

**Description** : correspond à l'utilisateur authentifié actuel.

**Informations complémentaires** :

- L'utilisation de cette fonction dans une requête entraîne l'échec de la requête pour les utilisateurs non authentifiés.

**Exemples** :

- Lister tous les tickets dont l'utilisateur authentifié actuel est le responsable :

  ```plaintext
  assignee = currentUser()
  ```

- Lister toutes les merge requests dont l'utilisateur authentifié actuel est le responsable mais pas l'auteur :

  ```plaintext
  type = MergeRequest and assignee = currentUser() and author != currentUser()
  ```

### Aujourd'hui {#today}

**Nom de la fonction** : `today`

**Paramètres** : Aucune

**Syntaxe** : `today()`

**Description** : correspond à la date du jour à 00:00 dans le fuseau horaire de l'utilisateur.

**Informations complémentaires** :

- Lorsqu'elle est utilisée avec l'opérateur `=`, la plage horaire est considérée de 00:00 à 23:59 dans le fuseau horaire de l'utilisateur.

**Exemples** :

- Lister tous les tickets créés aujourd'hui :

  ```plaintext
  created = today()
  ```

- Lister toutes les merge requests fusionnées aujourd'hui :

  ```plaintext
  type = MergeRequest and merged = today()
  ```

## Fonctions dans les vues intégrées {#functions-in-embedded-views}

Pour dériver une nouvelle colonne à partir d'un champ existant d'une [vue intégrée](_index.md#embedded-views), incluez des fonctions dans le paramètre `fields`.

### Extraire des labels dans une nouvelle colonne {#extract-labels-into-a-new-column}

**Nom de la fonction** : `labels`

**Paramètres** : une ou plusieurs valeurs `String`

**Syntaxe** : `labels("field1", "field2")`

**Description** :

La fonction `labels` prend en paramètres une ou plusieurs valeurs de chaîne de noms de labels, et crée une colonne filtrée contenant uniquement ces labels sur les tickets. La fonction fonctionne également comme un extracteur : si un label a été extrait, il n'apparaît plus dans la colonne `labels` habituelle, si vous choisissez d'afficher également cette colonne.

**Informations complémentaires** :

- Par défaut, cette fonction recherche une correspondance exacte avec le nom du label. Utilisez un caractère générique (`*`) dans la chaîne pour correspondre à n'importe quel caractère.
- Un minimum de 1 et un maximum de 100 noms de labels peuvent être transmis à la fonction `labels`.
- Les noms de labels transmis à cette fonction ne sont pas sensibles à la casse. Par exemple, `Deliverable` et `deliverable` sont équivalents.

**Exemples** :

- Inclure tous les labels à portée limitée `workflow` dans la colonne :

  ```plaintext
  labels("workflow::*")
  ```

- Inclure les labels `Deliverable`, `Stretch` et `Spike` :

  ```plaintext
  labels("Deliverable", "Stretch", "Spike")
  ```

- Inclure tous les labels tels que `backend`, `frontend` et autres se terminant par `end` :

  ```plaintext
  labels("*end")
  ```

Pour inclure la fonction `labels` dans une vue intégrée :

````markdown
```glql
display: list
fields: title, health, due, labels("workflow::*"), labels
limit: 5
query: project = "gitlab-org/gitlab" AND assignee = currentUser() AND state = opened
```
````
