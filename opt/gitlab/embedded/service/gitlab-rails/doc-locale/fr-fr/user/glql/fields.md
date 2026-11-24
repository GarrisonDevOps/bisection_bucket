---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Champs GLQL
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/14767) dans GitLab 17.4 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `glql_integration`. Fonctionnalité désactivée par défaut.
- Activé sur GitLab.com dans GitLab 17.4 pour un sous-ensemble de groupes et de projets.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/476990) de version expérimentale à [version bêta](../../policy/development_stages_support.md#beta) dans GitLab 17.10.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/work_items/476990) dans GitLab 17.10.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/554870) dans GitLab 18.3. Suppression du feature flag `glql_integration`.

{{< /history >}}

Avec le langage de requête GitLab (GLQL), les champs sont utilisés pour :

- Filtrer les résultats retournés par une [requête GLQL](_index.md#query-syntax).
- Contrôler les détails affichés dans une [vue intégrée](_index.md#presentation-syntax).
- Trier les résultats affichés dans une vue intégrée.

Vous utilisez les champs dans trois paramètres de vue intégrée :

- **`query`** - Définir les conditions permettant de déterminer les éléments à récupérer. Le paramètre `query` peut inclure une ou plusieurs expressions au format `<field> <operator> <value>`. Les expressions multiples sont jointes avec `and`, par exemple, `group = "gitlab-org" and author = currentUser()`.
- **`fields`** - Spécifier les colonnes et les détails qui apparaissent dans votre vue. Une liste de champs ou de [fonctions de champs](functions.md#functions-in-embedded-views) séparés par des virgules, par exemple, `fields: title, state, health, epic, milestone, weight, updated`.
- **`sort`** - Classer les éléments selon des critères spécifiques. Un nom de champ suivi d'un ordre de tri (`asc` ou `desc`), par exemple, `sort: updated desc`.

## Sources de données {#data-sources}

Pour obtenir la liste des sources de données prises en charge et leurs champs, consultez [les sources de données GLQL](data_sources/_index.md).

## Dépannage {#troubleshooting}

### Erreurs d'expiration des requêtes {#query-timeout-errors}

Vous pourriez rencontrer ces messages d'erreur :

```plaintext
Embedded view timed out. Add more filters to reduce the number of results.
```

```plaintext
Query temporarily blocked due to repeated timeouts. Please try again later or try narrowing your search scope.
```

Ces erreurs surviennent lorsque l'exécution de votre requête prend trop de temps. Les ensembles de résultats volumineux et les recherches étendues peuvent provoquer des délais d'expiration.

Pour résoudre ce problème, ajoutez des filtres afin de limiter la portée de votre recherche :

- Ajoutez des filtres de plage de dates pour limiter les résultats à une période spécifique, en utilisant des champs de date tels que `created`, `updated` ou `closed`. Par exemple :

  ````yaml
  ```glql
  display: table
  fields: title, labels, created
  query: type = Issue and group = "gitlab-org" and label = "group::planner intelligence" and created > "2025-01-01" and created < "2025-03-01"
  ```
  ````

- Filtrer par mises à jour récentes pour se concentrer sur les éléments actifs :

  ````yaml
  ```glql
  display: table
  fields: title, labels, updated
  query: type = Issue and group = "gitlab-org" and label = "group::planner intelligence" and updated > -3m
  ```
  ````

- Utiliser des requêtes spécifiques à un projet plutôt que des recherches à l'échelle du groupe lorsque cela est possible :

  ````yaml
  ```glql
  display: table
  fields: title, state, assignee
  query: type = Issue and project = "gitlab-org/gitlab" and state = opened and updated > -1m
  ```
  ````
