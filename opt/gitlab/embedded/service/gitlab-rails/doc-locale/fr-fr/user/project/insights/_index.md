---
stage: Analytics
group: Optimize
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Informations
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les analyses sont des graphiques à barres interactifs qui affichent le nombre d'éléments (par exemple, les bugs créés) par mois.

Configurez les analyses et créez des rapports personnalisés pour vos projets et groupes afin d'explorer des données telles que :

- Les tickets créés et fermés au cours d'une période donnée.
- Le délai moyen de fusion des merge requests.
- Hygiène de triage.

## Afficher les analyses {#view-insights}

Prérequis :

- Pour les analyses de projet, vous devez avoir accès au projet et l'autorisation de consulter les informations sur ses merge requests et ses tickets.
- Pour les analyses de groupe, vous devez avoir l'autorisation de consulter le groupe.

Pour afficher les analyses d'un projet ou d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Analyses**.
1. Pour afficher un rapport, dans la liste déroulante **Sélectionner un rapport**, sélectionnez le rapport que vous souhaitez afficher. Pour afficher les annotations, survolez chaque barre du graphique.
1. Facultatif. Filtrez les résultats :
   - Pour afficher uniquement les données d'une partie de la plage de 90 jours, sélectionnez les icônes de pause ({{< icon name="status-paused" >}}) et faites-les glisser le long de l'axe horizontal.
   - Pour exclure une dimension du graphique, sélectionnez le nom de la dimension dans la légende sous le graphique.

### Exploration des graphiques {#drill-down-on-charts}

Vous pouvez explorer les données de tous les graphiques dont `query.data_source` est `issuables`.

Pour afficher un rapport détaillé des données pour une priorité ou une gravité spécifique au cours d'un mois :

- Sur le graphique, sélectionnez la barre empilée sur laquelle vous souhaitez effectuer une exploration.

### Créer un lien profond vers un rapport {#create-a-report-deep-link}

Vous pouvez diriger les utilisateurs vers un rapport spécifique dans les analyses en utilisant l'URL en lien profond.

Pour créer un lien profond, ajoutez la clé du rapport à la fin de l'URL du rapport d'analyses. Par exemple, un rapport GitLab avec la clé `bugsCharts` a l'URL de lien profond `https://gitlab.com/gitlab-org/gitlab/insights/#/bugsCharts`.

## Configuration {#configuration}

### Fichier par défaut {#default-file}

GitLab lit les analyses depuis le [fichier de configuration par défaut](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/fixtures/insights/default.yml).

Les analyses de projet sont configurées avec le fichier [`.gitlab/insights.yml`](#configuration) dans le projet. Si un projet ne dispose pas d'un fichier de configuration, il utilise la [configuration du groupe](#for-groups).

Le fichier `.gitlab/insights.yml` est un fichier YAML dans lequel vous définissez :

- La structure et l'ordre des graphiques dans un rapport.
- Le style des graphiques affichés dans le rapport de votre projet ou groupe.

Dans le fichier `.gitlab/insights.yml` :

- Les [paramètres de configuration](#parameters) définissent le comportement du graphique.
- Chaque rapport possède une clé unique et un ensemble de graphiques à récupérer et afficher.
- Chaque définition de graphique est composée d'un hash constitué de paires clé-valeur.

#### Exemple {#example}

L'exemple suivant présente une définition unique qui affiche un rapport avec un seul graphique :

```yaml
bugsCharts:
  title: "Charts for bugs"
  charts:
    - title: "Monthly bugs created"
      description: "Open bugs created per month"
      type: bar
      query:
        data_source: issuables
        params:
          issuable_type: issue
          issuable_state: opened
          filter_labels:
            - bug
          group_by: month
          period_limit: 24
```

L'exemple suivant présente une configuration complète pour un fichier `.gitlab/insights.yml` qui affiche trois graphiques :

```yaml
.projectsOnly: &projectsOnly
  projects:
    only:
      - 3
      - groupA/projectA
      - groupA/subgroupB/projectC

bugsCharts:
  title: "Charts for bugs"
  charts:
    - title: "Monthly bugs created"
      description: "Open bugs created per month"
      type: bar
      <<: *projectsOnly
      query:
        data_source: issuables
        params:
          issuable_type: issue
          issuable_state: opened
          filter_labels:
            - bug
          group_by: month
          period_limit: 24

    - title: "Weekly bugs by severity"
      type: stacked-bar
      <<: *projectsOnly
      query:
        data_source: issuables
        params:
          issuable_type: issue
          issuable_state: opened
          filter_labels:
            - bug
          collection_labels:
            - S1
            - S2
            - S3
            - S4
          group_by: week
          period_limit: 104

    - title: "Monthly bugs by team"
      type: line
      <<: *projectsOnly
      query:
        data_source: issuables
        params:
          issuable_type: merge_request
          issuable_state: opened
          filter_labels:
            - bug
          collection_labels:
            - Manage
            - Plan
            - Create
          group_by: month
          period_limit: 24
```

### Paramètres {#parameters}

Le tableau suivant répertorie les paramètres du graphique :

| Mot-clé                                            | Description |
|:---------------------------------------------------|:------------|
| [`title`](#title)                                  | Le titre du graphique. Celui-ci s'affiche sur la page Analyses. |
| [`description`](#description)                      | Une description pour le graphique individuel. Celle-ci s'affiche au-dessus du graphique concerné. |
| [`type`](#type)                                    | Le type de graphique : `bar`, `line` ou `stacked-bar`. |
| [`query`](#query)                                  | Un hash qui définit la source de données et les conditions de filtrage pour le graphique. |

#### `title` {#title}

Utilisez `title` pour mettre à jour le titre du graphique. Le titre s'affiche dans le rapport d'analyses.

**Exemple** :

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
```

#### `description` {#description}

Utilisez `description` pour ajouter une description du graphique. La description s'affiche au-dessus du graphique, sous le titre.

**Exemple** :

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
  description: "Open bugs created per month"
```

#### `type` {#type}

Utilisez `type` pour définir le type de graphique.

**Valeurs prises en charge** :

| Nom  | Exemple : |
| ----- | ------- |
| `bar` | ![Exemple de graphique à barres Analyses](img/insights_example_bar_chart_v11_10.png) |
| `bar` (série temporelle avec `group_by`) | ![Exemple de graphique à barres de série temporelle Analyses](img/insights_example_bar_time_series_chart_v11_10.png) |
| `line` | ![Exemple de graphique à barres empilées Analyses](img/insights_example_line_chart_v11_10.png) |
| `stacked-bar` | ![Exemple de graphique à barres empilées Analyses](img/insights_example_stacked_bar_chart_v11_10.png) |

La source de données `dora` prend en charge les [types de graphiques](#type) `bar` et `line`.

**Exemple** :

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
  type: bar
```

#### `query` {#query}

Utilisez `query` pour définir la source de données et les conditions de filtrage pour le graphique.

**Exemple** :

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
  description: "Open bugs created per month"
  type: bar
  query:
    data_source: issuables
    params:
      issuable_type: issue
      issuable_state: opened
      filter_labels:
        - bug
      collection_labels:
        - S1
        - S2
        - S3
        - S4
      group_by: week
      period_limit: 104
```

Le format hérité sans le paramètre `data_source` est toujours pris en charge :

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
  description: "Open bugs created per month"
  type: bar
  query:
    issuable_type: issue
    issuable_state: opened
    filter_labels:
      - bug
    collection_labels:
      - S1
      - S2
      - S3
      - S4
    group_by: week
    period_limit: 104
```

##### `query.data_source` {#querydata_source}

Utilisez `data_source` pour définir la source de données qui expose les données.

**Valeurs prises en charge** :

- `issuables` : expose les données des merge requests ou des tickets.
- `dora` : expose les métriques DORA.

##### Paramètres de requête `issuable` {#issuable-query-parameters}

###### `query.params.issuable_type` {#queryparamsissuable_type}

Utilisez `query.params.issuable_type` pour définir le type d'issuable pour lequel créer un graphique.

**Valeurs prises en charge** :

- `issue` : le graphique affiche les données des tickets.
- `merge_request` : le graphique affiche les données des merge requests.

###### `query.params.issuable_state` {#queryparamsissuable_state}

Utilisez `query.params.issuable_state` pour filtrer par état actuel de l'issuable interrogé.

Par défaut, le filtre d'état `opened` est appliqué.

**Valeurs prises en charge** :

- `opened` : tickets ou merge requests ouverts.
- `closed` : tickets ou merge requests fermés.
- `locked` : tickets ou merge requests dont la discussion est verrouillée.
- `merged` : merge requests fusionnées.
- `all` : tickets ou merge requests dans tous les états.

###### `query.params.filter_labels` {#queryparamsfilter_labels}

Utilisez `query.params.filter_labels` pour filtrer par labels appliqués à l'issuable interrogé.

Par défaut, aucun filtre de label n'est appliqué. Tous les labels définis doivent être appliqués à l'issuable pour qu'il soit sélectionné.

**Exemple** :

```yaml
monthlyBugsCreated:
  title: "Monthly regressions created"
  type: bar
  query:
    data_source: issuables
    params:
      issuable_type: issue
      issuable_state: opened
      filter_labels:
        - bug
        - regression
```

###### `query.params.collection_labels` {#queryparamscollection_labels}

Utilisez `query.params.collection_labels` pour regrouper les issuables par les labels configurés. Le regroupement n'est pas appliqué par défaut.

**Exemple** :

```yaml
weeklyBugsBySeverity:
  title: "Weekly bugs by severity"
  type: stacked-bar
  query:
    data_source: issuables
    params:
      issuable_type: issue
      issuable_state: opened
      filter_labels:
        - bug
      collection_labels:
        - S1
        - S2
        - S3
        - S4
```

###### `query.group_by` {#querygroup_by}

Utilisez `query.group_by` pour définir l'axe X du graphique.

**Valeurs prises en charge** :

- `day` : regrouper les données par jour.
- `week` : regrouper les données par semaine.
- `month` : regrouper les données par mois.

###### `query.period_limit` {#queryperiod_limit}

Utilisez `query.period_limit` pour définir jusqu'où dans le passé interroger les issuables (en utilisant `query.period_field`).

L'unité est liée à la valeur définie dans `query.group_by`. Par exemple, si vous avez défini `query.group_by: 'day'` et `query.period_limit: 365`, le graphique affiche les données des 365 derniers jours.

Par défaut, des valeurs par défaut sont appliquées en fonction du `query.group_by` que vous avez défini.

| `query.group_by` | Valeur par défaut |
| ---------------- | ------------- |
| `day`            | 30            |
| `week`           | 4             |
| `month`          | 12            |

##### `query.period_field` {#queryperiod_field}

Utilisez `query.period_field` pour définir le champ d'horodatage par lequel regrouper les issuables.

**Valeurs prises en charge** :

- `created_at` (par défaut) : regrouper les données à l'aide du champ `created_at`.
- `closed_at` : regrouper les données à l'aide du champ `closed_at` (pour les tickets uniquement).
- `merged_at` : regrouper les données à l'aide du champ `merged_at` (pour les merge requests uniquement).

Le `period_field` est automatiquement défini sur :

- `closed_at` si `query.issuable_state` est `closed`
- `merged_at` si `query.issuable_state` est `merged`
- `created_at` sinon

> [!note]
> Jusqu'à ce que [ce bug](https://gitlab.com/gitlab-org/gitlab/-/issues/26911) soit résolu, vous pourriez voir `created_at` à la place de `merged_at`. `created_at` est utilisé à la place.

##### Paramètres de requête `DORA` {#dora-query-parameters}

Utilisez des requêtes spécifiques à DORA avec la source de données `dora` pour créer une définition de graphique DORA.

**Exemple** :

```yaml
dora:
  title: "DORA charts"
  charts:
    - title: "DORA deployment frequency"
      type: bar # or line
      query:
        data_source: dora
        params:
          metric: deployment_frequency
          group_by: day
          period_limit: 10
      projects:
        only:
          - 38
    - title: "DORA lead time for changes"
      description: "DORA lead time for changes"
      type: bar
      query:
        data_source: dora
        params:
          metric: lead_time_for_changes
          group_by: day
          environment_tiers:
            - staging
          period_limit: 30
```

###### `query.metric` {#querymetric}

Utilisez `query.metric` pour définir les [métriques DORA](../../../api/dora/metrics.md#the-value-field) à interroger.

**Valeurs prises en charge** :

- `deployment_frequency` (par défaut)
- `lead_time_for_changes`
- `time_to_restore_service`
- `change_failure_rate`

###### `query.group_by` {#querygroup_by-1}

Utilisez `query.group_by` pour définir l'axe X de votre graphique.

**Valeurs prises en charge** :

- `day` (par défaut) : regrouper les données par jour.
- `month` : regrouper les données par mois.

###### `query.period_limit` {#queryperiod_limit-1}

Utilisez `query.period_limit` pour définir jusqu'où les métriques sont interrogées dans le passé (par défaut : 15). La période maximale est de 180 jours ou 6 mois.

###### `query.environment_tiers` {#queryenvironment_tiers}

Utilisez `query.environment_tiers` pour définir un tableau d'environnements à inclure dans le calcul.

**Valeurs prises en charge** :

- `production`(par défaut)
- `staging`
- `testing`
- `development`
- `other`

#### `projects` {#projects}

Utilisez `projects` pour limiter la source d'interrogation des issuables :

- Si `.gitlab/insights.yml` est utilisé pour les analyses d'un groupe, utilisez `projects` pour définir les projets depuis lesquels interroger les issuables. Par défaut, tous les projets du groupe sont utilisés.
- Si `.gitlab/insights.yml` est utilisé pour les analyses d'un projet, la spécification d'autres projets ne produit aucun résultat. Par défaut, le projet est utilisé.

##### `projects.only` {#projectsonly}

Utilisez `projects.only` pour spécifier les projets depuis lesquels les issuables sont interrogés.

Les projets répertoriés dans ce paramètre sont ignorés dans les cas suivants :

- Ils n'existent pas.
- L'utilisateur actuel ne dispose pas des autorisations suffisantes pour les lire.
- Ils sont en dehors du groupe.

**Exemple** :

```yaml
monthlyBugsCreated:
  title: "Monthly bugs created"
  description: "Open bugs created per month"
  type: bar
  query:
    data_source: issuables
    params:
      issuable_type: issue
      issuable_state: opened
      filter_labels:
        - bug
  projects:
    only:
      - 3                         # You can use the project ID
      - groupA/projectA           # Or full project path
      - groupA/subgroupB/projectC # Projects in subgroups can be included
      - groupB/project            # Projects outside the group will be ignored
```

### Configurer les analyses {#configure-insights}

Vous pouvez configurer les analyses pour les projets et les groupes. Après avoir créé un fichier `.gitlab/insights.yml` dans un projet, vous pouvez également l'utiliser pour le groupe du projet.

> [!note]
> Un fichier `.gitlab/insights.yml` personnalisé remplace la configuration par défaut. Pour conserver la configuration d'origine, copiez le contenu du [fichier de configuration par défaut](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/fixtures/insights/default.yml) comme base.

#### Pour les projets {#for-projects}

Prérequis :

- Vous devez disposer du rôle Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Pour configurer les analyses de projet, créez un fichier `.gitlab/insights.yml` de l'une des façons suivantes :

- Localement, dans le répertoire racine de votre projet, puis envoyez vos modifications.
- Depuis l'interface utilisateur :
  1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
  1. Au-dessus de la liste de fichiers, sélectionnez la branche vers laquelle vous souhaitez effectuer un commit, sélectionnez l'icône plus, puis sélectionnez **Nouveau fichier**.
  1. Pour le champ **Nom du fichier**, saisissez `.gitlab/insights.yml`.
  1. Dans l'éditeur de fichiers, saisissez la configuration. Consultez un [exemple de configuration](#example).
  1. Sélectionnez **Valider les modifications**.

#### Pour les groupes {#for-groups}

Prérequis :

- Un projet de votre groupe doit posséder un fichier `.gitlab/insights.yml`.

Pour configurer les analyses de groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Données d'analyse**.
1. Dans la section **Analyses**, sélectionnez un projet contenant le fichier de configuration `.gitlab/insights.yml`.
1. Sélectionnez **Enregistrer les modifications**.
