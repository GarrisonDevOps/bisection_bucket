---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: "Types d'affichage GLQL"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/14767) dans GitLab 17.4 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `glql_integration`. Fonctionnalité désactivée par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/554870) dans GitLab 18.3. Suppression du feature flag `glql_integration`.

{{< /history >}}

Un type d'affichage contrôle la façon dont une [vue intégrée](_index.md#embedded-views) affiche les résultats d'une requête GLQL. Définissez le type d'affichage avec le paramètre `display` dans la source de la vue.

Si vous ne définissez pas de paramètre `display`, les résultats s'affichent sous forme de liste.

Certains types d'affichage fonctionnent avec n'importe quelle requête. D'autres fonctionnent uniquement en [mode analytique](_index.md#analytics-mode), qui agrège les données en dimensions et en métriques.

Les types d'affichage suivants sont disponibles dans n'importe quel mode :

| Type d'affichage                  | Valeur `display` | Description |
| ----------------------------- | --------------- | ----------- |
| Tableau               | `table`         | Un tableau avec une ligne par résultat et une colonne par champ. |
| Liste                 | `list`          | Une liste non ordonnée de résultats. |
| Liste ordonnée | `orderedList`   | Une liste numérotée de résultats. |

Les types d'affichage suivants sont disponibles uniquement en mode analytique :

| Type d'affichage                  | Valeur `display` | Description |
| ----------------------------- | --------------- | ----------- |
| Statistique unique | `stat`          | Une métrique agrégée unique, affichée sous forme de grande valeur. |
| Graphique en colonnes | `columnChart`   | Un graphique qui compare des métriques selon les catégories définies par vos dimensions. |
| Graphique en barres | `barChart` | Un graphique horizontal qui compare des métriques selon les catégories définies par vos dimensions. |
| Liste de barres | `barList` | Un graphique horizontal qui affiche chaque valeur de dimension en tant que part du total. |
| Graphique en courbes     | `lineChart`     | Un graphique qui trace une ou plusieurs métriques sous forme de courbes sur une dimension, afin de visualiser les tendances. |
| Graphique en aires     | `areaChart`     | Un graphique qui trace une ou plusieurs métriques sous forme de zones remplies sur une dimension, afin de visualiser les tendances et les volumes. |
| Carte thermique     | `heatMap`     | Une grille de cellules ombrées, une par paire de valeurs de dimension, où une cellule plus sombre représente une valeur plus grande. |
| Graphique en barres divergentes | `divergingBarChart` | Un graphique qui reflète deux métriques autour d'une colonne de catégorie centrale partagée, chacune mise à l'échelle de sa propre barre la plus grande. |

## Tableau {#table}

{{< history >}}

- Les descriptions dynamiques et `hiddenMetrics` [introduites](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256879) dans GitLab 19.5.

{{< /history >}}

Un tableau affiche une ligne par résultat et une colonne par [champ](fields.md).

Pour trier un tableau par colonne, sélectionnez l'en-tête de colonne. Cette vue réorganise les lignes chargées dans la vue, et non l'ensemble de résultats complet.

Un tableau peut décrire son résultat. Cela nécessite le [mode analytique](_index.md#analytics-mode). Définissez `description` sous `displayConfig`, et définissez `hiddenMetrics` pour exclure une métrique des colonnes. Consultez [Descriptions dynamiques](#dynamic-descriptions) pour la syntaxe des espaces réservés et les règles associées.

### Exemple {#example}

Pour afficher les cinq premiers tickets ouverts assignés à l'utilisateur actuel dans le projet `gitlab-org/gitlab` sous forme de tableau, avec les colonnes `title`, `state`, `health`, `epic`, `milestone`, `weight` et `updated` :

````yaml
```glql
display: table
title: My open issues
fields: title, state, health, epic, milestone, weight, updated
limit: 5
query: type = Issue AND project = "gitlab-org/gitlab" AND assignee = currentUser() AND state = opened
```
````

## Liste {#list}

Une liste affiche les résultats sous forme de liste non ordonnée. Les listes sont le type d'affichage par défaut.

### Exemple {#example-1}

Pour afficher les cinq premiers tickets ouverts assignés à l'utilisateur actuel dans le projet `gitlab-org/gitlab` sous forme de liste, triés par date d'échéance avec les plus proches en premier, et affichant les champs `title`, `health` et `due` :

````yaml
```glql
display: list
fields: title, health, due
limit: 5
sort: due asc
query: type = Issue AND project = "gitlab-org/gitlab" AND assignee = currentUser() AND state = opened
```
````

## Liste ordonnée {#ordered-list}

Une liste ordonnée affiche les résultats sous forme de liste numérotée. Utilisez une liste ordonnée lorsque l'ordre des résultats est significatif, par exemple pour un classement.

### Exemple {#example-2}

Pour afficher les cinq premiers tickets ouverts assignés à l'utilisateur actuel dans le projet `gitlab-org/gitlab` sous forme de liste ordonnée, triés par date d'échéance avec les plus proches en premier, et affichant les champs `title`, `health` et `due` :

````yaml
```glql
display: orderedList
fields: title, health, due
limit: 5
sort: due asc
query: type = Issue AND project = "gitlab-org/gitlab" AND assignee = currentUser() AND state = opened
```
````

## Statistique unique {#single-stat}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241395) dans GitLab 19.2.
- Option d'affichage `compact` [introduite](https://gitlab.com/groups/gitlab-org/-/work_items/23470) dans GitLab 19.5.
- Descriptions dynamiques [introduites](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255287) dans GitLab 19.5.

{{< /history >}}

Une statistique unique visualise une métrique agrégée du [mode analytique](_index.md#analytics-mode) sous forme de grande valeur. Utilisez une statistique unique pour mettre en évidence un chiffre clé, tel qu'un total ou un taux.

Une statistique unique requiert :

- Le mode analytique, défini avec `mode: analytics`.
- Une ou plusieurs métriques, définies avec le paramètre `metrics`. La statistique affiche la valeur de la première métrique et ignore les autres, sauf si la description les référence.
- Aucun `dimensions`.

Les valeurs sont formatées automatiquement en fonction de la métrique. Par exemple, les dénombrements utilisent des séparateurs de milliers et les taux s'affichent en pourcentages. Pour afficher les nombres en notation compacte, par exemple `1.45M`, définissez `compact: true` sous `displayConfig`. Les taux conservent leur format en pourcentage, et les durées sont réduites à leur plus grande unité, par exemple `1h 1m 1s` devient `1h`.

Pour décrire la valeur, définissez `description` sous `displayConfig`. Consultez [Descriptions dynamiques](#dynamic-descriptions) pour la syntaxe des espaces réservés et les règles associées.

### Exemple {#example-3}

Pour afficher le nombre total de suggestions de code au cours des 30 derniers jours sous forme de statistique unique :

````yaml
```glql
display: stat
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
metrics: totalCount
```
````

Pour décrire la valeur avec les autres métriques sélectionnées par la requête :

````yaml
```glql
display: stat
displayConfig:
  description: "%{acceptedCount} of %{shownCount} suggestions accepted"
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
metrics: acceptanceRate, acceptedCount, shownCount
```
````

## Graphique en colonnes {#column-chart}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/21212) dans GitLab 19.1.
- L'option d'affichage `maxSeries` [introduite](https://gitlab.com/groups/gitlab-org/-/work_items/23470) dans GitLab 19.5.

{{< /history >}}

Un graphique en colonnes visualise les données agrégées du [mode analytique](_index.md#analytics-mode). Utilisez un graphique en colonnes pour comparer des métriques selon les catégories définies par vos dimensions.

Un graphique en colonnes requiert :

- Le mode analytique, défini avec `mode: analytics`.
- Une ou deux `dimensions` pour regrouper les résultats.
- Au moins une métrique à tracer (à l'aide du paramètre `metrics`).

Le nombre de dimensions et de métriques détermine la façon dont le graphique s'affiche :

- Une dimension avec une ou plusieurs métriques trace une colonne pour chaque métrique. Pour empiler ces colonnes, définissez `stacked: true` sous `displayConfig`. Avec une seule métrique, `stacked` n'a aucun effet visible.
- Deux dimensions avec une métrique tracent un graphique en colonnes empilées regroupées par la deuxième dimension. Avec deux dimensions, vous ne pouvez utiliser qu'une seule métrique, et GitLab ignore `displayConfig.stacked`.

Avec deux dimensions, l'option `maxSeries` sous `displayConfig` limite le nombre de valeurs de la deuxième dimension qui obtiennent leur propre segment. Les valeurs avec les totaux les plus élevés conservent le leur, et les autres sont regroupées dans un segment `Other (N)`. Une valeur unique dépassant la limite reste telle quelle. Sans `maxSeries`, chaque valeur obtient un segment. Une valeur `maxSeries` qui n'est pas un nombre entier supérieur à zéro est ignorée.

### Exemple {#example-4}

Pour afficher l'utilisation des suggestions de code par langue au cours des 30 derniers jours sous forme de graphique en colonnes :

````yaml
```glql
display: columnChart
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: totalCount
```
````

Pour empiler les métriques dans une seule colonne au lieu de les tracer côte à côte :

````yaml
```glql
display: columnChart
displayConfig:
  stacked: true
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: acceptedCount, rejectedCount
```
````

## Graphique en barres {#bar-chart}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/21212) dans GitLab 19.2.
- Options d'affichage `categoryLabels`, `colorBy` et `showAxisTitles` [introduites](https://gitlab.com/gitlab-org/gitlab/-/work_items/628025) dans GitLab 19.4.

{{< /history >}}

Un graphique en barres visualise les données agrégées du [mode analytique](_index.md#analytics-mode) sous forme de barres horizontales. Utilisez un graphique en barres pour comparer des métriques selon les catégories définies par vos dimensions, en particulier lorsque les étiquettes de catégories sont longues.

Un graphique en barres requiert :

- Le mode analytique, défini avec `mode: analytics`.
- Une ou deux `dimensions` pour regrouper les résultats.
- Au moins une métrique à tracer (à l'aide du paramètre `metrics`).

Le nombre de dimensions et de métriques détermine la façon dont le graphique s'affiche :

- Une dimension avec une ou plusieurs métriques trace une barre pour chaque métrique. Pour empiler ces barres, définissez `stacked: true` sous `displayConfig`. Avec une seule métrique, `stacked` n'a aucun effet visible.
- Deux dimensions avec une métrique tracent un graphique en barres empilées regroupées par la deuxième dimension. Avec deux dimensions, vous ne pouvez utiliser qu'une seule métrique, et GitLab ignore `displayConfig.stacked`.

Un graphique en barres trace la première ligne en bas, donc triez par ordre croissant pour placer la valeur la plus grande en haut. Le graphique est aussi grand que ses lignes le nécessitent, jusqu'à la hauteur par défaut du graphique.

Un graphique en barres accepte également ces options sous `displayConfig` :

- `categoryLabels: valueAndShare` ajoute la valeur de chaque catégorie et sa part du total à l'étiquette de catégorie, par exemple `Returning · 1,555 · 78%`. La valeur par défaut, `plain`, affiche uniquement le nom de la catégorie. Elle s'applique uniquement aux métriques de dénombrement, telles que `usersCount`, `totalCount` ou `acceptedCount`, avec une dimension et une métrique, et est ignorée dans les autres cas. Le total est la somme des lignes affichées, de sorte que les parts s'additionnent toujours à 100 % de ce qui est affiché. La part n'est significative que lorsque chaque élément appartient à exactement une catégorie. Par exemple, avec `usersCount`, un utilisateur actif dans plusieurs catégories est comptabilisé une fois dans chaque ligne, de sorte que la part ne représente pas une part des utilisateurs. Lorsque la requête utilise un `limit`, le total ne couvre que les lignes affichées.
- `colorBy: category` attribue à chaque barre sa propre teinte unie à partir d'une palette de bleus, au lieu d'une seule couleur pour la série. La barre du dessus reçoit la teinte la plus marquée, la plus sombre en mode clair et la plus claire en mode sombre, afin que les barres restent lisibles dans les deux cas. Nécessite une dimension et une métrique, et est ignorée dans les autres cas.
- `showAxisTitles: false` masque les deux titres d'axe.

### Exemple {#example-5}

Pour afficher l'utilisation des suggestions de code par langue au cours des 30 derniers jours sous forme de graphique en barres :

````yaml
```glql
display: barChart
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: totalCount
```
````

Pour empiler les métriques dans une seule barre au lieu de les tracer côte à côte :

````yaml
```glql
display: barChart
displayConfig:
  stacked: true
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: acceptedCount, rejectedCount
```
````

Pour afficher la part des suggestions acceptées pour chaque langue sous forme de barre étiquetée et colorée individuellement, sans titres d'axe :

````yaml
```glql
display: barChart
displayConfig:
  categoryLabels: valueAndShare
  colorBy: category
  showAxisTitles: false
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: acceptedCount
sort: acceptedCount asc
```
````

## Liste de barres {#bar-list}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/623319) dans GitLab 19.4.
- Options d'affichage `valueLabels`, `color` et `scale` [introduites](https://gitlab.com/gitlab-org/gitlab/-/work_items/628026) dans GitLab 19.5.
- Lignes issues des métriques pour une requête sans dimension, et `color: gray`, [introduites](https://gitlab.com/gitlab-org/gitlab/-/work_items/628932) dans GitLab 19.5.
- Barres empilées à deux dimensions et option d'affichage `maxSeries` [introduites](https://gitlab.com/groups/gitlab-org/-/work_items/23470) dans GitLab 19.5.
- Option d'affichage `metricRows` [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/628025) dans GitLab 19.5.
- Les descriptions dynamiques et `hiddenMetrics` [introduites](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256879) dans GitLab 19.5.

{{< /history >}}

Une liste de barres visualise les données agrégées du [mode analytique](_index.md#analytics-mode) sous forme de barres horizontales. Par défaut, la longueur de chaque barre correspond au pourcentage de cette ligne par rapport au total de toutes les lignes, et non à une comparaison avec la ligne la plus grande. Une liste de barres répond à la question « quelle est la part de cet élément dans l'ensemble », tandis qu'un graphique en barres répond à la question « comment ces éléments se comparent-ils les uns aux autres ».

Une liste de barres requiert :

- Le mode analytique, défini avec `mode: analytics`.
- Jusqu'à deux valeurs `dimensions`.
- Au moins une métrique, définie avec le paramètre `metrics`.

Avec une dimension, chaque ligne est une valeur de cette dimension et la première métrique définit la valeur de la ligne. Une requête qui nomme plusieurs métriques affiche la première et ignore les autres. Les lignes sont triées par ordre décroissant de valeur. Plus de deux dimensions entraîne une erreur de validation dans la vue, tout comme plus d'une métrique associée à deux dimensions.

Sans dimension, chaque métrique devient une ligne, dans l'ordre où la requête les nomme. Utilisez cette option pour comparer des percentiles ou des dénombrements d'une même mesure, comme le médian et le 75e percentile du temps de fusion. La valeur de chaque ligne est formatée dans l'unité de sa métrique, de sorte qu'une durée s'affiche comme `9h 24m` plutôt que comme un nombre de millisecondes. Ces lignes conservent leur ordre, ne sont jamais regroupées dans une ligne `Other` et n'affichent aucune variation par rapport à la période précédente. Une métrique sans valeur dans la réponse, comme un percentile sur aucune merge request, s'affiche sous la forme d'un tiret cadratin (`—`) avec une barre vide.

Certaines métriques ne peuvent pas ignorer leur dimension. Une métrique qui compare un intervalle de temps avec le précédent, comme `returningUsersCount`, nécessite la dimension de date. Pour obtenir une ligne par métrique à partir d'une requête qui en possède une, définissez `metricRows: true` sous `displayConfig`. Les valeurs proviennent de la première ligne de la réponse, donc triez la requête pour placer la ligne souhaitée en premier.

Avec des dimensions, l'option `maxRows` sous `displayConfig` définit le nombre de lignes affichées par page. La valeur par défaut est six, et les lignes sont classées par valeur, de la plus haute à la plus basse. Lorsque la requête retourne davantage de lignes, les contrôles **Précédent** et **Suivant** permettent de naviguer dans les lignes déjà [récupérées automatiquement](#pagination-support), de sorte que le changement de page ne déclenche aucune nouvelle récupération. Cette récupération s'arrête à 1 000 lignes, de sorte que la pagination couvre au maximum les 1 000 premières lignes. Une ligne unique dépassant la taille de page reste sur la première page plutôt que de démarrer une page à elle seule. Les parts restent relatives au total de toutes les pages. Une valeur `maxRows` qui n'est pas un nombre entier supérieur à zéro revient à la valeur par défaut.

La part du total n'est significative que lorsque la métrique est un dénombrement ou une somme. Pour une métrique telle qu'une moyenne ou un médian, le total qui sous-tend les parts n'a aucune signification.

Une liste de barres sans dimension affiche une barre par métrique. Pour sélectionner une métrique uniquement pour la description, sans lui attribuer de barre, ajoutez-la à `hiddenMetrics` sous `displayConfig`. Consultez [Descriptions dynamiques](#dynamic-descriptions) pour la syntaxe des espaces réservés et les règles `hiddenMetrics`.

### Une dimension {#one-dimension}

Chaque ligne est une valeur de la dimension.

L'étiquette de chaque ligne affiche une valeur au-delà de la fin de la barre, contrôlée par `valueLabels` sous `displayConfig` :

- `valueLabels: shareAndValue` est la valeur par défaut. Elle affiche la part de la ligne dans le total ainsi qu'une valeur compacte, par exemple `89% · 85.6k`.
- `valueLabels: value` affiche uniquement la valeur de la ligne, en chiffres complets, par exemple `1,071`. Utilisez cette option lorsque le dénombrement importe davantage que la part.

La couleur des barres est définie par `color` sous `displayConfig` :

- `color: orange` est la valeur par défaut. Elle correspond à l'apparence existante.
- `color: blue` trace les barres dans le même bleu que les autres graphiques GLQL utilisent pour leur première série, la couleur par défaut de la palette de graphiques.
- `color: gray` trace des barres gris neutre, pour une ligne de base affichée à côté d'une liste colorée.

La longueur des barres est mesurée par rapport à une échelle, définie par `scale` sous `displayConfig` :

- `scale: total` est la valeur par défaut. La longueur d'une barre correspond à la part de la ligne dans le total de toutes les lignes, de sorte que la piste représente 100 % de l'ensemble et que l'espace après une barre correspond au reste du total.
- `scale: max` fait en sorte que la ligne la plus grande remplisse la piste, chaque autre barre étant dimensionnée par rapport à elle, afin que les barres comparent les lignes entre elles. Utilisez cette option lorsque les lignes sont nombreuses ou réparties de manière homogène, et que les parts du total laissent chaque barre courte.

L'étiquette n'est pas affectée par `scale` : avec `valueLabels: shareAndValue`, elle affiche toujours la part du total, quelle que soit la valeur de `scale`.

Toute autre valeur pour `valueLabels`, `color` ou `scale` entraîne une erreur de validation dans la vue.

### Deux dimensions {#two-dimensions}

Chaque ligne est une valeur de la première dimension, et sa barre se divise en segments empilés, un par valeur de la deuxième dimension, avec une légende sous le graphique. Les lignes sont étiquetées avec leur total compact.

L'option `maxSeries` sous `displayConfig` limite le nombre de valeurs de la deuxième dimension qui obtiennent leur propre segment ; les autres sont regroupées dans un segment `Other (N)`. Un segment unique dépassant la limite reste tel quel. La valeur par défaut est six.

Les pages de lignes utilisent le même `maxRows` et les mêmes contrôles qu'avec une dimension, chaque ligne conservant ses segments.

La sélection d'une entrée de légende masque ce segment et redimensionne les barres et les étiquettes restantes par rapport au total visible.

Les options `valueLabels`, `color` et `scale` ainsi que la comparaison avec la période précédente s'appliquent uniquement à une dimension.

### Exemples {#examples}

Pour afficher l'utilisation des suggestions de code par langue au cours des 30 derniers jours sous forme de liste de barres :

````yaml
```glql
display: barList
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: totalCount
```
````

Pour afficher plus que les six lignes par défaut :

````yaml
```glql
display: barList
displayConfig:
  maxRows: 10
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: totalCount
```
````

Pour afficher les sessions Duo Agent Platform par type de flow au cours des 30 derniers jours en bleu avec uniquement la valeur dans chaque étiquette, avec des barres dimensionnées par rapport à la ligne la plus grande plutôt qu'au total :

````yaml
```glql
display: barList
displayConfig:
  valueLabels: value
  color: blue
  scale: max
mode: analytics
query: type = AgentPlatformSession and created >= -30d
dimensions: flowType
metrics: usersCount
```
````

Pour comparer le médian et le 75e percentile du temps de fusion pour les merge requests fusionnées au cours des 30 derniers jours, avec une ligne par percentile et la barre la plus longue remplissant la piste :

````yaml
```glql
display: barList
displayConfig:
  valueLabels: value
  scale: max
mode: analytics
query: type = MergeRequest and merged >= -30d
metrics: timeToMergeQuantile(0.5) as "Median", timeToMergeQuantile(0.75) as "p75"
```
````

Pour répartir les utilisateurs actifs au cours d'une période entre ceux qui avaient également une session lors de la période précédente et ceux qui n'en avaient pas, avec une ligne pour chaque groupe. La requête couvre deux périodes consécutives de 30 jours, car `returningUsersCount` n'a rien à comparer sans la période précédente, et trie le dernier intervalle en premier afin que `metricRows` lise celui-ci. `origin` ancre les intervalles au début de la plage, afin qu'ils s'alignent sur elle plutôt que de compter depuis l'epoch Unix :

````yaml
```glql
display: barList
displayConfig:
  metricRows: true
mode: analytics
query: type = DuoWorkflow and created >= 2026-07-16 and created < 2026-09-14
dimensions: created(granularity=30d, origin=2026-07-16)
metrics: joinedUsersCount as "New", returningUsersCount as "Returning"
sort: created desc
```
````

Pour répartir les sessions de chaque utilisateur au cours des 30 derniers jours par type de flow, avec au maximum quatre types de flow dans leur propre segment :

````yaml
```glql
display: barList
displayConfig:
  maxSeries: 4
mode: analytics
query: type = AgentPlatformSession and created >= -30d
dimensions: user, flowType
metrics: totalCount
```
````

## Graphique en courbes {#line-chart}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/240016) dans GitLab 19.1.

{{< /history >}}

Un graphique en courbes visualise les données agrégées du [mode analytique](_index.md#analytics-mode) sous forme d'une ou plusieurs courbes. Utilisez un graphique en courbes pour montrer l'évolution des métriques sur une dimension, par exemple dans le temps.

Un graphique en courbes requiert :

- Le mode analytique, défini avec `mode: analytics`.
- Exactement une `dimension` pour l'axe des abscisses.
- Au moins une `metric` à tracer. Chaque métrique s'affiche sous la forme d'une courbe distincte.

### Exemple {#example-6}

Pour afficher l'utilisation des suggestions de code par langue au cours des 30 derniers jours sous forme de graphique en courbes, avec une courbe pour le total des suggestions et une pour les suggestions acceptées :

````yaml
```glql
display: lineChart
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: language
metrics: totalCount, acceptedCount
```
````

## Graphique en aires {#area-chart}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/glql/-/work_items/103) dans GitLab 19.3.

{{< /history >}}

Un graphique en aires visualise les données agrégées du [mode analytique](_index.md#analytics-mode) sous forme d'une ou plusieurs zones remplies. Utilisez un graphique en aires pour montrer l'évolution des métriques sur une dimension, par exemple dans le temps, et pour mettre en valeur le volume derrière la tendance.

Un graphique en aires requiert :

- Le mode analytique, défini avec `mode: analytics`.
- Une ou deux `dimensions` pour regrouper les résultats.
- Au moins une métrique à tracer (à l'aide du paramètre `metrics`).

Le nombre de dimensions et de métriques détermine la façon dont le graphique s'affiche :

- Une dimension avec une ou plusieurs métriques trace une aire pour chaque métrique. Les aires se chevauchent avec des remplissages semi-transparents. Pour empiler les aires de manière cumulative, définissez `stacked: true` sous `displayConfig`. Avec une seule métrique, `stacked` n'a aucun effet visible.
- Deux dimensions avec une métrique tracent un graphique en aires empilées regroupées par la deuxième dimension. Avec deux dimensions, vous ne pouvez utiliser qu'une seule métrique, et GitLab ignore `displayConfig.stacked`.

### Exemple {#example-7}

Pour afficher les suggestions de code affichées et acceptées au cours des 30 derniers jours sous forme d'aires superposées :

````yaml
```glql
display: areaChart
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: timestamp
metrics: shownCount, acceptedCount
```
````

Pour empiler les métriques de manière cumulative :

````yaml
```glql
display: areaChart
displayConfig:
  stacked: true
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: timestamp
metrics: shownCount, acceptedCount
```
````

## Carte thermique {#heat-map}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/628031) dans GitLab 19.4.
- Options d'affichage `maxColumns` et `maxRows` [introduites](https://gitlab.com/gitlab-org/gitlab/-/work_items/628031) dans GitLab 19.5.

{{< /history >}}

Une carte thermique visualise les données agrégées du [mode analytique](_index.md#analytics-mode) sous forme de grille de cellules ombrées, une cellule par paire de valeurs de dimension. Utilisez une carte thermique pour comparer une seule métrique sur deux dimensions simultanément et pour identifier l'emplacement des valeurs les plus élevées.

Une carte thermique requiert :

- Le mode analytique, défini avec `mode: analytics`.
- Exactement deux `dimensions` pour regrouper les résultats. La première s'étend le long des colonnes, la seconde vers le bas des lignes.
- Exactement une métrique pour l'ombrage des cellules (à l'aide du paramètre `metrics`).

Chaque cellule affiche sa valeur, ombrée du plus clair au plus sombre à mesure que la valeur augmente. L'ombrage utilise des bandes fixes dérivées des valeurs du résultat, de sorte qu'une cellule plus sombre représente toujours une valeur plus grande. Les cellules sans aucune valeur sont ombrées d'un gris neutre plutôt que de la couleur la plus claire, afin qu'une petite valeur ne soit pas confondue avec une valeur absente. Survolez une cellule pour afficher sa ligne, sa colonne et sa valeur exacte.

Pour décrire le panneau au-dessus de la grille, définissez `description` sous `displayConfig`.

Pour limiter le nombre de valeurs de dimension que la grille trace, définissez `maxColumns` ou `maxRows` sous `displayConfig`. `maxColumns` limite la première dimension, qui s'étend le long des colonnes, et `maxRows` limite la deuxième, qui s'étend vers le bas des lignes. Les valeurs conservées sont les plus grandes, classées par la métrique totalisée sur l'autre axe, et un axe plafonné est ordonné du plus grand au plus petit, les égalités étant départagées par étiquette. Cet ordre remplace celui que `sort` attribue à cet axe. L'autre axe suit toujours la requête.

Les valeurs dépassant la limite sont supprimées, et rien dans la grille n'indique qu'elles sont absentes. Indiquez donc la limite dans le titre ou la description du panneau. Aucune des deux options n'a de valeur par défaut, et une valeur qui n'est pas un nombre entier supérieur à zéro est ignorée.

### Exemple {#example-8}

Pour comparer le volume de suggestions de code selon les IDE et les langues au cours des 30 derniers jours :

````yaml
```glql
display: heatMap
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: ideName, language
metrics: totalCount
```
````

Pour ajouter une description au-dessus de la grille :

````yaml
```glql
display: heatMap
displayConfig:
  description: Code Suggestions accepted per language, by IDE.
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: ideName, language
metrics: acceptedCount
```
````

Pour afficher uniquement les cinq IDE les plus actifs :

````yaml
```glql
display: heatMap
displayConfig:
  description: Code Suggestions accepted per language, for the five busiest IDEs.
  maxColumns: 5
mode: analytics
query: type = CodeSuggestion and timestamp >= -30d
dimensions: ideName, language
metrics: acceptedCount
```
````

## Graphique en barres divergentes {#diverging-bar-chart}

Un graphique en barres divergentes visualise les données agrégées du [mode analytique](_index.md#analytics-mode) sous forme de deux métriques reflétées autour d'une colonne de catégorie centrale partagée. Les barres de la première métrique s'étendent vers la gauche depuis le centre, et les barres de la deuxième métrique s'étendent vers la droite. Utilisez un graphique en barres divergentes pour comparer deux métriques selon des catégories lorsqu'une métrique peut éclipser l'autre en valeur absolue.

Chaque moitié du graphique est mise à l'échelle indépendamment, par rapport à sa propre barre la plus grande. Cela signifie qu'une catégorie peut représenter une faible part d'une métrique et l'essentiel de l'autre, les deux barres remplissant tout de même leur côté du graphique. Les deux moitiés utilisant des échelles différentes, les longueurs de barres ne sont comparables qu'au sein d'une même moitié, jamais d'un côté à l'autre du centre.

Un graphique en barres divergentes requiert :

- Le mode analytique, défini avec `mode: analytics`.
- Exactement une valeur dans `dimensions` pour regrouper les résultats.
- Exactement deux métriques à tracer (à l'aide du paramètre `metrics`).

Tout ce qui diffère d'exactement une dimension et de exactement deux métriques entraîne une erreur de validation dans la vue.

Les lignes s'affichent dans l'ordre renvoyé par la requête. Utilisez `sort` pour contrôler cet ordre, car un graphique en barres divergentes ne trie pas lui-même les lignes. Les valeurs de chaque métrique sont formatées dans l'unité propre à cette métrique, ce qui permet d'associer un dénombrement à un taux.

La colonne de catégorie représente une part de la largeur du graphique, de sorte que les étiquettes de catégorie qui ne s'y adaptent pas sont tronquées. Dans un panneau étroit, gardez les noms de catégories courts.

Il n'existe pas d'option `displayConfig` pour ce type d'affichage.

### Exemple {#example-9}

Pour comparer le nombre d'utilisateurs uniques par rapport au nombre total de sessions pour GitLab Duo Agent Platform, regroupés par type de flow, au cours des 30 derniers jours :

````yaml
```glql
display: divergingBarChart
mode: analytics
query: type = AgentPlatformSession and created >= -30d
dimensions: flowType
metrics: usersCount, totalCount
sort: totalCount desc
```
````

## Descriptions dynamiques {#dynamic-descriptions}

{{< history >}}

- Descriptions dynamiques pour la statistique unique [introduites](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255287) dans GitLab 19.5.
- Descriptions dynamiques pour la liste de barres et le tableau [introduites](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256879) dans GitLab 19.5.
- `hiddenMetrics` pour la liste de barres et le tableau [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256879) dans GitLab 19.5.

{{< /history >}}

Les types d'affichage `stat`, `barList` et `table` prennent en charge une description dynamique en [mode analytique](_index.md#analytics-mode). Utilisez une description pour résumer le résultat en une phrase, en complément de la visualisation.

Pour décrire le résultat, définissez `description` sous `displayConfig`. Une description peut inclure des espaces réservés `%{metricName}`, où `metricName` identifie une métrique depuis `metrics`. GitLab remplace chaque espace réservé par la valeur de cette métrique, formatée selon l'unité propre à cette métrique. Un espace réservé qui nomme une métrique non sélectionnée par la requête affiche une erreur de validation. Lorsque la valeur d'une métrique est absente de la réponse, son espace réservé s'affiche sous la forme d'un tiret cadratin (`—`).

Les métriques sont toujours identifiées par leur nom de clé, sauf lorsqu'il s'agit de métriques paramétrées en double, auquel cas elles ont besoin d'un alias pour être identifiées. Par exemple, `metrics: totalCount as "count"` est toujours référencé sous `%{totalCount}`, car l'alias définit uniquement le label. Lorsque la même métrique apparaît deux fois avec des paramètres différents, comme dans `metrics: durationQuantile(0.5) as "Median", durationQuantile(0.95) as "p95 duration"`, chaque alias devient la clé, et vous les référencez sous `%{Median}` et `%{p95 duration}`.

Pour la liste de barres et le tableau, une description ne peut pas utiliser d'espaces réservés lorsque la requête comporte des `dimensions`. Cela entraîne une erreur de validation dans la vue : `Description placeholders cannot be used with dimensions.` Un espace réservé lit une seule ligne ; ainsi, avec des dimensions, il afficherait la valeur d'un groupe comme si elle couvrait tous les groupes. Une description sans espace réservé fonctionne tout de même avec des dimensions.

Pour la liste de barres et le tableau, définissez `hiddenMetrics` sous `displayConfig` sur une liste de métriques à exclure des barres ou des colonnes. Nommez-les de la même façon que les espaces réservés. Nommer une métrique dupliquée par son nom de base, comme `durationQuantile`, masque toutes ses copies. GitLab exécute tout de même ces métriques, afin que la description puisse les citer. Une valeur `hiddenMetrics` qui n'est pas une liste, ou un nom qui ne correspond pas à l'une des métriques de la requête, entraîne une erreur de validation dans la vue. Une liste de barres nécessite qu'au moins une métrique soit exclue de `hiddenMetrics`.

La description s'affiche au-dessus de la visualisation. Pendant le chargement de la requête, une description contenant des espaces réservés reste masquée, afin de ne jamais afficher de tirets cadratins pour des valeurs qui ne sont pas encore disponibles.

### Exemple {#example-10}

Pour tracer le médian et le 75e percentile du temps de fusion pour les merge requests créées par GitLab Duo, et indiquer combien ont été fusionnées sans tracer une troisième barre :

````yaml
```glql
display: barList
mode: analytics
query: type = MergeRequest and createdByDuo = true and merged >= -30d
metrics: timeToMergeQuantile(0.5) as "Median", timeToMergeQuantile(0.75) as "p75", throughputCount
displayConfig:
  description: "%{throughputCount} merged merge requests"
  hiddenMetrics: [throughputCount]
```
````

## Prise en charge de la pagination {#pagination-support}

{{< history >}}

- Pagination automatique pour les visualisations en mode analytique [introduite](https://gitlab.com/gitlab-org/glql/-/work_items/170) dans GitLab 19.5.

{{< /history >}}

Les types d'affichage disponibles dans n'importe quel mode affichent la première page de résultats et proposent une action **Charger davantage** pour récupérer les pages supplémentaires. Pour plus d'informations, consultez [la pagination](_index.md#pagination).

Les visualisations agrégées en mode analytique, telles que les graphiques et les statistiques, ne proposent pas d'action **Charger davantage**. Elles récupèrent automatiquement toutes les pages de résultats agrégés, jusqu'à un maximum de 1 000 lignes.

Si votre requête retourne plus de 1 000 lignes agrégées, la visualisation affiche les 1 000 premières lignes. Pour afficher toutes vos données, ajoutez des filtres à la requête ou regroupez par moins de dimensions.

Pour afficher une seule page à la place, définissez `limit` dans le bloc. La visualisation affiche alors au maximum ce nombre de lignes, jusqu'à un maximum de 100.
