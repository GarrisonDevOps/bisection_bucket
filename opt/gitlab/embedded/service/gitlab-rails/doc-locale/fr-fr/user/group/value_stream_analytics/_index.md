---
stage: Analytics
group: Optimize
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Données d'analyse des chaînes de valeur"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les données d'analyse des chaînes de valeur calculent la durée de chaque étape de votre processus de développement logiciel. Vous pouvez mesurer le temps nécessaire pour passer d'une idée à la production en suivant les événements liés aux merge requests ou aux tickets.

Utilisez les données d'analyse des chaînes de valeur pour identifier :

- Le temps nécessaire pour passer d'une idée à la production.
- La vélocité d'un projet donné.
- Les goulots d'étranglement dans le processus de développement.
- Les tickets ou les merge requests dont le traitement s'étale dans le temps.
- Les facteurs qui ralentissent votre cycle de vie du développement logiciel.

Les données d'analyse des chaînes de valeur aident les entreprises à :

- Visualiser leurs flux de travail DevSecOps de bout en bout.
- Identifier et résoudre les inefficacités.
- Optimiser leurs flux de travail pour apporter plus de valeur, plus rapidement (par exemple, [réduire le temps de revue des merge requests](https://about.gitlab.com/blog/how-we-reduced-mr-review-time-with-value-stream-management/)).

Pour une démonstration interactive, consultez [la visite guidée du produit Value Stream Management](https://gitlab.navattic.com/vsm).

Les données d'analyse des chaînes de valeur ont une structure hiérarchique :

- Une **chaîne de valeur** contient une liste d'étapes de chaîne de valeur.
- Chaque liste d'étapes de chaîne de valeur contient une ou plusieurs **étapes**.
- Chaque étape est définie par deux **événements** : début et fin.

## Métriques {#metrics}

La page **Vue d'ensemble** dans les données d'analyse des chaînes de valeur affiche les métriques clés des performances du cycle de vie DevSecOps pour les projets et les groupes.

### Métriques du cycle de vie {#lifecycle-metrics}

Les données d'analyse des chaînes de valeur incluent les métriques de cycle de vie suivantes :

- **Durée d'exécution** : temps médian entre la création du ticket et sa clôture.
- **Temps de cycle** : temps médian entre le moment où un ticket est pour la première fois [référencé dans le message de commit](../../project/issues/crosslinking_issues.md#from-commit-messages) d'une merge request et le moment où ce ticket référencé est clôturé. Vous devez inclure `#` suivi du numéro du ticket (par exemple, `#123`) dans le message de commit, sinon aucune donnée n'est affichée. Le temps de cycle est généralement plus court que le délai de mise à disposition, car la merge request est créée après le premier commit.
- **Nouveaux tickets** : nombre de nouveaux tickets créés.
- **Déploiements** : nombre total de déploiements en production.

### Métriques DORA {#dora-metrics}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les données d'analyse des chaînes de valeur incluent les métriques [DORA](../../analytics/dora_metrics.md) suivantes :

- Fréquence de déploiement
- Délai de mise à disposition des modifications
- Délai de restauration du service
- Taux d'échec des modifications

Les métriques DORA sont calculées à partir des données de l'[API DORA](../../../api/dora/metrics.md).

Si vous disposez d'un abonnement GitLab Premium ou GitLab Ultimate :

- Le nombre de déploiements réussis est calculé avec les données DORA.
- Les données sont filtrées en fonction de l'environnement et de l'édition de l'environnement.

## Chaînes de valeur {#value-streams}

Une chaîne de valeur est l'ensemble du processus de travail qui apporte de la valeur aux clients. Les chaînes de valeur sont des objets conteneurs pour les étapes. Vous pouvez avoir plusieurs chaînes de valeur par groupe, pour vous concentrer sur différents aspects du cycle de vie DevOps.

## Étapes de la chaîne de valeur {#value-stream-stages}

Une étape représente une paire d'événements (événements de début et de fin) avec des métadonnées supplémentaires, telles que le nom de l'étape. Vous pouvez utiliser les données d'analyse des chaînes de valeur avec les étapes par défaut intégrées, que vous pouvez réorganiser et masquer. Vous pouvez également créer et ajouter des étapes personnalisées qui correspondent à vos workflows de développement spécifiques.

## Événements d'étape de chaîne de valeur {#value-stream-stage-events}

{{< history >}}

- L'événement d'assignation du premier relecteur d'une merge request a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/466383) dans GitLab 17.2. Les événements d'assignation de relecteur dans les merge requests créées ou mises à jour avant GitLab 17.2 ne sont pas disponibles pour les rapports.

{{< /history >}}

Les événements sont les éléments constitutifs qui définissent quand les étapes commencent et se terminent. Chaque événement a une heure de début et une heure de fin :

- L'heure de l'événement de début indique quand le travail commence dans une étape (par exemple, quand un ticket est créé).
- L'heure de l'événement de fin indique quand le travail se termine dans une étape (par exemple, quand un ticket est clôturé).

GitLab calcule la durée d'une étape en fonction des heures des événements de début et de fin, selon cette formule : durée de l'étape = Heure de l'événement de fin - Heure de l'événement de début

Les données d'analyse des chaînes de valeur prennent en charge les événements suivants :

- Ticket clôturé
- Ticket créé
- Ticket ajouté pour la première fois à un tableau
- Ticket ajouté pour la première fois à une itération
- Ticket assigné pour la première fois
- Ticket associé pour la première fois à un jalon
- Ticket mentionné pour la première fois dans un commit
- Label ajouté au ticket
- Label retiré du ticket
- Merge request clôturée
- Merge request créée
- Merge request assignée pour la première fois
- Premier commit dans la merge request
- Merge request déployée pour la première fois en production
- Label ajouté à la merge request
- Label retiré de la merge request
- Merge request approuvée pour la dernière fois
- Dernière build de la merge request terminée
- Dernière build de la merge request démarrée
- Merge request fusionnée
- Premier relecteur assigné à la merge request

Vous pouvez partager vos idées ou commentaires sur les événements d'étape dans [l'issue 520962](https://gitlab.com/gitlab-org/gitlab/-/issues/520962).

## Mesure des étapes {#stage-measurement}

Les données d'analyse des chaînes de valeur mesurent chaque étape de son événement de début à son événement de fin. Seuls les éléments ayant atteint leur événement de fin sont inclus dans le calcul du temps d'étape.

Par défaut, les tickets bloqués ne sont pas inclus dans l'aperçu du cycle de vie. Cependant, vous pouvez utiliser des labels personnalisés (par exemple `workflow::blocked`) pour les suivre.

Vous pouvez personnaliser les étapes dans les données d'analyse des chaînes de valeur en fonction d'événements prédéfinis. Pour vous aider dans la configuration, GitLab fournit une liste prédéfinie d'étapes que vous pouvez utiliser comme modèle. Par exemple, vous pouvez définir une étape qui commence lorsque vous ajoutez un label à un ticket, et se termine lorsque vous ajoutez un autre label.

Le tableau suivant donne un aperçu des étapes prédéfinies dans les données d'analyse des chaînes de valeur.

| Étape   | Méthode de mesure   |
| ------- | -------------------- |
| Ticket     | Le temps médian entre la création d'un ticket et l'action entreprise pour le résoudre, soit en lui ajoutant un label, soit en l'ajoutant à un jalon, selon ce qui se produit en premier. Le label n'est suivi que s'il dispose déjà d'une [liste de tableau des tickets](../../project/issue_board.md) créée pour lui. |
| Forfait      | Le temps médian entre l'action effectuée pour l'étape précédente et le push du premier commit vers la branche. Le premier commit sur la branche déclenche la séparation entre **Forfait** et **Code**. Au moins un des commits de la branche doit contenir le numéro du ticket associé (par exemple, `#42`). Si aucun des commits de la branche ne mentionne le numéro du ticket associé, il n'est pas pris en compte dans le calcul du temps de l'étape. |
| Code      | Le temps médian entre le push d'un premier commit (étape précédente) et la création d'une merge request (MR) liée à ce commit. La clé pour maintenir le suivi du processus est d'inclure le [modèle de clôture de ticket](../../project/issues/managing_issues.md#default-closing-pattern) dans la description de la merge request. Par exemple, `Closes #xxx`, où `xxx` est le numéro du ticket lié à cette merge request. Si le modèle de clôture n'est pas présent, le calcul utilise l'heure de création du premier commit dans la merge request comme heure de début. |
| Test      | Le temps médian pour exécuter l'ensemble du pipeline pour ce projet. Il est lié au temps que GitLab CI/CD prend pour exécuter chaque job pour les commits poussés vers cette merge request. Il s'agit essentiellement du temps début->fin pour tous les pipelines. |
| Examen    | Le temps médian pour examiner une merge request ayant un modèle de clôture de ticket, entre sa création et jusqu'à sa fusion. |
| Préproduction   | Le temps médian entre la fusion d'une merge request ayant un modèle de clôture de ticket et le tout premier déploiement vers un [environnement de production](#production-environment). S'il n'existe pas d'environnement de production, cela n'est pas suivi. |

> [!note]
> Les données d'analyse des chaînes de valeur fonctionnent sur des données horodatées et n'agrègent que les événements de début et de fin finaux de l'étape. Pour les éléments qui passent plusieurs fois d'une étape à l'autre, le temps d'étape est calculé uniquement à partir des horodatages des événements finaux.

### Environnement de production {#production-environment}

Les données d'analyse des chaînes de valeur identifient les [environnements de production](../../../ci/environments/_index.md#deployment-tier-of-environments) en recherchant les [environnements](../../../ci/yaml/_index.md#environment) de projet dont le nom correspond à l'un de ces modèles :

- `prod` ou `prod/*`
- `production` ou `production/*`

Ces modèles ne sont pas sensibles à la casse.

Vous pouvez modifier le nom d'un environnement de projet dans votre configuration GitLab CI/CD.

### Exemple de workflow {#example-workflow}

Cet exemple montre un workflow à travers les sept étapes en une seule journée.

Si une étape ne comprend pas d'heure de début et d'heure de fin, ses données ne sont pas incluses dans le temps médian. Dans cet exemple, des jalons ont été créés et le CI/CD pour les tests et la configuration des environnements est configuré.

- 09:00 : créer un ticket. L'étape **Ticket** commence.
- 11:00 : ajouter le ticket à un jalon (ou au backlog), commencer à travailler sur le ticket et créer une branche localement. L'étape **Ticket** se termine et l'étape **Forfait** commence.
- 12:00 : effectuer le premier commit.
- 12:30 : effectuer le deuxième commit vers la branche qui mentionne le numéro du ticket. L'étape **Forfait** se termine et l'étape **Code** commence.
- 14:00 : pousser la branche et créer une merge request contenant le [modèle de clôture de ticket](../../project/issues/managing_issues.md#closing-issues-automatically). L'étape **Code** se termine et les étapes **Test** et **Examen** commencent.
- GitLab CI/CD prend 5 minutes pour exécuter les scripts définis dans le [fichier `.gitlab-ci.yml`](../../../ci/yaml/_index.md).
- 19:00 : fusionner la merge request. L'étape **Examen** se termine et l'étape **Préproduction** commence.
- 19:30 : le déploiement vers l'environnement `production` se termine. La **Préproduction** se termine.

Les données d'analyse des chaînes de valeur enregistrent les temps suivants pour chaque étape :

- **Ticket** : 09:00 à 11:00 : 2 h
- **Forfait** : 11:00 à 12:00 : 1 h
- **Code** : 12:00 à 14:00 : 2 h
- **Test** : 5 minutes
- **Examen** : 14:00 à 19:00 : 5 h
- **Préproduction** : 19:00 à 19:30 : 30 minutes

Gardez à l'esprit les observations suivantes liées à cet exemple :

- Cet exemple montre que peu importe si votre premier commit ne mentionne pas le numéro du ticket, vous pouvez le faire ultérieurement dans n'importe quel commit sur la branche sur laquelle vous travaillez.
- L'étape **Test** est utilisée dans le calcul du temps total du cycle. Elle est incluse dans le processus d'**Examen**, car chaque MR doit être testée.
- Cet exemple n'illustre qu'un seul cycle des sept étapes. Le tableau de bord des données d'analyse des chaînes de valeur affiche le temps médian pour plusieurs cycles.

### Durée cumulée des événements de label {#cumulative-label-event-duration}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/432576) dans GitLab 16.9 [avec des feature flags](../../../administration/feature_flags/_index.md) nommés `enable_vsa_cumulative_label_duration_calculation` et `vsa_duration_from_db`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com et GitLab Self-Managed](https://gitlab.com/gitlab-com/gl-infra/production/-/issues/17476) dans GitLab 16.10. Le feature flag `vsa_duration_from_db` a été supprimé.
- Le feature flag `enable_vsa_cumulative_label_duration_calculation` a été [supprimé](https://gitlab.com/gitlab-com/gl-infra/production/-/issues/17478) dans GitLab 17.0.

{{< /history >}}

Avec cette fonctionnalité, les données d'analyse des chaînes de valeur mesurent la durée des événements répétitifs pour les étapes basées sur des labels. Vous devez configurer des événements de suppression ou d'ajout de label pour les événements de début et de fin.

Par exemple, une étape suit l'ajout et la suppression du label `in progress`, avec les horaires suivants :

- 9:00 : label ajouté.
- 10:00 : label supprimé.
- 12:00 : label ajouté.
- 14:00 label supprimé.

Avec la méthode de calcul d'origine, la durée est de cinq heures (de 9:00 à 14:00). Avec le calcul de durée cumulée des événements de label activé, la durée est de trois heures (de 9:00 à 10:00 et de 12:00 à 14:00).

> [!note]
> Lorsque vous mettez à niveau votre version de GitLab vers la version 16.10 (ou une version supérieure), les étapes d'analyse des chaînes de valeur existantes basées sur des labels sont automatiquement réagrégées à l'aide du processus d'agrégation en arrière-plan.

### Étapes basées sur des labels pour les chaînes de valeur personnalisées {#label-based-stages-for-custom-value-streams}

Pour mesurer des workflows complexes, vous pouvez utiliser des [labels à portée limitée](../../project/labels.md#scoped-labels). Par exemple, pour mesurer le temps de déploiement d'un environnement de préproduction vers la production, vous pouvez utiliser les labels suivants :

- Lorsque le code est déployé en préproduction, le label `workflow::staging` est ajouté à la merge request.
- Lorsque le code est déployé en production, le label `workflow::production` est ajouté à la merge request.

![Étape d'analyse des chaînes de valeur basée sur des labels](img/vsa_label_based_stage_v14_0.png "Création d'une étape d'analyse des chaînes de valeur basée sur des labels")

#### Étiquetage automatique des données avec des webhooks {#automatic-data-labeling-with-webhooks}

Vous pouvez ajouter automatiquement des labels en utilisant les [événements webhook GitLab](../../project/integrations/webhook_events.md), afin qu'un label soit appliqué aux merge requests ou aux tickets lorsqu'un événement spécifique se produit. Vous pouvez ensuite ajouter des étapes basées sur des labels pour suivre votre workflow. Pour en savoir plus sur l'implémentation, consultez l'article de blog [Applying GitLab Labels Automatically](https://about.gitlab.com/blog/applying-gitlab-labels-automatically/).

#### Exemple de configuration {#example-configuration}

![Exemple de configuration](img/object_hierarchy_v14_10.png "Exemple de configuration de chaîne de valeur personnalisée")

Dans l'exemple précédent, deux chaînes de valeur indépendantes sont configurées pour deux équipes qui utilisent des workflows de développement différents dans le **groupe Test** (espace de nommage de niveau supérieur).

La première chaîne de valeur utilise des événements standard basés sur des horodatages pour définir les étapes. La deuxième chaîne de valeur utilise des événements de label.

## Agrégation des données {#data-aggregation}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les données d'analyse des chaînes de valeur utilisent un processus en arrière-plan pour collecter et agréger les données au niveau des étapes, ce qui lui permet de s'adapter à de grands groupes avec un nombre élevé de tickets et de merge requests. En raison de ce processus, il peut y avoir un léger délai entre le moment où une action est effectuée (par exemple, la clôture d'un ticket) et celui où les données s'affichent sur la page des données d'analyse des chaînes de valeur.

Le traitement des données et l'affichage des résultats peuvent prendre jusqu'à 10 minutes. La collecte de données peut prendre plus de 10 minutes dans les cas suivants :

- S'il s'agit de la première fois que vous consultez les données d'analyse des chaînes de valeur et que vous n'avez pas encore créé de chaîne de valeur.
- Si la hiérarchie des groupes a été réorganisée.
- S'il y a eu des mises à jour en masse sur les tickets et les merge requests.

Pour voir quand les données ont été mises à jour pour la dernière fois, dans le coin droit à côté de **Modifier**, survolez le badge **Dernière mise à jour**.

## Afficher les données d'analyse des chaînes de valeur {#view-value-stream-analytics}

Prérequis :

- Vous devez disposer du rôle Rapporteur, Développeur, Chargé de maintenance ou Propriétaire.
- Vous devez créer une chaîne de valeur personnalisée. Les données d'analyse des chaînes de valeur n'affichent que les chaînes de valeur personnalisées créées pour votre groupe ou projet.

Pour afficher les données d'analyse des chaînes de valeur pour votre groupe ou projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**.
1. Pour afficher les métriques d'une étape particulière, sélectionnez une étape sous la zone de texte **Filtrer les résultats**.
1. Facultatif. Filtrer les résultats :
   1. Sélectionnez la zone de texte **Filtrer les résultats**.
   1. Sélectionnez un paramètre.
   1. Sélectionnez une valeur ou saisissez du texte pour affiner les résultats.
   1. Pour afficher les métriques dans une plage de dates particulière, sélectionnez une plage de dates prédéfinie ou l'option **Personnalisé** dans la liste déroulante. Avec l'option **Personnalisé** sélectionnée :

      - Dans le champ **Du**, sélectionnez une date de début.
      - Dans le champ **Au**, sélectionnez une date de fin.

      Les graphiques et la liste affichent les éléments de workflow créés pendant la plage de dates.
1. Facultatif. Trier les résultats par ordre croissant ou décroissant :
   - Pour trier par élément de workflow le plus récent ou le plus ancien, sélectionnez l'en-tête **Dernier événement**.
   - Pour trier par la durée la plus longue ou la plus courte passée dans chaque étape, sélectionnez l'en-tête **Durée**.

Un badge à côté de l'en-tête du tableau des éléments de workflow indique le nombre d'éléments de workflow ayant été complétés pendant l'étape sélectionnée.

Le tableau affiche une liste des éléments de workflow associés à l'étape sélectionnée. En fonction de l'étape sélectionnée, il peut s'agir :

- Les tickets
- Les merge requests

> [!note]
> La date de fin de chaque plage de dates prédéfinie est le jour actuel, et elle est incluse dans le nombre de jours sélectionnés. Par exemple, la date de début pour `Last 30 days` est 29 jours avant le jour actuel, pour un total de 30 jours.

### Filtres de données {#data-filters}

Vous pouvez filtrer les données d'analyse des chaînes de valeur pour afficher les données correspondant à des critères spécifiques. Les filtres suivants sont pris en charge :

- Plage de dates
- Projet
- Assigné
- Auteur
- Jalon
- Label

## Afficher les métriques du cycle de vie et DORA {#view-lifecycle-and-dora-metrics}

Prérequis :

- Pour afficher les métriques de déploiement, vous devez avoir un [environnement de production configuré](#production-environment).

Pour afficher les métriques du cycle de vie :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**. Les métriques du cycle de vie s'affichent sous la zone de texte **Filtrer les résultats**.
1. Facultatif. Filtrer les résultats :
   1. Sélectionnez la zone de texte **Filtrer les résultats**. En fonction du filtre sélectionné, le tableau de bord agrège automatiquement les métriques du cycle de vie et affiche le statut de la chaîne de valeur.
   1. Sélectionnez un paramètre.
   1. Sélectionnez une valeur ou saisissez du texte pour affiner les résultats.
   1. Pour ajuster la plage de dates :
      - Dans le champ **Du**, sélectionnez une date de début.
      - Dans le champ **Au**, sélectionnez une date de fin.

Pour afficher le [tableau de bord des chaînes de valeur](../../analytics/value_streams_dashboard.md) et les [métriques DORA](../../analytics/dora_metrics.md) :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**.
1. Sous la zone de texte **Filtrer les résultats**, dans la ligne **Métriques du cycle de vie**, sélectionnez **Value Streams Dashboard / DORA**.
1. Facultatif. Pour ouvrir la nouvelle page, ajoutez ce chemin `/analytics/dashboards/value_streams_dashboard` à l'URL du groupe (par exemple, `https://gitlab.com/groups/gitlab-org/-/analytics/dashboards/value_streams_dashboard`).

## Afficher les métriques pour chaque étape de développement {#view-metrics-for-each-development-stage}

Les données d'analyse des chaînes de valeur affichent le temps médian passé par les tickets ou les merge requests dans chaque étape de développement.

Pour afficher le temps médian passé dans chaque étape par un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**.
1. Facultatif. Filtrer les résultats :
   1. Sélectionnez la zone de texte **Filtrer les résultats**.
   1. Sélectionnez un paramètre.
   1. Sélectionnez une valeur ou saisissez du texte pour affiner les résultats.
   1. Pour ajuster la plage de dates :
      - Dans le champ **Du**, sélectionnez une date de début.
      - Dans le champ **Au**, sélectionnez une date de fin.
1. Pour afficher les métriques de chaque étape, au-dessus de la zone de texte **Filtrer les résultats**, survolez une étape.

> [!note]
> Le sélecteur de plage de dates filtre les éléments par heure d'événement. L'heure de l'événement correspond au moment où l'étape sélectionnée s'est terminée pour l'élément donné.

Vous pouvez également utiliser l'[API GraphQL](../../../api/graphql/value_stream_analytics.md) pour récupérer les données d'analyse des chaînes de valeur.

## Afficher les tâches par type {#view-tasks-by-type}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le graphique **Tâches par type** affiche le nombre cumulé de tâches terminées (tickets clôturés et merge requests fusionnées) par jour pour votre groupe.

Le graphique utilise les filtres globaux de la page pour afficher les données en fonction du groupe et de la période sélectionnés.

Pour afficher les tâches par type :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**.
1. Sous la zone de texte **Filtrer les résultats**, sélectionnez **Vue d'ensemble**. Le graphique **Tâches par type** s'affiche sous le graphique **Durée totale**.
1. Facultatif. Pour filtrer les tâches par type, sélectionnez **Paramètres** ({{< icon name="settings" >}}), puis **Tickets** ou **requêtes de fusion**.
1. Facultatif. Pour filtrer les tâches par label, sélectionnez **Paramètres** ({{< icon name="settings" >}}), puis un ou plusieurs labels. Par défaut, les principaux labels du groupe (maximum 10) sont sélectionnés. Vous pouvez sélectionner un maximum de 15 labels.

## Créer une chaîne de valeur {#create-a-value-stream}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- **Nouvelle chaîne de valeur** est passé d'une boîte de dialogue à une page dans GitLab 16.10 via [un changement](https://gitlab.com/gitlab-org/gitlab/-/issues/381002) [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `vsa_standalone_settings_page`. Fonctionnalité désactivée par défaut.
- [Disponible de manière générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/171856) dans GitLab 17.7. Le feature flag `vsa_standalone_settings_page` a été supprimé.

{{< /history >}}

### Avec les étapes par défaut {#with-default-stages}

Pour créer une chaîne de valeur avec les étapes par défaut :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**.
1. Sélectionnez **Nouvelle chaîne de valeur**.
1. Saisissez un nom pour la chaîne de valeur.
1. Sélectionnez **Créer à partir du modèle par défaut**.
1. Personnalisez les étapes par défaut :
   - Pour réorganiser les étapes, sélectionnez les flèches vers le haut ou vers le bas.
   - Pour masquer une étape, sélectionnez **Masquer** ({{< icon name="eye-slash" >}}).
1. Pour ajouter une étape personnalisée, sélectionnez **Ajouter une étape**.
   - Saisissez un nom pour l'étape.
   - Sélectionnez un **Événement de début** et un **Événement d'arrêt**.
1. Sélectionnez **Nouvelle chaîne de valeur**.

> [!note]
> Si vous avez récemment effectué une mise à niveau vers GitLab Premium, la collecte et l'affichage des données peuvent prendre jusqu'à 30 minutes.

### Avec des étapes personnalisées {#with-custom-stages}

Pour créer une chaîne de valeur avec des étapes personnalisées :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**.
1. Sélectionnez **Nouvelle chaîne de valeur**.
1. Pour chaque étape :
   - Saisissez un nom pour l'étape.
   - Sélectionnez un **Événement de début** et un **Événement d'arrêt**.
1. Pour ajouter une autre étape, sélectionnez **Ajouter une étape**.
1. Pour réorganiser les étapes, sélectionnez les flèches vers le haut ou vers le bas.
1. Sélectionnez **Nouvelle chaîne de valeur**.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une explication en vidéo, voir [Optimizing merge request review process with Value Stream Analytics](https://www.youtube.com/watch?v=kblpge6xeL8).
<!-- Video published on 2024-07-29 -->

## Modifier une chaîne de valeur {#edit-a-value-stream}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- **Modifier la chaîne de valeur** est passé d'une boîte de dialogue à une page dans GitLab 16.10 via [un changement](https://gitlab.com/gitlab-org/gitlab/-/issues/381002) [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `vsa_standalone_settings_page`. Fonctionnalité désactivée par défaut.
- [Disponible de manière générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/171856) dans GitLab 17.7. Le feature flag `vsa_standalone_settings_page` a été supprimé.

{{< /history >}}

Après avoir créé une chaîne de valeur, vous pouvez la personnaliser selon vos besoins. Pour modifier une chaîne de valeur :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**.
1. Dans la liste déroulante des chaînes de valeur, sélectionnez la chaîne de valeur que vous souhaitez modifier.
1. À côté de la liste déroulante des chaînes de valeur, sélectionnez **Modifier**.
1. Facultatif :
   - Renommer la chaîne de valeur.
   - Masquer ou réorganiser les étapes par défaut.
   - Supprimer les étapes personnalisées existantes.
   - Pour ajouter de nouvelles étapes, sélectionnez **Ajouter une étape**.
   - Sélectionnez les événements de début et de fin pour l'étape.
1. Facultatif. Pour annuler les modifications, sélectionnez **Restaurer les valeurs par défaut de la chaîne de valeur**.
1. Sélectionnez **Enregistrer la chaîne de valeur**.

## Supprimer une chaîne de valeur {#delete-a-value-stream}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour supprimer une chaîne de valeur personnalisée :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**.
1. Dans la liste déroulante des chaînes de valeur, sélectionnez la chaîne de valeur que vous souhaitez supprimer, puis **Supprimer (nom de la chaîne de valeur)**.
1. Pour confirmer, sélectionnez **Supprimer**.

## Afficher le nombre de jours nécessaires à l'exécution d'un cycle {#view-number-of-days-for-a-cycle-to-complete}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le **graphique de durée totale** indique le nombre moyen de jours nécessaires à l'exécution des cycles de développement. Le graphique affiche les données des 500 derniers éléments de workflow.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**.
1. Au-dessus de la zone **Filtrer les résultats**, sélectionnez une étape :
   - Pour afficher un résumé du temps de cycle pour toutes les étapes, sélectionnez **Vue d'ensemble**.
   - Pour afficher le temps de cycle d'une étape spécifique, sélectionnez une étape.
1. Facultatif. Filtrer les résultats :
   1. Sélectionnez la zone de texte **Filtrer les résultats**.
   1. Sélectionnez un paramètre.
   1. Sélectionnez une valeur ou saisissez du texte pour affiner les résultats.
   1. Pour ajuster la plage de dates :
      - Dans le champ **Du**, sélectionnez une date de début.
      - Dans le champ **Au**, sélectionnez une date de fin.

## Réagréger les données après une mise à niveau {#reaggregate-data-after-upgrade}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

Sur les instances de grande taille, lorsque vous effectuez une mise à niveau de la version de GitLab et en particulier si plusieurs versions mineures sont sautées, les processus d'agrégation en arrière-plan peuvent durer plus longtemps. Ce délai peut entraîner des données obsolètes sur la page des données d'analyse des chaînes de valeur. Pour accélérer le processus d'agrégation et éviter les données obsolètes, dans la [console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session), vous pouvez invoquer le snippet d'agrégation synchrone pour un groupe donné :

```ruby
group = Group.find(-1) # put your group id here
group_to_aggregate = group.root_ancestor

loop do
  cursor = {}
  context = Analytics::CycleAnalytics::AggregationContext.new(cursor: cursor)
  service_response = Analytics::CycleAnalytics::DataLoaderService.new(group: group_to_aggregate, model: Issue, context: context).execute

  if service_response.success? && service_response.payload[:reason] == :limit_reached
    cursor = service_response.payload[:context].cursor
  elsif service_response.success?
    puts "finished"
    break
  else
    puts "failed"
    break
  end
end

loop do
  cursor = {}
  context = Analytics::CycleAnalytics::AggregationContext.new(cursor: cursor)
  service_response = Analytics::CycleAnalytics::DataLoaderService.new(group: group_to_aggregate, model: MergeRequest, context: context).execute

  if service_response.success? && service_response.payload[:reason] == :limit_reached
    cursor = service_response.payload[:context].cursor
  elsif service_response.success?
    puts "finished"
    break
  else
    puts "failed"
    break
  end
end
```

## Autorisations d'accès {#access-permissions}

Les autorisations d'accès pour les données d'analyse des chaînes de valeur dépendent du type de projet.

| Type de projet | Autorisations                                       |
|--------------|---------------------------------------------------|
| Public       | Tout le monde peut y accéder.                                |
| Interne     | Tout utilisateur authentifié peut y accéder.                |
| Privé      | Tout utilisateur ayant le rôle Reporter, Developer, Maintainer ou Owner peut y accéder. |

## Disponibilité des fonctionnalités {#feature-availability}

Les données d'analyse des chaînes de valeur offrent des fonctionnalités pour les projets et les groupes, avec une disponibilité variable selon l'édition.

- Dans l'édition Gratuite, les données d'analyse des chaînes de valeur n'agrègent pas les données. Elles interrogent directement la base de données où le filtre de plage de dates est appliqué à la date de création des tickets et des merge requests. Vous pouvez afficher les données d'analyse des chaînes de valeur avec les étapes par défaut prédéfinies.
- Dans les éditions GitLab Premium et GitLab Ultimate, les données d'analyse des chaînes de valeur agrègent les données et appliquent le filtre de plage de dates sur l'événement de fin. Vous pouvez également créer, modifier et supprimer des chaînes de valeur.

| Fonctionnalité                                              | Groupe (GitLab Premium, GitLab Ultimate)                                                                        | Projet (GitLab Premium, GitLab Ultimate)        | Projet (Gratuite) |
|------------------------------------------------------|-----------------------------------------------------------------------------------------------|---------------------------------|----------------------|
| Créer des chaînes de valeur personnalisées                          | {{< yes >}}                                                                                           | {{< yes >}}                             | {{< no >}} Une seule chaîne de valeur (par défaut) est présente avec les étapes par défaut |
| Créer des étapes personnalisées                                 | {{< yes >}}                                                                                           | {{< yes >}}                             | {{< no >}}                   |
| Filtrage (par exemple, par auteur, label, jalon) | {{< yes >}}                                                                                           | {{< yes >}}                             | {{< yes >}}                  |
| Graphique du temps par étape                                     | {{< yes >}}                                                                                           | {{< yes >}}                             | {{< no >}}                   |
| Graphique de durée totale                                     | {{< yes >}}                                                                                           | {{< yes >}}                             | {{< no >}}                   |
| Graphique des tâches par type                                   | {{< yes >}}                                                                                           | {{< no >}}                              | {{< no >}}                   |
| Métriques DORA                                         | {{< yes >}}                                                                                           | {{< yes >}}                             | {{< no >}}                   |
| Résumé du temps de cycle et du délai de mise à disposition (métriques du cycle de vie) | {{< yes >}}                                                                                           | {{< yes >}}                             | {{< no >}}                   |
| Nouveaux tickets, commits et déploiements (métriques du cycle de vie) | {{< yes >}} Hors commits                                                                        | {{< yes >}}                             | {{< yes >}}                  |
| Utilise un backend agrégé                              | {{< yes >}}                                                                                           | {{< yes >}}                             | {{< no >}}                   |
| Comportement du filtre de date                                 | Filtre les éléments [terminés dans la plage de dates](https://gitlab.com/groups/gitlab-org/-/work_items/6046) | Filtre les éléments par date de création. | Filtre les éléments par date de création. |
| Autorisation                                        | Au minimum Reporter                                                                             | Au minimum Reporter               | Peut être public        |

## Dépannage {#troubleshooting}

### 100 % d'utilisation CPU par Sidekiq `cronjob:analytics_cycle_analytics` {#100-cpu-utilization-by-sidekiq-cronjobanalytics_cycle_analytics}

Il est possible que les jobs d'arrière-plan des données d'analyse des chaînes de valeur impactent fortement les performances en monopolisant les ressources CPU.

Pour remédier à cette situation :

1. Désactivez la fonctionnalité pour tous les projets dans [la console Rails](../../../administration/operations/rails_console.md) et supprimez les jobs existants :

   ```ruby
   Project.find_each do |p|
     p.analytics_access_level='disabled';
     p.save!
   end

   Analytics::CycleAnalytics::GroupStage.delete_all
   Analytics::CycleAnalytics::Aggregation.delete_all
   ```

1. Configurez un [routage Sidekiq](../../../administration/sidekiq/processing_specific_job_classes.md) avec, par exemple, une seule entrée `feature_category=value_stream_management` et plusieurs entrées `feature_category!=value_stream_management`. Trouvez d'autres métadonnées de file d'attente pertinentes dans la [liste Enterprise Edition](../../../administration/sidekiq/processing_specific_job_classes.md#list-of-available-job-classes).
1. Activez les données d'analyse des chaînes de valeur pour un projet à la fois. Vous devrez peut-être affiner davantage le routage Sidekiq en fonction de vos exigences de performance.
