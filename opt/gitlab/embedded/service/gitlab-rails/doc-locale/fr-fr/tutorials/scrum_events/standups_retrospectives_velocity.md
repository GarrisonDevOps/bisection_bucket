---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Animez des stand-ups quotidiens et des rétrospectives, puis suivez les points de story, la vélocité et la volatilité pour prévoir la livraison des sprints."
title: 'Tutoriel : faciliter les stand-ups, les rétrospectives et le suivi de la vélocité'
---

<!-- vale gitlab_base.FutureTense = NO -->

En plus des cérémonies Scrum fondamentales telles que la planification et les revues de sprint, les équipes peuvent utiliser GitLab pour faciliter les cérémonies Scrum courantes suivantes, aussi bien dans les environnements colocalisés que distribués :

- Stand-ups quotidiens
- Rétrospectives
- Points de story
- Vélocité et volatilité

Ce tutoriel s'appuie sur les concepts et les workflows du [tutoriel Scrum d'introduction](_index.md). Si vous n'avez pas encore terminé ce tutoriel, faites-le avant de poursuivre.

## Stand-ups quotidiens {#daily-stand-ups}

Consignes générales :

- Limitez le stand-up à 15 minutes maximum.
- Si un sujet nécessite une discussion approfondie au-delà d'une simple mise à jour de statut, reportez la discussion afin que les parties concernées puissent se réunir séparément après le stand-up pour en discuter davantage.

### Stand-up synchrone {#synchronous-stand-up}

Si vous êtes colocalisés, réunissez-vous dans la même salle et parcourez le tableau **Current Sprint** pour discuter des mises à jour relatives aux tickets concernés.

Si vous êtes distribués, participez à un appel vidéo et désignez une personne pour partager son écran afin de passer en revue le tableau du sprint en cours.

Plutôt que de passer en revue ensemble le tableau du sprint en cours, vous pouvez utiliser le format suivant. Chaque membre de l'équipe doit répondre à ces trois questions :

- « Qu'ai-je accompli hier ? »
- « Sur quoi est-ce que je travaille aujourd'hui ? »
- « Suis-je ou vais-je bientôt être bloqué par quelque chose ? »

### Stand-up asynchrone {#asynchronous-stand-up}

Pour faciliter un stand-up asynchrone dans GitLab, plusieurs options s'offrent à vous :

- Dans l'outil de messagerie de votre équipe : utilisez l'automatisation pour collecter les stand-ups de chaque membre de l'équipe. GitLab utilise [Geekbot](https://geekbot.com/) en interne.
- Dans GitLab :

  1. Créez un ticket intitulé **Stand-up** et ajoutez-le à l'itération en cours.
  1. Chaque jour du sprint, la première personne à renseigner son stand-up doit créer un nouveau commentaire avec la date, puis ajouter un commentaire avec sa mise à jour.
  1. Chaque membre de l'équipe ajoute ses mises à jour respectives à la discussion sous forme de fil de discussion. [Voir un exemple](https://gitlab.com/tech-marketing/demos/gitlab-agile-demo/scrum-public-demo/application-b/-/issues/6) dans un projet de démonstration.

## Rétrospectives de sprint {#sprint-retrospectives}

Une rétrospective est une opportunité sans reproche pour l'équipe d'identifier des améliorations de processus et de célébrer les progrès accomplis. Vous pouvez choisir parmi de nombreux formats de rétrospective.

<!-- vale gitlab_base.InclusiveLanguage = NO -->
James Shore propose [un excellent plan pour mener une rétrospective](https://www.jamesshore.com/v2/books/aoad1/retrospectives) dans son livre « The Art of Agile ».
<!-- vale gitlab_base.InclusiveLanguage = YES -->

### Rétrospectives synchrones {#synchronous-retrospectives}

Il peut être utile de consulter le [rapport d'itération](../../user/group/iterations/_index.md#iteration-report) lors des rétrospectives.

Pour consulter un rapport d'itération pour une itération terminée :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations**.
1. En haut, sélectionnez **Terminé** et choisissez votre cadence d'itération.
1. Sélectionnez l'itération la plus récemment terminée.

### Rétrospectives asynchrones {#asynchronous-retrospectives}

Vous pouvez utiliser les tickets GitLab pour les rétrospectives asynchrones.

1. Dans l'itération en cours, créez un nouveau ticket intitulé **Rétrospective**.

   Vous pouvez appliquer de nombreux formats identiques à ceux utilisés pour les rétrospectives synchrones. [Voir un exemple de ticket](https://gitlab.com/tech-marketing/demos/gitlab-agile-demo/scrum-public-demo/application-b/-/issues/7) qui applique le plan de rétrospective proposé par James Shore.
1. S'il y a de nombreux éléments d'action, envisagez de créer des tickets distincts pour les suivre indépendamment de la rétrospective.
1. Une fois que l'équipe a terminé de trier les éléments d'action, fermez le ticket de rétrospective.

## Points de story {#story-points}

Pour identifier la complexité relative et l'effort nécessaire pour compléter une story, vous pouvez utiliser des points de story. Les points de story peuvent également vous aider à identifier et à discuter des compromis en termes de portée et d'implémentation au cours du processus de planification.

Dans GitLab, les équipes saisissent les points de story en utilisant la zone de texte **Poids** dans un ticket ou une tâche. Vous pouvez définir des poids sur les stories (tickets) ou les tâches en fonction de votre stratégie d'estimation.

### Déterminer la valeur des points de story {#deciding-the-value-of-story-points}

Vous devez utiliser une suite de Fibonacci modifiée pour votre échelle de points de story : 0, 1, 2, 3, 5, 8, 13, 20 et 40. Comme Mike Cohn le [souligne](https://www.mountaingoatsoftware.com/blog/why-the-fibonacci-sequence-works-well-for-estimating) en exposant la [loi de Weber](https://en.wikipedia.org/wiki/Weber%E2%80%93Fechner_law#Weber's_law), « les nombres trop proches les uns des autres sont impossibles à distinguer comme estimations ».

Lorsque vous déterminez la valeur d'un seul point de story, il est utile de définir comme référence qu'un seul point de story correspond à la journée « idéale » d'une personne développeuse. Lors d'une telle journée, la personne développeuse est très productive, n'est bloquée par rien et maintient un flux de travail tout au long de la journée.

Vous pouvez travailler avec votre équipe pour convenir d'une valeur différente pour un seul point de story. Il est essentiel qu'une fois la définition arrêtée, vous ne la modifiiez pas. Si vous la modifiez, sachez que votre vélocité et votre volatilité seront probablement inexactes pour les quelques sprints suivants.

Par exemple, si vous vous fixez comme objectif de livrer quatre à dix user stories par itération, découpez toute story dont la valeur en points est supérieure à trois en deux stories ou plus de plus petite taille. Idéalement, votre équipe devrait chercher à découper ou combiner les stories jusqu'à ce qu'elles valent un ou deux points.

> [!note]
> Les parties prenantes ne doivent jamais utiliser les points de story pour mesurer la performance de l'équipe ou [comparer une équipe à une autre](https://towardsdatascience.com/why-story-points-are-a-horrible-metric-for-software-engineers-421bc8971f11/).

## Vélocité et volatilité {#velocity-and-volatility}

Au fil du temps, les équipes peuvent utiliser les points de story pour comprendre leur vélocité. La compréhension de la vélocité est utile lorsque vous ajustez la taille de la portée des sprints et que vous définissez des attentes plus fiables auprès des parties prenantes extérieures à l'équipe.

Vous pouvez calculer la **vélocité** en faisant la moyenne du nombre de points de story livrés sur plusieurs sprints précédents.

La **volatilité** représente l'écart type du nombre de points de story livrés lors des sprints précédents, divisé par votre vélocité actuelle.

Connaître la volatilité de votre équipe est important pour comprendre dans quelle mesure vous êtes prévisible dans la réalisation des stories d'une itération à l'autre. L'un des domaines les plus critiques sur lesquels se concentrer est la réduction de la volatilité de votre équipe.

Les sections suivantes examinent deux équipes qui ont chacune terminé le même nombre de points de story sur neuf itérations. Vous verrez comment une volatilité plus faible offre une meilleure prévisibilité dans la prévision des performances futures de l'équipe, ce qui permet aux équipes de définir de meilleures attentes auprès des parties prenantes.

### Créer une feuille de calcul de suivi de la vélocité et de la volatilité {#create-a-velocity-and-volatility-tracker-spreadsheet}

Tant que la vélocité et la volatilité ne sont pas intégrées nativement dans GitLab (voir l'[epic 435](https://gitlab.com/groups/gitlab-org/-/epics/435)), vous pouvez suivre la vélocité et la volatilité de votre équipe dans une feuille de calcul telle que la suivante :

![Feuille de calcul montrant le tracker de vélocité et de volatilité d'une équipe Scrum.](img/velocity_chart_v17_3.png)

Cet exemple utilise Google Sheets. Vous devrez peut-être adapter les formules à votre logiciel de feuille de calcul préféré.

Pour créer une telle feuille de calcul, créez et renseignez les colonnes suivantes.

Pour calculer la vélocité et la volatilité actuelles :

- **Itération** : numéros ou titres des itérations passées.
- **Points de story réalisés**
- **Vélocité** :
  - Le nombre dans la première cellule est identique à celui de la colonne **Points de story réalisés**.
  - Toutes les autres cellules affichent le nombre moyen de points de story livrés sur plusieurs sprints précédents. Cet exemple utilise jusqu'à quatre sprints.
  - Par exemple, la cellule `C10` contient la formule suivante : `=AVERAGE(B7:B10)`.
- **Volatilité** :
  - Calculez l'écart type du nombre de points de story livrés lors des sprints précédents, divisé par votre vélocité actuelle.
  - Par exemple, la cellule `D10` contient la formule suivante : `=(STDEV(B7:B10)/C10)`.

Pour prévoir le nombre futur de points de story réalisés :

- Une cellule pour les points du backlog restants. Dans cet exemple, il s'agit de `F4`.
- **Itération future** : numéros ou titres des itérations futures.
- **Pire cas** : la prévision du pire cas pour les points de story restants après chaque itération.
  - Le calcul se réfère à la vélocité et à la volatilité de la dernière itération terminée. Ici :
    - Volatilité : `C10`
    - Vélocité : `D10`
  - La formule dans la première cellule soustrait à partir du nombre dans la cellule `F4`. Par exemple : `=F4-(C10*(1-D10))`.
  - Toutes les autres cellules soustraient à partir de la cellule supérieure. Par exemple, la cellule `H10` contient la formule suivante : `=H9-($C$10*(1-$D$10))`.
- **Attendu** : une prévision réaliste des points de story restants après chaque itération, soustrayant la dernière vélocité calculée des points de story restants.
  - La formule dans la première cellule soustrait à partir du nombre dans la cellule `F4`. Par exemple : `=F4-$C$10`.
  - Toutes les autres cellules soustraient à partir de la cellule supérieure. Par exemple, la cellule `I10` contient la formule suivante : `=I9-$C$10`.
- **Meilleur cas** : la prévision du meilleur cas pour les points de story restants après chaque itération.
  - Comme pour le pire cas, le calcul se réfère à la vélocité et à la volatilité de la dernière itération terminée.
  - La formule dans la première cellule soustrait à partir du nombre dans la cellule `F4`. Par exemple : `=F4-(C10*(1+D10))`.
  - Toutes les autres cellules soustraient à partir de la cellule supérieure. Par exemple, la cellule `J10` contient la formule suivante : `=J9-($C$10*(1+$D$10))`.
- Graphique en courbes pour illustrer la prévision :
  - Intitulez le graphique `Worst Case, Expected and Best Case`
  - Définissez la plage sur les quatre colonnes ci-dessus.
  - Définissez la colonne Itération future comme axe X.
  - Ajoutez une série pour chacune des colonnes restantes.
  - Cochez les cases suivantes : **Utiliser la ligne 1 comme en-têtes**, **Utiliser la colonne G comme étiquettes**, **Traiter les étiquettes comme du texte**.

Pour maintenir le tracker à jour, à la fin de chaque sprint, mettez-le à jour avec le nombre de points de story réalisés par votre équipe.

### Une volatilité élevée diminue la prévisibilité {#high-volatility-decreases-predictability}

Le premier exemple est celui d'une équipe avec une volatilité élevée sur les neuf derniers sprints :

| Itération | Points de story réalisés | Vélocité | Volatilité |
| --------- | ---------------------- | -------- | ---------- |
| 1         | 8                      | 8        | 0 %         |
| 2         | 15                     | 11,5     | 43 %        |
| 3         | 11                     | 11,33    | 40 %        |
| 4         | 7                      | 10,25    | 35 %        |
| 5         | 6                      | 9,75     | 42 %        |
| 6         | 15                     | 9,75     | 42 %        |
| 7         | 10                     | 9,5      | 43 %        |
| 8         | 6                      | 9,25     | 46 %        |
| 9         | 8                      | 9,75     | 40 %        |

En supposant que l'équipe dispose de 200 points restants dans son backlog, vous pouvez utiliser sa vélocité et sa volatilité actuelles pour prédire les scénarios du pire cas, attendu et du meilleur cas quant au nombre de sprints supplémentaires nécessaires pour compléter le backlog.

![Graphique de prévision à volatilité élevée montrant un large écart entre les scénarios du meilleur et du pire cas.](img/high_volatility_v17_3.png)

L'équipe livrera le backlog :

- Dans le meilleur cas, en 24 sprints.
- Dans le scénario attendu, en 30 sprints.
- Dans le pire cas, en 43 sprints.

Si chaque sprint dure deux semaines et que d'autres fonctions métier s'appuient sur les dates de livraison estimées pour coordonner leur travail, un écart de 38 semaines entre les meilleurs, attendus et pires cas n'est pas très exploitable. Cette grande variabilité érode la confiance entre l'équipe Scrum et le reste de l'organisation.

### Une faible volatilité augmente la prévisibilité {#low-volatility-increases-predictability}

Le deuxième exemple examine une équipe avec une faible volatilité sur les neuf derniers sprints :

| Itération | Points de story réalisés | Vélocité | Volatilité |
| --------- | ---------------------- | -------- | ---------- |
| 1         | 9                      | 9        | 0 %         |
| 2         | 10                     | 9,5      | 8 %         |
| 3         | 11                     | 10       | 10 %        |
| 4         | 9                      | 9,75     | 10 %        |
| 5         | 8                      | 9,5      | 14 %        |
| 6         | 10                     | 9,5      | 14 %        |
| 7         | 9                      | 9        | 9 %         |
| 8         | 11                     | 9,5      | 14 %        |
| 9         | 9                      | 9,75     | 10 %        |

Comme l'équipe précédente, celle-ci avait la même vélocité finale, mais une métrique de volatilité bien plus faible. Avec la même taille de backlog de 200 points de story, cette équipe est bien plus confiante pour communiquer un calendrier plus réaliste et prévisible pour l'achèvement du backlog :

![Graphique de prévision à faible volatilité montrant un écart réduit entre les scénarios.](img/low_volatility_v17_3.png)

Les deux équipes ont réalisé le même nombre de points de story. Cependant, l'équipe avec la volatilité la plus faible peut communiquer une fenêtre de livraison de 28 à 32 sprints (contre 24 à 43), ce qui ne représente que huit semaines de variabilité dans le calendrier. Ce niveau de prévisibilité favorise la confiance entre l'équipe Scrum et le reste de l'organisation.

### Réduire la volatilité {#reducing-volatility}

Si vous constatez une volatilité élevée, vous pouvez explorer les pistes suivantes :

1. Maintenez une équipe produit stable et concentrée.

   Supposons que les membres de l'équipe répartissent leur temps sur de nombreux flux de travail et ne soient pas affectés de manière constante à la même équipe et au même flux de travail d'un sprint à l'autre. Dans ce cas, cela peut entraîner des fluctuations de la vélocité.
1. Décomposez les stories en tranches verticales plus petites.

   Examinez vos stories récemment terminées et évaluez les écarts en termes de points de story. Une story à cinq points présente bien plus de complexité et d'inconnues qu'une story à un seul point. Adoptez une démarche intentionnelle en équipe pour n'intégrer dans une itération que des stories avec un poids d'un ou deux. Si vous ne parvenez pas à réduire la taille d'une grande story, envisagez de réaliser un [engineering spike](https://www.jamesshore.com/v2/books/aoad1/spike_solutions). Comprenez le chemin d'implémentation et identifiez comment votre équipe peut aborder la story de manière plus incrémentale et itérative.
1. Identifiez vos goulots d'étranglement dans les processus.

   Vous pouvez créer un [rapport d'analyse de la chaîne de valeur personnalisé](../../user/group/value_stream_analytics/_index.md#with-custom-stages) qui reflète les étapes du workflow qu'une story traverse lors d'un sprint. Ce rapport peut aider à concentrer les discussions de vos rétrospectives sur les étapes de workflow spécifiques qui prennent le plus de temps lors de vos cycles de sprint.

## Sujets connexes {#related-topics}

- [Tutoriel : configurer un tableau de tickets pour un stand-up d'équipe](../boards_for_standups/_index.md)
