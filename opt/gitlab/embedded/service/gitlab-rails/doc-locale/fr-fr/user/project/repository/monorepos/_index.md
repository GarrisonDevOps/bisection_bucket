---
stage: Tenant Scale
group: Gitaly
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Améliorer les performances des monodépôts
---

Un monodépôt est un dépôt qui contient des sous-projets. Une seule application contient souvent des projets interdépendants. Par exemple, un backend, un frontend web, une application iOS et une application Android. Les monodépôts sont courants, mais ils peuvent présenter des risques de performance. Problèmes courants :

- Fichiers binaires volumineux.
- Nombreux fichiers avec de longs historiques.
- Nombreux clones et push simultanés.
- Limites de mise à l'échelle verticale.
- Limites de bande passante réseau.
- Limites de bande passante disque.

GitLab est lui-même basé sur Git. Son service de stockage Git, [Gitaly](https://gitlab.com/gitlab-org/gitaly), est confronté aux contraintes de performance associées aux monodépôts. Ce que nous avons appris peut vous aider à mieux gérer votre propre monodépôt.

- Les caractéristiques d'un dépôt susceptibles d'avoir un impact sur les performances.
- Quelques outils et étapes pour optimiser les monodépôts.

## Optimiser Gitaly pour les monodépôts {#optimize-gitaly-for-monorepos}

Git compresse les objets en [packfiles](https://git-scm.com/book/en/v2/Git-Internals-Packfiles) pour utiliser moins d'espace. Lorsque vous clonez, récupérez ou poussez des données, Git utilise des packfiles. Ces fichiers réduisent l'espace disque et la bande passante réseau, mais la création de packfiles nécessite beaucoup de CPU et de mémoire.

Les monodépôts massifs comportent plus de commits, de fichiers, de branches et de tags que les dépôts de plus petite taille. Lorsque les objets grossissent et que leur transfert prend plus de temps, la création de packfiles devient plus coûteuse et plus lente. Dans Git, le processus [`git-pack-objects`](https://git-scm.com/docs/git-pack-objects) est l'opération la plus gourmande en ressources, car il :

1. Analyse l'historique des commits et les fichiers.
1. Détermine les fichiers à renvoyer au client.
1. Crée des packfiles.

Le trafic provenant de `git clone` et de `git fetch` lance un processus `git-pack-objects` sur le serveur. Les systèmes d'intégration continue automatisés, comme GitLab CI/CD, peuvent générer une grande partie de ce trafic. Des volumes élevés de trafic CI/CD automatisé envoient de nombreuses requêtes de clone et de fetch, ce qui peut solliciter fortement votre serveur Gitaly.

Utilisez ces stratégies pour réduire la charge sur votre serveur Gitaly.

### Activer le cache `pack-objects` de Gitaly {#enable-the-gitaly-pack-objects-cache}

Activez le [cache `pack-objects` de Gitaly](../../../../administration/gitaly/configure_gitaly.md#pack-objects-cache), qui réduit la charge du serveur pour les clones et les fetchs.

Lorsqu'un client Git envoie une requête de clone ou de fetch, les données produites par `git-pack-objects` peuvent être mises en cache pour être réutilisées. Si votre monodépôt est cloné fréquemment, l'activation du [cache `pack-objects` de Gitaly](../../../../administration/gitaly/configure_gitaly.md#pack-objects-cache) réduit la charge du serveur. Lorsqu'il est activé, Gitaly maintient un cache en mémoire au lieu de régénérer les données de réponse pour chaque appel de clone ou de fetch.

Pour plus d'informations, consultez [Cache pack-objects](../../../../administration/gitaly/configure_gitaly.md#pack-objects-cache).

### Configurer les URI de bundle Git {#configure-git-bundle-uris}

Créez et stockez des [bundles Git](https://git-scm.com/docs/bundle-uri) sur un stockage tiers à faible latence, comme un CDN. Git télécharge d'abord les paquets depuis votre bundle, puis récupère les objets et références restants depuis votre remote Git. Cette approche initialise votre base de données d'objets plus rapidement et réduit la charge sur Gitaly.

- Elle accélère les clones et les fetchs pour les utilisateurs dont la connexion réseau au serveur GitLab est médiocre.
- Elle réduit la charge sur les serveurs qui exécutent des jobs CI/CD en pré-chargeant des bundles.

Pour en savoir plus, consultez [URI de bundle](../../../../administration/gitaly/bundle_uris.md).

### Configurer les délais d'expiration de négociation Gitaly {#configure-gitaly-negotiation-timeouts}

Lors de tentatives de fetch ou d'archivage de dépôts, des erreurs `fatal: the remote end hung up unexpectedly` peuvent survenir si vous avez :

- Des dépôts volumineux.
- De nombreux dépôts en parallèle.
- Le même dépôt volumineux en parallèle.

Pour atténuer ce problème, augmentez les [valeurs de délai de négociation par défaut](../../../../administration/settings/gitaly_timeouts.md#configure-the-negotiation-timeouts).

### Dimensionner correctement votre matériel {#size-your-hardware-correctly}

Les monodépôts sont généralement destinés aux organisations de grande taille avec de nombreux utilisateurs. Pour prendre en charge votre monodépôt, votre environnement GitLab doit correspondre à l'une des [architectures de référence](../../../../administration/reference_architectures/_index.md) fournies par les équipes GitLab Test Platform et Support. Ces architectures constituent la méthode recommandée pour déployer GitLab à grande échelle tout en maintenant les performances.

### Réduire le nombre de références Git {#reduce-the-number-of-git-references}

Dans Git, les [références](https://git-scm.com/book/en/v2/Git-Internals-Git-References) sont des noms de branches et de tags qui pointent vers des commits spécifiques. Git stocke les références sous forme de fichiers libres dans le dossier `.git/refs` de votre dépôt. Pour afficher toutes les références de votre dépôt, exécutez `git for-each-ref`.

Lorsque le nombre de références dans votre dépôt augmente, le temps de recherche nécessaire pour trouver une référence spécifique augmente également. Chaque fois que Git analyse une référence, le temps de recherche accru entraîne une latence accrue.

Pour résoudre ce problème, Git utilise [pack-refs](https://git-scm.com/docs/git-pack-refs) pour créer un fichier unique `.git/packed-refs` contenant toutes les références de ce dépôt. Cette méthode réduit l'espace de stockage nécessaire pour les références. Elle réduit également le temps de recherche, car la recherche dans un seul fichier est plus rapide que la recherche dans tous les fichiers d'un répertoire.

Git gère les références nouvellement créées ou mises à jour avec des fichiers libres. Elles ne sont pas nettoyées et ajoutées au fichier `.git/packed-refs` tant que vous n'avez pas exécuté `git pack-refs`. Gitaly exécute `git pack-refs` lors de l'[entretien](../../../../administration/housekeeping.md#heuristical-housekeeping). Bien que cela aide de nombreux dépôts, les dépôts à forte écriture présentent encore ces problèmes de performance :

- La création ou la mise à jour de références crée de nouveaux fichiers libres.
- La suppression de références nécessite la modification du fichier `packed-refs` existant pour supprimer la référence existante.

Git itère à travers toutes les références lorsque vous fetchez ou clonez un dépôt. Le serveur examine (« parcourt ») la structure de graphe interne de chaque référence, trouve les objets manquants et les envoie au client. Les processus d'itération et de parcours sont gourmands en CPU et augmentent la latence. Cette latence peut provoquer un effet domino dans les dépôts à forte activité. Chaque opération est plus lente, et chaque opération retarde les opérations suivantes.

Pour atténuer les effets d'un grand nombre de références dans un monodépôt :

- Créez un processus automatisé pour nettoyer les anciennes branches.
- Si certaines références n'ont pas besoin d'être visibles par le client, masquez-les à l'aide du paramètre de configuration [`transfer.hideRefs`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-transferhideRefs). Gitaly ignore toute configuration Git côté serveur ; vous devez donc modifier la configuration Gitaly elle-même dans `/etc/gitlab/gitlab.rb` :

  ```ruby
  gitaly['configuration'] = {
    # ...
    git: {
      # ...
      config: [
        # ...
        { key: "transfer.hideRefs", value: "refs/namespace_to_hide" },
      ],
    },
  }
  ```

Dans Git 2.42.0 et versions ultérieures, différentes opérations Git peuvent ignorer les références masquées lors d'un parcours du graphe d'objets.

### Planifier les tâches d'optimisation du dépôt {#schedule-repository-optimization-tasks}

La façon dont les données sont stockées dans la base de données d'objets d'un dépôt Git peut devenir inefficace avec le temps, ce qui ralentit les opérations Git. Vous pouvez [planifier l'exécution d'une tâche quotidienne en arrière-plan par Gitaly](../../../../administration/housekeeping.md#configure-scheduled-housekeeping) avec une durée maximale pour nettoyer ces éléments et améliorer les performances.

## Optimiser CI/CD pour les monodépôts {#optimize-cicd-for-monorepos}

Pour maintenir la scalabilité de GitLab avec votre monodépôt, optimisez la façon dont vos jobs CI/CD interagissent avec votre dépôt. Les pipelines longs et volumineux sont des points de friction courants pour les monodépôts. Dans la configuration du pipeline de votre monodépôt, utilisez des [règles de build](../../../../ci/yaml/_index.md#rules) qui détectent le type de modifications apportées et :

- Ignorent les jobs inutiles.
- N'exécutent que les jobs pertinents dans les pipelines enfants.

### Réduire les clones simultanés dans CI/CD {#reduce-concurrent-clones-in-cicd}

Réduisez la simultanéité des pipelines CI/CD en [échelonnant vos pipelines planifiés](../../../../ci/pipelines/schedules.md#distribute-pipeline-schedules-to-prevent-system-load) pour qu'ils s'exécutent à des moments différents. Même quelques minutes d'écart peuvent aider.

Les charges CI/CD sont souvent simultanées, car les pipelines sont [planifiés à des heures précises](../../../../ci/pipelines/pipeline_efficiency.md#reduce-how-often-jobs-run). Les requêtes Git vers votre dépôt peuvent connaître des pics durant ces périodes, ce qui affecte les performances des processus CI/CD et des utilisateurs.

### Utiliser des clones superficiels et des filtres dans les processus CI/CD {#use-shallow-clones-and-filters-in-cicd-processes}

Pour les appels `git clone` et `git fetch` dans vos systèmes CI/CD, la quantité de données transférées peut être limitée avec ces options :

- [`--depth`](https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---depthltdepthgt)
- [`--filter`](https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---filterfilter-spec)

#### Clone superficiel dans CI/CD {#shallow-clone-in-cicd}

Le filtre `--depth` crée ce que l'on appelle un _clone superficiel_. GitLab et GitLab Runner effectuent un [clone superficiel](../../../../ci/pipelines/settings.md#limit-the-number-of-changes-fetched-during-clone) par défaut.

La profondeur de clone peut être configurée dans la configuration du pipeline CI/CD GitLab avec `GIT_DEPTH`, par exemple :

```yaml
variables:
  GIT_DEPTH: 10

test:
  script:
    - ls -al
```

#### Clone partiel dans CI/CD {#partial-clone-in-cicd}

Vous créez un _clone partiel_ en utilisant l'option `--filter`. Pour passer cet argument à `git-clone`, définissez la variable `GIT_CLONE_EXTRA_FLAGS`. Par exemple, pour limiter la taille maximale des blobs à 1 Mo, ajoutez :

```yaml
variables:
  GIT_CLONE_EXTRA_FLAGS: --filter=blob:limit=1m
```

### Filtrer les chemins et les types d'objets {#filter-out-paths-and-object-types}

Pour filtrer les objets de types spécifiques ou issus de chemins spécifiques, utilisez l'option `git sparse-checkout`. Pour plus d'informations, consultez [filtrer par chemin de fichier](../../../../topics/git/clone.md#filter-by-file-path).

### Utiliser `git fetch` dans les opérations CI/CD {#use-git-fetch-in-cicd-operations}

S'il est possible de conserver une copie de travail du dépôt disponible, utilisez `git fetch` plutôt que `git clone` sur les systèmes CI/CD. `git fetch` nécessite moins de travail de la part du serveur :

- `git clone` demande l'intégralité du dépôt depuis le début. `git-pack-objects` doit traiter et envoyer toutes les branches et tous les tags.
- `git fetch` ne demande que les références Git manquantes dans le dépôt. `git-pack-objects` ne traite qu'un sous-ensemble de l'ensemble des références Git. Cette stratégie réduit également le volume total de données transférées.

Par défaut, GitLab utilise la [stratégie Git `fetch`](../../../../ci/runners/configure_runners.md#git-strategy) recommandée pour les dépôts volumineux.

### Définir un chemin pour `git clone` {#set-a-git-clone-path}

Si votre monodépôt est utilisé avec un workflow basé sur la duplication, envisagez de définir [`GIT_CLONE_PATH`](../../../../ci/runners/configure_runners.md#custom-build-directories) pour contrôler l'emplacement où vous clonez votre dépôt.

Git stocke les duplications sous forme de dépôts séparés avec des worktrees distincts. GitLab Runner ne peut pas optimiser l'utilisation des worktrees. Configurez et utilisez l'exécuteur GitLab Runner uniquement pour le projet concerné. Pour rendre le processus plus efficace, ne le partagez pas entre différents projets.

Le [`GIT_CLONE_PATH`](../../../../ci/runners/configure_runners.md#custom-build-directories) doit se trouver dans le répertoire défini dans `$CI_BUILDS_DIR`. Vous ne pouvez pas choisir n'importe quel chemin sur le disque.

### Désactiver `git clean` sur les jobs CI/CD {#disable-git-clean-on-cicd-jobs}

La commande `git clean` supprime les fichiers non suivis de l'arbre de travail. Dans les dépôts volumineux, elle génère beaucoup d'E/S disque. Si vous réutilisez des machines existantes et pouvez réutiliser un worktree existant, envisagez de la désactiver sur les jobs CI/CD. Par exemple, `GIT_CLEAN_FLAGS: -ffdx -e .build/` peut éviter la suppression de répertoires du worktree entre les exécutions. Cela peut accélérer les builds incrémentiels.

Pour désactiver `git clean` sur les jobs CI/CD, définissez [`GIT_CLEAN_FLAGS`](../../../../ci/runners/configure_runners.md#git-clean-flags) sur `none` pour ces jobs.

Par défaut, GitLab garantit que :

- Votre worktree est sur le SHA indiqué.
- Votre dépôt est propre.

Pour connaître les paramètres exacts acceptés par `GIT_CLEAN_FLAGS`, consultez la documentation Git pour [`git clean`](https://git-scm.com/docs/git-clean). Les paramètres disponibles dépendent de votre version de Git.

### Modifier le comportement de `git fetch` avec des indicateurs {#change-git-fetch-behavior-with-flags}

Modifiez le comportement de `git fetch` pour exclure toutes les données dont vos jobs CI/CD n'ont pas besoin. Si votre projet contient de nombreux tags et que vos jobs CI/CD n'en ont pas besoin, utilisez `GIT_FETCH_EXTRA_FLAGS` pour définir [`--no-tags`](https://git-scm.com/docs/git-fetch#Documentation/git-fetch.txt---no-tags). Ce paramètre peut accélérer vos fetchs et les rendre plus compacts.

Même si votre dépôt ne contient pas beaucoup de tags, `--no-tags` peut améliorer les performances dans certains cas. Pour plus d'informations, consultez [le ticket 746](https://gitlab.com/gitlab-com/gl-infra/observability/team/-/issues/746) et la [documentation Git pour `GIT_FETCH_EXTRA_FLAGS`](../../../../ci/runners/configure_runners.md#git-fetch-extra-flags).

### Utiliser le long polling pour les runners {#use-long-polling-for-runners}

Les runners interrogent périodiquement une instance GitLab pour de nouveaux jobs CI/CD. L'intervalle d'interrogation dépend de :

- Du paramètre `check_interval`.
- Du nombre de runners configurés dans votre fichier de configuration des runners.

Si votre serveur gère de nombreux runners, cette interrogation peut entraîner des problèmes de performance sur l'instance GitLab, tels que des temps de mise en file d'attente plus longs et une utilisation plus élevée du CPU. Le long polling maintient les requêtes de jobs des runners en attente jusqu'à ce qu'un nouveau job soit prêt.

Pour les instructions de configuration, consultez [le long polling](../../../../ci/runners/long_polling.md).

## Optimiser Git pour les monodépôts {#optimize-git-for-monorepos}

Pour maintenir la scalabilité de GitLab avec votre monodépôt, optimisez le dépôt lui-même.

### Éviter les clones superficiels pour le développement {#avoid-shallow-clones-for-development}

Évitez les clones superficiels pour le développement. Les clones superficiels augmentent considérablement le temps nécessaire pour pousser des modifications. Les clones superficiels fonctionnent bien avec les jobs CI/CD, car le contenu du dépôt n'est pas modifié après le checkout.

Pour le développement local, utilisez plutôt des [clones partiels](https://www.git-scm.com/docs/git-clone#Documentation/git-clone.txt---filterltfilter-specgt) pour :

- Filtrer les blobs, avec `git clone --filter=blob:none`
- Filtrer les arbres, avec `git clone --filter=tree:0`

Pour plus d'informations, consultez [Réduire la taille du clone](../../../../topics/git/clone.md#reduce-clone-size).

### Profiler votre dépôt pour identifier les problèmes {#profile-your-repository-to-find-problems}

Les dépôts volumineux rencontrent généralement des problèmes de performance dans Git. Le projet [`git-sizer`](https://github.com/github/git-sizer) profile votre dépôt et vous aide à comprendre les problèmes potentiels. Il peut vous aider à développer des stratégies d'atténuation pour prévenir les problèmes de performance. L'analyse de votre dépôt nécessite un miroir Git complet ou un clone nu, afin de s'assurer que toutes les références Git sont présentes.

Pour profiler votre dépôt avec `git-sizer` :

1. [Installez `git-sizer`](https://github.com/github/git-sizer?tab=readme-ov-file#getting-started).
1. Exécutez cette commande pour cloner votre dépôt dans le format Git nu compatible avec `git-sizer` :

   ```shell
   git clone --mirror <git_repo_url>
   ```

1. Dans le répertoire de votre dépôt Git, exécutez `git-sizer` avec toutes les statistiques :

   ```shell
   git-sizer -v
   ```

Après le traitement, la sortie de `git-sizer` devrait ressembler à cet exemple. Chaque ligne inclut un **niveau de préoccupation** pour cet aspect du dépôt. Les niveaux de préoccupation élevés sont indiqués par davantage d'astérisques. Les éléments présentant des niveaux de préoccupation extrêmement élevés sont signalés par des points d'exclamation. Dans cet exemple, quelques éléments présentent un niveau de préoccupation élevé :

```shell
Processing blobs: 1652370
Processing trees: 3396199
Processing commits: 722647
Matching commits to trees: 722647
Processing annotated tags: 534
Processing references: 539
| Name                         | Value     | Level of concern               |
| ---------------------------- | --------- | ------------------------------ |
| Overall repository size      |           |                                |
| * Commits                    |           |                                |
|   * Count                    |   723 k   | *                              |
|   * Total size               |   525 MiB | **                             |
| * Trees                      |           |                                |
|   * Count                    |  3.40 M   | **                             |
|   * Total size               |  9.00 GiB | ****                           |
|   * Total tree entries       |   264 M   | *****                          |
| * Blobs                      |           |                                |
|   * Count                    |  1.65 M   | *                              |
|   * Total size               |  55.8 GiB | *****                          |
| * Annotated tags             |           |                                |
|   * Count                    |   534     |                                |
| * References                 |           |                                |
|   * Count                    |   539     |                                |
|                              |           |                                |
| Biggest objects              |           |                                |
| * Commits                    |           |                                |
|   * Maximum size         [1] |  72.7 KiB | *                              |
|   * Maximum parents      [2] |    66     | ******                         |
| * Trees                      |           |                                |
|   * Maximum entries      [3] |  1.68 k   | *                              |
| * Blobs                      |           |                                |
|   * Maximum size         [4] |  13.5 MiB | *                              |
|                              |           |                                |
| History structure            |           |                                |
| * Maximum history depth      |   136 k   |                                |
| * Maximum tag depth      [5] |     1     |                                |
|                              |           |                                |
| Biggest checkouts            |           |                                |
| * Number of directories  [6] |  4.38 k   | **                             |
| * Maximum path depth     [7] |    13     | *                              |
| * Maximum path length    [8] |   134 B   | *                              |
| * Number of files        [9] |  62.3 k   | *                              |
| * Total size of files    [9] |   747 MiB |                                |
| * Number of symlinks    [10] |    40     |                                |
| * Number of submodules       |     0     |                                |
```

### Utiliser Git LFS pour les fichiers binaires volumineux {#use-git-lfs-for-large-binary-files}

Stockez les fichiers binaires (comme les paquets, les fichiers audio, vidéo ou graphiques) en tant qu'objets Git Large File Storage (Git LFS).

Lorsque des utilisateurs committent des fichiers dans Git, Git utilise le [type d'objet](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects) blob pour stocker et gérer leur contenu. Git ne gère pas efficacement les données binaires volumineuses, ce qui rend les blobs volumineux problématiques pour Git. Si `git-sizer` signale des blobs de plus de 10 Mo, vous avez généralement des fichiers binaires volumineux dans votre dépôt. Les fichiers binaires volumineux posent des problèmes à la fois au serveur et au client :

- Pour le serveur : contrairement au code source textuel, les données binaires sont souvent déjà compressées. Git ne peut pas compresser davantage les données binaires, ce qui génère des packfiles volumineux. Les packfiles volumineux nécessitent plus de CPU, de mémoire et de bande passante pour être créés et envoyés.
- Pour le client : Git stocke le contenu des blobs à la fois dans les packfiles (généralement dans `.git/objects/pack/`) et dans les fichiers ordinaires (dans les [worktrees](https://git-scm.com/docs/git-worktree)). Les fichiers binaires nécessitent bien plus d'espace que le code source textuel.

Git LFS stocke les objets en externe, par exemple dans un stockage d'objets. Votre dépôt Git contient un pointeur vers l'emplacement de l'objet, plutôt que le fichier binaire lui-même. Cela peut améliorer les performances du dépôt. Pour plus d'informations, consultez la [documentation Git LFS](../../../../topics/git/lfs/_index.md).

## Sujets connexes {#related-topics}

- [Configurer Gitaly](../../../../administration/gitaly/configure_gitaly.md)
