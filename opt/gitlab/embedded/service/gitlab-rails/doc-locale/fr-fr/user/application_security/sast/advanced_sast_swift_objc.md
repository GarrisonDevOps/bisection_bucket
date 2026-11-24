---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Configuration avancée de SAST pour Swift et Objective-C
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : version bêta

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/16318) en [version bêta](../../../policy/development_stages_support.md#beta) dans GitLab 19.3.
- L'analyse incrémentielle a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249721) dans GitLab 19.4.

{{< /history >}}

GitLab Advanced SAST analyse le code Swift et Objective-C à l'aide d'une analyse de contamination inter-fichiers et inter-fonctions, ce qui étend la couverture de [GitLab Advanced SAST](gitlab_advanced_sast.md) aux applications iOS.

L'analyse Swift et Objective-C s'exécute en tant que job CI/CD distinct, `gitlab-advanced-sast-ext`, fourni avec sa propre image de conteneur. Aucune configuration supplémentaire n'est requise. Lorsque GitLab Advanced SAST est activé, le job s'exécute si le dépôt contient des fichiers Swift (`.swift`), Objective-C (`.m`) ou Objective-C++ (`.mm`).

## Activer l'analyse GitLab Advanced SAST pour Swift et Objective-C {#turn-on-gitlab-advanced-sast-swift-and-objective-c-analysis}

Prérequis :

- [Activer GitLab Advanced SAST](gitlab_advanced_sast.md#turn-on-gitlab-advanced-sast).

L'analyse Swift et Objective-C utilise la même variable d'activation que les autres langages pris en charge :

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  GITLAB_ADVANCED_SAST_ENABLED: "true"
```

Lorsque cette variable est définie et que le dépôt contient des fichiers Swift ou Objective-C, GitLab ajoute le job `gitlab-advanced-sast-ext` à l'étape `test` du pipeline.

## Désactiver l'analyse GitLab Advanced SAST pour Swift et Objective-C {#turn-off-gitlab-advanced-sast-swift-and-objective-c-analysis}

Pour désactiver l'analyse Swift et Objective-C tout en maintenant GitLab Advanced SAST activé pour les autres langages, ajoutez `gitlab-advanced-sast-ext` à la variable `SAST_EXCLUDED_ANALYZERS` :

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  GITLAB_ADVANCED_SAST_ENABLED: "true"
  SAST_EXCLUDED_ANALYZERS: "gitlab-advanced-sast-ext"
```

Pour désactiver entièrement GitLab Advanced SAST, y compris l'analyse Swift et Objective-C, définissez `GITLAB_ADVANCED_SAST_ENABLED` sur `"false"`.

Si `GITLAB_ADVANCED_SAST_ENABLED` est défini en tant que variable CI/CD de groupe, une valeur dans le fichier `.gitlab-ci.yml` du projet ne le remplace pas. Pour remplacer une variable de groupe, définissez une variable CI/CD de projet portant le même nom. Pour plus d'informations, consultez [Priorité des variables CI/CD](../../../ci/variables/_index.md#cicd-variable-precedence).

## Analyse incrémentielle {#incremental-scanning}

L'analyse incrémentielle est activée par défaut. L'analyseur met en cache son store d'analyse de contamination entre les exécutions de pipeline, puis réanalyse uniquement les fichiers dont le code ou les dépendances ont changé, et réutilise les résultats mis en cache pour le code inchangé. Cela réduit les temps d'analyse sur les grandes bases de code où la plupart du code ne change pas entre les commits.

Pour les autres langages GitLab Advanced SAST, la fonctionnalité équivalente est l'[analyse incrémentielle](gitlab_advanced_sast.md#incremental-scanning), qui est désactivée par défaut et configurée avec différentes variables CI/CD.

Le job `gitlab-advanced-sast-ext` transporte le store d'un pipeline à l'autre en utilisant le `cache:` du job, indexé par la branche avec repli sur la branche par défaut.

La réutilisation du cache nécessite que le runner ait accès au cache précédent. Si votre instance utilise plusieurs runners sans [mise en cache distribuée](https://docs.gitlab.com/runner/configuration/autoscale/#distributed-runners-caching), le store peut ne pas être disponible et l'analyseur effectue une analyse complète.

### Désactiver l'analyse incrémentielle {#turn-off-incremental-scanning}

Pour désactiver l'analyse incrémentielle et analyser tout le code à chaque exécution, définissez la variable `GITLAB_ADVANCED_SAST_EXT_INCREMENTAL_ENABLED` sur `"false"` :

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  GITLAB_ADVANCED_SAST_ENABLED: "true"
  GITLAB_ADVANCED_SAST_EXT_INCREMENTAL_ENABLED: "false"
```

### Désactiver le cache {#disable-the-cache}

La désactivation de l'analyse incrémentielle maintient `cache:` actif, de sorte que chaque pipeline continue de charger et de télécharger le store. Le store reste initialisé, ce qui vous permet de réactiver l'analyse incrémentielle et de le réutiliser immédiatement.

Pour supprimer également le coût du cache de chaque pipeline, remplacez le job par un `cache:` vide :

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  GITLAB_ADVANCED_SAST_ENABLED: "true"

gitlab-advanced-sast-ext:
  cache: []
```

Avec le cache désactivé, chaque pipeline effectue une analyse complète sans coût de cache. La réactivation de l'analyse incrémentielle nécessite alors une analyse complète pour initialiser à nouveau le store.

## Couverture des vulnérabilités {#vulnerability-coverage}

L'analyseur trace les entrées non fiables depuis les sources jusqu'aux sinks vulnérables à travers les fichiers et les fonctions. En plus des types de faiblesses générales tels que l'injection SQL et la transmission en clair d'informations sensibles, il modélise les API et flux de données spécifiques à iOS, notamment :

- Les liens profonds et les schémas d'URL personnalisés en tant que sources d'entrées non fiables.
- Les classes d'accessibilité des éléments du trousseau de clés.
- Stockage de données sensibles dans `UserDefaults`, le pasteboard et les fichiers locaux.
- Chargement de contenu WebKit et UIWebView.

Pour la liste complète des types de faiblesses détectées par l'analyseur, consultez [Couverture CWE pour Swift et Objective-C](advanced_sast_coverage.md#swift-and-objective-c-cwe-coverage).

## Pipelines FIPS {#fips-pipelines}

Aucune image compatible FIPS n'est disponible pour l'analyse Swift et Objective-C pendant la version bêta. Comme pour les autres analyseurs, une image conforme FIPS est disponible uniquement pour GitLab Advanced SAST et l'analyseur basé sur Semgrep.

Dans les pipelines qui utilisent des [images compatibles FIPS](_index.md#fips-enabled-images), le job `gitlab-advanced-sast-ext` s'exécute tout de même et échoue car il ne peut pas extraire une image compatible FIPS. Pour utiliser SAST de manière conforme FIPS, [désactivez l'analyse Swift et Objective-C](#turn-off-gitlab-advanced-sast-swift-and-objective-c-analysis).

## Problèmes connus {#known-issues}

Pendant la version bêta, l'analyse Swift et Objective-C présente les problèmes connus suivants :

- Les [environnements hors ligne](../offline_deployments/_index.md) ne sont pas pris en charge.
- Les résultats ne sont pas dédupliqués par rapport aux résultats de l'analyseur SAST basé sur Semgrep. Lorsque les deux analyseurs détectent la même vulnérabilité dans un fichier Swift ou Objective-C, les deux résultats sont signalés.
- Les [ensembles de règles personnalisés](customize_rulesets.md) ne sont pas pris en charge.
- L'[analyse par différence](gitlab_advanced_sast.md#diff-based-scanning) n'est pas prise en charge.
