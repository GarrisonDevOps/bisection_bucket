---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Étapes d'Auto DevOps"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les sections suivantes décrivent les étapes d'[Auto DevOps](_index.md). Lisez-les attentivement pour comprendre le fonctionnement de chacune.

## Auto Build {#auto-build}

> [!note]
> Auto Build n'est pas pris en charge si Docker in Docker n'est pas disponible pour vos GitLab Runners, comme dans les clusters OpenShift. La prise en charge d'OpenShift dans GitLab est suivie [dans un epic dédié](https://gitlab.com/groups/gitlab-org/-/epics/2068).

Auto Build crée un build de l'application à partir d'un `Dockerfile` existant ou de buildpacks Heroku. L'image Docker résultante est envoyée vers le [registre de conteneurs](../../user/packages/container_registry/_index.md) et taguée avec le SHA du commit ou le tag.

### Auto Build avec un Dockerfile {#auto-build-using-a-dockerfile}

Si le dépôt d'un projet contient un `Dockerfile` à sa racine, Auto Build utilise `docker build` pour créer une image Docker.

Si vous utilisez également Auto Review Apps et Auto Deploy, et que vous choisissez de fournir votre propre `Dockerfile`, vous devez soit :

- Exposer votre application sur le port `5000`, car le [chart Helm par défaut](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app) suppose que ce port est disponible.
- Remplacer les valeurs par défaut en [personnalisant le chart Helm Auto Deploy](customize.md#custom-helm-chart).

### Auto Build avec Cloud Native Buildpacks {#auto-build-using-cloud-native-buildpacks}

Auto Build génère un build d'une application à partir du `Dockerfile` du projet, si celui-ci est présent. Si aucun `Dockerfile` n'est présent, Auto Build génère le build de votre application à l'aide des [Cloud Native Buildpacks](https://buildpacks.io) pour détecter l'application et la builder dans une image Docker. Cette fonctionnalité utilise la [commande `pack`](https://github.com/buildpacks/pack). Le [builder](https://buildpacks.io/docs/for-app-developers/concepts/builder/) par défaut est `heroku/buildpacks:22`, mais un autre builder peut être sélectionné à l'aide de la variable CI/CD `AUTO_DEVOPS_BUILD_IMAGE_CNB_BUILDER`.

Chaque buildpack exige que le dépôt de votre projet contienne certains fichiers pour qu'Auto Build puisse builder votre application avec succès. La structure est propre au builder et aux buildpacks que vous avez sélectionnés. Par exemple, lors de l'utilisation du builder Heroku (par défaut), le répertoire racine de votre application doit contenir le fichier approprié pour le langage de votre application :

- Pour les projets Python, un fichier `Pipfile` ou `requirements.txt`.
- Pour les projets Ruby, un fichier `Gemfile` ou `Gemfile.lock`.

Pour connaître les exigences applicables aux autres langages et frameworks, consultez la [documentation des buildpacks Heroku](https://devcenter.heroku.com/articles/buildpacks#officially-supported-buildpacks).

> [!note]
> Auto Test utilise toujours Herokuish, car la détection des suites de tests ne fait pas encore partie de la spécification Cloud Native Buildpack. Pour plus d'informations, consultez le [ticket 212689](https://gitlab.com/gitlab-org/gitlab/-/issues/212689).

#### Monter des volumes dans le conteneur de build {#mount-volumes-into-the-build-container}

La variable `BUILDPACK_VOLUMES` peut être utilisée pour transmettre des définitions de montage de volumes à la commande `pack`. Les montages sont transmis à `pack build` à l'aide d'arguments `--volume`. Chaque définition de volume peut inclure toutes les fonctionnalités fournies par `build pack`, telles que le chemin hôte, le chemin cible, la possibilité d'écriture du volume, et une ou plusieurs options de volume.

Utilisez le caractère pipe `|` pour transmettre plusieurs volumes. Chaque élément de la liste est transmis à `build back` à l'aide d'un argument `--volume` distinct.

Dans cet exemple, trois volumes sont montés dans le conteneur en tant que `/etc/foo`, `/opt/foo` et `/var/opt/foo` :

```yaml
buildjob:
  variables:
    BUILDPACK_VOLUMES: /mnt/1:/etc/foo:ro|/mnt/2:/opt/foo:ro|/mnt/3:/var/opt/foo:rw
```

Pour en savoir plus sur la définition des volumes, consultez la [documentation de `pack build`](https://buildpacks.io/docs/for-platform-operators/how-to/integrate-ci/pack/cli/pack_build/).

### Migration de Herokuish vers Cloud Native Buildpacks {#moving-from-herokuish-to-cloud-native-buildpacks}

Les builds utilisant Cloud Native Buildpacks prennent en charge les mêmes options que les builds utilisant Herokuish, avec les mises en garde suivantes :

- Le buildpack doit être un Cloud Native Buildpack. Un buildpack Heroku peut être converti en Cloud Native Buildpack à l'aide du [`cnb-shim`](https://github.com/heroku/cnb-shim) de Heroku.
- `BUILDPACK_URL` doit être dans un format [pris en charge par `pack`](https://buildpacks.io/docs/app-developer-guide/specify-buildpacks/).
- La commande `/bin/herokuish` n'est pas présente dans l'image buildée, et il n'est plus nécessaire (ni possible) de préfixer les commandes avec `/bin/herokuish procfile exec`. À la place, les commandes personnalisées doivent être préfixées avec `/cnb/lifecycle/launcher` pour recevoir l'environnement d'exécution correct.

## Auto Test {#auto-test}

Auto Test exécute les tests appropriés pour votre application à l'aide de [Herokuish](https://github.com/gliderlabs/herokuish) et des [buildpacks Heroku](https://devcenter.heroku.com/articles/buildpacks) en analysant votre projet pour détecter le langage et le framework. Plusieurs langages et frameworks sont détectés automatiquement, mais si votre langage n'est pas détecté, vous pouvez peut-être créer un [buildpack personnalisé](customize.md#custom-buildpacks). Consultez les [langages actuellement pris en charge](#currently-supported-languages).

Auto Test utilise les tests déjà présents dans votre application. S'il n'y a pas de tests, c'est à vous de les ajouter.

<!-- vale gitlab_base.Spelling = NO -->

> [!note]
> Tous les buildpacks pris en charge par [Auto Build](#auto-build) ne sont pas pris en charge par Auto Test. Auto Test utilise [Herokuish](https://gitlab.com/gitlab-org/gitlab/-/issues/212689), *et non* les Cloud Native Buildpacks, et seuls les buildpacks qui implémentent la [Testpack API](https://devcenter.heroku.com/articles/testpack-api) sont pris en charge.

<!-- vale gitlab_base.Spelling = YES -->

Auto Test provisionne une base de données PostgreSQL temporaire et définit `DATABASE_URL` pour pointer vers celle-ci.

Le job Auto Test est défini dans le modèle [`Jobs/Test.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Test.gitlab-ci.yml).

### Langages actuellement pris en charge {#currently-supported-languages}

Tous les buildpacks ne prennent pas encore en charge Auto Test, car il s'agit d'une amélioration relativement récente. Tous les [langages officiellement pris en charge](https://devcenter.heroku.com/articles/heroku-ci#supported-languages) par Heroku prennent en charge Auto Test. Les langages pris en charge par les buildpacks Herokuish de Heroku prennent tous en charge Auto Test, mais le multi-buildpack ne le prend pas en charge.

Les buildpacks pris en charge sont :

```plaintext
- heroku-buildpack-multi
- heroku-buildpack-ruby
- heroku-buildpack-nodejs
- heroku-buildpack-clojure
- heroku-buildpack-python
- heroku-buildpack-java
- heroku-buildpack-gradle
- heroku-buildpack-scala
- heroku-buildpack-play
- heroku-buildpack-php
- heroku-buildpack-go
- buildpack-nginx
```

Si votre application a besoin d'un buildpack qui ne figure pas dans la liste précédente, vous pouvez utiliser un [buildpack personnalisé](customize.md#custom-buildpacks).

## Auto Code Quality {#auto-code-quality}

Auto Code Quality utilise l'[image Code Quality](https://gitlab.com/gitlab-org/ci-cd/codequality) pour exécuter une analyse statique et d'autres vérifications du code sur le code actuel. Une fois le rapport créé, il est téléversé en tant qu'artefact que vous pouvez télécharger et consulter ultérieurement. Le widget de merge request affiche également toutes les [différences entre les branches source et cible](../../ci/testing/code_quality.md).

## Auto SAST {#auto-sast}

Le test statique de sécurité des applications (SAST) exécute une analyse statique sur le code actuel et vérifie la présence de problèmes de sécurité potentiels. L'étape Auto SAST nécessite [GitLab Runner](https://docs.gitlab.com/runner/) 11.5 ou une version ultérieure.

Une fois le rapport créé, il est téléversé en tant qu'artefact que vous pouvez télécharger et consulter ultérieurement. Le widget de merge request affiche également tous les avertissements de sécurité sur les licences [Ultimate](https://about.gitlab.com/pricing/).

Pour plus d'informations, consultez [SAST](../../user/application_security/sast/_index.md).

## Détection automatique des secrets {#auto-secret-detection}

La détection des secrets utilise l'[image Docker de détection des secrets](https://gitlab.com/gitlab-org/security-products/analyzers/secrets) pour analyser le code actuel et vérifier la présence de secrets exposés.

Une fois le rapport créé, il est téléversé en tant qu'artefact que vous pouvez télécharger et évaluer ultérieurement. Le widget de merge request affiche également tous les avertissements de sécurité sur les licences [Ultimate](https://about.gitlab.com/pricing/).

Pour plus d'informations, consultez la [détection des secrets](../../user/application_security/secret_detection/_index.md).

## Analyse automatique des dépendances {#auto-dependency-scanning}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'analyse des dépendances analyse les dépendances du projet et vérifie la présence de problèmes de sécurité potentiels. L'étape d'analyse automatique des dépendances est ignorée sur les licences autres qu'[Ultimate](https://about.gitlab.com/pricing/).

Une fois le rapport créé, il est téléversé en tant qu'artefact que vous pouvez télécharger et consulter ultérieurement. Le widget de merge request affiche tous les avertissements de sécurité détectés.

Pour plus d'informations, consultez l'[analyse des dépendances](../../user/application_security/dependency_scanning/_index.md).

## Analyse automatique des conteneurs {#auto-container-scanning}

L'analyse statique des vulnérabilités pour les conteneurs utilise [Trivy](https://aquasecurity.github.io/trivy/latest/) pour vérifier la présence de problèmes de sécurité potentiels dans les images Docker. L'étape d'analyse automatique des conteneurs est ignorée sur les licences autres qu'[Ultimate](https://about.gitlab.com/pricing/).

Une fois le rapport créé, il est téléversé en tant qu'artefact que vous pouvez télécharger et consulter ultérieurement. La merge request affiche tous les problèmes de sécurité détectés.

Pour plus d'informations, consultez l'[analyse des conteneurs](../../user/application_security/container_scanning/_index.md).

## Auto Review Apps {#auto-review-apps}

Il s'agit d'une étape facultative, car de nombreux projets ne disposent pas d'un cluster Kubernetes. Si les [exigences](requirements.md) ne sont pas satisfaites, le job est ignoré silencieusement.

Les [environnements éphémères](../../ci/review_apps/_index.md) sont des environnements d'application temporaires basés sur le code de la branche, permettant aux développeurs, aux designers, aux équipes QA, aux chefs de produit et aux autres relecteurs de voir et d'interagir concrètement avec les modifications du code dans le cadre du processus de revue. Auto Review Apps crée un environnement éphémère pour chaque branche.

Auto Review Apps déploie votre application uniquement sur votre cluster Kubernetes. Si aucun cluster n'est disponible, aucun déploiement n'est effectué.

L'environnement éphémère dispose d'une URL unique basée sur une combinaison de l'identifiant du projet, du nom de la branche ou du tag, d'un numéro unique et du domaine de base Auto DevOps, par exemple `13083-review-project-branch-123456.example.com`. Le widget de merge request affiche un lien vers l'environnement éphémère pour faciliter sa découverte. Lorsque la branche ou le tag est supprimé, par exemple après la fusion d'une merge request, l'environnement éphémère est également supprimé.

Les environnements éphémères sont déployés à l'aide du chart [auto-deploy-app](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app) avec Helm, que vous pouvez [personnaliser](customize.md#custom-helm-chart). L'application est déployée dans l'[espace de nommage Kubernetes](../../user/project/clusters/deploy_to_cluster.md#deployment-variables) correspondant à l'environnement.

[Local Tiller](https://gitlab.com/gitlab-org/gitlab-foss/-/merge_requests/22036) est utilisé. Les versions précédentes de GitLab disposaient d'un Tiller installé dans l'espace de nommage du projet.

> [!warning]
> Vos applications ne doivent pas être manipulées en dehors de Helm (en utilisant Kubernetes directement). Cela peut entraîner une confusion avec Helm qui ne détecte pas le changement, et les déploiements suivants avec Auto DevOps peuvent annuler vos modifications. De plus, si vous modifiez quelque chose et souhaitez annuler la modification en redéployant, Helm peut ne pas détecter qu'un changement a eu lieu et, par conséquent, ne pas réaliser qu'il doit réappliquer l'ancienne configuration.

## Auto DAST {#auto-dast}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le test dynamique de sécurité des applications (DAST) utilise l'outil open source populaire [OWASP ZAProxy](https://github.com/zaproxy/zaproxy) pour analyser le code actuel et vérifier la présence de problèmes de sécurité potentiels. L'étape Auto DAST est ignorée sur les licences autres qu'[Ultimate](https://about.gitlab.com/pricing/).

- Sur votre branche par défaut, DAST analyse une application déployée spécifiquement à cet effet, sauf si vous [remplacez la branche cible](#overriding-the-dast-target). L'application est supprimée après l'exécution de DAST.
- Sur les branches de fonctionnalité, DAST analyse l'[environnement éphémère](#auto-review-apps).

Une fois l'analyse DAST terminée, tous les avertissements de sécurité sont affichés dans le [tableau de bord de sécurité](../../user/application_security/security_dashboard/_index.md) et dans le widget de merge request.

Pour plus d'informations, consultez [DAST](../../user/application_security/dast/_index.md).

### Remplacement de la cible DAST {#overriding-the-dast-target}

Pour utiliser une cible personnalisée à la place des environnements éphémères déployés automatiquement, définissez une variable CI/CD `DAST_WEBSITE` avec l'URL à analyser par DAST.

> [!warning]
> Si [DAST Full Scan](../../user/application_security/dast/browser/_index.md) est activé, GitLab déconseille fortement de définir `DAST_WEBSITE` sur un environnement de staging ou de production. DAST Full Scan attaque activement la cible, ce qui peut mettre hors service votre application et entraîner une perte ou une corruption des données.

### Ignorer Auto DAST {#skipping-auto-dast}

Vous pouvez ignorer les jobs DAST :

- Sur toutes les branches en définissant la variable CI/CD `DAST_DISABLED` sur `"true"`.
- Uniquement sur la branche par défaut en définissant la variable `DAST_DISABLED_FOR_DEFAULT_BRANCH` sur `"true"`.
- Uniquement sur les branches de fonctionnalité en définissant la variable `REVIEW_DISABLED` sur `"true"`. Cela ignore également l'environnement éphémère.

## Auto Browser Performance Testing {#auto-browser-performance-testing}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Auto [Browser Performance Testing](../../ci/testing/browser_performance_testing.md) mesure les performances navigateur d'une page web avec le [conteneur Sitespeed.io](https://hub.docker.com/r/sitespeedio/sitespeed.io/), crée un rapport JSON incluant le score de performance global pour chaque page, et téléverse le rapport en tant qu'artefact. Par défaut, il teste la page racine de vos environnements de revue et de production. Si vous souhaitez tester des URL supplémentaires, ajoutez les chemins dans un fichier nommé `.gitlab-urls.txt` dans le répertoire racine, un par ligne. Par exemple :

```plaintext
/
/features
/direction
```

Les différences de performances navigateur entre les branches source et cible sont également [affichées dans le widget de merge request](../../ci/testing/browser_performance_testing.md).

## Auto Load Performance Testing {#auto-load-performance-testing}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Auto [Load Performance Testing](../../ci/testing/load_performance_testing.md) mesure les performances serveur d'une application avec le [conteneur k6](https://hub.docker.com/r/loadimpact/k6/), crée un rapport JSON incluant plusieurs métriques de résultats clés, et téléverse le rapport en tant qu'artefact.

Une configuration initiale est nécessaire. Un test [k6](https://k6.io/) doit être rédigé et adapté à votre application spécifique. Le test doit également être configuré pour pouvoir récupérer l'URL dynamique de l'environnement via une variable CI/CD.

Les différences de résultats des tests de charge entre les branches source et cible sont également [affichées dans le widget de merge request](../../user/project/merge_requests/widgets.md).

## Auto Deploy {#auto-deploy}

Vous avez la possibilité de déployer sur [Amazon Elastic Compute Cloud (Amazon EC2)](https://aws.amazon.com/ec2/) en plus d'un cluster Kubernetes.

Auto Deploy est une étape facultative d'Auto DevOps. Si les [exigences](requirements.md) ne sont pas satisfaites, le job est ignoré.

Après la fusion d'une branche ou d'une merge request dans la branche par défaut du projet, Auto Deploy déploie l'application dans un environnement `production` du cluster Kubernetes, avec un espace de nommage basé sur le nom du projet et l'identifiant unique du projet, par exemple `project-4321`.

Auto Deploy n'inclut pas de déploiements vers des environnements de staging ou canary par défaut, mais le [modèle Auto DevOps](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Auto-DevOps.gitlab-ci.yml) contient des définitions de jobs pour ces tâches si vous souhaitez les activer.

Vous pouvez utiliser des [variables CI/CD](cicd_variables.md) pour mettre à l'échelle automatiquement vos réplicas de pods et appliquer des arguments personnalisés aux commandes `helm upgrade` d'Auto DevOps. C'est un moyen simple de [personnaliser le chart Helm Auto Deploy](customize.md#custom-helm-chart).

Helm utilise le chart [auto-deploy-app](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app) pour déployer l'application dans l'[espace de nommage Kubernetes](../../user/project/clusters/deploy_to_cluster.md#deployment-variables) correspondant à l'environnement.

[Local Tiller](https://gitlab.com/gitlab-org/gitlab-foss/-/merge_requests/22036) est utilisé. Les versions précédentes de GitLab disposaient d'un Tiller installé dans l'espace de nommage du projet.

> [!warning]
> Vos applications ne doivent pas être manipulées en dehors de Helm (en utilisant Kubernetes directement). Cela peut entraîner une confusion avec Helm qui ne détecte pas le changement, et les déploiements suivants avec Auto DevOps peuvent annuler vos modifications. De plus, si vous modifiez quelque chose et souhaitez annuler la modification en redéployant, Helm peut ne pas détecter qu'un changement a eu lieu et, par conséquent, ne pas réaliser qu'il doit réappliquer l'ancienne configuration.

### Jetons de déploiement GitLab {#gitlab-deploy-tokens}

Les [jetons de déploiement GitLab](../../user/project/deploy_tokens/_index.md#gitlab-deploy-token) sont créés pour les projets internes et privés lorsqu'Auto DevOps est activé et que les paramètres Auto DevOps sont enregistrés. Vous pouvez utiliser un jeton de déploiement pour un accès permanent au registre. Après avoir révoqué manuellement le jeton de déploiement GitLab, celui-ci n'est pas recréé automatiquement.

Si le jeton de déploiement GitLab est introuvable, `CI_REGISTRY_PASSWORD` est utilisé.

> [!note]
> `CI_REGISTRY_PASSWORD` n'est valide que pendant le déploiement. Kubernetes peut extraire l'image de conteneur avec succès lors du déploiement, mais si l'image doit être extraite à nouveau, par exemple après l'éviction d'un pod, Kubernetes ne peut pas le faire car il tente de récupérer l'image à l'aide de `CI_REGISTRY_PASSWORD`.

### Kubernetes 1.16+ {#kubernetes-116}

> [!warning]
> La valeur par défaut du paramètre `deploymentApiVersion` a été remplacée par `apps/v1` à la place de `extensions/v1beta`.

Dans Kubernetes 1.16 et versions ultérieures, plusieurs [API ont été supprimées](https://kubernetes.io/blog/2019/07/18/api-deprecations-in-1-16/), notamment la prise en charge de `Deployment` dans la version `extensions/v1beta1`.

Pour utiliser Auto Deploy sur un cluster Kubernetes 1.16+ :

1. Si vous déployez votre application pour la première fois, aucune configuration n'est normalement requise.
1. Si vous disposez d'une base de données PostgreSQL dans le cluster installée avec `AUTO_DEVOPS_POSTGRES_CHANNEL` défini sur `1`, suivez le [guide de mise à niveau de PostgreSQL](upgrading_postgresql.md).

> [!warning]
> Suivez le [guide de mise à niveau de PostgreSQL](upgrading_postgresql.md) pour sauvegarder et restaurer votre base de données avant de passer à la version `2`.

### Migrations {#migrations}

Vous pouvez configurer l'initialisation et les migrations de la base de données pour PostgreSQL afin qu'elles s'exécutent dans le pod d'application en définissant les variables CI/CD du projet `DB_INITIALIZE` et `DB_MIGRATE`.

Si elle est présente, `DB_INITIALIZE` est exécutée en tant que commande shell dans un pod d'application sous forme de hook Helm post-installation. Comme certaines applications ne peuvent pas fonctionner sans une étape d'initialisation de base de données réussie, GitLab déploie la première release sans le déploiement de l'application, avec uniquement l'étape d'initialisation de la base de données. Une fois l'initialisation de la base de données terminée, GitLab déploie une deuxième release avec le déploiement de l'application de façon standard.

Un hook post-installation signifie que si un déploiement réussit, `DB_INITIALIZE` n'est plus traité par la suite.

Si elle est présente, `DB_MIGRATE` est exécutée en tant que commande shell dans un pod d'application sous forme de hook Helm de pré-mise à niveau.

Par exemple, dans une application Rails dans une image buildée avec les [Cloud Native Buildpacks](#auto-build-using-cloud-native-buildpacks) :

- `DB_INITIALIZE` peut être défini sur `RAILS_ENV=production /cnb/lifecycle/launcher bin/rails db:setup`
- `DB_MIGRATE` peut être défini sur `RAILS_ENV=production /cnb/lifecycle/launcher bin/rails db:migrate`

Sauf si votre dépôt contient un `Dockerfile`, votre image est buildée avec Cloud Native Buildpacks, et vous devez préfixer les commandes exécutées dans ces images avec `/cnb/lifecycle/launcher` pour répliquer l'environnement dans lequel votre application s'exécute.

### Mise à niveau du chart auto-deploy-app {#upgrade-auto-deploy-app-chart}

Vous pouvez mettre à niveau le chart auto-deploy-app en suivant le [guide de mise à niveau](upgrading_auto_deploy_dependencies.md).

### Workers {#workers}

Certaines applications web doivent exécuter des déploiements supplémentaires pour les « processus workers ». Par exemple, les applications Rails utilisent couramment des processus workers distincts pour exécuter des tâches en arrière-plan, comme l'envoi d'e-mails.

Le [chart Helm par défaut](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app) utilisé dans Auto Deploy [prend en charge l'exécution de processus workers](https://gitlab.com/gitlab-org/charts/auto-deploy-app/-/merge_requests/9).

Pour exécuter un worker, vous devez vous assurer que celui-ci peut répondre aux vérifications de santé standard, qui attendent une réponse HTTP réussie sur le port `5000`. Pour [Sidekiq](https://github.com/sidekiq/sidekiq), vous pouvez utiliser le [gem `sidekiq_alive`](https://rubygems.org/gems/sidekiq_alive).

Pour utiliser Sidekiq, vous devez également vous assurer que vos déploiements ont accès à une instance Redis. Auto DevOps ne déploie pas cette instance pour vous, vous devez donc :

- Maintenir votre propre instance Redis.
- Définir une variable CI/CD `K8S_SECRET_REDIS_URL`, qui est l'URL de cette instance, pour vous assurer qu'elle est transmise à vos déploiements.

Après avoir configuré votre worker pour qu'il réponde aux vérifications de santé, exécutez un worker Sidekiq pour votre application Rails. Vous pouvez activer les workers en définissant les paramètres suivants dans le [fichier `.gitlab/auto-deploy-values.yaml`](customize.md#customize-helm-chart-values) :

```yaml
workers:
  sidekiq:
    replicaCount: 1
    command:
      - /cnb/lifecycle/launcher
      - sidekiq
    preStopCommand:
      - /cnb/lifecycle/launcher
      - sidekiqctl
      - quiet
    terminationGracePeriodSeconds: 60
```

### Exécution de commandes dans le conteneur {#running-commands-in-the-container}

Sauf si votre dépôt contient [un Dockerfile personnalisé](#auto-build-using-a-dockerfile), les applications buildées avec [Auto Build](#auto-build) peuvent nécessiter que les commandes soient encapsulées comme suit :

```shell
/cnb/lifecycle/launcher $COMMAND
```

Voici quelques raisons pour lesquelles vous pouvez avoir besoin d'encapsuler des commandes :

- Association via `kubectl exec`.
- Utilisation du [terminal Web](../../ci/environments/_index.md#web-terminals-deprecated) GitLab.

Par exemple, pour démarrer une console Rails depuis le répertoire racine de l'application, exécutez :

```shell
/cnb/lifecycle/launcher procfile exec bin/rails c
```

## Auto Code Intelligence {#auto-code-intelligence}

[GitLab code intelligence](../../user/project/code_intelligence.md) ajoute des fonctionnalités de navigation dans le code communes aux environnements de développement intégrés (IDE), notamment les signatures de types, la documentation des symboles et la fonctionnalité « aller à la définition ». Cette fonctionnalité est alimentée par [LSIF](https://lsif.dev/) et disponible uniquement pour les projets Auto DevOps utilisant le langage Go. GitLab prévoit d'ajouter la prise en charge d'autres langages à mesure que de nouveaux indexeurs LSIF deviennent disponibles. Vous pouvez suivre l'[epic Code Intelligence](https://gitlab.com/groups/gitlab-org/-/work_items/4212) pour les mises à jour.

Cette étape est activée par défaut. Vous pouvez la désactiver en ajoutant la variable CI/CD `CODE_INTELLIGENCE_DISABLED`. Pour en savoir plus sur la [désactivation des jobs Auto DevOps](cicd_variables.md#job-skipping-variables).
