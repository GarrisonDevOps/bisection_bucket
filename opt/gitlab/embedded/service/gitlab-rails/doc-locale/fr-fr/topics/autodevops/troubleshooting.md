---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Dépannage d'Auto DevOps"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les informations contenues dans cette page de documentation décrivent les erreurs courantes lors de l'utilisation d'Auto DevOps, ainsi que les solutions de contournement disponibles.

## Tracer les commandes Helm {#trace-helm-commands}

Définissez la variable CI/CD `TRACE` sur n'importe quelle valeur pour que les commandes Helm produisent une sortie détaillée. Vous pouvez utiliser cette sortie pour diagnostiquer les problèmes de déploiement d'Auto DevOps.

Vous pouvez résoudre certains problèmes de déploiement d'Auto DevOps en modifiant les variables de configuration avancées d'Auto DevOps. En savoir plus sur la [personnalisation des variables CI/CD d'Auto DevOps](cicd_variables.md).

## Impossible de sélectionner un buildpack {#unable-to-select-a-buildpack}

Auto Test peut ne pas détecter votre langage ou votre framework avec l'erreur suivante :

```plaintext
Step 5/11 : RUN /bin/herokuish buildpack build
 ---> Running in eb468cd46085
    -----> Unable to select a buildpack
The command '/bin/sh -c /bin/herokuish buildpack build' returned a non-zero code: 1
```

Les raisons possibles sont les suivantes :

- Il se peut que votre application manque les fichiers clés que le buildpack recherche. Les applications Ruby nécessitent un `Gemfile` pour être correctement détectées, même s'il est possible d'écrire une application Ruby sans `Gemfile`.
- Il se peut qu'aucun buildpack n'existe pour votre application. Essayez de spécifier un [buildpack personnalisé](customize.md#custom-buildpacks).

## Erreur de fin de vie du builder {#builder-sunset-error}

En raison de cette [mise à jour Heroku](https://github.com/heroku/cnb-builder-images/pull/478), les images héritées shimmed `heroku/buildpacks:20` et `heroku/builder-classic:22` génèrent désormais des erreurs au lieu d'avertissements.

Pour résoudre ce problème, vous devez migrer vers les images de builder `heroku/builder:*`. À titre de solution de contournement temporaire, vous pouvez également définir une variable d'environnement pour ignorer les erreurs.

### Migration vers `heroku/builder:*` {#migrating-to-herokubuilder}

Avant de migrer, vous devez lire les notes de release de chaque [release de spécification](https://github.com/buildpacks/spec/releases) pour identifier les changements potentiellement incompatibles. Dans ce cas, les versions d'API buildpack concernées sont 0.6 et 0.7. Ces changements incompatibles sont particulièrement pertinents pour les personnes responsables de la maintenance des buildpacks.

Pour plus d'informations sur les changements, vous pouvez également comparer [la spécification elle-même](https://github.com/buildpacks/spec/compare/buildpack/v0.5...buildpack/v0.7#files_bucket).

### Ignorer les erreurs {#skipping-errors}

À titre de solution de contournement temporaire, vous pouvez ignorer les erreurs en définissant et en transmettant la variable d'environnement `ALLOW_EOL_SHIMMED_BUILDER` :

```yaml
  variables:
    ALLOW_EOL_SHIMMED_BUILDER: "1"
    AUTO_DEVOPS_BUILD_IMAGE_FORWARDED_CI_VARIABLES: ALLOW_EOL_SHIMMED_BUILDER
```

## Le pipeline qui étend Auto DevOps avec only / except échoue {#pipeline-that-extends-auto-devops-with-only--except-fails}

Si votre pipeline échoue avec le message suivant :

```plaintext
Unable to run pipeline

  jobs:test config key may not be used with `rules`: only
```

Cette erreur apparaît lorsque la configuration des règles du job inclus a été remplacée par la syntaxe `only` ou `except`. Pour corriger ce problème, vous devez faire la transition de votre syntaxe `only/except` vers les règles.

## Échec de création d'un espace de nommage Kubernetes {#failure-to-create-a-kubernetes-namespace}

Auto Deploy échoue si GitLab ne peut pas créer un espace de nommage Kubernetes et un compte de service pour votre projet. Pour obtenir de l'aide pour déboguer ce problème, consultez [Dépannage des jobs de déploiement ayant échoué](../../user/project/clusters/deploy_to_cluster.md#troubleshooting).

## Auto DevOps est automatiquement désactivé pour un projet {#auto-devops-is-automatically-disabled-for-a-project}

Si Auto DevOps est automatiquement désactivé pour un projet, cela peut être dû aux raisons suivantes :

- Le paramètre Auto DevOps n'a pas été explicitement activé dans le [projet](_index.md#per-project) lui-même. Il est activé uniquement dans le [groupe](_index.md#per-group) parent ou son [instance](../../administration/settings/continuous_integration.md#configure-auto-devops-for-all-projects).
- Le projet n'a pas d'historique de pipelines Auto DevOps réussis.
- Un pipeline Auto DevOps a échoué.

Pour résoudre ce problème :

- Activez le paramètre Auto DevOps dans le projet.
- Corrigez les erreurs qui interrompent le pipeline afin que celui-ci puisse être relancé.

## Erreur : `unable to recognize "": no matches for kind "Deployment" in version "extensions/v1beta1"` {#error-unable-to-recognize--no-matches-for-kind-deployment-in-version-extensionsv1beta1}

Après la mise à niveau de votre cluster Kubernetes vers [v1.16+](stages.md#kubernetes-116), vous pouvez rencontrer ce message lors du déploiement avec Auto DevOps :

```plaintext
UPGRADE FAILED
Error: failed decoding reader into objects: unable to recognize "": no matches for kind "Deployment" in version "extensions/v1beta1"
```

Cela peut se produire si vos déploiements actuels sur l'espace de nommage d'environnement ont été déployés avec une API dépréciée/supprimée qui n'existe pas dans Kubernetes v1.16+.

Pour récupérer ces ressources obsolètes, vous devez convertir les déploiements actuels en mappant les API héritées vers les nouvelles API.

## `Error: not a valid chart repository or cannot be reached` {#error-not-a-valid-chart-repository-or-cannot-be-reached}

Comme [annoncé dans le billet de blog officiel de la CNCF](https://www.cncf.io/blog/2020/10/07/important-reminder-for-all-helm-users-stable-incubator-repos-are-deprecated-and-all-images-are-changing-location/), le dépôt de charts Helm stable a été déprécié et supprimé le 13 novembre 2020. Vous pouvez rencontrer cette erreur après cette date :

```plaintext
Error: error initializing: Looks like "https://kubernetes-charts.storage.googleapis.com"
is not a valid chart repository or cannot be reached
```

Certaines fonctionnalités de GitLab dépendaient du chart stable. Pour atténuer l'impact, les dépendances utilisent de nouveaux dépôts officiels ou le [dépôt Helm Stable Archive maintenu par GitLab](https://gitlab.com/gitlab-org/cluster-integration/helm-stable-archive). Auto Deploy contient [un exemple de correction](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/merge_requests/127).

Dans Auto Deploy, `v1.0.6+` de `auto-deploy-image` n'ajoute plus le dépôt stable déprécié à la commande `helm`. Si vous utilisez un chart personnalisé qui repose sur le dépôt stable déprécié, spécifiez une version plus ancienne de `auto-deploy-image` comme dans cet exemple :

```yaml
include:
  - template: Auto-DevOps.gitlab-ci.yml

.auto-deploy:
  image: "registry.gitlab.com/gitlab-org/cluster-integration/auto-deploy-image:v1.0.5"
```

Gardez à l'esprit que cette approche cessera de fonctionner lorsque le dépôt stable sera supprimé ; vous devrez donc à terme corriger votre chart personnalisé.

Pour corriger votre chart personnalisé :

1. Dans le répertoire de votre chart, mettez à jour la valeur `repository` dans votre fichier `requirements.yaml` depuis :

   ```yaml
   repository: "https://kubernetes-charts.storage.googleapis.com/"
   ```

   vers :

   ```yaml
   repository: "https://charts.helm.sh/stable"
   ```

1. Dans le répertoire de votre chart, exécutez `helm dep update .` en utilisant la même version majeure de Helm qu'Auto DevOps.
1. Commitez les modifications du fichier `requirements.yaml`.
1. Si vous aviez auparavant un fichier `requirements.lock`, commitez les modifications apportées au fichier. Si vous n'aviez pas auparavant de fichier `requirements.lock` dans votre chart, vous n'avez pas besoin de commiter le nouveau. Ce fichier est facultatif, mais lorsqu'il est présent, il est utilisé pour vérifier l'intégrité des dépendances téléchargées.

Vous trouverez plus d'informations dans le [ticket #263778, « Migrate PostgreSQL from stable Helm repository »](https://gitlab.com/gitlab-org/gitlab/-/issues/263778).

## `Error: release .... failed: timed out waiting for the condition` {#error-release--failed-timed-out-waiting-for-the-condition}

Lorsque vous débutez avec Auto DevOps, vous pouvez rencontrer cette erreur lors du premier déploiement de votre application :

```plaintext
INSTALL FAILED
PURGING CHART
Error: release staging failed: timed out waiting for the condition
```

Cela est très probablement causé par un échec de la sonde de liveness (ou de readiness) tentée pendant le processus de déploiement. Par défaut, ces sondes sont exécutées sur la page racine de l'application déployée sur le port 5000. Si votre application n'est pas configurée pour servir quoi que ce soit sur la page racine, ou est configurée pour s'exécuter sur un port *autre* que 5000, cette vérification échoue.

En cas d'échec, vous devriez voir ces échecs dans les événements de l'espace de nommage Kubernetes concerné. Ces événements ressemblent à l'exemple suivant :

```plaintext
LAST SEEN   TYPE      REASON                   OBJECT                                            MESSAGE
3m20s       Warning   Unhealthy                pod/staging-85db88dcb6-rxd6g                      Readiness probe failed: Get http://10.192.0.6:5000/: dial tcp 10.192.0.6:5000: connect: connection refused
3m32s       Warning   Unhealthy                pod/staging-85db88dcb6-rxd6g                      Liveness probe failed: Get http://10.192.0.6:5000/: dial tcp 10.192.0.6:5000: connect: connection refused
```

Pour modifier le port utilisé pour les vérifications de liveness, transmettez des [valeurs personnalisées au chart Helm](customize.md#customize-helm-chart-values) utilisé par Auto DevOps :

1. Créez un répertoire et un fichier à la racine de votre dépôt nommé `.gitlab/auto-deploy-values.yaml`.
1. Remplissez le fichier avec le contenu suivant, en remplaçant les valeurs de port par le numéro de port réel sur lequel votre application est configurée pour s'exécuter :

   ```yaml
   service:
     internalPort: <port_value>
     externalPort: <port_value>
   ```

1. Commitez vos modifications.

Après avoir commité vos modifications, les sondes suivantes devraient utiliser les ports nouvellement définis. La page sondée peut également être modifiée en remplaçant les valeurs `livenessProbe.path` et `readinessProbe.path` (indiquées dans le fichier [`values.yaml` par défaut](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/blob/master/assets/auto-deploy-app/values.yaml)) de la même manière.
