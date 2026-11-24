---
stage: Verify
group: CI Platform
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Flotte de runners.
title: Concevoir et configurer une flotte de runners GitLab sur Google Kubernetes Engine
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

Utilisez ces recommandations pour analyser vos exigences de build CI/CD afin de concevoir, configurer et valider une flotte de runners GitLab hébergée sur Google Kubernetes Engine (GKE).

Le diagramme suivant illustre le parcours de mise en œuvre de votre flotte de runners. Le guide suit les étapes suivantes :

![Diagramme des étapes de la flotte de runners](img/runner_fleet_steps_diagram_v17_5.png)

Vous pouvez utiliser ce framework pour planifier un déploiement de runner pour un groupe unique ou une instance GitLab qui dessert l'ensemble de votre organisation.

Ce framework comprend les étapes suivantes :

1. [Évaluer les charges de travail CI/CD attendues](#assess-the-expected-cicd-workloads)
1. [Planifier la configuration de la flotte de runners](#plan-the-runner-fleet-configuration)
1. [Déployer le runner sur GKE](#deploy-the-runner-on-gke)
1. [Optimiser](#optimize)

## Évaluer les charges de travail CI/CD attendues {#assess-the-expected-cicd-workloads}

Dans cette phase, vous collectez les exigences de build CI/CD des équipes de développement que vous accompagnez. Le cas échéant, créez un inventaire des langages de programmation, de script et de balisage utilisés.

Il est possible que vous accompagniez plusieurs équipes de développement, différents langages de programmation et diverses exigences de build. Commencez par une équipe, un projet et un ensemble d'exigences de build CI/CD pour la première série d'analyses approfondies.

Pour évaluer les charges de travail CI/CD attendues :

- Estimez la demande en jobs CI/CD que vous prévoyez de supporter (horaire, quotidienne, hebdomadaire).
- Estimez les ressources CPU et RAM requises pour un job CI/CD représentatif d'un projet spécifique. Ces estimations aident à identifier les différents profils que vous pourriez supporter. Les caractéristiques de ces profils sont importantes pour identifier le cluster GKE approprié nécessaire pour répondre à vos exigences. Reportez-vous à cet exemple pour savoir comment déterminer les exigences en CPU et RAM.
- Déterminez si vous avez des exigences de sécurité ou de politique qui vous obligent à segmenter l'accès à certains runners par groupes ou projets.

### Estimer les exigences en CPU et RAM pour un job CI/CD {#estimate-the-cpu-and-ram-requirements-for-a-cicd-job}

Les exigences en ressources CPU et RAM varient en fonction de facteurs tels que le type de langage de programmation ou le type de job CI/CD (build, tests d'intégration, tests unitaires, analyses de sécurité). La section suivante décrit une méthode pour collecter les exigences en CPU et en ressources des jobs CI/CD. Vous pouvez adopter cette approche et la développer selon vos propres besoins.

Par exemple, pour exécuter un job CI/CD similaire à celui défini dans la duplication du projet FastAPI : [`ra-group/fastapi`](https://gitlab.com/ra-group2/fastapi). Le job dans cet exemple utilise une image Python, télécharge les dépendances du projet et exécute les tests unitaires existants. Le `.gitlab-ci.yml` pour le job est le suivant :

```yaml
tests:
  image: python:3.11.10-bookworm
  parallel: 25
  script:
  - pip install -r requirements.txt
  - pytest
```

Pour identifier les ressources de calcul et RAM nécessaires, utilisez Docker pour :

- Créer une image spécifique qui utilise la duplication FastAPI et le script de job CI/CD comme point d'entrée.
- Exécuter un conteneur avec l'image construite et surveiller l'utilisation des ressources.

Suivez les étapes ci-dessous pour identifier les ressources de calcul et RAM nécessaires :

1. Créez un fichier de script dans votre projet qui contient toutes les commandes CI. Le fichier de script est nommé `entrypoint.sh`.

   ```shell
   #!/bin/bash
   cd /fastapi || exit
   pip install -r requirements.txt
   pytest
   ```

1. Créez un Dockerfile pour créer une image dans laquelle le fichier `entrypoint.sh` exécute le script CI.

   ```dockerfile
   FROM python:3.11.10-bookworm
   RUN mkdir /fastapi
   COPY . /fastapi
   RUN chmod +x /fastapi/entrypoint.sh
   CMD [ "bash", "/fastapi/entrypoint.sh" ]
   ```

1. Construisez l'image. Pour simplifier le processus, effectuez toutes les opérations telles que la construction, le stockage et l'exécution de l'image localement. Cette approche élimine la nécessité d'un registre en ligne pour récupérer et pousser l'image.

   ```shell
   ❯ docker build . -t my-project_dir/fastapi:testing
   ...
   Successfully tagged my-project_dir/fastapi:testing
   ```

1. Exécutez un conteneur avec l'image construite et surveillez simultanément l'utilisation des ressources pendant l'exécution du conteneur. Créez un script nommé `metrics.sh` avec la commande suivante :

   ```shell
   #! /bin/bash

   container_id=$(docker run -d --rm my-project_dir/fastapi:testing)

   while true; do
       echo "Collecting metrics..."
       metrics=$(docker stats --no-trunc --no-stream --format "table {{.ID}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep "$container_id")
       if [ -z "$metrics" ]; then
           exit 0
       fi
       echo "Saving metrics..."
       echo "$metrics" >> metrics.log
       sleep 1
   done
   ```

   Ce script exécute un conteneur détaché avec l'image construite. L'identifiant du conteneur est ensuite utilisé pour collecter son utilisation de `CPU` et de `Memory` jusqu'à ce que le conteneur se termine avec succès. Les métriques collectées sont sauvegardées dans un fichier appelé `metrics.log`.

   > [!note]
   > Dans l'exemple, le job CI/CD est de courte durée, donc la durée de veille entre chaque interrogation du conteneur est définie sur une seconde. Ajustez cette valeur selon vos besoins.
1. Analysez le fichier `metrics.log` pour identifier le pic d'utilisation du conteneur de test.

   Dans l'exemple, l'utilisation maximale du CPU est de `107.50%` et l'utilisation maximale de la mémoire est de `303.1Mi`.

   ```log
   223e93dd05c6   94.98%    83.79MiB / 15.58GiB
   223e93dd05c6   28.27%    85.4MiB / 15.58GiB
   223e93dd05c6   53.92%    121.8MiB / 15.58GiB
   223e93dd05c6   70.73%    171.9MiB / 15.58GiB
   223e93dd05c6   20.78%    177.2MiB / 15.58GiB
   223e93dd05c6   26.19%    180.3MiB / 15.58GiB
   223e93dd05c6   77.04%    224.1MiB / 15.58GiB
   223e93dd05c6   97.16%    226.5MiB / 15.58GiB
   223e93dd05c6   98.52%    259MiB / 15.58GiB
   223e93dd05c6   98.78%    303.1MiB / 15.58GiB
   223e93dd05c6   100.03%   159.8MiB / 15.58GiB
   223e93dd05c6   103.97%   204MiB / 15.58GiB
   223e93dd05c6   107.50%   207.8MiB / 15.58GiB
   223e93dd05c6   105.96%   215.7MiB / 15.58GiB
   223e93dd05c6   101.88%   226.2MiB / 15.58GiB
   223e93dd05c6   100.44%   226.7MiB / 15.58GiB
   223e93dd05c6   100.20%   226.9MiB / 15.58GiB
   223e93dd05c6   100.60%   227.6MiB / 15.58GiB
   223e93dd05c6   100.46%   228MiB / 15.58GiB
   ```

### Analyse des métriques collectées {#analyzing-the-metrics-collected}

Sur la base des métriques collectées, pour ce profil de job, vous pouvez limiter le job de l'exécuteur Kubernetes à `1 CPU` et `~304 Mi of Memory`. Même si cette conclusion est exacte, elle peut ne pas être pratique pour tous les cas d'usage.

Si vous utilisez un cluster avec un pool de nœuds de trois nœuds `e2-standard-4` pour exécuter des jobs, la limite `1 CPU` ne permet d'exécuter que 12 jobs simultanément (un nœud `e2-standard-4` dispose de 4 vCPU et 16 Go de mémoire). Les jobs supplémentaires attendent que les jobs en cours se terminent et libèrent les ressources avant de démarrer.

La mémoire demandée est critique car Kubernetes termine tout pod qui utilise plus de mémoire que la limite définie ou disponible sur le cluster. En revanche, la limite CPU est plus flexible mais a un impact sur la durée du job. Une limite CPU plus basse augmente le temps nécessaire à l'exécution d'un job. Dans l'exemple précédent, définir la limite CPU à `250m` (ou `0.25`) au lieu de `1` a multiplié par quatre la durée du job (d'environ deux minutes à huit à dix minutes).

La méthode de collecte de métriques utilisant un mécanisme d'interrogation, vous devez arrondir à la hausse l'utilisation maximale identifiée. Par exemple, au lieu de `303 Mi` pour l'utilisation de la mémoire, arrondissez à `400 Mi`.

Points importants à prendre en compte pour l'exemple précédent :

- Les métriques ont été collectées sur la machine locale, qui n'a pas la même configuration CPU qu'un cluster Google Kubernetes Engine. Cependant, ces métriques ont été validées en les surveillant sur un cluster Kubernetes avec un nœud `e2-standard-4`.
- Pour obtenir une représentation précise de ces métriques, exécutez les tests décrits dans la [phase d'évaluation](#assess-the-expected-cicd-workloads) sur une VM Google Compute Engine.

## Planifier la configuration de la flotte de runners {#plan-the-runner-fleet-configuration}

Dans la phase de planification, définissez la configuration appropriée de la flotte de runners pour votre organisation. Tenez compte de la portée du runner (instance, groupe, projet) et de la configuration du cluster Kubernetes en fonction de :

- Votre évaluation de la demande en ressources des jobs CI/CD
- Votre inventaire des types de jobs CI/CD

### Portée du runner {#runner-scope}

Pour planifier la portée du runner, tenez compte des questions suivantes :

- Souhaitez-vous que les propriétaires de projets et de groupes créent et gèrent leurs propres runners ?

  - Par défaut, les propriétaires de projets et de groupes peuvent créer une configuration de runner et enregistrer des runners dans un projet ou un groupe dans GitLab.
  - Cette conception permet aux équipes de développement de créer rapidement un environnement de build. Cette approche réduit les frictions lors de la prise en main de GitLab CI/CD. Cependant, dans les grandes organisations, cette approche peut conduire à de nombreux runners sous-utilisés ou inutilisés dans l'environnement.
- Votre organisation a-t-elle des politiques de sécurité ou autres qui exigent de segmenter l'accès à certains types de runners pour des groupes ou des projets spécifiques ?

La méthode la plus simple pour déployer un runner dans un environnement GitLab Self-Managed est de le créer pour une instance. Les runners dont la portée est définie pour une instance sont disponibles pour tous les groupes et projets par défaut.

Si vous pouvez répondre à tous les besoins de votre organisation avec des runners d'instance, ce modèle de déploiement est le plus efficace. Il garantit que vous pouvez exploiter une flotte de build CI/CD à grande échelle de manière efficace et rentable.

S'il existe des exigences pour segmenter l'accès à des runners spécifiques pour certains groupes ou projets, intégrez-les dans votre processus de planification.

#### Exemple de configuration de flotte de runners - Runners d'instance {#example-runner-fleet-configuration---instance-runners}

La configuration présentée dans le tableau illustre la flexibilité disponible lors de la configuration d'une flotte de runners pour votre organisation. Cet exemple utilise plusieurs runners avec différentes tailles d'instance et différents labels de jobs. Ces runners vous permettent de supporter différents types de jobs CI/CD, chacun avec des exigences spécifiques en ressources CPU et RAM. Cependant, ce n'est peut-être pas le modèle le plus efficace lors de l'utilisation de Kubernetes.

| Type de runner | Label de runner       | Portée                                                               | Nombre de types de runners à proposer | Spécification du worker du runner | Environnement hôte du runner | Configuration de l'environnement |
|:------------|:-----------------|:--------------------------------------------------------------------|:------------------------------|:----------------------------|:------------------------|:--------------------------|
| Instance    | ci-runner-small  | Disponible pour exécuter des jobs CI/CD pour tous les groupes et projets par défaut. | 5                             | 2 vCPU, 8 Go de RAM            | Kubernetes              | → 3 nœuds <br> → Nœud de calcul du worker du runner = `e2-standard-2` |
| Instance    | ci-runner-medium | Disponible pour exécuter des jobs CI/CD pour tous les groupes et projets par défaut. | 2                             | 4 vCPU, 16 Go de RAM           | Kubernetes              | → 3 nœuds <br> → Nœud de calcul du worker du runner = `e2-standard-4` |
| Instance    | ci-runner-large  | Disponible pour exécuter des jobs CI/CD pour tous les groupes et projets par défaut. | 1                             | 8 vCPU, 32 Go de RAM           | Kubernetes              | → 3 nœuds <br> → Nœud de calcul du worker du runner = `e2-standard-8` |

Dans l'exemple de configuration de flotte de runners, il y a au total trois configurations de runners et huit runners exécutant activement des jobs CI/CD.

Avec l'exécuteur Kubernetes, vous pouvez utiliser le planificateur Kubernetes et écraser les ressources des conteneurs. En théorie, vous pouvez déployer un seul GitLab Runner sur un cluster Kubernetes disposant de ressources adéquates. Vous pouvez ensuite écraser les ressources des conteneurs pour sélectionner le type de calcul approprié pour chaque job CI/CD. La mise en œuvre de ce modèle réduit le nombre de configurations de runners séparées que vous devez déployer et exploiter.

### Bonnes pratiques {#best-practices}

- Dédier toujours un pool de nœuds aux gestionnaires de runners.
  - Le traitement des journaux et la gestion du cache ou des artefacts peuvent être gourmands en CPU.
- Toujours définir une limite par défaut (CPU/mémoire pour les conteneurs Build/Helper/Service) dans le fichier `config.toml`.
- Toujours autoriser l'écrasement maximal des ressources dans le fichier `config.toml`.
- Dans la définition du job (`.gitlab-ci.yml`), spécifiez la limite appropriée requise par les jobs.
  - Si aucune valeur n'est spécifiée, les valeurs par défaut définies dans le fichier `config.toml` sont utilisées.
  - Si un conteneur dépasse sa limite de mémoire, le système le termine automatiquement via le processus Out of Memory (OOM) kill.
- Utilisez le feature flag `FF_PRINT_POD_EVENTS` et la configuration `print_pod_warning_events`. Pour plus de détails, consultez la [documentation sur les feature flags](https://docs.gitlab.com/runner/configuration/feature-flags/) et la [documentation sur la configuration des permissions de l'API du runner](https://docs.gitlab.com/runner/executors/kubernetes/#configure-runner-api-permissions).

## Déployer le runner sur GKE {#deploy-the-runner-on-gke}

Lorsque vous êtes prêt à installer GitLab Runner sur un cluster Google Kubernetes, vous disposez de nombreuses options. Si vous avez créé votre cluster sur GKE, vous pouvez utiliser le Helm Chart ou l'Operator GitLab Runner pour installer le runner sur le cluster.

Si vous n'avez pas encore configuré le cluster sur GKE, GitLab fournit le GitLab Runner Infrastructure Toolkit (GRIT) qui effectue simultanément les actions suivantes :

- Crée un cluster GKE multi-pool de nœuds : édition standard et mode standard.
- Installe GitLab Runner sur le cluster à l'aide de l'opérateur Kubernetes GitLab Runner.

L'exemple suivant utilise GRIT pour déployer le cluster Google Kubernetes et le gestionnaire GitLab Runner.

Pour avoir le cluster et GitLab Runner bien configurés, tenez compte des informations suivantes :

- Combien de types de jobs dois-je couvrir ?
  - Ces informations proviennent de la phase d'évaluation. La phase d'évaluation agrège les métriques et identifie le nombre de groupes résultants, en tenant compte des contraintes organisationnelles. Un « type de job » est un ensemble de jobs catégorisés identifiés lors de la phase d'évaluation. Cette catégorisation est basée sur les ressources maximales nécessaires au job.
- Combien de gestionnaires GitLab Runner dois-je exécuter ?
  - Ces informations proviennent de la phase de planification. Si l'organisation gère les projets séparément, appliquez ce framework à chaque projet individuellement. Cette approche est pertinente uniquement lorsque plusieurs profils de jobs sont identifiés (pour l'ensemble de l'organisation ou pour un projet spécifique), et qu'ils sont tous gérés par un runner individuel ou une flotte de runners GitLab. Une configuration de base utilise généralement un gestionnaire GitLab Runner par cluster GKE.
- Quel est le nombre maximal estimé de jobs CI/CD simultanés ?
  - Ces informations représentent une estimation du nombre maximal de jobs CI/CD simultanés exécutés à tout moment. Ces informations sont nécessaires lors de la configuration du gestionnaire GitLab Runner en indiquant la durée d'attente pendant l'étape `Prepare` : planification des pods de jobs sur un nœud avec des ressources disponibles limitées.

### Applications réelles pour la duplication FastAPI {#real-life-applications-for-the-fastapi-fork}

Pour la duplication FastAPI, tenez compte des informations suivantes :

- Combien de profils de jobs dois-je couvrir ?
  - Vous disposez d'un profil de job avec les caractéristiques suivantes : `1 CPU` et `303 Mi` de mémoire. Comme expliqué dans la section [Analyse des métriques collectées](#analyzing-the-metrics-collected), ces valeurs brutes changent comme suit :
    - `400 Mi` pour la limite de mémoire au lieu de `303 Mi` afin d'éviter tout échec de job dû aux limites de mémoire.
    - `0.20` pour le CPU au lieu de `1 CPU`. Pour cet exemple, vous privilégiez la précision et la qualité à la vitesse lors de l'exécution des tâches.
- Combien de gestionnaires GitLab Runner dois-je exécuter ?
  - Un seul gestionnaire GitLab Runner est suffisant pour vos tests.
- Quelle est la charge de travail attendue ?
  - Vous souhaitez exécuter jusqu'à 20 jobs simultanément à tout moment.

Sur la base de ces données, tout cluster GKE avec les caractéristiques minimales suivantes devrait être suffisant :

- CPU minimum : `(0.20 + helper CPU usage) * number of jobs simultaneously`. Dans cet exemple, vous obtenez `7 vCPU` avec la limite du conteneur helper définie sur `0.15 CPU`.
- Mémoire minimum : `(400Mi + helper memory usage) * number of jobs simultaneously`. Dans cet exemple, vous obtenez au moins `10 Gi` avec la limite du helper définie sur `100 Mi`.

D'autres caractéristiques, telles que le stockage minimum requis, doivent également être prises en compte. Cependant, l'exemple ne prend pas cela en compte.

Les configurations possibles pour notre cluster GKE peuvent être (les deux configurations vous permettent d'exécuter plus de 20 jobs simultanément) :

- Cluster GKE avec un pool de nœuds de `3 e2-standard-4` nœuds pour un total de `12 vCPU` et `48 GiB` de mémoire
- Cluster GKE avec un pool de nœuds d'un seul nœud `e2-standard-8` pour un total de `8 vCPU` et `32 GiB` de mémoire

La première configuration est utilisée dans cet exemple. Pour éviter que le traitement des journaux du gestionnaire GitLab Runner n'impacte le traitement global des journaux, utilisez un pool de nœuds dédié sur lequel GitLab Runner est installé.

#### Configuration GKE GRIT {#gke-grit-configuration}

La configuration GKE résultante pour GRIT ressemble à ceci :

```terraform
google_project     = "GCLOUD_PROJECT"
google_region      = "GCLOUD_REGION"
google_zone        = "GCLOUD_ZONE"
name               = "my-grit-gke-cluster"
node_pools = {
  "runner-manager" = {
    node_count = 1,
    node_config = {
      machine_type = "e2-standard-2",
      image_type   = "cos_containerd",   #Linux OS container only. Change to windows_ltsc_containerd for Windows OS container
      disk_size_gb = 50,
      disk_type    = "pd-balanced",
      labels = {
        "app" = "gitlab-runner",
      }
    },
  },
  "worker-pool" = {
    node_count = 3,
    node_config = {
      machine_type = "e2-standard-4",    #4 vCPU, 16 GB each
      image_type   = "cos_containerd",   #Linux OS container only. Change to windows_ltsc_containerd for Windows OS container
      disk_size_gb = 150,
      disk_type    = "pd-balanced",
      labels = {
        "app" = "gitlab-runner-job"
      }
    },
  },
}
```

Dans la configuration précédente :

- Le bloc `runner-manager` fait référence au pool de nœuds où GitLab Runner est installé. Dans notre exemple, un `e2-standard-2` est plus que suffisant.
- La section labels dans le bloc `runner-manager` est utile lors de l'installation de GitLab Runner sur GitLab. Un sélecteur de nœud est configuré via la configuration de l'opérateur pour s'assurer que GitLab Runner est installé sur un nœud de ce pool de nœuds.
- Le bloc `worker-pool` fait référence au pool de nœuds où le pod de job CI/CD est créé. La configuration fournie crée un pool de nœuds de `3 e2-standard-4` nœuds étiquetés `"app" = "gitlab-runner-job"` pour héberger le pod de job.
- Le paramètre `image_type` peut être utilisé pour définir l'image utilisée par les nœuds. Il peut être défini sur `windows_ltsc_containerd` si votre charge de travail repose principalement sur une image Windows.

Voici une illustration de cette configuration :

![Illustration de la configuration du cluster](img/nodepool_illustration_example_v17_5.png)

#### Configuration GitLab Runner GRIT {#gitlab-runner-grit-configuration}

La configuration GitLab Runner résultante pour GRIT ressemble à ceci :

```terraform
gitlab_pat         = "glpat-REDACTED"
gitlab_project_id  = GITLAB_PROJECT_ID
runner_description = "my-grit-gitlab-runner"
runner_image       = "registry.gitlab.com/gitlab-org/ci-cd/gitlab-runner-ubi-images/gitlab-runner-ocp:amd64-v17.3.1"
helper_image       = "registry.gitlab.com/gitlab-org/ci-cd/gitlab-runner-ubi-images/gitlab-runner-helper-ocp:x86_64-v17.3.1"
concurrent     = 20
check_interval = 1
runner_tags    = ["my-custom-tag"]
config_template    = <<EOT
[[runners]]
  name = "my-grit-gitlab-runner"
  shell = "bash"
  environment = [
    "FF_PRINT_POD_EVENTS=true",
  ]
  [runners.kubernetes]
    image = "alpine"
    cpu_limit = "0.25"
    memory_limit = "400Mi"
    helper_cpu = "150m"
    helper_memory = "150Mi"
    cpu_limit_overwrite_max_allowed = "0.25"
    memory_limit_overwrite_max_allowed = "400Mi"
    helper_cpu_limit_overwrite_max_allowed = "150m"
    helper_memory_limit_overwrite_max_allowed = "150Mi"
    print_pod_warning_events = true
  [runners.kubernetes.node_selector]
    "app" = "gitlab-runner-job"
EOT
pod_spec = [
  {
    name      = "selector",
    patchType = "merge",
    patch     = <<EOT
nodeSelector:
  app: "gitlab-runner"
EOT
  }
]
```

Dans la configuration précédente :

- Le paramètre `pod_spec` nous permet de définir un sélecteur de nœud pour le pod exécutant GitLab Runner. Dans la configuration, le sélecteur de nœud est défini sur `"app" = "gitlab-runner"` pour s'assurer que GitLab Runner est installé sur le pool de nœuds runner-manager.
- Le paramètre `config_template` fournit une limite par défaut pour tous les jobs exécutés par le gestionnaire GitLab Runner. Il permet également d'écraser ces limites tant que la valeur définie n'est pas supérieure aux valeurs par défaut.
- Le feature flag `FF_PRINT_POD_EVENTS` et la configuration `print_pod_warning_events` sont également définis pour faciliter le débogage en cas d'échec de job. Consultez la [documentation sur les feature flags](https://docs.gitlab.com/runner/configuration/feature-flags/) et la [documentation sur la configuration des permissions de l'API du runner](https://docs.gitlab.com/runner/executors/kubernetes/#configure-runner-api-permissions) pour plus de détails.

### Applications réelles pour un cas d'usage hypothétique {#real-life-applications-for-a-hypothetical-use-case}

Prenez les informations suivantes en considération :

- Combien de profils de jobs dois-je couvrir ?
  - Deux profils (les spécifications fournies tiennent compte des limites du helper) :
    - Jobs moyens : `300m CPU` et `200 MiB`
    - Jobs gourmands en CPU : `1 CPU` et `1 GiB`
- Combien de gestionnaires GitLab Runner dois-je exécuter ?
  - Un.
- Quelle est la charge de travail attendue ?
  - Jusqu'à 50 jobs moyens simultanément
  - Jusqu'à 25 jobs gourmands en CPU simultanément

#### Configuration GKE {#gke-configuration}

- Besoins pour les jobs moyens :
  - CPU : `300m * 50 = 5 CPU` (approximatif)
  - Mémoire : `200 MiB * 50 = 10 GiB`
- Besoins pour les jobs gourmands en CPU :
  - CPU : `1 * 25 = 25`
  - Mémoire : `1 GiB * 25 = 25 GiB`

Le cluster GKE doit disposer de :

- Un pool de nœuds pour le gestionnaire GitLab Runner (supposons que le traitement des journaux n'est pas exigeant) : nœud `1 e2-standard-2`
- Un pool de nœuds pour les jobs moyens : 3 nœuds `e2-standard-4`
- Un pool de nœuds pour les jobs gourmands en CPU : 1 nœud `e2-highcpu-32` (`32 vCPU` et `32 GiB` de mémoire)

```terraform
google_project     = "GCLOUD_PROJECT"
google_region      = "GCLOUD_REGION"
google_zone        = "GCLOUD_ZONE"
name               = "my-grit-gke-cluster"
node_pools = {
  "runner-manager" = {
    node_count = 1,
    node_config = {
      machine_type = "e2-standard-2",
      image_type   = "cos_containerd",   #Linux OS container only. Change to windows_ltsc_containerd for Windows OS container
      disk_size_gb = 50,
      disk_type    = "pd-balanced",
      labels = {
        "app" = "gitlab-runner",
      }
    },
  },
  "medium-pool" = {
    node_count = 3,
    node_config = {
      machine_type = "e2-standard-4",    #4 vCPU, 16 GB each
      image_type   = "cos_containerd",   #Linux OS container only. Change to windows_ltsc_containerd for Windows OS container
      disk_size_gb = 150,
      disk_type    = "pd-balanced",
      labels = {
        "app" = "gitlab-runner-job"
      }
    },
  },
  "cpu-intensive-pool" = {
    node_count = 1,
    node_config = {
      machine_type = "e2-highcpu-32", #32 vCPU, 32 GB each
      image_type   = "cos_containerd",
      disk_size_gb = 150,
      disk_type    = "pd-balanced",
      labels = {
        "app" = "gitlab-runner-job"
      }
    },
  },
}
```

#### Configuration de GitLab Runner {#gitlab-runner-configuration}

L'implémentation actuelle de GRIT ne permet pas l'installation de plus d'un runner à la fois. Le `config_template` fourni ne définit pas de configurations telles que `node_selection` et d'autres limites, comme dans l'exemple précédent. Une configuration simple permet la valeur d'écrasement maximale autorisée pour les jobs gourmands en CPU et définit les valeurs correctes dans le fichier `.gitlab-ci.yml`. La configuration GitLab Runner résultante ressemble à ceci :

```terraform
gitlab_pat         = "glpat-REDACTED"
gitlab_project_id  = GITLAB_PROJECT_ID
runner_description = "my-grit-gitlab-runner"
runner_image       = "registry.gitlab.com/gitlab-org/ci-cd/gitlab-runner-ubi-images/gitlab-runner-ocp:amd64-v17.3.1"
helper_image       = "registry.gitlab.com/gitlab-org/ci-cd/gitlab-runner-ubi-images/gitlab-runner-helper-ocp:x86_64-v17.3.1"
concurrent     = 100
check_interval = 1
runner_tags    = ["my-custom-tag"]
config_template    = <<EOT
[[runners]]
  name = "my-grit-gitlab-runner"
  shell = "bash"
  environment = [
    "FF_PRINT_POD_EVENTS=true",
  ]
  [runners.kubernetes]
    image = "alpine"
    cpu_limit_overwrite_max_allowed = "0.75"
    memory_limit_overwrite_max_allowed = "900Mi"
    helper_cpu_limit_overwrite_max_allowed = "250m"
    helper_memory_limit_overwrite_max_allowed = "100Mi"
    print_pod_warning_events = true
EOT
pod_spec = [
  {
    name      = "selector",
    patchType = "merge",
    patch     = <<EOT
nodeSelector:
  app: "gitlab-runner"
EOT
  }
]
```

Le fichier `.gitlab-ci.yml` ressemble à ceci :

- Pour les jobs moyens :

  ```yaml
  variables:
    KUBERNETES_CPU_LIMIT: "200m"
    KUBERNETES_MEMORY_LIMIT: "100Mi"
    KUBERNETES_HELPER_CPU_LIMIT: "100m"
    KUBERNETES_HELPER_MEMORY_LIMIT: "100Mi"

  tests:
    image: some-image:latest
    script:
    - command_1
    - command_2
    # ...
    - command_n
    tags:
      - my-custom-tag
  ```

- Pour les jobs gourmands en CPU :

  ```yaml
  variables:
    KUBERNETES_CPU_LIMIT: "0.75"
    KUBERNETES_MEMORY_LIMIT: "900Mi"
    KUBERNETES_HELPER_CPU_LIMIT: "150m"
    KUBERNETES_HELPER_MEMORY_LIMIT: "100Mi"

  tests:
    image: custom-cpu-intensive-image:latest
    script:
    - cpu_intensive_command_1
    - cpu_intensive_command_2
    # ...
    - cpu_intensive_command_n
    tags:
      - my-custom-tag
  ```

> [!note]
> Pour une configuration plus simple, utilisez un GitLab Runner par cluster pour chaque profil de job. Cette approche est recommandée jusqu'à ce que GitLab prenne en charge soit plusieurs installations de GitLab Runner sur le même cluster, soit plusieurs sections `[[runners]]` dans le template `config.toml`.

### Configurer la surveillance et l'observabilité {#set-up-monitoring-and-observability}

En tant que dernière étape de la phase de déploiement, vous devez établir une solution pour surveiller l'environnement hôte du runner et GitLab Runner. Les métriques au niveau de l'infrastructure, du runner et des jobs CI/CD fournissent des informations sur l'efficacité et la fiabilité de votre infrastructure de build CI/CD. Elles fournissent également les informations nécessaires pour ajuster et optimiser le cluster Kubernetes, GitLab Runner et la configuration des jobs CI/CD.

#### Bonnes pratiques de surveillance {#monitoring-best-practices}

- Surveillez les métriques au niveau des jobs : durée des jobs, taux de réussite et d'échec des jobs.
  - Pour analyser les métriques au niveau des jobs, identifiez quels jobs CI/CD sont exécutés le plus fréquemment et consomment le plus de ressources de calcul et de RAM au total. Ce profil de job est un bon point de départ pour évaluer les opportunités d'optimisation.
- Surveillez l'utilisation des ressources du cluster Kubernetes :
  - Utilisation du CPU
  - Utilisation de la mémoire
  - Utilisation du réseau
  - Utilisation du disque

Consultez la [page de surveillance dédiée à GitLab Runner](https://docs.gitlab.com/runner/monitoring/) pour plus de détails sur la marche à suivre.

## Optimiser {#optimize}

L'optimisation d'un environnement de build CI/CD est un processus continu. Le type et le volume des jobs CI/CD évoluent constamment, nécessitant votre engagement actif.

Vous avez probablement des objectifs organisationnels spécifiques pour le CI/CD et l'infrastructure de build CI/CD. Par conséquent, la première étape consiste à définir vos exigences d'optimisation et vos objectifs quantifiables.

Voici un exemple d'exigences d'optimisation provenant de notre base de clients :

- Temps de démarrage des jobs CI/CD
- Durée des jobs CI/CD
- Fiabilité des jobs CI/CD
- Optimisation des coûts de calcul CI/CD

L'étape suivante consiste à commencer à analyser les métriques CI/CD conjointement avec les métriques d'infrastructure du cluster Kubernetes. Une corrélation critique à analyser est la suivante :

- Utilisation du CPU par espace de nommage Kubernetes
- Utilisation de la mémoire par espace de nommage Kubernetes
- Utilisation du CPU par nœud
- Utilisation de la mémoire par nœud
- Taux d'échec des jobs CI/CD

Généralement sur Kubernetes, les taux élevés d'échec des jobs CI/CD (indépendants des échecs dus aux tests instables) sont attribués à des contraintes de ressources sur le cluster Kubernetes. Analysez ces métriques pour atteindre l'équilibre optimal entre les temps de démarrage des jobs CI/CD, la durée des jobs, la fiabilité des jobs et l'utilisation des ressources d'infrastructure dans la configuration de votre cluster Kubernetes.

### Bonnes pratiques {#best-practices-1}

- Établissez un processus pour catégoriser les jobs CI/CD dans l'ensemble de votre organisation par type de job.
- Établissez un framework de catégorisation des types de jobs pour simplifier à la fois la configuration de la surveillance et l'approche d'optimisation de l'infrastructure de build GitLab CI/CD sur Kubernetes et du type de job CI/CD.
- Attribuer à chaque type de job son propre nœud sur le cluster peut aboutir au meilleur équilibre entre les performances des jobs CI/CD, la fiabilité des jobs et l'utilisation de l'infrastructure.

L'utilisation de Kubernetes comme pile d'infrastructure pour l'environnement de build CI/CD offre des avantages significatifs. Cependant, cela nécessite une surveillance et une optimisation continues de l'infrastructure Kubernetes. Après avoir mis en place un framework d'observabilité et d'optimisation, vous pouvez supporter des millions de jobs CI/CD par mois. Vous pouvez éliminer les contentions de ressources, obtenir des exécutions de jobs CI/CD déterministes et une utilisation optimale des ressources. Ces améliorations se traduisent par une efficacité opérationnelle et une optimisation des coûts.

## Étapes suivantes {#next-steps}

Suivez les prochaines étapes pour offrir une meilleure expérience utilisateur :

- Prise en charge de plusieurs installations de GitLab Runner sur le même cluster. Cela permet une meilleure gestion des scénarios où plusieurs profils de jobs doivent être gérés (le GitLab Runner peut être configuré de manière adéquate pour éviter tout usage abusif des ressources).
- Prise en charge de la mise à l'échelle automatique des nœuds GKE. Cela permet à GKE d'effectuer une mise à l'échelle automatique à la hausse ou à la baisse en fonction de la charge de travail, réduisant ainsi les coûts.
- Activer la surveillance des métriques des jobs. Cela permet aux administrateurs de mieux optimiser leur cluster et GitLab Runner en fonction de l'utilisation réelle.
