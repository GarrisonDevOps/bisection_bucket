---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Mesurez les émissions de carbone de votre infrastructure cloud et de vos applications avec Carmen.
title: Carmen
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> Carmen est un logiciel en cours de développement qui n'a pas été approuvé ni adopté par la Green Software Foundation. Ne vous fiez pas à Carmen à d'autres fins que l'examen de l'état actuel du développement. GitLab ne maintient pas cet outil et n'en assure pas le support, et ne garantit pas que cet outil satisfait aux exigences réglementaires ou de conformité. Carmen n'est pas adapté aux rapports ESG d'entreprise, aux déclarations de conformité ou aux supports marketing.

[Carmen](https://github.com/Green-Software-Foundation/if-carmen) (Carbon Measurement Engine) est un outil open source qui mesure les émissions de carbone de votre infrastructure cloud et de vos applications.

Carmen mesure les émissions de carbone à partir de deux sources :

- Infrastructure : consommation d'énergie et émissions de carbone des machines virtuelles et des charges de travail cloud, à l'aide des données d'utilisation des VM au format CSV.
- Application : émissions de carbone des charges de travail individuelles et des pods s'exécutant dans un cluster Kubernetes, à l'aide des métriques Prometheus.

Carmen génère un rapport CSV utilisable dans Grafana, des tableaux de bord FinOps ou vos propres outils.

## Format des données d'entrée {#input-data-format}

Le daemon Carmen attend les données d'utilisation des VM au format CSV. Pour un fichier local, pointez `config.yaml` vers le chemin où se trouve votre fichier CSV. Si vous utilisez Azure Blob Storage, configurez votre compte de stockage dans `config.yaml` et Carmen lit les données directement.

Les champs obligatoires sont :

| Champ                  | Description                                                    | Exemple |
| ---------------------- | -------------------------------------------------------------- | ------- |
| `Time`                 | Horodatage au format ISO 8601.                                  | `2024-10-15T14:30:00Z` |
| `Id`                   | Identifiant unique de la VM (détermine la granularité du rapport).    | `vm-a1b2c3d4` |
| `Size`                 | Taille de l'instance VM.                                              | `Standard_D4s_v3` |
| `Region`               | Région où la VM est déployée.                               | `eastus` |
| `Service`              | Service cloud ou catégorie de produit.                             | `Compute` |
| `Component`            | Couche applicative que la VM dessert.                               | `api-gateway` |
| `Subscription`         | Identifiant d'abonnement cloud.                                 | `prod-subscription-001` |
| `Name`                 | Nom de la VM lisible par l'humain.                                        | `production-web-01` |
| `Instance`             | Identifiant d'instance pour une VM dans un groupe de déploiement.            | `web-server-03` |
| `Environment`          | Environnement de déploiement.                                        | `production` |
| `Partition`            | Partition logique ou locataire.                                   | `team-finance` |
| `AverageCpuPercentage` | Utilisation moyenne du CPU pendant la période de mesure (0-100). | `45.7`  |
| `DiskSizeGb`           | Espace disque total provisionné en gigaoctets.                   | `128`   |

Le champ `Id` détermine la granularité du rapport. Chaque valeur unique dans `Id` génère un composant dans la sortie. Le niveau par VM est courant, mais vous pouvez utiliser un identifiant plus grossier (par service) ou plus fin selon les informations dont vous avez besoin.

## Ajouter Carmen à votre pipeline {#add-carmen-to-your-pipeline}

Vous pouvez exécuter Carmen en tant que job CI/CD pour générer un rapport d'émissions de carbone à partir de vos données d'utilisation des VM, enregistré en tant qu'artefact de pipeline.

Prérequis :

- Python 3.12, pip, npm, Git, `lsb-release` et bash dans votre environnement de runner.
- Données d'utilisation des VM sous forme de fichier CSV local au format requis. Carmen prend également en charge la lecture depuis Azure Blob Storage.
- Un fichier `config.yaml` à un chemin connu.

Pour ajouter Carmen à votre pipeline :

1. Dans votre fichier `.gitlab-ci.yml`, ajoutez un job qui installe Carmen et exécute le daemon sur les données d'exemple fournies avec Carmen :

   ```yaml
   carbon-report:
     image: python:3.12
     before_script:
       - apt-get update && apt-get install -y nodejs npm git lsb-release
       - git clone https://github.com/Green-Software-Foundation/if-carmen.git
       - npm install -g "@grnsft/if@1.0.0" "@grnsft/if-plugins@0.3.2" "@grnsft/if-unofficial-plugins@0.3.1"
       - pip install --upgrade pip && pip install -e $CI_PROJECT_DIR/if-carmen
     script:
       - cd $CI_PROJECT_DIR/if-carmen/example-data && carbon-daemon
     artifacts:
       paths:
         - if-carmen/example-data/output/
       expire_in: 1 week
   ```

1. Exécutez le pipeline et confirmez que le job produit un fichier `CO2_<date>.csv` dans les artefacts avec des valeurs non nulles dans les colonnes `EnergykWh` et `TotalCarbonGramsCO2eq`.
1. Ajoutez un fichier `config.yaml` à votre dépôt pointant vers vos données CSV locales :

   ```yaml
   carmen_daemon:
     source:
       type: local
       file_names:
         - "vm_metrics.csv"
       local:
         source_path: "data/vm-metrics"
     upload:
       type: local
       local:
         upload_path: "./output"
   ```

   Pour Azure Blob Storage, définissez `source.type` sur `azure` et ajoutez les paramètres et les identifiants de votre compte de stockage Azure. Pour toutes les options, consultez [la configuration de Carmen](https://github.com/Green-Software-Foundation/if-carmen/blob/dev/docs/configuration.md).

1. Remplacez les sections `script` et `artifacts` de votre job :

   ```yaml
   script:
     - mkdir -p $CI_PROJECT_DIR/output
     - cd $CI_PROJECT_DIR && carbon-daemon
   artifacts:
     paths:
       - output/
     expire_in: 1 week
   ```

1. Exécutez à nouveau le pipeline et confirmez que le fichier de sortie `CO2_<date>.csv` contient vos propres données.

## Afficher les résultats {#view-results}

Carmen génère un rapport CSV avec une ligne par composant (VM) par jour. Le fichier de sortie suit le modèle de nommage `CO2_<date>.csv` et est enregistré dans le chemin configuré dans `upload.local.upload_path`.

Pour afficher les résultats :

1. Accédez à votre pipeline.
1. Sélectionnez le job `carbon-report`.
1. Sous **Artéfacts de job**, sélectionnez **Parcourir**.
1. Ouvrez le fichier `CO2_<date>.csv`.

Le rapport comprend les champs suivants :

| Champ                         | Description |
| ----------------------------- | ----------- |
| `Date`                        | La plage de rapport de 24 heures. |
| `Id`                          | Identifiant unique du composant (VM). |
| `Name`                        | Nom lisible par l'humain de la VM. |
| `EnergykWh`                   | Énergie totale consommée en kilowattheures. |
| `OperationalCarbonGramsCO2eq` | Émissions de carbone liées à la consommation d'énergie pendant l'exploitation. |
| `EmbodiedCarbonGramsCO2eq`    | Émissions de carbone liées à la fabrication, au transport et à l'élimination du matériel. |
| `TotalCarbonGramsCO2eq`       | Somme des émissions de carbone opérationnelles et intrinsèques. |
| `CarbonIntensity`             | Intensité carbone du réseau électrique régional (gCO2eq/kWh). |

## Mesure des applications {#application-measurement}

Pour mesurer les émissions de carbone des charges de travail individuelles dans un cluster Kubernetes, vous pouvez déployer Carmen en tant que service API sidecar aux côtés de Prometheus. Ce mode extrait les métriques CPU et mémoire par pod à des intervalles configurables.

Ce déploiement nécessite un cluster Kubernetes avec Helm, Prometheus, kube-state-metrics et cAdvisor. Pour plus d'informations, consultez [Carmen as a Service](https://github.com/Green-Software-Foundation/if-carmen/blob/dev/docs/carmen-as-a-service.md) dans le dépôt Carmen.

## Dépannage {#troubleshooting}

Lorsque vous travaillez avec Carmen, vous pouvez rencontrer les problèmes suivants.

### Le premier rapport de sortie semble incorrect {#first-report-output-looks-incorrect}

Les valeurs d'émissions de carbone semblent anormalement élevées ou basses.

Ce problème se produit lorsque Carmen utilise par défaut la configuration matérielle de référence, car les spécifications réelles de la VM n'ont pas été fournies.

Pour résoudre ce problème, fournissez les spécifications réelles de la VM à partir de l'API de votre fournisseur cloud.

### La sortie ne contient qu'une seule ligne par VM {#output-contains-only-one-row-per-vm}

Votre rapport contient moins de lignes que prévu.

Ce problème se produit lorsque plusieurs enregistrements partagent la même valeur `Id`.

Pour résoudre ce problème, vérifiez la colonne `Id` dans votre fichier CSV d'entrée. Chaque valeur unique dans `Id` génère un composant dans la sortie.

### Carmen ne produit aucune sortie {#carmen-produces-no-output}

Le répertoire de sortie est vide après l'exécution de `carbon-daemon`.

Ce problème peut être causé par le fait que l'Impact Framework n'est pas installé globalement, ou que les chemins de `config.yaml` ne se résolvent pas depuis le répertoire où vous exécutez `carbon-daemon`.

Pour résoudre ce problème :

- Vérifiez que `@grnsft/if` est installé et accessible : `if-run --version`
- Vérifiez que les chemins dans `config.yaml` se résolvent depuis votre répertoire de travail.

### Les mesures sont agrégées uniquement en totaux journaliers {#measurements-aggregate-to-daily-totals-only}

Vous avez besoin de valeurs d'émissions de carbone horaires ou infra-journalières.

Carmen agrège uniquement en totaux journaliers. La résolution horaire est une limitation connue.
