---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Analyse de l'Infrastructure as Code"
description: "Détection des vulnérabilités, analyse de la configuration et intégration au pipeline."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'analyse de l'Infrastructure as Code (IaC) s'exécute dans votre pipeline CI/CD et vérifie la présence de vulnérabilités connues dans vos fichiers de définition d'infrastructure. Identifiez les vulnérabilités avant qu'elles ne soient committées sur la branche par défaut afin de traiter proactivement les risques pour votre application.

L'analyseur IaC génère des rapports au format JSON sous forme d'[artefacts de job](../../../ci/yaml/artifacts_reports.md#artifactsreportssast).

Avec GitLab Ultimate, les résultats de l'analyse IaC sont également traités afin que vous puissiez :

- Les consulter dans les merge requests.
- Les utiliser dans les workflows d'approbation.
- Les examiner dans le rapport de vulnérabilités.

## Premiers pas {#getting-started}

Si vous découvrez l'analyse IaC, suivez ces étapes pour l'activer pour votre projet.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.
- Un minimum de 4 Go de RAM pour garantir des performances constantes.
- Un runner GitLab sous Linux avec l'exécuteur Docker ou Kubernetes. Si vous utilisez des runners hébergés pour GitLab.com, l'exécuteur Docker ou Kubernetes est activé par défaut.
  - GitLab Runner sur Windows n'est pas pris en charge.
  - Les architectures CPU autres qu'AMD64 ne sont pas prises en charge.
- La configuration GitLab CI/CD (`.gitlab-ci.yml`) doit inclure l'étape `test`. L'étape `test` est incluse par défaut, mais si vous redéfinissez les étapes, vous devez l'ajouter explicitement.

Pour activer l'analyse IaC :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez à **Compilation** > Éditeur de **pipeline**.
1. Ajoutez le template ou le composant CI/CD d'analyse IaC.

   Pour utiliser le template, ajoutez les lignes suivantes :

   ```yaml
   include:
     - template: Jobs/SAST-IaC.gitlab-ci.yml
   ```

   Pour utiliser le composant CI/CD, ajoutez les lignes suivantes :

   ```yaml
   include:
     - component: gitlab.com/components/sast/iac-sast@main
   ```

1. Sélectionnez l'onglet **Valider**, puis sélectionnez **Valider le pipeline**.

   Le message **Simulation terminée avec succès** confirme que le fichier est valide.
1. Sélectionnez l'onglet **Éditer**.
1. Remplissez les champs :
   - Message de commit.
   - Branche. Par exemple, `add-iac`.
1. Cochez la case **Lancer une nouvelle merge request avec ces modifications**, puis sélectionnez **Valider les modifications**.

   La page de la merge request s'ouvre.
1. Remplissez les champs selon votre workflow standard, puis sélectionnez **Créer une requête de fusion**.
1. Examinez et modifiez la merge request selon votre procédure habituelle, puis sélectionnez **Fusionner**.

À ce stade, l'analyse IaC est activée dans votre pipeline :

- Le job d'analyse IaC s'exécute sur chaque pipeline et lance l'analyseur KICS.
- L'analyseur détermine si le projet contient des fichiers IaC pris en charge.
- Si des fichiers pris en charge sont trouvés, l'analyseur recherche les vulnérabilités.
- Si aucun fichier pris en charge n'est trouvé, le job se termine sans aucun résultat.

Le job correspondant apparaît sous l'étape `test` dans votre pipeline.

Vous pouvez consulter un exemple fonctionnel dans le [projet exemple d'analyse IaC](https://gitlab.com/gitlab-org/security-products/demos/analyzer-configurations/kics/iac-getting-started).

### Étapes suivantes {#next-steps}

Après avoir activé l'analyse IaC, vous pouvez :

- En savoir plus sur la façon de [comprendre les résultats](#understanding-the-results)
- Consulter les [conseils d'optimisation](#optimize-iac-scanning)
- Planifier un [déploiement sur plusieurs projets](#roll-out)

## Comprendre les résultats {#understanding-the-results}

Prérequis :

- Le rôle Gestionnaire de sécurité, Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Vous pouvez examiner les vulnérabilités dans un pipeline :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.
1. Sélectionnez le pipeline.
1. Sélectionnez l'onglet **Sécurisation**.
1. Sélectionnez une vulnérabilité pour afficher ses détails, notamment :
   - Description : explique la cause de la vulnérabilité, son impact potentiel et les étapes de remédiation recommandées.
   - Statut : indique si la vulnérabilité a été classée ou résolue.
   - Gravité : [En savoir plus sur les niveaux de gravité](../vulnerabilities/severities.md).
   - Emplacement : indique le nom du fichier et le numéro de la ligne où le problème a été détecté. La sélection du chemin de fichier ouvre la ligne correspondante dans la vue du code.
   - Analyseur :  indique l'analyseur qui a détecté la vulnérabilité.
   - Identifiants :  une liste de références utilisées pour classifier la vulnérabilité, telles que les identifiants CWE et les identifiants des règles qui l'ont détectée.

Dans GitLab Ultimate, vous pouvez également télécharger les résultats de l'analyse de sécurité :

Prérequis :

- Le rôle Gestionnaire de sécurité, Développeur, Chargé de maintenance ou Propriétaire pour le projet.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.
1. Sélectionnez le pipeline.
1. Sélectionnez l'onglet **Sécurisation**.
1. Dans l'onglet **Sécurité** du pipeline, sélectionnez **Télécharger les résultats**.

Pour plus de détails, voir [Rapport de sécurité du pipeline](../detect/security_scanning_results.md).

> [!note]
> Les résultats sont générés sur les branches de fonctionnalités. Lorsqu'ils sont fusionnés dans la branche par défaut, ils deviennent des vulnérabilités. Cette distinction est importante lors de l'évaluation de votre posture de sécurité.

Autres façons de consulter les résultats de l'analyse IaC :

- [Rapports de merge request](../../project/merge_requests/reports.md) : Affiche les résultats nouvellement introduits ou résolus.
- [Vue des modifications de la merge request](../sast/_index.md#merge-request-changes-view) : Affiche les annotations en ligne pour les lignes modifiées.
- [Rapport de vulnérabilités](../vulnerability_report/_index.md) : Affiche les vulnérabilités confirmées sur la branche par défaut.

## Langages et frameworks pris en charge {#supported-languages-and-frameworks}

L'analyse IaC prend en charge une variété de fichiers de configuration IaC. Lorsque des fichiers de configuration pris en charge sont détectés dans un projet, ils sont analysés à l'aide de [KICS](https://kics.io/). Les projets contenant un mélange de fichiers de configuration IaC sont pris en charge.

Formats de configuration pris en charge :

- Ansible
- AWS CloudFormation
- Azure Resource Manager

  > [!note]
  > L'analyse IaC peut analyser les modèles Azure Resource Manager au format JSON. Si vous rédigez des modèles dans [Bicep](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/overview), vous devez utiliser l'[interface de ligne de commande Bicep](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/bicep-cli) pour convertir vos fichiers Bicep en JSON avant que l'analyse IaC puisse les analyser.

- Dockerfile
- Google Deployment Manager
- Kubernetes
- OpenAPI
- Terraform

  KICS ne signale les résultats que pour les types de ressources pour lesquels il dispose de requêtes. KICS dispose de requêtes Terraform pour ces fournisseurs :

  - Alibaba Cloud
  - AWS
  - Azure
  - Databricks
  - GitHub
  - Google Cloud
  - Kubernetes
  - NIFCLOUD
  - Tencent Cloud

  KICS dispose également de vérifications indépendantes du fournisseur. Pour les autres fournisseurs, ces vérifications sont les seules qui s'appliquent. Pour plus d'informations, consultez [les plateformes KICS](https://docs.kics.io/latest/platforms/).

  > [!note]
  > Les modules Terraform dans un registre personnalisé ne sont pas analysés pour détecter les vulnérabilités. Pour plus d'informations sur la fonctionnalité proposée, consultez le [ticket 357004](https://gitlab.com/gitlab-org/gitlab/-/issues/357004).

## Optimiser l'analyse IaC {#optimize-iac-scanning}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez optimiser l'analyse IaC pour réduire le bruit et vous concentrer sur les résultats pertinents :

- Désactiver des règles spécifiques en utilisant un fichier `sast-ruleset.toml`.
- Remplacer des attributs de règle (comme la gravité) en utilisant un fichier `sast-ruleset.toml`.
- Désactiver l'analyse de fichiers spécifiques en utilisant des annotations KICS dans ces fichiers.

L'analyse IaC ne prend pas en charge l'ajout ou le remplacement de règles. Pour les options prises en charge par chaque analyseur, consultez les [options de personnalisation des règles](../sast/customize_rulesets.md#rule-customization-options).

Utilisez un fichier `sast-ruleset.toml` pour désactiver des règles ou remplacer des attributs de règle. Cette approche offre les avantages suivants :

- Intégration à la gestion des vulnérabilités GitLab pour résoudre automatiquement les résultats existants lorsque des règles sont désactivées.
- Documentation gérée par contrôle de version de vos décisions en matière de politique de sécurité.
- La possibilité de partager des ensembles de règles entre plusieurs projets lors du déploiement de l'analyse IaC.

### Définition de l'ensemble de règles {#ruleset-definition}

Chaque règle d'analyse IaC est contenue dans une section `ruleset`, qui contient les éléments suivants :

- Un champ `type` pour la règle. Pour l'analyse IaC, le type d'identifiant est `kics_id`.
- Un champ `value` pour l'identifiant de la règle. Les identifiants de règles KICS sont des chaînes alphanumériques. Pour trouver l'identifiant de la règle :
  - Recherchez-le dans l'[artefact de rapport JSON](#reports-json-format).
  - Recherchez le nom de la règle dans la [liste des requêtes KICS](https://docs.kics.io/latest/queries/all-queries/) et copiez l'identifiant alphanumérique affiché. Le nom de la règle est affiché sur la [page de détails de la vulnérabilité](../vulnerabilities/_index.md) lorsqu'une violation de règle est détectée.

### Désactiver des règles {#disable-rules}

Vous pouvez désactiver des règles d'analyse IaC spécifiques. Les résultats précédemment détectés par des règles désactivées sont [automatiquement résolus](#automatic-vulnerability-resolution).

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour désactiver des règles d'analyseur :

1. Créez un répertoire `.gitlab` à la racine de votre projet, s'il n'existe pas déjà.
1. Créez un fichier d'ensemble de règles personnalisé nommé `sast-ruleset.toml` dans le répertoire `.gitlab`, s'il n'existe pas déjà.
1. Définissez l'indicateur `disabled` sur `true` dans le contexte d'une section `ruleset`.
1. Dans une ou plusieurs sous-sections `ruleset`, listez les règles à désactiver.

Après avoir fusionné le fichier `sast-ruleset.toml` sur la branche par défaut, les résultats existants pour les règles désactivées sont [automatiquement résolus](#automatic-vulnerability-resolution).

Dans l'exemple de fichier `sast-ruleset.toml` suivant, les règles désactivées sont assignées à l'analyseur `kics` en faisant correspondre le `type` et la `value` des identifiants :

```toml
[kics]
  [[kics.ruleset]]
    disable = true
    [kics.ruleset.identifier]
      type = "kics_id"
      value = "8212e2d7-e683-49bc-bf78-d6799075c5a7"

  [[kics.ruleset]]
    disable = true
    [kics.ruleset.identifier]
      type = "kics_id"
      value = "b03a748a-542d-44f4-bb86-9199ab4fd2d5"
```

### Désactiver l'analyse d'un fichier {#disable-scanning-of-a-file}

Pour désactiver l'analyse d'un fichier, entièrement ou pour une seule règle, utilisez les [annotations KICS](https://docs.kics.io/latest/running-kics/#using_commands_on_scanned_files_as_comments) dans ce fichier.

Cette fonctionnalité n'est disponible que pour certains types de fichiers IaC. Consultez la [documentation KICS](https://docs.kics.io/latest/running-kics/#using_commands_on_scanned_files_as_comments) pour obtenir la liste des types de fichiers pris en charge.

- Pour ignorer l'analyse d'un fichier entier, ajoutez `# kics-scan ignore` comme commentaire en haut du fichier.
- Pour désactiver une règle spécifique dans un fichier entier, ajoutez `# kics-scan disable=<kics_id>` comme commentaire en haut du fichier.

### Remplacer des règles {#override-rules}

Vous pouvez remplacer des règles d'analyse IaC spécifiques pour les personnaliser. Par exemple, attribuez à une règle une gravité inférieure, ou créez un lien vers votre propre documentation expliquant comment corriger un résultat.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour remplacer des règles :

1. Créez un répertoire `.gitlab` à la racine de votre projet, s'il n'existe pas déjà.
1. Créez un fichier d'ensemble de règles personnalisé nommé `sast-ruleset.toml` dans le répertoire `.gitlab`, s'il n'existe pas déjà.
1. Dans une ou plusieurs sous-sections `ruleset.identifier`, listez les règles à remplacer.
1. Dans le contexte `ruleset.override` d'une section `ruleset`, indiquez les clés à remplacer. Toute combinaison de clés peut être remplacée. Les clés valides sont :
   - description
   - message
   - name
   - severity (les options valides sont : Critical, High, Medium, Low, Unknown, Info)

Dans l'exemple de fichier `sast-ruleset.toml` suivant, les règles sont associées par le `type` et la `value` des identifiants, puis remplacées :

```toml
[kics]
  [[kics.ruleset]]
    [kics.ruleset.identifier]
      type = "kics_id"
      value = "8212e2d7-e683-49bc-bf78-d6799075c5a7"
    [kics.ruleset.override]
      description = "OVERRIDDEN description"
      message = "OVERRIDDEN message"
      name = "OVERRIDDEN name"
      severity = "Info"
```

## Configuration hors ligne {#offline-configuration}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Un environnement hors ligne dispose d'un accès limité, restreint ou intermittent aux ressources externes via Internet. Pour les instances dans un tel environnement, IaC nécessite quelques modifications de configuration. Les instructions de cette section doivent être réalisées conjointement avec les instructions détaillées dans [les environnements hors ligne](../offline_deployments/_index.md).

### Configurer GitLab Runner {#configure-gitlab-runner}

Par défaut, un runner tente de récupérer des images Docker depuis le registre de conteneurs GitLab, même si une copie locale est disponible. Vous devriez utiliser ce paramètre par défaut pour vous assurer que les images Docker restent à jour. Toutefois, si aucune connectivité réseau n'est disponible, vous devez modifier la variable `pull_policy` par défaut de GitLab Runner.

Configurez la variable CI/CD `pull_policy` de GitLab Runner sur [`if-not-present`](https://docs.gitlab.com/runner/executors/docker/#using-the-if-not-present-pull-policy).

### Utiliser une image locale de l'analyseur IaC {#use-local-iac-analyzer-image}

Utilisez une image locale de l'analyseur IaC si vous souhaitez obtenir l'image depuis un registre Docker local plutôt que depuis le registre de conteneurs GitLab.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.
- L'importation d'images Docker dans un registre Docker local hors ligne dépend de votre politique de sécurité réseau. Consultez votre équipe informatique pour trouver un processus accepté et approuvé pour importer ou accéder temporairement aux ressources externes.

Pour utiliser une image locale de l'analyseur IaC :

1. Importez l'image par défaut de l'analyseur IaC depuis `registry.gitlab.com` dans votre [registre de conteneurs Docker local](../../packages/container_registry/_index.md) :

   ```plaintext
   registry.gitlab.com/security-products/kics:6
   ```

   L'image de l'analyseur IaC est [mise à jour périodiquement](../detect/vulnerability_scanner_maintenance.md), vous devez donc mettre à jour régulièrement la copie locale.

1. Définissez la variable CI/CD `SECURE_ANALYZERS_PREFIX` sur le registre de conteneurs Docker local.

   ```yaml
   include:
     - template: Jobs/SAST-IaC.gitlab-ci.yml

   variables:
     SECURE_ANALYZERS_PREFIX: "localhost:5000/analyzers"
   ```

Le job IaC doit maintenant utiliser la copie locale de l'image Docker de l'analyseur, sans nécessiter d'accès à Internet.

## Utiliser une version spécifique de l'analyseur {#use-a-specific-analyzer-version}

Le template CI/CD géré par GitLab spécifie une version majeure et récupère automatiquement la dernière release de l'analyseur dans cette version majeure. Dans certains cas, vous pouvez avoir besoin d'utiliser une version spécifique. Par exemple, vous pourriez avoir besoin d'éviter une régression dans une release ultérieure.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour utiliser une version spécifique de l'analyseur :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Version** > **Éditeur de pipeline**.
1. Ajoutez la variable CI/CD `SAST_ANALYZER_IMAGE_TAG`, après la ligne qui inclut le template `SAST-IaC.gitlab-ci.yml`.

   > [!note]
   > Définissez cette variable uniquement dans un job spécifique. Si vous la définissez au niveau supérieur, la version que vous avez définie est utilisée pour les autres analyseurs SAST.

   Définissez le tag sur :

   - Une version majeure, comme `3`. Vos pipelines utilisent toutes les mises à jour mineures ou correctives publiées dans cette version majeure.
   - Une version mineure, comme `3.7`. Vos pipelines utilisent toutes les mises à jour correctives publiées dans cette version mineure.
   - Une version corrective, comme `3.7.0`. Vos pipelines ne reçoivent aucune mise à jour.

Cet exemple utilise une version mineure spécifique de l'analyseur IaC :

```yaml
include:
  - template: Jobs/SAST-IaC.gitlab-ci.yml

kics-iac-sast:
  variables:
    SAST_ANALYZER_IMAGE_TAG: "3.1"
```

## Distributions prises en charge {#supported-distributions}

Les scanners GitLab sont fournis avec une image Alpine de base pour des raisons de taille et de maintenabilité.

### Utiliser des images compatibles FIPS {#use-fips-enabled-images}

GitLab fournit des versions [Red Hat UBI compatibles FIPS](https://www.redhat.com/en/blog/introducing-red-hat-universal-base-image) des images des scanners, en plus des images standard.

Pour utiliser les images compatibles FIPS dans un pipeline, définissez `SAST_IMAGE_SUFFIX` sur `-fips` ou modifiez le tag standard en ajoutant l'extension `-fips`.

L'exemple suivant utilise la variable CI/CD `SAST_IMAGE_SUFFIX`.

```yaml
variables:
  SAST_IMAGE_SUFFIX: '-fips'

include:
  - template: Jobs/SAST-IaC.gitlab-ci.yml
```

## Résolution automatique des vulnérabilités {#automatic-vulnerability-resolution}

Pour vous aider à vous concentrer sur les vulnérabilités encore pertinentes, l'analyse IaC [résout](../vulnerabilities/_index.md#vulnerability-status-values) automatiquement les vulnérabilités lorsque :

- Vous [désactivez une règle prédéfinie](#disable-rules).
- Nous supprimons une règle de l'ensemble de règles par défaut.

Si vous réactivez la règle ultérieurement, les résultats sont rouverts pour classement.

Le système de gestion des vulnérabilités ajoute une note lorsqu'il résout automatiquement une vulnérabilité.

## Format JSON des rapports {#reports-json-format}

Le scanner IaC génère un fichier de rapport JSON dans le format de rapport SAST existant. Pour plus d'informations, consultez le [schéma de ce rapport](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/sast-report-format.json).

Le fichier de rapport JSON peut être téléchargé depuis :

- La page des pipelines CI/CD.
- L'onglet des pipelines dans les merge requests en [définissant `artifacts: paths`](../../../ci/yaml/_index.md#artifactspaths) sur `gl-sast-report.json`.

Pour plus d'informations, consultez [Télécharger des artefacts](../../../ci/jobs/job_artifacts.md).

## Déploiement {#roll-out}

Après avoir validé les résultats de l'analyse IaC pour un projet, vous pouvez appliquer la même approche à d'autres projets.

- Utilisez l'[exécution d'analyse imposée](../detect/security_configuration.md#create-a-shared-configuration) pour appliquer les paramètres d'analyse IaC à l'ensemble des groupes.
- Partagez et réutilisez un ensemble de règles central en [spécifiant un fichier de configuration distant](../sast/customize_rulesets.md#use-a-remote-ruleset-file).

## Dépannage {#troubleshooting}

Lorsque vous utilisez l'analyse IaC, vous pouvez rencontrer les problèmes suivants.

### Les résultats de l'analyse IaC s'affichent comme `No longer detected` de manière inattendue {#iac-scanning-findings-show-as-no-longer-detected-unexpectedly}

Si un résultat précédemment détecté s'affiche de manière inattendue comme `No longer detected`, cela peut être dû à une mise à jour du scanner. Une mise à jour peut désactiver des règles jugées inefficaces ou des faux positifs, et les résultats sont marqués comme `No longer detected`.

### Message `exec /bin/sh: exec format error` dans le job log {#message-exec-binsh-exec-format-error-in-job-log}

Vous pouvez obtenir une erreur dans le job log indiquant `exec /bin/sh: exec format error`. Ce problème survient lors d'une tentative d'exécution de l'analyseur d'analyse IaC sur une architecture autre qu'AMD64. Pour plus de détails sur les prérequis de l'analyse IaC, consultez les [prérequis](#getting-started).
