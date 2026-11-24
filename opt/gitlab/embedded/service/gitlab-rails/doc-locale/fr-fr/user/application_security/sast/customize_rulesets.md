---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Personnalisez les règles de l'analyseur SAST dans GitLab en désactivant, en remplaçant ou en substituant les règles par défaut."
title: Personnaliser les ensembles de règles
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'analyseur SAST basé sur Semgrep et l'analyseur GitLab Advanced SAST disposent chacun d'un [ensemble de règles par défaut](rules.md). Vous pouvez personnaliser leurs règles pour répondre aux exigences de sécurité de votre organisation. Par exemple, vous pourriez vouloir augmenter le niveau de gravité d'une règle spécifique.

Avant d'écrire des règles personnalisées pour l'analyseur SAST basé sur Semgrep, vous pouvez les prototyper et les tester de manière interactive dans le [Semgrep Playground](https://semgrep.dev/playground/new). Lorsque vous utilisez le Playground, ignorez les résultats dans le panneau **test code** marqués d'une icône étoile ({{< icon name="star" >}}) et dont l'info-bulle indique **Finding found with the Semgrep Pro Engine**. Ces résultats ne sont pas compatibles avec le moteur Semgrep open source utilisé par GitLab. Pour plus d'informations sur le format des règles Semgrep, consultez [Learn Semgrep Syntax](https://semgrep.dev/learn).

## Glossaire des ensembles de règles {#ruleset-glossary}

Règle : contrôle de sécurité individuel ou modèle de détection qui analyse des vulnérabilités spécifiques.

Ensemble de règles : fichier au format YAML qui spécifie les règles individuelles à appliquer par un analyseur.

Fichier de configuration de l'ensemble de règles : fichier au format TOML qui spécifie quel ensemble de règles appliquer et s'il est stocké localement ou à distance. Nom de fichier : `sast-ruleset.toml`.

Passthrough : un passthrough est une source de configuration qui extrait les personnalisations d'ensemble de règles depuis un fichier, un dépôt Git, une URL ou une configuration en ligne. Vous pouvez combiner plusieurs passthroughs en une chaîne, où chacun peut écraser ou ajouter à la configuration précédente.

## Options de personnalisation des règles {#rule-customization-options}

Vous pouvez personnaliser les ensembles de règles par défaut en désactivant des règles, en remplaçant leurs métadonnées, ou en substituant ou ajoutant des règles.

Le tableau ci-dessous présente les options de personnalisation disponibles pour chaque type d'analyseur.

| Personnalisation                          | GitLab Advanced SAST                                                                                                                                             | GitLab Semgrep             | [Autres analyseurs](analyzers.md#official-analyzers) et [analyse IaC](../iac_scanning/_index.md) |
|----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------|----------------------------------------------------|
| Désactiver les règles par défaut               | {{< yes >}}                                                                                                                                                      | {{< yes >}}                | {{< yes >}}                                        |
| Remplacer les métadonnées des règles par défaut  | {{< yes >}}                                                                                                                                                      | {{< yes >}}                | {{< yes >}}                                        |
| Remplacer ou ajouter aux règles par défaut | Prend en charge la modification du comportement des règles structurelles non-taint par défaut et l'application des passthroughs de type fichier et brut. Les autres types de passthroughs sont ignorés. | Prend en charge les passthroughs complets. | {{< no >}}                                         |

> [!note]
> La portée du support de GitLab est limitée à l'intégration de l'analyseur Semgrep et aux ensembles de règles par défaut. Si vous remplacez ou ajoutez des règles par défaut, vous devez gérer les problèmes de compatibilité qui pourraient en résulter. Pour plus de détails, consultez la [documentation sur la compatibilité de l'analyseur Semgrep](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep/-/blob/main/COMPATIBILITY.md).

### Désactiver les règles par défaut {#disable-default-rules}

Vous pouvez désactiver les règles par défaut pour tout analyseur SAST. Par exemple, vous pourriez vouloir exclure une règle spécifique en fonction de la politique organisationnelle.

Consultez les exemples suivants :

- [Désactiver des règles GitLab Advanced SAST par défaut spécifiques](#disable-specific-default-gitlab-advanced-sast-rules)
- [Désactiver des règles par défaut spécifiques d'autres analyseurs SAST](#disable-specific-default-rules-of-other-sast-analyzers)

### Remplacer les métadonnées des règles par défaut {#override-metadata-of-default-rules}

Vous pouvez remplacer certains attributs des règles par défaut pour tout analyseur SAST. Par exemple, vous pourriez vouloir remplacer la gravité d'une vulnérabilité en fonction de la politique organisationnelle, ou choisir un message différent à afficher dans le rapport de vulnérabilité.

Consultez [remplacer les métadonnées des règles par défaut](#override-default-rule-metadata) pour un exemple.

### Remplacer ou ajouter aux règles par défaut {#replace-or-add-to-the-default-rules}

Vous pouvez remplacer ou ajouter aux règles par défaut de l'analyseur SAST basé sur Semgrep et de l'analyseur GitLab Advanced SAST. Par défaut, la définition d'un ensemble de règles personnalisé remplace l'ensemble de règles par défaut. Pour ajouter à l'ensemble de règles par défaut, vous devez définir `keepdefaultrules` sur `true` dans votre [fichier de configuration de l'ensemble de règles](#configuration-methods).

Consultez les exemples suivants :

- [Remplacer toutes les règles GitLab Advanced SAST par défaut](#replace-all-default-gitlab-advanced-sast-rules)
- [Remplacer ou ajouter aux règles par défaut de `semgrep`](#replace-or-add-to-the-default-rules-of-semgrep)

### Effets de la personnalisation de l'ensemble de règles {#effects-of-ruleset-customization}

Le tableau suivant décrit ce qui se passe lorsque vous personnalisez des ensembles de règles SAST :

| Action                     | Comportement de l'analyse                                                                                                                                                               | Onglet sécurité du pipeline                                                                                                      | Rapport de vulnérabilités                                                                                                                                   |
|----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| Désactiver une règle             | Les analyseurs continuent d'analyser la vulnérabilité, mais les résultats de la règle sont supprimés une fois l'analyse terminée. GitLab Advanced SAST exclut les règles désactivées de l'analyse initiale. | Les résultats détectés par la règle avant sa désactivation n'apparaissent plus après l'exécution du pipeline suivant.                        | Les vulnérabilités détectées par la règle avant sa désactivation sont marquées comme [**N'est plus détectée**](../vulnerability_report/_index.md#activity-filter). |
| Remplacer les métadonnées          | Aucun changement dans le comportement de l'analyse.                                                                                                                                                 | Les métadonnées des résultats détectés par la règle avant son remplacement sont mises à jour après l'exécution du pipeline suivant.               | Les métadonnées des vulnérabilités détectées par la règle avant son remplacement sont mises à jour.                                                                 |
| Remplacer l'ensemble de règles par défaut | L'ensemble de règles par défaut n'est pas utilisé par les analyseurs qui prennent en charge les ensembles de règles personnalisés.                                                                                               | Les résultats détectés par les règles de l'ensemble de règles par défaut avant son remplacement n'apparaissent plus après l'exécution du pipeline suivant. | Les vulnérabilités détectées par les règles de l'ensemble de règles par défaut sont marquées comme [**N'est plus détectée**](../vulnerability_report/_index.md#activity-filter). |

## Méthodes de configuration {#configuration-methods}

Vous pouvez fournir vos personnalisations d'ensemble de règles de différentes manières :

Fichier d'ensemble de règles local : définissez vos personnalisations dans un fichier `sast-ruleset.toml` commis dans votre dépôt. Cette approche maintient la configuration de votre ensemble de règles sous contrôle de version, avec le code source.

Fichier d'ensemble de règles distant : spécifiez un emplacement distant (dépôt Git, URL ou autre source) où votre fichier d'ensemble de règles est hébergé. Cette approche vous permet de gérer un ensemble de règles de manière centralisée et de le réutiliser dans plusieurs projets.

> [!note]
> Un fichier `.gitlab/sast-ruleset.toml` local est prioritaire sur un fichier d'ensemble de règles distant.

Vous fournissez vos personnalisations à l'aide de passthroughs, qui sont des sources de configuration pouvant être combinées en un ensemble de règles.

Toute personnalisation d'ensemble de règles doit être conforme au [schéma d'ensemble de règles SAST](#schema).

### Utiliser un fichier d'ensemble de règles local {#use-a-local-ruleset-file}

Utilisez un fichier d'ensemble de règles local lorsque vous souhaitez stocker les personnalisations avec le code source. Les personnalisations locales s'appliquent uniquement à un projet individuel.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour créer le fichier d'ensemble de règles local :

1. Créez un répertoire `.gitlab` à la racine de votre projet, s'il n'existe pas déjà.
1. Créez un fichier nommé `sast-ruleset.toml` dans le répertoire `.gitlab`.
1. Ajoutez votre ensemble de règles personnalisé au fichier `sast-ruleset.toml`.
1. Commitez le fichier d'ensemble de règles local dans le dépôt.

Consultez les [exemples](#examples) d'un fichier d'ensemble de règles local.

### Utiliser un fichier d'ensemble de règles distant {#use-a-remote-ruleset-file}

Utilisez un fichier d'ensemble de règles distant lorsque vous souhaitez appliquer les mêmes personnalisations à plusieurs projets. Un fichier d'ensemble de règles distant est stocké en dehors du dépôt des projets qui l'utilisent.

Pour utiliser un fichier d'ensemble de règles distant, procédez comme suit :

- Créez un ensemble de règles distant.
- Référencez l'ensemble de règles distant depuis chaque projet.

Un fichier `.gitlab/sast-ruleset.toml` local est prioritaire sur un fichier d'ensemble de règles distant.

> [!warning]
> La définition de `SAST_RULESET_GIT_REFERENCE` étend la limite de confiance de votre projet au dépôt référencé. Les responsables de ce dépôt peuvent modifier la configuration de l'ensemble de règles à tout moment, y compris en activant [`interpolate`](#interpolate) pour évaluer les variables d'environnement dans le job SAST. Ne référencez que des ensembles de règles provenant de dépôts que vous contrôlez ou qui sont gérés par une équipe en laquelle vous avez confiance. Ne pointez pas `SAST_RULESET_GIT_REFERENCE` vers des dépôts publics ou non contrôlés. Pour éviter les modifications silencieuses, épinglez la référence à un SHA Git spécifique afin que l'ensemble de règles ne puisse pas changer sans une mise à jour explicite dans votre projet.

#### Créer un fichier d'ensemble de règles distant {#create-a-remote-ruleset-file}

Créez un fichier d'ensemble de règles distant comme ensemble de règles central pour plusieurs projets.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour créer un ensemble de règles distant :

- Créez l'ensemble de règles dans le dépôt du projet.

  Pour des exemples de fichiers d'ensemble de règles, consultez les [exemples](#examples).

#### Référencer le fichier d'ensemble de règles distant {#reference-the-remote-ruleset-file}

Référencez un fichier d'ensemble de règles distant pour appliquer ses règles à un projet.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.
- [Ensemble de règles distant dans un projet](#create-a-remote-ruleset-file).
- Accès en lecture au projet dans lequel l'ensemble de règles distant est stocké. Par exemple, utilisez un token de job ou un token d'accès de groupe.

Pour référencer un fichier d'ensemble de règles distant, procédez comme suit dans chaque projet :

- Définissez la variable CI/CD `SAST_RULESET_GIT_REFERENCE` pour spécifier l'emplacement du fichier d'ensemble de règles distant.

  La référence au fichier d'ensemble de règles distant utilise un format similaire aux [URL Git](https://git-scm.com/docs/git-clone#_git_urls) pour spécifier un URI de projet, une authentification facultative et un SHA Git facultatif. La variable utilise le format suivant :

  ```plaintext
  [<AUTH_USER>[:<AUTH_PASSWORD>]@]<PROJECT_PATH>[@<GIT_SHA>]
  ```

L'exemple suivant active SAST et utilise un fichier d'ensemble de règles distant. Dans cet exemple, le fichier est commis sur la branche par défaut de `example-ruleset-project` au chemin `.gitlab/sast-ruleset.toml`.

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  SAST_RULESET_GIT_REFERENCE: "gitlab.com/example-group/example-ruleset-project"
```

Pour un exemple avancé, consultez [l'exemple de configuration privée distante](#specify-a-private-remote-configuration).

#### Résoudre les problèmes des fichiers de configuration distants {#troubleshooting-remote-configuration-files}

Si le fichier de configuration distant ne semble pas appliquer correctement les personnalisations, les causes possibles sont :

1. Votre dépôt contient un fichier `.gitlab/sast-ruleset.toml` local.
   - Par défaut, un fichier local est utilisé s'il est présent, même si une configuration distante est définie comme variable.
   - Vous pouvez définir la [variable CI/CD SECURE_ENABLE_LOCAL_CONFIGURATION](../../../ci/variables/_index.md) sur `false` pour ignorer le fichier de configuration local.
1. Il y a un problème d'authentification.
   - Pour vérifier si c'est la cause du problème, essayez de référencer un fichier de configuration depuis un emplacement de dépôt qui ne nécessite pas d'authentification.

## Schéma {#schema}

Le fichier de configuration de l'ensemble de règles utilise la syntaxe TOML. Les sections suivantes décrivent la structure et les paramètres valides pour chaque élément de configuration.

### Section de niveau supérieur {#top-level-section}

La section de niveau supérieur contient une ou plusieurs sections de configuration, définies sous forme de [tables TOML](https://toml.io/en/v1.0.0#table).

| Paramètre       | Description                                                                                                                                            |
|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `[$analyzer]` | Déclare une section de configuration pour un analyseur. Le nom suit les noms définis dans la liste des [analyseurs SAST](analyzers.md#official-analyzers). |

Exemple de configuration :

```toml
[semgrep]
...
```

Évitez de créer des sections de configuration qui modifient des règles existantes et construisent un ensemble de règles personnalisé, car ce dernier remplace complètement les règles par défaut.

### Section de configuration `[$analyzer]` {#analyzer-configuration-section}

La section `[$analyzer]` vous permet de personnaliser le comportement d'un analyseur. Les propriétés valides diffèrent selon le type de configuration que vous effectuez.

| Paramètre                 | S'applique à    | Description                                                                                                                                                                                                                                                                                                   |
|-------------------------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `[[$analyzer.ruleset]]` | Règles par défaut | Définit les modifications apportées à une règle existante.                                                                                                                                                                                                                                                                    |
| `interpolate`           | Tous           | Si la valeur est `true`, vous pouvez utiliser `$VAR` dans la configuration pour évaluer les variables d'environnement. Utilisez cette fonctionnalité avec précaution pour éviter de divulguer des secrets ou des tokens. (Par défaut : `false`)                                                                                                                           |
| `description`           | Passthroughs  | Description de l'ensemble de règles personnalisé.                                                                                                                                                                                                                                                                            |
| `targetdir`             | Passthroughs  | Le répertoire où la configuration finale doit être persistée. Si ce champ est vide, un répertoire avec un nom aléatoire est créé. Le répertoire peut contenir jusqu'à 100 Mo de fichiers. Si le job SAST s'exécute avec des privilèges d'utilisateur non root, assurez-vous que l'utilisateur dispose des permissions de lecture et d'écriture pour ce répertoire. |
| `validate`              | Passthroughs  | Si la valeur est `true`, le contenu de chaque passthrough est validé. La validation fonctionne pour les contenus `yaml`, `xml`, `json` et `toml`. Le validateur approprié est identifié en fonction de l'extension utilisée dans le paramètre `target` de la section `[[$analyzer.passthrough]]`. (Par défaut : `false`)                    |
| `timeout`               | Passthroughs  | La durée maximale consacrée à l'évaluation de la chaîne de passthroughs avant l'expiration du délai. Le délai d'expiration ne peut pas dépasser 300 secondes. (Par défaut : 60)                                                                                                                                                                          |
| `keepdefaultrules`      | Passthroughs  | Si la valeur est `true`, les règles par défaut de l'analyseur sont activées conjointement avec les passthroughs définis. (Par défaut : `false`)                                                                                                                                                                                 |

#### `interpolate` {#interpolate}

> [!warning]
> Pour réduire le risque de divulgation de secrets, utilisez cette fonctionnalité avec précaution. Lorsque `interpolate = true`, toute référence `$VAR` dans la configuration est développée par rapport à l'environnement du job CI/CD, y compris les variables CI/CD et les variables protégées exposées au job. Les valeurs développées peuvent apparaître dans la sortie de l'analyse, les artefacts ou tout autre canal dans lequel l'ensemble de règles écrit. Si le fichier de configuration est chargé depuis un emplacement distant défini par [`SAST_RULESET_GIT_REFERENCE`](#reference-the-remote-ruleset-file), l'auteur distant contrôle si `interpolate` est activé. Ne référencez que des ensembles de règles provenant de dépôts en lesquels vous avez confiance.

L'exemple ci-dessous montre une configuration qui utilise la variable d'environnement `$GITURL` pour accéder à un dépôt privé. La variable contient un nom d'utilisateur et un token (par exemple `https://user:token@url`), de sorte qu'ils ne sont pas explicitement stockés dans le fichier de configuration.

```toml
[semgrep]
  description = "My private Semgrep ruleset"
  interpolate = true

  [[semgrep.passthrough]]
    type  = "git"
    value = "$GITURL"
    ref = "main"
```

### Section `[[$analyzer.ruleset]]` {#analyzerruleset-section}

La section `[[$analyzer.ruleset]]` cible et modifie une seule règle par défaut. Vous pouvez définir une ou plusieurs de ces sections par analyseur.

| Paramètre                          | Description                                             |
|----------------------------------|---------------------------------------------------------|
| `disable`                        | Indique si la règle doit être désactivée. (Par défaut : `false`) |
| `[$analyzer.ruleset.identifier]` | Sélectionne la règle par défaut à modifier.                |
| `[$analyzer.ruleset.override]`   | Définit les remplacements pour la règle.                     |

Exemple de configuration :

```toml
[semgrep]
  [[semgrep.ruleset]]
    disable = true
    ...
```

### Section `[$analyzer.ruleset.identifier]` {#analyzerrulesetidentifier-section}

La section `[$analyzer.ruleset.identifier]` définit les identifiants de la règle par défaut que vous souhaitez modifier.

| Paramètre | Description                                           |
|---------|-------------------------------------------------------|
| `type`  | Le type d'identifiant utilisé par la règle par défaut.      |
| `value` | La valeur de l'identifiant utilisé par la règle par défaut. |

Vous pouvez rechercher les valeurs correctes pour `type` et `value` en consultant le fichier [`gl-sast-report.json`](_index.md#download-a-sast-report) produit par l'analyseur. Vous pouvez télécharger ce fichier en tant qu'artefact de job depuis le job CI de l'analyseur.

Par exemple, l'extrait ci-dessous montre un résultat d'une règle `semgrep` avec trois identifiants. Les clés `type` et `value` dans l'objet JSON correspondent aux valeurs que vous devez fournir dans cette section.

```json
...
  "vulnerabilities": [
    {
      "id": "7331a4b7093875f6eb9f6eb1755b30cc792e9fb3a08c9ce673fb0d2207d7c9c9",
      "category": "sast",
      "message": "Key Exchange without Entity Authentication",
      "description": "Audit the use of ssh.InsecureIgnoreHostKey\n",
      ...
      "identifiers": [
        {
          "type": "semgrep_id",
          "name": "gosec.G106-1",
          "value": "gosec.G106-1"
        },
        {
          "type": "cwe",
          "name": "CWE-322",
          "value": "322",
          "url": "https://cwe.mitre.org/data/definitions/322.html"
        },
        {
          "type": "gosec_rule_id",
          "name": "Gosec Rule ID G106",
          "value": "G106"
        }
      ]
    }
    ...
  ]
...
```

Exemple de configuration :

```toml
[semgrep]
  [[semgrep.ruleset]]
    [semgrep.ruleset.identifier]
      type = "semgrep_id"
      value = "gosec.G106-1
    ...
```

### Section `[$analyzer.ruleset.override]` {#analyzerrulesetoverride-section}

La section `[$analyzer.ruleset.override]` vous permet de remplacer les attributs d'une règle par défaut.

| Paramètre       | Description                                                                                         |
|---------------|-----------------------------------------------------------------------------------------------------|
| `description` | Description détaillée du problème.                                                                |
| `message`     | (Obsolète) Description du problème.                                                            |
| `name`        | Le nom de la règle.                                                                               |
| `severity`    | La gravité de la règle. Les options valides sont : `Critical`, `High`, `Medium`, `Low`, `Unknown`, `Info` |

> [!note]
> Bien que `message` soit renseigné par les analyseurs, il a été [déprécié](https://gitlab.com/gitlab-org/security-products/analyzers/report/-/blob/1d86d5f2e61dc38c775fb0490ee27a45eee4b8b3/vulnerability.go#L22) au profit de `name` et `description`.

Exemple de configuration :

```toml
[semgrep]
  [[semgrep.ruleset]]
    [semgrep.ruleset.override]
      severity = "Critical"
      name = "Command injection"
    ...
```

### Section `[[$analyzer.passthrough]]` {#analyzerpassthrough-section}

> [!note]
> Les configurations de passthrough sont disponibles uniquement pour l'[analyseur basé sur Semgrep](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep).

La section `[[$analyzer.passthrough]]` vous permet de créer une configuration personnalisée pour un analyseur. Vous pouvez définir jusqu'à 20 de ces sections par analyseur. Les passthroughs sont composés en une _chaîne de passthroughs_ qui produit une configuration complète remplaçant les règles par défaut de l'analyseur.

Les passthroughs sont évalués dans l'ordre. Les passthroughs répertoriés plus tard dans la chaîne ont une priorité plus élevée et peuvent écraser ou ajouter aux données produites par les passthroughs précédents (selon le `mode`). Cela est utile dans les cas où vous devez utiliser ou modifier une configuration existante.

La taille de la configuration générée par un seul passthrough est limitée à 10 Mo.

| Paramètre     | S'applique à     | Description                                                                                                                                                                   |
|-------------|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `type`      | Tous            | L'un des types suivants : `file`, `raw`, `git` ou `url`.                                                                                                                                        |
| `target`    | Tous            | Le fichier cible destiné à contenir les données écrites lors de l'évaluation du passthrough. Si ce champ est vide, un nom de fichier aléatoire est utilisé.                                                               |
| `mode`      | Tous            | Si `overwrite`, le fichier `target` est écrasé. Si `append`, le nouveau contenu est ajouté au fichier `target`. Le type `git` prend uniquement en charge `overwrite`. (Par défaut : `overwrite`) |
| `ref`       | `type = "git"` | Contient le nom de la branche, du tag ou du SHA à récupérer                                                                                                                      |
| `subdir`    | `type = "git"` | Utilisé pour sélectionner un sous-répertoire du dépôt Git comme source de configuration.                                                                                              |
| `value`     | Tous            | Pour les types `file`, `url` et `git`, définit l'emplacement du fichier ou du dépôt Git. Pour le type `raw`, contient la configuration en ligne.                            |
| `validator` | Tous            | Utilisé pour invoquer explicitement des validateurs (`xml`, `yaml`, `json`, `toml`) sur le fichier cible après l'évaluation d'un passthrough.                                                |

#### Types de passthroughs {#passthrough-types}

| Type   | Description                                          |
|--------|------------------------------------------------------|
| `file` | Utilisez un fichier présent dans le dépôt Git.    |
| `raw`  | Fournissez la configuration en ligne.                    |
| `git`  | Récupérez la configuration depuis un dépôt Git distant. |
| `url`  | Récupérez la configuration via HTTP.                  |

> [!warning]
> Lorsque vous utilisez le passthrough `raw` avec un extrait YAML, il est recommandé de formater toutes les indentations dans le fichier `sast-ruleset.toml` avec des espaces. La spécification YAML impose l'utilisation d'espaces plutôt que de tabulations, et l'analyseur ne parvient pas à analyser votre ensemble de règles personnalisé si l'indentation n'est pas représentée en conséquence.

## Exemples {#examples}

Les exemples suivants montrent comment personnaliser des ensembles de règles pour des scénarios courants. Consultez la section schéma pour comprendre les options de configuration utilisées dans chaque exemple.

### Remplacer toutes les règles GitLab Advanced SAST par défaut {#replace-all-default-gitlab-advanced-sast-rules}

Avec la configuration d'ensemble de règles personnalisé suivante, l'ensemble de règles par défaut de l'analyseur GitLab Advanced SAST est remplacé par un ensemble de règles personnalisé contenu dans un fichier appelé `my-gitlab-advanced-sast-rules.yml` dans le dépôt analysé.

```yaml
# my-gitlab-advanced-sast-rules.yml
---
rules:
- id: my-custom-rule
  pattern: print("Hello World")
  message: |
    Unauthorized use of Hello World.
  severity: ERROR
  languages:
  - python
```

```toml
[gitlab-advanced-sast]
  description = "My custom ruleset for Semgrep"

  [[gitlab-advanced-sast.passthrough]]
    type  = "file"
    value = "my-gitlab-advanced-sast-rules.yml"
```

### Désactiver des règles GitLab Advanced SAST par défaut spécifiques {#disable-specific-default-gitlab-advanced-sast-rules}

Dans cet exemple, des règles par défaut spécifiques sont désactivées selon les critères suivants :

- Un identifiant CWE, qui identifie une classe entière de vulnérabilités.
- Un identifiant de règle GitLab Advanced SAST, qui identifie une stratégie de détection spécifique utilisée dans GitLab Advanced SAST.
- Un identifiant de règle Semgrep associé, inclus dans les résultats GitLab Advanced SAST pour des raisons de compatibilité. Ces métadonnées supplémentaires permettent aux résultats d'être automatiquement transférés lorsque les deux analyseurs créent des résultats similaires au même emplacement.

Ces identifiants sont affichés dans les [détails de la vulnérabilité](../vulnerabilities/_index.md) de chaque vulnérabilité. Vous pouvez également voir chaque identifiant et son `type` associé dans l'[artefact de rapport SAST téléchargeable](_index.md#download-a-sast-report).

```toml
[gitlab-advanced-sast]
  [[gitlab-advanced-sast.ruleset]]
    disable = true
    [gitlab-advanced-sast.ruleset.identifier]
      type = "cwe"
      value = "89"

  [[gitlab-advanced-sast.ruleset]]
    disable = true
    [gitlab-advanced-sast.ruleset.identifier]
      type = "gitlab-advanced-sast_id"
      value = "java-spring-csrf-unrestricted-requestmapping-atomic"

  [[gitlab-advanced-sast.ruleset]]
    disable = true
    [gitlab-advanced-sast.ruleset.identifier]
      type = "semgrep_id"
      value = "java_cookie_rule-CookieHTTPOnly"
```

### Désactiver des règles par défaut spécifiques d'autres analyseurs SAST {#disable-specific-default-rules-of-other-sast-analyzers}

Avec la configuration d'ensemble de règles personnalisé suivante, les règles par défaut suivantes sont omises du rapport :

- Les règles `semgrep` avec un `semgrep_id` égal à `gosec.G106-1` ou un `cwe` égal à `322`.
- Les règles `sobelow` avec un `sobelow_rule_id` égal à `sql_injection`.
- Les règles `flawfinder` avec un `flawfinder_func_name` égal à `memcpy`.

```toml
[semgrep]
  [[semgrep.ruleset]]
    disable = true
    [semgrep.ruleset.identifier]
      type = "semgrep_id"
      value = "gosec.G106-1"

  [[semgrep.ruleset]]
    disable = true
    [semgrep.ruleset.identifier]
      type = "cwe"
      value = "322"

[sobelow]
  [[sobelow.ruleset]]
    disable = true
    [sobelow.ruleset.identifier]
      type = "sobelow_rule_id"
      value = "sql_injection"

[flawfinder]
  [[flawfinder.ruleset]]
    disable = true
    [flawfinder.ruleset.identifier]
      type = "flawfinder_func_name"
      value = "memcpy"
```

### Remplacer les métadonnées des règles par défaut {#override-default-rule-metadata}

Avec la configuration d'ensemble de règles personnalisé suivante, les vulnérabilités trouvées avec `semgrep` ayant un type `CWE` et une valeur `322` voient leur gravité remplacée par `Critical`.

```toml
[semgrep]
  [[semgrep.ruleset]]
    [semgrep.ruleset.identifier]
      type = "cwe"
      value = "322"
    [semgrep.ruleset.override]
      severity = "Critical"
```

### Remplacer ou ajouter aux règles par défaut de `semgrep` {#replace-or-add-to-the-default-rules-of-semgrep}

Avec la configuration d'ensemble de règles personnalisé suivante, l'ensemble de règles par défaut de l'analyseur `semgrep` est remplacé par un ensemble de règles personnalisé contenu dans un fichier appelé `my-semgrep-rules.yml` dans le dépôt analysé.

```yaml
# my-semgrep-rules.yml
---
rules:
- id: my-custom-rule
  pattern: print("Hello World")
  message: |
    Unauthorized use of Hello World.
  severity: ERROR
  languages:
  - python
```

```toml
[semgrep]
  description = "My custom ruleset for Semgrep"

  [[semgrep.passthrough]]
    type  = "file"
    value = "my-semgrep-rules.yml"
```

### Créer une configuration personnalisée à l'aide d'une chaîne de passthroughs pour `semgrep` {#build-a-custom-configuration-using-a-passthrough-chain-for-semgrep}

Avec la configuration d'ensemble de règles personnalisé suivante, l'ensemble de règles par défaut de l'analyseur `semgrep` est remplacé par un ensemble de règles personnalisé produit en évaluant une chaîne de quatre passthroughs. Chaque passthrough produit un fichier qui est écrit dans le répertoire `/sgrules` du conteneur. Un `timeout` de 60 secondes est défini au cas où des remotes Git ne répondent pas.

Différents types de passthroughs sont illustrés dans cet exemple :

- Deux passthroughs `git`, le premier récupérant la branche `develop` depuis le dépôt Git `myrules`, et le second récupérant la révision `97f7686` depuis le dépôt `sast-rules`, en ne prenant en compte que les fichiers dans le sous-répertoire `go`.
  - L'entrée `sast-rules` a une priorité plus élevée car elle apparaît plus tard dans la configuration.
  - En cas de conflit de nom de fichier entre les deux extractions, les fichiers du dépôt `sast-rules` écrasent les fichiers du dépôt `myrules`.
- Un passthrough `raw`, qui écrit sa `value` dans `/sgrules/insecure.yml`.
- Un passthrough `url`, qui récupère une configuration hébergée à une URL et l'écrit dans `/sgrules/gosec.yml`.

Ensuite, Semgrep est invoqué avec la configuration finale située sous `/sgrules`.

```toml
[semgrep]
  description = "My custom ruleset for Semgrep"
  targetdir = "/sgrules"
  timeout = 60

  [[semgrep.passthrough]]
    type  = "git"
    value = "https://gitlab.com/user/myrules.git"
    ref = "develop"

  [[semgrep.passthrough]]
    type  = "git"
    value = "https://gitlab.com/gitlab-org/secure/gsoc-sast-vulnerability-rules/playground/sast-rules.git"
    ref = "97f7686db058e2141c0806a477c1e04835c4f395"
    subdir = "go"

  [[semgrep.passthrough]]
    type  = "raw"
    target = "insecure.yml"
    value = """
rules:
- id: "insecure"
  patterns:
    - pattern: "func insecure() {...}"
  message: |
    Insecure function insecure detected
  metadata:
    cwe: "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
  severity: "ERROR"
  languages:
    - "go"
"""

  [[semgrep.passthrough]]
    type  = "url"
    value = "https://semgrep.dev/c/p/gosec"
    target = "gosec.yml"
```

### Configurer le mode pour les passthroughs dans une chaîne {#configure-the-mode-for-passthroughs-in-a-chain}

Vous pouvez choisir comment gérer les conflits de noms de fichiers qui surviennent entre les passthroughs dans une chaîne. Le comportement par défaut consiste à écraser les fichiers existants portant le même nom, mais vous pouvez choisir `mode = append` à la place pour ajouter le contenu des fichiers ultérieurs aux précédents.

Vous pouvez utiliser le mode `append` uniquement pour les types de passthrough `file`, `url` et `raw`.

Avec la configuration d'ensemble de règles personnalisé suivante, deux passthroughs `raw` sont utilisés pour assembler itérativement le fichier `/sgrules/my-rules.yml`, qui est ensuite fourni à Semgrep comme ensemble de règles. Chaque passthrough ajoute une seule règle à l'ensemble de règles. Le premier passthrough est responsable de l'initialisation de l'objet de niveau supérieur `rules`, conformément à la [syntaxe des règles Semgrep](https://semgrep.dev/docs/writing-rules/rule-syntax).

```toml
[semgrep]
  description = "My custom ruleset for Semgrep"
  targetdir = "/sgrules"
  validate = true

  [[semgrep.passthrough]]
    type  = "raw"
    target = "my-rules.yml"
    value = """
rules:
- id: "insecure"
  patterns:
    - pattern: "func insecure() {...}"
  message: |
    Insecure function 'insecure' detected
  metadata:
    cwe: "..."
  severity: "ERROR"
  languages:
    - "go"
"""

  [[semgrep.passthrough]]
    type  = "raw"
    mode  = "append"
    target = "my-rules.yml"
    value = """
- id: "secret"
  patterns:
    - pattern-either:
        - pattern: '$MASK = "..."'
    - metavariable-regex:
        metavariable: "$MASK"
        regex: "(password|pass|passwd|pwd|secret|token)"
  message: |
    Use of hard-coded password
  metadata:
    cwe: "..."
  severity: "ERROR"
  languages:
    - "go"
"""
```

```yaml
# /sgrules/my-rules.yml
rules:
- id: "insecure"
  patterns:
    - pattern: "func insecure() {...}"
  message: |
    Insecure function 'insecure' detected
  metadata:
    cwe: "..."
  severity: "ERROR"
  languages:
    - "go"
- id: "secret"
  patterns:
    - pattern-either:
        - pattern: '$MASK = "..."'
    - metavariable-regex:
        metavariable: "$MASK"
        regex: "(password|pass|passwd|pwd|secret|token)"
  message: |
    Use of hard-coded password
  metadata:
    cwe: "..."
  severity: "ERROR"
  languages:
    - "go"
```

### Spécifier une configuration distante privée {#specify-a-private-remote-configuration}

L'exemple suivant active SAST et utilise un fichier de personnalisation d'ensemble de règles partagé :

- Le fichier est téléchargé depuis un projet privé nécessitant une authentification. Cet exemple utilise un [token d'accès de groupe](../../group/settings/group_access_tokens.md) stocké de manière sécurisée dans une variable CI/CD.
- Le fichier est extrait à un SHA de commit Git spécifique plutôt que sur la branche par défaut.

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  SAST_RULESET_GIT_REFERENCE: "oauth2:$GROUP_ACCESS_TOKEN@gitlab.com/example-group/example-ruleset-project@c8ea7e3ff126987fb4819cc35f2310755511c2ab"
```

### Projets de démonstration {#demonstration-projects}

Parcourez les [projets de démonstration](https://gitlab.com/gitlab-org/security-products/demos/analyzer-configurations) qui illustrent certaines de ces options de configuration.

Bon nombre de ces projets illustrent l'utilisation d'ensembles de règles distants pour remplacer ou désactiver des règles, et sont regroupés par analyseur concerné.

Vous pouvez également regarder des démonstrations vidéo sur la configuration d'ensembles de règles distants :

- [Analyseur IaC avec un ensemble de règles distant](https://youtu.be/VzJFyaKpA-8)
