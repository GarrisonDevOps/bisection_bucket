---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 'Tutoriel : générer une nomenclature logicielle avec le registre de paquets GitLab'
---

Ce tutoriel vous montre comment générer une nomenclature logicielle (SBOM) au format CycloneDX avec un pipeline CI/CD. Le pipeline que vous allez créer collecte les paquets de plusieurs projets au sein d'un groupe, vous offrant ainsi une vue complète des dépendances des projets liés.

Vous allez créer un environnement virtuel Python pour suivre ce tutoriel, mais vous pouvez appliquer la même approche à d'autres types de paquets pris en charge.

## Qu'est-ce qu'une nomenclature logicielle ? {#what-is-a-software-bill-of-materials}

Une SBOM est un inventaire lisible par machine de tous les composants logiciels qui constituent un produit logiciel. La SBOM peut inclure :

- Les dépendances directes et indirectes
- Les composants et licences open source
- Les versions des paquets et leurs origines

Une organisation souhaitant utiliser un produit logiciel peut exiger une SBOM pour évaluer la sécurité du produit avant de l'adopter.

Si vous connaissez le registre de paquets GitLab, vous vous demandez peut-être quelle est la différence entre une SBOM et une [liste de dépendances](../../application_security/dependency_list/_index.md). Le tableau suivant met en évidence les principales différences :

| Différences   | Liste de dépendances                                               | SBOM |
|---------------|---------------------------------------------------------------|------|
| Portée     | Affiche les dépendances pour des projets ou des groupes individuels.         | Crée un inventaire de tous les paquets publiés au sein de votre groupe. |
| Direction | Suit ce dont vos projets dépendent (dépendances entrantes).  | Suit ce que votre groupe publie (paquets sortants). |
| Couverture  | Basé sur les manifestes de paquets, comme `package.json` ou `pom.xml`. | Couvre les artefacts réellement publiés dans votre registre de paquets. |

## Qu'est-ce que CycloneDX ? {#what-is-cyclonedx}

CycloneDX est un format léger et standardisé pour créer des SBOM. CycloneDX fournit un schéma bien défini qui aide les organisations à :

- Documenter les composants logiciels et leurs relations.
- Suivre les vulnérabilités dans la chaîne d'approvisionnement logicielle.
- Vérifier la conformité des licences pour les dépendances open source.
- Établir un format SBOM cohérent et lisible par machine.

CycloneDX prend en charge plusieurs formats de sortie, notamment JSON, XML et Protocol Buffers, ce qui le rend polyvalent pour différents besoins d'intégration. La spécification est conçue pour être à la fois complète et efficace, couvrant tout ce qui va de l'identification de base des composants aux métadonnées détaillées sur la provenance des logiciels.

## Avant de commencer {#before-you-begin}

Pour suivre ce tutoriel, vous avez besoin :

- D'un groupe avec le rôle Maintainer ou Owner.
- D'un accès à GitLab CI/CD.
- D'un [GitLab Runner](../../../ci/runners/_index.md#runner-categories) configuré si vous utilisez une instance GitLab Self-Managed. Si vous utilisez GitLab.com, vous pouvez ignorer cette exigence.
- Facultatif. D'un [jeton de déploiement de groupe](../../project/deploy_tokens/_index.md) pour authentifier les requêtes auprès du registre de paquets.

## Étapes {#steps}

Ce tutoriel comprend deux ensembles d'étapes à effectuer :

- Configurer un pipeline CI/CD qui génère une SBOM au format CycloneDX
- Accéder à la SBOM générée et aux fichiers de statistiques de paquets, et travailler avec ces fichiers

Voici un aperçu de ce que vous allez faire :

1. [Ajouter la configuration de base du pipeline](#add-the-base-pipeline-configuration).
1. [Configurer l'étape `prepare`](#configure-the-prepare-stage).
1. [Configurer l'étape `collect`](#configure-the-collect-stage).
1. [Configurer l'étape `aggregate`](#configure-the-aggregate-stage).
1. [Configurer l'étape `publish`](#configure-the-publish-stage).
1. [Accéder aux fichiers SBOM et de statistiques générés](#access-the-generated-files).

> [!note]
> Avant d'implémenter cette solution, tenez compte des points suivants :
>
> - Les dépendances des paquets ne sont pas résolues (seuls les paquets directs sont listés).
> - Les versions des paquets sont incluses, mais ne sont pas analysées pour détecter les vulnérabilités.

### Ajouter la configuration de base du pipeline {#add-the-base-pipeline-configuration}

Commencez par configurer l'image de base qui définit les variables et les étapes utilisées tout au long du pipeline.

Dans les sections suivantes, vous allez enrichir le pipeline en ajoutant la configuration pour chaque étape.

Dans votre projet :

1. Créez un fichier `.gitlab-ci.yml`.
1. Dans le fichier, ajoutez la configuration de base suivante :

   ```yaml
   # Base image for all jobs
   image: alpine:latest

   variables:
     SBOM_OUTPUT_DIR: "sbom-output"
     SBOM_FORMAT: "cyclonedx"
     OUTPUT_TYPE: "json"
     GROUP_PATH: ${CI_PROJECT_NAMESPACE}

   before_script:
     - apk add --no-cache curl jq ca-certificates

   stages:
     - prepare
     - collect
     - aggregate
     - publish
   ```

Cette configuration :

- Utilise Alpine Linux pour sa faible empreinte et son démarrage rapide des jobs
- Prend en charge les jetons de déploiement de groupe pour l'authentification
- Installe `curl` pour les requêtes API, `jq` pour le traitement JSON, et `ca-certificates` pour garantir des connexions HTTPS sécurisées
- Stocke tous les résultats dans le répertoire `sbom-output`
- Génère une SBOM au format CycloneDX JSON

### Configurer l'étape `prepare` {#configure-the-prepare-stage}

L'étape `prepare` configure un environnement Python et installe les dépendances requises.

Dans votre fichier `.gitlab-ci.yml`, ajoutez la configuration suivante :

```yaml
# Set up Python virtual environment and install required packages
prepare_environment:
  stage: prepare
  script: |
    mkdir -p ${SBOM_OUTPUT_DIR}
    apk add --no-cache python3 py3-pip py3-virtualenv
    python3 -m venv venv
    . venv/bin/activate
    pip3 install cyclonedx-bom
  artifacts:
    paths:
      - ${SBOM_OUTPUT_DIR}/
      - venv/
    expire_in: 1 week
```

Cette étape :

- Crée un environnement virtuel Python pour l'isolation
- Installe la bibliothèque CycloneDX pour la génération de SBOM
- Crée le répertoire de sortie pour les artefacts
- Conserve l'environnement virtuel pour les étapes ultérieures
- Définit une expiration d'une semaine pour les artefacts afin de gérer le stockage

### Configurer l'étape `collect` {#configure-the-collect-stage}

L'étape `collect` collecte les informations sur les paquets depuis le registre de paquets de votre groupe.

Dans votre fichier `.gitlab-ci.yml`, ajoutez la configuration suivante :

```yaml
# Collect package information and versions from GitLab registry
collect_group_packages:
  stage: collect
  script: |
    mkdir -p "${SBOM_OUTPUT_DIR}"
    echo "[]" > "${SBOM_OUTPUT_DIR}/packages.json"

    # Resolve the auth header at runtime: use the group deploy token if set,
    # otherwise fall back to the CI job token.
    if [ -n "${GROUP_DEPLOY_TOKEN:-}" ]; then
      AUTH="Deploy-Token: ${GROUP_DEPLOY_TOKEN}"
    else
      AUTH="JOB-TOKEN: ${CI_JOB_TOKEN}"
    fi

    GROUP_PATH_ENCODED=$(echo "${GROUP_PATH}" | sed 's|/|%2F|g')
    PACKAGES_URL="${CI_API_V4_URL}/groups/${GROUP_PATH_ENCODED}/packages"

    # Optional exclusion list - you can add package types you want to exclude
    # EXCLUDE_TYPES="terraform npm"

    page=1
    while true; do
      # Fetch all packages without specifying type, with pagination
      http_status=$(curl --silent \
                      --output /tmp/api_response.json \
                      --write-out "%{http_code}" \
                      --header "$AUTH" \
                      "${PACKAGES_URL}?per_page=100&page=${page}")
      response=$(cat /tmp/api_response.json)

      if [ "$http_status" -lt 200 ] || [ "$http_status" -ge 300 ]; then
        echo "ERROR: HTTP ${http_status}"; echo "$response" | jq . 2>/dev/null || echo "$response"; exit 1
      fi

      response_type=$(echo "$response" | jq -r 'type' 2>/dev/null || echo "invalid")
      if [ "$response_type" != "array" ]; then
        echo "ERROR: Expected array, got ${response_type}"; echo "$response" | jq . 2>/dev/null || echo "$response"; exit 1
      fi

      count=$(echo "$response" | jq '. | length')
      [ "$count" -eq 0 ] && break

      # Filter packages if EXCLUDE_TYPES is set, using exact type matching
      if [ -n "${EXCLUDE_TYPES:-}" ]; then
        response=$(echo "$response" | jq --argjson types \
          "$(echo "${EXCLUDE_TYPES}" | tr ' ' '\n' | jq -R . | jq -s .)" \
          '[.[] | select(.package_type as $t | $types | any(. == $t) | not)]')
        count=$(echo "$response" | jq '. | length')
      fi

      # Merge this page of results with existing data
      jq -s '.[0] + .[1]' "${SBOM_OUTPUT_DIR}/packages.json" <(echo "$response") > "${SBOM_OUTPUT_DIR}/packages.tmp.json"
      mv "${SBOM_OUTPUT_DIR}/packages.tmp.json" "${SBOM_OUTPUT_DIR}/packages.json"

      # Move to next page if we got a full page of results
      [ "$count" -lt 100 ] && break
      page=$((page + 1))
    done
  artifacts:
    paths:
      - ${SBOM_OUTPUT_DIR}/
    expire_in: 1 week
  dependencies:
    - prepare_environment
```

Cette étape :

- Résout l'en-tête d'authentification à l'exécution en utilisant un jeton de déploiement de groupe s'il est disponible, ou le jeton de job CI/CD sinon
- Effectue un seul appel API pour récupérer tous les types de paquets à la fois (au lieu d'appels séparés par type)
- Prend en charge une liste d'exclusion facultative qui filtre les types de paquets par correspondance exacte
- Implémente la pagination pour gérer les groupes comportant de nombreux paquets (100 par page)
- Encode le chemin du groupe en URL pour gérer correctement les sous-groupes
- Vérifie le code de statut HTTP et le type de réponse, et arrête le job en cas d'erreur

### Configurer l'étape `aggregate` {#configure-the-aggregate-stage}

L'étape `aggregate` traite les données collectées et génère la SBOM.

Dans votre fichier `.gitlab-ci.yml`, ajoutez la configuration suivante :

```yaml
# Generate SBOM by aggregating package data
aggregate_sboms:
  stage: aggregate
  before_script:
    - apk add --no-cache python3 py3-virtualenv
    - . venv/bin/activate
  script: |
    cat > process_sbom.py << 'EOL'
    import json
    import os
    from datetime import datetime
    from urllib.parse import quote

    # Map GitLab package types to valid PURL types. Defaults to "generic".
    PURL_TYPE_MAP = {
        "pypi": "pypi", "npm": "npm", "maven": "maven", "nuget": "nuget",
        "composer": "composer", "conan": "conan", "conda": "conda",
        "golang": "golang", "helm": "helm", "rubygems": "gem",
        "generic": "generic", "debian": "deb", "rpm": "rpm", "terraform": "terraform",
    }

    def make_purl(package_type, name, version):
        """Build a spec-compliant PURL with percent-encoded name and version."""
        purl_type = PURL_TYPE_MAP.get(package_type, "generic")
        # Maven names use a "/" namespace separator that the PURL spec requires,
        # so keep it unencoded for that type.
        safe_name = quote(name, safe='/') if purl_type == "maven" else quote(name, safe='')
        safe_version = quote(version, safe='')
        return f"pkg:{purl_type}/{safe_name}@{safe_version}"

    def analyze_version_history(packages_file):
        """Process version information by aggregating packages with same name and type"""
        version_history = {}
        package_versions = {}  # Dict to group packages by name and type

        try:
            with open(packages_file, 'r') as f:
                packages = json.load(f)
                if not isinstance(packages, list):
                    return version_history

                # First, group packages by name and type
                for package in packages:
                    key = f"{package.get('name')}:{package.get('package_type')}"
                    if key not in package_versions:
                        package_versions[key] = []

                    package_versions[key].append({
                        'id': package.get('id'),
                        'version': package.get('version', 'unknown'),
                        'created_at': package.get('created_at')
                    })

                # Then process each group to create version history
                for package_key, versions in package_versions.items():
                    # Sort versions by creation date, newest first
                    versions.sort(key=lambda x: x.get('created_at', ''), reverse=True)

                    # Use the first package's ID as the key (newest version)
                    if versions:
                        package_id = str(versions[0]['id'])
                        version_history[package_id] = {
                            'versions': [v['version'] for v in versions],
                            'latest_version': versions[0]['version'] if versions else None,
                            'version_count': len(versions),
                            'first_published': min((v.get('created_at') for v in versions if v.get('created_at')), default=None),
                            'last_updated': max((v.get('created_at') for v in versions if v.get('created_at')), default=None)
                        }
        except Exception as e:
            print(f"Error processing version history: {e}")
        return version_history

    def merge_package_data(package_file):
        """Combine package data and generate component list"""
        merged_components = {}
        package_stats = {
            'total_packages': 0,
            'package_types': {}
        }

        try:
            with open(package_file, 'r') as f:
                packages = json.load(f)
                if not isinstance(packages, list):
                    return [], package_stats

                for package in packages:
                    package_stats['total_packages'] += 1
                    pkg_type = package.get('package_type', 'unknown')
                    package_stats['package_types'][pkg_type] = package_stats['package_types'].get(pkg_type, 0) + 1

                    version = package.get('version', 'unknown')
                    component = {
                        'type': 'library',
                        'name': package['name'],
                        'version': version,
                        'purl': make_purl(pkg_type, package['name'], version),
                        'package_type': pkg_type,
                        'properties': [{
                            'name': 'registry_url',
                            'value': package.get('_links', {}).get('web_path', '')
                        }]
                    }

                    key = f"{component['name']}:{component['version']}"
                    if key not in merged_components:
                        merged_components[key] = component
        except Exception as e:
            print(f"Error merging package data: {e}")
            return [], package_stats

        return list(merged_components.values()), package_stats

    # Main processing
    version_history = analyze_version_history(f"{os.environ['SBOM_OUTPUT_DIR']}/packages.json")
    components, stats = merge_package_data(f"{os.environ['SBOM_OUTPUT_DIR']}/packages.json")
    stats['version_history'] = version_history

    # Create final SBOM document
    sbom = {
        "bomFormat": os.environ['SBOM_FORMAT'],
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "tools": [{
                "vendor": "GitLab",
                "name": "Package Registry SBOM Generator",
                "version": "1.0.0"
            }],
            "properties": [{
                "name": "package_stats",
                "value": json.dumps(stats)
            }]
        },
        "components": components
    }

    # Write results to files
    with open(f"{os.environ['SBOM_OUTPUT_DIR']}/merged_sbom.{os.environ['OUTPUT_TYPE']}", 'w') as f:
        json.dump(sbom, f, indent=2)

    with open(f"{os.environ['SBOM_OUTPUT_DIR']}/package_stats.json", 'w') as f:
        json.dump(stats, f, indent=2)
    EOL

    python3 process_sbom.py
  artifacts:
    paths:
      - ${SBOM_OUTPUT_DIR}/
    expire_in: 1 week
  dependencies:
    - prepare_environment
    - collect_group_packages
```

Cette étape :

- Utilise une analyse optimisée de l'historique des versions qui fonctionne directement avec le fichier `packages.json`
- Regroupe les paquets par nom et type pour identifier les différentes versions d'un même paquet
- Crée une SBOM conforme à CycloneDX au format JSON
- Calcule les statistiques des paquets, notamment :
  - Le nombre total de paquets par type
  - L'historique des versions pour chaque paquet
  - Les dates de première publication et de dernière mise à jour
- Réutilise l'artefact d'environnement virtuel de l'étape `prepare` au lieu d'en créer un nouveau
- Génère des URL de paquet (`purl`) conformes à la spécification pour chaque composant, avec le type de paquet mappé vers un type PURL valide et le nom et la version encodés en pourcentage
- Gère les données manquantes ou invalides de manière robuste avec une gestion appropriée des exceptions
- Crée à la fois la SBOM et un fichier de statistiques séparé

### Configurer l'étape `publish` {#configure-the-publish-stage}

L'étape `publish` charge la SBOM générée et le fichier de statistiques vers GitLab.

Dans votre fichier `.gitlab-ci.yml`, ajoutez la configuration suivante :

```yaml
# Publish SBOM files to GitLab package registry
publish_sbom:
  stage: publish
  script: |
    # Resolve the auth header at runtime, as in the collect stage.
    if [ -n "${GROUP_DEPLOY_TOKEN:-}" ]; then
      AUTH="Deploy-Token: ${GROUP_DEPLOY_TOKEN}"
    else
      AUTH="JOB-TOKEN: ${CI_JOB_TOKEN}"
    fi

    # Upload generated files
    curl --header "$AUTH" \
         --upload-file "${SBOM_OUTPUT_DIR}/merged_sbom.${OUTPUT_TYPE}" \
         "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/sbom/${CI_COMMIT_SHA}/merged_sbom.${OUTPUT_TYPE}"

    curl --header "$AUTH" \
         --upload-file "${SBOM_OUTPUT_DIR}/package_stats.json" \
         "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/sbom/${CI_COMMIT_SHA}/package_stats.json"
  dependencies:
    - aggregate_sboms
```

Cette étape :

- Publie la SBOM et les fichiers de statistiques dans le registre de paquets de votre projet
- Utilise le type de paquet générique pour le stockage
- Utilise le SHA du commit comme version du paquet pour la traçabilité

Le fichier SBOM enregistre déjà l'horodatage de génération dans `metadata.timestamp`, et le pipeline sauvegarde les statistiques des paquets dans `package_stats.json`.

## Accéder aux fichiers générés {#access-the-generated-files}

Une fois le pipeline terminé, il génère ces fichiers :

- `merged_sbom.json` : la SBOM complète au format CycloneDX
- `package_stats.json` : statistiques sur vos paquets

Pour accéder aux fichiers générés :

1. Dans votre projet, sélectionnez **Déployer** > **Registre de paquets**.
1. Trouvez le paquet nommé `sbom`.
1. Téléchargez la SBOM et les fichiers de statistiques.

### Utilisation du fichier SBOM {#using-the-sbom-file}

Le fichier SBOM est conforme à la [spécification JSON CycloneDX 1.4](https://cyclonedx.org/docs/1.4/json/) et fournit des détails sur les paquets publiés, les versions des paquets et les artefacts présents dans le registre de paquets de votre groupe.

Vous pouvez également utiliser le fichier SBOM à des fins de conformité et d'audit, notamment pour :

- Générer des rapports sur les paquets publiés
- Documenter le contenu du registre de paquets de votre groupe
- Suivre l'activité de publication au fil du temps

Lorsque vous travaillez avec des fichiers CycloneDX, envisagez d'utiliser les outils suivants :

- [OWASP Dependency-Track](https://dependencytrack.org/)
- [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli)
- [OWASP CycloneDX Sunshine](https://cyclonedx.github.io/Sunshine/)
- [Outils d'analyse SBOM](https://cyclonedx.org/tool-center/)

### Utilisation du fichier de statistiques {#using-the-statistics-file}

Le fichier de statistiques fournit des analyses et un suivi de l'activité du registre de paquets.

Par exemple, pour analyser votre registre de paquets, vous pouvez :

- Afficher le nombre total de paquets publiés par type.
- Consulter le nombre de versions pour chaque paquet.
- Suivre les dates de première publication et de dernière mise à jour.

Pour suivre l'activité du registre de paquets, vous pouvez :

- Surveiller les tendances de publication des paquets.
- Identifier les paquets mis à jour le plus fréquemment.
- Suivre la croissance du registre de paquets au fil du temps.

Vous pouvez utiliser un outil CLI tel que `jq` avec le fichier de statistiques pour générer des analyses ou des informations d'activité dans un format JSON lisible.

Le bloc de code suivant liste plusieurs exemples de commandes `jq` que vous pouvez exécuter sur le fichier de statistiques à des fins d'analyse générale ou de reporting :

```shell
# Get total package count in registry
jq '.total_packages' package_stats.json

# List package types and their counts
jq '.package_types' package_stats.json

# Find packages with most versions published
jq '.version_history | to_entries | sort_by(.value.version_count) | reverse | .[0:5]' package_stats.json
```

## Planification du pipeline {#pipeline-scheduling}

Si vous mettez fréquemment à jour votre registre de paquets, vous devez mettre à jour votre SBOM en conséquence. Vous pouvez configurer la planification de pipeline pour générer une SBOM mise à jour en fonction de votre activité de publication.

Tenez compte des recommandations suivantes :

- Mises à jour quotidiennes : recommandé si vous publiez des paquets fréquemment ou si vous avez besoin de rapports à jour
- Mises à jour hebdomadaires : adapté à la plupart des équipes avec une activité de publication de paquets modérée
- Mises à jour mensuelles : suffisant pour les groupes avec des mises à jour de paquets peu fréquentes

Pour planifier le pipeline :

1. Dans votre projet, accédez à **Version** > **Planifications de pipeline**.
1. Sélectionnez **Créer une nouvelle planification de pipeline** et remplissez le formulaire :
   - Dans la liste déroulante **Fuseau horaire Cron**, sélectionnez un fuseau horaire.
   - Sélectionnez un **Schéma de l'intervalle**, ou ajoutez un modèle **Personnalisé** en utilisant la [syntaxe cron](../../../ci/pipelines/schedules.md).
   - Sélectionnez la branche ou le tag pour le pipeline.
   - Sous **Variables**, saisissez un nombre quelconque de variables CI/CD pour la planification.
1. Sélectionnez **Créer une planification du pipeline**.

## Dépannage {#troubleshooting}

Vous pourriez rencontrer les problèmes suivants lors de ce tutoriel.

### Erreurs d'authentification {#authentication-errors}

Si vous rencontrez des erreurs d'authentification :

- Vérifiez les permissions de votre jeton de déploiement de groupe.
- Assurez-vous que le jeton dispose des portées `read_package_registry` et `write_package_registry`.
- Vérifiez que le jeton n'a pas expiré.

### Types de paquets manquants {#missing-package-types}

Si des types de paquets sont manquants :

- Assurez-vous que votre [jeton de déploiement a accès](../../project/deploy_tokens/_index.md#pull-packages-from-a-package-registry) à tous les types de paquets.
- Vérifiez si le type de paquet est activé dans les paramètres de votre groupe.

### Problèmes de mémoire dans l'étape `aggregate` {#memory-issues-in-the-aggregate-stage}

Si vous rencontrez des problèmes de mémoire :

- Utilisez un runner avec davantage de mémoire.
- Traitez moins de paquets à la fois en filtrant les types de paquets.

### Recommandations en matière de ressources {#resource-recommendations}

Pour des performances optimales :

- Utilisez des runners avec au moins 2 Go de RAM.
- Prévoyez 5 à 10 minutes par tranche de 1 000 paquets.
- Augmentez le délai d'expiration du job pour les groupes comportant de nombreux paquets.

### Obtenir de l'aide {#getting-help}

Si vous rencontrez d'autres problèmes :

- Consultez les job logs pour identifier les messages d'erreur spécifiques.
- Vérifiez l'accès à l'API en utilisant directement des commandes `curl`.
- Testez d'abord avec un sous-ensemble plus restreint de types de paquets.
