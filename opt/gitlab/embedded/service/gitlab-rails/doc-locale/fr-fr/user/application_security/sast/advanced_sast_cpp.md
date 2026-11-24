---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Configuration avancée de SAST C/C++
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/18368) en version [bêta](../../../policy/development_stages_support.md#beta) dans GitLab 18.6.
- [Disponibilité générale](https://gitlab.com/groups/gitlab-org/-/work_items/18369) dans GitLab 18.8.

{{< /history >}}

## Activer l'analyse GitLab Advanced SAST C/C++ {#turn-on-gitlab-advanced-sast-cc-analysis}

Prérequis :

- [Activer GitLab Advanced SAST](gitlab_advanced_sast.md#turn-on-gitlab-advanced-sast).
- [Base de données de compilation](#compilation-database)

Pour activer l'analyse GitLab Advanced SAST C/C++ dans votre projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez à **Compilation** > Éditeur de **pipeline**.
1. Ajoutez l'analyse C/C++ à la configuration de votre job SAST. Les instructions ici supposent que la base de données de compilation est nommée `compile_commands.json`.

   - Si vous utilisez le modèle CI/CD, ajoutez à votre configuration les variables CI/CD suivantes après l'instruction `include:` :

     ```yaml
     include:
       - template: Jobs/SAST.gitlab-ci.yml

     variables:
       GITLAB_ADVANCED_SAST_CPP_ENABLED: "true"
       SAST_COMPILATION_DATABASE: "compile_commands.json"
     ```

   - Si vous utilisez le composant CI/CD, ajoutez à votre configuration le paramètre d'entrée et la variable CI/CD suivants :

     ```yaml
     include:
     - component: gitlab.com/components/sast/sast@main
         inputs:
           run_advanced_sast_cpp: "true"

     variables:
       SAST_COMPILATION_DATABASE: "compile_commands.json"
     ```

1. Sélectionnez l'onglet **Valider**, puis sélectionnez **Valider le pipeline**.

   Le message **Simulation terminée avec succès** confirme que le fichier est valide.
1. Sélectionnez l'onglet **Éditer**.
1. Remplissez les champs :
   - Message de commit.
   - Branche. Par exemple, `add-sast`.
1. Cochez la case **Lancer une nouvelle merge request avec ces modifications**, puis sélectionnez **Valider les modifications**.

   La page de la merge request s'ouvre.
1. Remplissez les champs selon votre workflow standard, puis sélectionnez **Créer une requête de fusion**.
1. Examinez et modifiez la merge request selon votre procédure habituelle, puis sélectionnez **Fusionner**.

## Base de données de compilation {#compilation-database}

L'analyseur GitLab Advanced SAST CPP nécessite une base de données de compilation (CDB) pour analyser correctement les fichiers sources.

Une CDB est un fichier JSON (`compile_commands.json`) qui contient une entrée pour chaque unité de traduction. Chaque entrée spécifie généralement les éléments suivants :

- La commande du compilateur utilisée pour construire le fichier
- Les indicateurs du compilateur et les chemins d'inclusion
- Le répertoire de travail où la compilation est effectuée

La CDB permet à l'analyseur de reproduire l'environnement de build exact, garantissant ainsi une analyse syntaxique et sémantique précise.

Pour utiliser GitLab Advanced SAST CPP, vous devez créer une CDB et la fournir à l'analyseur.

### Créer une CDB {#create-a-cdb}

La façon dont vous générez une CDB dépend de votre système de build. Voici quelques exemples courants.

#### Exemple : CMake {#example-cmake}

[CMake](https://cmake.org/) peut générer une CDB directement avec le paramètre `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` ajouté à un appel `cmake` :

```shell
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

Cette option configure le projet et produit un fichier `compile_commands.json` dans le dossier `build`, qui enregistre les commandes du compilateur pour chaque fichier source.

L'analyseur GitLab Advanced SAST CPP s'appuie sur ce fichier pour reproduire fidèlement l'environnement de build.

Exportez le fichier `compile_commands.json` généré en tant qu'[artefact de job](../../../ci/jobs/job_artifacts.md) dans l'exemple de job de build suivant :

```yaml
<YOUR-BUILD-JOB-NAME>:
  image: ubuntu:24.04
  before_script:
    - apt update -qq && apt install -y -qq cmake build-essential
  script:
    - mkdir -p build
    - cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    - make -j$(nproc)
  artifacts:
    paths:
      - build/compile_commands.json # Pass the CDB file to the gitlab-advanced-sast-cpp job
```

#### Exemples pour différents systèmes de build {#examples-for-various-build-systems}

Vous pouvez également trouver des exemples complets de création d'une CDB et d'exécution de GitLab Advanced SAST CPP avec différents systèmes de build :

- [Exemple CMake](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/1)
- [Exemple Meson](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/2)
- [Exemple compiledb](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/5)
- [Exemple compiledb-go](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/7)
- [Exemple Make + Bear](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/4)
- [Exemple Ninja + Bear](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/3)
- [Exemple Bazel](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/8)

### Fournir la CDB à l'analyseur {#provide-the-cdb-to-the-analyzer}

Indiquez à l'analyseur GitLab Advanced SAST CPP où trouver la CDB avec la variable `SAST_COMPILATION_DATABASE` :

```yaml
variables:
  SAST_COMPILATION_DATABASE: YOUR_COMPILATION_DATABASE.json
```

Si `SAST_COMPILATION_DATABASE` n'est pas spécifié, l'analyseur GitLab Advanced SAST CPP utilise par défaut un fichier nommé `compile_commands.json` situé dans le répertoire racine du projet.

Le job de build qui génère le fichier `compile_commands.json` doit l'exporter en tant qu'[artefact de job](../../../ci/jobs/job_artifacts.md) pour que le job `gitlab-advanced-sast-cpp` puisse le consommer :

```yaml
variables:
  SAST_COMPILATION_DATABASE: build/compile_commands.json

<YOUR-BUILD-JOB-NAME>:
  image: ubuntu:24.04
  before_script:
    - apt update -qq && apt install -y -qq cmake build-essential
  script:
    - mkdir -p build
    - cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    - make -j$(nproc)
  artifacts:
    paths:
      - build/compile_commands.json # Pass the CDB file to the gitlab-advanced-sast-cpp job
```

Vous pouvez également consulter [la mise en cache de la CDB](#caching-a-cdb).

### Optimiser le temps d'exécution de l'analyse {#optimize-analysis-runtime}

Pour optimiser le temps d'exécution de l'analyse du code C/C++, vous pouvez exécuter l'analyse en parallèle en divisant la CDB en plusieurs fragments.

Le [dépôt `GitLab Advanced SAST CPP`](https://gitlab.com/gitlab-org/security-products/demos/sast/gitlab-advanced-sast-cpp-templates/-/blob/main/templates/scripts.yml) fournit des scripts d'aide pour diviser la CDB et exécuter l'analyse en parallèle.

Pour exécuter l'analyse de code C/C++ en parallèle :

1. Incluez les scripts :

   ```yaml
   include:
     - project: "gitlab-org/security-products/demos/sast/gitlab-advanced-sast-cpp-templates"
       file: "templates/scripts.yml"
   ```

1. Référencez les scripts d'aide et divisez la CDB dans votre job de build :

   ```yaml
   <YOUR-BUILD-JOB-NAME>:
     script:
       - <your-script to generate the CDB>
       - !reference [.gitlab-advanced-sast-cpp-scripts]
       - split_cdb "${BUILD_DIR}" 1 4 # Split into 4 fragments
     artifacts:
       paths:
         - ${BUILD_DIR} # Pass the split CDB files to the parallelized gitlab-advanced-sast-cpp jobs
   ```

   > [!note]
   > `split_cdb` est codé en dur pour lire `${BUILD_DIR}/compile_commands.json`. Votre build doit générer la CDB à cet emplacement exact avant d'appeler `split_cdb`.

1. Exécutez les jobs d'analyse en parallèle :

   ```yaml
   gitlab-advanced-sast-cpp:
     parallel: 4
     variables:
       SAST_COMPILATION_DATABASE: "${BUILD_DIR}/compile_commands${CI_NODE_INDEX}.json"
     needs:
       - job: <YOUR-BUILD-JOB-NAME>
         artifacts: true
   ```

   - `parallel: 4` distribue l'exécution sur 4 jobs.
   - `${CI_NODE_INDEX}` (1, 2, 3, 4) sélectionne le fragment de CDB approprié.
   - `needs` garantit que les jobs d'analyse reçoivent les artefacts produits par votre job de build.

Avec cette configuration, votre job de build produit un seul fichier `compile_commands.json`. Le script `split_cdb` crée plusieurs partitions, et les jobs d'analyse s'exécutent en parallèle, chaque job traitant une partition.

## Configuration de l'ensemble de règles {#ruleset-configuration}

GitLab Advanced SAST CPP prend en charge les [ensembles de règles personnalisés](customize_rulesets.md) où une « règle » est un contrôleur GitLab Advanced SAST CPP.

Les ensembles de règles personnalisés peuvent être créés avec des [passthroughs](customize_rulesets.md#build-a-custom-configuration-using-a-passthrough-chain-for-semgrep) composés de [fichiers de configuration `CodeChecker`](https://github.com/Ericsson/codechecker/blob/master/docs/config_file.md).

La configuration des passthroughs est gérée comme suit :

- `targetDir` et `target` sont ignorés. Après le traitement des passthroughs, tous les indicateurs résultants sont transmis directement à `CodeChecker`.
- Le mode `overwrite` remplace l'intégralité de la configuration et le mode `append` ajoute des indicateurs.
- Certains indicateurs `CodeChecker` ne peuvent pas être personnalisés, notamment les indicateurs d'analyse `-o`, `--output` et les indicateurs de parsing `-o, --output, -e, --export`.
- Les éléments de configuration `server` et `store` sont ignorés.

L'exemple suivant montre comment les passthroughs de différentes sources se combinent :

Fichier `.gitlab/sast-ruleset.toml` :

```toml
[gitlab-advanced-sast-cpp]
    description = "My ruleset"

    [[gitlab-advanced-sast-cpp.passthrough]]
        # replace the GitLab default configuration with my own
        mode  = "overwrite"
        type  = "url"
        value = "https://example.com/gitlab-advanced-sast-cpp.yaml"

    [[gitlab-advanced-sast-cpp.passthrough]]
        # append flags from a file in the current repository
        mode  = "append"
        type  = "file"
        value = "gitlab-advanced-sast-cpp.yml"
```

Configuration distante à l'adresse `https://example.com/gitlab-advanced-sast-cpp.yaml` :

```yaml
analyzer:
  - --disable-all
  - --enable=core.DivideZero
```

Configuration locale à l'adresse `gitlab-advanced-sast-cpp.yml` :

```yaml
analyzer:
  - --enable=core.CallAndMessage
```

La configuration combinée résultante est la suivante :

```yaml
analyzer:
  - --disable-all
  - --enable=core.DivideZero
  - --enable=core.CallAndMessage
```

## Environnement hors ligne {#offline-environment}

Pour exécuter GitLab Advanced SAST C/C++ dans un environnement hors connexion, dupliquez l'image de l'analyseur `clangsa` dans votre registre local avant d'exécuter l'analyse. L'image standard `gitlab-advanced-sast` n'inclut pas l'image `clangsa` utilisée pour les autres langages. Vous devez dupliquer cette image séparément.

Pour dupliquer l'image `clangsa`, utilisez le [modèle `Secure-Binaries.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/Secure-Binaries.gitlab-ci.yml). Ce modèle inclut un job `gitlab-advanced-sast-cpp` qui extrait et envoie l'image `clangsa` vers votre registre.

Pour plus d'informations sur la configuration d'un environnement hors connexion, consultez [les environnements hors connexion](../offline_deployments/_index.md).

## Dépannage {#troubleshooting}

### Recalage des chemins avec `cdb-rebase` {#rebasing-paths-with-cdb-rebase}

Si les chemins à l'intérieur de la CDB ne correspondent pas aux chemins de conteneur dans votre job CI/CD, ajustez-les avec [cdb-rebase](https://gitlab.com/gitlab-org/security-products/analyzers/clangsa/-/tree/main/cmd/cdb-rebase).

Installation :

```shell
go install gitlab.com/gitlab-org/secure/tools/cdb-rebase@latest
```

Le binaire est installé dans `$GOPATH/bin` ou `$HOME/go/bin`. Assurez-vous que ce répertoire figure dans votre `PATH`.

Exemple d'utilisation :

```shell
cdb-rebase compile_commands.json /host/path /container/path > rebased_compile_commands.json
```

### Corriger la CDB {#fixing-the-cdb}

Si l'environnement de build diffère de l'environnement d'analyse, la CDB générée peut nécessiter des ajustements. Vous pouvez la modifier avec [jq](https://jqlang.org), ou utiliser `cdb_append`, une fonction shell du [script d'aide prédéfini](https://gitlab.com/gitlab-org/security-products/demos/sast/gitlab-advanced-sast-cpp-templates/-/blob/main/templates/scripts.yml).

`cdb_append` ajoute des options de compilation à une CDB existante. Elle accepte :

- Premier argument : le dossier contenant `compile_commands.json`
- Arguments suivants : options de compilation supplémentaires à ajouter

Exemple en CI/CD :

```yaml
include:
  - project: "gitlab-org/security-products/demos/sast/gitlab-advanced-sast-cpp-templates"
    file: "templates/scripts.yml"

<YOUR-BUILD-JOB-NAME>:
  script:
    - !reference [.gitlab-advanced-sast-cpp-scripts]
    - <your-script to generate the CDB>
    - cdb_append "${BUILD_DIR}" "-I'$PWD/include-cache'" "-Wno-error=register"
```

### Mise en cache d'une CDB {#caching-a-cdb}

Pour accélérer le processus de compilation et d'analyse, la CDB peut être [mise en cache](../../../ci/caching/_index.md).

```yaml
.cdb_cache:
  cache: &cdb_cache
    key:
      files:
        - Makefile
        - src/
    paths:
      - compile_commands.json

<YOUR-BUILD-JOB-NAME>:
  script:
    - <your-script to generate the CDB>
  cache:
    <<: *cdb_cache
    policy: pull-push

gitlab-advanced-sast-cpp:
  cache:
    <<: *cdb_cache
    policy: pull
```

Pour un exemple complet, consultez le projet de démonstration [`cached-cdb`](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/cached-db).

### Gestion des chemins absolus dans une CDB {#handling-absolute-paths-in-a-cdb}

Dans le [projet de démonstration](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/cached-db/-/blob/1a36792b744d7a6ad396a8ac8114ca8947e45b62/.gitlab-ci.yml#L27), `bear` est exécuté depuis le [répertoire de builds](https://docs.gitlab.com/runner/configuration/advanced-configuration/#default-build-directory) d'un job Docker. Les chemins de la CDB sont absolus, basés sur [/builds/$CI_PROJECT_PATH](../../../ci/variables/predefined_variables.md). Le job d'analyse `gitlab-advanced-sast-cpp` s'exécute au même emplacement, de sorte que les chemins sont corrects.

Si la CDB a été générée à un chemin non disponible lors de l'analyse, elle doit être recalée. L'outil `cdb-rebase`, inclus dans l'image de l'analyseur, réécrit les chemins `directory`, `file` et `output`.

Exemple :

```yaml
gitlab-advanced-sast-cpp:
  before-script:
    # Rebase the original CDB to be relative to the current directory.
    #
    # ORIGINAL_CDB_PATH     - Path to the CDB artifact from a previous job (e.g., artifacts/compile_commands.json)
    # ORIGINAL_CDB_BASEPATH - The absolute path to the project root when the ORIGINAL_CDB_PATH was generated.
    #                         (e.g., /mnt/custom_build_area/my-project or /home/user/my-project)
    - /cdb-rebase   --input "$ORIGINAL_CDB_PATH" \
                    --output compile_commands.json \
                    --src "$ORIGINAL_CDB_BASEPATH" \
                    --dst .
```

Pour une démonstration complète, consultez [cdb-rebase-demo](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/cdb-rebase-demo)

Au-delà du simple recalage des chemins, `cdb-rebase` peut également gérer les fichiers d'en-tête entre les environnements de build et d'analyse :

- Mettre en cache les en-têtes externes : avec `--include-cache`, les en-têtes situés en dehors de l'arborescence source sont copiés dans un cache portable.
- Ajouter des chemins d'inclusion : avec `--include`, spécifiez des répertoires d'inclusion supplémentaires à mettre en cache.
- Exclure des fichiers : avec `--exclude`, ignorez les en-têtes que vous ne souhaitez pas conserver.

Exemple :

```shell
/cdb-rebase --src /my-project \
            --dst /scan-env \
            --input build/compile_commands.json \
            --output rebased_cdb.json \
            --include-cache include-cache \
            --include third_party/include \
            --exclude dummy.h
```

L'outil `cdb-rebase` est également disponible dans les environnements où Go est installé, ce qui permet de recaler la CDB au moment de sa génération, par exemple.

```shell
go install gitlab.com/gitlab-org/security-products/analyzers/clangsa/cmd/cdb-rebase@latest
bear -o compile_commands_abs.json -- make
cdb-rebase -i compile_commands_abs.json -o compile_commands.json -s "$PWD" -d .
```

> [!note]
> La commande `go install` ci-dessus installe `cdb-rebase` dans le chemin `GOBIN`, qui peut être trouvé avec `go env GOBIN`.

### Couverture d'analyse partielle due à des fichiers d'en-tête manquants {#partial-scan-coverage-due-to-missing-header-files}

Une couverture d'analyse partielle peut survenir lorsque les fichiers d'en-tête système ou tiers requis ne sont pas disponibles dans le job d'analyse. Les en-têtes installés lors du job de build doivent être explicitement transmis au job d'analyse et rendus résolvables via les chemins d'inclusion enregistrés dans la base de données de compilation.

Une approche courante consiste à mettre en cache les en-têtes requis et à mettre à jour la base de données de compilation pour les référencer :

```shell
# Create and populate an include cache
mkdir -p include-cache
dpkg -L <build-dependency-packages> | sed -n 's:^/usr/include/::p' > headers.txt
rsync -a --files-from=headers.txt /usr/include/ include-cache/

# Add cached headers to compile flags
cdb_append . "-I'$PWD/include-cache'"
```

Pour une démonstration complète, consultez l'[exemple](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/OpenSceneGraph/-/merge_requests/4).
