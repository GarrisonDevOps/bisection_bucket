---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Créer des paquets
---

Utilisez le registre de paquets GitLab pour installer et créer des paquets dans différents formats de paquets.

## Composer {#composer}

1. Créez un répertoire appelé `my-composer-package` et accédez à ce répertoire :

   ```shell
   mkdir my-composer-package && cd my-composer-package
   ```

1. Exécutez [`composer init`](https://getcomposer.org/doc/03-cli.md#init) et répondez aux invites.

   Pour l'espace de nommage, saisissez votre [espace de nommage](../../namespace/_index.md) unique, comme votre nom d'utilisateur GitLab ou le nom de votre groupe.

   Un fichier appelé `composer.json` est créé :

   ```json
   {
     "name": "<namespace>/composer-test",
     "description": "Library XY",
     "type": "library",
     "license": "GPL-3.0-only",
     "authors": [
       {
         "name": "John Doe",
         "email": "john@example.com"
       }
     ],
     "require": {}
   }
   ```

## Conan 1 {#conan-1}

### Installer Conan 1 {#install-conan-1}

Prérequis :

- Vous devez installer Conan version 1.x.

Téléchargez le gestionnaire de paquets Conan dans votre environnement de développement local en suivant les instructions sur [conan.io](https://conan.io/downloads).

Une fois l'installation terminée, vérifiez que vous pouvez utiliser Conan dans votre terminal en exécutant :

```shell
conan --version
```

La version de Conan s'affiche dans la sortie :

```plaintext
Conan version 1.20.5
```

### Installer CMake {#install-cmake}

Lorsque vous développez avec C++ et Conan, vous pouvez choisir parmi de nombreux compilateurs disponibles. Cet exemple utilise le générateur de système de build CMake.

Pour installer CMake :

- Pour Mac, utilisez [Homebrew](https://brew.sh/) et exécutez `brew install cmake`.
- Pour les autres systèmes d'exploitation, suivez les instructions sur [cmake.org](https://cmake.org/resources/).

Une fois l'installation terminée, vérifiez que vous pouvez utiliser CMake dans votre terminal en exécutant :

```shell
cmake --version
```

La version de CMake s'affiche dans la sortie.

### créer un projet {#create-a-project}

Pour tester le registre de paquets, vous avez besoin d'un projet C++. Si vous n'en avez pas encore, vous pouvez cloner le [projet de démarrage hello world](https://github.com/conan-io/hello) de Conan.

### Créer un paquet Conan 1 {#build-a-conan-1-package}

Pour créer un paquet :

1. Ouvrez un terminal et accédez au dossier racine de votre projet.
1. Générez une nouvelle recette en exécutant `conan new` avec un nom de paquet et une version :

   ```shell
   conan new Hello/0.1 -t
   ```

1. Créez un paquet pour la recette en exécutant `conan create` avec l'utilisateur et le canal Conan :

   ```shell
   conan create . mycompany/beta
   ```

   > [!note]
   > Si vous utilisez un [remote d'instance](../conan_1_repository/_index.md#add-a-remote-for-your-instance), vous devez suivre une [convention de nommage](../conan_1_repository/_index.md#package-recipe-naming-convention-for-instance-remotes) spécifique.

Un paquet avec la recette `Hello/0.1@mycompany/beta` est créé.

Pour plus de détails sur la création et la gestion des paquets Conan, consultez la [documentation Conan](https://docs.conan.io/en/latest/creating_packages.html).

## Conan 2 {#conan-2}

### Installer Conan 2 {#install-conan-2}

Prérequis :

- Vous devez installer Conan version 2.x. Conan version 2 de base est disponible et les améliorations futures peuvent être suivies dans l'[epic 8258](https://gitlab.com/groups/gitlab-org/-/work_items/8258).

Installez le gestionnaire de paquets Conan dans votre environnement de développement local en suivant les instructions sur [conan.io](https://docs.conan.io/2/installation.html).

Une fois l'installation terminée, exécutez la commande suivante pour vérifier que vous pouvez utiliser Conan dans votre terminal :

```shell
conan --version
```

La version de Conan s'affiche dans la sortie :

```plaintext
Conan version 2.17.0
```

### Créer un profil Conan 2 {#create-conan-2-profile}

Vous devez définir un profil pour Conan 2. Si vous avez déjà défini un profil, ignorez cette étape.

Pour créer un profil, exécutez la commande suivante :

```shell
conan profile detect
```

Vérifiez le profil :

```shell
conan profile list
```

La commande liste le profil dans la sortie :

```plaintext
Profiles found in the cache:
default
```

Le profil généré est généralement suffisant pour commencer. Pour plus d'informations sur les profils Conan, consultez [les profils Conan 2](https://docs.conan.io/2/reference/config_files/profiles.html#profiles).

### Installer CMake {#install-cmake-1}

Lorsque vous développez avec C++ et Conan, vous pouvez choisir parmi de nombreux compilateurs disponibles. L'exemple suivant utilise le générateur de système de build CMake.

Prérequis :

- Installez CMake.
  - Pour macOS, installez [Homebrew](https://brew.sh/) et exécutez `brew install cmake`.
  - Pour les autres systèmes d'exploitation, suivez les instructions sur [cmake.org](https://cmake.org/resources/).

Une fois l'installation terminée, vérifiez que vous pouvez utiliser CMake dans votre terminal avec la commande suivante :

```shell
cmake --version
```

La version de CMake s'affiche dans la sortie.

### créer un projet {#create-a-project-1}

Prérequis :

- Pour tester le registre de paquets, vous devez disposer d'un projet C++.

Accédez à votre dossier de projet local et utilisez la commande `conan new` pour créer un exemple de projet de bibliothèque C++ `"Hello World"` avec le template `cmake_lib` :

```shell
mkdir hello && cd hello
conan new cmake_lib -d name=hello -d version=0.1
```

Pour des exemples plus avancés, consultez le [projet d'exemples](https://github.com/conan-io/examples2) Conan 2.

### Créer un paquet Conan 2 {#build-a-conan-2-package}

Prérequis :

- [Créez un projet C++](#create-a-project).

Pour créer un paquet :

1. Assurez-vous que vous êtes dans le dossier `hello` créé dans la section précédente.
1. Créez un paquet pour la recette en exécutant `conan create` avec l'utilisateur et le canal Conan :

   ```shell
   conan create . --channel=beta --user=mycompany
   ```

Un paquet avec la recette `hello/0.1@mycompany/beta` est créé.

Pour plus de détails sur la création et la gestion des paquets Conan, consultez [Création de paquets](https://docs.conan.io/2/tutorial/creating_packages).

## Maven {#maven}

### Installer Maven {#install-maven}

Les versions minimales requises sont :

- Java 11.0.5+
- Maven 3.6+

Suivez les instructions sur [maven.apache.org](https://maven.apache.org/install.html) pour télécharger et installer Maven dans votre environnement de développement local. Une fois l'installation terminée, vérifiez que vous pouvez utiliser Maven dans votre terminal en exécutant :

```shell
mvn --version
```

La sortie doit être similaire à :

```shell
Apache Maven 3.6.1 (d66c9c0b3152b2e69ee9bac180bb8fcc8e6af555; 2019-04-04T20:00:29+01:00)
Maven home: /Users/<your_user>/apache-maven-3.6.1
Java version: 12.0.2, vendor: Oracle Corporation, runtime: /Library/Java/JavaVirtualMachines/jdk-12.0.2.jdk/Contents/Home
Default locale: en_GB, platform encoding: UTF-8
OS name: "mac os x", version: "10.15.2", arch: "x86_64", family: "mac"
```

### Créer un paquet Maven {#build-a-maven-package}

1. Ouvrez votre terminal et créez un répertoire pour stocker le projet.
1. Depuis le nouveau répertoire, exécutez cette commande Maven pour initialiser un nouveau paquet :

   ```shell
   mvn archetype:generate -DgroupId=com.mycompany.mydepartment -DartifactId=my-project -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false
   ```

   Les arguments sont :

   - `DgroupId` : une chaîne unique qui identifie votre paquet. Suivez les [conventions de nommage Maven](https://maven.apache.org/guides/mini/guide-naming-conventions.html).
   - `DartifactId` : le nom du `JAR`, ajouté à la fin du `DgroupId`.
   - `DarchetypeArtifactId` : l'archétype utilisé pour créer la structure initiale du projet.
   - `DinteractiveMode` : créez le projet en mode batch (facultatif).

Ce message indique que le projet a été configuré avec succès :

```shell
...
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  3.429 s
[INFO] Finished at: 2020-01-28T11:47:04Z
[INFO] ------------------------------------------------------------------------
```

Dans le dossier où vous avez exécuté la commande, un nouveau répertoire doit s'afficher. Le nom du répertoire doit correspondre au paramètre `DartifactId`, qui dans ce cas est `my-project`.

## Gradle {#gradle}

### Installer Gradle {#install-gradle}

Si vous souhaitez créer un nouveau projet Gradle, vous devez installer Gradle. Suivez les instructions sur [gradle.org](https://gradle.org/install/) pour télécharger et installer Gradle dans votre environnement de développement local.

Dans votre terminal, vérifiez que vous pouvez utiliser Gradle en exécutant :

```shell
gradle -version
```

Pour utiliser un projet Gradle existant, dans le répertoire du projet, exécutez `gradlew` sous Linux, ou `gradlew.bat` sous Windows.

La sortie doit être similaire à :

```plaintext
------------------------------------------------------------
Gradle 6.0.1
------------------------------------------------------------

Build time:   2019-11-18 20:25:01 UTC
Revision:     fad121066a68c4701acd362daf4287a7c309a0f5

Kotlin:       1.3.50
Groovy:       2.5.8
Ant:          Apache Ant(TM) version 1.10.7 compiled on September 1 2019
JVM:          11.0.5 (Oracle Corporation 11.0.5+10)
OS:           Windows 10 10.0 amd64
```

### Créer un paquet {#create-a-package}

1. Ouvrez votre terminal et créez un répertoire pour stocker le projet.
1. Depuis ce nouveau répertoire, exécutez cette commande pour initialiser un nouveau paquet :

   ```shell
   gradle init
   ```

   La sortie doit être :

   ```plaintext
   Select type of project to generate:
     1: basic
     2: application
     3: library
     4: Gradle plugin
   Enter selection (default: basic) [1..4]
   ```

1. Saisissez `3` pour créer un nouveau projet de bibliothèque. La sortie doit être :

   ```plaintext
   Select implementation language:
     1: C++
     2: Groovy
     3: Java
     4: Kotlin
     5: Scala
     6: Swift
   ```

1. Saisissez `3` pour créer un nouveau projet de bibliothèque Java. La sortie doit être :

   ```plaintext
   Select build script DSL:
     1: Groovy
     2: Kotlin
   Enter selection (default: Groovy) [1..2]
   ```

1. Saisissez `1` pour créer un nouveau projet de bibliothèque Java décrit en Groovy DSL, ou `2` pour en créer un décrit en Kotlin DSL. La sortie doit être :

   ```plaintext
   Select test framework:
     1: JUnit 4
     2: TestNG
     3: Spock
     4: JUnit Jupiter
   ```

1. Saisissez `1` pour initialiser le projet avec les bibliothèques de test JUnit 4. La sortie doit être :

   ```plaintext
   Project name (default: test):
   ```

1. Saisissez un nom de projet ou appuyez sur <kbd>Entrée</kbd> pour utiliser le nom du répertoire comme nom de projet.

## sbt {#sbt}

### Installer sbt {#install-sbt}

Installez sbt pour créer de nouveaux projets sbt.

Pour installer sbt dans votre environnement de développement :

1. Suivez les instructions sur [scala-sbt.org](https://www.scala-sbt.org/1.x/docs/Setup.html).
1. Depuis votre terminal, vérifiez que vous pouvez utiliser sbt :

   ```shell
   sbt --version
   ```

La sortie est similaire à :

```plaintext
[warn] Project loading failed: (r)etry, (q)uit, (l)ast, or (i)gnore? (default: r)
sbt script version: 1.9.8
```

### Créer un projet Scala {#create-a-scala-project}

1. Ouvrez votre terminal et créez un répertoire pour stocker le projet.
1. Depuis le nouveau répertoire, initialisez un nouveau projet :

   ```shell
   sbt new scala/scala-seed.g8
   ```

   La sortie est :

   ```plaintext
   Minimum Scala build.

   name [My Something Project]: hello

   Template applied in ./hello
   ```

1. Saisissez un nom de projet ou appuyez sur <kbd>Entrée</kbd> pour utiliser le nom du répertoire comme nom de projet.
1. Ouvrez le fichier `build.sbt` et modifiez-le comme décrit dans la [documentation sbt](https://www.scala-sbt.org/1.x/docs/Publishing.html) pour publier votre projet dans le registre de paquets.

## npm {#npm}

### Installer npm {#install-npm}

Installez Node.js et npm dans votre environnement de développement local en suivant les instructions sur [npmjs.com](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm/).

Une fois l'installation terminée, vérifiez que vous pouvez utiliser npm dans votre terminal en exécutant :

```shell
npm --version
```

La version de npm s'affiche dans la sortie :

```plaintext
6.10.3
```

### Créer un paquet npm {#create-an-npm-package}

1. Créez un répertoire vide.
1. Accédez au répertoire et initialisez un paquet vide en exécutant :

   ```shell
   npm init
   ```

1. Répondez aux questions posées. Assurez-vous que le nom du paquet suit la [convention de nommage](../npm_registry/_index.md#naming-convention) et que sa portée correspond au projet ou au groupe où le registre existe.

## Yarn {#yarn}

### Installer Yarn {#install-yarn}

En guise d'alternative à npm, vous pouvez installer Yarn dans votre environnement local en suivant les instructions sur [classic.yarnpkg.com](https://classic.yarnpkg.com/en/docs/install).

Une fois l'installation terminée, vérifiez que vous pouvez utiliser Yarn dans votre terminal en exécutant :

```shell
yarn --version
```

La version de Yarn s'affiche dans la sortie :

```plaintext
1.19.1
```

### Créer un paquet {#create-a-package-1}

1. Créez un répertoire vide.
1. Accédez au répertoire et initialisez un paquet vide en exécutant :

   ```shell
   yarn init
   ```

1. Répondez aux questions posées. Assurez-vous que le nom du paquet suit la [convention de nommage](../npm_registry/_index.md#naming-convention) et que sa portée correspond au projet ou au groupe où le registre existe.

Un fichier `package.json` est créé.

## NuGet {#nuget}

### Installer NuGet {#install-nuget}

Suivez les instructions de [Microsoft](https://learn.microsoft.com/en-us/nuget/install-nuget-client-tools) pour installer NuGet. Si vous disposez de [Visual Studio](https://visualstudio.microsoft.com/vs/), NuGet est probablement déjà installé.

Vérifiez que la [CLI NuGet](https://www.nuget.org/) est installée en exécutant :

```shell
nuget help
```

La sortie doit être similaire à :

```plaintext
NuGet Version: 5.1.0.6013
usage: NuGet <command> [args] [options]
Type 'NuGet help <command>' for help on a specific command.

Available commands:

[output truncated]
```

## PyPI {#pypi}

### Installer pip et twine {#install-pip-and-twine}

Installez une version récente de [pip](https://pypi.org/project/pip/) et de [twine](https://pypi.org/project/twine/).

### créer un projet {#create-a-project-2}

Créez un projet de test.

1. Ouvrez votre terminal.
1. Créez un répertoire appelé `MyPyPiPackage`, puis accédez à ce répertoire :

   ```shell
   mkdir MyPyPiPackage && cd MyPyPiPackage
   ```

1. Créez un autre répertoire et accédez-y :

   ```shell
   mkdir mypypipackage && cd mypypipackage
   ```

1. Créez les fichiers requis dans ce répertoire :

   ```shell
   touch __init__.py
   touch greet.py
   ```

1. Ouvrez le fichier `greet.py`, puis ajoutez :

   ```python
   def SayHello():
       print("Hello from MyPyPiPackage")
       return
   ```

1. Ouvrez le fichier `__init__.py`, puis ajoutez :

   ```python
   from .greet import SayHello
   ```

1. Pour tester le code, dans votre répertoire `MyPyPiPackage`, démarrez l'invite Python.

   ```shell
   python
   ```

1. Exécutez cette commande :

   ```python
   >>> from mypypipackage import SayHello
   >>> SayHello()
   ```

Un message indique que le projet a été configuré avec succès :

```plaintext
Python 3.8.2 (v3.8.2:7b3ab5921f, Feb 24 2020, 17:52:18)
[Clang 6.0 (clang-600.0.57)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from mypypipackage import SayHello
>>> SayHello()
Hello from MyPyPiPackage
```

### Créer un paquet PyPI {#create-a-pypi-package}

Après avoir créé un projet, vous pouvez créer un paquet.

1. Dans votre terminal, accédez au répertoire `MyPyPiPackage`.
1. Créez un fichier `pyproject.toml` :

   ```shell
   touch pyproject.toml
   ```

   Ce fichier contient toutes les informations sur le paquet. Pour plus d'informations sur ce fichier, consultez [la création de `pyproject.toml`](https://packaging.python.org/en/latest/tutorials/packaging-projects/#creating-pyproject-toml). Étant donné que GitLab identifie les paquets sur la base des [noms normalisés Python (PEP-503)](https://www.python.org/dev/peps/pep-0503/#normalized-names), assurez-vous que le nom de votre paquet répond à ces exigences. Consultez la [section d'installation](../pypi_repository/_index.md#authenticate-with-the-gitlab-package-registry) pour plus de détails.

1. Ouvrez le fichier `pyproject.toml`, puis ajoutez les informations de base :

   ```toml
   [build-system]
   requires = ["setuptools>=61.0"]
   build-backend = "setuptools.build_meta"

   [project]
   name = "mypypipackage"
   version = "0.0.1"
   authors = [
       { name="Example Author", email="author@example.com" },
   ]
   description = "A small example package"
   requires-python = ">=3.7"
   classifiers = [
      "Programming Language :: Python :: 3",
      "Operating System :: OS Independent",
   ]

   [tool.setuptools.packages]
   find = {}
   ```

1. Enregistrez le fichier.
1. Installez la bibliothèque de build du paquet :

   ```shell
   pip install build
   ```

1. Créez le paquet :

   ```shell
   python -m build
   ```

La sortie doit être visible dans un dossier `dist` nouvellement créé :

```shell
ls dist
```

La sortie doit être similaire à ce qui suit :

```plaintext
mypypipackage-0.0.1-py3-none-any.whl mypypipackage-0.0.1.tar.gz
```

Le paquet est maintenant prêt à être publié dans le registre de paquets.
