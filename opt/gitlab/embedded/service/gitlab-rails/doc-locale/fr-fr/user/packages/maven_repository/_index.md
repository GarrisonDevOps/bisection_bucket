---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Paquets Maven dans le registre de paquets
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Publiez des artefacts [Maven](https://maven.apache.org) dans le registre de paquets de votre projet. Installez ensuite les paquets chaque fois que vous avez besoin de les utiliser comme dépendance.

Pour la documentation des endpoints d'API spécifiques utilisés par le client du gestionnaire de paquets Maven, consultez la [documentation de l'API Maven](../../../api/packages/maven.md).

Clients pris en charge :

- `mvn`. Apprenez à construire un paquet [Maven](../workflows/build_packages.md#maven).
- `gradle`. Apprenez à construire un paquet [Gradle](../workflows/build_packages.md#gradle).
- `sbt`.

## Publier dans le registre de paquets GitLab {#publish-to-the-gitlab-package-registry}

### S'authentifier auprès du registre de paquets {#authenticate-to-the-package-registry}

Vous avez besoin d'un jeton pour publier un paquet. Différents jetons sont disponibles selon ce que vous essayez d'accomplir. Pour plus d'informations, consultez les [recommandations sur les jetons](../package_registry/supported_functionality.md#authenticate-with-the-registry).

Créez un jeton et enregistrez-le pour l'utiliser ultérieurement dans le processus.

N'utilisez pas de méthodes d'authentification autres que celles documentées ici. Les méthodes d'authentification non documentées pourraient être supprimées à l'avenir.

#### Modifier la configuration du client {#edit-the-client-configuration}

Mettez à jour votre configuration pour vous authentifier auprès du dépôt Maven via HTTP.

##### En-tête HTTP personnalisé {#custom-http-header}

Vous devez ajouter les informations d'authentification au fichier de configuration de votre client.

{{< tabs >}}

{{< tab title="`mvn`" >}}

| Type de jeton            | Le nom doit être    | Jeton                                                                  |
| --------------------- | --------------- | ---------------------------------------------------------------------- |
| Jeton d'accès personnel | `Private-Token` | Collez le jeton tel quel ou définissez une variable d'environnement pour contenir le jeton |
| Jeton de déploiement          | `Deploy-Token`  | Collez le jeton tel quel ou définissez une variable d'environnement pour contenir le jeton |
| Jeton de job CI          | `Job-Token`     | `${CI_JOB_TOKEN}`                                                      |
| Jeton OAuth           | `Authorization` | Préfixez le jeton avec `Bearer` (par exemple, `Bearer <oauth_token>`)  |

> [!note]
> Le champ `<name>` doit être nommé pour correspondre au jeton que vous avez choisi.

Ajoutez la section suivante à votre fichier [`settings.xml`](https://maven.apache.org/settings.html).

```xml
<settings>
  <servers>
    <server>
      <id>gitlab-maven</id>
      <configuration>
        <httpHeaders>
          <property>
            <name>REPLACE_WITH_NAME</name>
            <value>REPLACE_WITH_TOKEN</value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
  </servers>
</settings>
```

{{< /tab >}}

{{< tab title="`gradle`" >}}

| Type de jeton            | Le nom doit être    | Jeton                                                                  |
| --------------------- | --------------- | ---------------------------------------------------------------------- |
| Jeton d'accès personnel | `Private-Token` | Collez le jeton tel quel ou définissez une variable d'environnement pour contenir le jeton |
| Jeton de déploiement          | `Deploy-Token`  | Collez le jeton tel quel ou définissez une variable d'environnement pour contenir le jeton |
| Jeton de job CI          | `Job-Token`     | `System.getenv("CI_JOB_TOKEN")`                                        |
| Jeton OAuth           | `Authorization` | Préfixez le jeton avec `Bearer` (par exemple, `Bearer <oauth_token>`)  |

> [!note]
> Le champ `<name>` doit être nommé pour correspondre au jeton que vous avez choisi.

Dans [votre répertoire `GRADLE_USER_HOME`](https://docs.gradle.org/current/userguide/directory_layout.html#dir:gradle_user_home), créez un fichier `gradle.properties` avec le contenu suivant :

```properties
gitLabPrivateToken=REPLACE_WITH_YOUR_TOKEN
```

Ajoutez une section `repositories` à votre fichier [`build.gradle`](https://docs.gradle.org/current/userguide/tutorial_using_tasks.html) :

- En Groovy DSL :

  ```groovy
  repositories {
      maven {
          url "https://gitlab.example.com/api/v4/groups/<group>/-/packages/maven"
          name "GitLab"
          credentials(HttpHeaderCredentials) {
              name = 'REPLACE_WITH_NAME'
              value = gitLabPrivateToken
          }
          authentication {
              header(HttpHeaderAuthentication)
          }
      }
  }
  ```

- En Kotlin DSL :

  ```kotlin
  repositories {
      maven {
          url = uri("https://gitlab.example.com/api/v4/groups/<group>/-/packages/maven")
          name = "GitLab"
          credentials(HttpHeaderCredentials::class) {
              name = "REPLACE_WITH_NAME"
              value = findProperty("gitLabPrivateToken") as String?
          }
          authentication {
              create("header", HttpHeaderAuthentication::class)
          }
      }
  }
  ```

{{< /tab >}}

{{< /tabs >}}

##### Authentification HTTP de base {#basic-http-authentication}

Vous pouvez également utiliser l'authentification HTTP de base pour vous authentifier auprès du registre de paquets Maven.

{{< tabs >}}

{{< tab title="`mvn`" >}}

| Type de jeton            | Le nom doit être                 | Jeton                                                                  |
| --------------------- | ---------------------------- | ---------------------------------------------------------------------- |
| Jeton d'accès personnel | Le nom d'utilisateur de l'utilisateur     | Collez le jeton tel quel ou définissez une variable d'environnement pour contenir le jeton |
| Jeton de déploiement          | Le nom d'utilisateur du jeton de déploiement | Collez le jeton tel quel ou définissez une variable d'environnement pour contenir le jeton |
| Jeton de job CI          | `gitlab-ci-token`            | `${CI_JOB_TOKEN}`                                                      |

Ajoutez la section suivante à votre fichier [`settings.xml`](https://maven.apache.org/settings.html).

```xml
<settings>
  <servers>
    <server>
      <id>gitlab-maven</id>
      <username>REPLACE_WITH_NAME</username>
      <password>REPLACE_WITH_TOKEN</password>
      <configuration>
        <authenticationInfo>
          <userName>REPLACE_WITH_NAME</userName>
          <password>REPLACE_WITH_TOKEN</password>
        </authenticationInfo>
      </configuration>
    </server>
  </servers>
</settings>
```

{{< /tab >}}

{{< tab title="`gradle`" >}}

| Type de jeton            | Le nom doit être                 | Jeton                                                                  |
| --------------------- | ---------------------------- | ---------------------------------------------------------------------- |
| Jeton d'accès personnel | Le nom d'utilisateur de l'utilisateur     | Collez le jeton tel quel ou définissez une variable d'environnement pour contenir le jeton |
| Jeton de déploiement          | Le nom d'utilisateur du jeton de déploiement | Collez le jeton tel quel ou définissez une variable d'environnement pour contenir le jeton |
| Jeton de job CI          | `gitlab-ci-token`            | `System.getenv("CI_JOB_TOKEN")`                                        |

Dans [votre répertoire `GRADLE_USER_HOME`](https://docs.gradle.org/current/userguide/directory_layout.html#dir:gradle_user_home), créez un fichier `gradle.properties` avec le contenu suivant :

```properties
gitLabPrivateToken=REPLACE_WITH_YOUR_TOKEN
```

Ajoutez une section `repositories` à votre [`build.gradle`](https://docs.gradle.org/current/userguide/tutorial_using_tasks.html).

- En Groovy DSL :

  ```groovy
  repositories {
      maven {
          url "https://gitlab.example.com/api/v4/groups/<group>/-/packages/maven"
          name "GitLab"
          credentials(PasswordCredentials) {
              username = 'REPLACE_WITH_NAME'
              password = gitLabPrivateToken
          }
          authentication {
              basic(BasicAuthentication)
          }
      }
  }
  ```

- En Kotlin DSL :

  ```kotlin
  repositories {
      maven {
          url = uri("https://gitlab.example.com/api/v4/groups/<group>/-/packages/maven")
          name = "GitLab"
          credentials(BasicAuthentication::class) {
              username = "REPLACE_WITH_NAME"
              password = findProperty("gitLabPrivateToken") as String?
          }
          authentication {
              create("basic", BasicAuthentication::class)
          }
      }
  }
  ```

{{< /tab >}}

{{< tab title="`sbt`" >}}

| Type de jeton            | Le nom doit être                 | Jeton                                                                  |
|-----------------------|------------------------------|------------------------------------------------------------------------|
| Jeton d'accès personnel | Le nom d'utilisateur de l'utilisateur     | Collez le jeton tel quel ou définissez une variable d'environnement pour contenir le jeton |
| Jeton de déploiement          | Le nom d'utilisateur du jeton de déploiement | Collez le jeton tel quel ou définissez une variable d'environnement pour contenir le jeton |
| Jeton de job CI          | `gitlab-ci-token`            | `sys.env.get("CI_JOB_TOKEN").get`                                      |

L'authentification pour [SBT](https://www.scala-sbt.org/index.html) est basée sur [l'authentification HTTP de base](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication). Vous devez fournir un nom et un mot de passe.

> [!note]
> Le champ de nom doit être nommé pour correspondre au jeton que vous avez choisi.

Pour installer un paquet depuis le registre de paquets GitLab Maven en utilisant `sbt`, vous devez configurer un [résolveur Maven](https://www.scala-sbt.org/1.x/docs/Resolvers.html#Maven+resolvers). Si vous accédez à un projet ou groupe privé ou interne, vous devez configurer des [identifiants](https://www.scala-sbt.org/1.x/docs/Publishing.html#Credentials). Après avoir configuré le résolveur et l'authentification, vous pouvez installer un paquet depuis un projet, un groupe ou un espace de nommage.

Dans votre [`build.sbt`](https://www.scala-sbt.org/1.x/docs/Directories.html#sbt+build+definition+files), ajoutez les lignes suivantes :

```scala
resolvers += ("gitlab" at "<endpoint url>")

credentials += Credentials("GitLab Packages Registry", "<host>", "<name>", "<token>")
```

Dans cet exemple :

- `<endpoint url>` est l'[URL du endpoint](#endpoint-urls). Exemple : `https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven`.
- `<host>` est l'hôte présent dans `<endpoint url>` sans le schéma de protocole ni le port. Exemple : `gitlab.example.com`.
- `<name>` et `<token>` sont expliqués dans le tableau précédent.

{{< /tab >}}

{{< /tabs >}}

### Convention de nommage {#naming-convention}

Vous pouvez utiliser l'un des trois endpoints pour installer un paquet Maven. Vous devez publier un paquet dans un projet, mais le endpoint que vous choisissez détermine les paramètres que vous ajoutez à votre fichier `pom.xml` pour la publication.

Les trois endpoints sont :

- Projet : à utiliser lorsque vous avez peu de paquets Maven et qu'ils ne se trouvent pas dans le même groupe GitLab.
- Groupe : à utiliser lorsque vous souhaitez installer des paquets provenant de nombreux projets différents dans le même groupe GitLab. GitLab ne garantit pas l'unicité des noms de paquets au sein du groupe. Vous pouvez avoir deux projets avec le même nom de paquet et la même version de paquet. Par conséquent, GitLab sert celui qui est le plus récent.
- Instance : à utiliser lorsque vous avez de nombreux paquets dans différents groupes GitLab ou dans leur propre espace de nommage.

Pour le endpoint au niveau de l'instance, assurez-vous que la section correspondante de votre `pom.xml` dans Maven ressemble à ceci :

```xml
  <groupId>group-slug.subgroup-slug</groupId>
  <artifactId>project-slug</artifactId>
```

Seuls les paquets dont le chemin correspond à celui du projet sont exposés par le endpoint au niveau de l'instance.

| Projet             | Paquet                          | Endpoint au niveau de l'instance disponible |
| ------------------- | -------------------------------- | --------------------------------- |
| `foo/bar`           | `foo/bar/1.0-SNAPSHOT`           | Oui                               |
| `gitlab-org/gitlab` | `foo/bar/1.0-SNAPSHOT`           | Non                                |
| `gitlab-org/gitlab` | `gitlab-org/gitlab/1.0-SNAPSHOT` | Oui                               |

#### URL des endpoints {#endpoint-urls}

| Point de terminaison | URL du endpoint pour `pom.xml`                                               | Informations supplémentaires |
|----------|--------------------------------------------------------------------------|------------------------|
| Projet  | `https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven` | Remplacez `gitlab.example.com` par votre nom de domaine. Remplacez `<project_id>` par l'ID de votre projet, disponible sur votre [page de présentation du projet](../../project/working_with_projects.md#find-the-project-id). |
| Groupe    | `https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/maven`   | Remplacez `gitlab.example.com` par votre nom de domaine. Remplacez `<group_id>` par l'ID de votre groupe, disponible sur la page d'accueil de votre groupe. |
| Instance | `https://gitlab.example.com/api/v4/packages/maven`                       | Remplacez `gitlab.example.com` par votre nom de domaine. |

### Modifier le fichier de configuration pour la publication {#edit-the-configuration-file-for-publishing}

Vous devez ajouter les informations de publication au fichier de configuration de votre client.

{{< tabs >}}

{{< tab title="`mvn`" >}}

Quel que soit le endpoint choisi, vous devez disposer :

- D'une URL spécifique au projet dans la section `distributionManagement`.
- D'une section `repository` et `distributionManagement`.

La section `repository` correspondante de votre `pom.xml` dans Maven doit ressembler à ceci :

```xml
<repositories>
  <repository>
    <id>gitlab-maven</id>
    <url><your_endpoint_url></url>
  </repository>
</repositories>
<distributionManagement>
  <repository>
    <id>gitlab-maven</id>
    <url>https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven</url>
  </repository>
  <snapshotRepository>
    <id>gitlab-maven</id>
    <url>https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven</url>
  </snapshotRepository>
</distributionManagement>
```

- L'`id` est ce que vous avez [défini dans `settings.xml`](#edit-the-client-configuration).
- La valeur de `<your_endpoint_url>` dépend du [endpoint](#endpoint-urls) que vous choisissez.
- Remplacez `gitlab.example.com` par votre nom de domaine.

{{< /tab >}}

{{< tab title="`gradle`" >}}

Pour publier un paquet avec Gradle :

1. Ajoutez le plugin Gradle [`maven-publish`](https://docs.gradle.org/current/userguide/publishing_maven.html) à la section des plugins :

   - En Groovy DSL :

     ```groovy
     plugins {
         id 'java'
         id 'maven-publish'
     }
     ```

   - En Kotlin DSL :

     ```kotlin
     plugins {
         java
         `maven-publish`
     }
     ```

1. Ajoutez une section `publishing` :

   - En Groovy DSL :

     ```groovy
     publishing {
         publications {
             library(MavenPublication) {
                 from components.java
             }
         }
         repositories {
             maven {
                 url "https://gitlab.example.com/api/v4/projects/<PROJECT_ID>/packages/maven"
                 credentials(HttpHeaderCredentials) {
                     name = "REPLACE_WITH_TOKEN_NAME"
                     value = gitLabPrivateToken // the variable resides in $GRADLE_USER_HOME/gradle.properties
                 }
                 authentication {
                     header(HttpHeaderAuthentication)
                 }
             }
         }
     }
     ```

   - En Kotlin DSL :

     ```kotlin
     publishing {
         publications {
             create<MavenPublication>("library") {
                 from(components["java"])
             }
         }
         repositories {
             maven {
                 url = uri("https://gitlab.example.com/api/v4/projects/<PROJECT_ID>/packages/maven")
                 credentials(HttpHeaderCredentials::class) {
                     name = "REPLACE_WITH_TOKEN_NAME"
                     value =
                         findProperty("gitLabPrivateToken") as String? // the variable resides in $GRADLE_USER_HOME/gradle.properties
                 }
                 authentication {
                     create("header", HttpHeaderAuthentication::class)
                 }
             }
         }
     }
     ```

{{< /tab >}}

{{< /tabs >}}

## Publier un paquet {#publish-a-package}

> [!warning]
> L'utilisation de l'option `DeployAtEnd` peut entraîner le rejet d'un chargement avec `400 bad request {"message":"Validation failed: Name has already been taken"}`. Pour plus de détails, consultez le [ticket 424238](https://gitlab.com/gitlab-org/gitlab/-/issues/424238).

Après avoir configuré l'[authentification](#authenticate-to-the-package-registry) et [choisi un endpoint pour la publication](#naming-convention), publiez un paquet Maven dans votre projet.

{{< tabs >}}

{{< tab title="`mvn`" >}}

Pour publier un paquet avec Maven :

```shell
mvn deploy
```

Si le déploiement réussit, le message de succès de la construction doit s'afficher :

```shell
...
[INFO] BUILD SUCCESS
...
```

Le message doit également indiquer que le paquet a été publié au bon emplacement :

```shell
Uploading to gitlab-maven: https://example.com/api/v4/projects/PROJECT_ID/packages/maven/com/mycompany/mydepartment/my-project/1.0-SNAPSHOT/my-project-1.0-20200128.120857-1.jar
```

{{< /tab >}}

{{< tab title="`gradle`" >}}

Exécutez la tâche de publication :

```shell
gradle publish
```

Accédez à la page **Paquets et registres** de votre projet et consultez les paquets publiés.

{{< /tab >}}

{{< tab title="`sbt`" >}}

Configurez le paramètre `publishTo` dans votre fichier `build.sbt` :

```scala
publishTo := Some("gitlab" at "<endpoint url>")
```

Assurez-vous que les identifiants sont correctement référencés. Consultez la [documentation de `sbt`](https://www.scala-sbt.org/1.x/docs/Publishing.html#Credentials) pour plus d'informations.

Pour publier un paquet avec `sbt` :

```shell
sbt publish
```

Si le déploiement réussit, le message de succès de la construction s'affiche :

```shell
[success] Total time: 1 s, completed Jan 28, 2020 12:08:57 PM
```

Vérifiez le message de succès pour vous assurer que le paquet a été publié au bon emplacement :

```shell
[info]  published my-project_2.12 to https://gitlab.example.com/api/v4/projects/PROJECT_ID/packages/maven/com/mycompany/my-project_2.12/0.1.1-SNAPSHOT/my-project_2.12-0.1.1-SNAPSHOT.pom
```

{{< /tab >}}

{{< /tabs >}}

> [!note]
> Si vous protégez un paquet Maven avant de le publier, le paquet sera rejeté avec une erreur `403 Forbidden` et un message d'erreur `Authorization failed`. Assurez-vous que le paquet Maven n'est pas protégé lors de la publication. Pour plus d'informations sur les règles de protection des paquets, consultez [comment protéger un paquet](../package_registry/package_protection_rules.md#protect-a-package).

## Installer un paquet {#install-a-package}

Pour installer un paquet depuis le registre de paquets GitLab, vous devez configurer la [connexion distante et vous authentifier](#authenticate-to-the-package-registry). Une fois cette opération effectuée, vous pouvez installer un paquet depuis un projet, un groupe ou un espace de nommage.

Si plusieurs paquets ont le même nom et la même version, lors de l'installation d'un paquet, le paquet publié le plus récemment est récupéré.

{{< tabs >}}

{{< tab title="`mvn`" >}}

Pour installer un paquet avec `mvn install` :

1. Ajoutez manuellement la dépendance à votre fichier `pom.xml` de projet. Pour ajouter l'exemple créé précédemment, le XML serait :

   ```xml
   <dependency>
     <groupId>com.mycompany.mydepartment</groupId>
     <artifactId>my-project</artifactId>
     <version>1.0-SNAPSHOT</version>
   </dependency>
   ```

1. Dans votre projet, exécutez la commande suivante :

   ```shell
   mvn install
   ```

Le message doit indiquer que le paquet est en cours de téléchargement depuis le registre de paquets :

```shell
Downloading from gitlab-maven: http://gitlab.example.com/api/v4/projects/PROJECT_ID/packages/maven/com/mycompany/mydepartment/my-project/1.0-SNAPSHOT/my-project-1.0-20200128.120857-1.pom
```

Vous pouvez également installer des paquets en utilisant directement la [commande `dependency:get`](https://maven.apache.org/plugins/maven-dependency-plugin/get-mojo.html) de Maven.

1. Dans le répertoire de votre projet, exécutez :

   ```shell
   mvn dependency:get -Dartifact=com.nickkipling.app:nick-test-app:1.1-SNAPSHOT -DremoteRepositories=gitlab-maven::::<gitlab endpoint url>  -s <path to settings.xml>
   ```

   - `<gitlab endpoint url>` est l'URL du [endpoint](#endpoint-urls) GitLab.
   - `<path to settings.xml>` est le chemin vers le fichier `settings.xml` qui contient les [informations d'authentification](#edit-the-client-configuration).

> [!note]
> Les ID de dépôt dans la commande `gitlab-maven` et dans le fichier `settings.xml` doivent correspondre.

Le message doit indiquer que le paquet est en cours de téléchargement depuis le registre de paquets :

```shell
Downloading from gitlab-maven: http://gitlab.example.com/api/v4/projects/PROJECT_ID/packages/maven/com/mycompany/mydepartment/my-project/1.0-SNAPSHOT/my-project-1.0-20200128.120857-1.pom
```

{{< /tab >}}

{{< tab title="`gradle`" >}}

Pour installer un paquet avec `gradle` :

1. Ajoutez une [dépendance](https://docs.gradle.org/current/userguide/declaring_dependencies.html) à `build.gradle` dans la section des dépendances :

   - En Groovy DSL :

     ```groovy
     dependencies {
         implementation 'com.mycompany.mydepartment:my-project:1.0-SNAPSHOT'
     }
     ```

   - En Kotlin DSL :

     ```kotlin
     dependencies {
         implementation("com.mycompany.mydepartment:my-project:1.0-SNAPSHOT")
     }
     ```

1. Dans votre projet, exécutez la commande suivante :

   ```shell
   gradle build
   ```

{{< /tab >}}

{{< tab title="`sbt`" >}}

Pour installer un paquet avec `sbt` :

1. Ajoutez une [dépendance inline](https://www.scala-sbt.org/1.x/docs/Library-Management.html#Dependencies) à `build.sbt` :

   ```scala
   libraryDependencies += "com.mycompany.mydepartment" % "my-project" % "8.4"
   ```

1. Dans votre projet, exécutez la commande suivante :

   ```shell
   sbt update
   ```

{{< /tab >}}

{{< /tabs >}}

### Téléchargements par proxy pour les paquets Maven {#proxy-downloads-for-maven-packages}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/507768) dans GitLab 17.8.

{{< /history >}}

Le registre de paquets Maven de GitLab utilise les [sommes de contrôle incluses à distance](https://maven.apache.org/resolver/expected-checksums.html#remote-included-checksums). Lorsque vous téléchargez un fichier, le registre proxie le fichier et envoie à la fois le fichier et ses sommes de contrôle associées aux clients Maven en une seule requête.

L'utilisation des sommes de contrôle incluses à distance avec les clients Maven récents :

- Réduit le nombre de requêtes web des clients vers le registre de paquets Maven de GitLab.
- Diminue la charge sur votre instance GitLab.
- Améliore le temps d'exécution des commandes client.

En raison de contraintes techniques, lorsque vous utilisez le stockage objet, le registre de paquets Maven ignore le paramètre [téléchargement par proxy](../../../administration/object_storage.md#proxy-download) dans la configuration du stockage objet pour `packages`. À la place, le téléchargement par proxy est toujours activé pour les téléchargements du registre de paquets Maven.

> [!note]
> Si vous n'utilisez pas le stockage objet, ce comportement n'a aucun impact sur votre instance.

## Intégration CI/CD pour les paquets Maven {#cicd-integration-for-maven-packages}

Vous pouvez utiliser CI/CD pour construire, tester et publier automatiquement des paquets Maven. Les exemples de cette section couvrent des scénarios tels que :

- Projets multi-modules
- Releases versionnées
- Publication conditionnelle
- Intégration avec les analyses de qualité du code et de sécurité

Vous pouvez adapter et combiner ces exemples selon les besoins spécifiques de votre projet.

N'oubliez pas d'ajuster la version de Maven, la version de Java et les autres paramètres en fonction des exigences de votre projet. Assurez-vous également d'avoir correctement configuré les identifiants et les paramètres nécessaires pour la publication dans le registre de paquets GitLab.

### Construction et publication de base d'un paquet Maven {#basic-maven-package-build-and-publish}

Cet exemple configure un pipeline qui construit et publie un paquet Maven :

```yaml
default:
  image: maven:3.8.5-openjdk-17
  cache:
    paths:
      - .m2/repository/
      - target/

variables:
  MAVEN_CLI_OPTS: "-s .m2/settings.xml --batch-mode"
  MAVEN_OPTS: "-Dmaven.repo.local=.m2/repository"

stages:
  - build
  - test
  - publish

build:
  stage: build
  script:
    - mvn $MAVEN_CLI_OPTS compile

test:
  stage: test
  script:
    - mvn $MAVEN_CLI_OPTS test

publish:
  stage: publish
  script:
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

### Projet Maven multi-modules avec des jobs parallèles {#multi-module-maven-project-with-parallel-jobs}

Pour les projets plus importants avec plusieurs modules, vous pouvez utiliser des jobs parallèles pour accélérer le processus de construction :

```yaml
default:
  image: maven:3.8.5-openjdk-17
  cache:
    paths:
      - .m2/repository/
      - target/

variables:
  MAVEN_CLI_OPTS: "-s .m2/settings.xml --batch-mode"
  MAVEN_OPTS: "-Dmaven.repo.local=.m2/repository"

stages:
  - build
  - test
  - publish

build:
  stage: build
  script:
    - mvn $MAVEN_CLI_OPTS compile

test:
  stage: test
  parallel:
    matrix:
      - MODULE: [module1, module2, module3]
  script:
    - mvn $MAVEN_CLI_OPTS test -pl $MODULE

publish:
  stage: publish
  script:
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

### Releases versionnées avec des tags {#versioned-releases-with-tags}

Cet exemple crée des releases versionnées lorsqu'un tag est poussé :

```yaml
default:
  image: maven:3.8.5-openjdk-17
  cache:
    paths:
      - .m2/repository/
      - target/

variables:
  MAVEN_CLI_OPTS: "-s .m2/settings.xml --batch-mode"
  MAVEN_OPTS: "-Dmaven.repo.local=.m2/repository"

stages:
  - build
  - test
  - publish
  - release

build:
  stage: build
  script:
    - mvn $MAVEN_CLI_OPTS compile

test:
  stage: test
  script:
    - mvn $MAVEN_CLI_OPTS test

publish:
  stage: publish
  script:
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

release:
  stage: release
  script:
    - mvn versions:set -DnewVersion=${CI_COMMIT_TAG}
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_TAG
```

### Publication conditionnelle basée sur les modifications {#conditional-publishing-based-on-changes}

Cet exemple publie des paquets uniquement lorsque certains fichiers sont modifiés :

```yaml
default:
  image: maven:3.8.5-openjdk-17
  cache:
    paths:
      - .m2/repository/
      - target/

variables:
  MAVEN_CLI_OPTS: "-s .m2/settings.xml --batch-mode"
  MAVEN_OPTS: "-Dmaven.repo.local=.m2/repository"

stages:
  - build
  - test
  - publish

build:
  stage: build
  script:
    - mvn $MAVEN_CLI_OPTS compile

test:
  stage: test
  script:
    - mvn $MAVEN_CLI_OPTS test

publish:
  stage: publish
  script:
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      changes:
        - pom.xml
        - src/**/*
```

### Intégration avec les analyses de qualité du code et de sécurité {#integration-with-code-quality-and-security-scans}

Cet exemple intègre des vérifications de qualité du code et des analyses de sécurité dans le pipeline :

```yaml
default:
  image: maven:3.8.5-openjdk-17
  cache:
    paths:
      - .m2/repository/
      - target/

variables:
  MAVEN_CLI_OPTS: "-s .m2/settings.xml --batch-mode"
  MAVEN_OPTS: "-Dmaven.repo.local=.m2/repository"

include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Code-Quality.gitlab-ci.yml

stages:
  - build
  - test
  - quality
  - publish

build:
  stage: build
  script:
    - mvn $MAVEN_CLI_OPTS compile

test:
  stage: test
  script:
    - mvn $MAVEN_CLI_OPTS test

code_quality:
  stage: quality

sast:
  stage: quality

publish:
  stage: publish
  script:
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

## Conseils utiles {#helpful-hints}

### Publier un paquet avec le même nom ou la même version {#publishing-a-package-with-the-same-name-or-version}

Lorsque vous publiez un paquet avec le même nom et la même version qu'un paquet existant, les nouveaux fichiers du paquet sont ajoutés au paquet existant. Vous pouvez toujours utiliser l'interface utilisateur ou l'API pour accéder aux anciens artefacts du paquet existant et les consulter.

Pour supprimer les anciennes versions de paquets, envisagez d'utiliser l'API des paquets ou l'interface utilisateur.

### Ne pas autoriser les paquets Maven dupliqués {#do-not-allow-duplicate-maven-packages}

{{< history >}}

- Le rôle requis a [changé](https://gitlab.com/gitlab-org/gitlab/-/issues/350682) de Developer à Maintainer dans GitLab 15.0.
- Le rôle requis a [changé](https://gitlab.com/gitlab-org/gitlab/-/issues/370471) de Maintainer à Owner dans GitLab 17.0.

{{< /history >}}

Pour empêcher les utilisateurs de publier des paquets Maven dupliqués, vous pouvez utiliser l'[API GraphQL](../../../api/graphql/reference/_index.md#packagesettings) ou l'interface utilisateur.

Dans l'interface utilisateur :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Dans la ligne **Maven** du tableau **Paquets dupliqués**, désactivez le bouton **Autoriser les doublons**.
1. Facultatif. Dans la zone de texte **Exception**, saisissez une expression régulière correspondant aux noms et versions des paquets à autoriser.

> [!note]
> Si **Autoriser les doublons** est activé, vous pouvez spécifier les noms et versions de paquets qui ne doivent pas avoir de doublons dans la zone de texte **Exception**.

Vos modifications sont automatiquement enregistrées.

### Transfert de requêtes vers Maven Central {#request-forwarding-to-maven-central}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/85299) dans GitLab 15.4 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `maven_central_request_forwarding`. Fonctionnalité désactivée par défaut.
- Le rôle requis a [changé](https://gitlab.com/gitlab-org/gitlab/-/issues/370471) de Maintainer à Owner dans GitLab 17.0.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Lorsqu'un paquet Maven n'est pas trouvé dans le registre de paquets, la requête est transmise à [Maven Central](https://search.maven.org/).

Lorsque le feature flag est activé, les administrateurs peuvent désactiver ce comportement dans les [paramètres d'intégration continue](../../../administration/settings/continuous_integration.md).

Le transfert Maven est restreint aux seuls [endpoints](#naming-convention) de niveau projet et de niveau groupe. Le endpoint au niveau de l'instance est soumis à des restrictions de nommage qui l'empêchent d'être utilisé pour des paquets ne respectant pas cette convention, et présente également un risque de sécurité trop élevé pour les attaques de type chaîne d'approvisionnement.

#### Configuration supplémentaire pour `mvn` {#additional-configuration-for-mvn}

Lorsque vous utilisez `mvn`, il existe de nombreuses façons de configurer votre projet Maven pour qu'il demande des paquets dans Maven Central depuis GitLab. Les dépôts Maven sont interrogés dans un [ordre spécifique](https://maven.apache.org/guides/mini/guide-multiple-repositories.html#repository-order). Par défaut, Maven Central est généralement vérifié en premier via le [Super POM](https://maven.apache.org/guides/introduction/introduction-to-the-pom.html#Super_POM), GitLab doit donc être configuré pour être interrogé avant maven-central.

Pour vous assurer que toutes les requêtes de paquets sont envoyées à GitLab plutôt qu'à Maven Central, vous pouvez remplacer Maven Central comme dépôt central en ajoutant une section `<mirror>` à votre `settings.xml` :

```xml
<settings>
  <servers>
    <server>
      <id>central-proxy</id>
      <configuration>
        <httpHeaders>
          <property>
            <name>Private-Token</name>
            <value><personal_access_token></value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
  </servers>
  <mirrors>
    <mirror>
      <id>central-proxy</id>
      <name>GitLab proxy of central repo</name>
      <url>https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven</url>
      <mirrorOf>central</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

### Créer des paquets Maven avec GitLab CI/CD {#create-maven-packages-with-gitlab-cicd}

Après avoir configuré votre dépôt pour utiliser le dépôt de paquets pour Maven, vous pouvez configurer GitLab CI/CD pour construire automatiquement de nouveaux paquets.

{{< tabs >}}

{{< tab title="`mvn`" >}}

Vous pouvez créer un nouveau paquet chaque fois que la branche par défaut est mise à jour.

1. Créez un fichier `ci_settings.xml` qui servira de fichier `settings.xml` pour Maven.
1. Ajoutez la section `server` avec le même ID que celui défini dans votre fichier `pom.xml`. Par exemple, utilisez `gitlab-maven` comme ID :

   ```xml
   <settings xmlns="http://maven.apache.org/SETTINGS/1.1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.1.0 http://maven.apache.org/xsd/settings-1.1.0.xsd">
     <servers>
       <server>
         <id>gitlab-maven</id>
         <configuration>
           <httpHeaders>
             <property>
               <name>Job-Token</name>
               <value>${CI_JOB_TOKEN}</value>
             </property>
           </httpHeaders>
         </configuration>
       </server>
     </servers>
   </settings>
   ```

1. Assurez-vous que votre fichier `pom.xml` inclut les éléments suivants. Vous pouvez soit laisser Maven utiliser les [variables CI/CD prédéfinies](../../../ci/variables/predefined_variables.md), comme indiqué dans cet exemple, soit coder en dur le nom d'hôte de votre serveur et l'ID de votre projet.

   ```xml
   <repositories>
     <repository>
       <id>gitlab-maven</id>
       <url>${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/maven</url>
     </repository>
   </repositories>
   <distributionManagement>
     <repository>
       <id>gitlab-maven</id>
       <url>${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/maven</url>
     </repository>
     <snapshotRepository>
       <id>gitlab-maven</id>
       <url>${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/maven</url>
     </snapshotRepository>
   </distributionManagement>
   ```

1. Ajoutez un job `deploy` à votre fichier `.gitlab-ci.yml` :

   ```yaml
   deploy:
     image: maven:3.6-jdk-11
     script:
       - 'mvn deploy -s ci_settings.xml'
     rules:
       - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
   ```

1. Poussez ces fichiers vers votre dépôt.

La prochaine fois que le job `deploy` s'exécute, il copie `ci_settings.xml` vers le répertoire personnel de l'utilisateur. Dans cet exemple :

- L'utilisateur est `root`, car le job s'exécute dans un conteneur Docker.
- Maven utilise les variables CI/CD configurées.

{{< /tab >}}

{{< tab title="`gradle`" >}}

Vous pouvez créer un paquet chaque fois que la branche par défaut est mise à jour.

1. Authentifiez-vous avec [un jeton de job CI dans Gradle](#edit-the-client-configuration).
1. Ajoutez un job `deploy` à votre fichier `.gitlab-ci.yml` :

   ```yaml
   deploy:
     image: gradle:6.5-jdk11
     script:
       - 'gradle publish'
     rules:
       - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
   ```

1. Committez les fichiers dans votre dépôt.

Lorsque le pipeline réussit, le paquet Maven est créé.

{{< /tab >}}

{{< /tabs >}}

### Validation de version {#version-validation}

La chaîne de version est validée à l'aide de l'expression régulière suivante.

```ruby
\A(?!.*\.\.)[\w+.-]+\z
```

Vous pouvez expérimenter avec l'expression régulière et tester vos chaînes de version sur [cet éditeur d'expressions régulières](https://rubular.com/r/rrLQqUXjfKEoL6).

### Utiliser des paramètres différents pour les déploiements snapshot et release {#use-different-settings-for-snapshot-and-release-deployments}

Pour utiliser des URL ou des paramètres différents pour les snapshots et les releases :

- Dans la section `<distributionManagement>` de votre fichier `pom.xml`, définissez des éléments `<repository>` et `<snapshotRepository>` séparés.

### Options de ligne de commande Maven utiles {#useful-maven-command-line-options}

Il existe quelques [options de ligne de commande Maven](https://maven.apache.org/ref/current/maven-embedder/cli.html) que vous pouvez utiliser lors de l'exécution de tâches avec GitLab CI/CD.

- La progression du transfert de fichiers peut rendre les logs CI difficiles à lire. L'option `-ntp,--no-transfer-progress` a été ajoutée dans [3.6.1](https://maven.apache.org/docs/3.6.1/release-notes.html#User_visible_Changes). Alternativement, consultez `-B,--batch-mode` [ou des modifications de niveau de journalisation inférieures.](https://stackoverflow.com/questions/21638697/disable-maven-download-progress-indication)

- Spécifiez où trouver le fichier `pom.xml` (`-f,--file`) :

  ```yaml
  package:
    script:
      - 'mvn --no-transfer-progress -f helloworld/pom.xml package'
  ```

- Spécifiez où trouver les paramètres utilisateur (`-s,--settings`) à la place de [l'emplacement par défaut](https://maven.apache.org/settings.html). Il existe également une option `-gs,--global-settings` :

  ```yaml
  package:
    script:
      - 'mvn -s settings/ci.xml package'
  ```

### Commandes CLI prises en charge {#supported-cli-commands}

Le dépôt Maven de GitLab prend en charge les commandes CLI suivantes :

{{< tabs >}}

{{< tab title="`mvn`" >}}

- `mvn deploy` : publiez votre paquet dans le registre de paquets.
- `mvn install` : installez les paquets spécifiés dans votre projet Maven.
- `mvn dependency:get` : installez un paquet spécifique.

{{< /tab >}}

{{< tab title="`gradle`" >}}

- `gradle publish` : publiez votre paquet dans le registre de paquets.
- `gradle build` : assemble et teste ce projet.

{{< /tab >}}

{{< /tabs >}}

## Dépannage {#troubleshooting}

Lors de l'utilisation de paquets Maven dans GitLab, vous pouvez rencontrer un problème. Pour résoudre de nombreux problèmes courants, essayez ces étapes :

- Vérifier l'authentification : assurez-vous que vos jetons d'authentification sont corrects et n'ont pas expiré.
- Vérifier les permissions : confirmez que vous disposez des permissions nécessaires pour publier ou installer des paquets.
- Valider les paramètres Maven : vérifiez attentivement votre fichier `settings.xml` pour vous assurer qu'il est correctement configuré.
- Examiner les logs GitLab CI/CD : pour les problèmes CI/CD, examinez attentivement les job logs à la recherche de messages d'erreur.
- S'assurer de l'exactitude des URL des endpoints : vérifiez que vous utilisez les URL des endpoints correctes pour votre projet ou groupe.
- Utilisez l'option -s avec les commandes `mvn` : exécutez toujours les commandes Maven avec l'option `-s`, par exemple `mvn package -s settings.xml`. Sans cette option, les paramètres d'authentification ne sont pas appliqués et Maven pourrait ne pas trouver les paquets.

### Vider le cache {#clear-the-cache}

Pour améliorer les performances, les clients mettent en cache les fichiers liés à un paquet. Si vous rencontrez des problèmes, videz le cache avec ces commandes :

{{< tabs >}}

{{< tab title="`mvn`" >}}

```shell
rm -rf ~/.m2/repository
```

{{< /tab >}}

{{< tab title="`gradle`" >}}

```shell
rm -rf ~/.gradle/caches # Or replace ~/.gradle with your custom GRADLE_USER_HOME
```

{{< /tab >}}

{{< /tabs >}}

### Examiner les journaux de trace réseau {#review-network-trace-logs}

Si vous rencontrez des problèmes avec le dépôt Maven, vous pouvez examiner les journaux de trace réseau. L'examen des journaux de trace réseau fournit des messages d'erreur plus détaillés, que les clients Maven n'incluent pas par défaut.

Par exemple, essayez d'exécuter `mvn deploy` localement avec un jeton PAT et utilisez ces options :

```shell
mvn deploy \
-Dorg.slf4j.simpleLogger.log.org.apache.maven.wagon.providers.http.httpclient=trace \
-Dorg.slf4j.simpleLogger.log.org.apache.maven.wagon.providers.http.httpclient.wire=trace
```

> [!warning]
> Lorsque vous définissez ces options, toutes les requêtes réseau sont journalisées et une grande quantité de données est générée.

### Vérifier vos paramètres Maven {#verify-your-maven-settings}

Si vous rencontrez des problèmes dans CI/CD liés au fichier `settings.xml`, essayez d'ajouter une tâche de script supplémentaire ou un job pour [vérifier les paramètres effectifs](https://maven.apache.org/plugins/maven-help-plugin/effective-settings-mojo.html).

Le plugin d'aide peut également fournir des [propriétés système](https://maven.apache.org/plugins/maven-help-plugin/system-mojo.html), y compris les variables d'environnement :

```yaml
mvn-settings:
  script:
    - 'mvn help:effective-settings'

package:
  script:
    - 'mvn help:system'
    - 'mvn package'
```

### Erreur `401 Unauthorized` lors de la tentative de publication d'un paquet {#401-unauthorized-error-when-trying-to-publish-a-package}

Cela indique généralement un problème d'authentification. Vérifiez que :

- Votre jeton d'authentification est valide et n'a pas expiré.
- Vous utilisez le bon type de jeton (jeton d'accès personnel, jeton de déploiement ou jeton de job CI).
- Le jeton dispose des permissions nécessaires (`api`, `read_api` ou `read_repository`).
- Pour les projets Maven, vous utilisez l'option `-s` avec vos commandes mvn (par exemple, `mvn deploy -s settings.xml`). Sans cette option, Maven n'appliquera pas les paramètres d'authentification de votre fichier `settings.xml`, ce qui entraîne des erreurs d'accès non autorisé.

### Erreur `400 Bad Request` avec le message « Validation failed: Version is invalid » {#400-bad-request-error-with-message-validation-failed-version-is-invalid}

GitLab a des exigences spécifiques concernant les chaînes de version. Assurez-vous que votre version suit le format :

```plaintext
^(?!.*\.\.)(?!.*\.$)[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*(\+[0-9A-Za-z-]+)?$
```

Par exemple, « 1.0.0 », « 1.0-SNAPSHOT » et « 1.0.0-alpha » sont valides, mais « 1..0 » ou « 1.0\. » ne le sont pas.

### Erreur `403 Forbidden` lors de la tentative de publication d'un paquet {#403-forbidden-error-when-trying-to-publish-a-package}

L'erreur `403 Forbidden` avec le message `Authorization failed` indique généralement un problème d'authentification ou de permissions. Vérifiez que :

- Vous utilisez le bon type de jeton (jeton d'accès personnel, jeton de déploiement ou jeton de job CI/CD). Pour plus d'informations, consultez [S'authentifier auprès du registre de paquets](#authenticate-to-the-package-registry).
- Le jeton dispose des permissions nécessaires. Seuls les utilisateurs ayant le rôle Developer, Maintainer ou Owner peuvent publier des paquets. Pour plus d'informations, consultez [les permissions GitLab](../../permissions.md#project-packages-and-registries).
- Le paquet que vous publiez n'est pas protégé par des règles de protection des push. Pour plus d'informations sur les règles de protection des paquets, consultez [comment protéger un paquet](../package_registry/package_protection_rules.md#protect-a-package).

### Erreurs `Artifact already exists` lors de la publication {#artifact-already-exists-errors-when-publishing}

Cette erreur se produit lorsque vous essayez de publier une version de paquet qui existe déjà. Pour résoudre :

- Incrémentez la version de votre paquet avant de le publier.
- Si vous utilisez des versions SNAPSHOT, assurez-vous d'autoriser les remplacements SNAPSHOT dans votre configuration.

### Le paquet publié n'apparaît pas dans l'interface utilisateur {#published-package-not-appearing-in-the-ui}

Si vous venez de publier un paquet, quelques instants peuvent être nécessaires avant qu'il apparaisse. S'il n'apparaît toujours pas :

- Vérifiez que vous disposez des permissions nécessaires pour afficher les paquets.
- Vérifiez que le paquet a été publié avec succès en examinant les logs CI/CD ou la sortie Maven.
- Assurez-vous de regarder dans le bon projet ou groupe.

### Conflits de dépendances du dépôt Maven {#maven-repository-dependency-conflicts}

Les conflits de dépendances peuvent être résolus en :

- Définissant explicitement les versions dans votre `pom.xml`.
- Utilisant la section de gestion des dépendances de Maven pour contrôler les versions.
- Utilisant la balise `<exclusions>` pour exclure les dépendances transitives conflictuelles.

### Erreur `Unable to find valid certification path to requested target` {#unable-to-find-valid-certification-path-to-requested-target-error}

Il s'agit généralement d'un problème de certificat SSL. Pour résoudre :

- Assurez-vous que votre JDK fait confiance au certificat SSL du serveur GitLab.
- Si vous utilisez un certificat auto-signé, ajoutez-le au truststore de votre JDK.
- En dernier recours, vous pouvez désactiver la vérification SSL dans les paramètres Maven. Non recommandé pour la production.

### Erreurs de pipeline `No plugin found for prefix` {#no-plugin-found-for-prefix-pipeline-errors}

Cela signifie généralement que Maven ne trouve pas le plugin. Pour résoudre :

- Assurez-vous que le plugin est correctement défini dans votre `pom.xml`.
- Vérifiez que votre configuration CI/CD utilise le bon fichier de paramètres Maven.
- Vérifiez que votre pipeline a accès à tous les dépôts nécessaires.
