---
stage: AI Clients
group: Duo Chat
info: This page is maintained by Developer Relations, author @dnsmichi, see <https://handbook.gitlab.com/handbook/marketing/developer-relations/developer-advocacy/content/#maintained-documentation>
description: "Fonctionnalités et caractéristiques natives de l'IA."
title: "Cas d'utilisation de GitLab Duo"
---

Les cas d'utilisation suivants fournissent des exemples pratiques, des exercices et des workflows avec GitLab Duo. Apprenez à :

- Refactoriser le code source existant.
- Utiliser GitLab Duo Root Cause Analysis pour résoudre les problèmes liés aux jobs ayant échoué.
- Résoudre les vulnérabilités de sécurité.

> [!note]
> Si vous utilisez GitLab Self-Managed : GitLab Duo requiert GitLab 17.2 ou une version ultérieure pour une expérience utilisateur et des résultats optimaux. Les versions antérieures peuvent continuer à fonctionner. Cependant, l'expérience peut être dégradée.

## Utiliser GitLab Duo pour relever les défis du développement {#use-gitlab-duo-to-solve-development-challenges}

### Démarrer avec une application C# {#start-with-a-c-application}

Dans ces exemples, ouvrez votre IDE C#, assurez-vous que [GitLab Duo est activé](turn_on_off.md), et découvrez comment utiliser les fonctionnalités natives de l'IA de GitLab Duo pour plus d'efficacité.

#### Outil CLI pour interroger l'API REST GitLab {#cli-tool-for-querying-the-gitlab-rest-api}

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez le [GitLab Duo Coffee Chat : démarrer avec C#](https://www.youtube.com/watch?v=AdRtX9L--Po)
<!-- Video published on 2024-01-30 -->

Le défi consiste à créer un outil CLI pour interroger l'API REST GitLab.

- Demandez à GitLab Duo Chat comment démarrer un nouveau projet C# et apprenez à utiliser la CLI dotNET :

  ```markdown
  How can I get started creating an empty C# console application in VS Code?
  ```

- Utilisez Code Suggestions pour générer un client API REST avec un nouveau commentaire de code :

  ```c#
  // Connect to a REST API and print the response
  ```

- Le code source généré peut nécessiter une explication. Utilisez la tâche de code `/explain` pour comprendre le fonctionnement des appels à l'API REST.

Une fois le code source généré à partir d'un commentaire Code Suggestions, vous devez configurer CI/CD.

- Chat peut vous aider avec les bonnes pratiques pour un fichier `.gitignore` en C# :

  ```markdown
  Show a .gitignore and .gitlab-ci.yml configuration for a C# project.
  ```

- Si votre job CI/CD échoue, utilisez Root Cause Analysis pour [résoudre les problèmes liés aux jobs CI/CD ayant échoué](../gitlab_duo_chat/examples.md#troubleshoot-failed-cicd-jobs-with-root-cause-analysis). Vous pouvez également copier le message d'erreur dans GitLab Duo Chat et demander de l'aide :

  ```markdown
  Explain the CI/CD error: The current .NET SDK does not support targeting
  .NET 8.0
  ```

- Pour créer des tests ultérieurement, demandez à GitLab Duo d'utiliser la tâche de code `/refactor` pour refactoriser le code sélectionné dans une fonction.

- Chat peut également expliquer les mots-clés et fonctions spécifiques à un langage de programmation, ou les erreurs du compilateur C#.

  ```markdown
  Can you explain async and await in C# with practical examples?

  explain error CS0122: 'Program' is inaccessible due to its protection level
  ```

- Générez des tests en utilisant la tâche de code `/tests`.

La question suivante est de savoir où placer les tests générés dans les solutions C#. En tant que débutant, vous ne savez peut-être pas que l'application et les projets de test doivent exister au même niveau de solution pour éviter les problèmes d'importation.

- GitLab Duo Chat peut vous aider en posant des questions et en affinant les invites :

  ```markdown
  In C# and VS Code, how can I add a reference to a project from a test project?

  Provide the XML configuration which I can add to a C# .csproj file to add a
  reference to another project in the existing solution?
  ```

- Parfois, vous devez affiner l'invite pour obtenir de meilleurs résultats. L'invite `/refactor into the public class` crée une proposition de code accessible depuis le projet de test ultérieurement.

  ```markdown
  /refactor into the public class
  ```

- Vous pouvez également utiliser la tâche de code `/refactor` pour demander à Chat comment exécuter des tests dans le fichier `.gitlab-ci.yml`.

  ```markdown
  /refactor add a job to run tests (the test project)
  ```

Ressources :

- [Projet avec le code source](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-01-29)

### Améliorer une application C++ {#improve-a-c-application}

#### Refactoriser une application C++ avec SQLite {#refactor-a-c-application-with-sqlite}

Dans cet exemple, il existe un code source avec une seule fonction principale. Il répète du code et ne peut pas être testé.

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez le [GitLab Duo Coffee Chat : C++, SQLite et CMake](https://www.youtube.com/watch?v=zGOo1jzQ5zM)
<!-- Video published on 2024-01-10 -->

Pour refactoriser le code source en fonctions réutilisables et testables :

1. Ouvrez VS Code ou le Web IDE avec GitLab Duo activé.
1. Sélectionnez le code source et utilisez une invite affinée pour demander à GitLab Duo Chat de le refactoriser en fonctions :

   ```markdown
   /refactor into functions
   ```

   Cette étape de refactorisation peut ne pas fonctionner pour l'intégralité du code source sélectionné.

1. Divisez la stratégie de refactorisation en blocs fonctionnels. Par exemple, itérez sur toutes les opérations d'insertion, de mise à jour et de suppression dans la base de données.

1. Pour générer des tests pour les fonctions nouvellement créées, sélectionnez à nouveau le code source et utilisez la tâche de code `/tests`. Incluez une invite spécifique avec des instructions pour le framework de test :

   ```markdown
   /tests using the CTest test framework
   ```

1. Si votre application utilise le framework `Boost.Test` à la place, affinez l'invite :

   ```markdown
   /tests using the Boost.Test framework
   ```

Ressources :

- [Projet avec le code source](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-01-09)

#### Refactoriser les fonctions C++ en code orienté objet {#refactor-c-functions-into-object-oriented-code}

Dans cet exemple, le code source existant a été encapsulé dans des fonctions. Pour prendre en charge davantage de types de bases de données à l'avenir, le code doit être refactorisé en classes avec héritage d'objets.

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez la présentation de ces étapes dans le [GitLab Duo Coffee Chat : refactoriser les fonctions C++ en classes `OOP`](https://www.youtube.com/watch?v=Z9EJh0J9358)
<!-- Video published on 2024-01-24 -->

##### Commencer à travailler sur la classe {#start-working-on-the-class}

- Demandez à GitLab Duo Chat comment implémenter un modèle orienté objet pour une classe de base de données et en hériter dans une classe SQLite :

  ```markdown
  Explain a generic database implementation using a base class, and SQLite specific class using C++. Provide source examples and steps to follow.
  ```

- La courbe d'apprentissage comprend des questions à GitLab Duo Chat sur les fonctions virtuelles pures et les surcharges de fonctions virtuelles dans la classe d'implémentation.

  ```markdown
  What is a pure virtual function, and what is required for the developer inheriting from that class?
  ```

- Les tâches de code peuvent aider à refactoriser le code. Sélectionnez les fonctions dans le fichier d'en-tête C++ et utilisez une invite affinée :

  ```markdown
  /refactor into class with public functions, and private path/db attributes. Inherit from the base class DB

  /refactor into a base class with pure virtual functions called DB. Remove the SQLite specific parts.
  ```

- GitLab Duo Chat guide également sur la surcharge des constructeurs, l'initialisation des objets et la gestion optimisée de la mémoire avec les pointeurs partagés.

  ```markdown
  How to add a function implementation to a class in a cpp file?

  How to pass values to class attributes through the class constructor call?
  ```

##### Trouver de meilleures réponses {#find-better-answers}

- La question suivante n'a pas fourni suffisamment de contexte.

  ```markdown
  Should I use virtual override instead of just override?
  ```

- À la place, essayez d'ajouter plus de contexte pour obtenir de meilleures réponses.

  ```markdown
  When implementing a pure virtual function in an inherited class, should I use virtual function override, or just function override? Context is C++.
  ```

- Une question relativement complexe porte sur la manière d'instancier un objet à partir de la classe nouvellement créée et d'appeler des fonctions spécifiques.

  ```markdown
  How to instantiate an object from a class in C++, call the constructor with the SQLite DB path and call the functions. Prefer pointers.
  ```

- Le résultat peut être utile, mais des améliorations étaient nécessaires pour les pointeurs partagés et les en-têtes de code source requis.

  ```markdown
  How to instantiate an object from a class in C++, call the constructor with the SQLite DB path and call the functions. Prefer shared pointers. Explain which header includes are necessary.
  ```

- Code Suggestions aide à générer la syntaxe correcte pour l'arithmétique de pointeur `std::shared_ptr` et à améliorer la qualité du code.

  ```c++
  // Define the SQLite path in a variable, default value database.db

  // Create a shared pointer for the SQLite class

  // Open a database connection using OpenConnection
  ```

##### Refactoriser votre code {#refactor-your-code}

- Après avoir refactorisé le code source, des erreurs de compilation peuvent survenir. Demandez à Chat de les expliquer.

  ```markdown
  Explain the error: `db` is a private member of `SQLiteDB`
  ```

- Une chaîne de requête SQL spécifique doit être refactorisée en chaîne multiligne pour une édition plus efficace.

  ```c++
  std::string sql = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL)";
  ```

- Sélectionnez le code source et utilisez la tâche de code `/refactor` :

  ```markdown
  /refactor into a stringstream with multiple lines
  ```

- Vous pouvez également refactoriser des fonctions utilitaires en une classe avec des fonctions statiques en C++, puis demander à Chat comment les appeler.

  ```markdown
  /refactor into a class providing static functions

  How to call the static functions in the class?
  ```

Après avoir refactorisé le code source, la base pour davantage de types de bases de données est établie et la qualité globale du code est améliorée.

Ressources :

- [Projet avec le code source](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-01-23)

### Expliquer, tester et refactoriser une application Kotlin {#explain-test-and-refactor-a-kotlin-application}

Dans cet exemple, l'application d'aventure issue des [invites de génération de code Kotlin](#kotlin-code-generation-prompts) doit être analysée et améliorée grâce à la refactorisation et aux tests.

Le code source actuel ressemble à ceci :

```kotlin
package org.example

// Create a text adventure
// Search for the golden LEGO brick
// Add visual helpers
// Use random timer traps for game over
// Create a text adventure
fun createTextAdventure() {
    println("Welcome to the golden LEGO brick adventure!")
    println("You find yourself in a dimly lit room. What do you do?")

    var gameOver = false
    while (!gameOver) {
        println("1. Search for the golden LEGO brick")
        println("2. Examine the room")
        println("3. Quit")

        val choice = readLine()?.toIntOrNull() ?: 0
        when (choice) {
            1 -> searchForBrick()
            2 -> examineRoom()
            3 -> {
                println("Goodbye!")
                gameOver = true
            }
            else -> println("Invalid choice. Please try again.")
        }
    }
}

fun searchForBrick() {
    println("You search the room carefully, looking for any sign of the golden LEGO brick.")
    if (Math.random() < 0.2) {
        println("Congratulations! You found the golden LEGO brick!")
    } else {
        println("Your search turns up nothing. You'll have to try again.")
    }
}

fun examineRoom() {
    println("You look around the room, taking in the details.")
    println("The room is dimly lit, with shadows in the corners.")
    println("There is a door to the north and a table in the center of the room.")
}

fun main() {
    createTextAdventure()
}
```

1. Sélectionnez le code source dans l'IDE, puis faites un clic droit pour que GitLab Duo Chat explique le code.
1. Affinez les invites pour en savoir plus sur les bugs, les conseils d'optimisation ou les vulnérabilités :

   ```markdown
   /explain focus on bugs and improvements

   The provided code is a simple text adventure game written in Kotlin. It allows the user to search for a golden LEGO brick or
   examine the room. While the code is functional, there are a few potential bugs and areas for improvement:

   1. Potential Bugs:

   The searchForBrick() function uses Math.random() to determine if the player finds the golden LEGO brick. However, this function
   does not handle the case where the player finds the brick. The game will continue indefinitely, even after the player has found
   the brick.

   2. Improvements:

   Game Over Condition: The game should have a proper game over condition when the player finds the golden LEGO brick. This could
   be achieved by introducing a boolean flag or a separate game state to track whether the brick has been found.
   ```

1. Utilisez la commande `/tests` pour demander à Chat de générer des tests pour le code sélectionné :

   ```markdown
   /tests

   To test the code, you can use JUnit for Kotlin. Here are some tests you can write:

     import org.junit.jupiter.api.Test
     import java.io.ByteArrayInputStream
     import java.io.ByteArrayOutputStream
     import java.io.PrintStream

     class TextAdventureTest {

         private val standardOut = System.out
         private val standardIn = System.`in`

         @Test
         fun `test searchForBrick success`() {
             val outContent = ByteArrayOutputStream()
             System.setOut(PrintStream(outContent))

             searchForBrick()

             val output = outContent.toString().trim()
             assert(output.contains("Congratulations! You found the golden LEGO brick!"))

             System.setOut(standardOut)
         }

      ...
     }
   ```

Une fois que vous vous êtes assuré que tout est testé, demandez à Chat de refactoriser le code sélectionné :

```markdown
/refactor fix bugs, improve UX

...

Improvements:

Extracted the menu printing logic into a separate printMenu function for better code organization and readability.
Used Random.nextDouble() instead of Math.random() for better compatibility with Kotlin's standard library.
Added a prompt for the user to enter their choice after printing the menu.
Removed the unnecessary gameOver variable initialization, as it's already assigned a value in the createTextAdventure function.
Added a comment in the searchForBrick function to remind you to add additional logic or game over condition if needed.
These changes should improve the code's readability, maintainability, and user experience.
```

Le code source refactorisé peut ressembler à ceci :

```kotlin
package org.example

import kotlin.random.Random

// Create a text adventure
// Search for the golden LEGO brick
// Add visual helpers
// Use random timer traps for game over
// Create a text adventure
fun createTextAdventure() {
    println("Welcome to the golden LEGO brick adventure!")
    println("You find yourself in a dimly lit room. What do you do?")

    var gameOver = false
    while (!gameOver) {
        printMenu()
        val choice = readLine()?.toIntOrNull()
        when (choice) {
            1 -> searchForBrick()
            2 -> examineRoom()
            3 -> {
                println("Goodbye!")
                gameOver = true
            }
            else -> println("Invalid choice. Please try again.")
        }
    }
}

fun printMenu() {
    println("1. Search for the golden LEGO brick")
    println("2. Examine the room")
    println("3. Quit")
    print("Enter your choice: ")
}

fun searchForBrick() {
    println("You search the room carefully, looking for any sign of the golden LEGO brick.")
    if (Random.nextDouble() < 0.2) {
        println("Congratulations! You found the golden LEGO brick!")
        // Add additional logic or game over condition here
    } else {
        println("Your search turns up nothing. You'll have to try again.")
    }
}

fun examineRoom() {
    println("You look around the room, taking in the details.")
    println("The room is dimly lit, with shadows in the corners.")
    println("There is a door to the north and a table in the center of the room.")
}

fun main() {
    createTextAdventure()
}
```

### Démarrer avec PowerShell {#get-started-with-powershell}

> [!note]
> La prise en charge de PowerShell est en [version expérimentale](../project/repository/code_suggestions/supported_extensions.md#add-support-for-more-languages).

1. Utilisez GitLab Duo Chat pour savoir comment démarrer avec un script PowerShell qui affiche la taille des fichiers du répertoire actuel.

   ```markdown
   How to get started with a PowerShell script that prints the file size of the current directory?
   ```

   Vous pouvez également utiliser Code Suggestions pour générer le code source.

1. Créez un nouveau script `get-file-sizes.ps1` avec le contenu suivant :

   ```powershell
   # Collect the files in a directory and print their size
   ```

1. Attendez que Code Suggestions complète l'invite, puis ajoutez les invites suivantes pour expérimenter différents formats de sortie :

   ```powershell
   # Collect the files in a directory and print their size

   $directory = Read-Host -Prompt "Enter the directory path to get file sizes"
   $files = Get-ChildItem -Path $directory -File
   foreach ($file in $files) {
       $fileSize = [Math]::Round(($file.Length / 1KB), 2)
       Write-Host "$($file.Name) - $fileSize KB"
   }

   # Repeat the code above but store the results in a CSV file
   ```

1. Répétez les étapes avec des invites pour différents formats d'exportation, ou utilisez la saisie automatique de Code Suggestions. Par exemple :

   ```powershell
   # Collect the files in a directory and print their size

   $directory = Read-Host -Prompt "Enter the directory path to get file sizes"
   $files = Get-ChildItem -Path $directory -File
   foreach ($file in $files) {
       $fileSize = [Math]::Round(($file.Length / 1KB), 2)
       Write-Host "$($file.Name) - $fileSize KB"
   }

   # Repeat the code above but store the results in a CSV file
   $csvFile = "$directory\file-sizes.csv"
   $fileData = foreach ($file in $files) {
       [PSCustomObject]@{
           FileName = $file.Name
           FileSize = [Math]::Round(($file.Length / 1KB), 2)
       }
   }
   $fileData | Export-Csv -Path $csvFile -NoTypeInformation
   Write-Host "File sizes saved to $csvFile"

   # Repeat the code above but store the results in a JSON file
   $jsonFile = "$directory\file-sizes.json"
   $fileData | ConvertTo-Json | Out-File -FilePath $jsonFile
   Write-Host "File sizes saved to $jsonFile"

   # Repeat the code above but store the results in a XML file
   $xmlFile = "$directory\file-sizes.xml"
   $fileData | ConvertTo-Xml -NoTypeInformation | Out-File -FilePath $xmlFile
   Write-Host "File sizes saved to $xmlFile"

   # Repeat the code above but store the results in a HTML file
   $htmlFile = "$directory\file-sizes.html"
   $fileData | ConvertTo-Html -Property FileName, FileSize | Out-File -FilePath $htmlFile
   Write-Host "File sizes saved to $htmlFile"

   # Repeat the code above but store the results in a TXT file
   $txtFile = "$directory\file-sizes.txt"
   $fileData | Out-File -FilePath $txtFile
   Write-Host "File sizes saved to $txtFile"
   ```

## Expliquer et résoudre les vulnérabilités {#explain-and-resolve-vulnerabilities}

### Vulnérabilités dans le code C {#vulnerabilities-in-c-code}

Dans cet exemple, les vulnérabilités de sécurité détectées en C doivent être corrigées avec l'aide de GitLab Duo.

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez la présentation de ces étapes [GitLab Duo Coffee Chat : défi de résolution de vulnérabilités n° 1](https://www.youtube.com/watch?v=Ypwx4lFnHP0)
<!-- Video published on 2024-01-30 -->

[Cet extrait de code source](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-01-30/-/blob/4685e4e1c658565ae956ad9befdfcc128e60c6cf/src/main-vulnerable-source.c) introduit une vulnérabilité de sécurité avec un [dépassement de tampon](https://en.wikipedia.org/wiki/Buffer_overflow) :

```c
    strcpy(region, "Hello GitLab Duo Vulnerability Resolution challenge");

    printf("Contents of region: %s\n", region);
```

[Les scanners de sécurité SAST](../application_security/sast/_index.md) peuvent détecter et signaler le problème. Utilisez [Vulnerability Explanation](../application_security/analyze/duo.md) pour comprendre le problème. Vulnerability Resolution aide à générer une merge request. Si les modifications suggérées ne correspondent pas aux exigences ou peuvent entraîner des problèmes, vous pouvez utiliser Code Suggestions et Chat pour les affiner. Par exemple :

1. Ouvrez VS Code ou le Web IDE avec GitLab Duo activé et ajoutez un commentaire avec des instructions :

   ```c
       // Avoid potential buffer overflows

       // Possible AI-generated code below
       strncpy(region, "Hello GitLab Duo Vulnerability Resolution challenge", pagesize);
       region[pagesize-1] = '\0';
       printf("Contents of region: %s\n", region);
   ```

1. Supprimez le code suggéré et utilisez un commentaire différent pour utiliser une méthode alternative.

   ```c
       // Avoid potential buffer overflows using snprintf()

       // Possible AI-generated code below
       snprintf(region, pagesize, "Hello GitLab Duo Vulnerability Resolution challenge");

       printf("Contents of region: %s\n", region);
   ```

1. Utilisez GitLab Duo Chat pour poser des questions. La tâche de code `/refactor` peut générer différentes suggestions. Si vous préférez un algorithme ou une fonction spécifique, affinez l'invite :

   ```markdown
   /refactor using snprintf
   ```

Ressources :

- Projet avec le code source : [GitLab Duo Coffee Chat 2024-01-30 - Défi de résolution de vulnérabilités](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-01-30)

## Répondre aux questions sur GitLab {#answer-questions-about-gitlab}

Dans cet exemple, le défi consiste à utiliser GitLab Duo Chat pour résoudre des problèmes.

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez la présentation de ces étapes dans le [GitLab Duo Coffee Chat : résoudre des problèmes avec GitLab Duo Chat Challenge](https://www.youtube.com/watch?v=Ypwx4lFnHP0)
<!-- Video published on 2024-02-02 -->

- Vous pouvez utiliser GitLab Duo Chat pour expliquer les erreurs CI/CD.

  ```markdown
  Explain this CI/CD error: build.sh: line 14: go command not found
  ```

- Que se passe-t-il lorsque vous êtes impatient et que vous saisissez seulement un ou deux mots ?

  ```markdown
  labels

  issue labels
  ```

  GitLab Duo Chat demande davantage de contexte.

- Reformulez votre question en une phrase complète, décrivant le problème et demandant une solution.

  ```markdown
  Explain labels in GitLab. Provide an example for efficient usage.
  ```

Ressources :

- [Projet avec le code source](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-02-01)

## Cas d'utilisation de Root Cause Analysis {#root-cause-analysis-use-cases}

Utilisez Root Cause Analysis pour déterminer la cause première d'un échec de job CI/CD. Les exemples suivants illustrent les erreurs courantes et vous encouragent à dupliquer le projet et à vous exercer à trouver et corriger la cause première.

Pour plus d'informations, consultez le billet de blog [Developing GitLab Duo : Blending AI and Root Cause Analysis to fix CI/CD pipelines](https://about.gitlab.com/blog/developing-gitlab-duo-blending-ai-and-root-cause-analysis-to-fix-ci-cd/).

### Analyser l'absence du runtime Go {#analyze-missing-go-runtime}

Les jobs CI/CD peuvent être exécutés dans des conteneurs, générés à partir de l'attribut `image` fourni. Si le conteneur ne fournit pas de runtime de langage de programmation, les sections `script` exécutées qui font référence au binaire `go` échouent. Par exemple, le message d'erreur `/bin/sh: eval: line 149: go: not found` doit être compris et corrigé. Si la commande `go` est introuvable dans le contexte d'exécution du conteneur, plusieurs raisons peuvent expliquer cela :

- Le job utilise une image de conteneur minimale comme `alpine`, et le runtime du langage Go n'a pas été installé.
- Le job utilise la mauvaise image de conteneur par défaut spécifiée dans la configuration CI/CD, ou utilise le mot-clé `default`.
- Le job utilise l'exécuteur shell au lieu de l'image de conteneur. Le système d'exploitation hôte est défaillant, n'a pas le runtime du langage Go installé ou n'est pas configuré.

Le projet [Challenge : Root Cause Analysis - Go GitLab Release Fetcher](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-challenges/root-cause-analysis/challenge-root-cause-analysis-go-gitlab-release-fetcher) fournit un exercice pour analyser et corriger les problèmes CI/CD avec une application Go Tanuki. Dans cet exercice, les jobs `build` et `docker-build` échouent. Une fois le problème résolu, le pipeline CI/CD réussit et le job `build` affiche une sortie. Le répertoire `solution/` fournit deux solutions possibles.

## Utiliser GitLab Duo pour contribuer à GitLab {#use-gitlab-duo-to-contribute-to-gitlab}

L'utilisation de GitLab Duo se concentre sur la contribution à la base de code GitLab et sur la manière dont les clients peuvent contribuer plus efficacement.

La base de code GitLab est volumineuse et nécessite de comprendre des algorithmes parfois complexes ou des implémentations spécifiques aux applications.

### Contribuer au frontend : paramètres du profil {#contribute-to-frontend-profile-settings}

Dans cet exemple, le défi consiste à mettre à jour la page de profil GitLab et à améliorer les paramètres des réseaux sociaux.

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez l'enregistrement ici : [GitLab Duo Coffee Chat : contribuer à GitLab à l'aide de Code Suggestions et de Chat](https://www.youtube.com/watch?v=TauP7soXj-E)
<!-- Video published on 2024-02-23 -->

Vous pouvez utiliser GitLab Duo Chat pour expliquer et refactoriser le code, et générer des tests. Code Suggestions aide à compléter le code existant et peut générer de nouvelles fonctions et de nouveaux algorithmes en Ruby, Go ou VueJS.

1. Utilisez la tâche de code `/explain` pour expliquer les sections de code sélectionnées et apprendre comment fonctionnent les templates HAML.
1. Vous pouvez affiner les invites de tâche de code et demander à la place `/explain how HAML rendering works`

Vous pouvez également écrire directement dans l'invite de chat, par exemple :

```markdown
how to populate a select in haml
```

Les exemples de refactorisation portent sur les éléments suivants :

1. `/refactor into a HAML dropdown`
1. Après avoir inspecté le code du formulaire UI existant, affinez l'invite vers `/refactor into a HAML dropdown with a form select`

GitLab Duo Chat a aidé au débogage des erreurs en préfixant le message d'erreur :

```markdown
Explain this error: undefined method `icon` for
```

## Invites de génération de code {#code-generation-prompts}

Les exemples suivants fournissent des invites de [génération de code](../project/repository/code_suggestions/_index.md#best-practices-for-code-generation) pour les [langages pris en charge](../project/repository/code_suggestions/supported_extensions.md) dans GitLab Duo. Vous pouvez utiliser des commentaires multilignes pour affiner les invites de génération de code.

Les exemples sont stockés dans le [projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts), maintenu par l'équipe Developer Relations. Ces exemples ont été testés et fonctionnent correctement. Vous devez les examiner et les adapter à votre environnement.

### Invites de génération de code C {#c-code-generation-prompts}

Créez un outil de statistiques Linux qui collecte les E/S, les performances, l'utilisation du disque et la latence TCP, et affiche leurs résultats. Pour un exemple complet, consultez le billet de blog [Top tips for efficient AI-powered Code Suggestions with GitLab Duo](https://about.gitlab.com/blog/top-tips-for-efficient-ai-powered-code-suggestions-with-gitlab-duo/#code-suggestions-flow-with-comments).

```c
// Create a Linux statistic tool
// Collect IO, performance, disk usage, TCP latency
// Print summaries

// Import required headers
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <sys/statfs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>


int main() {
    struct stat statbuf;

    if (stat("/etc", &statbuf) != 0) {
        perror("stat");
        return 1;
    }

    printf("IO Block Size: %ld\n", statbuf.st_blksize);

    // TODO: add CPU usage, disk usage, network latency measurements

```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `c` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/c).

### Invites de génération de code C++ {#c-code-generation-prompts-1}

Créez une application CLI faisant office de client HTTP.

```c++
// Create a CLI app as HTTP client
// Create a main function
// Include all headers
// Read program options: URL, API endpoint, basic auth

#include <iostream>
#include <curl/curl.h>
#include <string>

int main(int argc, char** argv) {
  std::string url;
  std::string endpoint;
  std::string username;
  std::string password;

  // Parse command line options
  // ...

  CURL* curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // Set up basic auth
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERPWD, (username + ":" + password).c_str());

    CURLcode res = curl_easy_perform(curl);

    if(res != CURLE_OK) {
      std::cerr << "Request failed: " << curl_easy_strerror(res) << std::endl;
    }

    curl_easy_cleanup(curl);
  }

  return 0;
}
```

Créez une application pour gérer des nœuds de fichiers distribués.

```c++
// Create an application to manage distributed file nodes
// Provide an overview the health state of nodes
// Use OOP patterns to define the base file node
// Add specific filesystems inherited from the base file

class FileNode {
public:
    std::string name;
    std::string ipAddress;
    int port;
    HealthState healthState;

    FileNode(std::string name, std::string ipAddress, int port)
        : name(name), ipAddress(ipAddress), port(port), healthState(HealthState::Healthy) {}

    void setHealthState(HealthState state) {
        healthState = state;
    }
};

class LocalFileNode : public FileNode {
public:
    std::string mountPoint;

    LocalFileNode(std::string name, std::string mountPoint)
        : FileNode(name, "127.0.0.1", 0), mountPoint(mountPoint) {}
};

class NetworkFileNode : public FileNode {
public:
    std::string user;
    std::string password;

    NetworkFileNode(std::string name, std::string ipAddress, int port, std::string user, std::string password)
        : FileNode(name, ipAddress, port), user(user), password(password) {}
};

int main(){

}
```

Créez un programme eBPF qui s'attache aux événements noyau `XDP` pour mesurer le trafic réseau. Fonctionne uniquement sur les noyaux Linux.

```c++
// Create an eBPF program which attaches to XDP kernel events
// Count all packets by IP address
// Print a summary
// Include necessary headers

#include <bpf/bpf.h>

struct data {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
};

BPF_TABLE("array", int, long, counts, 1024);

int xdp_prog(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void*)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end) {
            counts.increment(ip->saddr);
        }
    }

    return XDP_PASS;
}
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `c++` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/c++).

### Invites de génération de code `C#` {#c-code-generation-prompts-2}

Créez une application d'analyse médicale à partir de différents capteurs et stockez les données dans `MSSQL`.

```c#
// Create a medical analyzer app
// Collect data from different sensors
// Store data in MSSQL
// Provide methods to access the sensor data

using System.Data.SqlClient;

namespace MedicalAnalyzer
{
    public class SensorDataStore
    {
        private SqlConnection connection;

        public SensorDataStore()
        {
            // Create SQL Server connection
            connection = new SqlConnection("connection string here");
        }

        public void StoreSensorData(SensorData data)
        {
            // Open connection
            connection.Open();

            // Insert sensor data into database
            var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO SensorData (Timestamp, DeviceId, Value) " +
                                  "VALUES (@timestamp, @deviceId, @value)";
            command.Parameters.AddWithValue("@timestamp", data.Timestamp);
            command.Parameters.AddWithValue("@deviceId", data.DeviceId);
            command.Parameters.AddWithValue("@value", data.Value);
            command.ExecuteNonQuery();

            // Close connection
            connection.Close();
        }

        public SensorData[] GetSensorData(DateTime startTime, DateTime endTime)
        {
            // Query database and return results
        }
    }
}
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `c#` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/c%23).

### Invites de génération de code CSS {#css-code-generation-prompts}

```css
/* Create CSS classes for animating a rainbow */

@keyframes rainbow {
    0% {
        background-position: 0% 50%;
    }
    50% {
        background-position: 100% 50%;
    }
    100% {
        background-position: 0% 50%;
    }
}

.rainbow {
    background: linear-gradient(to right, #ff0000, #ff7700, #ffff00, #00ff00, #0000ff, #8b00ff);
    background-size: 600% 600%;
    animation: rainbow 30s ease infinite;
}
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `css` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/css).

### Invites de génération de code Go {#go-code-generation-prompts}

Créez une application d'observabilité pour Kubernetes qui lit et affiche l'état des conteneurs, des pods et des services dans le cluster.

```go
// Create a client for Kubernetes observability
// Create a function that
// Reads the kubernetes configuration file from the KUBECONFIG env var
// Create kubernetes context, namespace default
// Inspect container, pod, service status and print an overview
// Import necessary packages
// Create main package

package main

import (
  "context"
  "fmt"
  "os"

  "k8s.io/client-go/kubernetes"
  "k8s.io/client-go/tools/clientcmd"

  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {

  clientset := getClientset()
  namespace := "default"

  printPods(clientset, namespace)
  printServices(clientset, namespace)
  printContainers(clientset, namespace)

}

func getClientset() *kubernetes.Clientset {

  kubeconfig := os.Getenv("KUBECONFIG")

  config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
  if err != nil {
    panic(err)
  }

  clientset, err := kubernetes.NewForConfig(config)
  if err != nil {
    panic(err)
  }

  return clientset
}

func printPods(clientset *kubernetes.Clientset, namespace string) {

  pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
  if err != nil {
    panic(err)
  }

  fmt.Printf("There are %d pods in the %s namespace\n", len(pods.Items), namespace)

}

func printServices(clientset *kubernetes.Clientset, namespace string) {

  services, err := clientset.CoreV1().Services(namespace).List(context.TODO(), metav1.ListOptions{})
  if err != nil {
    panic(err)
  }

  fmt.Printf("There are %d services in the %s namespace\n", len(services.Items), namespace)

}

// Create a function to print Containers
// Collect and print the count

func printContainers(clientset *kubernetes.Clientset, namespace string) {

    pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        panic(err)
    }

    var totalContainers int
    for _, pod := range pods.Items {
        totalContainers += len(pod.Spec.Containers)
    }

    fmt.Printf("There are %d containers in the %s namespace\n", totalContainers, namespace)

}
```

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez l'enregistrement ici : [GitLab Duo Coffee Chat : défi de génération de code avec Go et l'observabilité Kubernetes](https://www.youtube.com/watch?v=ORpRqp-A9hQ)
<!-- Video published on 2024-03-27. Maintainer: Developer Relations. -->

Créez un magasin clé-valeur en mémoire, similaire à Redis. Pour une présentation complète, consultez le billet de blog [Top tips for efficient AI-powered Code Suggestions with GitLab Duo](https://about.gitlab.com/blog/top-tips-for-efficient-ai-powered-code-suggestions-with-gitlab-duo/#iterate-faster-with-code-generation).

```go
// Create an in-memory key value store, similar to Redis
// Provide methods to
// set/unset keys
// update values
// list/print with filters
// Use BoltDB as external library
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `go` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/go).

### Invites de génération de code Java {#java-code-generation-prompts}

Créez une application d'analyse de données avec différentes sources de données pour les métriques. Fournissez une API pour les requêtes et l'agrégation de données.

```java
// Create a data analytics app
// Parse different input sources and their values
// Store the metrics in a columnar format
// Provide an API to query and aggregate data
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `java` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/java).

### Invites de génération de code JavaScript {#javascript-code-generation-prompts}

Créez une application de congés payés pour les employés en ReactJS, avec un sélecteur de date et d'heure.

```javascript
// Create a Paid Time Off app for users
// Create a date-time picker in ReactJS
// Provide start and end options
// Show public holidays based on the selected country
// Send the request to a server API
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `javascript` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/javascript).

### Invites de génération de code HTML {#html-code-generation-prompts}

```html
<!-- Create an AI knowledge base.
Describe where AI can help with efficient DevSecOps workflows.
Add a table with one Dev, one Ops, one Sec example.
-->

<table>
  <tr>
    <th>Dev</th>
    <th>Ops</th>
    <th>Sec</th>
  </tr>
  <tr>
    <td>Automated testing and continuous integration</td>
    <td>Infrastructure as code and automated provisioning</td>
    <td>Static code analysis and vulnerability scanning</td>
  </tr>
</table>
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `html` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/html).

### Invites de génération de code Kotlin {#kotlin-code-generation-prompts}

Générez une aventure textuelle et partez à la recherche d'un trésor. Ajoutez des aides visuelles et utilisez des pièges à minuterie aléatoires pour le game over.

```kotlin
package org.example

// Create a text adventure
// Search for the golden LEGO brick
// Add visual helpers
// Use random timer traps for game over
// Create a text adventure
fun createTextAdventure() {
    println("Welcome to the golden LEGO brick adventure!")
    println("You find yourself in a dimly lit room. What do you do?")

    var gameOver = false
    while (!gameOver) {
        println("1. Search for the golden LEGO brick")
        println("2. Examine the room")
        println("3. Quit")

        val choice = readLine()?.toIntOrNull() ?: 0
        when (choice) {
            1 -> searchForBrick()
            2 -> examineRoom()
            3 -> {
                println("Goodbye!")
                gameOver = true
            }
            else -> println("Invalid choice. Please try again.")
        }
    }
}

fun searchForBrick() {
    println("You search the room carefully, looking for any sign of the golden LEGO brick.")
    if (Math.random() < 0.2) {
        println("Congratulations! You found the golden LEGO brick!")
    } else {
        println("Your search turns up nothing. You'll have to try again.")
    }
}

fun examineRoom() {
    println("You look around the room, taking in the details.")
    println("The room is dimly lit, with shadows in the corners.")
    println("There is a door to the north and a table in the center of the room.")
}

fun main() {
    createTextAdventure()
}
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `kotlin` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/kotlin).

### Invites de génération de code PHP {#php-code-generation-prompts}

Créez un outil de récupération de flux RSS pour les releases GitLab, avec la possibilité de filtrer par titre.

```php
// Create a web form to show GitLab releases
// Fetch the RSS feed from https://about.gitlab.com/atom.xml
// Provide filter options for the title

$feedUrl = 'https://about.gitlab.com/atom.xml';

$xml = simplexml_load_file($feedUrl);

$titleFilter = $_GET['titleFilter'];

echo '<h1>GitLab Releases</h1>';
echo '<ul>';
foreach ($xml->entry as $entry) {
    $title = $entry->title;
    if (empty($titleFilter) || strpos($title, $titleFilter) !== false) {
        echo '<li>' . $title . '</li>';
    }
}
echo '</ul>';

```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `php` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/php).

### Invites de génération de code PowerShell {#powershell-code-generation-prompts}

Créez un script qui collecte tous les fichiers d'un répertoire et affiche leur taille. Affinez l'invite pour stocker les résultats dans un fichier CSV ou JSON.

```powershell
# Collect the files in a directory and print their size

$directory = Read-Host -Prompt "Enter the directory path to get file sizes"
$files = Get-ChildItem -Path $directory -File
foreach ($file in $files) {
    $fileSize = [Math]::Round(($file.Length / 1KB), 2)
    Write-Host "$($file.Name) - $fileSize KB"
}

# Repeat the code above but store the results in a CSV file

$csvFile = "$directory\file-sizes.csv"
$fileData = foreach ($file in $files) {
    [PSCustomObject]@{
        FileName = $file.Name
        FileSize = [Math]::Round(($file.Length / 1KB), 2)
    }
}
$fileData | Export-Csv -Path $csvFile -NoTypeInformation
Write-Host "File sizes saved to $csvFile"

# Repeat the code above but store the results in a JSON file

$jsonFile = "$directory\file-sizes.json"
$fileData | ConvertTo-Json | Out-File -FilePath $jsonFile
Write-Host "File sizes saved to $jsonFile"
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `powershell` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/powershell).

### Invites de génération de code Python {#python-code-generation-prompts}

Créez un serveur web utilisant Flask pour gérer les utilisateurs via l'API REST et les stocker dans SQLite.

```python
# Create a Flask webserver
# Add REST API entrypoints to manage users by ID
# Implement create, update, delete functions
# User data needs to be stored in SQlite, create table if not exists
# Run the server on port 8080, support TLS
# Print required packages for requirements.txt in a comment.
# Use Python 3.10 as default

# Potential AI-generated code below
import flask
from flask import request
import sqlite3

app = flask.Flask(__name__)

# Create SQLite database and users table if not exists
conn = sqlite3.connect('users.db')
conn.execute('''CREATE TABLE IF NOT EXISTS users
         (id INTEGER PRIMARY KEY, name TEXT, email TEXT)''')

@app.route('/users', methods=['POST'])
def create_user():
  # Get user data from request
  name = request.form['name']
  email = request.form['email']

  # Insert user into database
  conn.execute('INSERT INTO users (name, email) VALUES (?, ?)', (name, email))

  return 'User created successfully'

@app.route('/users/<int:id>', methods=['PUT'])
def update_user(id):
  # Get user data from request
  name = request.form['name']
  email = request.form['email']

  # Update user in database
  conn.execute('UPDATE users SET name = ?, email = ? WHERE id = ?', (name, email, id))

  return 'User updated successfully'

@app.route('/users/<int:id>', methods=['DELETE'])
def delete_user(id):
  # Delete user from database
  conn.execute('DELETE FROM users WHERE id = ?', (id,))

  return 'User deleted successfully'

if __name__ == '__main__':
  # Required packages - flask, sqlite3
  app.run(host='0.0.0.0', port=8080, ssl_context='adhoc')

```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `python` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/python).

### Invites de génération de code Ruby {#ruby-code-generation-prompts}

Créez une application d'analyse de journaux qui stocke les données de journaux dans Elasticsearch.

```ruby
# Create a Ruby app as log parser
# Provide hooks to replace sensitive strings in log lines
# Format the logs and store them in Elasticsearch

# Potential AI-generated code below
require 'logger'
require 'elasticsearch'

class LogParser
  attr_reader :logger

  def initialize
    @logger = Logger.new(STDOUT)
    @elasticsearch = Elasticsearch::Client.new
  end

  def parse_and_store(logs)
    sanitized_logs = sanitize_logs(logs)
    formatted_logs = format_logs(sanitized_logs)
    store_in_elasticsearch(formatted_logs)
  end

  private

  def sanitize_logs(logs)
    logs.map { |line| sanitize_line(line) }
  end

  def sanitize_line(line)
    # replace sensitive data
    line.gsub(/\d{16}/, '[REDACTED]')
  end

  def format_logs(logs)
    logs.map { |line| "#{Time.now}: #{line}" }
  end

  def store_in_elasticsearch(logs)
    logs.each { |log| @elasticsearch.index(index: 'app-logs', document: log) }
  end
end
```

Créez une classe utilitaire de client de journalisation qui prend en charge le format syslog avec les niveaux de gravité, le nom de l'application et la chaîne de message.

```ruby
# Create Logging utility class
# Define default log level as attribute
# Add method for logging, inputs: level, app, message
# Print the data with formatted date and time in syslog format

# Potential AI-generated code below
class Logging
  attr_accessor :log_level

  def log(level, app, message)
    time = Time.now.strftime("%b %d %H:%M:%S")
    puts "#{time} #{app}[#{Process.pid}]: #{level} - #{message}"
  end
end

# Instantiate class and test the log method

# Potential AI-generated code below
logger = Logging.new
logger.log_level = :debug

logger.log(:info, 'MyApp', 'Application started - info')
logger.log(:debug, 'MyApp', 'Application started - debug')
logger.log(:error, 'MyApp', 'Application started - error')
logger.log(:fatal, 'MyApp', 'Application started - fatal')
logger.log(:warn, 'MyApp', 'Application started - warn')
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `ruby` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/ruby).

### Invites de génération de code Rust {#rust-code-generation-prompts}

```rust
// Query the GitLab REST API
// Get all open merge requests for gitlab-org/gitlab

use serde_json::Value;

fn main() {

    let client = reqwest::blocking::Client::new();
    let url = "https://gitlab.com/api/v4/projects/278964/merge_requests?state=opened";
    let response = client.get(url).send().unwrap().text().unwrap();
    let json: Value = serde_json::from_str(&response).unwrap();

    // TODO: Pagination, default fetch results: 20
    // Read the response headers to access the next page

    println!("{}", json.to_string());

    for mr in json.as_array().unwrap() {
        println!("{} - URL: {}", mr["title"], mr["web_url"]);
    }
}
```

Créez une application de lecture de flux RSS, d'après le billet de blog [Learn advanced Rust programming with a little help from AI](https://about.gitlab.com/blog/learn-advanced-rust-programming-with-a-little-help-from-ai-code-suggestions/).

```rust
    // Create a function that iterates over the source array
    // and fetches the data using HTTP from the RSS feed items.
    // Store the results in a new hash map.
    // Print the hash map to the terminal.
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `rust` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/rust).

### Invites de génération de code Scala {#scala-code-generation-prompts}

```scala
// Implement Newtons Method
// Create an object with a main function
// Add a function that implements Newtons method for solving equations
// Add a driver function which tests the implemented function
object NewtonsMethod {
  def solveEquation(f: Double => Double, df: Double => Double, x0: Double, tolerance: Double): Double = {
    var x = x0
    var error = Double.PositiveInfinity
    while (math.abs(error) > tolerance) {
      error = f(x) / df(x)
      x -= error
    }
    x
  }

  def main(args: Array[String]): Unit = {
    val f: Double => Double = x => x * x - 4
    val df: Double => Double = x => 2 * x
    val x0 = 3.0
    val tolerance = 1e-6
    val root = solveEquation(f, df, x0, tolerance)
    println(s"The root is: $root")
  }
}
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `scala` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/scala).

### Invites de génération de code pour les scripts shell {#shell-scripts-code-generation-prompts}

Créez un script `mytop.sh` qui affiche les 10 premiers processus par utilisation du CPU, de la mémoire et des E/S disque. Commencez par le premier commentaire de code et laissez Code Suggestions générer le reste.

```shell
#!/bin/bash

# Get the top 10 processes by CPU usage
top -b -n 1 | head -n 11 | awk '{print $1, $2, $3, $9}' | column -t

# Get the top 10 processes by memory usage
top -b -n 1 | head -n 11 | awk '{print $1, $2, $4, $6}' | column -t

# Get the top 10 processes by disk I/O
top -b -n 1 | head -n 11 | awk '{print $1, $2, $7, $8}' | column -t

# Get the top 10 processes by network I/O
top -b -n 1 | head -n 11 | awk '{print $1, $2, $10, $11}' | column -t

```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `shell` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/shell).

### Invites de génération de code TypeScript {#typescript-code-generation-prompts}

Créez une fonction utilitaire qui analyse les formats d'adresse IPv6 et IPv4.

```typescript
"use strict";
// Generate a TypeScript function which parses IPv6 and IPv4 address formats
// Use regular expressions
function parseAddress(address) {
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv6Regex.test(address)) {
        return {
            ipVersion: 6,
            address
        };
    }
    else if (ipv4Regex.test(address)) {
        return {
            ipVersion: 4,
            address
        };
    }
    else {
        throw new Error('Invalid IP address');
    }
}
// Test the function with random inputs
const testInputs = [
    '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    '192.168.0.1',
    'not-an-ip'
];
for (const input of testInputs) {
    try {
        const result = parseAddress(input);
        console.log(result);
    }
    catch (error) {
        console.error(`Invalid address: ${input}`);
    }
}
```

Les exemples de code source générés par l'IA sont disponibles dans le [répertoire `typescript` du projet GitLab Duo Prompts](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/typescript).

## Ressources {#resources}

Bon nombre de ces cas d'utilisation sont disponibles sous forme d'enregistrements pratiques dans la [playlist YouTube GitLab Duo Coffee Chat](https://www.youtube.com/playlist?list=PL05JrBw4t0Kp5uj_JgQiSvHw1jQu0mSVZ).

### Ressources de blog {#blog-resources}

Les billets de blog suivants fournissent des tutoriels pour ces cas d'utilisation :

- [Top tips for efficient AI-powered Code Suggestions with GitLab Duo](https://about.gitlab.com/blog/top-tips-for-efficient-ai-powered-code-suggestions-with-gitlab-duo/)
- [10 best practices for using AI-powered GitLab Duo Chat](https://about.gitlab.com/blog/10-best-practices-for-using-ai-powered-gitlab-duo-chat/)
- [GitLab Duo Chat 101 : Get more done on GitLab with our AI assistant](https://about.gitlab.com/blog/gitlab-duo-chat-101-get-more-done-on-gitlab-with-our-ai-assistant/)
- [Developing GitLab Duo : How we are dogfooding our AI features](https://about.gitlab.com/blog/developing-gitlab-duo-how-we-are-dogfooding-our-ai-features/)
- [Developing GitLab Duo : Secure and thoroughly test AI-generated code](https://about.gitlab.com/blog/how-gitlab-duo-helps-secure-and-thoroughly-test-ai-generated-code/)
- [Developing GitLab Duo : Blending AI and Root Cause Analysis to fix CI/CD pipelines](https://about.gitlab.com/blog/developing-gitlab-duo-blending-ai-and-root-cause-analysis-to-fix-ci-cd/)
- [Developing GitLab Duo : AI Impact analytics dashboard measures the ROI of AI](https://about.gitlab.com/blog/developing-gitlab-duo-ai-impact-analytics-dashboard-measures-the-roi-of-ai/)

Des billets de blog tutoriels sur Code Suggestions sont disponibles pour les langages suivants :

- [Learning Rust with a little help from AI](https://about.gitlab.com/blog/learning-rust-with-a-little-help-from-ai-code-suggestions-getting-started/)
- [Learn advanced Rust programming with a little help from AI](https://about.gitlab.com/blog/learn-advanced-rust-programming-with-a-little-help-from-ai-code-suggestions/)
- [Learning Python with a little help from AI](https://about.gitlab.com/blog/learning-python-with-a-little-help-from-ai-code-suggestions/)
- [Write Terraform plans faster with GitLab Duo Code Suggestions](https://about.gitlab.com/blog/write-terraform-plans-faster-with-gitlab-duo-code-suggestions/)
- [Explore the Dragon Realm : Build a C++ adventure game with a little help from AI](https://about.gitlab.com/blog/building-a-text-adventure-using-cplusplus-and-code-suggestions/)
