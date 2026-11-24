---
stage: AI Clients
group: Duo Chat
info: This page is maintained by Developer Relations, author @dnsmichi, see <https://handbook.gitlab.com/handbook/marketing/developer-relations/developer-advocacy/content/#maintained-documentation>
description: AI 기반 기능 및 기능.
title: GitLab Duo 사용 사례
---

다음 사용 사례는 GitLab Duo를 사용한 실용적인 예제, 연습, 워크플로를 제공합니다. 다음 방법을 알아봅니다:

- 기존 소스 코드를 리팩터링합니다.
- GitLab Duo 근본 원인 분석을 사용하여 실패한 작업을 문제 해결합니다.
- 보안 취약성을 해결합니다.

> [!note]
> GitLab Self-Managed를 사용하는 경우: GitLab Duo를 사용하려면 최상의 사용자 경험과 결과를 위해 GitLab 17.2 이상이 필요합니다. 이전 버전도 계속 작동할 수 있습니다. 그러나 사용 환경이 저하될 수 있습니다.

## GitLab Duo를 사용하여 개발 과제 해결 {#use-gitlab-duo-to-solve-development-challenges}

### C# 애플리케이션으로 시작 {#start-with-a-c-application}

이 예제에서는 C# IDE를 열고 [GitLab Duo가 활성화됨](turn_on_off.md)을 확인하며 더 효율적으로 GitLab Duo AI 기반 기능을 사용하는 방법을 탐색합니다.

#### GitLab REST API 쿼리를 위한 CLI 도구 {#cli-tool-for-querying-the-gitlab-rest-api}

<i class="fa-youtube-play" aria-hidden="true"></i> [GitLab Duo Coffee Chat을 시청하세요: C# 시작하기](https://www.youtube.com/watch?v=AdRtX9L--Po)
<!-- Video published on 2024-01-30 -->

과제는 GitLab REST API를 쿼리하기 위한 CLI 도구를 만드는 것입니다.

- GitLab Duo Chat에 새로운 C# 프로젝트를 시작하는 방법을 묻고 dotNET CLI를 사용하는 방법을 알아봅니다:

  ```markdown
  How can I get started creating an empty C# console application in VS Code?
  ```

- 코드 제안을 사용하여 새로운 코드 주석으로 REST API 클라이언트를 생성합니다:

  ```c#
  // Connect to a REST API and print the response
  ```

- 생성된 소스 코드에 설명이 필요할 수 있습니다. `/explain` 코드 작업을 사용하여 REST API 호출이 어떻게 작동하는지 이해합니다.

코드 제안 주석에서 소스 코드가 생성된 후 CI/CD를 구성해야 합니다.

- Chat은 C#을 위한 `.gitignore` 파일의 모범 사례를 도와줄 수 있습니다:

  ```markdown
  Show a .gitignore and .gitlab-ci.yml configuration for a C# project.
  ```

- CI/CD 작업이 실패하면 근본 원인 분석을 사용하여 [실패한 CI/CD 작업을 문제 해결](../gitlab_duo_chat/examples.md#troubleshoot-failed-cicd-jobs-with-root-cause-analysis)합니다. 또는 오류 메시지를 GitLab Duo Chat에 복사하여 도움을 요청할 수 있습니다:

  ```markdown
  Explain the CI/CD error: The current .NET SDK does not support targeting
  .NET 8.0
  ```

- 나중에 테스트를 만들려면 GitLab Duo에 `/refactor` 코드 작업을 사용하여 선택한 코드를 함수로 리팩터링하도록 요청합니다.

- Chat은 프로그래밍 언어별 키워드, 함수 또는 C# 컴파일러 오류도 설명할 수 있습니다.

  ```markdown
  Can you explain async and await in C# with practical examples?

  explain error CS0122: 'Program' is inaccessible due to its protection level
  ```

- `/tests` 코드 작업을 사용하여 테스트를 생성합니다.

다음 질문은 C# 솔루션에서 생성된 테스트를 어디에 놓을지입니다. 초보자의 경우 가져오기 문제를 피하려면 애플리케이션 및 테스트 프로젝트가 동일한 솔루션 수준에 있어야 한다는 것을 알지 못할 수 있습니다.

- GitLab Duo Chat은 프롬프트 질문을 문의하고 개선하여 도움을 줄 수 있습니다:

  ```markdown
  In C# and VS Code, how can I add a reference to a project from a test project?

  Provide the XML configuration which I can add to a C# .csproj file to add a
  reference to another project in the existing solution?
  ```

- 프롬프트를 개선하여 더 나은 결과를 얻어야 하는 경우도 있습니다. `/refactor into the public class` 프롬프트는 나중에 테스트 프로젝트에서 액세스할 수 있는 코드에 대한 제안을 생성합니다.

  ```markdown
  /refactor into the public class
  ```

- `/refactor` 코드 작업을 사용하여 Chat에 `.gitlab-ci.yml` 파일에서 테스트를 실행하는 방법을 물을 수도 있습니다.

  ```markdown
  /refactor add a job to run tests (the test project)
  ```

리소스:

- [소스 코드가 포함된 프로젝트](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-01-29)

### C++ 애플리케이션 개선 {#improve-a-c-application}

#### SQLite를 사용하여 C++ 애플리케이션 리팩터링 {#refactor-a-c-application-with-sqlite}

이 예제에서는 단일 main 함수를 포함하는 기존 소스 코드가 있습니다. 코드를 반복하며 테스트할 수 없습니다.

<i class="fa-youtube-play" aria-hidden="true"></i> [GitLab Duo Coffee Chat을 시청하세요: C++, SQLite 및 CMake](https://www.youtube.com/watch?v=zGOo1jzQ5zM)
<!-- Video published on 2024-01-10 -->

소스 코드를 재사용 가능하고 테스트 가능한 함수로 리팩터링하려면:

1. GitLab Duo가 활성화된 VS Code 또는 Web IDE를 엽니다.
1. 소스 코드를 선택하고 GitLab Duo Chat에 요청할 개선된 프롬프트를 사용하여 함수로 리팩터링합니다:

   ```markdown
   /refactor into functions
   ```

   이 리팩터링 단계는 전체 선택한 소스 코드에 대해 작동하지 않을 수 있습니다.

1. 리팩터링 전략을 기능 블록으로 분할합니다. 예를 들어 데이터베이스의 모든 삽입, 업데이트 및 삭제 작업에 대해 반복합니다.

1. 새로 생성된 함수에 대한 테스트를 생성하려면 소스 코드를 다시 선택하고 `/tests` 코드 작업을 사용합니다. 테스트 프레임워크에 대한 특정 프롬프트 지침을 포함합니다:

   ```markdown
   /tests using the CTest test framework
   ```

1. 애플리케이션이 `Boost.Test` 프레임워크를 대신 사용하는 경우 프롬프트를 개선합니다:

   ```markdown
   /tests using the Boost.Test framework
   ```

리소스:

- [소스 코드가 포함된 프로젝트](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-01-09)

#### C++ 함수를 객체 지향 코드로 리팩터링 {#refactor-c-functions-into-object-oriented-code}

이 예제에서는 기존 소스 코드가 함수로 래핑되었습니다. 향후 더 많은 데이터베이스 유형을 지원하려면 코드를 클래스 및 객체 상속으로 리팩터링해야 합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> [GitLab Duo Coffee Chat의 단계별 설명을 시청하세요: C++ 함수를 `OOP` 클래스로 리팩터링](https://www.youtube.com/watch?v=Z9EJh0J9358)
<!-- Video published on 2024-01-24 -->

##### 클래스 작업 시작 {#start-working-on-the-class}

- GitLab Duo Chat에 기본 데이터베이스 클래스에 대한 객체 지향 패턴을 구현하고 SQLite 클래스에 상속하는 방법을 문의합니다:

  ```markdown
  Explain a generic database implementation using a base class, and SQLite specific class using C++. Provide source examples and steps to follow.
  ```

- 학습 곡선에는 GitLab Duo Chat에 순수 가상 함수 및 구현 클래스의 가상 함수 재정의에 대해 문의하는 것이 포함됩니다.

  ```markdown
  What is a pure virtual function, and what is required for the developer inheriting from that class?
  ```

- 코드 작업은 코드 리팩터링을 도울 수 있습니다. C++ 헤더 파일의 함수를 선택하고 개선된 프롬프트를 사용합니다:

  ```markdown
  /refactor into class with public functions, and private path/db attributes. Inherit from the base class DB

  /refactor into a base class with pure virtual functions called DB. Remove the SQLite specific parts.
  ```

- GitLab Duo Chat은 생성자 오버로딩, 객체 초기화 및 공유 포인터를 사용한 최적화된 메모리 관리도 안내합니다.

  ```markdown
  How to add a function implementation to a class in a cpp file?

  How to pass values to class attributes through the class constructor call?
  ```

##### 더 나은 답변 찾기 {#find-better-answers}

- 다음 질문은 충분한 컨텍스트를 제공하지 않았습니다.

  ```markdown
  Should I use virtual override instead of just override?
  ```

- 더 나은 답변을 얻으려면 더 많은 컨텍스트를 추가해 봅니다.

  ```markdown
  When implementing a pure virtual function in an inherited class, should I use virtual function override, or just function override? Context is C++.
  ```

- 상대적으로 복잡한 질문에는 새로 생성된 클래스에서 객체를 인스턴스화하고 특정 함수를 호출하는 방법이 포함됩니다.

  ```markdown
  How to instantiate an object from a class in C++, call the constructor with the SQLite DB path and call the functions. Prefer pointers.
  ```

- 결과는 도움이 될 수 있지만 공유 포인터 및 필수 소스 코드 헤더에 대한 개선이 필요합니다.

  ```markdown
  How to instantiate an object from a class in C++, call the constructor with the SQLite DB path and call the functions. Prefer shared pointers. Explain which header includes are necessary.
  ```

- 코드 제안은 `std::shared_ptr` 포인터 산술의 올바른 구문을 생성하고 코드 품질을 개선합니다.

  ```c++
  // Define the SQLite path in a variable, default value database.db

  // Create a shared pointer for the SQLite class

  // Open a database connection using OpenConnection
  ```

##### 코드 리팩터링 {#refactor-your-code}

- 소스 코드를 리팩터링한 후 컴파일러 오류가 발생할 수 있습니다. Chat에 설명을 요청합니다.

  ```markdown
  Explain the error: `db` is a private member of `SQLiteDB`
  ```

- 특정 SQL 쿼리 문자열은 더 효율적인 편집을 위해 여러 줄 문자열로 리팩터링해야 합니다.

  ```c++
  std::string sql = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL)";
  ```

- 소스 코드를 선택하고 `/refactor` 코드 작업을 사용합니다:

  ```markdown
  /refactor into a stringstream with multiple lines
  ```

- 또한 C++에서 정적 함수를 사용하는 클래스로 유틸리티 함수를 리팩터링한 다음 Chat에 함수를 호출하는 방법을 물을 수 있습니다.

  ```markdown
  /refactor into a class providing static functions

  How to call the static functions in the class?
  ```

소스 코드를 리팩터링한 후 더 많은 데이터베이스 유형에 대한 기초가 구축되고 전반적인 코드 품질이 향상됩니다.

리소스:

- [소스 코드가 포함된 프로젝트](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-01-23)

### Kotlin 애플리케이션 설명, 테스트 및 리팩터링 {#explain-test-and-refactor-a-kotlin-application}

이 예제에서 [Kotlin 코드 생성 프롬프트](#kotlin-code-generation-prompts)의 어드벤처 애플리케이션을 분석하고 리팩터링 및 테스트로 개선해야 합니다.

현재 소스 코드는 다음과 같습니다:

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

1. IDE에서 소스 코드를 선택한 다음 오른쪽 클릭하여 GitLab Duo Chat이 코드를 설명하도록 합니다.
1. 버그, 최적화 팁 또는 취약성에 대해 자세히 알아보려면 프롬프트를 개선합니다:

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

1. `/tests` 명령을 사용하여 Chat에 선택한 코드에 대한 테스트를 생성하도록 요청합니다:

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

모든 것이 테스트되었는지 확인한 후 Chat에 선택한 코드를 리팩터링하도록 요청합니다:

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

리팩터링된 소스 코드는 다음과 같습니다:

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

### PowerShell 시작 {#get-started-with-powershell}

> [!note]
> PowerShell 지원은 [실험](../project/repository/code_suggestions/supported_extensions.md#add-support-for-more-languages)적입니다.

1. GitLab Duo Chat을 사용하여 현재 디렉터리의 파일 크기를 인쇄하는 PowerShell 스크립트를 시작하는 방법을 문의합니다.

   ```markdown
   How to get started with a PowerShell script that prints the file size of the current directory?
   ```

   또는 코드 제안을 사용하여 소스 코드를 생성할 수 있습니다.

1. 다음 내용으로 새 스크립트 `get-file-sizes.ps1`을 만듭니다:

   ```powershell
   # Collect the files in a directory and print their size
   ```

1. 코드 제안이 프롬프트를 완료할 때까지 기다린 다음 다양한 출력 형식을 실험하기 위해 다음 프롬프트를 추가합니다:

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

1. 다양한 내보내기 형식에 대한 프롬프트로 단계를 반복하거나 코드 제안 자동 완성을 사용합니다. 예를 들어:

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

## 취약성 설명 및 해결 {#explain-and-resolve-vulnerabilities}

### C 코드의 취약성 {#vulnerabilities-in-c-code}

이 예제에서 C에서 탐지된 보안 취약성을 GitLab Duo의 도움으로 수정해야 합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> [GitLab Duo Coffee Chat의 단계별 설명을 시청하세요: 취약성 해결 과제 #1](https://www.youtube.com/watch?v=Ypwx4lFnHP0)
<!-- Video published on 2024-01-30 -->

[이 소스 코드 스니펫](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-01-30/-/blob/4685e4e1c658565ae956ad9befdfcc128e60c6cf/src/main-vulnerable-source.c)은 [버퍼 오버플로우](https://en.wikipedia.org/wiki/Buffer_overflow)로 인한 보안 취약성을 도입합니다:

```c
    strcpy(region, "Hello GitLab Duo Vulnerability Resolution challenge");

    printf("Contents of region: %s\n", region);
```

[SAST 보안 스캐너](../application_security/sast/_index.md)는 문제를 탐지하고 보고할 수 있습니다. [취약성 설명](../application_security/analyze/duo.md)을 사용하여 문제를 이해합니다. 취약성 해결을 통해 MR을 생성할 수 있습니다. 제안된 변경 사항이 요구 사항에 맞지 않거나 문제를 야기할 수 있는 경우 코드 제안 및 Chat을 사용하여 개선할 수 있습니다. 예를 들어:

1. GitLab Duo가 활성화된 VS Code 또는 Web IDE를 열고 지침이 있는 주석을 추가합니다:

   ```c
       // Avoid potential buffer overflows

       // Possible AI-generated code below
       strncpy(region, "Hello GitLab Duo Vulnerability Resolution challenge", pagesize);
       region[pagesize-1] = '\0';
       printf("Contents of region: %s\n", region);
   ```

1. 제안된 코드를 삭제하고 다른 주석을 사용하여 대체 방법을 사용합니다.

   ```c
       // Avoid potential buffer overflows using snprintf()

       // Possible AI-generated code below
       snprintf(region, pagesize, "Hello GitLab Duo Vulnerability Resolution challenge");

       printf("Contents of region: %s\n", region);
   ```

1. GitLab Duo Chat을 사용하여 질문합니다. `/refactor` 코드 작업은 다양한 제안을 생성할 수 있습니다. 특정 알고리즘 또는 함수를 선호하는 경우 프롬프트를 개선합니다:

   ```markdown
   /refactor using snprintf
   ```

리소스:

- 소스 코드가 포함된 프로젝트: [GitLab Duo Coffee Chat 2024-01-30 - 취약성 해결 과제](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-01-30)

## GitLab에 대한 질문에 답변 {#answer-questions-about-gitlab}

이 예제에서 과제는 GitLab Duo Chat을 사용하여 문제를 해결하는 것입니다.

<i class="fa-youtube-play" aria-hidden="true"></i> [GitLab Duo Coffee Chat의 단계별 설명을 시청하세요: GitLab Duo Chat 과제로 문제 해결](https://www.youtube.com/watch?v=Ypwx4lFnHP0)
<!-- Video published on 2024-02-02 -->

- GitLab Duo Chat을 사용하여 CI/CD 오류를 설명할 수 있습니다.

  ```markdown
  Explain this CI/CD error: build.sh: line 14: go command not found
  ```

- 한 두 단어만 입력하면 조급할 때 어떻게 됩니까?

  ```markdown
  labels

  issue labels
  ```

  GitLab Duo Chat은 더 많은 컨텍스트를 요청합니다.

- 질문을 문제를 설명하고 해결책을 요청하는 완전한 문장으로 개선합니다.

  ```markdown
  Explain labels in GitLab. Provide an example for efficient usage.
  ```

리소스:

- [소스 코드가 포함된 프로젝트](https://gitlab.com/gitlab-da/use-cases/ai/gitlab-duo-coffee-chat-2024/gitlab-duo-coffee-chat-2024-02-01)

## 근본 원인 분석 사용 사례 {#root-cause-analysis-use-cases}

근본 원인 분석을 사용하여 CI/CD 작업 실패의 근본 원인을 파악합니다. 다음 예제는 일반적인 오류를 보여주며 근본 원인을 찾고 수정하는 연습을 권장합니다.

자세한 내용은 블로그 게시물 [GitLab Duo 개발을 참조하세요: CI/CD 파이프라인 수정을 위해 AI와 근본 원인 분석 혼합](https://about.gitlab.com/blog/developing-gitlab-duo-blending-ai-and-root-cause-analysis-to-fix-ci-cd/).

### 누락된 Go 런타임 분석 {#analyze-missing-go-runtime}

CI/CD 작업은 `image` 특성에서 생성된 컨테이너에서 실행할 수 있습니다. 컨테이너가 프로그래밍 언어 런타임을 제공하지 않으면 `script` 섹션이 `go` 이진 파일을 참조하여 실패합니다. 예를 들어 오류 메시지 `/bin/sh: eval: line 149: go: not found`를 이해하고 수정해야 합니다. `go` 명령이 컨테이너의 런타임 컨텍스트에서 발견되지 않으면 여러 가지 이유 때문일 수 있습니다:

- 작업은 `alpine`과 같은 최소 컨테이너 이미지를 사용하며 Go 언어 런타임이 설치되지 않았습니다.
- 작업은 CI/CD 구성에 지정된 잘못된 기본 컨테이너 이미지를 사용하거나 `default` 키워드를 사용합니다.
- 작업은 컨테이너 이미지 대신 셸 실행기를 사용합니다. 호스트 운영 체제가 손상되었거나 Go 언어 런타임이 설치되지 않았거나 구성되지 않았습니다.

[과제: 근본 원인 분석 - Go GitLab 릴리스 가져오기](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-challenges/root-cause-analysis/challenge-root-cause-analysis-go-gitlab-release-fetcher)는 Go Tanuki 앱으로 CI/CD 문제를 분석하고 수정하는 연습을 제공합니다. 이 연습에서 `build` 및 `docker-build` 작업이 실패하고 있습니다. 문제를 수정하면 CI/CD 파이프라인이 성공하고 `build` 작업이 출력을 인쇄합니다. `solution/` 디렉터리는 두 가지 가능한 해결책을 제공합니다.

## GitLab Duo를 사용하여 GitLab에 기여 {#use-gitlab-duo-to-contribute-to-gitlab}

GitLab Duo 사용은 GitLab 코드베이스에 기여하고 고객이 더 효율적으로 기여하는 방법에 중점을 둡니다.

GitLab 코드베이스는 크며 때때로 복잡한 알고리즘 또는 애플리케이션별 구현을 이해해야 합니다.

### 프론트엔드에 기여: 프로필 설정 {#contribute-to-frontend-profile-settings}

이 예제에서 과제는 GitLab 프로필 페이지를 업데이트하고 소셜 네트워크 설정을 개선하는 것입니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 여기에서 녹화를 시청하세요: [GitLab Duo Coffee Chat: 코드 제안 및 Chat을 사용하여 GitLab에 기여](https://www.youtube.com/watch?v=TauP7soXj-E)
<!-- Video published on 2024-02-23 -->

GitLab Duo Chat을 사용하여 코드를 설명하고 리팩터링하며 테스트를 생성할 수 있습니다. 코드 제안은 기존 코드를 완성하는 데 도움이 되며 Ruby, Go 또는 VueJS의 새로운 함수 및 알고리즘을 생성할 수 있습니다.

1. `/explain` 코드 작업을 사용하여 선택한 코드 섹션을 설명하고 HAML 템플릿이 어떻게 작동하는지 알아봅니다.
1. 코드 작업 프롬프트를 개선할 수 있으며 대신 `/explain how HAML rendering works`을 문의할 수 있습니다

또는 Chat 프롬프트에 직접 작성할 수 있습니다. 예를 들어:

```markdown
how to populate a select in haml
```

리팩터링 예제에는 다음이 포함됩니다:

1. `/refactor into a HAML dropdown`
1. 기존 UI 양식 코드를 검사한 후 프롬프트를 `/refactor into a HAML dropdown with a form select`로 개선합니다

GitLab Duo Chat은 오류 메시지 앞에 오류 디버깅을 도왔습니다:

```markdown
Explain this error: undefined method `icon` for
```

## 코드 생성 프롬프트 {#code-generation-prompts}

다음 예제는 GitLab Duo의 [코드 생성](../project/repository/code_suggestions/_index.md#best-practices-for-code-generation) 프롬프트를 [지원되는 언어](../project/repository/code_suggestions/supported_extensions.md)에 제공합니다. 여러 줄 주석을 사용하여 코드 생성 프롬프트를 개선할 수 있습니다.

예제는 [GitLab Duo 프롬프트 프로젝트](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts)에 저장되어 있으며 개발자 관계 팀이 유지 관리합니다. 이 예제는 테스트를 거쳤습니다. 환경에 맞게 검토하고 조정해야 합니다.

### C 코드 생성 프롬프트 {#c-code-generation-prompts}

I/O, 성능, 디스크 사용량 및 TCP 지연을 수집하고 해당 출력을 인쇄하는 Linux 통계 도구를 만듭니다. 전체 예제는 블로그 게시물 [GitLab Duo를 사용한 효율적인 AI 기반 코드 제안 상위 팁 블로그 게시물](https://about.gitlab.com/blog/top-tips-for-efficient-ai-powered-code-suggestions-with-gitlab-duo/#code-suggestions-flow-with-comments)을 참조하세요.

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`c` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/c)에서 사용할 수 있습니다.

### C++ 코드 생성 프롬프트 {#c-code-generation-prompts-1}

HTTP 클라이언트로 작동하는 CLI 애플리케이션을 만듭니다.

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

분산 파일 노드를 관리하는 애플리케이션을 만듭니다.

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

`XDP` 커널 이벤트에 연결하여 네트워크 트래픽을 측정하는 eBPF 프로그램을 만듭니다. Linux 커널에서만 작동합니다.

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`c++` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/c++)에서 사용할 수 있습니다.

### `C#` 코드 생성 프롬프트 {#c-code-generation-prompts-2}

다양한 센서에서 의료 분석기 앱을 만들고 `MSSQL`에 데이터를 저장합니다.

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`c#` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/c%23)에서 사용할 수 있습니다.

### CSS 코드 생성 프롬프트 {#css-code-generation-prompts}

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`css` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/css)에서 사용할 수 있습니다.

### Go 코드 생성 프롬프트 {#go-code-generation-prompts}

클러스터의 컨테이너, Pod 및 서비스의 상태를 읽고 인쇄하는 Kubernetes 관찰성 애플리케이션을 만듭니다.

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

<i class="fa-youtube-play" aria-hidden="true"></i> 여기에서 녹화를 시청하세요: [GitLab Duo Coffee Chat: Go 및 Kubernetes 관찰성을 사용한 코드 생성 과제](https://www.youtube.com/watch?v=ORpRqp-A9hQ)
<!-- Video published on 2024-03-27. Maintainer: Developer Relations. -->

Redis와 유사한 메모리 내 키 값 저장소를 만듭니다. 전체 설명을 보려면 블로그 게시물 [GitLab Duo를 사용한 효율적인 AI 기반 코드 제안 상위 팁](https://about.gitlab.com/blog/top-tips-for-efficient-ai-powered-code-suggestions-with-gitlab-duo/#iterate-faster-with-code-generation) 블로그 게시물을 참조하세요.

```go
// Create an in-memory key value store, similar to Redis
// Provide methods to
// set/unset keys
// update values
// list/print with filters
// Use BoltDB as external library
```

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`go` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/go)에서 사용할 수 있습니다.

### Java 코드 생성 프롬프트 {#java-code-generation-prompts}

메트릭에 대한 다양한 데이터 소스가 있는 데이터 분석 애플리케이션을 만듭니다. 데이터 쿼리 및 집계를 위한 API를 제공합니다.

```java
// Create a data analytics app
// Parse different input sources and their values
// Store the metrics in a columnar format
// Provide an API to query and aggregate data
```

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`java` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/java)에서 사용할 수 있습니다.

### JavaScript 코드 생성 프롬프트 {#javascript-code-generation-prompts}

ReactJS에서 날짜-시간 선택기를 사용하여 직원을 위한 유급 휴가 신청 애플리케이션을 만듭니다.

```javascript
// Create a Paid Time Off app for users
// Create a date-time picker in ReactJS
// Provide start and end options
// Show public holidays based on the selected country
// Send the request to a server API
```

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`javascript` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/javascript)에서 사용할 수 있습니다.

### HTML 코드 생성 프롬프트 {#html-code-generation-prompts}

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`html` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/html)에서 사용할 수 있습니다.

### Kotlin 코드 생성 프롬프트 {#kotlin-code-generation-prompts}

텍스트 어드벤처를 생성하고 보물을 검색합니다. 시각적 도우미를 추가하고 게임 오버를 위해 무작위 타이머 함정을 사용합니다.

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`kotlin` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/kotlin)에서 사용할 수 있습니다.

### PHP 코드 생성 프롬프트 {#php-code-generation-prompts}

GitLab 릴리스에 대한 RSS 피드 가져오기를 만들고 제목으로 필터링을 허용합니다.

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`php` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/php)에서 사용할 수 있습니다.

### PowerShell 코드 생성 프롬프트 {#powershell-code-generation-prompts}

디렉터리의 모든 파일을 수집하고 크기를 인쇄하는 스크립트를 만듭니다. 프롬프트를 개선하여 결과를 CSV 또는 JSON 파일에 저장합니다.

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`powershell` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/powershell)에서 사용할 수 있습니다.

### Python 코드 생성 프롬프트 {#python-code-generation-prompts}

Flask를 사용하여 REST API를 사용하여 사용자를 관리하고 SQLite에 저장하는 웹 서버를 만듭니다.

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`python` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/python)에서 사용할 수 있습니다.

### Ruby 코드 생성 프롬프트 {#ruby-code-generation-prompts}

Elasticsearch에 로그 데이터를 저장하는 로그 파서 애플리케이션을 만듭니다.

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

심각도 수준, 애플리케이션 이름 및 메시지 문자열을 지원하는 syslog 형식을 지원하는 로그 클라이언트 유틸리티 클래스를 만듭니다.

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`ruby` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/ruby)에서 사용할 수 있습니다.

### Rust 코드 생성 프롬프트 {#rust-code-generation-prompts}

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

블로그 게시물 [AI의 도움으로 고급 Rust 프로그래밍을 배우세요](https://about.gitlab.com/blog/learn-advanced-rust-programming-with-a-little-help-from-ai-code-suggestions/)의 예제인 RSS 피드 리더 앱을 만듭니다.

```rust
    // Create a function that iterates over the source array
    // and fetches the data using HTTP from the RSS feed items.
    // Store the results in a new hash map.
    // Print the hash map to the terminal.
```

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`rust` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/rust)에서 사용할 수 있습니다.

### Scala 코드 생성 프롬프트 {#scala-code-generation-prompts}

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`scala` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/scala)에서 사용할 수 있습니다.

### 셸 스크립트 코드 생성 프롬프트 {#shell-scripts-code-generation-prompts}

CPU, 메모리 및 디스크 I/O 사용량별 상위 10개 프로세스를 표시하는 `mytop.sh` 스크립트를 만듭니다. 첫 번째 코드 주석으로 시작하고 코드 제안이 나머지를 생성하도록 합니다.

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`shell` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/shell)에서 사용할 수 있습니다.

### TypeScript 코드 생성 프롬프트 {#typescript-code-generation-prompts}

IPv6 및 IPv4 주소 형식을 구문 분석하는 유틸리티 함수를 만듭니다.

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

AI로 생성된 소스 코드 예제는 GitLab Duo 프롬프트 프로젝트의 [`typescript` 디렉터리](https://gitlab.com/gitlab-da/use-cases/ai/ai-workflows-2024/gitlab-duo-prompts/-/tree/main/code-suggestions/typescript)에서 사용할 수 있습니다.

## 리소스 {#resources}

많은 사용 사례는 [GitLab Duo Coffee Chat YouTube 재생 목록](https://www.youtube.com/playlist?list=PL05JrBw4t0Kp5uj_JgQiSvHw1jQu0mSVZ)의 실습 녹화로 사용할 수 있습니다.

### 블로그 리소스 {#blog-resources}

다음 블로그 게시물은 이러한 사용 사례에 대한 자습서를 제공합니다:

- [GitLab Duo를 사용한 효율적인 AI 기반 코드 제안의 상위 팁](https://about.gitlab.com/blog/top-tips-for-efficient-ai-powered-code-suggestions-with-gitlab-duo/)
- [AI 기반 GitLab Duo Chat 사용을 위한 10가지 모범 사례](https://about.gitlab.com/blog/10-best-practices-for-using-ai-powered-gitlab-duo-chat/)
- [GitLab Duo Chat 101: GitLab에서 AI 어시스턴트를 사용하여 더 많은 작업 수행](https://about.gitlab.com/blog/gitlab-duo-chat-101-get-more-done-on-gitlab-with-our-ai-assistant/)
- [GitLab Duo 개발: AI 기능을 직접 활용하는 방법](https://about.gitlab.com/blog/developing-gitlab-duo-how-we-are-dogfooding-our-ai-features/)
- [GitLab Duo 개발: AI로 생성된 코드를 안전하게 하고 철저히 테스트](https://about.gitlab.com/blog/how-gitlab-duo-helps-secure-and-thoroughly-test-ai-generated-code/)
- [GitLab Duo 개발: CI/CD 파이프라인을 수정하기 위해 AI와 근본 원인 분석 혼합](https://about.gitlab.com/blog/developing-gitlab-duo-blending-ai-and-root-cause-analysis-to-fix-ci-cd/)
- [GitLab Duo 개발: AI 영향 분석 대시보드는 AI의 ROI를 측정합니다](https://about.gitlab.com/blog/developing-gitlab-duo-ai-impact-analytics-dashboard-measures-the-roi-of-ai/)

코드 제안 자습서 블로그 게시물은 다음 언어에 사용할 수 있습니다:

- [AI의 도움으로 Rust 배우기](https://about.gitlab.com/blog/learning-rust-with-a-little-help-from-ai-code-suggestions-getting-started/)
- [AI의 도움으로 고급 Rust 프로그래밍 배우기](https://about.gitlab.com/blog/learn-advanced-rust-programming-with-a-little-help-from-ai-code-suggestions/)
- [AI의 도움으로 Python 배우기](https://about.gitlab.com/blog/learning-python-with-a-little-help-from-ai-code-suggestions/)
- [GitLab Duo 코드 제안으로 Terraform 계획을 더 빠르게 작성하기](https://about.gitlab.com/blog/write-terraform-plans-faster-with-gitlab-duo-code-suggestions/)
- [드래곤 영역 탐험: AI의 도움으로 C++ 어드벤처 게임 빌드](https://about.gitlab.com/blog/building-a-text-adventure-using-cplusplus-and-code-suggestions/)
