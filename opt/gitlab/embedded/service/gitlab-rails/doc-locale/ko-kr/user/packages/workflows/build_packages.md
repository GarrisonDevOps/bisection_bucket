---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 패키지 빌드
---

GitLab 패키지 레지스트리를 사용하여 다양한 패키지 형식으로 패키지를 설치하고 빌드합니다.

## Composer {#composer}

1. `my-composer-package`이라는 디렉터리를 만들고 해당 디렉터리로 이동합니다:

   ```shell
   mkdir my-composer-package && cd my-composer-package
   ```

1. [`composer init`](https://getcomposer.org/doc/03-cli.md#init)를 실행하고 프롬프트에 응답합니다.

   네임스페이스의 경우 GitLab 사용자명이나 그룹명과 같은 고유한 [네임스페이스](../../namespace/_index.md)를 입력합니다.

   `composer.json`이라는 파일이 생성됩니다:

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

### Conan 1 설치 {#install-conan-1}

사전 요구 사항:

- Conan 버전 1.x를 설치해야 합니다.

[conan.io](https://conan.io/downloads)의 지침을 따라 Conan 패키지 관리자를 로컬 개발 환경에 다운로드합니다.

설치가 완료되면 다음 명령을 실행하여 터미널에서 Conan을 사용할 수 있는지 확인합니다:

```shell
conan --version
```

Conan 버전이 출력에 인쇄됩니다:

```plaintext
Conan version 1.20.5
```

### CMake 설치 {#install-cmake}

C++와 Conan으로 개발할 때 많은 사용 가능한 컴파일러 중에서 선택할 수 있습니다. 이 예제는 CMake 빌드 시스템 생성기를 사용합니다.

CMake를 설치하려면:

- Mac의 경우 [Homebrew](https://brew.sh/)를 사용하고 `brew install cmake`를 실행합니다.
- 다른 운영 체제의 경우 [cmake.org](https://cmake.org/resources/)의 지침을 따릅니다.

설치가 완료되면 다음 명령을 실행하여 터미널에서 CMake를 사용할 수 있는지 확인합니다:

```shell
cmake --version
```

CMake 버전이 출력에 인쇄됩니다.

### 프로젝트 생성 {#create-a-project}

패키지 레지스트리를 테스트하려면 C++ 프로젝트가 필요합니다. 이미 프로젝트가 없으면 Conan [hello world 스타터 프로젝트](https://github.com/conan-io/hello)를 복제할 수 있습니다.

### Conan 1 패키지 빌드 {#build-a-conan-1-package}

패키지를 빌드하려면:

1. 터미널을 열고 프로젝트의 루트 폴더로 이동합니다.
1. `conan new`을 실행하고 패키지 이름과 버전을 지정하여 새 레시피를 생성합니다:

   ```shell
   conan new Hello/0.1 -t
   ```

1. `conan create`을 실행하여 Conan 사용자 및 채널이 포함된 레시피용 패키지를 만듭니다:

   ```shell
   conan create . mycompany/beta
   ```

   > [!note]
   > [인스턴스 원격](../conan_1_repository/_index.md#add-a-remote-for-your-instance)을 사용하는 경우 특정 [명명 규칙](../conan_1_repository/_index.md#package-recipe-naming-convention-for-instance-remotes)을 따라야 합니다.

`Hello/0.1@mycompany/beta`이라는 레시피가 포함된 패키지가 생성됩니다.

Conan 패키지 생성 및 관리에 대한 자세한 내용은 [Conan 설명서](https://docs.conan.io/en/latest/creating_packages.html)를 참조하세요.

## Conan 2 {#conan-2}

### Conan 2 설치 {#install-conan-2}

사전 요구 사항:

- Conan 버전 2.x를 설치해야 합니다. 기본 Conan 버전 2를 사용할 수 있으며 향후 개선 사항은 [에픽 8258](https://gitlab.com/groups/gitlab-org/-/work_items/8258)에서 추적할 수 있습니다.

[conan.io](https://docs.conan.io/2/installation.html)의 지침을 따라 Conan 패키지 관리자를 로컬 개발 환경에 설치합니다.

설치를 완료한 후 다음 명령을 실행하여 터미널에서 Conan을 사용할 수 있는지 확인합니다:

```shell
conan --version
```

Conan 버전이 출력에 인쇄됩니다:

```plaintext
Conan version 2.17.0
```

### Conan 2 프로필 생성 {#create-conan-2-profile}

Conan 2의 프로필을 정의해야 합니다. 이미 프로필을 정의한 경우 이 단계를 건너뜁니다.

프로필을 생성하려면 다음 명령을 실행합니다:

```shell
conan profile detect
```

프로필을 확인합니다:

```shell
conan profile list
```

명령이 출력에 프로필을 나열합니다:

```plaintext
Profiles found in the cache:
default
```

생성된 프로필은 시작하기에 충분합니다. Conan 프로필에 대한 자세한 내용은 [Conan 2 프로필](https://docs.conan.io/2/reference/config_files/profiles.html#profiles)을 참조하세요.

### CMake 설치 {#install-cmake-1}

C++와 Conan으로 개발할 때 많은 사용 가능한 컴파일러 중에서 선택할 수 있습니다. 다음 예제는 CMake 빌드 시스템 생성기를 사용합니다.

사전 요구 사항:

- CMake를 설치합니다.
  - macOS의 경우 [Homebrew](https://brew.sh/)를 설치하고 `brew install cmake`를 실행합니다.
  - 다른 운영 체제의 경우 [cmake.org](https://cmake.org/resources/)의 지침을 따릅니다.

설치가 완료되면 다음 명령으로 터미널에서 CMake를 사용할 수 있는지 확인합니다:

```shell
cmake --version
```

CMake 버전이 출력에 인쇄됩니다.

### 프로젝트 생성 {#create-a-project-1}

사전 요구 사항:

- 패키지 레지스트리를 테스트하려면 C++ 프로젝트가 있어야 합니다.

로컬 프로젝트 폴더로 이동하고 `conan new` 명령을 사용하여 `cmake_lib` 템플릿으로 `"Hello World"` C++ 라이브러리 예제 프로젝트를 생성합니다:

```shell
mkdir hello && cd hello
conan new cmake_lib -d name=hello -d version=0.1
```

더 고급 예제는 Conan 2 [예제 프로젝트](https://github.com/conan-io/examples2)를 참조하세요.

### Conan 2 패키지 빌드 {#build-a-conan-2-package}

사전 요구 사항:

- [C++ 프로젝트를 생성](#create-a-project)합니다.

패키지를 빌드하려면:

1. 이전 섹션에서 생성한 `hello` 폴더에 있는지 확인합니다.
1. `conan create`을 실행하여 Conan 사용자 및 채널이 포함된 레시피용 패키지를 만듭니다:

   ```shell
   conan create . --channel=beta --user=mycompany
   ```

`hello/0.1@mycompany/beta`이라는 레시피가 포함된 패키지가 생성됩니다.

Conan 패키지 생성 및 관리에 대한 자세한 내용은 [패키지 생성](https://docs.conan.io/2/tutorial/creating_packages)을 참조하세요.

## Maven {#maven}

### Maven 설치 {#install-maven}

필수 최소 버전은:

- Java 11.0.5+
- Maven 3.6+

[maven.apache.org](https://maven.apache.org/install.html)의 지침을 따라 로컬 개발 환경용 Maven을 다운로드하고 설치합니다. 설치가 완료된 후 다음 명령을 실행하여 터미널에서 Maven을 사용할 수 있는지 확인합니다:

```shell
mvn --version
```

출력은 다음과 유사해야 합니다:

```shell
Apache Maven 3.6.1 (d66c9c0b3152b2e69ee9bac180bb8fcc8e6af555; 2019-04-04T20:00:29+01:00)
Maven home: /Users/<your_user>/apache-maven-3.6.1
Java version: 12.0.2, vendor: Oracle Corporation, runtime: /Library/Java/JavaVirtualMachines/jdk-12.0.2.jdk/Contents/Home
Default locale: en_GB, platform encoding: UTF-8
OS name: "mac os x", version: "10.15.2", arch: "x86_64", family: "mac"
```

### Maven 패키지 빌드 {#build-a-maven-package}

1. 터미널을 열고 프로젝트를 저장할 디렉터리를 만듭니다.
1. 새 디렉터리에서 이 Maven 명령을 실행하여 새 패키지를 초기화합니다:

   ```shell
   mvn archetype:generate -DgroupId=com.mycompany.mydepartment -DartifactId=my-project -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false
   ```

   인수는:

   - `DgroupId`: 패키지를 식별하는 고유 문자열입니다. [Maven 명명 규칙](https://maven.apache.org/guides/mini/guide-naming-conventions.html)을 따릅니다.
   - `DartifactId`: `JAR`의 이름으로 `DgroupId`의 끝에 추가됩니다.
   - `DarchetypeArtifactId`: 프로젝트의 초기 구조를 만드는 데 사용되는 원형입니다.
   - `DinteractiveMode`: 배치 모드를 사용하여 프로젝트를 만듭니다(선택 사항).

이 메시지는 프로젝트가 성공적으로 설정되었음을 나타냅니다:

```shell
...
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  3.429 s
[INFO] Finished at: 2020-01-28T11:47:04Z
[INFO] ------------------------------------------------------------------------
```

명령을 실행한 폴더에 새 디렉터리가 표시되어야 합니다. 디렉터리 이름은 `DartifactId` 매개변수와 일치해야 하며, 이 경우 `my-project`입니다.

## Gradle {#gradle}

### Gradle 설치 {#install-gradle}

새 Gradle 프로젝트를 만들려면 Gradle을 설치해야 합니다. [gradle.org](https://gradle.org/install/)의 지침을 따라 로컬 개발 환경용 Gradle을 다운로드하고 설치합니다.

터미널에서 다음 명령을 실행하여 Gradle을 사용할 수 있는지 확인합니다:

```shell
gradle -version
```

기존 Gradle 프로젝트를 사용하려면 프로젝트 디렉터리에서 Linux에서 `gradlew`을 실행하거나 Windows에서 `gradlew.bat`를 실행합니다.

출력은 다음과 유사해야 합니다:

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

### 패키지 만들기 {#create-a-package}

1. 터미널을 열고 프로젝트를 저장할 디렉터리를 만듭니다.
1. 이 새 디렉터리에서 이 명령을 실행하여 새 패키지를 초기화합니다:

   ```shell
   gradle init
   ```

   출력은:

   ```plaintext
   Select type of project to generate:
     1: basic
     2: application
     3: library
     4: Gradle plugin
   Enter selection (default: basic) [1..4]
   ```

1. `3`을 입력하여 새 라이브러리 프로젝트를 만듭니다. 출력은:

   ```plaintext
   Select implementation language:
     1: C++
     2: Groovy
     3: Java
     4: Kotlin
     5: Scala
     6: Swift
   ```

1. `3`을 입력하여 새 Java 라이브러리 프로젝트를 만듭니다. 출력은:

   ```plaintext
   Select build script DSL:
     1: Groovy
     2: Kotlin
   Enter selection (default: Groovy) [1..2]
   ```

1. `1`을 입력하여 Groovy DSL로 설명된 새 Java 라이브러리 프로젝트를 만들거나 `2`을 입력하여 Kotlin DSL로 설명된 프로젝트를 만듭니다. 출력은:

   ```plaintext
   Select test framework:
     1: JUnit 4
     2: TestNG
     3: Spock
     4: JUnit Jupiter
   ```

1. `1`을 입력하여 JUnit 4 테스트 라이브러리를 사용하여 프로젝트를 초기화합니다. 출력은:

   ```plaintext
   Project name (default: test):
   ```

1. 프로젝트 이름을 입력하거나 <kbd>Enter</kbd> 키를 눌러 디렉터리 이름을 프로젝트 이름으로 사용합니다.

## sbt {#sbt}

### sbt 설치 {#install-sbt}

sbt를 설치하여 새로운 sbt 프로젝트를 만듭니다.

개발 환경용 sbt를 설치하려면:

1. [scala-sbt.org](https://www.scala-sbt.org/1.x/docs/Setup.html)의 지침을 따릅니다.
1. 터미널에서 sbt를 사용할 수 있는지 확인합니다:

   ```shell
   sbt --version
   ```

출력은 다음과 유사합니다:

```plaintext
[warn] Project loading failed: (r)etry, (q)uit, (l)ast, or (i)gnore? (default: r)
sbt script version: 1.9.8
```

### Scala 프로젝트 만들기 {#create-a-scala-project}

1. 터미널을 열고 프로젝트를 저장할 디렉터리를 만듭니다.
1. 새 디렉터리에서 새 프로젝트를 초기화합니다:

   ```shell
   sbt new scala/scala-seed.g8
   ```

   출력은:

   ```plaintext
   Minimum Scala build.

   name [My Something Project]: hello

   Template applied in ./hello
   ```

1. 프로젝트 이름을 입력하거나 <kbd>Enter</kbd> 키를 눌러 디렉터리 이름을 프로젝트 이름으로 사용합니다.
1. `build.sbt` 파일을 열고 프로젝트를 패키지 레지스트리에 게시하기 위해 [sbt 설명서](https://www.scala-sbt.org/1.x/docs/Publishing.html)에 설명된 대로 편집합니다.

## npm {#npm}

### npm 설치 {#install-npm}

[npmjs.com](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm/)의 지침을 따라 로컬 개발 환경에 Node.js 및 npm을 설치합니다.

설치가 완료되면 다음 명령을 실행하여 터미널에서 npm을 사용할 수 있는지 확인합니다:

```shell
npm --version
```

npm 버전이 출력에 표시됩니다:

```plaintext
6.10.3
```

### npm 패키지 만들기 {#create-an-npm-package}

1. 빈 디렉터리를 만듭니다.
1. 디렉터리로 이동하고 다음을 실행하여 빈 패키지를 초기화합니다:

   ```shell
   npm init
   ```

1. 질문에 대한 응답을 입력합니다. 패키지 이름이 [명명 규칙](../npm_registry/_index.md#naming-convention)을 따르는지 확인하고 레지스트리가 있는 프로젝트 또는 그룹으로 범위를 지정합니다.

## Yarn {#yarn}

### Yarn 설치 {#install-yarn}

npm의 대안으로 [classic.yarnpkg.com](https://classic.yarnpkg.com/en/docs/install)의 지침을 따라 로컬 환경에 Yarn을 설치할 수 있습니다.

설치가 완료되면 다음 명령을 실행하여 터미널에서 Yarn을 사용할 수 있는지 확인합니다:

```shell
yarn --version
```

Yarn 버전이 출력에 표시됩니다:

```plaintext
1.19.1
```

### 패키지 만들기 {#create-a-package-1}

1. 빈 디렉터리를 만듭니다.
1. 디렉터리로 이동하고 다음을 실행하여 빈 패키지를 초기화합니다:

   ```shell
   yarn init
   ```

1. 질문에 대한 응답을 입력합니다. 패키지 이름이 [명명 규칙](../npm_registry/_index.md#naming-convention)을 따르는지 확인하고 레지스트리가 있는 프로젝트 또는 그룹으로 범위를 지정합니다.

`package.json` 파일이 생성됩니다.

## NuGet {#nuget}

### NuGet 설치 {#install-nuget}

[Microsoft](https://learn.microsoft.com/en-us/nuget/install-nuget-client-tools)의 지침을 따라 NuGet을 설치합니다. [Visual Studio](https://visualstudio.microsoft.com/vs/)가 있으면 NuGet이 이미 설치되어 있을 가능성이 높습니다.

[NuGet CLI](https://www.nuget.org/)가 설치되어 있는지 확인합니다:

```shell
nuget help
```

출력은 다음과 유사해야 합니다:

```plaintext
NuGet Version: 5.1.0.6013
usage: NuGet <command> [args] [options]
Type 'NuGet help <command>' for help on a specific command.

Available commands:

[output truncated]
```

## PyPI {#pypi}

### pip 및 twine 설치 {#install-pip-and-twine}

[pip](https://pypi.org/project/pip/)와 [twine](https://pypi.org/project/twine/)의 최신 버전을 설치합니다.

### 프로젝트 생성 {#create-a-project-2}

테스트 프로젝트를 만듭니다.

1. 터미널을 엽니다.
1. `MyPyPiPackage`이라는 디렉터리를 만들고 해당 디렉터리로 이동합니다:

   ```shell
   mkdir MyPyPiPackage && cd MyPyPiPackage
   ```

1. 다른 디렉터리를 만들고 이동합니다:

   ```shell
   mkdir mypypipackage && cd mypypipackage
   ```

1. 이 디렉터리에 필요한 파일을 만듭니다:

   ```shell
   touch __init__.py
   touch greet.py
   ```

1. `greet.py` 파일을 열고 다음을 추가합니다:

   ```python
   def SayHello():
       print("Hello from MyPyPiPackage")
       return
   ```

1. `__init__.py` 파일을 열고 다음을 추가합니다:

   ```python
   from .greet import SayHello
   ```

1. 코드를 테스트하려면 `MyPyPiPackage` 디렉터리에서 Python 프롬프트를 시작합니다.

   ```shell
   python
   ```

1. 이 명령을 실행합니다:

   ```python
   >>> from mypypipackage import SayHello
   >>> SayHello()
   ```

메시지는 프로젝트가 성공적으로 설정되었음을 나타냅니다:

```plaintext
Python 3.8.2 (v3.8.2:7b3ab5921f, Feb 24 2020, 17:52:18)
[Clang 6.0 (clang-600.0.57)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from mypypipackage import SayHello
>>> SayHello()
Hello from MyPyPiPackage
```

### PyPI 패키지 만들기 {#create-a-pypi-package}

프로젝트를 만든 후 패키지를 만들 수 있습니다.

1. 터미널에서 `MyPyPiPackage` 디렉터리로 이동합니다.
1. `pyproject.toml` 파일을 만듭니다.

   ```shell
   touch pyproject.toml
   ```

   이 파일에는 패키지에 대한 모든 정보가 포함되어 있습니다. 이 파일에 대한 자세한 내용은 [`pyproject.toml` 만들기](https://packaging.python.org/en/latest/tutorials/packaging-projects/#creating-pyproject-toml)를 참조하세요. GitLab이 [Python 표준화된 이름(PEP-503)](https://www.python.org/dev/peps/pep-0503/#normalized-names)을 기반으로 패키지를 식별하기 때문에 패키지 이름이 이러한 요구 사항을 충족하는지 확인합니다. 자세한 내용은 [설치 섹션](../pypi_repository/_index.md#authenticate-with-the-gitlab-package-registry)을 참조하세요.

1. `pyproject.toml` 파일을 열고 기본 정보를 추가합니다:

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

1. 파일을 저장합니다.
1. 패키지 빌드 라이브러리를 설치합니다:

   ```shell
   pip install build
   ```

1. 패키지를 빌드합니다:

   ```shell
   python -m build
   ```

출력은 새로 생성된 `dist` 폴더에 표시됩니다:

```shell
ls dist
```

출력은 다음과 유사해야 합니다:

```plaintext
mypypipackage-0.0.1-py3-none-any.whl mypypipackage-0.0.1.tar.gz
```

이제 패키지를 패키지 레지스트리에 게시할 준비가 되었습니다.
