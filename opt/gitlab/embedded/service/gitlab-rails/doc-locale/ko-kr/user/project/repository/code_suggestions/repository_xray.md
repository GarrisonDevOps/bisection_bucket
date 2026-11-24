---
stage: AI Coding
group: DAP Repository Flows
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Repository X-Ray는 코드 제안 기능이 프로젝트의 코드베이스와 의존성을 더 잘 이해하도록 도와줍니다.
title: 코드 제안이 포함된 Repository X-Ray
---

Repository X-Ray는 자동으로 다음을 향상시킵니다:

- [GitLab Duo 코드 제안](_index.md)에 대한 코드 생성 요청을 프로젝트 의존성에 대한 추가 컨텍스트를 제공하여 코드 권장 사항의 정확성과 관련성을 개선합니다.
- [코드 리팩터링](../../../gitlab_duo_chat/examples.md#refactor-code-in-the-ide), [코드 수정](../../../gitlab_duo_chat/examples.md#fix-code-in-the-ide) 및 [테스트 작성](../../../gitlab_duo_chat/examples.md#write-tests-in-the-ide) 요청입니다.

이를 위해 Repository X-Ray는 코드 어시스턴트에 다음을 통해 프로젝트의 코드베이스 및 의존성에 대한 더 자세한 정보를 제공합니다:

- 의존성 관리자 구성 파일 검색 (예: `Gemfile.lock`, `package.json`, `go.mod`).
- 해당 콘텐츠에서 라이브러리 목록을 추출합니다.
- 추출된 목록을 추가 컨텍스트로 제공하여 GitLab Duo 코드 제안이 코드 생성, 코드 리팩터링, 코드 수정 및 테스트 작성 요청에 사용하도록 합니다.

프로젝트에서 사용 중인 라이브러리와 기타 의존성을 이해함으로써 Repository X-Ray는 코드 어시스턴트가 프로젝트에서 사용하는 코딩 패턴, 스타일 및 기술과 일치하도록 제안을 맞춤형화하는 데 도움을 줍니다. 이는 더 원활하게 통합되고 주어진 스택에 대한 모범 사례를 따르는 코드 제안을 만듭니다.

> [!note]
> Repository X-Ray는 코드 생성 요청만 향상시키고 코드 완성 요청은 향상시키지 않습니다.

## Repository X-Ray 작동 원리 {#how-repository-x-ray-works}

{{< history >}}

- 최대 라이브러리 수 [GitLab 17.6에 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/500365).

{{< /history >}}

프로젝트의 기본 브랜치에 새 커밋을 푸시하면 Repository X-Ray가 백그라운드 작업을 트리거합니다. 이 작업은 리포지토리의 적용 가능한 구성 파일을 스캔하고 구문 분석합니다.

일반적으로 각 프로젝트에서는 한 번에 하나의 스캔 작업만 실행됩니다. 스캔이 이미 진행 중일 때 두 번째 스캔이 트리거되면 두 번째 스캔은 첫 번째 스캔이 완료될 때까지 기다렸다가 실행됩니다. 이는 최신 구성 파일 데이터를 구문 분석하고 데이터베이스에서 업데이트하기 전에 약간의 지연이 발생할 수 있습니다.

코드 생성 요청이 수행될 때 구문 분석된 데이터의 최대 300개 라이브러리가 추가 컨텍스트로 프롬프트에 포함됩니다.

## Repository X-Ray 활성화 {#enable-repository-x-ray}

{{< history >}}

- `ai_enable_internal_repository_xray_service`라는 이름의 [기능 플래그](../../../../administration/feature_flags/list.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/476180)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.6에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/483928)입니다. 기능 플래그 `ai_enable_internal_repository_xray_service`이 제거되었습니다.

{{< /history >}}

Repository X-Ray 서비스는 프로젝트가 [GitLab Duo 코드 제안](_index.md)에 액세스할 수 있는 경우 자동으로 활성화됩니다.

## 지원되는 언어 및 의존성 관리자 {#supported-languages-and-dependency-managers}

Repository X-Ray는 리포지토리 루트에서 최대 2개 디렉터리 수준을 검색합니다. 예를 들어 `Gemfile.lock`, `api/Gemfile.lock` 또는 `api/client/Gemfile.lock`을 지원하지만 `api/v1/client/Gemfile.lock`는 지원하지 않습니다. 각 언어에 대해 일치하는 첫 번째 의존성 관리자만 처리됩니다. 사용 가능한 경우 잠금 파일이 잠금 파일이 아닌 동등 항목보다 우선합니다.

| 언어   | 의존성 관리자 | 구성 파일                  | GitLab 버전 |
| ---------- |--------------------| ----------------------------------- | -------------- |
| C/C++      | Conan              | `conanfile.py`                      | 17.5 이상  |
| C/C++      | Conan              | `conanfile.txt`                     | 17.5 이상  |
| C/C++      | vcpkg              | `vcpkg.json`                        | 17.5 이상  |
| C#         | NuGet              | `*.csproj`                          | 17.5 이상  |
| Go         | Go 모듈         | `go.mod`                            | 17.4 이상  |
| Java       | Gradle             | `build.gradle`                      | 17.4 이상  |
| Java       | Maven              | `pom.xml`                           | 17.4 이상  |
| JavaScript | NPM                | `package-lock.json`, `package.json` | 17.5 이상  |
| Kotlin     | Gradle             | `build.gradle.kts`                  | 17.5 이상  |
| PHP        | Composer           | `composer.lock`, `composer.json`    | 17.5 이상  |
| Python     | Conda              | `environment.yml`                   | 17.5 이상  |
| Python     | Pip                | `*requirements*.txt`[^pip-configuration-files]   | 17.5 이상  |
| Python     | Poetry             | `poetry.lock`, `pyproject.toml`     | 17.5 이상  |
| Ruby       | RubyGems           | `Gemfile.lock`                      | 17.4 이상  |

[^pip-configuration-files]: Python Pip의 경우 `*requirements*.txt` 전역 패턴과 일치하는 모든 구성 파일이 처리됩니다.
