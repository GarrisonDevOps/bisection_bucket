---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: '튜토리얼: CI/CD로 자동으로 패키지 빌드 및 게시'
---

CI/CD를 사용하여 PyPI 패키지를 빌드하고 게시할 수 있습니다. 자동 빌드는 패키지를 최신 상태로 유지하고 다른 사용자가 사용할 수 있도록 도움을 줍니다.

이 튜토리얼에서는 샘플 PyPI 패키지를 빌드, 테스트 및 게시하기 위한 새로운 CI/CD 구성을 만들 것입니다. 완료하면 파이프라인의 각 단계가 어떻게 작동하는지 더 잘 이해하고 CI/CD를 자신의 패키지 레지스트리 워크플로우에 통합할 수 있을 것입니다.

CI/CD로 자동으로 패키지를 빌드하고 게시하려면:

1. [`.gitlab-ci.yml` 파일 생성](#create-a-gitlab-ciyml-file)
   1. 선택 사항. [CI/CD 변수 없이 인증](#authenticate-without-a-cicd-variable)
1. [파이프라인 확인](#check-the-pipeline)

## 시작하기 전에 {#before-you-begin}

이 튜토리얼을 완료하기 전에 다음 사항이 있는지 확인하세요:

- 테스트 프로젝트. 원하는 Python 프로젝트를 사용할 수 있지만 이 튜토리얼을 위해 특별히 프로젝트를 만드는 것을 고려하세요.
- PyPI 및 GitLab 패키지 레지스트리에 익숙함.

## `.gitlab-ci.yml` 파일 생성 {#create-a-gitlab-ciyml-file}

모든 CI/CD 구성은 `.gitlab-ci.yml`이 필요합니다. 이 파일은 CI/CD 파이프라인의 각 스테이지를 정의합니다. 이 경우 스테이지는 다음과 같습니다:

- `build` - PyPI 패키지 빌드.
- `test` - 테스트 프레임워크 `pytest`을(를) 사용하여 패키지 유효성 검사.
- `publish` - 패키지 레지스트리에 패키지 게시.

`.gitlab-ci.yml` 파일을 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. 파일 목록 위에서 커밋할 브랜치를 선택합니다.
1. 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}})를 선택합니다.
1. 파일 이름을 `.gitlab-ci.yml`로 지정합니다. 더 큰 창에 이 샘플 구성을 붙여넣습니다:

   ```yaml
   default:
     image: python:3.9
     cache:
       paths:
         - .pip-cache/
     before_script:
       - python --version
       - pip install --upgrade pip
       - pip install build twine

   stages:
     - build
     - test
     - publish

   variables:
     PIP_CACHE_DIR: "$CI_PROJECT_DIR/.pip-cache"

   build:
     stage: build
     script:
       - python -m build
     artifacts:
       paths:
         - dist/

   test:
     stage: test
     script:
       - pip install pytest
       - pip install dist/*.whl
       - pytest

   publish:
     stage: publish
     script:
       - TWINE_PASSWORD=${CI_JOB_TOKEN} TWINE_USERNAME=gitlab-ci-token python -m twine upload --repository-url ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi dist/*
     rules:
       - if: $CI_COMMIT_TAG
   ```

1. **변경 사항 커밋**을 선택합니다.

커밋한 코드에 대한 간단한 설명:

- `image` - 사용할 Docker 이미지를 지정합니다.
- `stages` - 이 파이프라인의 3개 스테이지를 정의합니다.
- `variables` 및 `cache` \- PIP이 캐싱을 사용하도록 구성합니다. 이를 통해 후속 파이프라인을 조금 더 빠르게 실행할 수 있습니다.
- `before_script` - 3개 스테이지를 완료하는 데 필요한 도구를 설치합니다.
- `build` - 패키지를 빌드하고 결과를 아티팩트로 저장합니다.
- `test` - pytest를 설치 및 실행하여 패키지를 유효성 검사합니다.
- `publish` - twine을 사용하여 패키지를 패키지 레지스트리에 업로드하며, 새 태그가 푸시될 때만 수행됩니다. `CI_JOB_TOKEN`을(를) 사용하여 패키지 레지스트리를 인증합니다.

### CI/CD 변수 없이 인증 {#authenticate-without-a-cicd-variable}

패키지 레지스트리를 인증하기 위해 예제 구성은 GitLab CI/CD에서 자동으로 제공되는 `CI_JOB_TOKEN`을(를) 사용합니다. 외부 PyPI 레지스트리에 게시하려면 프로젝트 설정에서 비밀 변수를 구성해야 합니다:

1. 왼쪽 사이드바에서 **설정** > **CI/CD** > **변수**를 선택합니다.
1. `PYPI_TOKEN`이라는 새 변수를 추가하고 PyPI API 토큰을 값으로 입력합니다.
1. `.gitlab-ci.yml` 파일에서 `publish:script`을(를) 다음으로 바꾸세요:

   ```yaml
   script:
   - TWINE_PASSWORD=${PYPI_TOKEN} TWINE_USERNAME=__token__ python -m twine upload dist/*
   ```

## 파이프라인 확인 {#check-the-pipeline}

변경 사항을 커밋할 때 파이프라인이 올바르게 실행되도록 확인해야 합니다:

- 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다. 가장 최근 파이프라인에는 이전에 정의된 3개 스테이지가 있어야 합니다.

파이프라인이 실행되지 않았다면 새로운 파이프라인을 수동으로 실행하고 성공적으로 완료되는지 확인합니다.

## 모범 사례 {#best-practices}

패키지의 보안과 안정성을 보장하려면 패키지 레지스트리에 게시하기 위한 모범 사례를 따르세요. 추가한 구성:

- 캐싱을 구현하여 파이프라인 속도를 높입니다.
- 아티팩트를 사용하여 빌드된 패키지를 스테이지 간에 전달합니다.
- 게시하기 전에 패키지를 유효성 검사하는 테스트 스테이지를 포함합니다.
- 인증 토큰 같은 민감한 정보에는 GitLab CI/CD 변수를 사용합니다.
- 새 Git 태그가 푸시될 때만 게시합니다. 이렇게 하면 올바르게 버전이 지정된 릴리스만 게시됩니다.

축하합니다! GitLab CI/CD로 패키지를 성공적으로 빌드, 테스트 및 게시했습니다. 유사한 구성을 사용하여 자신의 개발 프로세스를 간소화할 수 있을 것입니다.
