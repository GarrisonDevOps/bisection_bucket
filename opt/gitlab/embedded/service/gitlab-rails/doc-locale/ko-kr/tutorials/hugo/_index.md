---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: Hugo 사이트를 GitLab으로 빌드, 테스트 및 배포'
description: "CI/CD 파이프라인을 사용하여 Hugo 정적 사이트를 GitLab Pages에 빌드, 테스트 및 배포합니다."
---

<!-- vale gitlab_base.FutureTense = NO -->

이 튜토리얼에서는 Hugo 사이트를 빌드, 테스트 및 배포하는 CI/CD 파이프라인을 만듭니다.

튜토리얼을 마치면 작동하는 파이프라인과 GitLab Pages에 배포된 Hugo 사이트를 갖게 됩니다.

다음은 수행할 작업의 개요입니다:

1. Hugo 사이트를 준비합니다.
1. GitLab 프로젝트를 생성합니다.
1. Hugo 사이트를 GitLab으로 푸시합니다.
1. CI/CD 파이프라인을 사용하여 Hugo 사이트를 빌드합니다.
1. GitLab Pages를 사용하여 Hugo 사이트를 배포합니다.

## 시작하기 전에 {#before-you-begin}

- GitLab.com의 계정
- Git에 대한 숙지
- Hugo 사이트(아직 없는 경우 [Hugo 빠른 시작](https://gohugo.io/getting-started/quick-start/)을 따를 수 있습니다).

## Hugo 사이트 준비 {#prepare-your-hugo-site}

먼저 Hugo 사이트가 GitLab으로 푸시할 준비가 되었는지 확인합니다. 콘텐츠, 테마 및 Hugo 구성 파일이 필요합니다.

GitLab이 해당 작업을 수행하므로 사이트를 빌드하지 마세요. 실제로 `public` 폴더를 업로드하지 않는 것이 중요합니다. 이렇게 하면 나중에 충돌이 발생할 수 있습니다.

`public` 폴더를 제외하는 가장 쉬운 방법은 `.gitignore` 파일을 만들고 `public/`을(를) 텍스트로 추가하는 것입니다.

Hugo 프로젝트의 최상위 레벨에서 다음 명령으로 이를 수행할 수 있습니다:

```shell
echo "public/" >> .gitignore
```

이 명령은 `public/`을(를) 새 `.gitignore` 파일에 추가하거나 기존 파일에 추가합니다.

GitLab 프로젝트를 만든 후 Hugo 사이트를 푸시할 준비가 되었습니다.

## GitLab 프로젝트 생성 {#create-a-gitlab-project}

아직 하지 않았다면 Hugo 사이트용 빈 GitLab 프로젝트를 만듭니다.

GitLab에서 빈 프로젝트를 만들려면:

1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. 프로젝트 세부 정보를 입력합니다:
   - **프로젝트 이름** 텍스트 상자에 프로젝트 이름을 입력합니다. 이름은 소문자 또는 대문자(`a-zA-Z`), 숫자(`0-9`), 이모지 또는 밑줄(`_`)로 시작해야 합니다. 또한 점(`.`), 더하기(`+`), 대시(`-`) 또는 공백을 포함할 수 있습니다.
   - **프로젝트 슬러그** 텍스트 상자에 프로젝트 경로를 입력합니다. GitLab 인스턴스는 슬러그를 프로젝트의 URL 경로로 사용합니다. 슬러그를 변경하려면 먼저 프로젝트 이름을 입력한 다음 슬러그를 변경합니다.
   - **공개 수준**은 비공개 또는 공개일 수 있습니다. 비공개를 선택하면 웹사이트가 여전히 공개적으로 사용 가능하지만 코드는 비공개로 유지됩니다.
   - 기존 리포지토리를 푸시하고 있으므로 **README 파일을 포함하여 리포지토리 초기화** 상자를 선택 해제합니다.
1. 준비가 되면 **프로젝트 생성**을 선택합니다.
1. 코드를 이 새 프로젝트로 푸시하기 위한 지침이 표시됩니다. 다음 단계에서 해당 지침이 필요합니다.

이제 Hugo 사이트를 위한 홈을 갖추게 되었습니다!

## Hugo 사이트를 GitLab으로 푸시 {#push-your-hugo-site-to-gitlab}

다음으로 로컬 Hugo 사이트를 원격 GitLab 프로젝트로 푸시해야 합니다.

이전 단계에서 새 GitLab 프로젝트를 만들었다면 리포지토리를 초기화한 다음 파일을 커밋하고 푸시하기 위한 지침이 표시됩니다.

또는 로컬 Git 리포지토리의 원격 원본이 GitLab 프로젝트와 일치하는지 확인합니다.

기본 브랜치가 `main`이라고 가정하면 다음 명령으로 Hugo 사이트를 푸시할 수 있습니다:

```shell
git push origin main
```

사이트를 푸시한 후 `public` 폴더를 제외한 모든 콘텐츠를 확인합니다. `public` 폴더는 `.gitignore` 파일로 제외되었습니다.

다음 단계에서는 CI/CD 파이프라인을 사용하여 사이트를 빌드하고 `public` 폴더를 다시 생성합니다.

## CI/CD 파이프라인을 사용하여 Hugo 사이트 빌드 {#build-your-hugo-site-with-a-cicd-pipeline}

GitLab으로 Hugo 사이트를 빌드하려면 먼저 CI/CD 파이프라인에 대한 지침을 지정하는 `.gitlab-ci.yml` 파일을 만들어야 합니다. 이전에 이를 수행하지 않았다면 어려워 보일 수 있습니다. 하지만 GitLab은 필요한 모든 것을 제공합니다.

아래에 표시된 `.gitlab-ci.yml` 파일을 사용하려면 `hugo.toml` 파일도 일치하는 테마 경로를 나타내는지 확인합니다. 아래의 예제 `hugo.toml` 파일은 또한 GitLab Pages 프로젝트의 `baseURL` 설정을 표시합니다.

```yaml
baseURL = 'https://<your-namespace>.gitlab.io/<project-path>'
languageCode = 'en-us'
title = 'Hugo on GitLab'
[module]
[[module.imports]]
  path = 'github.com/adityatelange/hugo-PaperMod'
```

### GitLab 구성 옵션 추가 {#add-your-gitlab-configuration-options}

구성 옵션을 `.gitlab-ci.yml`이라는 특수 파일에 지정합니다.

Hugo 템플릿을 사용하여 `.gitlab-ci.yml` 파일을 만들려면:

1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. 파일 목록 위에서 더하기 아이콘( + )을 선택한 다음 드롭다운 목록에서 **새 파일**을 선택합니다.
1. 파일 이름으로 `.gitlab-ci.yml`을(를) 입력합니다. 시작 부분의 마침표를 생략하지 않습니다.
1. **템플릿 적용** 드롭다운 목록을 선택한 다음 필터 상자에 "Hugo"를 입력합니다.
1. 결과 **Hugo**를 선택하면 파일이 CI/CD를 사용하여 Hugo 사이트를 빌드하는 데 필요한 모든 코드로 채워집니다.

이 `.gitlab-ci.yml` 파일에서 일어나는 일을 자세히 살펴봅시다.

```yaml
default:
  image: "hugomods/hugo:exts"

variables:
  GIT_SUBMODULE_STRATEGY: recursive
  THEME_URL: "github.com/adityatelange/hugo-PaperMod"

test:  # builds and tests your site
  script:
    - hugo
  rules:
    - if: $CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH

create-pages:  # a user-defined job that builds your pages and saves them to the specified path.
  script:
    - hugo
  pages: true  # specifies that this is a Pages job
  artifacts:
    paths:
      - public
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  environment: production
```

- `image`은(는) Hugo가 포함된 GitLab Registry의 이미지를 지정합니다. 이 이미지는 사이트가 빌드되는 환경을 만드는 데 사용됩니다.
- `GIT_SUBMODULE_STRATEGY` 변수를 사용하면 GitLab이 Hugo 테마에 사용되는 Git 서브모듈도 확인합니다.
- `test`은(는) 배포되기 전에 Hugo 사이트에서 테스트를 실행할 수 있는 작업입니다. 테스트 작업은 기본 브랜치에 변경 사항을 커밋하는 경우를 제외한 모든 경우에 실행됩니다. 모든 명령을 `script`에 배치합니다. 이 작업의 명령인 `hugo`은(는) 테스트할 수 있도록 사이트를 빌드합니다.
- `create-pages`은(는) 정적 사이트 생성기에서 페이지를 만들기 위한 사용자 정의 작업입니다. 다시 이 작업은 [사용자 정의 작업 이름](../../user/project/pages/_index.md#user-defined-job-names)을 사용하고 `hugo` 명령을 실행하여 사이트를 빌드합니다. 그런 다음 `pages: true`은(는) 이것이 Pages 작업임을 지정하고 `artifacts`은(는) 결과 페이지가 `public`이라는 디렉터리에 추가됨을 지정합니다. `rules`를 사용하여 이 커밋이 기본 브랜치에서 수행되었는지 확인합니다. 일반적으로 다른 브랜치에서 라이브 사이트를 빌드하고 배포하지 않으려 합니다.

이 파일에 다른 항목을 추가할 필요가 없습니다. 준비가 되면 페이지 위쪽에서 **변경 사항 커밋**을 선택합니다.

Hugo 사이트를 빌드하는 파이프라인을 트리거했습니다!

## GitLab Pages를 사용하여 Hugo 사이트 배포 {#deploy-your-hugo-site-with-gitlab-pages}

빠르면 GitLab이 사이트를 빌드하고 배포하는 것을 볼 수 있습니다.

왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.

GitLab이 `test` 및 `create-pages` 작업을 실행했음을 확인합니다.

파이프라인이 완료되면 왼쪽 사이드바에서 **배포** > **Pages**를 선택하여 Pages 웹사이트의 링크를 찾습니다.

### Hugo 구성 옵션 추가 {#add-your-hugo-configuration-options}

Hugo 사이트를 처음 보면 스타일시트가 작동하지 않습니다. 걱정하지 마세요. Hugo 구성 파일에서 작은 변경을 수행해야 합니다. Hugo는 GitLab Pages 사이트의 URL을 알아야 스타일시트 및 기타 자산에 대한 상대 링크를 빌드할 수 있습니다:

1. 로컬 Hugo 사이트에서 최신 변경 사항을 가져오고 `config.yaml` 또는 `config.toml` 파일을 엽니다.
1. `BaseURL` 매개변수의 값을 GitLab Pages 설정에 나타나는 URL과 일치하도록 변경합니다.
1. 변경된 파일을 GitLab으로 푸시하면 파이프라인이 다시 트리거됩니다.

### GitLab Pages URL 찾기 {#find-your-gitlab-pages-url}

파이프라인이 완료되면 **배포** > **Pages**로 이동하여 Pages 웹사이트의 링크를 찾습니다.

파이프라인의 `pages` 작업이 `public` 디렉터리 내용을 GitLab Pages에 배포했습니다. **Pages 액세스**에서 `https://<your-namespace>.gitlab.io/<project-path>` 형식의 링크를 확인해야 합니다.

아직 파이프라인을 실행하지 않았다면 이 링크가 표시되지 않습니다.

표시된 링크를 선택하여 사이트를 봅니다. Hugo 구성의 `BaseURL` 설정을 GitLab 배포 URL과 일치하도록 변경해야 합니다.

### GitLab Pages 표시 여부 설정 {#set-your-gitlab-pages-visibility}

Hugo 사이트가 비공개 리포지토리에 저장되어 있으면 Pages 사이트가 표시되도록 권한을 변경해야 합니다. 그렇지 않으면 프로젝트 구성원에게만 표시됩니다. 사이트 권한을 변경하려면:

1. **설정** > **일반** > **표시 여부, 프로젝트 기능, 권한**으로 이동합니다.
1. **Pages** 섹션으로 스크롤한 다음 드롭다운 목록에서 **모두**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

이제 모두가 URL에서 사이트를 볼 수 있습니다.

GitLab으로 Hugo 사이트를 빌드, 테스트 및 배포했습니다. 훌륭한 작업입니다!

사이트를 변경하고 GitLab으로 푸시할 때마다 `.gitlab-ci.yml` 파일의 규칙을 사용하여 사이트가 자동으로 빌드, 테스트 및 배포됩니다.

CI/CD 파이프라인에 대해 자세히 알아보려면 [복잡한 파이프라인을 만드는 방법에 대한 이 튜토리얼](../../ci/quick_start/tutorial.md)을 시도하세요. [사용 가능한 다양한 유형의 테스트](../../ci/testing/_index.md)에 대해 자세히 알아볼 수도 있습니다.
