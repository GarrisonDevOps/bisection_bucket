---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Git 태그를 사용하여 리포지토리의 역사에서 중요한 지점을 표시하고 CI/CD 파이프라인을 트리거합니다.
title: 태그
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Git에서 태그는 리포지토리의 역사에서 중요한 지점을 표시합니다. Git은 두 가지 유형의 태그를 지원합니다:

- 경량 태그는 특정 커밋을 가리키고 다른 정보는 포함하지 않습니다. 소프트 태그라고도 합니다. 필요에 따라 생성하거나 제거합니다.
- 주석 태그는 메타데이터를 포함하고, 검증 목적으로 서명할 수 있으며, 변경할 수 없습니다.

태그의 생성 또는 삭제는 다음을 포함한 자동화의 트리거로 사용할 수 있습니다:

- [웹후크](../../integrations/webhook_events.md#tag-events)를 사용하여 Slack 알림과 같은 작업을 자동화합니다.
- [리포지토리 미러](../mirror/_index.md)를 업데이트하도록 신호를 보냅니다.
- [`if: $CI_COMMIT_TAG`](../../../../ci/jobs/job_rules.md#common-if-clauses-with-predefined-variables)를 사용하여 CI/CD 파이프라인을 실행합니다.

[릴리스를 생성](../../releases/_index.md)하면 GitLab은 릴리스 지점을 표시하는 태그도 생성합니다. 많은 프로젝트가 주석 릴리스 태그와 안정 브랜치를 결합합니다. 배포 또는 릴리스 태그를 자동으로 설정하는 것을 고려합니다.

GitLab UI에서 각 태그는 다음을 표시합니다:

![단일 태그의 예](img/tag-display_v18_3.png)

- 태그 이름 ({{< icon name="tag" >}})
- 태그 이름 복사 ({{< icon name="copy-to-clipboard" >}}).
- 선택 사항. 태그가 [보호됨](../../protected_tags.md)이면 **보호됨** 배지입니다.
- 커밋 SHA ({{< icon name="commit" >}})는 커밋의 내용으로 연결됩니다.
- 커밋의 제목과 생성 날짜입니다.
- 선택 사항. 릴리스로의 링크 ({{< icon name="rocket" >}})입니다.
- 선택 사항. 파이프라인이 실행된 경우 현재 파이프라인 상태입니다.
- 태그에 연결된 소스 코드 및 아티팩트로의 다운로드 링크입니다.
- [**릴리스 생성**](../../releases/_index.md#create-a-release) ({{< icon name="pencil" >}}) 링크입니다.
- 태그를 삭제하는 링크입니다.

## 프로젝트의 태그 보기 {#view-tags-for-a-project}

프로젝트의 모든 기존 태그를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **태그**를 선택합니다.

## RSS 피드로 태그 추적 {#track-tags-with-an-rss-feed}

GitLab은 프로젝트의 태그에 대한 RSS 피드를 제공합니다. 피드 버튼은 프로젝트에 최소 하나의 태그가 있을 때만 나타납니다.

피드를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **태그**를 선택합니다.
1. 오른쪽 위 모서리에서 피드 기호 ({{< icon name="rss" >}})를 선택합니다.

피드 URL에는 피드 리더로 인증하는 [피드 토큰](../../../../security/tokens/_index.md#feed-token)이 포함되어 있습니다.

## 커밋 목록에서 태그된 커밋 보기 {#view-tagged-commits-in-the-commits-list}

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **커밋**을 선택합니다.
1. 태그가 있는 커밋은 태그 아이콘 ({{< icon name="tag" >}}) 및 태그 이름으로 레이블이 지정됩니다. 이 예제는 `v1.26.0` 태그가 지정된 커밋을 보여줍니다:

   ![커밋 보기의 태그된 커밋](img/tags_commits_view_v15_10.png)

이 태그의 커밋 목록을 보려면 태그 이름을 선택합니다.

## 태그 생성 {#create-a-tag}

태그는 명령줄 또는 GitLab UI에서 생성할 수 있습니다.

### 명령줄에서 {#from-the-command-line}

명령줄에서 경량 또는 주석 태그를 생성하고 업스트림으로 푸시하려면:

1. 경량 태그를 생성하려면 `git tag TAG_NAME` 명령을 실행하고, `TAG_NAME`를 원하는 태그 이름으로 변경합니다.
1. 주석 태그를 생성하려면 명령줄에서 `git tag`의 버전 중 하나를 실행합니다:

   ```shell
   # In this short version, the annotated tag's name is "v1.0",
   # and the message is "Version 1.0".
   git tag -a v1.0 -m "Version 1.0"

   # Use this version to write a longer tag message
   # for annotated tag "v1.0" in your text editor.
   git tag -a v1.0
   ```

1. `git push origin --tags`로 태그를 업스트림으로 푸시합니다.

### UI에서 {#from-the-ui}

GitLab UI에서 태그를 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **태그**를 선택합니다.
1. **새 태그**를 선택합니다.
1. **태그 이름**을 제공합니다.
1. **다음에서 생성**에서 기존 브랜치 이름, 태그 또는 커밋 SHA를 선택합니다.
1. 선택 사항. **메시지**를 추가하여 주석 태그를 생성하거나 빈 상태로 두어 경량 태그를 생성합니다.
1. **태그 생성**을 선택합니다.

## 태그 이름 지정 {#name-your-tag}

Git은 [태그 이름 규칙](https://git-scm.com/docs/git-check-ref-format)을 적용하여 태그 이름이 다른 도구와 호환되도록 유지합니다. GitLab은 태그 이름에 대한 추가 요구 사항을 추가하고 잘 구조화된 태그 이름의 이점을 제공합니다.

GitLab은 모든 태그에 다음과 같은 추가 규칙을 적용합니다:

- 태그 이름에는 공백이 허용되지 않습니다.
- 40 또는 64자의 16진수로 시작하는 태그 이름은 Git 커밋 해시와 유사하기 때문에 금지됩니다.
- 태그 이름은 `-`, `refs/heads/`, `refs/tags/` 또는 `refs/remotes/`로 시작할 수 없습니다.
- 태그 이름은 대소문자를 구분합니다.

## 태그 이름 복사 {#copy-a-tag-name}

태그 이름을 클립보드에 복사하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **태그**를 선택합니다.
1. 태그 이름 옆에서 **태그 이름 복사** ({{< icon name="copy-to-clipboard" >}})를 선택합니다.

## 태그 삭제 방지 {#prevent-tag-deletion}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

사용자가 `git push`로 태그를 제거하지 않도록 하려면 [푸시 규칙](../push_rules.md)을 생성합니다.

## 태그에서 파이프라인 트리거 {#trigger-pipelines-from-a-tag}

GitLab CI/CD는 파이프라인 구성에서 태그를 식별하기 위해 미리 정의된 변수인 [`CI_COMMIT_TAG`](../../../../ci/variables/predefined_variables.md)를 제공합니다. 이 변수를 작업 규칙 및 워크플로 규칙에서 사용하여 파이프라인이 태그에 의해 트리거되었는지 테스트할 수 있습니다.

기본적으로 CI/CD 작업에 특정 규칙이 없으면 새로 생성된 태그에 대한 태그 파이프라인에 포함됩니다. 태그 파이프라인은 태그가 커밋을 대상으로 할 때만 생성됩니다.

프로젝트의 CI/CD 파이프라인 구성을 위한 `.gitlab-ci.yml` 파일에서 `CI_COMMIT_TAG` 변수를 사용하여 새 태그에 대한 파이프라인을 제어할 수 있습니다:

- 작업 수준에서 [`rules:if`](../../../../ci/yaml/_index.md#rulesif)를 사용합니다.
- 파이프라인 수준에서 [`workflow`](../../../../ci/yaml/workflow.md) 키워드를 사용합니다.

## 태그 파이프라인에서 보안 검사 트리거 {#trigger-security-scans-in-tag-pipelines}

기본적으로 검사 실행 정책은 태그가 아닌 브랜치에서만 실행됩니다. 그러나 파이프라인 실행 정책을 구성하여 태그에서 보안 검사를 실행할 수 있습니다.

태그에서 보안 검사를 실행하려면:

1. 보안 스캐너 템플릿을 확장하는 사용자 지정 작업이 포함된 CI/CD 구성 YAML 파일을 생성하고 태그에서 실행할 규칙을 포함합니다.
1. 이 구성을 파이프라인에 주입하는 파이프라인 실행 정책을 생성합니다.

### 파이프라인 실행 정책 예제 {#example-pipeline-execution-policy}

이 예제는 종속성 검사 및 SAST 검사를 태그에서 실행하는 파이프라인 실행 정책을 생성하는 방법을 보여줍니다:

```yaml
pipeline_execution_policy:
- name: Pipeline Execution Policy
  description: Run security scans on tags
  enabled: true
  pipeline_config_strategy: inject_policy
  content:
    include:
    - project: <Project path to YAML>
      file: tag-security-scans.yml
  skip_ci:
    allowed: false
```

### CI/CD 구성 예제 {#example-cicd-configuration}

이 예제는 보안 스캐너 작업을 확장하여 태그에서 실행하는 방법을 보여줍니다:

```yaml
include:
  - template: Jobs/Dependency-Scanning.gitlab-ci.yml
  - template: Jobs/SAST.gitlab-ci.yml

# Extend dependency scanning to run on tags
gemnasium-python-dependency_scanning_tags:
  extends: gemnasium-python-dependency_scanning
  rules:
    - if: $CI_COMMIT_TAG

# Extend SAST scanning to run on tags
semgrep-sast_tags:
  extends: semgrep-sast
  rules:
    - if: $CI_COMMIT_TAG

# Example of a custom job that runs only on tags
policy_job_for_tags:
  script:
    - echo "This job runs only on tags"
  rules:
    - if: $CI_COMMIT_TAG

# Example of a job that runs on all pipelines
policy_job_always:
  script:
    - echo "This policy job runs always."
```

## 관련 항목 {#related-topics}

- [태깅(Git 참고 페이지)](https://git-scm.com/book/en/v2/Git-Basics-Tagging)
- [보호된 태그](../../protected_tags.md)
- [버전 비교](../compare_revisions.md)
- [태그 API](../../../../api/tags.md)
