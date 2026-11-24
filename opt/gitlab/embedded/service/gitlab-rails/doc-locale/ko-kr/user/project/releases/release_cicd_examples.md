---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: CI/CD 릴리스 예제
---

GitLab 릴리스 기능은 유연하며 워크플로우에 맞게 구성할 수 있습니다. 이 페이지에는 CI/CD 릴리스 작업의 예제가 있습니다. 각 예제는 CI/CD 파이프라인에서 릴리스를 생성하는 방법을 보여줍니다.

## Git 태그가 생성되었을 때 릴리스 생성 {#create-a-release-when-a-git-tag-is-created}

이 CI/CD 예제에서 릴리스는 다음 이벤트 중 하나로 트리거됩니다:

- 리포지토리에 Git 태그를 푸시합니다.
- UI에서 Git 태그를 생성합니다.

Git 태그를 수동으로 생성하고 그 결과로 릴리스를 생성하려는 경우 이 방법을 사용할 수 있습니다.

> [!note]
> UI에서 Git 태그를 생성할 때 릴리스 정보를 제공하지 마세요. 릴리스 정보를 제공하면 릴리스가 생성되어 파이프라인이 실패합니다.

다음 `.gitlab-ci.yml` 파일 예제의 핵심 포인트입니다:

- `rules` stanza는 작업이 파이프라인에 추가되는 시기를 정의합니다.
- Git 태그는 릴리스의 이름과 설명에 사용됩니다.

```yaml
release_job:
  stage: release
  image: registry.gitlab.com/gitlab-org/cli:latest
  rules:
    - if: $CI_COMMIT_TAG                 # Run this job when a tag is created
  script:
    - echo "running release_job"
  release:                               # See https://docs.gitlab.com/ci/yaml/#release for available properties
    tag_name: '$CI_COMMIT_TAG'
    description: '$CI_COMMIT_TAG'
```

## 기본 브랜치에 커밋이 병합되었을 때 릴리스 생성 {#create-a-release-when-a-commit-is-merged-to-the-default-branch}

이 CI/CD 예제에서 릴리스는 기본 브랜치에 커밋을 병합할 때 트리거됩니다. 릴리스 워크플로우에서 태그를 수동으로 생성하지 않는 경우 이 방법을 사용할 수 있습니다.

다음 `.gitlab-ci.yml` 파일 예제의 핵심 포인트입니다:

- Git 태그, 설명 및 참조는 파이프라인에서 자동으로 생성됩니다.
- 태그를 수동으로 생성하면 `release_job` 작업이 실행되지 않습니다.

```yaml
release_job:
  stage: release
  image: registry.gitlab.com/gitlab-org/cli:latest
  rules:
    - if: $CI_COMMIT_TAG
      when: never                                  # Do not run this job when a tag is created manually
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH  # Run this job when commits are pushed or merged to the default branch
  script:
    - echo "running release_job for $TAG"
  release:                                         # See https://docs.gitlab.com/ci/yaml/#release for available properties
    tag_name: 'v0.$CI_PIPELINE_IID'                # The version is incremented per pipeline.
    description: 'v0.$CI_PIPELINE_IID'
    ref: '$CI_COMMIT_SHA'                          # The tag is created from the pipeline SHA.
```

> [!note]
> `before_script` 또는 `script`에 설정된 환경 변수는 동일 작업 내에서 확장할 수 없습니다. [변수를 확장할 수 있도록 하기](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/6400)에 대해 자세히 알아보세요.

## 사용자 지정 스크립트에서 릴리스 메타데이터 생성 {#create-release-metadata-in-a-custom-script}

이 CI/CD 예제에서 릴리스 준비는 더 나은 유연성을 위해 별도의 작업으로 분할됩니다:

- `prepare_job` 작업은 릴리스 메타데이터를 생성합니다. 사용자 지정 이미지를 포함하여 모든 이미지를 작업을 실행하는 데 사용할 수 있습니다. 생성된 메타데이터는 변수 파일 `variables.env`에 저장됩니다. 이 메타데이터는 [다운스트림 작업으로 전달됩니다](../../../ci/variables/dotenv_variables.md#pass-variables-to-later-jobs).
- `release_job`은 변수 파일의 콘텐츠를 사용하여 릴리스를 생성하며, 변수 파일에서 전달된 메타데이터를 사용합니다. 이 작업은 `registry.gitlab.com/gitlab-org/cli:latest` 이미지를 사용해야 하며, 이 이미지에는 `glab` CLI가 포함되어 있습니다.

```yaml
prepare_job:
  stage: prepare                                              # This stage must run before the release stage
  rules:
    - if: $CI_COMMIT_TAG
      when: never                                             # Do not run this job when a tag is created manually
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH             # Run this job when commits are pushed or merged to the default branch
  script:
    - echo "EXTRA_DESCRIPTION=some message" >> variables.env  # Generate the EXTRA_DESCRIPTION and TAG environment variables
    - echo "TAG=v$(cat VERSION)" >> variables.env             # and append to the variables.env file
  artifacts:
    reports:
      dotenv: variables.env                                   # Use artifacts:reports:dotenv to expose the variables to other jobs

release_job:
  stage: release
  image: registry.gitlab.com/gitlab-org/cli:latest
  needs:
    - job: prepare_job
      artifacts: true
  rules:
    - if: $CI_COMMIT_TAG
      when: never                                  # Do not run this job when a tag is created manually
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH  # Run this job when commits are pushed or merged to the default branch
  script:
    - echo "running release_job for $TAG"
  release:
    name: 'Release $TAG'
    description: 'Created using the CLI $EXTRA_DESCRIPTION'  # $EXTRA_DESCRIPTION and the $TAG
    tag_name: '$TAG'                                                 # variables must be defined elsewhere
    ref: '$CI_COMMIT_SHA'                                            # in the pipeline. For example, in the
    milestones:                                                      # prepare_job
      - 'm1'
      - 'm2'
      - 'm3'
    released_at: '2020-07-15T08:00:00Z'  # Optional, is auto generated if not defined, or can use a variable.
    assets:
      links:
        - name: 'asset1'
          url: 'https://example.com/assets/1'
        - name: 'asset2'
          url: 'https://example.com/assets/2'
          filepath: '/pretty/url/1' # optional
          link_type: 'other' # optional
```

## 릴리스 생성 시 여러 파이프라인 건너뛰기 {#skip-multiple-pipelines-when-creating-a-release}

CI/CD 작업을 사용하여 릴리스를 생성하면 연결된 태그가 아직 존재하지 않는 경우 여러 파이프라인이 트리거될 수 있습니다. 이것이 어떻게 발생할 수 있는지 이해하려면 다음 워크플로우를 고려하세요:

- 먼저 태그, 다음으로 릴리스:
  1. UI에서 태그를 생성하거나 푸시합니다.
  1. 태그 파이프라인이 트리거되고 `release` 작업을 실행합니다.
  1. 릴리스가 생성됩니다.
- 먼저 릴리스, 다음으로 태그:
  1. 기본 브랜치에 커밋이 푸시되거나 병합될 때 파이프라인이 트리거됩니다. 파이프라인은 `release` 작업을 실행합니다.
  1. 릴리스가 생성됩니다.
  1. 태그가 생성됩니다.
  1. 태그 파이프라인이 트리거됩니다. 파이프라인은 또한 `release` 작업을 실행합니다.

두 번째 워크플로우에서 `release` 작업은 여러 파이프라인에서 실행됩니다. 이를 방지하려면 [`workflow:rules` 키워드](../../../ci/yaml/_index.md#workflowrules)를 사용하여 릴리스 작업이 태그 파이프라인에서 실행되어야 하는지 결정할 수 있습니다:

```yaml
release_job:
  rules:
    - if: $CI_COMMIT_TAG
      when: never                                  # Do not run this job in a tag pipeline
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH  # Run this job when commits are pushed or merged to the default branch
  script:
    - echo "Create release"
  release:
    name: 'My awesome release'
    tag_name: '$CI_COMMIT_TAG'
```
