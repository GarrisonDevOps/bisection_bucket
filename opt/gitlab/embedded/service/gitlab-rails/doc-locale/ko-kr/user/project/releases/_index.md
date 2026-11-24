---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 릴리스
description: "릴리스, 버전 관리, 자산, 태그, 마일스톤 및 증거."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

중요한 마일스톤에서 프로젝트를 패키징하기 위해 릴리스를 생성합니다. 릴리스는 코드, 바이너리, 문서 및 릴리스 정보를 프로젝트의 완전한 스냅샷으로 결합합니다. 릴리스가 생성되면 GitLab이 자동으로 코드를 태그하고, 스냅샷을 보관하며, 감사 준비 증거를 생성합니다. 이렇게 하면 규정 준수 요구사항에 완벽한 영구 기록이 생성되며 사용자가 개발 프로세스에 확신을 가질 수 있습니다.

사용자가 다음과 같은 이점을 누릴 수 있습니다:

- 최신 안정 버전 및 설치 패키지에 대한 쉬운 액세스
- 새로운 기능 및 수정 사항에 대한 명확한 문서
- 해당 자산과 함께 특정 버전을 다운로드할 수 있는 기능
- 프로젝트의 진화를 시간에 따라 추적하는 간단한 방법

> [!warning]
> 릴리스와 관련된 Git 태그를 삭제하면 릴리스도 삭제됩니다.

릴리스를 생성하거나 생성한 후에 다음을 수행할 수 있습니다:

- 릴리스 정보를 추가합니다.
- 릴리스와 관련된 Git 태그에 대한 메시지를 추가합니다.
- [마일스톤과 연결](#associate-milestones-with-a-release)합니다.
- [릴리스 자산](release_fields.md#release-assets)(예: 런북 또는 패키지)을 첨부합니다.

## 릴리스 보기 {#view-releases}

릴리스 목록을 보려면:

- 왼쪽 사이드바에서 **배포** > **릴리즈**를 선택하거나
- 프로젝트의 개요 페이지에서 릴리스가 하나 이상 있으면 릴리스 수를 선택합니다.

  ![릴리스 수](img/releases_count_v13_2.png "릴리스의 증분 카운터")

  - 공개 프로젝트에서는 이 수가 모든 사용자에게 표시됩니다.
  - 비공개 프로젝트에서는 이 수가 최소 보고자 [역할](../../permissions.md#project-permissions)이 있는 사용자에게 표시됩니다.

### 릴리스 정렬 {#sort-releases}

**릴리스 날짜** 또는 **만든 날짜**로 릴리스를 정렬하려면 정렬 순서 드롭다운 목록에서 선택합니다. 오름차순 또는 내림차순 사이를 전환하려면 **정렬 순서**를 선택합니다.

![릴리스 정렬 드롭다운 목록 옵션](img/releases_sort_v13_6.png)

### 최신 릴리스로의 영구 링크 {#permanent-link-to-latest-release}

영구 링크를 통해 최신 릴리스 페이지에 액세스할 수 있습니다. GitLab은 항상 영구 링크 URL을 최신 릴리스 페이지의 주소로 리디렉션합니다.

URL의 형식은:

```plaintext
https://gitlab.example.com/namespace/project/-/releases/permalink/latest
```

영구 링크 URL에 접미사를 추가할 수도 있습니다. 예를 들어 최신 릴리스가 `v17.7.0#release` 이고 `gitlab-org` 네임스페이스 및 `gitlab-runner` 프로젝트에 있는 경우 읽기 쉬운 링크는 다음과 같습니다:

```plaintext
https://gitlab.com/gitlab-org/gitlab-runner/-/releases/v17.7.0#release
```

다음의 영구 링크를 사용하여 최신 릴리스 URL에 액세스할 수 있습니다:

```plaintext
https://gitlab.com/gitlab-org/gitlab-runner/-/releases/permalink/latest#release
```

릴리스 자산에 대한 영구 링크 추가에 대해 자세히 알아보려면 [최신 릴리스 자산으로의 영구 링크](release_fields.md#permanent-links-to-latest-release-assets)를 참조하세요.

#### 정렬 기본 설정 {#sorting-preferences}

기본적으로 GitLab은 `released_at` 시간을 사용하여 릴리스를 가져옵니다. 쿼리 매개변수 `?order_by=released_at`의 사용은 선택 사항이며, `?order_by=semver`에 대한 지원은 [이 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352945)에서 추적됩니다.

### RSS 피드로 릴리스 추적 {#track-releases-with-an-rss-feed}

GitLab은 프로젝트의 릴리스에 대한 RSS 피드를 제공합니다. 피드를 보려면:

1. 멤버인 프로젝트의 경우:
   1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
   1. **배포** > **릴리즈**를 선택합니다.
1. 모든 프로젝트:
   1. **프로젝트 개요** 페이지로 이동합니다.
   1. 오른쪽 사이드바에서 **릴리즈** ({{< icon name="rocket-launch" >}})를 선택합니다.
1. 오른쪽 상단에서 피드 기호 ({{< icon name="rss" >}})를 선택합니다.

## 릴리스 생성 {#create-a-release}

릴리스를 생성할 수 있습니다:

- [CI/CD 파이프라인에서 작업 사용](#creating-a-release-by-using-a-cicd-job)
- [릴리스 페이지에서](#create-a-release-in-the-releases-page)
- [릴리스 API](../../../api/releases/_index.md#create-a-release) 사용

### 릴리스 페이지에서 릴리스 생성 {#create-a-release-in-the-releases-page}

사전 요구 사항:

- 프로젝트의 개발자, 유지관리자 또는 소유자 역할이 있어야 합니다. 자세한 내용은 [릴리스 권한](#release-permissions)을 참조하세요.

릴리스 페이지에서 릴리스를 생성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **릴리즈**를 선택하고 **새 릴리즈**를 선택합니다.
1. [**태그 이름**](release_fields.md#tag-name) 드롭다운 목록에서:
   - 기존 Git 태그를 선택합니다. 이미 릴리스와 연결된 기존 태그를 선택하면 검증 오류가 발생합니다.
   - 새 Git 태그 이름을 입력합니다.
     1. **태그 생성** 팝오버에서 새 태그를 생성할 때 사용할 분기 또는 커밋 SHA를 선택합니다.
     1. 선택 사항. **태그 메시지 설정** 텍스트 상자에 [주석 태그](https://git-scm.com/book/en/v2/Git-Basics-Tagging#_annotated_tags)를 생성할 메시지를 입력합니다.
     1. **저장**을 선택합니다.
1. 선택 사항. 다음을 포함한 릴리스에 대한 추가 정보를 입력합니다:
   - [제목](release_fields.md#title)
   - [마일스톤](#associate-milestones-with-a-release).
   - [릴리스 정보](release_fields.md#release-notes-description)
   - [태그 메시지](../repository/tags/_index.md)를 포함할지 여부
   - [자산 링크](release_fields.md#links)
1. **릴리스 생성**을 선택합니다.

### CI/CD 작업을 사용하여 릴리스 생성 {#creating-a-release-by-using-a-cicd-job}

GitLab CI/CD 파이프라인의 일부로 직접 [`release` 키워드](../../../ci/yaml/_index.md#release)를 사용하여 릴리스를 생성할 수 있습니다. 일반적으로 CI/CD 파이프라인의 마지막 단계 중 하나로 릴리스를 생성해야 합니다.

릴리스는 작업이 오류 없이 처리되는 경우에만 생성됩니다. 릴리스 생성 중에 API가 오류를 반환하면 릴리스 작업이 실패합니다.

다음 링크는 CI/CD 작업을 사용하여 릴리스를 생성하기 위한 일반적인 예제 구성을 보여줍니다:

- [Git 태그가 생성될 때 릴리스 생성](release_cicd_examples.md#create-a-release-when-a-git-tag-is-created)
- [기본 분기에 커밋이 병합될 때 릴리스 생성](release_cicd_examples.md#create-a-release-when-a-commit-is-merged-to-the-default-branch)
- [커스텀 스크립트에서 릴리스 메타데이터 생성](release_cicd_examples.md#create-release-metadata-in-a-custom-script)

### 커스텀 SSL CA 인증서 기관 사용 {#use-a-custom-ssl-ca-certificate-authority}

`ADDITIONAL_CA_CERT_BUNDLE` CI/CD 변수를 사용하여 커스텀 SSL CA 인증서 기관을 구성할 수 있습니다. 이 변수는 `glab` CLI가 커스텀 인증서를 사용하여 HTTPS를 통한 API를 통해 릴리스를 생성할 때 피어를 확인하는 데 사용됩니다. `ADDITIONAL_CA_CERT_BUNDLE` 값에는 [X.509 PEM 공개 키 인증서의 텍스트 표현](https://www.rfc-editor.org/rfc/rfc7468#section-5.1) 또는 인증서 기관이 포함된 `path/to/file`이 포함되어야 합니다. 예를 들어, `.gitlab-ci.yml` 파일에서 이 값을 구성하려면 다음을 사용합니다:

```yaml
release:
  variables:
    ADDITIONAL_CA_CERT_BUNDLE: |
        -----BEGIN CERTIFICATE-----
        MIIGqTCCBJGgAwIBAgIQI7AVxxVwg2kch4d56XNdDjANBgkqhkiG9w0BAQsFADCB
        ...
        jWgmPqF3vUbZE0EyScetPJquRFRKIesyJuBFMAs=
        -----END CERTIFICATE-----
  script:
    - echo "Create release"
  release:
    name: 'My awesome release'
    tag_name: '$CI_COMMIT_TAG'
```

`ADDITIONAL_CA_CERT_BUNDLE` 값은 [UI의 커스텀 변수](../../../ci/variables/_index.md#for-a-project)로도 구성할 수 있으며, 인증서 경로가 필요한 `file` 또는 인증서의 텍스트 표현이 필요한 변수로 구성할 수 있습니다.

### 단일 파이프라인에서 여러 릴리스 생성 {#create-multiple-releases-in-a-single-pipeline}

파이프라인에는 여러 `release` 작업이 있을 수 있습니다. 예를 들면:

```yaml
ios-release:
  script:
    - echo "iOS release job"
  release:
    tag_name: v1.0.0-ios
    description: 'iOS release v1.0.0'

android-release:
  script:
    - echo "Android release job"
  release:
    tag_name: v1.0.0-android
    description: 'Android release v1.0.0'
```

### Generic 패키지로 릴리스 자산 {#release-assets-as-generic-packages}

[Generic 패키지](../../packages/generic_packages/_index.md)를 사용하여 릴리스 자산을 호스팅할 수 있습니다.

패키징된 자산으로 릴리스를 생성하려면:

1. CI/CD 파이프라인에서 패키지 파일을 빌드합니다.
1. `glab` CLI 작업으로 릴리스를 생성합니다:

   ```yaml
   Create Release:
     stage: release
     image: registry.gitlab.com/gitlab-org/cli:latest
     rules:
       - if: $CI_COMMIT_TAG
     script:
       - |
         glab release create "$CI_COMMIT_TAG" \
         --name "Release ${VERSION}" \
         --notes "Your release notes here" \
         path/to/your/release-asset-file \
         --use-package-registry
   ```

   포함하려는 모든 자산에 대해 추가 `--assets-link` 링크를 추가합니다.

## 예정된 릴리스 {#upcoming-releases}

[릴리스 API](../../../api/releases/_index.md#upcoming-releases)를 사용하여 릴리스를 미리 생성할 수 있습니다. 향후 `released_at` 날짜를 설정하면 **예정된 릴리스** 배지가 릴리스 태그 옆에 표시됩니다. `released_at` 날짜 및 시간이 경과하면 배지가 자동으로 제거됩니다.

![예정된 릴리스](img/upcoming_release_v18_8.png)

## 과거 릴리스 {#historical-releases}

[릴리스 API](../../../api/releases/_index.md#historical-releases) 또는 UI를 사용하여 과거 릴리스를 생성할 수 있습니다. 과거 `released_at` 날짜를 설정하면 **과거 릴리스** 배지가 릴리스 태그 옆에 표시됩니다. 과거에 릴리스되었기 때문에 [릴리스 증거](release_evidence.md)는 사용할 수 없습니다.

## 릴리스 수정 {#edit-a-release}

릴리스가 생성된 후 세부 정보를 수정하려면 [릴리스 업데이트 API](../../../api/releases/_index.md#update-a-release) 또는 UI를 사용할 수 있습니다.

사전 요구 사항:

- 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

UI에서:

1. 왼쪽 사이드바에서 **배포** > **릴리즈**를 선택합니다.
1. 수정할 릴리스의 오른쪽 상단에서 **릴리스 수정** (연필 아이콘)을 선택합니다.
1. **릴리스 수정** 페이지에서 릴리스의 세부 정보를 변경합니다.
1. **변경 사항 저장**을 선택합니다.

## 릴리스 삭제 {#delete-a-release}

릴리스를 삭제하면 해당 자산도 삭제됩니다. 그러나 관련된 Git 태그는 삭제되지 않습니다. 릴리스와 관련된 Git 태그를 삭제하면 릴리스도 삭제됩니다.

사전 요구 사항:

- 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다. [릴리스 권한](#release-permissions)에 대해 자세히 알아봅니다.

릴리스를 삭제하려면 [릴리스 삭제 API](../../../api/releases/_index.md#delete-a-release) 또는 UI를 사용합니다.

UI에서:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **릴리즈**를 선택합니다.
1. 삭제할 릴리스의 오른쪽 상단에서 **릴리스 수정** ({{< icon name="pencil" >}})을 선택합니다.
1. **릴리스 수정** 페이지에서 **삭제**를 선택합니다.
1. **릴리스 삭제**를 선택합니다.

## 릴리스와 마일스톤 연결 {#associate-milestones-with-a-release}

릴리스를 하나 이상의 [프로젝트 마일스톤](../milestones/_index.md#project-milestones-and-group-milestones)과 연결할 수 있습니다.

[GitLab Premium](https://about.gitlab.com/pricing/) 고객은 릴리스와 연결할 [그룹 마일스톤](../milestones/_index.md#project-milestones-and-group-milestones)을 지정할 수 있습니다.

사용자 인터페이스에서 이를 수행하거나 [릴리스 API](../../../api/releases/_index.md#create-a-release)에 대한 요청에 `milestones` 배열을 포함하여 수행할 수 있습니다.

사용자 인터페이스에서 마일스톤을 릴리스와 연결하려면:

1. 왼쪽 사이드바에서 **배포** > **릴리즈**를 선택합니다.
1. 수정할 릴리스의 오른쪽 상단에서 **릴리스 수정** (연필 아이콘)을 선택합니다.
1. **마일스톤** 목록에서 연결할 각 마일스톤을 선택합니다. 여러 마일스톤을 선택할 수 있습니다.
1. **변경 사항 저장**을 선택합니다.

**배포** > **릴리즈** 페이지에서 **마일스톤**이 최상위 섹션에 마일스톤의 이슈에 대한 통계와 함께 나열됩니다.

![하나의 관련 마일스톤을 가진 릴리스](img/release_with_milestone_v12_9.png)

릴리스는 **계획** > **마일스톤** 페이지에서도 표시되며, 이 페이지에서 마일스톤을 선택할 때도 표시됩니다.

다음은 릴리스가 없는 마일스톤, 하나의 릴리스가 있는 마일스톤, 두 개의 릴리스가 있는 마일스톤의 예입니다.

![릴리스 연결이 있거나 없는 마일스톤](img/milestone_list_with_releases_v12_5.png)

> [!note]
> 하위 그룹의 프로젝트 릴리스는 상위 그룹의 마일스톤과 연결될 수 없습니다. 자세히 알아보려면 이슈 #328054 [릴리스를 상위 그룹 마일스톤과 연결할 수 없음](https://gitlab.com/gitlab-org/gitlab/-/issues/328054)을 참조하세요.

## 릴리스가 생성될 때 알림 받기 {#get-notified-when-a-release-is-created}

프로젝트의 새 릴리스가 생성될 때 이메일로 알림을 받을 수 있습니다.

릴리스에 대한 알림을 구독하려면:

1. 왼쪽 사이드바에서 **프로젝트 개요**를 선택합니다.
1. **알림 설정** (벨 아이콘)을 선택합니다.
1. 목록에서 **커스텀**을 선택합니다.
1. **새 릴리즈** 체크박스를 선택합니다.
1. 대화를 닫아 저장합니다.

## 배포 변경금지를 설정하여 의도하지 않은 릴리스 방지 {#prevent-unintentional-releases-by-setting-a-deploy-freeze}

지정한 기간 동안 [*배포 동결* 기간](../../../ci/environments/deployment_safety.md)을 설정하여 의도하지 않은 프로덕션 릴리스를 방지합니다. 배포 동결은 배포를 자동화할 때 불확실성과 위험을 줄이는 데 도움이 됩니다.

유지관리자는 사용자 인터페이스에서 배포 동결 기간을 설정하거나 [고정 기간 API](../../../api/freeze_periods.md)를 사용하여 `freeze_start` 및 `freeze_end`를 설정할 수 있으며, 이는 [crontab](https://crontab.guru/) 항목으로 정의됩니다.

실행 중인 작업이 동결 기간 내에 있으면 GitLab CI/CD는 `$CI_DEPLOY_FREEZE`이라는 환경 변수를 생성합니다.

그룹 전체에 공유되는 파일에서 `.freezedeployment` 작업을 정의하여 그룹의 여러 프로젝트에서 배포 작업이 실행되는 것을 방지합니다. [`includes`](../../../ci/yaml/includes.md) 키워드를 사용하여 템플릿을 프로젝트의 `.gitlab-ci.yml` 파일에 통합합니다:

```yaml
.freezedeployment:
  stage: deploy
  before_script:
    - '[[ ! -z "$CI_DEPLOY_FREEZE" ]] && echo "INFRASTRUCTURE OUTAGE WINDOW" && exit 1; '
  rules:
    - if: '$CI_DEPLOY_FREEZE'
      when: manual
      allow_failure: true
    - when: on_success
```

배포 작업이 실행되는 것을 방지하려면 [`extends`](../../../ci/yaml/_index.md#extends) 키워드를 `deploy_to_production` 작업의 `.gitlab-ci.yml` 파일에서 사용하여 `.freezedeployment` 템플릿 작업에서 구성을 상속합니다:

```yaml
deploy_to_production:
  extends: .freezedeployment
  script: deploy_to_prod.sh
  environment: production
```

이 구성은 배포 작업을 조건부로 차단하고 파이프라인 연속성을 유지합니다. 동결 기간이 정의되면 작업이 실패하고 파이프라인이 배포 없이 진행될 수 있습니다. 동결 기간 후 수동 배포가 가능합니다.

이 접근 방식은 중요한 유지관리 중에 배포를 제어하고 CI/CD 파이프라인의 중단 없는 흐름을 보장합니다.

UI에서 배포 동결 기간을 설정하려면 다음 단계를 완료합니다:

1. 유지관리자 역할이 있는 사용자로 GitLab에 로그인합니다.
1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **배포 변경금지**로 스크롤합니다.
1. **펼침**을 선택하여 배포 동결 테이블을 봅니다.
1. **배포 변경금지 추가**를 선택하여 배포 동결 모달을 엽니다.
1. 원하는 배포 동결 기간의 시작 시간, 종료 시간 및 시간대를 입력합니다.
1. 모달에서 **배포 변경금지 추가**를 선택합니다.
1. 배포 동결이 저장된 후 편집 버튼 ({{< icon name="pencil" >}})을 선택하여 편집하고 삭제 버튼 ({{< icon name="remove" >}})을 선택하여 제거할 수 있습니다. ![배포 동결 기간을 설정하기 위한 배포 동결 모달](img/deploy_freeze_v14_3.png)

프로젝트에 여러 동결 기간이 있으면 모든 기간이 적용됩니다. 겹치면 동결은 완전히 겹치는 기간을 커버합니다.

자세한 내용은 [배포 안전](../../../ci/environments/deployment_safety.md)을 참조하세요.

## 릴리스 권한 {#release-permissions}

### 릴리스 보기 및 자산 다운로드 {#view-a-release-and-download-assets}

- 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있는 사용자는 프로젝트 릴리스에 대한 읽기 및 다운로드 액세스 권한이 있습니다.
- 게스트 역할이 있는 사용자는 프로젝트 릴리스에 대한 읽기 및 다운로드 액세스 권한이 있습니다. 이것은 관련 Git 태그 이름, 릴리스 설명 및 릴리스 작성자 정보를 포함합니다. 그러나 [소스 코드](release_fields.md#source-code) 및 [릴리스 증거](release_evidence.md)와 같은 다른 리포지토리 관련 정보는 수정됩니다.

### 소스 코드 액세스 권한을 부여하지 않고 릴리스 게시 {#publish-releases-without-giving-access-to-source-code}

[소스 코드](release_fields.md#source-code) 및 [릴리스 증거](release_evidence.md)와 같은 리포지토리 관련 정보를 프로젝트 멤버만 사용할 수 있도록 유지하면서 비프로젝트 멤버가 릴리스에 액세스할 수 있도록 할 수 있습니다. 이러한 설정은 릴리스를 사용하여 새로운 소프트웨어 버전에 액세스하도록 하지만 소스 코드를 공개적으로 사용할 수 없도록 하려는 프로젝트에 이상적입니다.

릴리스를 공개적으로 사용 가능하게 하려면 다음 [프로젝트 설정](../settings/_index.md#configure-project-features-and-permissions)을 설정합니다:

- **프로젝트 공개 수준**이 **공개**로 설정됨
- **리포지토리**가 활성화되고 **프로젝트 멤버만**로 설정됨
- **릴리즈**가 활성화되고 **액세스 권한이 있는 모든 사용자**로 설정됨

### 릴리스 및 자산 생성, 업데이트 및 삭제 {#create-update-and-delete-a-release-and-its-assets}

- 개발자, 유지 관리자 또는 소유자 역할이 있는 사용자는 프로젝트 릴리스 및 자산에 대한 쓰기 액세스 권한이 있습니다.
- 릴리스가 [보호된 태그](../protected_tags.md)와 연결된 경우 사용자는 [보호된 태그를 생성할 수 있도록](../protected_tags.md#configure-protected-tags) 허용되어야 합니다.

릴리스 권한 제어의 예로, 와일드카드 (`*`)로 태그를 보호하고 **유지관리자**를 **생성이 허용됨** 열에 설정하여 유지 관리자 또는 소유자 역할만 있는 사용자가 릴리스를 생성, 업데이트 및 삭제할 수 있도록 허용할 수 있습니다.

## 릴리스 메트릭 {#release-metrics}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab Premium 13.9에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/259703)됨

{{< /history >}}

그룹 수준 릴리스 메트릭은 **그룹** > **분석** > **CI/CD**로 이동하여 사용할 수 있습니다. 이러한 메트릭에는 다음이 포함됩니다:

- 그룹의 총 릴리스 수
- 최소한 하나의 릴리스를 가진 그룹의 프로젝트 비율

## 작동하는 예제 프로젝트 {#working-example-project}

Guided Exploration 프로젝트 [GitVersion으로 완전히 자동화된 소프트웨어 및 아티팩트 버전 관리](https://gitlab.com/guided-explorations/devops-patterns/utterly-automated-versioning)는 다음을 보여줍니다:

- GitLab 릴리스 사용.
- [GitLab CLI](../../../editor_extensions/gitlab_cli/_index.md) 사용.
- Generic 패키지 생성.
- 릴리스에 패키지 연결.
- [GitVersion](https://gitversion.net/) 도구를 사용하여 복잡한 리포지토리의 버전을 자동으로 결정하고 증가시킵니다.

테스트를 위해 예제 프로젝트를 자신의 그룹 또는 인스턴스에 복사할 수 있습니다. 프로젝트 페이지에서 다른 GitLab CI 패턴이 어떻게 표현되는지에 대한 자세한 내용을 확인할 수 있습니다.

## 문제 해결 {#troubleshooting}

### 릴리스 및 자산 생성, 업데이트 또는 삭제 시 오류 {#errors-when-creating-updating-or-deleting-releases-and-their-assets}

릴리스가 [보호된 태그](../protected_tags.md)와 연결된 경우 UI/API 요청으로 인해 다음과 같은 권한 부여 실패가 발생할 수 있습니다:

- `403 Forbidden`
- `Something went wrong while creating a new release`

사용자 또는 서비스/봇 계정이 [보호된 태그를 생성할 수 있도록](../protected_tags.md#configure-protected-tags) 허용되는지 확인하세요.

자세한 내용은 [릴리스 권한](#release-permissions)을 참조하세요.

### 스토리지에 대한 참고 사항 {#note-about-storage}

이 기능은 Git 태그 위에 구축되므로 릴리스 자체를 생성하는 데 필요한 것 외에 거의 추가 데이터가 필요하지 않습니다. 추가 자산 및 자동으로 생성되는 릴리스 증거는 스토리지를 소비합니다.

### GitLab CLI 버전 요구사항 {#gitlab-cli-version-requirement}

[`release` 키워드](../../../ci/yaml/_index.md#release)를 사용하는 방식이 변경될 예정입니다. `release-cli` 도구는 [대체되고](https://gitlab.com/groups/gitlab-org/-/epics/15437) 있으며 [GitLab CLI 도구](https://gitlab.com/gitlab-org/cli/)로 대체됩니다.

GitLab CLI 도구 `v1.58.0` 이상을 사용해야 합니다. 그렇지 않으면 다음 오류 메시지 또는 경고 중 하나가 표시될 수 있습니다:

- `Error: glab command not found. Please install glab v1.58.0 or higher.`
- `Error: Please use glab v1.58.0 or higher.`
- `Warning: release-cli will not be supported after 20.0. Please use glab version >= 1.58.0.`

GitLab CLI 도구를 갖는 방법은 두 가지입니다:

- `registry.gitlab.com/gitlab-org/release-cli:<version>` 컨테이너 이미지를 사용하는 경우 `registry.gitlab.com/gitlab-org/cli:v1.58.0` 또는 `registry.gitlab.com/gitlab-org/release-cli:v0.24.0`를 사용할 수 있으며, `glab` `v1.58.0`이 포함되어 있습니다.
- 러너에 릴리스-CLI 또는 GitLab CLI 도구를 수동으로 설치한 경우 GitLab CLI 버전이 최소 `v1.58.0`인지 확인하세요.
