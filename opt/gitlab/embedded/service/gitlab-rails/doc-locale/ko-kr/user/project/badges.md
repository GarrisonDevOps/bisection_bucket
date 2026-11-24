---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 배지
description: "파이프라인 상태, 그룹, 프로젝트 및 사용자 정의 배지."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

배지는 프로젝트에 대한 압축된 정보를 제시하는 통합된 방법입니다. 배지는 작은 이미지와 해당 이미지가 가리키는 URL로 구성됩니다. GitLab에서 배지는 프로젝트 개요 페이지에 프로젝트 설명 아래에 표시됩니다. [프로젝트](#project-badges) 및 [그룹](#group-badges) 수준에서 배지를 사용할 수 있습니다.

## 사용 가능한 배지 {#available-badges}

GitLab은 다음 파이프라인 배지를 제공합니다:

- [파이프라인 상태 배지](#pipeline-status-badges)
- [테스트 커버리지 보고서 배지](#test-coverage-report-badges)
- [최신 릴리스 배지](#latest-release-badges)

GitLab은 또한 [배지 스타일 조정](#customize-badges)을 지원합니다.

## 파이프라인 상태 배지 {#pipeline-status-badges}

파이프라인 상태 배지는 프로젝트의 최신 파이프라인 상태를 나타냅니다. 파이프라인 상태에 따라 배지는 다음 값 중 하나를 가질 수 있습니다:

- `pending`
- `running`
- `passed`
- `failed`
- `skipped`
- `manual`
- `canceled`
- `unknown`

다음 링크를 사용하여 파이프라인 상태 배지 이미지에 접근할 수 있습니다:

```plaintext
https://gitlab.example.com/<namespace>/<project>/badges/<branch>/pipeline.svg
```

### 건너뛴 항목만 제외하고 상태 표시 {#display-only-non-skipped-status}

파이프라인 상태 배지가 마지막 건너뛴 항목이 아닌 상태만 표시하도록 하려면 `?ignore_skipped=true` 쿼리 매개변수를 사용하세요:

```plaintext
https://gitlab.example.com/<namespace>/<project>/badges/<branch>/pipeline.svg?ignore_skipped=true
```

## 테스트 커버리지 보고서 배지 {#test-coverage-report-badges}

테스트 커버리지 보고서 배지는 프로젝트에서 테스트된 코드의 백분율을 나타냅니다. 값은 최신 성공한 파이프라인을 기반으로 계산됩니다.

다음 링크를 사용하여 테스트 커버리지 보고서 배지 이미지에 접근할 수 있습니다:

```plaintext
https://gitlab.example.com/<namespace>/<project>/badges/<branch>/coverage.svg
```

각 작업 로그가 일치하는 [코드 커버리지](../../ci/testing/code_coverage/coverage_reporting.md#configure-coverage-reporting)에 대한 정규식을 정의할 수 있습니다. 이는 파이프라인의 각 작업이 정의된 테스트 커버리지 백분율 값을 가질 수 있음을 의미합니다.

특정 작업에서 커버리지 보고서를 가져오려면 URL에 `job=coverage_job_name` 매개변수를 추가하세요. 예를 들어, 다음과 유사한 코드를 사용하여 `coverage` 작업의 테스트 커버리지 보고서 배지를 Markdown 파일에 추가할 수 있습니다:

```markdown
![coverage](https://gitlab.example.com/<namespace>/<project>/badges/<branch>/coverage.svg?job=coverage)
```

### 테스트 커버리지 한계 및 배지 색상 {#test-coverage-limits-and-badge-colors}

다음 표는 기본 테스트 커버리지 한계 및 배지 색상을 보여줍니다:

| 테스트 커버리지 | 백분율 범위           | 배지 색상 |
|---------------|-----------------------------|-------------|
| 양호          | 95 이상 100% 이하 | <span style="color: #4c1">■</span> `#4c1` |
| 허용 가능    | 90 이상 95% 미만                | <span style="color:#a3c51c"> ■</span> `#a3c51c` |
| 중간        | 75 이상 90% 미만                | <span style="color: #dfb317">■</span> `#dfb317` |
| 낮음           | 0 이상 75% 미만                 | <span style="color: #e05d44">■</span> `#e05d44` |
| 알 수 없음       | 커버리지 없음                 | <span style="color: #9f9f9f">■</span> `#9f9f9f` |

> [!note]
> _이상_은 상한선을 포함하여 말하지만 초과하지는 않습니다.

### 기본 한계 변경 {#change-the-default-limits}

커버리지 보고서 배지 URL에 다음 쿼리 매개변수를 전달하여 기본 한계를 재정의할 수 있습니다:

| 쿼리 매개변수  | 허용 가능한 값                            | 기본값 |
|------------------|----------------------------------------------|---------|
| `min_good`       | `3`과 `100` 사이의 모든 값              | `95`    |
| `min_acceptable` | `2`과 `min_good`−1 사이의 모든 값       | `90`    |
| `min_medium`     | `1`과 `min_acceptable`−1 사이의 모든 값 | `75`    |

예를 들어:

```plaintext
https://gitlab.example.com/<namespace>/<project>/badges/<branch>/coverage.svg?min_good=98&min_acceptable=75
```

유효하지 않은 경계를 설정하면 GitLab은 자동으로 유효하도록 조정합니다. 예를 들어 `min_good`을 `80`로, `min_acceptable`을 `85`로 설정하면 GitLab은 `min_acceptable`을 `79`으로 설정합니다 (`min_good - 1`) 최소 허용 가능 값이 최소 양호 값보다 높을 수 없기 때문입니다.

## 최신 릴리스 배지 {#latest-release-badges}

최신 릴리스 배지는 프로젝트의 최신 릴리스 태그 이름을 나타냅니다. 릴리스가 없으면 `none`을 표시합니다.

다음 링크를 사용하여 최신 릴리스 배지 이미지에 접근할 수 있습니다:

```plaintext
https://gitlab.example.com/<namespace>/<project>/-/badges/release.svg
```

기본적으로 배지는 [`released_at`](../../api/releases/_index.md#create-a-release) 시간을 사용하여 정렬된 릴리스를 가져오며 `?order_by` 쿼리 매개변수를 포함합니다.

```plaintext
https://gitlab.example.com/<namespace>/<project>/-/badges/release.svg?order_by=release_at
```

`value_width` 매개변수를 사용하여 릴리스 이름 필드의 너비를 변경할 수 있습니다. 값은 1에서 200 사이여야 하며 기본값은 54입니다. 범위를 벗어난 값을 설정하면 GitLab은 자동으로 기본값으로 조정합니다.

## 프로젝트 배지 {#project-badges}

배지는 유지관리자 또는 소유자가 프로젝트에 추가할 수 있으며 프로젝트의 **개요** 페이지에 표시됩니다. 여러 프로젝트에 동일한 배지를 추가해야 한다면 [그룹 수준](#group-badges)에서 추가하는 것을 고려할 수 있습니다.

### 프로젝트 배지 예: 파이프라인 상태 {#example-project-badge-pipeline-status}

일반적인 프로젝트 배지는 GitLab CI 파이프라인 상태를 표시합니다.

프로젝트에 이 배지를 추가하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **배지**를 확장합니다.
1. **이름** 아래에 _파이프라인 상태_를 입력합니다.
1. **링크** 아래에 다음 URL을 입력합니다: `https://gitlab.example.com/%{project_path}/-/commits/%{default_branch}`
1. **배지 이미지 URL** 아래에 다음 URL을 입력합니다: `https://gitlab.example.com/%{project_path}/badges/%{default_branch}/pipeline.svg`
1. **배지 추가**를 선택합니다.

## 그룹 배지 {#group-badges}

배지는 소유자가 그룹에 추가할 수 있으며 그룹에 속하는 모든 프로젝트의 **개요** 페이지에 표시됩니다. 그룹에 배지를 추가하면 그룹의 모든 프로젝트에 대해 프로젝트 수준 배지를 추가하고 적용합니다.

> [!note]
> 이 배지들이 코드베이스에서 프로젝트 수준 배지로 나타나지만 프로젝트 수준에서는 편집하거나 삭제할 수 없습니다.

각 프로젝트에 대한 개별 배지가 필요한 경우 다음 중 하나를 선택하세요:

- [프로젝트 수준](#project-badges)에서 배지를 추가합니다.
- [자리표시자](#placeholders)를 사용합니다.

## 배지 보기 {#view-badges}

프로젝트 또는 그룹에서 사용 가능한 배지를 보려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **배지**를 확장합니다.

## 배지 추가 {#add-a-badge}

프로젝트 또는 그룹에 새 배지를 추가하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **배지**를 확장합니다.
1. **배지 추가**를 선택합니다.
1. **이름** 텍스트 상자에 배지의 이름을 입력합니다.
1. **링크** 텍스트 상자에 배지가 가리켜야 할 URL을 입력합니다.
1. **배지 이미지 URL** 텍스트 상자에 배지에 표시할 이미지의 URL을 입력합니다.
1. **배지 추가**를 선택합니다.

## 파이프라인 배지의 URL 보기 {#view-the-url-of-pipeline-badges}

배지의 정확한 링크를 볼 수 있습니다. 그러면 해당 링크를 사용하여 HTML 또는 Markdown 페이지에 배지를 포함할 수 있습니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **일반 파이프라인**을 확장합니다.
1. **파이프라인 상태**, **커버리지 보고서** 또는 **최신 릴리스** 섹션에서 이미지의 URL을 봅니다.

> [!note]
> 파이프라인 상태 배지는 특정 Git 리비전(브랜치)을 기반으로 합니다. 올바른 파이프라인 상태를 보려면 적절한 브랜치를 선택했는지 확인하세요.

## 배지 사용자 정의 {#customize-badges}

{{< details >}}

- 상태:  베타

{{< /details >}}

{{< history >}}

- GitLab 18.5에서 `custom_project_badges`라는 [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/180832)되었습니다. 기본적으로 사용 중지됩니다.
- GitLab 18.6에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에 사용으로 설정](https://gitlab.com/gitlab-org/gitlab/-/issues/574344)되었습니다.
- GitLab 19.2에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/574344)입니다. 기능 플래그 `custom_project_badges`이 제거되었습니다.

{{< /history >}}

프로젝트에서 배지가 표시되는 방식을 사용자 정의할 수 있습니다:

- [기본 사용자 정의](#basic-customization)는 모든 배지 유형에 대해 작동합니다.
- [고급 사용자 정의](#custom-badges)는 사용자 정의 배지에만 사용 가능합니다.

### 기본 사용자 정의 {#basic-customization}

모든 배지 유형의 다음 측면을 사용자 정의할 수 있습니다:

- [스타일](#style)
- [키 텍스트](#key-text)
- [키 너비](#key-width)
- [값 너비](#value-width)

#### 스타일 {#style}

파이프라인, 커버리지, 릴리스 및 사용자 정의 배지는 URL에 `style=style_name` 매개변수를 추가하여 다양한 스타일로 렌더링할 수 있습니다. 두 가지 스타일을 사용할 수 있습니다:

- 평면(기본값):

  ```plaintext
  https://gitlab.example.com/<namespace>/<project>/badges/<branch>/coverage.svg?style=flat
  ```

  ![95.00% 커버리지를 보여주는 커버리지 배지입니다.](img/badge_flat.svg)

- 평면 사각형:

  ```plaintext
  https://gitlab.example.com/<namespace>/<project>/badges/<branch>/coverage.svg?style=flat-square
  ```

  ![평면 사각형 스타일로 95.00% 커버리지를 보여주는 커버리지 배지입니다.](img/badge_flat_square.svg)

#### 키 텍스트 {#key-text}

배지의 왼쪽 텍스트를 사용자 정의할 수 있습니다. 예를 들어 동일한 파이프라인에서 실행되는 여러 커버리지 작업을 구분합니다.

URL에 `key_text=custom_text` 매개변수를 추가하여 배지 키 텍스트를 사용자 정의합니다:

```plaintext
https://gitlab.example.com/gitlab-org/gitlab/badges/main/coverage.svg?job=karma&key_text=Frontend+Coverage&key_width=130
```

![95.00% 커버리지를 보여주는 프론트엔드 커버리지 배지입니다.](img/badge_custom_text.svg)

#### 키 너비 {#key-width}

URL에 `key_width=width` 매개변수를 추가하여 배지 키 너비를 사용자 정의합니다:

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/coverage.svg?key_width=130
```

#### 값 너비 {#value-width}

URL에 `value_width=width` 매개변수를 추가하여 배지 값 너비를 사용자 정의합니다:

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/coverage.svg?value_width=130
```

### 사용자 정의 배지 {#custom-badges}

사용자 정의 배지는 배지의 양쪽을 완벽하게 제어할 수 있게 해줍니다. 파이프라인 상태와 같이 미리 정의된 정보를 표시하는 표준 배지와 달리 사용자 정의 배지를 사용하면:

- 배지의 양쪽에 모든 텍스트를 표시합니다
- 사용자 정의 색상을 사용합니다
- 프로젝트별 정보를 표시합니다
- [자리표시자](#placeholders)를 사용하여 동적 배지를 만듭니다

[기본 사용자 정의 옵션](#basic-customization) 외에도 사용자 정의 배지는 다음과 같은 추가 사용자 정의 옵션을 지원합니다:

- [키 색상](#key-color)
- [값 색상](#value-color)
- [값 텍스트](#value-text)

다음 링크를 사용하여 사용자 정의 배지를 추가할 수 있습니다:

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/custom.svg
```

예를 들어 [자리표시자](#placeholders)를 사용하여 최신 태그에 대한 배지를 만들 수 있습니다:

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/custom.svg?key_text=Latest_tag&value_text=%{latest_tag}&key_color=white&value_color=7bc043
```

> [!warning]
> 자리표시자를 사용하면 배지가 프로젝트가 개인 리포지토리로 구성된 경우 기본 브랜치 또는 커밋 SHA와 같은 개인 정보를 노출할 수 있습니다. 이 동작은 의도적이며 배지는 공개적으로 사용하기 위한 것입니다. 정보가 민감한 경우 이러한 자리표시자를 사용하지 마세요.

#### 값 텍스트 {#value-text}

URL에 `value_text=text` 매개변수를 추가하여 오른쪽에 표시되는 텍스트를 사용자 정의합니다:

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/custom.svg?value_text=badge
```

#### 값 색상 {#value-color}

URL에 `value_color=color` 매개변수를 추가하여 오른쪽의 배경색을 사용자 정의합니다:

색상을 다음과 같이 전달할 수 있습니다:

- [명명된 색상](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Values/named-color) (예: `blue`)
- `fff`, `7bc043` 같은 16진수 표현 (앞의 `#`은 제외)

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/custom.svg?value_color=red
```

#### 키 색상 {#key-color}

URL에 `value_color=color` 매개변수를 추가하여 왼쪽의 배경색을 사용자 정의합니다:

색상을 다음과 같이 전달할 수 있습니다:

- [명명된 색상](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Values/named-color) (예: `blue`)
- `fff`, `7bc043` 같은 16진수 표현 (앞의 `#`은 제외)

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/custom.svg?key_color=green
```

### 사용자 정의 배지 이미지 추가 {#add-a-custom-badge-image}

사전 요구 사항:

- 프로젝트 또는 그룹에 대해 개발자, 유지관리자 또는 소유자 역할이 있어야 합니다.
- 배지에 대한 원하는 이미지를 직접 가리키는 유효한 URL이 있어야 합니다. 이미지가 GitLab 리포지토리에 있으면 이미지의 원본 링크를 사용하세요.

이미지를 포함한 사용자 정의 배지를 추가하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **배지**를 확장합니다.
1. **이름** 아래에 배지의 이름을 입력합니다.
1. **링크** 아래에 배지가 가리켜야 할 URL을 입력합니다.
1. **배지 이미지 URL** 아래에 사용자 정의 이미지의 URL을 입력합니다. 예를 들어 리포지토리에서 이미지를 사용하려면:

   ```plaintext
   https://gitlab.example.com/<project_path>/-/raw/<default_branch>/custom-image.svg
   ```

1. **배지 추가**를 선택합니다.

파이프라인을 통해 생성된 사용자 정의 이미지를 사용하려면 [URL로 최신 작업 아티팩트에 접근](../../ci/jobs/job_artifacts.md#by-job-name-and-branch)을 참조하세요.

## 배지 편집 {#edit-a-badge}

프로젝트 또는 그룹의 배지를 편집하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **배지**를 확장합니다.
1. 편집하려는 배지 옆에서 **편집**({{< icon name="pencil" >}})을 선택합니다.
1. **이름**, **링크** 또는 **배지 이미지 URL**을 편집합니다.
1. **변경 사항 저장**을 선택합니다.

## 배지 삭제 {#delete-a-badge}

프로젝트 또는 그룹의 배지를 삭제하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **배지**를 확장합니다.
1. 삭제하려는 배지 옆에서 **삭제**({{< icon name="remove" >}})을 선택합니다.
1. 확인 대화상자에서 **배지 삭제**를 선택합니다.

> [!note]
> 그룹과 연결된 배지는 [그룹 수준](#group-badges)에서만 편집하거나 삭제할 수 있습니다.

## 자리 표시자 {#placeholders}

배지가 가리키는 URL과 이미지 URL 모두 배지를 표시할 때 평가되는 자리표시자를 포함할 수 있습니다. 다음 자리표시자를 사용할 수 있습니다:

- `%{project_path}`: 상위 그룹을 포함한 프로젝트 경로
- `%{project_title}`: 프로젝트의 제목
- `%{project_name}`: 프로젝트의 이름
- `%{project_id}`: 프로젝트와 연결된 데이터베이스 ID
- `%{project_namespace}`: 프로젝트의 프로젝트 네임스페이스
- `%{group_name}`: 프로젝트의 그룹
- `%{gitlab_server}`: 프로젝트의 서버
- `%{gitlab_pages_domain}`: GitLab Pages를 호스팅하는 도메인
- `%{default_branch}`: 프로젝트 리포지토리에 대해 구성된 기본 브랜치 이름
- `%{commit_sha}`: 프로젝트 리포지토리의 기본 브랜치에 대한 가장 최근 커밋의 ID
- `%{latest_tag}`: 프로젝트 리포지토리에 추가된 최신 태그

> [!warning]
> 자리표시자를 사용하면 배지가 프로젝트가 개인 리포지토리로 구성된 경우 기본 브랜치 또는 커밋 SHA와 같은 개인 정보를 노출할 수 있습니다. 이 동작은 의도적이며 배지는 공개적으로 사용하기 위한 것입니다. 정보가 민감한 경우 이러한 자리표시자를 사용하지 마세요.

<!-- -->

> [!warning]
> [이슈 481729](https://gitlab.com/gitlab-org/gitlab/-/work_items/481729)로 인해 `%{gitlab_server}`과 `%{gitlab_pages_domain}`는 URL에서 호스트명을 지정하는 데 사용할 수 없지만 다른 매개변수에는 사용할 수 있습니다.
