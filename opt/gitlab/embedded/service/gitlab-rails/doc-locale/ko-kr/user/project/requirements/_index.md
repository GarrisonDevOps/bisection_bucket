---
stage: Plan
group: Portfolio Planning
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 요구 사항 관리
description: "수용 기준, 요구 사항 테스트 보고서 및 CSV 가져오기."
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

요구 사항을 사용하면 제품을 확인할 기준을 설정할 수 있습니다. 사용자, 이해관계자, 시스템, 소프트웨어 또는 캡처하고 싶은 다른 모든 항목을 기반으로 할 수 있습니다.

요구 사항은 제품의 특정 동작을 설명하는 GitLab의 아티팩트입니다. 요구 사항은 장기간 유지되며 수동으로 삭제하지 않으면 사라지지 않습니다.

업계 표준에서 애플리케이션이 특정 기능이나 동작을 해야 하는 경우 이를 반영하기 위해 [요구 사항을 생성](#create-a-requirement)할 수 있습니다. 기능이 더 이상 필요하지 않으면 [관련 요구 사항을 아카이브](#archive-a-requirement)할 수 있습니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 개요를 보려면 [요구 사항 관리](https://www.youtube.com/watch?v=uSS7oUNSEoU)를 참조하세요.
<!-- Video published on 2020-04-09 -->

<i class="fa-youtube-play" aria-hidden="true"></i> 더 자세한 안내는 [GitLab 요구 사항 추적성 안내](https://youtu.be/VIiuTQYFVa0)를 참조하세요.
<!-- Video published on 2020-02-12 -->

![열기, 아카이빙됨, 모든 요구 사항을 표시하는 탭이 있는 요구 사항 목록 보기입니다.](img/requirements_list_v13_5.png)

## 요구 사항 생성 {#create-a-requirement}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

각 프로젝트에서 요구 사항의 페이지 매김 목록을 사용할 수 있으며, 여기서 새 요구 사항을 생성할 수 있습니다.

사전 요구 사항:

- 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

요구 사항을 생성하려면:

1. 프로젝트에서 **계획** > **요구사항**으로 이동합니다.
1. **새 요구 사항**을 선택합니다.
1. 제목과 설명을 입력하고 **새 요구 사항**을 선택합니다.

![제목과 설명을 입력하는 오른쪽 사이드 패널의 요구 사항 양식입니다.](img/requirement_create_v13_5.png)

새로 생성된 요구 사항은 목록 상단에 표시되며, 요구 사항 목록은 생성 날짜를 기준으로 내림차순으로 정렬됩니다.

## 요구 사항 보기 {#view-a-requirement}

목록에서 요구 사항을 선택하여 볼 수 있습니다.

![선택한 요구 사항의 예입니다.](img/requirement_view_v13_5.png)

요구 사항을 보는 동안 편집하려면 요구 사항 제목 옆의 **편집** 아이콘 ({{< icon name="pencil" >}})을 선택합니다.

## 요구 사항 편집 {#edit-a-requirement}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

요구 사항 목록 페이지에서 요구 사항을 편집할 수 있습니다.

사전 요구 사항:

- 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나 요구 사항의 작성자 또는 할당자여야 합니다.

요구 사항을 편집하려면:

1. 요구 사항 목록에서 **편집** 아이콘 ({{< icon name="pencil" >}})을 선택합니다.
1. 텍스트 입력 필드에서 제목과 설명을 업데이트합니다. 편집 양식에서 **충족** 체크박스를 사용하여 요구 사항을 만족으로 표시할 수도 있습니다.
1. **변경 사항 저장**을 선택합니다.

## 요구 사항 아카이브 {#archive-a-requirement}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

**열기** 탭에 있는 동안 열려 있는 요구 사항을 아카이브할 수 있습니다.

사전 요구 사항:

- 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나 요구 사항의 작성자 또는 할당자여야 합니다.

요구 사항을 아카이브하려면 **아카이브** ({{< icon name="archive" >}})를 선택합니다.

요구 사항이 아카이브되면 **열기** 탭에 더 이상 표시되지 않습니다.

## 요구 사항 다시 열기 {#reopen-a-requirement}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

**아카이빙됨** 탭에서 아카이브된 요구 사항 목록을 볼 수 있습니다.

사전 요구 사항:

- 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있거나 요구 사항의 작성자 또는 할당자여야 합니다.

![아카이브된 요구 사항 목록 보기입니다.](img/requirements_archived_list_view_v13_1.png)

아카이브된 요구 사항을 다시 열려면 **다시 열기**를 선택합니다.

요구 사항이 다시 열리면 **아카이빙됨** 탭에 더 이상 표시되지 않습니다.

## 요구 사항 검색 {#search-for-a-requirement}

다음 기준을 기반으로 요구 사항 목록 페이지에서 요구 사항을 검색할 수 있습니다:

- 제목
- 작성자의 사용자명
- 상태(만족, 실패 또는 누락)

요구 사항을 검색하려면:

1. 프로젝트에서 **계획** > **요구사항** > **목록**으로 이동합니다.
1. **검색 또는 결과 필터** 필드를 선택합니다. 드롭다운 목록이 표시됩니다.
1. 드롭다운 목록에서 요구 사항 작성자 또는 상태를 선택하거나 요구 사항 제목으로 검색할 일반 텍스트를 입력합니다.
1. 키보드에서 <kbd>Enter</kbd>를 눌러 목록을 필터링합니다.

다음을 기준으로 요구 사항 목록을 정렬할 수도 있습니다:

- 생성 날짜
- 업데이트 날짜

## CI 작업에서 요구 사항을 만족할 수 있도록 허용 {#allow-requirements-to-be-satisfied-from-a-ci-job}

GitLab은 이제 [요구 사항 테스트 보고서](../../../ci/yaml/artifacts_reports.md#artifactsreportsrequirements)를 지원합니다. CI 파이프라인에 작업을 추가할 수 있으며, 트리거되면 모든 기존 요구 사항을 만족으로 표시합니다(편집 양식에서 요구 사항을 수동으로 만족할 수 있습니다. [요구 사항 편집](#edit-a-requirement)).

### CI에 수동 작업 추가 {#add-the-manual-job-to-ci}

수동 작업이 트리거될 때 요구 사항을 만족으로 표시하도록 CI를 구성하려면 다음 코드를 `.gitlab-ci.yml` 파일에 추가합니다.

```yaml
requirements_confirmation:
  when: manual
  allow_failure: false
  script:
    - mkdir tmp
    - echo "{\"*\":\"passed\"}" > tmp/requirements.json
  artifacts:
    reports:
      requirements: tmp/requirements.json
```

이 정의는 수동으로 트리거되는(`when: manual`) 작업을 CI 파이프라인에 추가합니다. 이것은 차단(`allow_failure: false`)이지만 CI 작업을 트리거하기 위해 사용하는 조건은 사용자의 재량입니다. 또한 CI 작업이 `requirements.json` 아티팩트를 생성하고 업로드하는 한 기존 CI 작업을 사용하여 모든 요구 사항을 만족으로 표시할 수 있습니다.

이 작업을 수동으로 트리거하면 `{"*":"passed"}`를 포함하는 `requirements.json` 파일이 아티팩트로 서버에 업로드됩니다. 서버 측에서 요구 사항 보고서는 "모두 통과" 기록(`{"*":"passed"}`)을 확인하고 성공 시 모든 기존 열려 있는 요구 사항을 만족으로 표시합니다.

#### 개별 요구 사항 지정 {#specifying-individual-requirements}

개별 요구 사항 및 해당 상태를 지정할 수 있습니다.

다음 요구 사항이 존재하는 경우:

- `REQ-1` (IID `1`)
- `REQ-2` (IID `2`)
- `REQ-3` (IID `3`)

첫 번째 요구 사항은 통과했고 두 번째는 실패했음을 지정할 수 있습니다. 유효한 값은 "passed" 및 "failed"입니다. 요구 사항 IID를 생략하면(이 경우 `REQ-3`의 IID `3`) 결과가 기록되지 않습니다.

```yaml
requirements_confirmation:
  when: manual
  allow_failure: false
  script:
    - mkdir tmp
    - echo "{\"1\":\"passed\", \"2\":\"failed\"}" > tmp/requirements.json
  artifacts:
    reports:
      requirements: tmp/requirements.json
```

### 조건부로 CI에 수동 작업 추가 {#add-the-manual-job-to-ci-conditionally}

열려 있는 요구 사항이 있을 때만 수동 작업을 포함하도록 CI를 구성하려면 `CI_HAS_OPEN_REQUIREMENTS` CI/CD 변수를 확인하는 규칙을 추가합니다.

```yaml
requirements_confirmation:
  rules:
    - if: '$CI_HAS_OPEN_REQUIREMENTS == "true"'
      when: manual
    - when: never
  allow_failure: false
  script:
    - mkdir tmp
    - echo "{\"*\":\"passed\"}" > tmp/requirements.json
  artifacts:
    reports:
      requirements: tmp/requirements.json
```

요구 사항과 [테스트 사례](../../../ci/test_cases/_index.md)가 [작업 항목으로 마이그레이션](https://gitlab.com/groups/gitlab-org/-/epics/5171)되고 있기 때문에 프로젝트에서 작업 항목을 활성화한 경우 이전 구성에서 `requirements`을(를) `requirements_v2`로 바꿔야 합니다:

```yaml
      requirements_v2: tmp/requirements.json
```

## CSV 파일에서 요구 사항 가져오기 {#import-requirements-from-a-csv-file}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

[CSV 파일](https://en.wikipedia.org/wiki/Comma-separated_values)을 업로드하여 프로젝트로 요구 사항을 가져올 수 있으며, 열 `title` 및 `description`을(를) 포함해야 합니다.

가져온 후 CSV 파일을 업로드한 사용자는 가져온 요구 사항의 작성자로 설정됩니다.

### 파일 가져오기 {#import-the-file}

파일을 가져오기 전에:

- 몇 가지 요구 사항만 포함하는 테스트 파일을 가져오는 것을 고려하세요. GitLab API를 사용하지 않고는 대규모 가져오기를 실행 취소할 방법이 없습니다.
- CSV 파일이 [파일 형식](#imported-csv-file-format) 요구 사항을 충족하는지 확인합니다.

요구 사항을 가져오려면:

1. 프로젝트에서 **계획** > **요구사항**으로 이동합니다.
   - 요구 사항이 있는 프로젝트의 경우 오른쪽 위 모서리에서 세로 줄임표({{< icon name="ellipsis_v" >}})를 선택한 후 **요구 사항 가져오기** ({{< icon name="import" >}})를 선택합니다.
   - 요구 사항이 없는 프로젝트의 경우 페이지 중간에서 **CSV 가져오기**를 선택합니다.
1. 파일을 선택한 후 **요구 사항 가져오기**를 선택합니다.

파일은 백그라운드에서 처리되며 가져오기가 완료된 후 알림 이메일이 전송됩니다.

### 가져온 CSV 파일 형식 {#imported-csv-file-format}

CSV 파일에서 요구 사항을 가져올 때 특정 방식으로 형식을 지정해야 합니다:

- **헤더 행**: CSV 파일은 다음 헤더를 포함해야 합니다: `title` 및 `description`. 헤더는 대소문자를 구분하지 않습니다.
- **열**: `title` 및 `description` 이외의 열의 데이터는 가져오지 않습니다.
- **구분 기호**: 열 구분 기호는 헤더 행에서 자동으로 감지됩니다. 지원되는 구분 기호 문자는 쉼표(`,`), 세미콜론(`;`) 및 탭(`\t`)입니다. 행 구분 기호는 `CRLF` 또는 `LF`일 수 있습니다.
- **큰따옴표 문자**: 큰따옴표(`"`) 문자는 필드를 인용하는 데 사용되며, 필드의 열 구분 기호 사용을 가능하게 합니다(아래 샘플 CSV 데이터의 세 번째 줄 참조). 인용된 필드에 큰따옴표(`"`)를 삽입하려면 연속으로 두 개의 큰따옴표 문자(`""`)를 사용합니다.
- **데이터 행**: 헤더 행 아래에서 후속 행은 동일한 열 순서를 따라야 합니다. 제목 텍스트는 필수이지만 설명은 선택사항이며 비워둘 수 있습니다.

샘플 CSV 데이터:

```plaintext
title,description
My Requirement Title,My Requirement Description
Another Title,"A description, with a comma"
"One More Title","One More Description"
```

### 파일 크기 {#file-size}

제한은 GitLab 인스턴스의 최대 첨부 파일 크기 구성 값에 따라 달라집니다.

GitLab.com의 경우 10MB로 설정됩니다.

## CSV 파일로 요구 사항 내보내기 {#export-requirements-to-a-csv-file}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

GitLab 요구 사항을 [CSV 파일](https://en.wikipedia.org/wiki/Comma-separated_values)로 내보낼 수 있으며 기본 알림 이메일로 첨부 파일로 전송됩니다.

요구 사항을 내보내면 사용자와 팀이 요구 사항을 다른 도구로 가져오거나 고객과 공유할 수 있습니다. 요구 사항을 내보내면 상위 수준 시스템과의 협업, 감사 및 규정 준수 작업을 지원할 수 있습니다.

사전 요구 사항:

- 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

요구 사항을 내보내려면:

1. 프로젝트에서 **계획** > **요구사항**으로 이동합니다.
1. 오른쪽 위 모서리에서 세로 줄임표({{< icon name="ellipsis_v" >}})를 선택한 후 **CSV로 내보내기** ({{< icon name="export" >}})를 선택합니다.

   확인 대화 상자가 표시됩니다.

1. **고급 내보내기 옵션**에서 내보낼 필드를 선택합니다.

   기본적으로 모든 필드가 선택됩니다. 필드를 내보내기에서 제외하려면 옆의 확인란을 선택 해제합니다.

1. **요구 사항 내보내기**를 선택합니다. 내보낸 CSV 파일이 사용자와 연결된 이메일 주소로 전송됩니다.

### 내보낸 CSV 파일 형식 {#exported-csv-file-format}

<!-- vale gitlab_base.Spelling = NO -->

Microsoft Excel, OpenOffice Calc 또는 Google Sheets와 같은 스프레드시트 편집기에서 내보낸 CSV 파일을 미리 볼 수 있습니다.

<!-- vale gitlab_base.Spelling = YES -->

내보낸 CSV 파일에는 다음 헤더가 포함됩니다:

- 요구 사항 ID
- 제목
- 설명
- 작성자
- 작성자 사용자명
- Created At(UTC)
- 상태
- 상태 업데이트 시간(UTC)
