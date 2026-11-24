---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: CSV에서 이슈 가져오기
description: "CSV 파일을 업로드하여 프로젝트로 이슈를 가져옵니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 17.7에서 플래너 역할에 대해 [허용](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)됩니다.
- `type` 열의 지원이 GitLab 18.4에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/199945)되었습니다.

{{< /history >}}

다음 열로 CSV(쉼표로 구분된 값) 파일을 업로드하여 프로젝트로 이슈를 가져올 수 있습니다:

| 이름          | 필수                             | 설명 |
| ------------- | ------------------------------------ | ----------- |
| `title`       | {{< yes >}} | 이슈 제목입니다. |
| `description` | {{< yes >}} | 이슈 설명입니다. |
| `due_date`    | {{< no >}} | `YYYY-MM-DD` 형식의 이슈 기한입니다. |
| `milestone`   | {{< no >}} | 이슈 마일스톤의 제목입니다. |
| `type`        | {{< no >}} | 이슈의 유형입니다. GitLab 18.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200893)되었습니다. |

다른 열의 데이터는 가져오지 않습니다.

`description` 필드를 사용하여 [빠른 작업](../quick_actions.md)을 삽입하여 이슈에 다른 데이터를 추가할 수 있습니다. 예를 들어 레이블, 담당자, 마일스톤을 들 수 있습니다.

또는 [이슈 이동](managing_issues.md#move-an-issue)할 수 있습니다. 이슈를 이동하면 더 많은 데이터가 보존됩니다.

CSV 파일을 업로드하는 사용자는 가져온 이슈의 작성자로 설정됩니다.

이슈를 가져오려면 프로젝트에 대해 플래너, 리포터, 보안 관리자, 개발자, 유지관리자 또는 소유자 역할이 필요합니다.

## 가져오기 준비 {#prepare-for-the-import}

- 몇 개의 이슈만 포함하는 테스트 파일 가져오기를 고려하세요. GitLab API를 사용하지 않고는 큰 가져오기를 취소할 방법이 없습니다.
- CSV 파일이 [파일 형식](#csv-file-format) 요구 사항을 충족하는지 확인하세요.
- CSV에 마일스톤 헤더가 포함되면 파일의 모든 고유 마일스톤 제목이 프로젝트 또는 상위 그룹에 이미 존재하는지 확인하세요.

## 파일 가져오기 {#import-the-file}

이슈를 가져오려면:

1. 프로젝트의 **이슈** 페이지로 이동합니다.
1. 프로젝트에 이슈가 있는지 여부에 따라 가져오기 기능을 엽니다:
   - 프로젝트에 기존 이슈가 있습니다. 오른쪽 위 모서리에서 **대량 편집** 옆에 있는 **조치**({{< icon name="ellipsis_v" >}}) > **CSV 가져오기**를 선택합니다.
   - 프로젝트에 이슈가 없습니다. 페이지 중앙에서 **CSV 가져오기**를 선택합니다.
1. 가져올 파일을 선택한 다음 **이슈 가져오기**를 선택합니다.

파일은 백그라운드에서 처리되며, 오류가 감지되거나 가져오기가 완료된 후에 알림 이메일이 전송됩니다.

## CSV 파일 형식 {#csv-file-format}

이슈를 가져오려면 GitLab은 CSV 파일이 특정 형식을 갖춰야 합니다.

> [!note]
> GitLab에서 본 가져온 파일 표시 방식에 영향을 미칠 수 있는 CSV 구문 분석 요구 사항에 대한 자세한 내용은 [CSV 구문 분석 고려 사항](../repository/files/csv.md#csv-parsing-considerations)을 참조하세요.

| 요소                | 형식 |
| ---------------------- | ------ |
| 헤더 행             | CSV 파일은 다음 헤더를 포함해야 합니다: `title` 및 `description`. 헤더의 대소문자는 상관없습니다. |
| 열                | `title`, `description`, `due_date`, `milestone`, `type` 범위를 벗어난 열의 데이터는 가져오지 않습니다. |
| 구분 기호             | 열 구분 기호는 헤더 행에서 감지됩니다. 지원되는 구분 기호 문자는 쉼표(`,`), 세미콜론(`;`), 탭(`\t`)입니다. 행 구분 기호는 `CRLF` 또는 `LF`일 수 있습니다. |
| 큰따옴표 문자 | 큰따옴표(`"`) 문자는 필드에 인용 부호를 붙이는 데 사용되며, 필드에서 열 구분 기호를 사용할 수 있게 합니다(아래 샘플 CSV 데이터의 세 번째 줄 참조). 인용된 필드에 큰따옴표(`"`)를 삽입하려면 큰따옴표 문자 2개를 연속으로 사용하세요(`""`). |
| 데이터 행              | 헤더 행 이후, 다음 행은 동일한 열 순서를 사용해야 합니다. 이슈 제목은 필수이지만 설명은 선택 사항입니다. |

특수 문자(예: `,` 또는 `\n`) 또는 필드의 여러 줄(예: [빠른 작업](../quick_actions.md) 사용 시)이 있으면 문자를 큰따옴표(`"`)로 감싸세요.

[빠른 작업](../quick_actions.md) 사용 시:

- 각 작업은 별도 줄에 있어야 합니다.
- `/label` 및 `/milestone`와 같은 빠른 작업의 경우 레이블 또는 마일스톤이 프로젝트에 이미 존재해야 합니다.
- 이슈를 할당하는 사용자는 프로젝트의 구성원이어야 합니다.

샘플 CSV 데이터:

```plaintext
title,description,due_date,milestone
My Issue Title,My Issue Description,2022-06-28
Another Title,"A description, with a comma",
"One More Title","One More Description",
An Issue with Quick Actions,"Hey can we change the frontend?

/assign @sjones
/label ~frontend ~documentation",
An issue with milestone,"My milestone is created",,v1.0
```

### 파일 크기 {#file-size}

제한은 GitLab 인스턴스가 호스팅되는 방식에 따라 다릅니다:

- GitLab Self-Managed: GitLab 인스턴스에 대해 `Max Attachment Size`의 구성 값으로 설정됩니다.
- GitLab.com: 10 MB로 제한됩니다.
