---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 쉼표로 구분된 값(CSV) 파일이 GitLab 프로젝트에 어떻게 표시되는지 알아봅니다.
title: CSV 파일
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

쉼표로 구분된 값(CSV) 파일은 값을 분리하기 위해 쉼표를 사용하는 구분 기호 텍스트 파일입니다. 파일의 각 행은 데이터 레코드입니다. 각 레코드는 쉼표로 분리된 하나 이상의 필드로 구성됩니다. 필드 구분자로 쉼표를 사용하는 것이 이 파일 형식의 이름의 출처입니다. CSV 파일은 일반적으로 표 형식의 데이터(숫자 및 텍스트)를 일반 텍스트로 저장하며, 이 경우 각 행은 동일한 수의 필드를 가집니다.

CSV 파일 형식은 완전히 표준화되지 않았습니다. 다른 문자를 열 구분 기호로 사용할 수 있습니다. 필드는 특수 문자를 이스케이프하기 위해 포함될 수도 있고 포함되지 않을 수도 있습니다.

리포지토리에 추가된 파일 중 `.csv` 확장자가 있는 파일은 GitLab에서 볼 때 표로 렌더링됩니다:

![표로 렌더링된 CSV 파일](img/csv_as_table_v17_10.png)

## CSV 파싱 고려 사항 {#csv-parsing-considerations}

GitLab은 [Papa Parse](https://github.com/mholt/PapaParse/) 라이브러리를 사용하여 CSV 파일을 파싱합니다. 이 라이브러리는 [RFC4180](https://datatracker.ietf.org/doc/html/rfc4180)을 따르며 특정 CSV 형식으로 파싱 문제를 유발할 수 있는 엄격한 형식 요구 사항이 있습니다.

예를 들어:

- 쉼표(`,`) 구분 기호와 큰따옴표(`"`) 주위의 간격으로 인해 파싱 오류가 발생할 수 있습니다.
- 쉼표와 큰따옴표를 모두 포함하는 필드로 인해 파서가 필드 경계를 잘못 식별할 수 있습니다.

다음 형식은 파싱 오류를 발생시킵니다:

```plaintext
"field1", "field2", "field3"
```

다음 형식은 성공적으로 파싱됩니다:

```plaintext
"field1","field2","field3"
```

CSV 파일이 GitLab에서 올바르게 표시되지 않는 경우:

- 필드가 큰따옴표(`"`)로 묶여 있는 경우, 큰따옴표와 쉼표(`,`) 구분 기호가 바로 인접하고 사이에 공백이 없는지 확인합니다.
- 특수 문자를 포함하는 모든 필드를 큰따옴표(`"`)로 묶습니다.
- 변경 후 CSV 파일이 GitLab에 표시되는 방식을 확인합니다.

이러한 파싱 요구 사항은 CSV 파일의 시각적 렌더링에만 영향을 미치며 리포지토리에 저장된 실제 파일 내용에는 영향을 주지 않습니다.
