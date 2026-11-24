---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 머지 리퀘스트를 CSV로 내보내기
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

프로젝트의 머지 리퀘스트에서 수집한 모든 데이터를 쉼표로 구분된 값(CSV) 파일로 내보냅니다.

머지 리퀘스트를 CSV 파일로 내보내려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**을 선택합니다.
1. 검색이나 필터를 추가합니다. 이를 통해 CSV 파일의 크기를 15MB 제한 이하로 유지할 수 있습니다. 이 제한은 파일을 다양한 이메일 제공업체로 이메일할 수 있도록 보장합니다.
1. **조치**({{< icon name="ellipsis_v" >}}) > **CSV로 내보내기**를 선택합니다.
1. 내보낼 머지 리퀘스트의 개수가 정확한지 확인합니다.
1. **머지 리퀘스트 내보내기**를 선택합니다.

## CSV 출력 {#csv-output}

다음 표는 CSV 파일의 속성을 보여줍니다.

| 열             | 설명                                                  |
|--------------------|--------------------------------------------------------------|
| 제목              | 머지 리퀘스트 제목                                          |
| 설명        | 머지 리퀘스트 설명                                    |
| MR ID              | MR `iid`                                                     |
| URL                | GitLab의 머지 리퀘스트에 대한 링크                        |
| 상태              | 열림, 닫음, 잠김 또는 병합됨                            |
| 소스 브랜치      | 소스 브랜치                                                |
| 대상 브랜치      | 대상 브랜치                                                |
| 소스 프로젝트 ID  | 소스 프로젝트의 ID                                     |
| 대상 프로젝트 ID  | 대상 프로젝트의 ID                                     |
| 작성자             | 머지 리퀘스트 작성자의 전체 이름                        |
| 작성자 사용자명    | 작성자의 사용자 이름(@ 기호 제외)            |
| 담당자          | 머지 리퀘스트 담당자의 전체 이름(쉼표로 구분됨)`,` |
| 담당자 사용자 이름 | 담당자의 사용자 이름(@ 기호 제외)         |
| 승인자          | 승인자의 전체 이름(쉼표로 구분됨)`,`               |
| 승인자 사용자 이름 | 승인자의 사용자 이름(@ 기호 제외)         |
| 병합된 사용자        | 병합된 사용자의 전체 이름                                 |
| 병합된 사용자 이름    | 병합 사용자의 사용자 이름(@ 기호 제외)        |
| 마일스톤 ID       | 머지 리퀘스트 마일스톤의 ID                            |
| Created At(UTC)   | `YYYY-MM-DD HH:MM:SS`로 형식화됨                           |
| 업데이트 시간(UTC)   | `YYYY-MM-DD HH:MM:SS`로 형식화됨                           |
