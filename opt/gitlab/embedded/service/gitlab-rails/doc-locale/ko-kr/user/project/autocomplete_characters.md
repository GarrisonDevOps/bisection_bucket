---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Markdown 필드의 자동완성 문자
title: 자동완성 문자
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

자동완성 문자는 Markdown 필드에 필드 값을 입력하는 빠른 방법을 제공합니다. Markdown 필드에서 다음 문자 중 하나를 사용하여 단어를 입력하기 시작하면 GitLab은 일치하는 값 집합에 대해 점진적으로 자동완성합니다. 문자열 일치는 대소문자를 구분하지 않습니다.

| 문자 | 자동완성    | 표시되는 관련 일치 항목 |
| --------- | ---------------- | ---------------------- |
| `~`       | 레이블           | 20                     |
| `%`       | 마일스톤       | 5                      |
| `@`       | 사용자 및 그룹 | 10                     |
| `#`       | 이슈           | 5                      |
| `!`       | 머지 리퀘스트   | 5                      |
| `&`       | 에픽            | 5                      |
| `$`       | 스니펫         | 5                      |
| `:`       | 이모지            | 5                      |
| `/`       | 빠른 작업    | 100                    |
| `*iteration:` | 반복 | 5 |

목록에서 항목을 선택하면 값이 필드에 입력됩니다. 더 많은 문자를 입력할수록 일치 항목이 더 정확합니다.

자동완성 문자를 [빠른 작업](quick_actions.md)과 함께 사용할 수 있습니다.

## 사용자 자동완성 {#user-autocomplete}

GitLab 인스턴스에 다음 사용자가 포함되어 있다고 가정합니다:

<!-- vale gitlab_base.Spelling = NO -->

| 사용자 이름        | 이름 |
| :-------------- | :--- |
| alessandra      | Rosy Grant |
| lawrence.white  | Kelsey Kerluke |
| leanna          | Rosemarie Rogahn |
| logan_gutkowski | Lee Wuckert |
| shelba          | Josefine Haley |

<!-- vale gitlab_base.Spelling = YES -->

사용자 자동완성은 쿼리로 시작하는 사용자 이름 또는 이름을 가진 사용자를 먼저 정렬합니다. 예를 들어 `@lea`을 입력하면 `leanna`가 먼저 표시되고 `@ros`을 입력하면 `Rosemarie Rogahn` 및 `Rosy Grant`가 먼저 표시됩니다. 쿼리를 포함하는 사용자 이름 또는 이름은 자동완성 메뉴에 나중에 표시됩니다.

전체 이름을 검색하여 사용자를 찾을 수도 있습니다. `Rosy Grant`을 찾으려면 사용자 이름이 예를 들어 `alessandra`일 수 있지만 `@rosygrant`처럼 공백 없이 전체 이름을 입력할 수 있습니다.
