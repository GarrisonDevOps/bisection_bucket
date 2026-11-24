---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab에서 파일의 Git 이력을 보는 방법입니다.
title: Git 파일 이력
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Git 파일 이력은 파일과 관련된 커밋 이력에 대한 정보를 제공합니다:

![단일 파일의 3개 커밋 목록이며 가장 최신 커밋은 '검증됨'으로 표시되어 있습니다.](img/file_history_output_v17_2.png)

각 커밋은 다음을 표시합니다:

- 커밋의 날짜입니다. GitLab은 같은 날에 만들어진 모든 커밋을 함께 그룹화합니다.
- 사용자의 아바타입니다.
- 사용자의 이름입니다. 이름 위에 마우스를 가져가면 사용자의 직책, 위치, 로컬 시간 및 현재 상태 메시지를 볼 수 있습니다.
- 커밋의 날짜이며 시간 경과 형식입니다. 커밋의 정확한 날짜와 시간을 보려면 날짜 위에 마우스를 올립니다.
- [커밋이 서명된](../signed_commits/_index.md) 경우 **검증됨** 배지입니다.
- 커밋 SHA입니다. GitLab은 처음 8개 문자를 표시합니다. **커밋 SHA 복사** ({{< icon name="copy-to-clipboard" >}})를 선택하여 전체 SHA를 복사합니다.
- 파일을 이 커밋 시점에 보였던 상태로 찾아보기 ({{< icon name="folder-open" >}})하는 링크입니다.

GitLab은 사용자가 커밋을 만들 때 기여자의 [Git 구성](https://git-scm.com/book/en/v2/Customizing-Git-Git-Configuration)에서 사용자 이름 및 이메일 정보를 검색합니다.

## 파일의 Git 이력 보기 {#view-a-files-git-history}

UI에서 파일의 Git 이력을 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. 리포지토리에서 원하는 파일로 이동합니다.
1. 마지막 커밋 블록에서 **이력**을 선택합니다.

## 이력 범위 결과 제한 {#limit-history-range-of-results}

오래된 파일이나 많은 커밋이 있는 파일의 이력을 검토할 때 날짜별로 검색 결과를 제한할 수 있습니다. 커밋의 날짜를 제한하면 매우 큰 리포지토리에서 [커밋 이력 요청 시간 초과](https://gitlab.com/gitlab-org/gitaly/-/issues/5426) 문제를 해결하는 데 도움이 됩니다.

GitLab UI에서 URL을 편집합니다. 다음 매개변수를 `YYYY-MM-DD` 형식으로 포함합니다(날짜는 UTC로 해석됨):

- `committed_before`
- `committed_after`

쿼리 문자열에서 각 키-값 쌍을 앰퍼샌드(`&`)로 구분합니다. 예:

```plaintext
?ref_type=heads&committed_after=2023-05-15&committed_before=2023-11-22
```

커밋 범위의 전체 URL은 다음과 같습니다:

```plaintext
https://gitlab.com/gitlab-org/gitlab/-/commits/master/CONTRIBUTING.md?ref_type=heads&committed_after=2023-05-15&committed_before=2023-11-22
```

## 관련 항목 {#related-topics}

- [Git blame](git_blame.md)
- [일반 Git 명령](../../../../topics/git/commands.md)
- [Git을 사용한 파일 관리](../../../../topics/git/file_management.md)
- [파일 트리 브라우저](file_tree_browser.md)
