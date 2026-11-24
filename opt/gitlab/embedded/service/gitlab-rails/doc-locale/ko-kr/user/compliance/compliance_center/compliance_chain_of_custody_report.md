---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab에서 위반 리포트를 생성하고 내보내 프로젝트 변경 사항과 머지 리퀘스트 세부 정보를 추적하여 규정을 준수합니다.
title: 위반 리포트
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

위반 리포트는 그룹 아래의 프로젝트에 대한 모든 커밋의 1개월 추적 기간을 제공합니다.

모든 커밋에 대한 리포트를 생성하려면 GitLab에서 다음을 수행합니다:

1. 그룹 아래의 모든 프로젝트를 가져옵니다.
1. 각 프로젝트에서 지난 1개월의 커밋을 시간 순서(최신순)로 가져옵니다. 각 프로젝트는 1024개의 커밋으로 제한됩니다. 1개월 기간에 1024개 이상의 커밋이 있으면 잘립니다.
1. 모든 커밋을 커밋 날짜(내림차순)로 정렬하고 일관된 순서 지정을 위해 커밋 SHA로 확정적 보조 정렬을 수행합니다.
1. 커밋을 CSV 파일에 씁니다. 리포트를 첨부 파일로 이메일로 발송하므로 파일은 15MB로 잘립니다.

리포트에는 다음이 포함됩니다:

- 커밋 SHA.
- 커밋 작성자.
- 커밋자(가능한 경우 커밋자 이메일을 기준으로 GitLab 사용자 이름으로 정규화).
- 커밋 날짜(UTC 형식으로 밀리초 정밀도 포함).
- 그룹.
- 프로젝트.

커밋에 관련된 머지 커밋이 있으면 다음도 포함됩니다:

- 머지 커밋 SHA.
- 머지 리퀘스트 ID.
- 머지 리퀘스트를 머지한 사용자.
- 머지 날짜.
- 파이프라인 ID.
- 머지 리퀘스트 승인자.

## 위반 리포트 생성 {#generate-chain-of-custody-report}

위반 리포트를 생성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.
1. 오른쪽 위 모서리에서 **내보내기**를 선택하세요.
1. **전체 위반 리포트 내보내기**를 선택합니다.

위반 리포트는 이메일로 발송됩니다.

## 특정 커밋 위반 리포트 생성 {#generate-commit-specific-chain-of-custody-report}

주어진 커밋 SHA에 대한 특정 커밋 위반 리포트를 생성할 수 있습니다. 이 리포트는 제공된 커밋 SHA에 대한 세부 정보만 제공합니다.

특정 커밋 위반 리포트를 생성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.
1. 오른쪽 위 모서리에서 **내보내기**를 선택하세요.
1. **특정 커밋에 대한 위반 리포트 내보내기**를 선택합니다.
1. 커밋 SHA를 입력한 후 **위반 리포트 내보내기**를 선택합니다.

위반 리포트는 이메일로 발송됩니다.

또는 직접 링크 `https://gitlab.com/groups/<group-name>/-/security/merge_commit_reports.csv?commit_sha={optional_commit_sha}`를 사용하여 `commit_sha` 쿼리 매개변수에 선택적 값을 전달합니다.
