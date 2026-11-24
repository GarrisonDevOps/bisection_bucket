---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 브랜치를 메인 브랜치에 병합하기
---

[브랜치를 생성](branch.md)한 후 필요한 변경 사항을 작성하고 [로컬에 커밋](commit.md)한 후에는 [브랜치를 푸시](commit.md#send-changes-to-gitlab)하고 커밋을 GitLab으로 보냅니다.

`git push`에 대한 응답으로 GitLab은 머지 리퀘스트를 생성할 수 있는 직접 링크를 제공합니다. 예를 들어:

```plaintext
...
remote: To create a merge request for my-new-branch, visit:
remote:   https://gitlab.example.com/my-group/my-project/merge_requests/new?merge_request%5Bsource_branch%5D=my-new-branch
```

브랜치를 메인 브랜치에 병합하려면:

1. Git이 제공한 링크에서 제공된 페이지로 이동한 후 [머지 리퀘스트를 생성](../../user/project/merge_requests/creating_merge_requests.md)합니다. 머지 리퀘스트의 **소스 브랜치**는 사용자의 브랜치이고 **타겟 브랜치**는 메인 브랜치여야 합니다.
1. 필요한 경우 [머지 리퀘스트 검토](../../user/project/merge_requests/reviews/_index.md#request-a-review)를 받습니다.
1. 다른 사용자가 [머지 리퀘스트를 병합](../../user/project/merge_requests/_index.md#merge-a-merge-request)하거나, 프로세스에 따라 머지 리퀘스트를 직접 병합합니다.

## 관련 항목 {#related-topics}

- [머지 리퀘스트](../../user/project/merge_requests/_index.md)
- [머지 방법](../../user/project/merge_requests/methods/_index.md)
- [병합 충돌](../../user/project/merge_requests/conflicts.md)
