---
title: REST API에서 자동 병합 취소
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
co_create: true
documentation_link: "../../../api/merge_requests/#cancel-auto-merge"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255702
categories: [ Code Review Workflow ]
level: secondary
weight: 20
---

이제 `cancel_auto_merge` API 엔드포인트를 사용하여 활성 자동 병합을 취소할 수 있습니다. 머지 리퀘스트가 머지 트레인에 있으면 호출도 트레인에서 제거합니다. 이전 `cancel_merge_when_pipeline_succeeds` 엔드포인트는 이제 더 이상 사용되지 않습니다.

별도로, `git push -o merge_request.auto_merge`은(는) 대상 브랜치에 병합할 수 없을 때 원격 메시지와 함께 거부됩니다. 이전 버전의 GitLab에서는 자동 병합이 기록되었으며 취소될 때까지 머지 리퀘스트를 병합할 수 없는 상태로 두었습니다.

이러한 기여를 해주신 다음 사용자들께 감사드립니다!

- [José M. Requena Plens](https://gitlab.com/jmrp)([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255702) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255704))
- [Bobby Nandigam](https://gitlab.com/bobby-nandigam)([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251960))
