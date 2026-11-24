---
title: 머지 리퀘스트 검토 및 배포 승인을 위한 웹후크
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: create
co_create: true
documentation_link: "../../../user/project/integrations/webhook_events/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246562
categories: [ Code Review Workflow, Deployment Management ]
level: secondary
---

머지 리퀘스트 검토 및 배포 승인을 위해 웹후크를 사용할 수 있습니다. 머지 리퀘스트 검토를 **변경 요청** 또는 **검토됨**으로 제출하면, GitLab이 `merge_request` 웹후크를 발생시키며 `changes.reviewers` 항목을 포함하므로 외부 도구는 단순한 승인이 아닌 검토 활동에 반응할 수 있습니다.

배포 웹후크는 `blocked`, `approved`, 및 `rejected` 상태를 최상위 `approver` 및 `approval` 필드와 함께 획득하여 배포를 전체 승인 수명 주기를 통해 추적할 수 있도록 합니다. `blocked` 상태는 모든 티어에서 사용할 수 있습니다. `approved` 및 `rejected` 상태는 Premium 및 Ultimate에서만 사용할 수 있으며, `approver.email`는 숨겨집니다.

이 기여에 감사드립니다. [Messias Tayllan](https://gitlab.com/tayllanr)([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246562)) 및 [Anvita Gupta](https://gitlab.com/arcesium-guptaanv)([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/239337))
